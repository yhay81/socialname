use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::{Duration, Instant},
};

use futures_util::StreamExt;
use reqwest::{
    Client, Method, StatusCode,
    header::{HeaderMap, HeaderName, HeaderValue, LOCATION},
    redirect::Policy,
};
use socialname_rule_compiler::{CompiledSiteRule, render_identity_template, render_url_template};
use socialname_rule_schema::{
    HttpMethod, ProbeSource, RedirectMode, RequestBodySource, TransportOutcome,
};
use url::Url;

use crate::ProbeResponse;

#[derive(Clone, Debug)]
pub struct ProbeClient {
    client: Client,
}

impl ProbeClient {
    pub fn new() -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .user_agent("SocialName/0.2 (+https://github.com/yhay81/socialname)")
            .build()?;
        Ok(Self { client })
    }

    pub async fn execute(
        &self,
        rule: &CompiledSiteRule,
        probe: &ProbeSource,
        username: &str,
    ) -> ProbeResponse {
        let start = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_millis(probe.http.timeout.total_ms),
            self.execute_inner(rule, probe, username),
        )
        .await;

        match result {
            Ok(Ok(mut response)) => {
                response.elapsed_ms = duration_ms(start.elapsed());
                response
            }
            Ok(Err(outcome)) => ProbeResponse {
                probe_id: probe.id.clone(),
                transport: outcome,
                status: None,
                final_url: None,
                headers: BTreeMap::new(),
                body: String::new(),
                body_bytes: 0,
                body_truncated: false,
                elapsed_ms: duration_ms(start.elapsed()),
            },
            Err(_) => ProbeResponse {
                probe_id: probe.id.clone(),
                transport: TransportOutcome::Timeout,
                status: None,
                final_url: None,
                headers: BTreeMap::new(),
                body: String::new(),
                body_bytes: 0,
                body_truncated: false,
                elapsed_ms: duration_ms(start.elapsed()),
            },
        }
    }

    async fn execute_inner(
        &self,
        rule: &CompiledSiteRule,
        probe: &ProbeSource,
        username: &str,
    ) -> Result<ProbeResponse, TransportOutcome> {
        let mut url =
            render_url_template(&probe.http.url, username).map_err(|_| TransportOutcome::Decode)?;
        validate_destination(&url, &probe.http.allowed_hosts)?;
        let initial_host = url.host_str().unwrap_or_default().to_owned();
        let selected_headers = response_header_allowlist(rule);

        let mut hops = 0_u8;
        loop {
            let request = self.build_request(probe, username, url.clone())?;
            let response = tokio::time::timeout(
                Duration::from_millis(probe.http.timeout.first_byte_ms),
                request.send(),
            )
            .await
            .map_err(|_| TransportOutcome::Timeout)?
            .map_err(map_reqwest_error)?;

            let status = response.status();
            if status.is_redirection() {
                let location = response
                    .headers()
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok());
                if let Some(location) = location {
                    match probe.http.redirects.mode {
                        RedirectMode::None => {
                            return read_response(
                                &probe.id,
                                response,
                                &selected_headers,
                                probe.http.limits.inspected_bytes,
                            )
                            .await;
                        }
                        RedirectMode::Follow | RedirectMode::SameSite => {
                            if hops >= probe.http.redirects.max_hops {
                                return Err(TransportOutcome::RedirectRejected);
                            }
                            let next = url
                                .join(location)
                                .map_err(|_| TransportOutcome::RedirectRejected)?;
                            validate_destination(&next, &probe.http.allowed_hosts)?;
                            if probe.http.redirects.mode == RedirectMode::SameSite
                                && next.host_str() != Some(initial_host.as_str())
                            {
                                return Err(TransportOutcome::RedirectRejected);
                            }
                            url = next;
                            hops += 1;
                            continue;
                        }
                    }
                }
            }

            return read_response(
                &probe.id,
                response,
                &selected_headers,
                probe.http.limits.inspected_bytes,
            )
            .await;
        }
    }

    fn build_request(
        &self,
        probe: &ProbeSource,
        username: &str,
        url: Url,
    ) -> Result<reqwest::RequestBuilder, TransportOutcome> {
        let method = match probe.http.method {
            HttpMethod::Get => Method::GET,
            HttpMethod::Head => Method::HEAD,
            HttpMethod::Post => Method::POST,
        };
        let mut request = self.client.request(method, url);

        let mut headers = HeaderMap::new();
        for (name, value) in &probe.http.headers {
            let name =
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| TransportOutcome::Decode)?;
            let value = HeaderValue::from_str(value).map_err(|_| TransportOutcome::Decode)?;
            headers.insert(name, value);
        }
        request = request.headers(headers);

        if let Some(body) = &probe.http.body {
            request = match body {
                RequestBodySource::Json { value } => {
                    request.json(&render_json_value(value.clone(), username)?)
                }
                RequestBodySource::Form { fields } => {
                    let rendered: Result<BTreeMap<_, _>, _> = fields
                        .iter()
                        .map(|(key, value)| {
                            render_identity_template(value, username)
                                .map(|value| (key.clone(), value))
                                .map_err(|_| TransportOutcome::Decode)
                        })
                        .collect();
                    request.form(&rendered?)
                }
                RequestBodySource::Text { value } => request.body(
                    render_identity_template(value, username)
                        .map_err(|_| TransportOutcome::Decode)?,
                ),
            };
        }
        Ok(request)
    }
}

async fn read_response(
    probe_id: &str,
    response: reqwest::Response,
    selected_headers: &BTreeSet<String>,
    inspected_limit: usize,
) -> Result<ProbeResponse, TransportOutcome> {
    let status = response.status();
    let final_url = response.url().to_string();
    let headers = collect_headers(response.headers(), selected_headers)?;
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::with_capacity(inspected_limit.min(16 * 1_024));
    let mut truncated = false;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(map_reqwest_error)?;
        let remaining = inspected_limit.saturating_sub(bytes.len());
        if chunk.len() > remaining {
            bytes.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        bytes.extend_from_slice(&chunk);
        if bytes.len() == inspected_limit {
            truncated = true;
            break;
        }
    }
    let body_bytes = bytes.len();
    let body = String::from_utf8_lossy(&bytes).into_owned();
    Ok(ProbeResponse {
        probe_id: probe_id.to_owned(),
        transport: if status == StatusCode::TOO_MANY_REQUESTS {
            TransportOutcome::RateLimited
        } else {
            TransportOutcome::Completed
        },
        status: Some(status.as_u16()),
        final_url: Some(final_url),
        headers,
        body,
        body_bytes,
        body_truncated: truncated,
        elapsed_ms: 0,
    })
}

fn collect_headers(
    headers: &HeaderMap,
    selected_headers: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>, TransportOutcome> {
    let mut output = BTreeMap::new();
    let mut total = 0_usize;
    for (name, value) in headers {
        let normalized = name.as_str().to_ascii_lowercase();
        if selected_headers.contains(&normalized) {
            let value = value.to_str().map_err(|_| TransportOutcome::Decode)?;
            total += normalized.len() + value.len();
            if total > 64 * 1_024 {
                return Err(TransportOutcome::ResponseTooLarge);
            }
            output.insert(normalized, value.to_owned());
        }
    }
    Ok(output)
}

fn response_header_allowlist(rule: &CompiledSiteRule) -> BTreeSet<String> {
    let mut headers = BTreeSet::from([
        "content-type".to_owned(),
        "location".to_owned(),
        "retry-after".to_owned(),
        "x-ratelimit-remaining".to_owned(),
    ]);
    let mut visitor = |condition: &socialname_rule_schema::ConditionSource| {
        collect_condition_headers(condition, &mut headers);
    };
    if let Some(blocked) = &rule.source.classification.blocked {
        visitor(blocked);
    }
    visitor(&rule.source.classification.found);
    visitor(&rule.source.classification.not_found);
    headers
}

fn collect_condition_headers(
    condition: &socialname_rule_schema::ConditionSource,
    headers: &mut BTreeSet<String>,
) {
    use socialname_rule_schema::ConditionSource;
    match condition {
        ConditionSource::All { all: children } | ConditionSource::Any { any: children } => {
            for child in children {
                collect_condition_headers(child, headers);
            }
        }
        ConditionSource::Not { not: child } => collect_condition_headers(child, headers),
        ConditionSource::Header { header: matcher } => {
            let normalized = matcher.name.to_ascii_lowercase();
            if !matches!(
                normalized.as_str(),
                "set-cookie" | "cookie" | "authorization" | "proxy-authorization"
            ) {
                headers.insert(normalized);
            }
        }
        ConditionSource::Status { .. }
        | ConditionSource::FinalUrl { .. }
        | ConditionSource::Body { .. }
        | ConditionSource::Json { .. }
        | ConditionSource::BodyLength { .. }
        | ConditionSource::Transport { .. } => {}
    }
}

fn validate_destination(url: &Url, allowed_hosts: &[String]) -> Result<(), TransportOutcome> {
    if url.scheme() != "https" {
        return Err(TransportOutcome::RedirectRejected);
    }
    let host = url
        .host_str()
        .ok_or(TransportOutcome::RedirectRejected)?
        .to_ascii_lowercase();
    if !allowed_hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&host))
    {
        return Err(TransportOutcome::RedirectRejected);
    }
    if host == "localhost" || host.ends_with(".localhost") {
        return Err(TransportOutcome::RedirectRejected);
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        if !is_public_ip(address) {
            return Err(TransportOutcome::RedirectRejected);
        }
    }
    Ok(())
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !(address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_unspecified())
        }
        IpAddr::V6(address) => {
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_unicast_link_local())
        }
    }
}

fn render_json_value(
    value: serde_json::Value,
    username: &str,
) -> Result<serde_json::Value, TransportOutcome> {
    match value {
        serde_json::Value::String(value) => render_identity_template(&value, username)
            .map(serde_json::Value::String)
            .map_err(|_| TransportOutcome::Decode),
        serde_json::Value::Array(values) => values
            .into_iter()
            .map(|value| render_json_value(value, username))
            .collect::<Result<Vec<_>, _>>()
            .map(serde_json::Value::Array),
        serde_json::Value::Object(values) => values
            .into_iter()
            .map(|(key, value)| render_json_value(value, username).map(|value| (key, value)))
            .collect::<Result<serde_json::Map<_, _>, _>>()
            .map(serde_json::Value::Object),
        scalar => Ok(scalar),
    }
}

fn map_reqwest_error(error: reqwest::Error) -> TransportOutcome {
    if error.is_timeout() {
        TransportOutcome::Timeout
    } else if error.is_connect() {
        TransportOutcome::Connect
    } else if error.is_decode() {
        TransportOutcome::Decode
    } else {
        TransportOutcome::Connect
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
