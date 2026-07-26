use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use futures_util::StreamExt;
use reqwest::{
    Client, Method, StatusCode,
    dns::{Addrs, Name, Resolve, Resolving},
    header::{
        ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, HeaderMap, HeaderName, HeaderValue,
        LOCATION,
    },
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
    response_mode: ResponseMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResponseMode {
    Local,
    Managed,
}

impl ProbeClient {
    pub fn new() -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .user_agent("SocialName/0.2 (+https://github.com/yhay81/socialname)")
            .build()?;
        Ok(Self {
            client,
            response_mode: ResponseMode::Local,
        })
    }

    pub fn new_managed() -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .user_agent("SocialName-Managed-Worker/0.2 (+https://github.com/yhay81/socialname)")
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .dns_resolver(ManagedDnsResolver::new(SystemDnsResolver))
            .build()?;
        Ok(Self {
            client,
            response_mode: ResponseMode::Managed,
        })
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

            if self.response_mode == ResponseMode::Managed {
                validate_header_budget(response.headers(), probe.http.limits.header_bytes)?;
            }
            let status = response.status();
            if status.is_redirection() {
                let location = response
                    .headers()
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok());
                if let Some(location) = location {
                    match probe.http.redirects.mode {
                        RedirectMode::None => {
                            return self
                                .read_response(&probe.id, response, &selected_headers, probe)
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

            return self
                .read_response(&probe.id, response, &selected_headers, probe)
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
        if self.response_mode == ResponseMode::Managed {
            headers.insert(
                ACCEPT_ENCODING,
                HeaderValue::from_static("gzip, br, deflate, zstd"),
            );
        }
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

    async fn read_response(
        &self,
        probe_id: &str,
        response: reqwest::Response,
        selected_headers: &BTreeSet<String>,
        probe: &ProbeSource,
    ) -> Result<ProbeResponse, TransportOutcome> {
        match self.response_mode {
            ResponseMode::Local => {
                read_local_response(
                    probe_id,
                    response,
                    selected_headers,
                    probe.http.limits.inspected_bytes,
                )
                .await
            }
            ResponseMode::Managed => {
                read_managed_response(probe_id, response, selected_headers, probe).await
            }
        }
    }
}

async fn read_local_response(
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

async fn read_managed_response(
    probe_id: &str,
    response: reqwest::Response,
    selected_headers: &BTreeSet<String>,
    probe: &ProbeSource,
) -> Result<ProbeResponse, TransportOutcome> {
    let status = response.status();
    let final_url = response.url().to_string();
    validate_header_budget(response.headers(), probe.http.limits.header_bytes)?;
    validate_content_length(response.headers(), probe.http.limits.compressed_bytes)?;
    let content_encoding = content_encoding(response.headers())?;
    let headers = collect_headers(response.headers(), selected_headers)?;
    let compressed = collect_compressed_body(response, probe.http.limits.compressed_bytes).await?;
    let decompressed_limit = probe.http.limits.decompressed_bytes;
    let decompressed = tokio::task::spawn_blocking(move || {
        decode_response_body(compressed, content_encoding, decompressed_limit)
    })
    .await
    .map_err(|_| TransportOutcome::Decode)??;
    let body_bytes = decompressed.len();
    let (body, body_truncated) = inspected_body(&decompressed, probe.http.limits.inspected_bytes);
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
        body_truncated,
        elapsed_ms: 0,
    })
}

fn inspected_body(decompressed: &[u8], limit: usize) -> (String, bool) {
    let inspected_bytes = decompressed.len().min(limit);
    (
        String::from_utf8_lossy(&decompressed[..inspected_bytes]).into_owned(),
        inspected_bytes < decompressed.len(),
    )
}

async fn collect_compressed_body(
    response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, TransportOutcome> {
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::with_capacity(limit.min(16 * 1_024));
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(map_reqwest_error)?;
        let next_length = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or(TransportOutcome::ResponseTooLarge)?;
        if next_length > limit {
            return Err(TransportOutcome::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContentEncoding {
    Identity,
    Gzip,
    Brotli,
    Deflate,
    Zstd,
}

fn content_encoding(headers: &HeaderMap) -> Result<ContentEncoding, TransportOutcome> {
    let mut values = headers.get_all(CONTENT_ENCODING).iter();
    let Some(value) = values.next() else {
        return Ok(ContentEncoding::Identity);
    };
    if values.next().is_some() {
        return Err(TransportOutcome::Decode);
    }
    match value
        .to_str()
        .map_err(|_| TransportOutcome::Decode)?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "identity" => Ok(ContentEncoding::Identity),
        "gzip" | "x-gzip" => Ok(ContentEncoding::Gzip),
        "br" => Ok(ContentEncoding::Brotli),
        "deflate" => Ok(ContentEncoding::Deflate),
        "zstd" => Ok(ContentEncoding::Zstd),
        _ => Err(TransportOutcome::Decode),
    }
}

fn decode_response_body(
    compressed: Vec<u8>,
    encoding: ContentEncoding,
    limit: usize,
) -> Result<Vec<u8>, TransportOutcome> {
    let reader: Box<dyn Read> = match encoding {
        ContentEncoding::Identity => Box::new(Cursor::new(compressed)),
        ContentEncoding::Gzip => Box::new(flate2::read::GzDecoder::new(Cursor::new(compressed))),
        ContentEncoding::Brotli => {
            Box::new(brotli::Decompressor::new(Cursor::new(compressed), 4_096))
        }
        ContentEncoding::Deflate => {
            Box::new(flate2::read::ZlibDecoder::new(Cursor::new(compressed)))
        }
        ContentEncoding::Zstd => Box::new(
            zstd::stream::read::Decoder::new(Cursor::new(compressed))
                .map_err(|_| TransportOutcome::Decode)?,
        ),
    };
    let read_limit = u64::try_from(limit)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or(TransportOutcome::ResponseTooLarge)?;
    let mut output = Vec::with_capacity(limit.min(16 * 1_024));
    reader
        .take(read_limit)
        .read_to_end(&mut output)
        .map_err(|_| TransportOutcome::Decode)?;
    if output.len() > limit {
        Err(TransportOutcome::ResponseTooLarge)
    } else {
        Ok(output)
    }
}

fn validate_header_budget(headers: &HeaderMap, limit: usize) -> Result<(), TransportOutcome> {
    let mut total = 0_usize;
    for (name, value) in headers {
        total = total
            .checked_add(name.as_str().len())
            .and_then(|total| total.checked_add(value.as_bytes().len()))
            .and_then(|total| total.checked_add(4))
            .ok_or(TransportOutcome::ResponseTooLarge)?;
        if total > limit {
            return Err(TransportOutcome::ResponseTooLarge);
        }
    }
    Ok(())
}

fn validate_content_length(headers: &HeaderMap, limit: usize) -> Result<(), TransportOutcome> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(TransportOutcome::Decode);
    }
    let length = value
        .to_str()
        .map_err(|_| TransportOutcome::Decode)?
        .parse::<u64>()
        .map_err(|_| TransportOutcome::Decode)?;
    if usize::try_from(length)
        .ok()
        .is_some_and(|length| length <= limit)
    {
        Ok(())
    } else {
        Err(TransportOutcome::ResponseTooLarge)
    }
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

const MAX_DNS_ADDRESSES: usize = 16;

#[derive(Clone, Copy, Debug, Default)]
struct SystemDnsResolver;

impl Resolve for SystemDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|_| {
                    Box::new(ManagedDnsError::ResolutionFailed) as Box<dyn Error + Send + Sync>
                })?
                .collect::<Vec<_>>();
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

#[derive(Clone, Debug)]
struct ManagedDnsResolver<R> {
    inner: Arc<R>,
}

impl<R> ManagedDnsResolver<R> {
    fn new(inner: R) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }
}

impl<R> Resolve for ManagedDnsResolver<R>
where
    R: Resolve + 'static,
{
    fn resolve(&self, name: Name) -> Resolving {
        let host_is_forbidden = name.as_str().eq_ignore_ascii_case("localhost")
            || name.as_str().to_ascii_lowercase().ends_with(".localhost");
        if host_is_forbidden {
            return Box::pin(async {
                Err(Box::new(ManagedDnsError::ForbiddenDestination) as Box<dyn Error + Send + Sync>)
            });
        }
        let resolving = self.inner.resolve(name);
        Box::pin(async move {
            let resolved = resolving.await.map_err(|_| {
                Box::new(ManagedDnsError::ResolutionFailed) as Box<dyn Error + Send + Sync>
            })?;
            let addresses = resolved.take(MAX_DNS_ADDRESSES + 1).collect::<Vec<_>>();
            let addresses = validate_resolved_addresses(addresses)
                .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)?;
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
enum ManagedDnsError {
    #[error("managed DNS resolution failed")]
    ResolutionFailed,
    #[error("managed DNS returned no usable address")]
    NoAddress,
    #[error("managed DNS returned too many addresses")]
    TooManyAddresses,
    #[error("managed DNS destination is forbidden")]
    ForbiddenDestination,
}

fn validate_resolved_addresses(
    addresses: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>, ManagedDnsError> {
    if addresses.is_empty() {
        return Err(ManagedDnsError::NoAddress);
    }
    if addresses.len() > MAX_DNS_ADDRESSES {
        return Err(ManagedDnsError::TooManyAddresses);
    }
    if addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err(ManagedDnsError::ForbiddenDestination);
    }
    let unique = addresses.into_iter().collect::<BTreeSet<_>>();
    if unique.is_empty() {
        Err(ManagedDnsError::NoAddress)
    } else {
        Ok(unique.into_iter().collect())
    }
}

fn validate_destination(url: &Url, allowed_hosts: &[String]) -> Result<(), TransportOutcome> {
    if url.scheme() != "https" {
        return Err(TransportOutcome::RedirectRejected);
    }
    if !url.username().is_empty() || url.password().is_some() {
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
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    ![
        (Ipv4Addr::new(0, 0, 0, 0), 8),
        (Ipv4Addr::new(10, 0, 0, 0), 8),
        (Ipv4Addr::new(100, 64, 0, 0), 10),
        (Ipv4Addr::new(127, 0, 0, 0), 8),
        (Ipv4Addr::new(169, 254, 0, 0), 16),
        (Ipv4Addr::new(172, 16, 0, 0), 12),
        (Ipv4Addr::new(192, 0, 0, 0), 24),
        (Ipv4Addr::new(192, 0, 2, 0), 24),
        (Ipv4Addr::new(192, 88, 99, 0), 24),
        (Ipv4Addr::new(192, 168, 0, 0), 16),
        (Ipv4Addr::new(198, 18, 0, 0), 15),
        (Ipv4Addr::new(198, 51, 100, 0), 24),
        (Ipv4Addr::new(203, 0, 113, 0), 24),
        (Ipv4Addr::new(224, 0, 0, 0), 4),
        (Ipv4Addr::new(240, 0, 0, 0), 4),
    ]
    .into_iter()
    .any(|(network, prefix)| ipv4_in_network(address, network, prefix))
}

fn ipv4_in_network(address: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    let shift = u32::from(32_u8.saturating_sub(prefix));
    let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
    u32::from(address) & mask == u32::from(network) & mask
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    ipv6_in_network(address, Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3)
        && ![
            (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23),
            (Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32),
            (Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16),
            (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20),
        ]
        .into_iter()
        .any(|(network, prefix)| ipv6_in_network(address, network, prefix))
}

fn ipv6_in_network(address: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    let shift = u32::from(128_u8.saturating_sub(prefix));
    let mask = u128::MAX.checked_shl(shift).unwrap_or(0);
    u128::from(address) & mask == u128::from(network) & mask
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
    if error_chain_contains_managed_dns(&error) {
        TransportOutcome::Dns
    } else if error.is_timeout() {
        TransportOutcome::Timeout
    } else if error.is_connect() {
        TransportOutcome::Connect
    } else if error.is_decode() {
        TransportOutcome::Decode
    } else {
        TransportOutcome::Connect
    }
}

fn error_chain_contains_managed_dns(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error.downcast_ref::<ManagedDnsError>().is_some() {
            return true;
        }
        current = error.source();
    }
    false
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io::Write,
        sync::{Arc, Mutex},
    };

    use super::*;

    #[test]
    fn managed_ip_policy_allows_only_public_unicast_destinations() {
        for address in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(is_public_ip(address.parse().unwrap()), "{address}");
        }

        for address in [
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.9",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "100::1",
            "2001::1",
            "2001:db8::1",
            "2002:7f00:1::",
            "3fff::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(!is_public_ip(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn destination_validation_rejects_credentials_and_private_literals() {
        let allowed = ["example.test".to_owned()];
        assert_eq!(
            validate_destination(
                &Url::parse("https://credential@example.test/profile").unwrap(),
                &allowed
            )
            .unwrap_err(),
            TransportOutcome::RedirectRejected
        );
        assert_eq!(
            validate_destination(
                &Url::parse("https://example.test:secret@example.test/profile").unwrap(),
                &allowed
            )
            .unwrap_err(),
            TransportOutcome::RedirectRejected
        );
        assert_eq!(
            validate_destination(
                &Url::parse("https://169.254.169.254/latest/meta-data").unwrap(),
                &["169.254.169.254".to_owned()]
            )
            .unwrap_err(),
            TransportOutcome::RedirectRejected
        );
    }

    #[test]
    fn managed_dns_rejects_mixed_private_answers_and_bounds_cardinality() {
        let public = SocketAddr::new("8.8.8.8".parse().unwrap(), 0);
        let private = SocketAddr::new("10.0.0.1".parse().unwrap(), 0);
        assert_eq!(
            validate_resolved_addresses(vec![public, private]).unwrap_err(),
            ManagedDnsError::ForbiddenDestination
        );
        assert_eq!(
            validate_resolved_addresses(Vec::new()).unwrap_err(),
            ManagedDnsError::NoAddress
        );
        assert_eq!(
            validate_resolved_addresses(vec![public; MAX_DNS_ADDRESSES + 1]).unwrap_err(),
            ManagedDnsError::TooManyAddresses
        );
        assert_eq!(
            validate_resolved_addresses(vec![public, public]).unwrap(),
            [public]
        );
    }

    #[derive(Clone, Debug)]
    struct ScriptedResolver {
        answers: Arc<Mutex<VecDeque<Vec<SocketAddr>>>>,
    }

    impl ScriptedResolver {
        fn new(answers: Vec<Vec<SocketAddr>>) -> Self {
            Self {
                answers: Arc::new(Mutex::new(answers.into())),
            }
        }
    }

    impl Resolve for ScriptedResolver {
        fn resolve(&self, _name: Name) -> Resolving {
            let answer = self.answers.lock().unwrap().pop_front();
            Box::pin(async move {
                let answer = answer.ok_or_else(|| {
                    Box::new(ManagedDnsError::ResolutionFailed) as Box<dyn Error + Send + Sync>
                })?;
                Ok(Box::new(answer.into_iter()) as Addrs)
            })
        }
    }

    #[tokio::test]
    async fn managed_dns_revalidates_every_connection_to_stop_rebinding() {
        let public = SocketAddr::new("8.8.8.8".parse().unwrap(), 0);
        let private = SocketAddr::new("169.254.169.254".parse().unwrap(), 0);
        let resolver =
            ManagedDnsResolver::new(ScriptedResolver::new(vec![vec![public], vec![private]]));

        let first = resolver
            .resolve("example.test".parse().unwrap())
            .await
            .unwrap()
            .collect::<Vec<_>>();
        assert_eq!(first, [public]);
        assert!(
            resolver
                .resolve("example.test".parse().unwrap())
                .await
                .is_err()
        );
    }

    #[test]
    fn managed_body_decoding_enforces_decompressed_limits_for_every_encoding() {
        let body = b"bounded managed response";

        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(body).unwrap();
        let gzip = gzip.finish().unwrap();

        let mut deflate =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        deflate.write_all(body).unwrap();
        let deflate = deflate.finish().unwrap();

        let mut brotli = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut brotli, 4_096, 5, 22);
            writer.write_all(body).unwrap();
        }
        let zstd = zstd::stream::encode_all(Cursor::new(body), 1).unwrap();

        for (encoding, encoded) in [
            (ContentEncoding::Identity, body.to_vec()),
            (ContentEncoding::Gzip, gzip),
            (ContentEncoding::Brotli, brotli),
            (ContentEncoding::Deflate, deflate),
            (ContentEncoding::Zstd, zstd),
        ] {
            assert_eq!(
                decode_response_body(encoded.clone(), encoding, body.len()).unwrap(),
                body
            );
            assert_eq!(
                decode_response_body(encoded, encoding, body.len() - 1).unwrap_err(),
                TransportOutcome::ResponseTooLarge
            );
        }
    }

    #[test]
    fn managed_body_retains_only_the_inspected_prefix() {
        assert_eq!(
            inspected_body(b"public profile body", 6),
            ("public".to_owned(), true)
        );
        assert_eq!(inspected_body(b"public", 6), ("public".to_owned(), false));
    }

    #[test]
    fn managed_header_and_declared_body_limits_cover_unselected_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "set-cookie",
            HeaderValue::from_static("sensitive-cookie-value"),
        );
        assert_eq!(
            validate_header_budget(&headers, 8).unwrap_err(),
            TransportOutcome::ResponseTooLarge
        );

        headers.clear();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("1025"));
        assert_eq!(
            validate_content_length(&headers, 1_024).unwrap_err(),
            TransportOutcome::ResponseTooLarge
        );
    }
}
