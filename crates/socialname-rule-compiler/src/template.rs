use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use url::{Url, form_urlencoded};

use crate::CompileError;

const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'?')
    .add(b'\\')
    .add(b'{')
    .add(b'}');

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemplateContext {
    Path,
    Query,
    Subdomain,
}

pub fn render_url_template(template: &str, username: &str) -> Result<Url, CompileError> {
    validate_url_template(template)?;

    let path = utf8_percent_encode(username, PATH_SEGMENT).to_string();
    let query: String = form_urlencoded::byte_serialize(username.as_bytes()).collect();
    let mut rendered = template
        .replace("{username:path}", &path)
        .replace("{username:query}", &query);
    if rendered.contains("{username:subdomain}") {
        rendered = rendered.replace("{username:subdomain}", validate_subdomain(username)?);
    }
    let url = Url::parse(&rendered)
        .map_err(|error| CompileError::InvalidUrlTemplate(error.to_string()))?;
    if url.scheme() != "https" {
        return Err(CompileError::InsecureUrl(rendered));
    }
    Ok(url)
}

pub fn render_identity_template(template: &str, username: &str) -> Result<String, CompileError> {
    validate_identity_template(template)?;
    Ok(template.replace("{username}", username))
}

pub fn validate_url_template(template: &str) -> Result<(), CompileError> {
    let allowed = [
        "{username:path}",
        "{username:query}",
        "{username:subdomain}",
    ];
    let mut scrubbed = template.to_owned();
    for placeholder in allowed {
        scrubbed = scrubbed.replace(placeholder, "socialname-probe");
    }
    if scrubbed.contains('{') || scrubbed.contains('}') {
        return Err(CompileError::InvalidUrlTemplate(
            "unknown or unclosed placeholder".to_owned(),
        ));
    }

    let authority_start = template
        .find("://")
        .map(|index| index + 3)
        .ok_or_else(|| CompileError::InvalidUrlTemplate("absolute URL required".to_owned()))?;
    let authority_end = template[authority_start..]
        .find(['/', '?', '#'])
        .map_or(template.len(), |index| authority_start + index);
    let query_start = template.find('?');
    let fragment_start = template.find('#').unwrap_or(template.len());

    for (placeholder, context) in [
        ("{username:path}", TemplateContext::Path),
        ("{username:query}", TemplateContext::Query),
        ("{username:subdomain}", TemplateContext::Subdomain),
    ] {
        for (index, _) in template.match_indices(placeholder) {
            let valid = match context {
                TemplateContext::Subdomain => index >= authority_start && index < authority_end,
                TemplateContext::Path => {
                    index >= authority_end
                        && query_start.is_none_or(|query| index < query)
                        && index < fragment_start
                }
                TemplateContext::Query => query_start.is_some_and(|query| index > query),
            };
            if !valid {
                return Err(CompileError::InvalidUrlTemplate(format!(
                    "{placeholder} appears in the wrong URL component"
                )));
            }
        }
    }

    let parsed = Url::parse(&scrubbed)
        .map_err(|error| CompileError::InvalidUrlTemplate(error.to_string()))?;
    if parsed.scheme() != "https" {
        return Err(CompileError::InsecureUrl(template.to_owned()));
    }
    if parsed.host_str().is_none() {
        return Err(CompileError::InvalidUrlTemplate(
            "URL host is required".to_owned(),
        ));
    }
    Ok(())
}

pub fn validate_identity_template(template: &str) -> Result<(), CompileError> {
    let scrubbed = template.replace("{username}", "socialname-probe");
    if scrubbed.contains('{') || scrubbed.contains('}') {
        return Err(CompileError::InvalidIdentityTemplate(template.to_owned()));
    }
    Ok(())
}

fn validate_subdomain(username: &str) -> Result<&str, CompileError> {
    let valid = !username.is_empty()
        && username.len() <= 63
        && !username.starts_with('-')
        && !username.ends_with('-')
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    if valid {
        Ok(username)
    } else {
        Err(CompileError::InvalidUrlTemplate(
            "username is not a valid DNS label".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_each_url_context() {
        let url = render_url_template(
            "https://{username:subdomain}.example.test/u/{username:path}?q={username:query}",
            "alice",
        )
        .unwrap();
        assert_eq!(url.as_str(), "https://alice.example.test/u/alice?q=alice");
    }

    #[test]
    fn path_username_cannot_escape_segment() {
        let url = render_url_template("https://example.test/u/{username:path}", "a/b").unwrap();
        assert_eq!(url.as_str(), "https://example.test/u/a%2Fb");
    }

    #[test]
    fn rejects_placeholder_in_wrong_component() {
        let error = validate_url_template("https://{username:path}.example.test/").unwrap_err();
        assert!(matches!(error, CompileError::InvalidUrlTemplate(_)));
    }
}
