use std::{collections::BTreeSet, fmt};

use sha2::{Digest, Sha256};
use socialname_protocol::ApiKeyScope;
use thiserror::Error;
use zeroize::Zeroize;

const TOKEN_MARKER: &str = "snk";
const TOKEN_VERSION: &str = "v1";
const PREFIX_BYTES: usize = 8;
const SECRET_BYTES: usize = 32;

pub(crate) struct ApiKeyToken {
    key_prefix: String,
    secret: [u8; SECRET_BYTES],
}

impl ApiKeyToken {
    pub(crate) fn generate() -> Self {
        let prefix: [u8; PREFIX_BYTES] = rand::random();
        let secret: [u8; SECRET_BYTES] = rand::random();
        Self {
            key_prefix: hex::encode(prefix),
            secret,
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, ApiKeyTokenError> {
        let mut parts = value.split('_');
        let marker = parts.next();
        let version = parts.next();
        let key_prefix = parts.next();
        let encoded_secret = parts.next();
        if marker != Some(TOKEN_MARKER) || version != Some(TOKEN_VERSION) || parts.next().is_some()
        {
            return Err(ApiKeyTokenError);
        }
        let key_prefix = key_prefix.filter(|prefix| {
            prefix.len() == PREFIX_BYTES * 2
                && prefix
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        });
        let encoded_secret = encoded_secret.filter(|secret| {
            secret.len() == SECRET_BYTES * 2
                && secret
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        });
        let (Some(key_prefix), Some(encoded_secret)) = (key_prefix, encoded_secret) else {
            return Err(ApiKeyTokenError);
        };
        let mut secret = [0_u8; SECRET_BYTES];
        if hex::decode_to_slice(encoded_secret, &mut secret).is_err() {
            secret.zeroize();
            return Err(ApiKeyTokenError);
        }
        Ok(Self {
            key_prefix: key_prefix.to_owned(),
            secret,
        })
    }

    pub(crate) fn key_prefix(&self) -> &str {
        &self.key_prefix
    }

    pub(crate) fn secret_hash(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(self.secret.as_slice());
        digest.finalize().into()
    }

    pub(crate) fn expose(&self) -> ApiKeyTokenExposure<'_> {
        ApiKeyTokenExposure(self)
    }
}

impl Drop for ApiKeyToken {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl fmt::Debug for ApiKeyToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKeyToken([REDACTED])")
    }
}

pub(crate) struct ApiKeyTokenExposure<'a>(&'a ApiKeyToken);

impl fmt::Display for ApiKeyTokenExposure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut encoded_secret = [0_u8; SECRET_BYTES * 2];
        hex::encode_to_slice(self.0.secret, &mut encoded_secret)
            .expect("fixed-size hexadecimal output buffer is exact");
        let encoded_secret_text =
            std::str::from_utf8(&encoded_secret).expect("hexadecimal output is ASCII");
        let result = write!(
            formatter,
            "{TOKEN_MARKER}_{TOKEN_VERSION}_{}_{}",
            self.0.key_prefix, encoded_secret_text
        );
        encoded_secret.zeroize();
        result
    }
}

impl fmt::Debug for ApiKeyTokenExposure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKeyTokenExposure([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("API key is invalid; the supplied value is omitted")]
pub(crate) struct ApiKeyTokenError;

pub(crate) fn parse_scopes(value: &str) -> Result<Vec<ApiKeyScope>, ScopeListError> {
    let scopes = value
        .split(',')
        .map(ApiKeyScope::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ScopeListError)?;
    let unique = scopes.iter().copied().collect::<BTreeSet<_>>();
    if scopes.is_empty() || scopes.len() > 16 || unique.len() != scopes.len() {
        Err(ScopeListError)
    } else {
        Ok(scopes)
    }
}

pub(crate) fn scope_values(scopes: &[ApiKeyScope]) -> Vec<String> {
    scopes
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect()
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("API key scopes are invalid; the supplied value is omitted")]
pub(crate) struct ScopeListError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_token_round_trips_without_debug_disclosure() {
        let token = ApiKeyToken::generate();
        let exposed = token.expose().to_string();
        assert_eq!(exposed.len(), 88);
        let parsed = ApiKeyToken::parse(&exposed).unwrap();
        assert_eq!(parsed.key_prefix(), token.key_prefix());
        assert_eq!(parsed.secret_hash(), token.secret_hash());
        assert!(!format!("{token:?}").contains(token.key_prefix()));
        assert!(!format!("{:?}", token.expose()).contains(token.key_prefix()));
    }

    #[test]
    fn malformed_tokens_are_rejected_without_reflection() {
        for token in [
            "",
            "snk_v1_short_secret",
            "SNK_v1_0123456789abcdef_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "snk_v1_0123456789ABCDEF_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "snk_v1_0123456789abcdef_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "snk_v1_0123456789abcdef_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_extra",
        ] {
            let error = ApiKeyToken::parse(token).unwrap_err();
            if !token.is_empty() {
                assert!(!error.to_string().contains(token));
            }
        }
    }

    #[test]
    fn scope_parser_is_closed_unique_and_bounded() {
        assert_eq!(
            parse_scopes("workspace:read,search:read").unwrap(),
            [ApiKeyScope::WorkspaceRead, ApiKeyScope::SearchRead]
        );
        for scopes in [
            "",
            "workspace:read,workspace:read",
            "workspace:read,secret:scope",
        ] {
            let error = parse_scopes(scopes).unwrap_err();
            if !scopes.is_empty() {
                assert!(!error.to_string().contains(scopes));
            }
        }
    }
}
