use axum::http::{HeaderMap, header::AUTHORIZATION};
use socialname_protocol::ApiKeyScope;
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::api_key::ApiKeyToken;

#[derive(Clone, Debug)]
pub(crate) struct AuthenticatedPrincipal {
    pub(crate) workspace_id: Uuid,
    pub(crate) api_key_id: Uuid,
    pub(crate) key_prefix: String,
    pub(crate) scopes: Vec<ApiKeyScope>,
    pub(crate) expires_at_unix_ms: Option<i64>,
}

pub(crate) async fn authenticate(
    pool: &PgPool,
    headers: &HeaderMap,
    required_scope: ApiKeyScope,
) -> Result<AuthenticatedPrincipal, AuthenticationError> {
    let token = bearer_token(headers)?;
    let secret_hash = token.secret_hash();
    let candidate: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT tenant_id, api_key_id \
         FROM socialname_authenticate_api_key($1, $2)",
    )
    .bind(token.key_prefix())
    .bind(&secret_hash[..])
    .fetch_optional(pool)
    .await
    .map_err(|_| AuthenticationError::Unavailable)?;
    let Some((workspace_id, api_key_id)) = candidate else {
        return Err(AuthenticationError::InvalidCredential);
    };

    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| AuthenticationError::Unavailable)?;
    sqlx::query("SELECT set_config('socialname.tenant_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthenticationError::Unavailable)?;
    let key: Option<(Vec<String>, Option<i64>)> = sqlx::query_as(
        "SELECT key.scopes, \
                (EXTRACT(EPOCH FROM key.expires_at) * 1000)::bigint \
         FROM api_keys AS key \
         JOIN tenants AS tenant ON tenant.id = key.tenant_id \
         WHERE key.tenant_id = $1 AND key.id = $2 \
           AND key.state = 'active' AND tenant.state = 'active' \
           AND (key.expires_at IS NULL OR key.expires_at > clock_timestamp())",
    )
    .bind(workspace_id)
    .bind(api_key_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| AuthenticationError::Unavailable)?;
    let Some((stored_scopes, expires_at_unix_ms)) = key else {
        return Err(AuthenticationError::InvalidCredential);
    };
    let scopes = stored_scopes
        .iter()
        .map(|scope| ApiKeyScope::parse(scope))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AuthenticationError::Unavailable)?;
    if !scopes.contains(&required_scope) {
        return Err(AuthenticationError::Forbidden);
    }

    sqlx::query(
        "UPDATE api_keys \
         SET last_used_at = GREATEST(\
            created_at, clock_timestamp(), COALESCE(last_used_at, created_at)\
         ) \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(workspace_id)
    .bind(api_key_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| AuthenticationError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| AuthenticationError::Unavailable)?;

    Ok(AuthenticatedPrincipal {
        workspace_id,
        api_key_id,
        key_prefix: token.key_prefix().to_owned(),
        scopes,
        expires_at_unix_ms,
    })
}

fn bearer_token(headers: &HeaderMap) -> Result<ApiKeyToken, AuthenticationError> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values
        .next()
        .ok_or(AuthenticationError::InvalidCredential)?;
    if values.next().is_some() {
        return Err(AuthenticationError::InvalidCredential);
    }
    let value = value
        .to_str()
        .map_err(|_| AuthenticationError::InvalidCredential)?;
    let Some((scheme, credential)) = value.split_once(' ') else {
        return Err(AuthenticationError::InvalidCredential);
    };
    if !scheme.eq_ignore_ascii_case("bearer")
        || credential.is_empty()
        || credential.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(AuthenticationError::InvalidCredential);
    }
    ApiKeyToken::parse(credential).map_err(|_| AuthenticationError::InvalidCredential)
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum AuthenticationError {
    #[error("authentication credential is invalid")]
    InvalidCredential,
    #[error("API key does not grant the required scope")]
    Forbidden,
    #[error("authentication service is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn bearer_parser_accepts_one_strict_redacted_token() {
        let token = ApiKeyToken::generate();
        let exposed = token.expose().to_string();
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {exposed}")).unwrap(),
        );
        let parsed = bearer_token(&headers).unwrap();
        assert_eq!(parsed.key_prefix(), token.key_prefix());
        assert_eq!(parsed.secret_hash(), token.secret_hash());
    }

    #[test]
    fn bearer_parser_rejects_missing_malformed_and_duplicate_headers() {
        let token = ApiKeyToken::generate().expose().to_string();
        let cases = [
            HeaderMap::new(),
            HeaderMap::from_iter([(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Basic {token}")).unwrap(),
            )]),
            HeaderMap::from_iter([(
                AUTHORIZATION,
                HeaderValue::from_static("Bearer invalid-secret"),
            )]),
        ];
        for headers in cases {
            assert_eq!(
                bearer_token(&headers).unwrap_err(),
                AuthenticationError::InvalidCredential
            );
        }

        let mut duplicate = HeaderMap::new();
        duplicate.append(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        duplicate.append(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        assert_eq!(
            bearer_token(&duplicate).unwrap_err(),
            AuthenticationError::InvalidCredential
        );
    }
}
