use std::{
    env, fmt,
    io::{self, Write},
};

use socialname_protocol::{ApiKeyScope, OrganizationRole};
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    api_key::{ApiKeyToken, parse_scopes, scope_values},
    database::{DATABASE_URL_ENV, DatabaseError, connect_database, database_url_from_env},
};

pub const WORKSPACE_SLUG_ENV: &str = "SOCIALNAME_WORKSPACE_SLUG";
pub const WORKSPACE_DISPLAY_NAME_ENV: &str = "SOCIALNAME_WORKSPACE_DISPLAY_NAME";
pub const MEMBERSHIP_SUBJECT_ENV: &str = "SOCIALNAME_MEMBERSHIP_SUBJECT";
pub const WORKSPACE_ID_ENV: &str = "SOCIALNAME_WORKSPACE_ID";
pub const MEMBERSHIP_ID_ENV: &str = "SOCIALNAME_MEMBERSHIP_ID";
pub const TARGET_MEMBERSHIP_ID_ENV: &str = "SOCIALNAME_TARGET_MEMBERSHIP_ID";
pub const API_KEY_ID_ENV: &str = "SOCIALNAME_API_KEY_ID";
pub const API_KEY_SCOPES_ENV: &str = "SOCIALNAME_API_KEY_SCOPES";
pub const API_KEY_EXPIRES_AT_ENV: &str = "SOCIALNAME_API_KEY_EXPIRES_AT_UNIX_MS";
pub const DAILY_TARGET_LIMIT_ENV: &str = "SOCIALNAME_DAILY_TARGET_LIMIT";
pub const API_KEY_DAILY_TARGET_LIMIT_ENV: &str = "SOCIALNAME_API_KEY_DAILY_TARGET_LIMIT";

const MAXIMUM_DAILY_TARGET_LIMIT: u32 = 1_000_000;

#[derive(Debug)]
pub struct IssuedApiKey {
    pub workspace_id: Uuid,
    pub membership_id: Uuid,
    pub api_key_id: Uuid,
    token: ApiKeyToken,
}

impl IssuedApiKey {
    pub fn write_once_to_stdout(&self) -> io::Result<()> {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        self.write_once_to(&mut output)?;
        output.flush()
    }

    fn write_once_to(&self, mut output: impl Write) -> io::Result<()> {
        writeln!(output, "workspace_id={}", self.workspace_id)?;
        writeln!(output, "membership_id={}", self.membership_id)?;
        writeln!(output, "api_key_id={}", self.api_key_id)?;
        writeln!(output, "api_key={}", self.token.expose())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeveloperQuotaPolicyOutput {
    pub workspace_id: Uuid,
    pub daily_target_limit: u32,
    pub api_key_daily_target_limit: u32,
    pub changed: bool,
}

impl DeveloperQuotaPolicyOutput {
    pub fn write_to_stdout(self) -> io::Result<()> {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        writeln!(output, "workspace_id={}", self.workspace_id)?;
        writeln!(output, "daily_target_limit={}", self.daily_target_limit)?;
        writeln!(
            output,
            "api_key_daily_target_limit={}",
            self.api_key_daily_target_limit
        )?;
        writeln!(output, "changed={}", self.changed)?;
        output.flush()
    }
}

pub async fn bootstrap_workspace_from_env() -> Result<IssuedApiKey, WorkspaceOperatorError> {
    let database_url = database_url_from_env(DATABASE_URL_ENV)?;
    let config = BootstrapConfig::from_env()?;
    let pool = connect_database(&database_url, 1).await?;
    let result = bootstrap_workspace(&pool, config).await;
    pool.close().await;
    result
}

pub async fn issue_api_key_from_env() -> Result<IssuedApiKey, WorkspaceOperatorError> {
    let database_url = database_url_from_env(DATABASE_URL_ENV)?;
    let config = ExistingWorkspaceConfig::from_env()?;
    let pool = connect_database(&database_url, 1).await?;
    let result = issue_api_key(&pool, config).await;
    pool.close().await;
    result
}

pub async fn revoke_api_key_from_env() -> Result<Uuid, WorkspaceOperatorError> {
    let database_url = database_url_from_env(DATABASE_URL_ENV)?;
    let config = RevokeConfig::from_env()?;
    let pool = connect_database(&database_url, 1).await?;
    let result = revoke_api_key(&pool, config).await;
    pool.close().await;
    result
}

pub async fn set_developer_quota_from_env()
-> Result<DeveloperQuotaPolicyOutput, WorkspaceOperatorError> {
    let database_url = database_url_from_env(DATABASE_URL_ENV)?;
    let config = DeveloperQuotaConfig::from_env()?;
    let pool = connect_database(&database_url, 1).await?;
    let result = set_developer_quota(&pool, config).await;
    pool.close().await;
    result
}

struct BootstrapConfig {
    slug: String,
    display_name: String,
    membership_subject: String,
    scopes: Vec<ApiKeyScope>,
    expires_at_unix_ms: Option<i64>,
}

impl BootstrapConfig {
    fn from_env() -> Result<Self, WorkspaceOperatorError> {
        let slug = required_env(WORKSPACE_SLUG_ENV)?;
        let display_name = required_env(WORKSPACE_DISPLAY_NAME_ENV)?;
        let membership_subject = required_env(MEMBERSHIP_SUBJECT_ENV)?;
        validate_slug(&slug)?;
        validate_bounded_text(WORKSPACE_DISPLAY_NAME_ENV, &display_name, 200)?;
        validate_bounded_text(MEMBERSHIP_SUBJECT_ENV, &membership_subject, 200)?;
        Ok(Self {
            slug,
            display_name,
            membership_subject,
            scopes: scopes_from_env()?,
            expires_at_unix_ms: optional_expiry_from_env()?,
        })
    }
}

struct ExistingWorkspaceConfig {
    workspace_id: Uuid,
    membership_id: Uuid,
    target_membership_id: Uuid,
    scopes: Vec<ApiKeyScope>,
    expires_at_unix_ms: Option<i64>,
}

impl ExistingWorkspaceConfig {
    fn from_env() -> Result<Self, WorkspaceOperatorError> {
        let membership_id = uuid_from_env(MEMBERSHIP_ID_ENV)?;
        Ok(Self {
            workspace_id: uuid_from_env(WORKSPACE_ID_ENV)?,
            membership_id,
            target_membership_id: optional_uuid_from_env(TARGET_MEMBERSHIP_ID_ENV)?
                .unwrap_or(membership_id),
            scopes: scopes_from_env()?,
            expires_at_unix_ms: optional_expiry_from_env()?,
        })
    }
}

struct RevokeConfig {
    workspace_id: Uuid,
    membership_id: Uuid,
    api_key_id: Uuid,
}

impl RevokeConfig {
    fn from_env() -> Result<Self, WorkspaceOperatorError> {
        Ok(Self {
            workspace_id: uuid_from_env(WORKSPACE_ID_ENV)?,
            membership_id: uuid_from_env(MEMBERSHIP_ID_ENV)?,
            api_key_id: uuid_from_env(API_KEY_ID_ENV)?,
        })
    }
}

#[derive(Clone, Copy)]
struct DeveloperQuotaConfig {
    workspace_id: Uuid,
    membership_id: Uuid,
    daily_target_limit: u32,
    api_key_daily_target_limit: u32,
}

impl DeveloperQuotaConfig {
    fn from_env() -> Result<Self, WorkspaceOperatorError> {
        let daily_target_limit = positive_bounded_u32_from_env(DAILY_TARGET_LIMIT_ENV)?;
        let api_key_daily_target_limit =
            positive_bounded_u32_from_env(API_KEY_DAILY_TARGET_LIMIT_ENV)?;
        if api_key_daily_target_limit > daily_target_limit {
            return Err(WorkspaceOperatorError::InvalidConfiguration(
                API_KEY_DAILY_TARGET_LIMIT_ENV,
            ));
        }
        Ok(Self {
            workspace_id: uuid_from_env(WORKSPACE_ID_ENV)?,
            membership_id: uuid_from_env(MEMBERSHIP_ID_ENV)?,
            daily_target_limit,
            api_key_daily_target_limit,
        })
    }
}

async fn bootstrap_workspace(
    pool: &PgPool,
    config: BootstrapConfig,
) -> Result<IssuedApiKey, WorkspaceOperatorError> {
    let workspace_id = Uuid::new_v4();
    let membership_id = Uuid::new_v4();
    let api_key_id = Uuid::new_v4();
    let audit_event_id = Uuid::new_v4();
    let token = ApiKeyToken::generate();
    let secret_hash = token.secret_hash();
    let scopes = scope_values(&config.scopes);
    let mut transaction = begin_tenant_transaction(pool, workspace_id).await?;

    sqlx::query(
        "INSERT INTO tenants (id, slug, display_name, created_at, updated_at) \
         VALUES ($1, $2, $3, clock_timestamp(), clock_timestamp())",
    )
    .bind(workspace_id)
    .bind(config.slug)
    .bind(config.display_name)
    .execute(&mut *transaction)
    .await
    .map_err(map_database_operation)?;
    sqlx::query(
        "INSERT INTO memberships \
         (id, tenant_id, subject_id, display_name, role, created_at, updated_at) \
         VALUES (\
            $1, $2, $3, 'Workspace owner', 'owner', \
            clock_timestamp(), clock_timestamp()\
         )",
    )
    .bind(membership_id)
    .bind(workspace_id)
    .bind(config.membership_subject)
    .execute(&mut *transaction)
    .await
    .map_err(map_database_operation)?;
    insert_api_key(
        &mut transaction,
        workspace_id,
        membership_id,
        api_key_id,
        &token,
        &secret_hash,
        &scopes,
        config.expires_at_unix_ms,
    )
    .await?;
    insert_audit_event(
        &mut transaction,
        audit_event_id,
        workspace_id,
        membership_id,
        "workspace.bootstrap",
        "workspace",
        workspace_id,
    )
    .await?;
    transaction.commit().await.map_err(map_database_operation)?;

    Ok(IssuedApiKey {
        workspace_id,
        membership_id,
        api_key_id,
        token,
    })
}

async fn issue_api_key(
    pool: &PgPool,
    config: ExistingWorkspaceConfig,
) -> Result<IssuedApiKey, WorkspaceOperatorError> {
    let api_key_id = Uuid::new_v4();
    let audit_event_id = Uuid::new_v4();
    let token = ApiKeyToken::generate();
    let secret_hash = token.secret_hash();
    let scopes = scope_values(&config.scopes);
    let mut transaction = begin_tenant_transaction(pool, config.workspace_id).await?;
    let operator_role =
        require_active_operator(&mut transaction, config.workspace_id, config.membership_id)
            .await?;
    let target_role = require_active_key_target(
        &mut transaction,
        config.workspace_id,
        config.target_membership_id,
    )
    .await?;
    if (operator_role == OrganizationRole::Administrator
        && config.target_membership_id != config.membership_id
        && !matches!(
            target_role,
            OrganizationRole::Member | OrganizationRole::Viewer
        ))
        || config
            .scopes
            .iter()
            .any(|scope| !target_role.permits_scope(*scope))
    {
        return Err(WorkspaceOperatorError::Forbidden);
    }
    insert_api_key(
        &mut transaction,
        config.workspace_id,
        config.target_membership_id,
        api_key_id,
        &token,
        &secret_hash,
        &scopes,
        config.expires_at_unix_ms,
    )
    .await?;
    insert_audit_event(
        &mut transaction,
        audit_event_id,
        config.workspace_id,
        config.membership_id,
        "api_key.issue",
        "api_key",
        api_key_id,
    )
    .await?;
    transaction.commit().await.map_err(map_database_operation)?;

    Ok(IssuedApiKey {
        workspace_id: config.workspace_id,
        membership_id: config.target_membership_id,
        api_key_id,
        token,
    })
}

async fn revoke_api_key(
    pool: &PgPool,
    config: RevokeConfig,
) -> Result<Uuid, WorkspaceOperatorError> {
    let mut transaction = begin_tenant_transaction(pool, config.workspace_id).await?;
    require_active_operator(&mut transaction, config.workspace_id, config.membership_id).await?;
    let result = sqlx::query(
        "UPDATE api_keys \
         SET state = 'revoked', revoked_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2 AND state <> 'revoked'",
    )
    .bind(config.workspace_id)
    .bind(config.api_key_id)
    .execute(&mut *transaction)
    .await
    .map_err(map_database_operation)?;
    if result.rows_affected() != 1 {
        return Err(WorkspaceOperatorError::NotFound);
    }
    insert_audit_event(
        &mut transaction,
        Uuid::new_v4(),
        config.workspace_id,
        config.membership_id,
        "api_key.revoke",
        "api_key",
        config.api_key_id,
    )
    .await?;
    transaction.commit().await.map_err(map_database_operation)?;
    Ok(config.api_key_id)
}

async fn set_developer_quota(
    pool: &PgPool,
    config: DeveloperQuotaConfig,
) -> Result<DeveloperQuotaPolicyOutput, WorkspaceOperatorError> {
    let mut transaction = begin_tenant_transaction(pool, config.workspace_id).await?;
    require_active_operator(&mut transaction, config.workspace_id, config.membership_id).await?;
    let existing: Option<(i32, i32)> = sqlx::query_as(
        "SELECT daily_target_limit, api_key_daily_target_limit \
         FROM developer_quota_policies \
         WHERE tenant_id = $1 \
         FOR UPDATE",
    )
    .bind(config.workspace_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(map_database_operation)?;
    let Some((existing_tenant_limit, existing_api_key_limit)) = existing else {
        return Err(WorkspaceOperatorError::NotFound);
    };
    let (current_tenant_usage, maximum_current_api_key_usage): (i64, i64) = sqlx::query_as(
        r#"
        WITH bounds AS (
            SELECT
                statement_timestamp() AS generated_at,
                date_trunc('day', statement_timestamp() AT TIME ZONE 'UTC')
                    AT TIME ZONE 'UTC' AS period_started_at
        ),
        key_usage AS (
            SELECT
                usage.api_key_id,
                sum(usage.quantity)::bigint AS quantity
            FROM developer_usage_records AS usage
            CROSS JOIN bounds
            WHERE usage.tenant_id = $1
              AND usage.occurred_at >= bounds.period_started_at
              AND usage.occurred_at < bounds.generated_at
              AND usage.retained_until > bounds.generated_at
            GROUP BY usage.api_key_id
        )
        SELECT
            COALESCE(sum(quantity), 0)::bigint,
            COALESCE(max(quantity) FILTER (WHERE api_key_id IS NOT NULL), 0)::bigint
        FROM key_usage
        "#,
    )
    .bind(config.workspace_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_database_operation)?;
    if i64::from(config.daily_target_limit) < current_tenant_usage
        || i64::from(config.api_key_daily_target_limit) < maximum_current_api_key_usage
    {
        return Err(WorkspaceOperatorError::QuotaBelowCurrentUsage);
    }

    let daily_target_limit = i32::try_from(config.daily_target_limit)
        .map_err(|_| WorkspaceOperatorError::InvalidConfiguration(DAILY_TARGET_LIMIT_ENV))?;
    let api_key_daily_target_limit =
        i32::try_from(config.api_key_daily_target_limit).map_err(|_| {
            WorkspaceOperatorError::InvalidConfiguration(API_KEY_DAILY_TARGET_LIMIT_ENV)
        })?;
    let changed = existing_tenant_limit != daily_target_limit
        || existing_api_key_limit != api_key_daily_target_limit;
    if changed {
        sqlx::query(
            "UPDATE developer_quota_policies \
             SET daily_target_limit = $2, api_key_daily_target_limit = $3, \
                 updated_at = clock_timestamp() \
             WHERE tenant_id = $1",
        )
        .bind(config.workspace_id)
        .bind(daily_target_limit)
        .bind(api_key_daily_target_limit)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_operation)?;
        sqlx::query(
            "INSERT INTO audit_events (\
                id, tenant_id, actor_membership_id, action, resource_kind, \
                resource_id, occurred_at, details\
             ) VALUES (\
                $1, $2, $3, 'developer_quota.update', 'workspace', $2, \
                clock_timestamp(), \
                jsonb_build_object(\
                    'daily_target_limit', $4::integer, \
                    'api_key_daily_target_limit', $5::integer\
                )\
             )",
        )
        .bind(Uuid::new_v4())
        .bind(config.workspace_id)
        .bind(config.membership_id)
        .bind(daily_target_limit)
        .bind(api_key_daily_target_limit)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_operation)?;
    }
    transaction.commit().await.map_err(map_database_operation)?;
    Ok(DeveloperQuotaPolicyOutput {
        workspace_id: config.workspace_id,
        daily_target_limit: config.daily_target_limit,
        api_key_daily_target_limit: config.api_key_daily_target_limit,
        changed,
    })
}

#[allow(clippy::too_many_arguments)]
async fn insert_api_key(
    transaction: &mut Transaction<'_, Postgres>,
    workspace_id: Uuid,
    membership_id: Uuid,
    api_key_id: Uuid,
    token: &ApiKeyToken,
    secret_hash: &[u8; 32],
    scopes: &[String],
    expires_at_unix_ms: Option<i64>,
) -> Result<(), WorkspaceOperatorError> {
    sqlx::query(
        "INSERT INTO api_keys (\
            id, tenant_id, created_by_membership_id, scopes, created_at, expires_at\
         ) VALUES (\
            $1, $2, $3, $4, clock_timestamp(), \
            CASE WHEN $5::bigint IS NULL THEN NULL \
                 ELSE to_timestamp($5::double precision / 1000.0) END\
         )",
    )
    .bind(api_key_id)
    .bind(workspace_id)
    .bind(membership_id)
    .bind(scopes)
    .bind(expires_at_unix_ms)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_operation)?;
    sqlx::query(
        "INSERT INTO api_key_credentials \
         (key_prefix, tenant_id, api_key_id, secret_hash, created_at) \
         VALUES ($1, $2, $3, $4, clock_timestamp())",
    )
    .bind(token.key_prefix())
    .bind(workspace_id)
    .bind(api_key_id)
    .bind(&secret_hash[..])
    .execute(&mut **transaction)
    .await
    .map_err(map_database_operation)?;
    Ok(())
}

async fn insert_audit_event(
    transaction: &mut Transaction<'_, Postgres>,
    event_id: Uuid,
    workspace_id: Uuid,
    membership_id: Uuid,
    action: &'static str,
    resource_kind: &'static str,
    resource_id: Uuid,
) -> Result<(), WorkspaceOperatorError> {
    sqlx::query(
        "INSERT INTO audit_events (\
            id, tenant_id, actor_membership_id, action, resource_kind, \
            resource_id, occurred_at\
         ) VALUES ($1, $2, $3, $4, $5, $6, clock_timestamp())",
    )
    .bind(event_id)
    .bind(workspace_id)
    .bind(membership_id)
    .bind(action)
    .bind(resource_kind)
    .bind(resource_id)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_operation)?;
    Ok(())
}

async fn begin_tenant_transaction(
    pool: &PgPool,
    workspace_id: Uuid,
) -> Result<Transaction<'_, Postgres>, WorkspaceOperatorError> {
    let mut transaction = pool.begin().await.map_err(map_database_operation)?;
    sqlx::query("SELECT set_config('socialname.tenant_id', $1, true)")
        .bind(workspace_id.to_string())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_operation)?;
    Ok(transaction)
}

async fn require_active_operator(
    transaction: &mut Transaction<'_, Postgres>,
    workspace_id: Uuid,
    membership_id: Uuid,
) -> Result<OrganizationRole, WorkspaceOperatorError> {
    let role: Option<String> = sqlx::query_scalar(
        "SELECT membership.role \
         FROM memberships AS membership \
         JOIN tenants AS tenant ON tenant.id = membership.tenant_id \
         WHERE membership.tenant_id = $1 AND membership.id = $2 \
           AND membership.state = 'active' \
           AND membership.role IN ('owner', 'administrator') \
           AND tenant.state = 'active'",
    )
    .bind(workspace_id)
    .bind(membership_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_database_operation)?;
    let role = role.ok_or(WorkspaceOperatorError::NotFound)?;
    OrganizationRole::parse(&role).map_err(|_| WorkspaceOperatorError::DatabaseOperationFailed)
}

async fn require_active_key_target(
    transaction: &mut Transaction<'_, Postgres>,
    workspace_id: Uuid,
    membership_id: Uuid,
) -> Result<OrganizationRole, WorkspaceOperatorError> {
    let role: Option<String> = sqlx::query_scalar(
        "SELECT role FROM memberships \
         WHERE tenant_id = $1 AND id = $2 AND state = 'active'",
    )
    .bind(workspace_id)
    .bind(membership_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_database_operation)?;
    let role = role.ok_or(WorkspaceOperatorError::NotFound)?;
    OrganizationRole::parse(&role).map_err(|_| WorkspaceOperatorError::DatabaseOperationFailed)
}

fn scopes_from_env() -> Result<Vec<ApiKeyScope>, WorkspaceOperatorError> {
    parse_scopes(&required_env(API_KEY_SCOPES_ENV)?)
        .map_err(|_| WorkspaceOperatorError::InvalidConfiguration(API_KEY_SCOPES_ENV))
}

fn optional_expiry_from_env() -> Result<Option<i64>, WorkspaceOperatorError> {
    let Some(value) = optional_env(API_KEY_EXPIRES_AT_ENV)? else {
        return Ok(None);
    };
    value
        .parse::<i64>()
        .ok()
        .filter(|timestamp| *timestamp > 0)
        .map(Some)
        .ok_or(WorkspaceOperatorError::InvalidConfiguration(
            API_KEY_EXPIRES_AT_ENV,
        ))
}

fn positive_bounded_u32_from_env(variable: &'static str) -> Result<u32, WorkspaceOperatorError> {
    required_env(variable)?
        .parse::<u32>()
        .ok()
        .filter(|value| (1..=MAXIMUM_DAILY_TARGET_LIMIT).contains(value))
        .ok_or(WorkspaceOperatorError::InvalidConfiguration(variable))
}

fn uuid_from_env(variable: &'static str) -> Result<Uuid, WorkspaceOperatorError> {
    Uuid::parse_str(&required_env(variable)?)
        .map_err(|_| WorkspaceOperatorError::InvalidConfiguration(variable))
}

fn optional_uuid_from_env(variable: &'static str) -> Result<Option<Uuid>, WorkspaceOperatorError> {
    optional_env(variable)?
        .map(|value| {
            Uuid::parse_str(&value)
                .map_err(|_| WorkspaceOperatorError::InvalidConfiguration(variable))
        })
        .transpose()
}

fn required_env(variable: &'static str) -> Result<String, WorkspaceOperatorError> {
    optional_env(variable)?.ok_or(WorkspaceOperatorError::MissingConfiguration(variable))
}

fn optional_env(variable: &'static str) -> Result<Option<String>, WorkspaceOperatorError> {
    match env::var(variable) {
        Ok(value) if value.is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => {
            Err(WorkspaceOperatorError::InvalidConfiguration(variable))
        }
    }
}

fn validate_slug(value: &str) -> Result<(), WorkspaceOperatorError> {
    let valid = !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(WorkspaceOperatorError::InvalidConfiguration(
            WORKSPACE_SLUG_ENV,
        ))
    }
}

fn validate_bounded_text(
    variable: &'static str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), WorkspaceOperatorError> {
    if !value.is_empty() && value.len() <= maximum_bytes && !value.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(WorkspaceOperatorError::InvalidConfiguration(variable))
    }
}

fn map_database_operation(error: sqlx::Error) -> WorkspaceOperatorError {
    let code = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code);
    if code.as_deref() == Some("23505") {
        WorkspaceOperatorError::Conflict
    } else {
        WorkspaceOperatorError::DatabaseOperationFailed
    }
}

#[derive(Debug, Error)]
pub enum WorkspaceOperatorError {
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error("{0} is required")]
    MissingConfiguration(&'static str),
    #[error("{0} is invalid; the supplied value is omitted")]
    InvalidConfiguration(&'static str),
    #[error("workspace or API key already exists")]
    Conflict,
    #[error("workspace, membership, or API key was not found")]
    NotFound,
    #[error("membership role does not permit the requested API key")]
    Forbidden,
    #[error("developer quota cannot be lower than current UTC-period usage")]
    QuotaBelowCurrentUsage,
    #[error("workspace operator database operation failed")]
    DatabaseOperationFailed,
}

impl fmt::Display for IssuedApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "IssuedApiKey {{ workspace_id: {}, membership_id: {}, api_key_id: {}, api_key: [REDACTED] }}",
            self.workspace_id, self.membership_id, self.api_key_id
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DATABASE_URL_ENV: &str = "SOCIALNAME_TEST_DATABASE_URL";

    #[test]
    fn validation_errors_name_variables_without_echoing_values() {
        let secret = "Secret Workspace\n";
        let error = validate_bounded_text(WORKSPACE_DISPLAY_NAME_ENV, secret, 200).unwrap_err();
        assert!(error.to_string().contains(WORKSPACE_DISPLAY_NAME_ENV));
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));
    }

    #[test]
    fn issued_key_display_is_redacted() {
        let issued = IssuedApiKey {
            workspace_id: Uuid::nil(),
            membership_id: Uuid::nil(),
            api_key_id: Uuid::nil(),
            token: ApiKeyToken::generate(),
        };
        let exposed = issued.token.expose().to_string();
        assert!(!issued.to_string().contains(&exposed));
        assert!(!format!("{issued:?}").contains(&exposed));

        let mut output = Vec::new();
        issued.write_once_to(&mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.matches(&exposed).count(), 1);
        assert_eq!(
            output
                .lines()
                .filter(|line| line.starts_with("api_key="))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn workspace_and_api_key_operator_lifecycle_is_transactional() {
        let Ok(database_url) = env::var(TEST_DATABASE_URL_ENV) else {
            eprintln!("skipping operator integration test; {TEST_DATABASE_URL_ENV} is not set");
            return;
        };
        crate::migrate_database(&database_url).await.unwrap();
        let pool = connect_database(&database_url, 1).await.unwrap();
        let slug = format!("operator-test-{}", Uuid::new_v4().simple());
        let bootstrap = bootstrap_workspace(
            &pool,
            BootstrapConfig {
                slug: slug.clone(),
                display_name: "Operator test".to_owned(),
                membership_subject: "operator-test-subject".to_owned(),
                scopes: vec![ApiKeyScope::WorkspaceRead],
                expires_at_unix_ms: None,
            },
        )
        .await
        .unwrap();
        let initial_hash = bootstrap.token.secret_hash();
        let stored_hash: Vec<u8> =
            sqlx::query_scalar("SELECT secret_hash FROM api_key_credentials WHERE api_key_id = $1")
                .bind(bootstrap.api_key_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored_hash, initial_hash);

        let issued = issue_api_key(
            &pool,
            ExistingWorkspaceConfig {
                workspace_id: bootstrap.workspace_id,
                membership_id: bootstrap.membership_id,
                target_membership_id: bootstrap.membership_id,
                scopes: vec![ApiKeyScope::SearchRead],
                expires_at_unix_ms: None,
            },
        )
        .await
        .unwrap();
        assert_ne!(issued.api_key_id, bootstrap.api_key_id);
        revoke_api_key(
            &pool,
            RevokeConfig {
                workspace_id: bootstrap.workspace_id,
                membership_id: bootstrap.membership_id,
                api_key_id: issued.api_key_id,
            },
        )
        .await
        .unwrap();

        let state: String =
            sqlx::query_scalar("SELECT state FROM api_keys WHERE tenant_id = $1 AND id = $2")
                .bind(bootstrap.workspace_id)
                .bind(issued.api_key_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(state, "revoked");
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events \
             WHERE tenant_id = $1 AND action IN (\
                'workspace.bootstrap', 'api_key.issue', 'api_key.revoke'\
             )",
        )
        .bind(bootstrap.workspace_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audit_count, 3);

        let default_quota: (i32, i32) = sqlx::query_as(
            "SELECT daily_target_limit, api_key_daily_target_limit \
             FROM developer_quota_policies WHERE tenant_id = $1",
        )
        .bind(bootstrap.workspace_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(default_quota, (10_000, 2_000));
        let quota_config = DeveloperQuotaConfig {
            workspace_id: bootstrap.workspace_id,
            membership_id: bootstrap.membership_id,
            daily_target_limit: 500,
            api_key_daily_target_limit: 100,
        };
        let changed_quota = set_developer_quota(&pool, quota_config).await.unwrap();
        assert!(changed_quota.changed);
        assert_eq!(changed_quota.daily_target_limit, 500);
        assert_eq!(changed_quota.api_key_daily_target_limit, 100);
        let unchanged_quota = set_developer_quota(&pool, quota_config).await.unwrap();
        assert!(!unchanged_quota.changed);
        let quota_audit_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events \
             WHERE tenant_id = $1 AND action = 'developer_quota.update'",
        )
        .bind(bootstrap.workspace_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(quota_audit_count, 1);

        let viewer_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO memberships (\
                id, tenant_id, subject_id, role, created_at, updated_at\
             ) VALUES (\
                $1, $2, 'operator-test-viewer', 'viewer', \
                clock_timestamp(), clock_timestamp()\
             )",
        )
        .bind(viewer_id)
        .bind(bootstrap.workspace_id)
        .execute(&pool)
        .await
        .unwrap();
        let viewer_key = issue_api_key(
            &pool,
            ExistingWorkspaceConfig {
                workspace_id: bootstrap.workspace_id,
                membership_id: bootstrap.membership_id,
                target_membership_id: viewer_id,
                scopes: vec![ApiKeyScope::WorkspaceRead],
                expires_at_unix_ms: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(viewer_key.membership_id, viewer_id);
        let viewer_write = issue_api_key(
            &pool,
            ExistingWorkspaceConfig {
                workspace_id: bootstrap.workspace_id,
                membership_id: bootstrap.membership_id,
                target_membership_id: viewer_id,
                scopes: vec![ApiKeyScope::WatchWrite],
                expires_at_unix_ms: None,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(viewer_write, WorkspaceOperatorError::Forbidden));
        let viewer_issue = issue_api_key(
            &pool,
            ExistingWorkspaceConfig {
                workspace_id: bootstrap.workspace_id,
                membership_id: viewer_id,
                target_membership_id: viewer_id,
                scopes: vec![ApiKeyScope::WorkspaceRead],
                expires_at_unix_ms: None,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(viewer_issue, WorkspaceOperatorError::NotFound));
        let viewer_quota = set_developer_quota(
            &pool,
            DeveloperQuotaConfig {
                workspace_id: bootstrap.workspace_id,
                membership_id: viewer_id,
                daily_target_limit: 600,
                api_key_daily_target_limit: 100,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(viewer_quota, WorkspaceOperatorError::NotFound));

        let duplicate = bootstrap_workspace(
            &pool,
            BootstrapConfig {
                slug,
                display_name: "Duplicate".to_owned(),
                membership_subject: "duplicate-subject".to_owned(),
                scopes: vec![ApiKeyScope::WorkspaceRead],
                expires_at_unix_ms: None,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(duplicate, WorkspaceOperatorError::Conflict));
        pool.close().await;
    }
}
