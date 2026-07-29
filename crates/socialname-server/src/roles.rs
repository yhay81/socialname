//! Runtime-role provisioning shared by the `provision-roles` operator
//! command and the PostgreSQL integration gate.
//!
//! The column-limited grants live in `roles/application_grants.sql` and
//! `roles/worker_grants.sql` with a `{role}` placeholder. The integration
//! test renders the same templates for its test roles, so a production role
//! cannot drift from the tested one without failing the gate.

use std::{env, fmt, time::Duration};

use sqlx::Executor;
use thiserror::Error;

use crate::database::{DATABASE_URL_ENV, DatabaseError, connect_database, database_url_from_env};

pub const APPLICATION_ROLE_ENV: &str = "SOCIALNAME_APPLICATION_ROLE";
pub const APPLICATION_ROLE_PASSWORD_ENV: &str = "SOCIALNAME_APPLICATION_ROLE_PASSWORD";
pub const WORKER_ROLE_ENV: &str = "SOCIALNAME_WORKER_ROLE";
pub const WORKER_ROLE_PASSWORD_ENV: &str = "SOCIALNAME_WORKER_ROLE_PASSWORD";

const DEFAULT_APPLICATION_ROLE: &str = "socialname_app";
const DEFAULT_WORKER_ROLE: &str = "socialname_worker";
const PROVISION_TIMEOUT: Duration = Duration::from_secs(60);
const ROLE_PLACEHOLDER: &str = "{role}";
const MAXIMUM_ROLE_LENGTH: usize = 63;
const MAXIMUM_PASSWORD_LENGTH: usize = 512;

const APPLICATION_GRANTS_TEMPLATE: &str = include_str!("roles/application_grants.sql");
const WORKER_GRANTS_TEMPLATE: &str = include_str!("roles/worker_grants.sql");

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RoleProvisionError {
    #[error("{0} is required")]
    MissingEnvironment(&'static str),
    #[error("{0} must contain valid Unicode")]
    InvalidEnvironmentEncoding(&'static str),
    #[error(
        "{0} must start with a lowercase letter or underscore and contain only \
         lowercase letters, digits, and underscores, at most 63 bytes"
    )]
    InvalidRoleName(&'static str),
    #[error(
        "{0} must be a non-empty password of at most 512 bytes without \
         control characters or dollar signs"
    )]
    InvalidPassword(&'static str),
    #[error("the application and worker role names must be distinct")]
    DuplicateRoleName,
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error("role provisioning timed out")]
    ProvisionTimedOut,
    #[error("role provisioning failed")]
    ProvisionFailed,
}

/// Error for a value that is not a valid lowercase PostgreSQL identifier.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("invalid role name")]
pub struct InvalidRoleName;

/// Error for a password value the provisioning SQL cannot safely embed.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("invalid role password")]
pub struct InvalidRolePassword;

/// A validated lowercase PostgreSQL role identifier. Validation exists so a
/// configured name can be embedded in role DDL without identifier quoting or
/// injection concerns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleName(String);

impl RoleName {
    pub fn new(value: &str) -> Result<Self, InvalidRoleName> {
        let valid_length = (1..=MAXIMUM_ROLE_LENGTH).contains(&value.len());
        let valid_start = value
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first == '_');
        let valid_characters = value.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        });
        if valid_length && valid_start && valid_characters {
            Ok(Self(value.to_owned()))
        } else {
            Err(InvalidRoleName)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A role password that the provisioning SQL can embed as a quoted literal.
/// Dollar signs are rejected so the surrounding dollar-quoted `DO` block can
/// never be terminated by password content; quotes are doubled at render
/// time. `Debug` never prints the value.
#[derive(Clone, PartialEq, Eq)]
pub struct RolePassword(String);

impl fmt::Debug for RolePassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RolePassword(redacted)")
    }
}

impl RolePassword {
    pub fn new(value: &str) -> Result<Self, InvalidRolePassword> {
        let valid_length = (1..=MAXIMUM_PASSWORD_LENGTH).contains(&value.len());
        let valid_characters = value
            .chars()
            .all(|character| !character.is_control() && character != '$');
        if valid_length && valid_characters {
            Ok(Self(value.to_owned()))
        } else {
            Err(InvalidRolePassword)
        }
    }

    fn quoted_literal(&self) -> String {
        self.0.replace('\'', "''")
    }
}

/// The nonsecret result of a completed provisioning run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionedRuntimeRoles {
    pub application_role: RoleName,
    pub worker_role: RoleName,
}

/// Renders the complete idempotent creation and grant SQL for the non-owner
/// application role.
pub fn render_application_role_sql(role: &RoleName, password: &RolePassword) -> String {
    render_role_sql(role, password, APPLICATION_GRANTS_TEMPLATE)
}

/// Renders the complete idempotent creation and grant SQL for the non-owner
/// worker role.
pub fn render_worker_role_sql(role: &RoleName, password: &RolePassword) -> String {
    render_role_sql(role, password, WORKER_GRANTS_TEMPLATE)
}

fn render_role_sql(role: &RoleName, password: &RolePassword, grants_template: &str) -> String {
    let role = role.as_str();
    let password = password.quoted_literal();
    // `SUPERUSER` and `BYPASSRLS` can only be *set* by a superuser, even when
    // set to their negative form, and a managed PostgreSQL owner is not one.
    // Creation still states them because they are the defaults there, while
    // reprovisioning asserts the invariant instead of reasserting it: a role
    // that somehow holds either attribute fails the transaction rather than
    // silently keeping a privilege that would defeat forced tenant RLS.
    let creation = format!(
        "DO $$\n\
         BEGIN\n\
             IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') THEN\n\
                 CREATE ROLE {role}\n\
                     LOGIN PASSWORD '{password}'\n\
                     NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;\n\
             END IF;\n\
         END\n\
         $$;\n\
         ALTER ROLE {role}\n\
             LOGIN PASSWORD '{password}'\n\
             NOCREATEDB NOCREATEROLE NOINHERIT;\n\
         DO $$\n\
         BEGIN\n\
             IF EXISTS (\n\
                 SELECT FROM pg_roles\n\
                 WHERE rolname = '{role}'\n\
                   AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole)\n\
             ) THEN\n\
                 RAISE EXCEPTION\n\
                     'runtime role {role} holds an elevated attribute';\n\
             END IF;\n\
         END\n\
         $$;\n"
    );
    let grants = grants_template.replace(ROLE_PLACEHOLDER, role);
    debug_assert!(!grants.contains(ROLE_PLACEHOLDER));
    format!("{creation}{grants}")
}

/// Reads the schema-owner database URL, role names (defaulting to
/// `socialname_app` and `socialname_worker`), and required passwords from the
/// environment, then provisions both runtime roles transactionally.
pub async fn provision_runtime_roles_from_env()
-> Result<ProvisionedRuntimeRoles, RoleProvisionError> {
    let database_url = database_url_from_env(DATABASE_URL_ENV)?;
    let application_role = role_name_from_env(APPLICATION_ROLE_ENV, DEFAULT_APPLICATION_ROLE)?;
    let worker_role = role_name_from_env(WORKER_ROLE_ENV, DEFAULT_WORKER_ROLE)?;
    if application_role == worker_role {
        return Err(RoleProvisionError::DuplicateRoleName);
    }
    let application_password = role_password_from_env(APPLICATION_ROLE_PASSWORD_ENV)?;
    let worker_password = role_password_from_env(WORKER_ROLE_PASSWORD_ENV)?;
    provision_runtime_roles(
        &database_url,
        &application_role,
        &application_password,
        &worker_role,
        &worker_password,
    )
    .await?;
    Ok(ProvisionedRuntimeRoles {
        application_role,
        worker_role,
    })
}

/// Provisions both runtime roles in one transaction against the schema-owner
/// connection. Reprovisioning is idempotent: creation is conditional, the
/// password and attributes are always reasserted, and the grants are
/// additive re-grants of the exact tested set.
pub async fn provision_runtime_roles(
    database_url: &str,
    application_role: &RoleName,
    application_password: &RolePassword,
    worker_role: &RoleName,
    worker_password: &RolePassword,
) -> Result<(), RoleProvisionError> {
    let pool = connect_database(database_url, 1).await?;
    let sql = format!(
        "{}{}",
        render_application_role_sql(application_role, application_password),
        render_worker_role_sql(worker_role, worker_password),
    );
    let provisioning = async {
        let mut transaction = pool
            .begin()
            .await
            .map_err(|_| RoleProvisionError::ProvisionFailed)?;
        transaction
            .execute(sqlx::raw_sql(&sql))
            .await
            .map_err(|_| RoleProvisionError::ProvisionFailed)?;
        transaction
            .commit()
            .await
            .map_err(|_| RoleProvisionError::ProvisionFailed)
    };
    let result = tokio::time::timeout(PROVISION_TIMEOUT, provisioning)
        .await
        .map_err(|_| RoleProvisionError::ProvisionTimedOut)
        .and_then(|inner| inner);
    pool.close().await;
    result
}

fn role_name_from_env(
    variable: &'static str,
    default: &str,
) -> Result<RoleName, RoleProvisionError> {
    let value = optional_env(variable)?.unwrap_or_else(|| default.to_owned());
    RoleName::new(&value).map_err(|InvalidRoleName| RoleProvisionError::InvalidRoleName(variable))
}

fn role_password_from_env(variable: &'static str) -> Result<RolePassword, RoleProvisionError> {
    let value = optional_env(variable)?.ok_or(RoleProvisionError::MissingEnvironment(variable))?;
    RolePassword::new(&value)
        .map_err(|InvalidRolePassword| RoleProvisionError::InvalidPassword(variable))
}

fn optional_env(variable: &'static str) -> Result<Option<String>, RoleProvisionError> {
    match env::var(variable) {
        Ok(value) if value.is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => {
            Err(RoleProvisionError::InvalidEnvironmentEncoding(variable))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_names_are_strictly_validated() {
        for valid in [
            "socialname_app",
            "_x",
            "a1_b2",
            "socialname_migration_test_worker",
        ] {
            assert!(RoleName::new(valid).is_ok(), "{valid} should be accepted");
        }
        let overlong = "a".repeat(MAXIMUM_ROLE_LENGTH + 1);
        for invalid in [
            "",
            "App",
            "1app",
            "app-role",
            "app role",
            "app;--",
            overlong.as_str(),
        ] {
            assert_eq!(RoleName::new(invalid), Err(InvalidRoleName), "{invalid:?}");
        }
    }

    #[test]
    fn passwords_reject_control_characters_and_dollar_quoting() {
        assert!(RolePassword::new("socialname-test-password").is_ok());
        assert!(RolePassword::new("with'quote").is_ok());
        for invalid in ["", "with\nnewline", "with\u{0}nul", "with$dollar"] {
            assert_eq!(
                RolePassword::new(invalid),
                Err(InvalidRolePassword),
                "{invalid:?}"
            );
        }
        let overlong = "a".repeat(MAXIMUM_PASSWORD_LENGTH + 1);
        assert_eq!(RolePassword::new(&overlong), Err(InvalidRolePassword));
    }

    #[test]
    fn password_debug_and_errors_never_reveal_the_value() {
        let password = RolePassword::new("secret-that-must-not-leak").unwrap();
        assert_eq!(format!("{password:?}"), "RolePassword(redacted)");
        let error = RoleProvisionError::InvalidPassword(APPLICATION_ROLE_PASSWORD_ENV);
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn rendered_role_sql_substitutes_every_placeholder_and_escapes_quotes() {
        let role = RoleName::new("socialname_app").unwrap();
        let password = RolePassword::new("pa'ss").unwrap();
        for sql in [
            render_application_role_sql(&role, &password),
            render_worker_role_sql(&role, &password),
        ] {
            assert!(!sql.contains(ROLE_PLACEHOLDER));
            assert!(sql.contains("CREATE ROLE socialname_app"));
            assert!(sql.contains("LOGIN PASSWORD 'pa''ss'"));
            assert!(sql.contains("NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS"));
            assert!(sql.contains("GRANT USAGE ON SCHEMA public TO socialname_app;"));
            // Reprovisioning must stay inside what a non-superuser owner of a
            // managed database is allowed to do.
            assert!(!sql.contains(
                "ALTER ROLE socialname_app\n    LOGIN PASSWORD 'pa''ss'\n    NOSUPERUSER"
            ));
            assert!(sql.contains("rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole"));
            assert!(sql.contains("holds an elevated attribute"));
        }
    }

    #[test]
    fn grant_templates_contain_no_concrete_role_names() {
        for template in [APPLICATION_GRANTS_TEMPLATE, WORKER_GRANTS_TEMPLATE] {
            assert!(template.contains(ROLE_PLACEHOLDER));
            assert!(!template.contains("socialname_migration_test"));
            assert!(!template.to_ascii_uppercase().contains("PASSWORD"));
        }
    }

    #[tokio::test]
    async fn provisioning_with_an_empty_url_fails_closed_without_echoing() {
        let role = RoleName::new("socialname_app").unwrap();
        let other = RoleName::new("socialname_worker").unwrap();
        let password = RolePassword::new("secret-that-must-not-leak").unwrap();
        let error = provision_runtime_roles("", &role, &password, &other, &password)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            RoleProvisionError::Database(DatabaseError::MissingUrl(DATABASE_URL_ENV))
        );
        assert!(!error.to_string().contains("secret"));
    }
}
