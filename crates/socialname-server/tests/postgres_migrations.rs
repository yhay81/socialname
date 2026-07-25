use std::{env, net::SocketAddr, time::Duration};

use axum::{
    body::{Body, to_bytes},
    http::{
        Request, StatusCode,
        header::{AUTHORIZATION, WWW_AUTHENTICATE},
    },
    response::Response,
};
use sha2::{Digest, Sha256};
use socialname_protocol::{ApiErrorCode, ApiErrorResponse, Validate, WorkspaceResource};
use socialname_server::{ServerConfig, build_router, migrate_database};
use sqlx::{Executor, PgPool, postgres::PgPoolOptions};
use tower::ServiceExt;
use uuid::Uuid;

const TEST_DATABASE_URL_ENV: &str = "SOCIALNAME_TEST_DATABASE_URL";
const TEST_APPLICATION_DATABASE_URL_ENV: &str = "SOCIALNAME_TEST_APPLICATION_DATABASE_URL";

#[tokio::test]
async fn initial_migration_enforces_tenant_evidence_and_deletion_boundaries() {
    let Ok(database_url) = env::var(TEST_DATABASE_URL_ENV) else {
        eprintln!("skipping PostgreSQL integration test; {TEST_DATABASE_URL_ENV} is not set");
        return;
    };

    migrate_database(&database_url).await.unwrap();
    migrate_database(&database_url).await.unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .unwrap();

    assert_schema_inventory(&pool).await;
    install_fixtures(&pool).await;
    install_api_key_fixtures(&pool).await;
    assert_api_key_scope_constraints(&pool).await;
    assert_tenant_isolation(&pool).await;
    assert_cross_tenant_references_are_rejected(&pool).await;
    assert_observations_are_immutable(&pool).await;
    assert_transition_and_delivery_safety(&pool).await;
    assert_deletion_deadlines_and_receipts(&pool).await;
    assert_authenticated_workspace_boundary(&pool).await;

    pool.close().await;
}

async fn assert_schema_inventory(pool: &PgPool) {
    let required_tables: i64 = sqlx::query_scalar(
        r#"
        WITH required(name) AS (
            VALUES
                ('tenants'), ('memberships'), ('api_keys'), ('api_key_credentials'),
                ('clients'), ('sites'),
                ('rule_packs'), ('rule_versions'), ('rule_health_records'),
                ('consent_grants'), ('consent_events'), ('searches'), ('search_targets'),
                ('watches'), ('watch_targets'), ('probe_jobs'), ('probe_job_consumers'),
                ('observations'), ('assertions'), ('assertion_support'), ('transitions'),
                ('transition_basis'), ('notification_endpoints'),
                ('notification_deliveries'), ('audit_events'), ('data_lineage_edges'),
                ('deletion_requests'), ('deletion_tasks'), ('deletion_receipts'),
                ('suppression_tokens')
        )
        SELECT count(*)
        FROM required
        JOIN pg_tables ON schemaname = 'public' AND tablename = required.name
        "#,
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(required_tables, 30);

    let tenant_policies: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_policies \
         WHERE schemaname = 'public' AND policyname = 'tenant_isolation'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(tenant_policies, 25);

    let forced_rls_tables: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_class \
         WHERE relnamespace = 'public'::regnamespace AND relkind = 'r' \
         AND relrowsecurity AND relforcerowsecurity",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(forced_rls_tables, 25);

    let plaintext_secret_columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns \
         WHERE table_schema = 'public' \
         AND ((table_name = 'api_keys' \
               AND column_name IN ('key_prefix', 'secret_hash', 'secret', 'token', 'plaintext')) \
           OR (table_name = 'notification_endpoints' \
               AND column_name IN ('destination', 'email', 'url')))",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(plaintext_secret_columns, 0);
}

async fn install_fixtures(pool: &PgPool) {
    pool.execute(sqlx::raw_sql(
        r#"
        INSERT INTO tenants (id, slug, display_name, created_at, updated_at)
        VALUES
            ('00000000-0000-0000-0000-000000000001', 'tenant-one', 'Tenant One',
             '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
            ('00000000-0000-0000-0000-000000000002', 'tenant-two', 'Tenant Two',
             '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');

        INSERT INTO memberships (
            id, tenant_id, subject_id, role, created_at, updated_at
        )
        VALUES
            ('00000000-0000-0000-0000-000000000011',
             '00000000-0000-0000-0000-000000000001',
             'subject-one', 'owner', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
            ('00000000-0000-0000-0000-000000000012',
             '00000000-0000-0000-0000-000000000002',
             'subject-two', 'owner', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');

        INSERT INTO sites (id, display_name, created_at, updated_at)
        VALUES ('github', 'GitHub', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');

        INSERT INTO rule_packs (
            id, version, pack_hash, state, created_at, published_at
        )
        VALUES (
            '00000000-0000-0000-0000-000000000020', 'fixture-v1',
            decode(repeat('20', 32), 'hex'), 'active',
            '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
        );

        INSERT INTO rule_versions (
            id, rule_pack_id, site_id, rule_hash, compiled_rule, enabled, created_at
        )
        VALUES (
            '00000000-0000-0000-0000-000000000021',
            '00000000-0000-0000-0000-000000000020',
            'github', decode(repeat('21', 32), 'hex'), '{}', true,
            '2026-01-01T00:00:00Z'
        );

        INSERT INTO consent_grants (
            id, tenant_id, membership_id, subject_kind, purpose,
            collection_profile_version, notice_version, source, granted_at
        )
        VALUES (
            '00000000-0000-0000-0000-000000000031',
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000011',
            'account', 'private_history', 'profile-v1', 'notice-v1', 'web',
            '2026-01-01T00:00:00Z'
        );

        INSERT INTO searches (
            id, tenant_id, requested_by_membership_id, idempotency_key_hash,
            mode, sync_policy, maximum_age_ms, region_classes, created_at, updated_at
        )
        VALUES (
            '00000000-0000-0000-0000-000000000041',
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000011',
            decode(repeat('41', 32), 'hex'), 'local', 'never', 60000,
            ARRAY['global'], '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
        );

        INSERT INTO search_targets (
            id, tenant_id, search_id, normalized_username, site_id, ordinal, created_at
        )
        VALUES (
            '00000000-0000-0000-0000-000000000042',
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000041',
            'fixture-user', 'github', 0, '2026-01-01T00:00:00Z'
        );

        INSERT INTO watches (
            id, tenant_id, created_by_membership_id, consent_grant_id,
            maximum_age_ms, interval_seconds, jitter_percent,
            maximum_probes_per_run, maximum_bytes_per_run, retention_days,
            region_classes, next_run_at, created_at, updated_at
        )
        VALUES (
            '00000000-0000-0000-0000-000000000051',
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000011',
            '00000000-0000-0000-0000-000000000031',
            60000, 3600, 10, 8, 1048576, 30, ARRAY['us', 'eu'],
            '2026-01-01T01:00:00Z', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
        );

        INSERT INTO watch_targets (
            id, tenant_id, watch_id, normalized_username, site_id, created_at
        )
        VALUES (
            '00000000-0000-0000-0000-000000000052',
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000051',
            'fixture-user', 'github', '2026-01-01T00:00:00Z'
        );

        INSERT INTO probe_jobs (
            id, tenant_id, normalized_username, site_id, rule_version_id,
            region_class, work_key_hash, state, available_at, created_at, updated_at,
            completed_at
        )
        VALUES
            ('00000000-0000-0000-0000-000000000061',
             '00000000-0000-0000-0000-000000000001', 'fixture-user', 'github',
             '00000000-0000-0000-0000-000000000021', 'us',
             decode(repeat('61', 32), 'hex'), 'succeeded',
             '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
             '2026-01-01T00:01:00Z', '2026-01-01T00:01:00Z'),
            ('00000000-0000-0000-0000-000000000063',
             '00000000-0000-0000-0000-000000000001', 'fixture-user', 'github',
             '00000000-0000-0000-0000-000000000021', 'eu',
             decode(repeat('63', 32), 'hex'), 'succeeded',
             '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
             '2026-01-01T00:02:00Z', '2026-01-01T00:02:00Z'),
            ('00000000-0000-0000-0000-000000000065',
             '00000000-0000-0000-0000-000000000001', 'fixture-user', 'github',
             '00000000-0000-0000-0000-000000000021', 'shared-client',
             decode(repeat('65', 32), 'hex'), 'succeeded',
             '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
             '2026-01-01T00:03:00Z', '2026-01-01T00:03:00Z');

        INSERT INTO observations (
            id, tenant_id, probe_job_id, consent_grant_id, normalized_username,
            site_id, rule_version_id, outcome_kind, verdict, evidence_class,
            evidence_digest, source, producer_kind, visibility, region_class,
            rule_health_green, observed_at, expires_at, created_at
        )
        VALUES
            ('00000000-0000-0000-0000-000000000062',
             '00000000-0000-0000-0000-000000000001',
             '00000000-0000-0000-0000-000000000061',
             '00000000-0000-0000-0000-000000000031',
             'fixture-user', 'github', '00000000-0000-0000-0000-000000000021',
             'definitive', 'not_found', 'e3_explicit_endpoint',
             decode(repeat('62', 32), 'hex'), 'managed_probe', 'managed_worker',
             'managed', 'us', true, '2026-01-01T00:00:30Z',
             '2026-01-02T00:00:30Z', '2026-01-01T00:01:00Z'),
            ('00000000-0000-0000-0000-000000000064',
             '00000000-0000-0000-0000-000000000001',
             '00000000-0000-0000-0000-000000000063',
             '00000000-0000-0000-0000-000000000031',
             'fixture-user', 'github', '00000000-0000-0000-0000-000000000021',
             'definitive', 'not_found', 'e3_explicit_endpoint',
             decode(repeat('64', 32), 'hex'), 'managed_probe', 'managed_worker',
             'managed', 'eu', true, '2026-01-01T00:01:30Z',
             '2026-01-02T00:01:30Z', '2026-01-01T00:02:00Z'),
            ('00000000-0000-0000-0000-000000000066',
             '00000000-0000-0000-0000-000000000001',
             '00000000-0000-0000-0000-000000000065',
             '00000000-0000-0000-0000-000000000031',
             'fixture-user', 'github', '00000000-0000-0000-0000-000000000021',
             'definitive', 'not_found', 'e1_weak_signal',
             decode(repeat('66', 32), 'hex'), 'shared_assertion', 'shared_cli',
             'shared', 'shared-client', true, '2026-01-01T00:02:30Z',
             '2026-01-02T00:02:30Z', '2026-01-01T00:03:00Z');

        INSERT INTO transitions (
            id, tenant_id, watch_target_id, transition_class, from_state, to_state,
            confirmation_status, suppression_reason, derivation_version,
            detected_at, created_at
        )
        VALUES (
            '00000000-0000-0000-0000-000000000081',
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000052',
            'account_state', 'found', 'not_found', 'suppressed',
            'shared_only_absence', 'transition-v1',
            '2026-01-01T00:03:00Z', '2026-01-01T00:03:00Z'
        );

        INSERT INTO transitions (
            id, tenant_id, watch_target_id, transition_class, from_state, to_state,
            confirmation_status, confirmation_basis, derivation_version,
            detected_at, created_at
        )
        VALUES (
            '00000000-0000-0000-0000-000000000082',
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000052',
            'account_state', 'found', 'not_found', 'confirmed',
            'two_managed_independent_regions', 'transition-v1',
            '2026-01-01T00:02:00Z', '2026-01-01T00:02:00Z'
        );

        INSERT INTO transition_basis (tenant_id, transition_id, observation_id, created_at)
        VALUES
            ('00000000-0000-0000-0000-000000000001',
             '00000000-0000-0000-0000-000000000081',
             '00000000-0000-0000-0000-000000000066', '2026-01-01T00:03:00Z'),
            ('00000000-0000-0000-0000-000000000001',
             '00000000-0000-0000-0000-000000000082',
             '00000000-0000-0000-0000-000000000062', '2026-01-01T00:02:00Z'),
            ('00000000-0000-0000-0000-000000000001',
             '00000000-0000-0000-0000-000000000082',
             '00000000-0000-0000-0000-000000000064', '2026-01-01T00:02:00Z');

        INSERT INTO notification_endpoints (
            id, tenant_id, channel, destination_ciphertext, destination_hash,
            encryption_key_id, state, created_at, verified_at
        )
        VALUES (
            '00000000-0000-0000-0000-000000000071',
            '00000000-0000-0000-0000-000000000001',
            'email', decode(repeat('71', 32), 'hex'), decode(repeat('72', 32), 'hex'),
            'test-key-v1', 'active', '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z'
        );
        "#,
    ))
    .await
    .unwrap();
}

async fn install_api_key_fixtures(pool: &PgPool) {
    for fixture in [
        ApiKeyFixture {
            id: "00000000-0000-0000-0000-0000000000b1",
            tenant_id: "00000000-0000-0000-0000-000000000001",
            membership_id: "00000000-0000-0000-0000-000000000011",
            prefix: "aaaaaaaaaaaaaaaa",
            secret_byte: 0x11,
            scopes: &["workspace:read"],
            state: "active",
            expires_at_unix_ms: None,
        },
        ApiKeyFixture {
            id: "00000000-0000-0000-0000-0000000000b2",
            tenant_id: "00000000-0000-0000-0000-000000000002",
            membership_id: "00000000-0000-0000-0000-000000000012",
            prefix: "bbbbbbbbbbbbbbbb",
            secret_byte: 0x22,
            scopes: &["workspace:read"],
            state: "active",
            expires_at_unix_ms: None,
        },
        ApiKeyFixture {
            id: "00000000-0000-0000-0000-0000000000b3",
            tenant_id: "00000000-0000-0000-0000-000000000001",
            membership_id: "00000000-0000-0000-0000-000000000011",
            prefix: "cccccccccccccccc",
            secret_byte: 0x33,
            scopes: &["search:read"],
            state: "active",
            expires_at_unix_ms: None,
        },
        ApiKeyFixture {
            id: "00000000-0000-0000-0000-0000000000b4",
            tenant_id: "00000000-0000-0000-0000-000000000001",
            membership_id: "00000000-0000-0000-0000-000000000011",
            prefix: "dddddddddddddddd",
            secret_byte: 0x44,
            scopes: &["workspace:read"],
            state: "revoked",
            expires_at_unix_ms: None,
        },
        ApiKeyFixture {
            id: "00000000-0000-0000-0000-0000000000b5",
            tenant_id: "00000000-0000-0000-0000-000000000001",
            membership_id: "00000000-0000-0000-0000-000000000011",
            prefix: "eeeeeeeeeeeeeeee",
            secret_byte: 0x55,
            scopes: &["workspace:read"],
            state: "active",
            expires_at_unix_ms: Some(1_767_312_000_000),
        },
    ] {
        let id = Uuid::parse_str(fixture.id).unwrap();
        let tenant_id = Uuid::parse_str(fixture.tenant_id).unwrap();
        let membership_id = Uuid::parse_str(fixture.membership_id).unwrap();
        let scopes = fixture
            .scopes
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect::<Vec<_>>();
        sqlx::query(
            "INSERT INTO api_keys (\
                id, tenant_id, created_by_membership_id, scopes, state, created_at, \
                expires_at, revoked_at\
             ) VALUES (\
                $1, $2, $3, $4, $5, '2026-01-01T00:00:00Z', \
                CASE WHEN $6::bigint IS NULL THEN NULL \
                     ELSE to_timestamp($6::double precision / 1000.0) END, \
                CASE WHEN $5 = 'revoked' THEN '2026-01-02T00:00:00Z'::timestamptz \
                     ELSE NULL END\
             )",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(membership_id)
        .bind(scopes)
        .bind(fixture.state)
        .bind(fixture.expires_at_unix_ms)
        .execute(pool)
        .await
        .unwrap();
        let hash = Sha256::digest([fixture.secret_byte; 32]);
        sqlx::query(
            "INSERT INTO api_key_credentials \
             (key_prefix, tenant_id, api_key_id, secret_hash, created_at) \
             VALUES ($1, $2, $3, $4, '2026-01-01T00:00:00Z')",
        )
        .bind(fixture.prefix)
        .bind(tenant_id)
        .bind(id)
        .bind(&hash[..])
        .execute(pool)
        .await
        .unwrap();
    }
}

struct ApiKeyFixture {
    id: &'static str,
    tenant_id: &'static str,
    membership_id: &'static str,
    prefix: &'static str,
    secret_byte: u8,
    scopes: &'static [&'static str],
    state: &'static str,
    expires_at_unix_ms: Option<i64>,
}

async fn assert_api_key_scope_constraints(pool: &PgPool) {
    let duplicate_scope = sqlx::query(
        "INSERT INTO api_keys (\
            id, tenant_id, created_by_membership_id, scopes, created_at\
         ) VALUES (\
            '00000000-0000-0000-0000-0000000000bf', \
            '00000000-0000-0000-0000-000000000001', \
            '00000000-0000-0000-0000-000000000011', \
            ARRAY['workspace:read', 'workspace:read'], \
            '2026-01-01T00:00:00Z'\
         )",
    )
    .execute(pool)
    .await
    .unwrap_err();
    assert_database_code(duplicate_scope, "23514");
}

async fn assert_tenant_isolation(pool: &PgPool) {
    pool.execute(sqlx::raw_sql(
        r#"
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'socialname_migration_test_app') THEN
                CREATE ROLE socialname_migration_test_app
                    LOGIN PASSWORD 'socialname-test-password'
                    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            END IF;
        END
        $$;
        ALTER ROLE socialname_migration_test_app
            LOGIN PASSWORD 'socialname-test-password'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
        GRANT USAGE ON SCHEMA public TO socialname_migration_test_app;
        GRANT SELECT, INSERT ON tenants, memberships TO socialname_migration_test_app;
        GRANT SELECT ON api_keys TO socialname_migration_test_app;
        GRANT UPDATE (last_used_at) ON api_keys TO socialname_migration_test_app;
        GRANT EXECUTE ON FUNCTION socialname_authenticate_api_key(text, bytea)
            TO socialname_migration_test_app;
        "#,
    ))
    .await
    .unwrap();

    let mut transaction = pool.begin().await.unwrap();
    transaction
        .execute("SET LOCAL ROLE socialname_migration_test_app")
        .await
        .unwrap();
    sqlx::query("SELECT set_config('socialname.tenant_id', $1, true)")
        .bind("00000000-0000-0000-0000-000000000001")
        .execute(&mut *transaction)
        .await
        .unwrap();

    let visible_slugs: Vec<String> = sqlx::query_scalar("SELECT slug FROM tenants ORDER BY slug")
        .fetch_all(&mut *transaction)
        .await
        .unwrap();
    assert_eq!(visible_slugs, ["tenant-one"]);

    let error = sqlx::query(
        r#"
        INSERT INTO tenants (id, slug, display_name, created_at, updated_at)
        VALUES (
            '00000000-0000-0000-0000-000000000003', 'tenant-three', 'Tenant Three',
            '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
        )
        "#,
    )
    .execute(&mut *transaction)
    .await
    .unwrap_err();
    assert_database_code(error, "42501");
    transaction.rollback().await.unwrap();

    let can_read_credentials: bool = sqlx::query_scalar(
        "SELECT has_table_privilege(\
            'socialname_migration_test_app', 'api_key_credentials', 'SELECT'\
         )",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(!can_read_credentials);

    let can_update_last_used: bool = sqlx::query_scalar(
        "SELECT has_column_privilege(\
            'socialname_migration_test_app', 'api_keys', 'last_used_at', 'UPDATE'\
         )",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let can_update_scopes: bool = sqlx::query_scalar(
        "SELECT has_column_privilege(\
            'socialname_migration_test_app', 'api_keys', 'scopes', 'UPDATE'\
         )",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(can_update_last_used);
    assert!(!can_update_scopes);
}

async fn assert_cross_tenant_references_are_rejected(pool: &PgPool) {
    let error = sqlx::query(
        r#"
        INSERT INTO search_targets (
            id, tenant_id, search_id, normalized_username, site_id, ordinal, created_at
        )
        VALUES (
            '00000000-0000-0000-0000-000000000043',
            '00000000-0000-0000-0000-000000000002',
            '00000000-0000-0000-0000-000000000041',
            'fixture-user', 'github', 0, '2026-01-01T00:00:00Z'
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap_err();
    assert_database_code(error, "23503");
}

async fn assert_observations_are_immutable(pool: &PgPool) {
    let error = sqlx::query(
        "UPDATE observations SET created_at = created_at \
         WHERE id = '00000000-0000-0000-0000-000000000062'",
    )
    .execute(pool)
    .await
    .unwrap_err();
    assert_database_code(error, "55000");
}

async fn assert_transition_and_delivery_safety(pool: &PgPool) {
    let invalid_basis = sqlx::query(
        r#"
        INSERT INTO transitions (
            id, tenant_id, watch_target_id, transition_class, from_state, to_state,
            confirmation_status, confirmation_basis, derivation_version,
            detected_at, created_at
        )
        VALUES (
            '00000000-0000-0000-0000-000000000083',
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000052',
            'account_state', 'found', 'not_found', 'confirmed',
            'managed_e4', 'transition-v1',
            '2026-01-01T00:04:00Z', '2026-01-01T00:04:00Z'
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap_err();
    assert_database_code(invalid_basis, "23514");

    let suppressed_delivery = sqlx::query(
        r#"
        INSERT INTO notification_deliveries (
            id, tenant_id, transition_id, endpoint_id, logical_notification_key,
            confirmation_basis, created_at
        )
        VALUES (
            '00000000-0000-0000-0000-000000000091',
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000081',
            '00000000-0000-0000-0000-000000000071',
            decode(repeat('91', 32), 'hex'), 'two_managed_independent_regions',
            '2026-01-01T00:04:00Z'
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap_err();
    assert_database_code(suppressed_delivery, "23514");

    sqlx::query(
        r#"
        INSERT INTO notification_deliveries (
            id, tenant_id, transition_id, endpoint_id, logical_notification_key,
            confirmation_basis, created_at
        )
        VALUES (
            '00000000-0000-0000-0000-000000000092',
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000082',
            '00000000-0000-0000-0000-000000000071',
            decode(repeat('92', 32), 'hex'), 'two_managed_independent_regions',
            '2026-01-01T00:04:00Z'
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn assert_deletion_deadlines_and_receipts(pool: &PgPool) {
    let invalid_deadlines = sqlx::query(
        r#"
        INSERT INTO deletion_requests (
            id, tenant_id, requested_by_membership_id, scope_kind, selector_token,
            requested_at, hide_by, support_withdrawal_by, primary_delete_by,
            derived_rebuild_by, backup_expiry_by
        )
        VALUES (
            '00000000-0000-0000-0000-0000000000a1',
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000011',
            'target', decode(repeat('a1', 32), 'hex'),
            '2026-01-01T00:00:00Z', '2025-12-31T23:00:00Z',
            '2026-01-01T02:00:00Z', '2026-01-01T03:00:00Z',
            '2026-01-01T04:00:00Z', '2026-02-01T00:00:00Z'
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap_err();
    assert_database_code(invalid_deadlines, "23514");

    pool.execute(sqlx::raw_sql(
        r#"
        INSERT INTO deletion_requests (
            id, tenant_id, requested_by_membership_id, scope_kind, selector_token,
            state, requested_at, hide_by, support_withdrawal_by, primary_delete_by,
            derived_rebuild_by, backup_expiry_by, completed_at
        )
        VALUES (
            '00000000-0000-0000-0000-0000000000a2',
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000011',
            'target', decode(repeat('a2', 32), 'hex'), 'completed',
            '2026-01-01T00:00:00Z', '2026-01-01T01:00:00Z',
            '2026-01-01T02:00:00Z', '2026-01-01T03:00:00Z',
            '2026-01-01T04:00:00Z', '2026-02-01T00:00:00Z',
            '2026-01-01T05:00:00Z'
        );

        INSERT INTO deletion_tasks (
            id, tenant_id, deletion_request_id, store_kind, state, deadline_at,
            attempt_count, available_at, completed_at
        )
        VALUES (
            '00000000-0000-0000-0000-0000000000a3',
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-0000000000a2',
            'primary', 'completed', '2026-01-01T03:00:00Z', 1,
            '2026-01-01T00:00:00Z', '2026-01-01T02:30:00Z'
        );

        INSERT INTO deletion_receipts (
            id, tenant_id, deletion_request_id, stores, primary_completed_at,
            backup_expiry_at, created_at
        )
        VALUES (
            '00000000-0000-0000-0000-0000000000a4',
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-0000000000a2',
            '{"primary":"deleted","backup":"expires"}',
            '2026-01-01T02:30:00Z', '2026-02-01T00:00:00Z',
            '2026-01-01T05:00:00Z'
        );

        INSERT INTO data_lineage_edges (
            id, tenant_id, parent_kind, parent_id, child_kind, child_id,
            purpose, created_at
        )
        VALUES (
            '00000000-0000-0000-0000-0000000000a5',
            '00000000-0000-0000-0000-000000000001',
            'deletion_request', '00000000-0000-0000-0000-0000000000a2',
            'deletion_receipt', '00000000-0000-0000-0000-0000000000a4',
            'erasure_evidence', '2026-01-01T05:00:00Z'
        );
        "#,
    ))
    .await
    .unwrap();
}

async fn assert_authenticated_workspace_boundary(administrator_pool: &PgPool) {
    let application_database_url = env::var(TEST_APPLICATION_DATABASE_URL_ENV)
        .expect("application database URL must accompany the PostgreSQL integration test");
    let application_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&application_database_url)
        .await
        .unwrap();

    let ready_response = server_request(&application_pool, "/health/ready", None).await;
    assert_eq!(ready_response.status(), StatusCode::OK);
    assert_eq!(json_body(ready_response).await["status"], "ready");

    let missing = server_request(&application_pool, "/v1/workspace", None).await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(missing.headers()[WWW_AUTHENTICATE], "Bearer");
    assert_api_error(missing, ApiErrorCode::Unauthenticated).await;

    let wrong_secret = api_key_token("aaaaaaaaaaaaaaaa", 0xff);
    let invalid = server_request(&application_pool, "/v1/workspace", Some(&wrong_secret)).await;
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    assert_api_error(invalid, ApiErrorCode::Unauthenticated).await;

    let insufficient_scope = api_key_token("cccccccccccccccc", 0x33);
    let forbidden = server_request(
        &application_pool,
        "/v1/workspace",
        Some(&insufficient_scope),
    )
    .await;
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    assert_api_error(forbidden, ApiErrorCode::Forbidden).await;

    let tenant_one_token = api_key_token("aaaaaaaaaaaaaaaa", 0x11);
    let tenant_one =
        server_request(&application_pool, "/v1/workspace", Some(&tenant_one_token)).await;
    assert_eq!(tenant_one.status(), StatusCode::OK);
    let tenant_one_json = json_body(tenant_one).await;
    let tenant_one_resource: WorkspaceResource =
        serde_json::from_value(tenant_one_json.clone()).unwrap();
    assert!(tenant_one_resource.validate().is_ok());
    assert_eq!(tenant_one_resource.slug, "tenant-one");
    assert_eq!(
        tenant_one_resource.authenticated_api_key.key_prefix,
        "aaaaaaaaaaaaaaaa"
    );
    let serialized = tenant_one_json.to_string();
    assert!(!serialized.contains(&tenant_one_token));
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("hash"));

    let tenant_two_token = api_key_token("bbbbbbbbbbbbbbbb", 0x22);
    let tenant_two =
        server_request(&application_pool, "/v1/workspace", Some(&tenant_two_token)).await;
    assert_eq!(tenant_two.status(), StatusCode::OK);
    let tenant_two_resource: WorkspaceResource =
        serde_json::from_value(json_body(tenant_two).await).unwrap();
    assert_eq!(tenant_two_resource.slug, "tenant-two");
    assert_ne!(
        tenant_one_resource.workspace_id,
        tenant_two_resource.workspace_id
    );

    for token in [
        api_key_token("dddddddddddddddd", 0x44),
        api_key_token("eeeeeeeeeeeeeeee", 0x55),
    ] {
        let response = server_request(&application_pool, "/v1/workspace", Some(&token)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_api_error(response, ApiErrorCode::Unauthenticated).await;
    }

    let last_used_recorded: bool = sqlx::query_scalar(
        "SELECT last_used_at IS NOT NULL FROM api_keys \
         WHERE id = '00000000-0000-0000-0000-0000000000b1'",
    )
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert!(last_used_recorded);

    let closed_pool = application_pool.clone();
    application_pool.close().await;
    let not_ready = server_request(&closed_pool, "/health/ready", None).await;
    assert_eq!(not_ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_body(not_ready).await["status"], "not_ready");
}

async fn server_request(pool: &PgPool, uri: &str, token: Option<&str>) -> Response {
    let mut request = Request::builder().uri(uri);
    if let Some(token) = token {
        request = request.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    build_router(test_server_config(), pool.clone())
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn test_server_config() -> ServerConfig {
    ServerConfig::new(
        "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        Duration::from_secs(1),
        4_096,
        8,
    )
    .unwrap()
}

fn api_key_token(prefix: &str, secret_byte: u8) -> String {
    format!("snk_v1_{prefix}_{}", hex::encode([secret_byte; 32]))
}

async fn json_body(response: Response) -> serde_json::Value {
    let bytes = to_bytes(response.into_body(), 64 * 1_024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn assert_api_error(response: Response, expected: ApiErrorCode) {
    let error: ApiErrorResponse = serde_json::from_value(json_body(response).await).unwrap();
    assert_eq!(error.error.code, expected);
    assert!(error.validate().is_ok());
}

fn assert_database_code(error: sqlx::Error, expected: &str) {
    let code = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|code| code.into_owned());
    assert_eq!(code.as_deref(), Some(expected), "{error}");
}
