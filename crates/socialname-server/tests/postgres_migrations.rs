use std::{env, net::SocketAddr, time::Duration};

use axum::{
    body::{Body, to_bytes},
    http::{
        Method, Request, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE, LOCATION, WWW_AUTHENTICATE},
    },
    response::Response,
};
use sha2::{Digest, Sha256};
use socialname_protocol::{
    ApiErrorCode, ApiErrorResponse, ConsentGrantId, EventId, OperationalFailure,
    OperationalFailureKind, ProtocolVersion, RegionClass, ResultSource, SearchCreateRequest,
    SearchEvent, SearchEventData, SearchId, SearchMode, SearchProgress, SearchResource,
    SearchState, SearchTerminalState, SiteId, SyncPolicy, Target, TargetSelection, Username,
    Validate, WorkspaceResource,
};
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
    reset_test_state(&pool).await;
    install_fixtures(&pool).await;
    install_api_key_fixtures(&pool).await;
    assert_api_key_scope_constraints(&pool).await;
    assert_tenant_isolation(&pool).await;
    assert_cross_tenant_references_are_rejected(&pool).await;
    assert_observations_are_immutable(&pool).await;
    assert_transition_and_delivery_safety(&pool).await;
    assert_deletion_deadlines_and_receipts(&pool).await;
    assert_authenticated_workspace_boundary(&pool).await;
    assert_private_search_and_event_stream_boundary(&pool).await;

    pool.close().await;
}

async fn reset_test_state(pool: &PgPool) {
    pool.execute(sqlx::raw_sql(
        r#"
        TRUNCATE TABLE
            tenants, memberships, api_keys, api_key_credentials, clients, sites,
            rule_packs, rule_versions, rule_health_records, consent_grants,
            consent_events, searches, search_targets, search_events, watches,
            watch_targets, probe_jobs, probe_job_consumers, observations,
            assertions, assertion_support, transitions, transition_basis,
            notification_endpoints, notification_deliveries, audit_events,
            data_lineage_edges, deletion_requests, deletion_tasks,
            deletion_receipts, suppression_tokens
        CASCADE;

        DO $$
        BEGIN
            IF EXISTS (
                SELECT FROM pg_roles
                WHERE rolname = 'socialname_migration_test_app'
            ) THEN
                REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public
                    FROM socialname_migration_test_app;
                REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public
                    FROM socialname_migration_test_app;
                REVOKE ALL PRIVILEGES ON SCHEMA public
                    FROM socialname_migration_test_app;
            END IF;
        END
        $$;
        "#,
    ))
    .await
    .unwrap();
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
                ('search_events'),
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
    assert_eq!(required_tables, 31);

    let tenant_policies: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_policies \
         WHERE schemaname = 'public' AND policyname = 'tenant_isolation'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(tenant_policies, 26);

    let forced_rls_tables: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_class \
         WHERE relnamespace = 'public'::regnamespace AND relkind = 'r' \
         AND relrowsecurity AND relforcerowsecurity",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(forced_rls_tables, 26);

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
            id, tenant_id, search_id, requested_username, site_id, ordinal, created_at
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
            scopes: &["workspace:read", "search:read", "search:write"],
            state: "active",
            expires_at_unix_ms: None,
        },
        ApiKeyFixture {
            id: "00000000-0000-0000-0000-0000000000b2",
            tenant_id: "00000000-0000-0000-0000-000000000002",
            membership_id: "00000000-0000-0000-0000-000000000012",
            prefix: "bbbbbbbbbbbbbbbb",
            secret_byte: 0x22,
            scopes: &["workspace:read", "search:read", "search:write"],
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
        GRANT SELECT ON sites, consent_grants, searches, search_targets, search_events
            TO socialname_migration_test_app;
        GRANT INSERT ON searches, search_targets, search_events
            TO socialname_migration_test_app;
        GRANT UPDATE (state, updated_at, completed_at) ON searches
            TO socialname_migration_test_app;
        GRANT UPDATE (state, completed_at) ON search_targets
            TO socialname_migration_test_app;
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

    let can_update_search_state: bool = sqlx::query_scalar(
        "SELECT has_column_privilege(\
            'socialname_migration_test_app', 'searches', 'state', 'UPDATE'\
         )",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let can_update_idempotency_hash: bool = sqlx::query_scalar(
        "SELECT has_column_privilege(\
            'socialname_migration_test_app', 'searches', \
            'idempotency_key_hash', 'UPDATE'\
         )",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let can_update_normalized_username: bool = sqlx::query_scalar(
        "SELECT has_column_privilege(\
            'socialname_migration_test_app', 'search_targets', \
            'normalized_username', 'UPDATE'\
         )",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(can_update_search_state);
    assert!(!can_update_idempotency_hash);
    assert!(!can_update_normalized_username);
}

async fn assert_cross_tenant_references_are_rejected(pool: &PgPool) {
    let error = sqlx::query(
        r#"
        INSERT INTO search_targets (
            id, tenant_id, search_id, requested_username, site_id, ordinal, created_at
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

async fn assert_private_search_and_event_stream_boundary(administrator_pool: &PgPool) {
    let application_database_url = env::var(TEST_APPLICATION_DATABASE_URL_ENV)
        .expect("application database URL must accompany the PostgreSQL integration test");
    let application_pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&application_database_url)
        .await
        .unwrap();
    let writer_token = api_key_token("aaaaaaaaaaaaaaaa", 0x11);
    let reader_token = api_key_token("cccccccccccccccc", 0x33);
    let other_tenant_token = api_key_token("bbbbbbbbbbbbbbbb", 0x22);
    let request = private_search_request(SyncPolicy::Private, "github", 60_000);
    let request_body = serde_json::to_string(&request).unwrap();

    let read_only_create = server_request_with(
        &application_pool,
        Method::POST,
        "/v1/searches",
        Some(&reader_token),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "read-only"),
        ],
        request_body.clone(),
    )
    .await;
    assert_eq!(read_only_create.status(), StatusCode::FORBIDDEN);
    assert_api_error(read_only_create, ApiErrorCode::Forbidden).await;

    let missing_key = server_request_with(
        &application_pool,
        Method::POST,
        "/v1/searches",
        Some(&writer_token),
        &[("content-type", "application/json")],
        request_body.clone(),
    )
    .await;
    assert_eq!(missing_key.status(), StatusCode::BAD_REQUEST);
    assert_api_error(missing_key, ApiErrorCode::InvalidRequest).await;

    let never_request = SearchCreateRequest {
        sync: SyncPolicy::Never,
        consent_grant_id: None,
        ..request.clone()
    };
    let never = server_request_with(
        &application_pool,
        Method::POST,
        "/v1/searches",
        Some(&writer_token),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "never-leaves-device"),
        ],
        serde_json::to_string(&never_request).unwrap(),
    )
    .await;
    assert_eq!(never.status(), StatusCode::BAD_REQUEST);
    let never_error = json_body(never).await;
    assert_eq!(never_error["error"]["code"], "invalid_request");
    assert!(!never_error.to_string().contains("private-search-target"));

    let shared_request = SearchCreateRequest {
        sync: SyncPolicy::Shared,
        ..request.clone()
    };
    let wrong_purpose = server_request_with(
        &application_pool,
        Method::POST,
        "/v1/searches",
        Some(&writer_token),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "wrong-purpose"),
        ],
        serde_json::to_string(&shared_request).unwrap(),
    )
    .await;
    assert_eq!(wrong_purpose.status(), StatusCode::FORBIDDEN);
    assert_api_error(wrong_purpose, ApiErrorCode::Forbidden).await;

    let unknown_site_request = private_search_request(SyncPolicy::Private, "unknown-site", 60_000);
    let unknown_site = server_request_with(
        &application_pool,
        Method::POST,
        "/v1/searches",
        Some(&writer_token),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "unknown-site"),
        ],
        serde_json::to_string(&unknown_site_request).unwrap(),
    )
    .await;
    assert_eq!(unknown_site.status(), StatusCode::BAD_REQUEST);
    let unknown_site_error = json_body(unknown_site).await;
    assert_eq!(unknown_site_error["error"]["code"], "invalid_request");
    assert!(!unknown_site_error.to_string().contains("unknown-site"));

    let created = server_request_with(
        &application_pool,
        Method::POST,
        "/v1/searches",
        Some(&writer_token),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "private-search-replay"),
        ],
        request_body.clone(),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let location = created.headers()[LOCATION].to_str().unwrap().to_owned();
    let created_resource: SearchResource =
        serde_json::from_value(json_body(created).await).unwrap();
    assert!(created_resource.validate().is_ok());
    assert_eq!(created_resource.state, SearchState::Accepted);
    assert_eq!(created_resource.progress.total_targets, 1);
    assert_eq!(created_resource.progress.completed_targets, 0);
    assert_eq!(
        location,
        format!("/v1/searches/{}", created_resource.search_id.as_str())
    );
    let search_id = Uuid::parse_str(created_resource.search_id.as_str()).unwrap();

    let replay = server_request_with(
        &application_pool,
        Method::POST,
        "/v1/searches",
        Some(&writer_token),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "private-search-replay"),
        ],
        request_body,
    )
    .await;
    assert_eq!(replay.status(), StatusCode::OK);
    let replay_resource: SearchResource = serde_json::from_value(json_body(replay).await).unwrap();
    assert_eq!(replay_resource.search_id, created_resource.search_id);

    let changed_request = private_search_request(SyncPolicy::Private, "github", 120_000);
    let conflict = server_request_with(
        &application_pool,
        Method::POST,
        "/v1/searches",
        Some(&writer_token),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "private-search-replay"),
        ],
        serde_json::to_string(&changed_request).unwrap(),
    )
    .await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_api_error(conflict, ApiErrorCode::IdempotencyConflict).await;

    let idempotency_hash = Sha256::digest(b"private-search-replay");
    let stored_hash_matches: bool = sqlx::query_scalar(
        "SELECT idempotency_key_hash = $1 \
         FROM searches WHERE id = $2",
    )
    .bind(&idempotency_hash[..])
    .bind(search_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert!(stored_hash_matches);

    let polled = server_request(
        &application_pool,
        &format!("/v1/searches/{search_id}"),
        Some(&writer_token),
    )
    .await;
    assert_eq!(polled.status(), StatusCode::OK);
    let polled_resource: SearchResource = serde_json::from_value(json_body(polled).await).unwrap();
    assert_eq!(polled_resource.search_id, created_resource.search_id);

    let cross_tenant = server_request(
        &application_pool,
        &format!("/v1/searches/{search_id}"),
        Some(&other_tenant_token),
    )
    .await;
    assert_eq!(cross_tenant.status(), StatusCode::NOT_FOUND);
    assert_api_error(cross_tenant, ApiErrorCode::NotFound).await;

    let started_event_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM search_events \
         WHERE search_id = $1 AND sequence = 1",
    )
    .bind(search_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    complete_search_with_operational_failure(administrator_pool, search_id).await;

    let completed = server_request(
        &application_pool,
        &format!("/v1/searches/{search_id}"),
        Some(&writer_token),
    )
    .await;
    let completed_resource: SearchResource =
        serde_json::from_value(json_body(completed).await).unwrap();
    assert_eq!(completed_resource.state, SearchState::Completed);
    assert_eq!(completed_resource.progress.completed_targets, 1);
    assert_eq!(completed_resource.progress.operational_failures, 1);
    assert!(completed_resource.validate().is_ok());

    let events = server_request_with(
        &application_pool,
        Method::GET,
        &format!("/v1/searches/{search_id}/events"),
        Some(&writer_token),
        &[],
        String::new(),
    )
    .await;
    assert_eq!(events.status(), StatusCode::OK);
    assert!(
        events.headers()[CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    let event_bytes = to_bytes(events.into_body(), 256 * 1_024).await.unwrap();
    let event_text = String::from_utf8(event_bytes.to_vec()).unwrap();
    let sequence_one = event_text.find("\"sequence\":1").unwrap();
    let sequence_two = event_text.find("\"sequence\":2").unwrap();
    let sequence_three = event_text.find("\"sequence\":3").unwrap();
    assert!(sequence_one < sequence_two && sequence_two < sequence_three);
    assert!(event_text.contains("\"type\":\"operational_failure\""));
    assert!(event_text.contains("\"type\":\"finished\""));
    assert!(!event_text.contains(&writer_token));
    assert!(!event_text.contains("private-search-replay"));

    let immutable_event = sqlx::query(
        "UPDATE search_events SET created_at = created_at \
         WHERE search_id = $1 AND sequence = 2",
    )
    .bind(search_id)
    .execute(administrator_pool)
    .await
    .unwrap_err();
    assert_database_code(immutable_event, "55000");

    let resumed = server_request_with(
        &application_pool,
        Method::GET,
        &format!("/v1/searches/{search_id}/events"),
        Some(&writer_token),
        &[("last-event-id", &started_event_id.to_string())],
        String::new(),
    )
    .await;
    assert_eq!(resumed.status(), StatusCode::OK);
    let resumed_bytes = to_bytes(resumed.into_body(), 256 * 1_024).await.unwrap();
    let resumed_text = String::from_utf8(resumed_bytes.to_vec()).unwrap();
    assert!(!resumed_text.contains("\"sequence\":1"));
    assert!(resumed_text.contains("\"sequence\":2"));
    assert!(resumed_text.contains("\"sequence\":3"));

    let malformed_resume = server_request_with(
        &application_pool,
        Method::GET,
        &format!("/v1/searches/{search_id}/events"),
        Some(&writer_token),
        &[("last-event-id", "not-an-event-id")],
        String::new(),
    )
    .await;
    assert_eq!(malformed_resume.status(), StatusCode::BAD_REQUEST);
    assert_api_error(malformed_resume, ApiErrorCode::InvalidRequest).await;

    let cancellation_request = private_search_request(SyncPolicy::Private, "github", 60_000);
    let cancellation_created = server_request_with(
        &application_pool,
        Method::POST,
        "/v1/searches",
        Some(&writer_token),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "cancel-search"),
        ],
        serde_json::to_string(&cancellation_request).unwrap(),
    )
    .await;
    let cancellation_resource: SearchResource =
        serde_json::from_value(json_body(cancellation_created).await).unwrap();
    let cancellation_id = Uuid::parse_str(cancellation_resource.search_id.as_str()).unwrap();
    for _ in 0..2 {
        let cancelled = server_request_with(
            &application_pool,
            Method::DELETE,
            &format!("/v1/searches/{cancellation_id}"),
            Some(&writer_token),
            &[],
            String::new(),
        )
        .await;
        assert_eq!(cancelled.status(), StatusCode::OK);
        let cancelled_resource: SearchResource =
            serde_json::from_value(json_body(cancelled).await).unwrap();
        assert_eq!(cancelled_resource.state, SearchState::Cancelled);
    }
    let finished_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM search_events \
         WHERE search_id = $1 AND event_type = 'finished'",
    )
    .bind(cancellation_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(finished_count, 1);

    let capacity_created = server_request_with(
        &application_pool,
        Method::POST,
        "/v1/searches",
        Some(&writer_token),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", "stream-capacity"),
        ],
        serde_json::to_string(&private_search_request(
            SyncPolicy::Private,
            "github",
            60_000,
        ))
        .unwrap(),
    )
    .await;
    let capacity_resource: SearchResource =
        serde_json::from_value(json_body(capacity_created).await).unwrap();
    let capacity_uri = format!(
        "/v1/searches/{}/events",
        capacity_resource.search_id.as_str()
    );
    let bounded_router = build_router(
        ServerConfig::new(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            Duration::from_secs(1),
            4_096,
            1,
        )
        .unwrap(),
        application_pool.clone(),
    );
    let first_stream = bounded_router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&capacity_uri)
                .header(AUTHORIZATION, format!("Bearer {writer_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first_stream.status(), StatusCode::OK);
    let capacity_denied = bounded_router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&capacity_uri)
                .header(AUTHORIZATION, format!("Bearer {writer_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(capacity_denied.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_api_error(capacity_denied, ApiErrorCode::Unavailable).await;
    drop(first_stream);
    let capacity_released = bounded_router
        .oneshot(
            Request::builder()
                .uri(&capacity_uri)
                .header(AUTHORIZATION, format!("Bearer {writer_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(capacity_released.status(), StatusCode::OK);
    drop(capacity_released);

    application_pool.close().await;
}

fn private_search_request(
    sync: SyncPolicy,
    site_id: &str,
    maximum_age_ms: i64,
) -> SearchCreateRequest {
    SearchCreateRequest {
        schema: ProtocolVersion::ApiV1,
        targets: TargetSelection {
            usernames: vec![Username::new("private-search-target").unwrap()],
            site_ids: vec![SiteId::new(site_id).unwrap()],
        },
        mode: SearchMode::Remote,
        sync,
        consent_grant_id: Some(
            ConsentGrantId::new("00000000-0000-0000-0000-000000000031").unwrap(),
        ),
        maximum_age_ms,
        region_classes: vec![RegionClass::new("jp").unwrap()],
    }
}

async fn complete_search_with_operational_failure(pool: &PgPool, search_id: Uuid) {
    let workspace_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let target_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM search_targets \
         WHERE tenant_id = $1 AND search_id = $2",
    )
    .bind(workspace_id)
    .bind(search_id)
    .fetch_one(pool)
    .await
    .unwrap();
    let emitted_at_unix_ms = 1_800_000_000_000_i64;
    let failure_event_id = Uuid::new_v4();
    let failure_event = SearchEvent {
        schema: ProtocolVersion::ApiV1,
        event_id: EventId::new(failure_event_id.to_string()).unwrap(),
        search_id: SearchId::new(search_id.to_string()).unwrap(),
        sequence: 2,
        emitted_at_unix_ms,
        data: SearchEventData::OperationalFailure {
            failure: OperationalFailure {
                target: Target {
                    username: Username::new("private-search-target").unwrap(),
                    site_id: SiteId::new("github").unwrap(),
                },
                kind: OperationalFailureKind::CapacityUnavailable,
                source: ResultSource::ManagedProbe,
                occurred_at_unix_ms: emitted_at_unix_ms,
                retryable: true,
                region_class: Some(RegionClass::new("jp").unwrap()),
                rule_hash: None,
            },
        },
    };
    let finished_event_id = Uuid::new_v4();
    let progress = SearchProgress {
        total_targets: 1,
        completed_targets: 1,
        definitive_results: 0,
        uncertain_results: 0,
        operational_failures: 1,
    };
    let finished_event = SearchEvent {
        schema: ProtocolVersion::ApiV1,
        event_id: EventId::new(finished_event_id.to_string()).unwrap(),
        search_id: SearchId::new(search_id.to_string()).unwrap(),
        sequence: 3,
        emitted_at_unix_ms: emitted_at_unix_ms + 1,
        data: SearchEventData::Finished {
            state: SearchTerminalState::Completed,
            progress,
        },
    };
    assert!(failure_event.validate().is_ok());
    assert!(finished_event.validate().is_ok());

    let mut transaction = pool.begin().await.unwrap();
    sqlx::query(
        "UPDATE search_targets \
         SET state = 'failed', completed_at = clock_timestamp() \
         WHERE tenant_id = $1 AND search_id = $2 AND id = $3",
    )
    .bind(workspace_id)
    .bind(search_id)
    .bind(target_id)
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE searches \
         SET state = 'completed', updated_at = clock_timestamp(), \
             completed_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(workspace_id)
    .bind(search_id)
    .execute(&mut *transaction)
    .await
    .unwrap();
    insert_search_event_fixture(
        &mut transaction,
        workspace_id,
        search_id,
        Some(target_id),
        failure_event_id,
        "operational_failure",
        &failure_event,
    )
    .await;
    insert_search_event_fixture(
        &mut transaction,
        workspace_id,
        search_id,
        None,
        finished_event_id,
        "finished",
        &finished_event,
    )
    .await;
    transaction.commit().await.unwrap();
}

#[allow(clippy::too_many_arguments)]
async fn insert_search_event_fixture(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workspace_id: Uuid,
    search_id: Uuid,
    target_id: Option<Uuid>,
    event_id: Uuid,
    event_type: &str,
    event: &SearchEvent,
) {
    sqlx::query(
        "INSERT INTO search_events (\
            id, tenant_id, search_id, search_target_id, sequence, event_type, \
            payload, emitted_at, created_at\
         ) VALUES (\
            $1, $2, $3, $4, $5, $6, $7::jsonb, \
            to_timestamp($8::double precision / 1000.0), clock_timestamp()\
         )",
    )
    .bind(event_id)
    .bind(workspace_id)
    .bind(search_id)
    .bind(target_id)
    .bind(i64::try_from(event.sequence).unwrap())
    .bind(event_type)
    .bind(serde_json::to_string(event).unwrap())
    .bind(event.emitted_at_unix_ms)
    .execute(&mut **transaction)
    .await
    .unwrap();
}

async fn server_request(pool: &PgPool, uri: &str, token: Option<&str>) -> Response {
    server_request_with(pool, Method::GET, uri, token, &[], String::new()).await
}

async fn server_request_with(
    pool: &PgPool,
    method: Method,
    uri: &str,
    token: Option<&str>,
    headers: &[(&str, &str)],
    body: String,
) -> Response {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        request = request.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    build_router(test_server_config(), pool.clone())
        .oneshot(request.body(Body::from(body)).unwrap())
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
