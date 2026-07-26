use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    env,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    http::{
        Method, Request, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE, LOCATION, WWW_AUTHENTICATE},
    },
    response::Response,
};
use sha2::{Digest, Sha256};
use socialname_canary::{
    PromotionBuildRequest, PromotionBuilder, PromotionEnvelope, PromotionSigningKey,
    RULE_PACK_TRUST_V1, RulePackMetadataBuildRequest, RulePackMetadataBuilder,
    RulePackMetadataEnvelope, RulePackMetadataSigningKey, RulePackMetadataVerifier,
    RulePackRolloutStage, RulePackTrustV1,
};
use socialname_domain::{
    EvidenceClass as DomainEvidenceClass, InconclusiveReason, RuleHealth, RuleHealthKey,
    RuleHealthRecord, SiteId as DomainSiteId, Verdict,
};
use socialname_engine::{Classification, SearchResult};
use socialname_protocol::{
    ApiErrorCode, ApiErrorResponse, ConsentGrantId, EventId, NotificationEndpointId,
    OperationalFailure, OperationalFailureKind, ProbeBudget, ProtocolVersion, RegionClass,
    ResultSource, SearchCreateRequest, SearchEvent, SearchEventData, SearchId, SearchMode,
    SearchProgress, SearchResource, SearchState, SearchTerminalState, SiteId, SyncPolicy, Target,
    TargetSelection, Username, Validate, WatchCreateRequest, WatchListPage, WatchPatchRequest,
    WatchResource, WatchSchedule, WatchState, WatchStateUpdate, WatchTransitionPage,
    WorkspaceResource,
};
use socialname_rule_compiler::{CompiledRulePack, CompiledSiteRule, RuleCompiler};
use socialname_server::{
    InitialRulePackTrust, RuleRegistryError, ServerConfig, apply_rule_pack_metadata, build_router,
    migrate_database,
};
use socialname_worker::{
    DeliveryError, DeliveryProcessConfig, DeliveryProcessOutcome, DeliverySecrets, DeliveryStore,
    ExpandOutcome, JobDisposition, JobError, JobExecutionError, JobStore, ManagedRule,
    WatchPlanOutcome, WebhookRequest, WebhookSendError, WebhookTransport, process_one_delivery,
};
use sqlx::{Executor, PgPool, postgres::PgPoolOptions};
use tower::ServiceExt;
use uuid::Uuid;

const TEST_DATABASE_URL_ENV: &str = "SOCIALNAME_TEST_DATABASE_URL";
const TEST_APPLICATION_DATABASE_URL_ENV: &str = "SOCIALNAME_TEST_APPLICATION_DATABASE_URL";
const TEST_WORKER_DATABASE_URL_ENV: &str = "SOCIALNAME_TEST_WORKER_DATABASE_URL";

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
    assert_watch_api_boundary(&pool).await;
    assert_managed_probe_job_boundary(&pool).await;
    assert_monitoring_console_boundary(&pool).await;

    pool.close().await;
}

async fn reset_test_state(pool: &PgPool) {
    pool.execute(sqlx::raw_sql(
        r#"
        TRUNCATE TABLE
            tenants, memberships, api_keys, api_key_credentials, clients, sites,
            rule_packs, rule_versions, rule_health_records,
            rule_pack_trust_roots, rule_pack_metadata, rule_pack_promotions,
            rule_pack_registry, rule_site_promotion_high_water, consent_grants,
            consent_events, searches, search_targets, search_events, watches,
            watch_targets, watch_notification_endpoints, watch_runs,
            watch_run_targets, probe_jobs, probe_job_consumers, observations,
            assertions, assertion_support, regional_assertions,
            regional_assertion_support, transitions, transition_basis,
            notification_endpoints, notification_deliveries,
            notification_delivery_attempts, audit_events,
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
            IF EXISTS (
                SELECT FROM pg_roles
                WHERE rolname = 'socialname_migration_test_worker'
            ) THEN
                REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public
                    FROM socialname_migration_test_worker;
                REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public
                    FROM socialname_migration_test_worker;
                REVOKE ALL PRIVILEGES ON SCHEMA public
                    FROM socialname_migration_test_worker;
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
                ('rule_pack_trust_roots'), ('rule_pack_metadata'),
                ('rule_pack_promotions'), ('rule_pack_registry'),
                ('rule_site_promotion_high_water'),
                ('consent_grants'), ('consent_events'), ('searches'), ('search_targets'),
                ('search_events'),
                ('watches'), ('watch_targets'), ('watch_notification_endpoints'),
                ('watch_runs'), ('watch_run_targets'), ('probe_jobs'), ('probe_job_consumers'),
                ('observations'), ('assertions'), ('assertion_support'),
                ('regional_assertions'), ('regional_assertion_support'), ('transitions'),
                ('transition_basis'), ('notification_endpoints'),
                ('notification_deliveries'), ('notification_delivery_attempts'),
                ('audit_events'), ('data_lineage_edges'),
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
    assert_eq!(required_tables, 42);

    let tenant_policies: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_policies \
         WHERE schemaname = 'public' AND policyname = 'tenant_isolation'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(tenant_policies, 32);

    let forced_rls_tables: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_class \
         WHERE relnamespace = 'public'::regnamespace AND relkind = 'r' \
         AND relrowsecurity AND relforcerowsecurity",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(forced_rls_tables, 32);

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
            id, tenant_id, watch_id, requested_username, ordinal,
            normalized_username, site_id, created_at
        )
        VALUES (
            '00000000-0000-0000-0000-000000000052',
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000051',
            'fixture-user', 0, 'fixture-user', 'github', '2026-01-01T00:00:00Z'
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
            'webhook', decode(repeat('71', 32), 'hex'), decode(repeat('72', 32), 'hex'),
            'endpoint-key-1', 'active', '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z'
        );
        "#,
    ))
    .await
    .unwrap();

    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let endpoint_id = Uuid::parse_str("00000000-0000-0000-0000-000000000071").unwrap();
    let destination = "https://hooks.example.test/socialname";
    let ciphertext = delivery_secrets()
        .seal_destination(tenant_id, endpoint_id, destination)
        .unwrap();
    let destination_hash = Sha256::digest(destination.as_bytes()).to_vec();
    sqlx::query(
        "UPDATE notification_endpoints \
         SET destination_ciphertext = $3, destination_hash = $4 \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(endpoint_id)
    .bind(ciphertext)
    .bind(destination_hash)
    .execute(pool)
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
            scopes: &[
                "workspace:read",
                "search:read",
                "search:write",
                "watch:read",
                "watch:write",
            ],
            state: "active",
            expires_at_unix_ms: None,
        },
        ApiKeyFixture {
            id: "00000000-0000-0000-0000-0000000000b2",
            tenant_id: "00000000-0000-0000-0000-000000000002",
            membership_id: "00000000-0000-0000-0000-000000000012",
            prefix: "bbbbbbbbbbbbbbbb",
            secret_byte: 0x22,
            scopes: &[
                "workspace:read",
                "search:read",
                "search:write",
                "watch:read",
                "watch:write",
            ],
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
        GRANT SELECT ON
            sites, consent_grants, searches, search_targets, search_events,
            watches, watch_targets, watch_notification_endpoints,
            notification_endpoints, watch_runs, watch_run_targets,
            transitions, transition_basis, notification_deliveries,
            rule_versions
            TO socialname_migration_test_app;
        GRANT INSERT ON
            searches, search_targets, search_events, watches, watch_targets,
            watch_notification_endpoints
            TO socialname_migration_test_app;
        GRANT UPDATE (state, updated_at, completed_at) ON searches
            TO socialname_migration_test_app;
        GRANT UPDATE (state, completed_at) ON search_targets
            TO socialname_migration_test_app;
        GRANT UPDATE (
            state, revision, maximum_age_ms, interval_seconds, jitter_percent,
            maximum_probes_per_run, maximum_bytes_per_run, retention_days,
            next_run_at, updated_at
        ) ON watches TO socialname_migration_test_app;
        GRANT UPDATE (retired_at) ON watch_targets
            TO socialname_migration_test_app;
        GRANT UPDATE (state, completed_at) ON watch_runs, watch_run_targets
            TO socialname_migration_test_app;
        GRANT DELETE ON watch_notification_endpoints
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
    pool.execute(sqlx::raw_sql(
        r#"
        INSERT INTO data_lineage_edges (
            id, tenant_id, parent_kind, parent_id, child_kind, child_id,
            purpose, created_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000093',
            '00000000-0000-0000-0000-000000000001',
            'transition', '00000000-0000-0000-0000-000000000082',
            'notification_delivery', '00000000-0000-0000-0000-000000000092',
            'confirmed_webhook', '2026-01-01T00:04:00Z'
        );
        INSERT INTO audit_events (
            id, tenant_id, action, resource_kind, resource_id,
            occurred_at, details
        ) VALUES (
            '00000000-0000-0000-0000-000000000094',
            '00000000-0000-0000-0000-000000000001',
            'notification.delivery.queued', 'notification_delivery',
            '00000000-0000-0000-0000-000000000092',
            '2026-01-01T00:04:00Z', '{"channel":"webhook"}'
        );
        "#,
    ))
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

async fn assert_watch_api_boundary(administrator_pool: &PgPool) {
    let application_database_url = env::var(TEST_APPLICATION_DATABASE_URL_ENV)
        .expect("application database URL must accompany the PostgreSQL integration test");
    let application_pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&application_database_url)
        .await
        .unwrap();
    let request = WatchCreateRequest {
        schema: ProtocolVersion::ApiV1,
        targets: TargetSelection {
            usernames: vec![Username::new("watch-target").unwrap()],
            site_ids: vec![SiteId::new("github").unwrap()],
        },
        region_classes: vec![RegionClass::new("jp").unwrap()],
        maximum_age_ms: 3_600_000,
        schedule: WatchSchedule {
            interval_seconds: 3_600,
            jitter_percent: 10,
        },
        probe_budget: ProbeBudget {
            maximum_probes_per_run: 1,
            maximum_bytes_per_run: 1_048_576,
        },
        notification_endpoint_ids: vec![
            NotificationEndpointId::new("00000000-0000-0000-0000-000000000071").unwrap(),
        ],
        private_history_consent_grant_id: ConsentGrantId::new(
            "00000000-0000-0000-0000-000000000031",
        )
        .unwrap(),
        retention_days: 400,
    };
    let created = server_request_with(
        &application_pool,
        Method::POST,
        "/v1/watches",
        Some(&api_key_token("aaaaaaaaaaaaaaaa", 0x11)),
        &[("content-type", "application/json")],
        serde_json::to_string(&request).unwrap(),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let location = created.headers()[LOCATION].to_str().unwrap().to_owned();
    let created_resource: WatchResource = serde_json::from_value(json_body(created).await).unwrap();
    assert!(created_resource.validate().is_ok());
    assert_eq!(created_resource.state, WatchState::Active);
    assert_eq!(created_resource.revision, 1);
    assert!(created_resource.next_run_at_unix_ms.is_some());
    assert_eq!(
        location,
        format!("/v1/watches/{}", created_resource.watch_id.as_str())
    );

    let wrong_scope = server_request(
        &application_pool,
        &location,
        Some(&api_key_token("cccccccccccccccc", 0x33)),
    )
    .await;
    assert_eq!(wrong_scope.status(), StatusCode::FORBIDDEN);
    assert_api_error(wrong_scope, ApiErrorCode::Forbidden).await;
    let foreign = server_request(
        &application_pool,
        &location,
        Some(&api_key_token("bbbbbbbbbbbbbbbb", 0x22)),
    )
    .await;
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
    assert_api_error(foreign, ApiErrorCode::NotFound).await;

    let paused_patch = WatchPatchRequest {
        schema: ProtocolVersion::ApiV1,
        expected_revision: 1,
        state: Some(WatchStateUpdate::Paused),
        maximum_age_ms: None,
        schedule: None,
        probe_budget: None,
        notification_endpoint_ids: None,
        retention_days: None,
    };
    let paused = server_request_with(
        &application_pool,
        Method::PATCH,
        &location,
        Some(&api_key_token("aaaaaaaaaaaaaaaa", 0x11)),
        &[("content-type", "application/json")],
        serde_json::to_string(&paused_patch).unwrap(),
    )
    .await;
    assert_eq!(paused.status(), StatusCode::OK);
    let paused_resource: WatchResource = serde_json::from_value(json_body(paused).await).unwrap();
    assert_eq!(paused_resource.state, WatchState::Paused);
    assert_eq!(paused_resource.revision, 2);
    assert_eq!(paused_resource.next_run_at_unix_ms, None);
    assert!(paused_resource.validate().is_ok());

    let stale = server_request_with(
        &application_pool,
        Method::PATCH,
        &location,
        Some(&api_key_token("aaaaaaaaaaaaaaaa", 0x11)),
        &[("content-type", "application/json")],
        serde_json::to_string(&paused_patch).unwrap(),
    )
    .await;
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    assert_api_error(stale, ApiErrorCode::Conflict).await;

    let active_patch = WatchPatchRequest {
        schema: ProtocolVersion::ApiV1,
        expected_revision: 2,
        state: Some(WatchStateUpdate::Active),
        maximum_age_ms: Some(60_000),
        schedule: None,
        probe_budget: None,
        notification_endpoint_ids: None,
        retention_days: None,
    };
    let active = server_request_with(
        &application_pool,
        Method::PATCH,
        &location,
        Some(&api_key_token("aaaaaaaaaaaaaaaa", 0x11)),
        &[("content-type", "application/json")],
        serde_json::to_string(&active_patch).unwrap(),
    )
    .await;
    assert_eq!(active.status(), StatusCode::OK);
    let active_resource: WatchResource = serde_json::from_value(json_body(active).await).unwrap();
    assert_eq!(active_resource.state, WatchState::Active);
    assert_eq!(active_resource.revision, 3);
    assert!(active_resource.next_run_at_unix_ms.is_some());
    assert!(active_resource.validate().is_ok());

    let deleted = server_request_with(
        &application_pool,
        Method::DELETE,
        &location,
        Some(&api_key_token("aaaaaaaaaaaaaaaa", 0x11)),
        &[],
        String::new(),
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::OK);
    let deleted_resource: WatchResource = serde_json::from_value(json_body(deleted).await).unwrap();
    assert_eq!(deleted_resource.state, WatchState::Deleting);
    assert_eq!(deleted_resource.revision, 4);
    assert_eq!(deleted_resource.next_run_at_unix_ms, None);
    assert!(deleted_resource.validate().is_ok());
    let repeated_delete = server_request_with(
        &application_pool,
        Method::DELETE,
        &location,
        Some(&api_key_token("aaaaaaaaaaaaaaaa", 0x11)),
        &[],
        String::new(),
    )
    .await;
    let repeated_resource: WatchResource =
        serde_json::from_value(json_body(repeated_delete).await).unwrap();
    assert_eq!(repeated_resource.revision, 4);

    let persisted_target: (String, Option<String>, i32) = sqlx::query_as(
        "SELECT requested_username, normalized_username, ordinal \
         FROM watch_targets WHERE watch_id = $1",
    )
    .bind(Uuid::parse_str(created_resource.watch_id.as_str()).unwrap())
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(persisted_target.0, "watch-target");
    assert_eq!(persisted_target.1, None);
    assert_eq!(persisted_target.2, 0);

    application_pool.close().await;
}

const MANAGED_JOB_RULE: &str = r#"
schema: socialname.dev/site/v1
id: managed-test
name: Managed Test
homepage: https://example.com/
profile_url: https://example.com/u/{username:path}
namespace: person
username:
  pattern: '^[a-z][a-z0-9-]{2,31}$'
  normalization: lowercase
probes:
  - id: profile
    http:
      method: GET
      url: https://example.com/u/{username:path}
      allowed_hosts: [example.com]
      expected_body: bounded_text
      transport_profile: minimal
plan:
  type: single
  probe: profile
classification:
  found:
    status:
      probe: profile
      in: [200]
  not_found:
    status:
      probe: profile
      in: [404]
metadata:
  enabled: true
"#;

const MANAGED_MANIFEST_HASH: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const MANAGED_ENGINE_HASH: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
const SECOND_CONSENT_GRANT_ID: &str = "00000000-0000-0000-0000-0000000000d3";

async fn assert_managed_probe_job_boundary(administrator_pool: &PgPool) {
    let fixture = managed_rule_fixture();
    let initial_rule_trust = fixture.trust.clone();
    let initial_trust_id = fixture.trust.content_id().unwrap();
    apply_rule_pack_metadata(
        administrator_pool,
        Some(InitialRulePackTrust {
            trust: &fixture.trust,
            expected_trust_id: &initial_trust_id,
        }),
        &fixture.canary_metadata,
        std::slice::from_ref(&fixture.candidate),
        current_unix_ms(),
    )
    .await
    .unwrap();
    let applied = apply_rule_pack_metadata(
        administrator_pool,
        None,
        &fixture.general_metadata,
        std::slice::from_ref(&fixture.candidate),
        current_unix_ms(),
    )
    .await
    .unwrap();
    assert_eq!(
        apply_rule_pack_metadata(
            administrator_pool,
            None,
            &fixture.general_metadata,
            std::slice::from_ref(&fixture.candidate),
            current_unix_ms(),
        )
        .await
        .unwrap_err(),
        RuleRegistryError::InvalidTransition
    );
    let rule_version_id = applied.rule_version_id("managed-test").unwrap();
    install_managed_rule_fixtures(administrator_pool, rule_version_id).await;
    install_worker_role(administrator_pool).await;
    let candidate = fixture.candidate;

    let worker_database_url = env::var(TEST_WORKER_DATABASE_URL_ENV)
        .expect("worker database URL must accompany the PostgreSQL integration test");
    let worker_pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&worker_database_url)
        .await
        .unwrap();
    let store = JobStore::new(worker_pool.clone());
    let managed_rule = fixture.managed_rule;
    let binding = store.bind_rule(&managed_rule).await.unwrap();
    assert_eq!(binding.rule_version_id(), rule_version_id);
    let coordinator_owner_can_cross_forced_rls: bool = sqlx::query_scalar(
        "SELECT bool_and(owner.rolsuper OR owner.rolbypassrls) \
         FROM pg_proc AS proc \
         JOIN pg_roles AS owner ON owner.oid = proc.proowner \
         WHERE proc.proname IN (\
              'socialname_worker_resolve_rule', \
              'socialname_worker_rule_version_available', \
             'socialname_worker_lock_next_target', \
             'socialname_worker_lock_due_watch', \
             'socialname_worker_lock_next_watch_target', \
             'socialname_worker_claim_job', \
             'socialname_worker_lock_claim_consent', \
             'socialname_worker_claim_webhook_delivery'\
         )",
    )
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert!(coordinator_owner_can_cross_forced_rls);

    let worker_security: (bool, bool, bool, i64) = sqlx::query_as(
        "SELECT current_user = 'socialname_migration_test_worker', \
                rolsuper, rolbypassrls, \
                (SELECT count(*) FROM searches) \
         FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&worker_pool)
    .await
    .unwrap();
    assert!(worker_security.0);
    assert!(!worker_security.1);
    assert!(!worker_security.2);
    assert_eq!(worker_security.3, 0);
    let can_read_credentials: bool = sqlx::query_scalar(
        "SELECT has_table_privilege(\
            current_user, 'api_key_credentials', 'SELECT'\
         )",
    )
    .fetch_one(&worker_pool)
    .await
    .unwrap();
    assert!(!can_read_credentials);

    let application_database_url = env::var(TEST_APPLICATION_DATABASE_URL_ENV)
        .expect("application database URL must accompany the PostgreSQL integration test");
    let application_pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&application_database_url)
        .await
        .unwrap();
    let first = create_managed_search(
        &application_pool,
        "managed-job-first",
        "private-search-target",
        "00000000-0000-0000-0000-000000000031",
    )
    .await;
    let second = create_managed_search(
        &application_pool,
        "managed-job-second",
        "private-search-target",
        "00000000-0000-0000-0000-000000000031",
    )
    .await;
    let third = create_managed_search(
        &application_pool,
        "managed-job-third",
        "private-search-target",
        SECOND_CONSENT_GRANT_ID,
    )
    .await;
    let managed_watch = create_managed_watch(
        &application_pool,
        "private-search-target",
        SECOND_CONSENT_GRANT_ID,
    )
    .await;
    let managed_watch_id = Uuid::parse_str(managed_watch.watch_id.as_str()).unwrap();
    let managed_watch_target_id: Uuid =
        sqlx::query_scalar("SELECT id FROM watch_targets WHERE watch_id = $1")
            .bind(managed_watch_id)
            .fetch_one(administrator_pool)
            .await
            .unwrap();
    sqlx::query(
        "UPDATE watches SET \
             updated_at = created_at, \
             next_run_at = clock_timestamp() - interval '1 microsecond' \
         WHERE id = $1",
    )
    .bind(managed_watch_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    let first_watch_run_id = match store.plan_one_watch(&binding).await.unwrap() {
        WatchPlanOutcome::Planned {
            run_id,
            target_count: 1,
        } => run_id,
        other => panic!("expected one planned watch target, got {other:?}"),
    };
    assert_eq!(
        store.plan_one_watch(&binding).await.unwrap(),
        WatchPlanOutcome::Idle
    );

    let first_expansion = store.expand_one(&binding, &managed_rule).await.unwrap();
    let first_job_id = match first_expansion {
        ExpandOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected a new managed job, got {other:?}"),
    };
    assert_eq!(
        store.expand_one(&binding, &managed_rule).await.unwrap(),
        ExpandOutcome::Coalesced {
            job_id: first_job_id
        }
    );
    let second_job_id = match store.expand_one(&binding, &managed_rule).await.unwrap() {
        ExpandOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected a purpose-isolated job, got {other:?}"),
    };
    assert_ne!(first_job_id, second_job_id);
    assert_eq!(
        store
            .expand_one_watch(&binding, &managed_rule)
            .await
            .unwrap(),
        ExpandOutcome::Coalesced {
            job_id: second_job_id
        }
    );
    assert_eq!(
        store.expand_one(&binding, &managed_rule).await.unwrap(),
        ExpandOutcome::Idle
    );

    let active_jobs: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM probe_jobs \
         WHERE rule_version_id = $1 AND state = 'queued'",
    )
    .bind(binding.rule_version_id())
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    let consumers: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM probe_job_consumers \
         WHERE probe_job_id IN ($1, $2)",
    )
    .bind(first_job_id)
    .bind(second_job_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(active_jobs, 2);
    assert_eq!(consumers, 4);

    let first_claim = store
        .claim(&binding, "worker-a", Duration::from_secs(5))
        .await
        .unwrap()
        .unwrap();
    let second_claim = store
        .claim(&binding, "worker-b", Duration::from_secs(5))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_claim.job_id(), first_job_id);
    assert_eq!(second_claim.job_id(), second_job_id);
    assert!(
        store
            .claim(&binding, "worker-extra", Duration::from_secs(5))
            .await
            .unwrap()
            .is_none()
    );

    let definitive = managed_result(
        Verdict::Found,
        None,
        DomainEvidenceClass::E4StructuredIdentity,
        &candidate.rule_hash,
        "b",
    );
    assert_eq!(
        store
            .record_result(&second_claim, &definitive, 3)
            .await
            .unwrap(),
        JobDisposition::Succeeded
    );
    assert_eq!(
        store
            .record_result(&second_claim, &definitive, 3)
            .await
            .unwrap(),
        JobDisposition::AlreadyFinal
    );
    let completed_watch_run: (String, i32, i32, i64, i64, String) = sqlx::query_as(
        "SELECT run.state, run.reserved_probes, run.maximum_probes, \
                run.reserved_bytes, run.maximum_bytes, target.state \
         FROM watch_runs AS run \
         JOIN watch_run_targets AS target \
           ON target.tenant_id = run.tenant_id \
          AND target.watch_run_id = run.id \
         WHERE run.id = $1",
    )
    .bind(first_watch_run_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(completed_watch_run.0, "completed");
    assert_eq!(completed_watch_run.1, 1);
    assert_eq!(completed_watch_run.2, 4);
    assert_eq!(
        completed_watch_run.3,
        i64::try_from(managed_rule.maximum_inspected_bytes_per_search()).unwrap()
    );
    assert!(completed_watch_run.3 <= completed_watch_run.4);
    assert_eq!(completed_watch_run.5, "completed");

    let current_assertion: (Uuid, String, String, i64) = sqlx::query_as(
        "SELECT id, verdict, quality, \
                (extract(epoch FROM expires_at - observed_at) * 1000)::bigint \
         FROM assertions \
         WHERE tenant_id = '00000000-0000-0000-0000-000000000001' \
           AND normalized_username = 'private-search-target' \
           AND site_id = 'managed-test' \
           AND is_current AND withdrawn_at IS NULL",
    )
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(current_assertion.1, "found");
    assert_eq!(current_assertion.2, "verified");
    assert_eq!(current_assertion.3, 24 * 60 * 60 * 1_000);
    let assertion_support_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM assertion_support \
         WHERE assertion_id = $1 AND support_role = 'supporting'",
    )
    .bind(current_assertion.0)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(assertion_support_count, 1);
    let regional_assertion: (String, String, String, String, i32, bool, i64) = sqlx::query_as(
        "SELECT regional.region_class, regional.outcome_kind, \
                    regional.verdict, regional.quality, \
                    regional.support_group_count, regional.managed_support, \
                    count(support.observation_id) \
             FROM regional_assertions AS regional \
             LEFT JOIN regional_assertion_support AS support \
               ON support.tenant_id = regional.tenant_id \
              AND support.regional_assertion_id = regional.id \
             WHERE regional.assertion_id = $1 \
             GROUP BY regional.id",
    )
    .bind(current_assertion.0)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(
        regional_assertion,
        (
            "jp".to_owned(),
            "definitive".to_owned(),
            "found".to_owned(),
            "verified".to_owned(),
            1,
            true,
            1,
        )
    );
    let baseline: (String, Uuid) = sqlx::query_as(
        "SELECT account_state, account_assertion_id \
         FROM watch_targets WHERE id = $1",
    )
    .bind(managed_watch_target_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(baseline, ("found".to_owned(), current_assertion.0));
    let initial_account_transitions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM transitions \
         WHERE watch_target_id = $1 AND transition_class = 'account_state'",
    )
    .bind(managed_watch_target_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(initial_account_transitions, 0);
    let assertion_event_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM search_events \
         WHERE search_id = $1 AND event_type = 'assertion_updated'",
    )
    .bind(Uuid::parse_str(third.search_id.as_str()).unwrap())
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(assertion_event_count, 1);
    let assertion_event_payload: serde_json::Value = sqlx::query_scalar(
        "SELECT payload FROM search_events \
         WHERE search_id = $1 AND event_type = 'assertion_updated'",
    )
    .bind(Uuid::parse_str(third.search_id.as_str()).unwrap())
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    let assertion_event: SearchEvent = serde_json::from_value(assertion_event_payload).unwrap();
    assert!(assertion_event.validate().is_ok());
    let SearchEventData::AssertionUpdated { assertion } = assertion_event.data else {
        panic!("expected assertion update event");
    };
    let regional = assertion
        .regional_assertions
        .expect("new assertion events include regional projections");
    assert_eq!(regional.len(), 1);
    assert_eq!(regional[0].region_class.as_str(), "jp");

    let historical_assertion_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO assertions (\
            id, tenant_id, normalized_username, site_id, outcome_kind, verdict, \
            quality, evidence_class, observed_at, expires_at, \
            derivation_version, is_current, created_at\
         ) VALUES (\
            $1, '00000000-0000-0000-0000-000000000001', \
            'private-search-target', 'managed-test', 'definitive', 'not_found', \
            'verified', 'e3_explicit_endpoint', \
            clock_timestamp() - interval '2 hours', \
            clock_timestamp() - interval '1 hour', 'assertion/v1', false, \
            clock_timestamp() - interval '1 hour'\
         )",
    )
    .bind(historical_assertion_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE watch_targets \
         SET account_state = 'not_found', account_assertion_id = $2, \
             account_state_since = clock_timestamp() - interval '2 hours' \
         WHERE id = $1",
    )
    .bind(managed_watch_target_id)
    .bind(historical_assertion_id)
    .execute(administrator_pool)
    .await
    .unwrap();

    sqlx::query(
        "UPDATE watches SET \
             updated_at = created_at, \
             next_run_at = clock_timestamp() - interval '1 microsecond' \
         WHERE id = $1",
    )
    .bind(managed_watch_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    let freshness_run_id = match store.plan_one_watch(&binding).await.unwrap() {
        WatchPlanOutcome::Planned { run_id, .. } => run_id,
        other => panic!("expected a freshness watch run, got {other:?}"),
    };
    assert_eq!(
        store
            .expand_one_watch(&binding, &managed_rule)
            .await
            .unwrap(),
        ExpandOutcome::FreshObservationCompleted
    );
    let freshness_run: (String, i64, String) = sqlx::query_as(
        "SELECT run.state, run.reserved_bytes, target.state \
         FROM watch_runs AS run \
         JOIN watch_run_targets AS target \
           ON target.tenant_id = run.tenant_id \
          AND target.watch_run_id = run.id \
         WHERE run.id = $1",
    )
    .bind(freshness_run_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(
        freshness_run,
        ("completed".to_owned(), 0, "satisfied".to_owned())
    );
    let confirmed_appearance: (String, String, String, i64) = sqlx::query_as(
        "SELECT transition.from_state, transition.to_state, \
                transition.confirmation_basis, count(basis.observation_id) \
         FROM transitions AS transition \
         LEFT JOIN transition_basis AS basis \
           ON basis.tenant_id = transition.tenant_id \
          AND basis.transition_id = transition.id \
         WHERE transition.watch_target_id = $1 \
           AND transition.transition_class = 'account_state' \
         GROUP BY transition.id",
    )
    .bind(managed_watch_target_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(
        confirmed_appearance,
        (
            "not_found".to_owned(),
            "found".to_owned(),
            "managed_e4".to_owned(),
            1,
        )
    );
    let confirmed_baseline: (String, Uuid) = sqlx::query_as(
        "SELECT account_state, account_assertion_id \
         FROM watch_targets WHERE id = $1",
    )
    .bind(managed_watch_target_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(
        confirmed_baseline,
        ("found".to_owned(), current_assertion.0)
    );

    let conflicting_job_id = Uuid::new_v4();
    let conflicting_observation_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO probe_jobs (\
            id, tenant_id, normalized_username, site_id, rule_version_id, \
            region_class, work_key_hash, consent_grant_id, visibility, state, \
            available_at, created_at, updated_at, completed_at\
         ) VALUES (\
            $1, '00000000-0000-0000-0000-000000000001', \
            'private-search-target', 'managed-test', $2, 'us', \
            decode(repeat('ef', 32), 'hex'), $3, 'private', 'succeeded', \
            clock_timestamp(), clock_timestamp(), clock_timestamp(), \
            clock_timestamp()\
         )",
    )
    .bind(conflicting_job_id)
    .bind(binding.rule_version_id())
    .bind(Uuid::parse_str(SECOND_CONSENT_GRANT_ID).unwrap())
    .execute(administrator_pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO observations (\
            id, tenant_id, probe_job_id, consent_grant_id, \
            normalized_username, site_id, rule_version_id, outcome_kind, \
            verdict, evidence_class, evidence_digest, source, producer_kind, \
            visibility, region_class, rule_health_green, observed_at, \
            expires_at, created_at\
         ) VALUES (\
            $1, '00000000-0000-0000-0000-000000000001', $2, $3, \
            'private-search-target', 'managed-test', $4, 'definitive', \
            'not_found', 'e3_explicit_endpoint', \
            decode(repeat('ee', 32), 'hex'), 'managed_probe', \
            'managed_worker', 'private', 'us', true, clock_timestamp(), \
            clock_timestamp() + interval '15 minutes', clock_timestamp()\
         )",
    )
    .bind(conflicting_observation_id)
    .bind(conflicting_job_id)
    .bind(Uuid::parse_str(SECOND_CONSENT_GRANT_ID).unwrap())
    .bind(binding.rule_version_id())
    .execute(administrator_pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE watches SET \
             updated_at = created_at, \
             next_run_at = clock_timestamp() - interval '1 microsecond' \
         WHERE id = $1",
    )
    .bind(managed_watch_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    let conflict_run_id = match store.plan_one_watch(&binding).await.unwrap() {
        WatchPlanOutcome::Planned { run_id, .. } => run_id,
        other => panic!("expected a conflict replay run, got {other:?}"),
    };
    assert_eq!(
        store
            .expand_one_watch(&binding, &managed_rule)
            .await
            .unwrap(),
        ExpandOutcome::FreshObservationCompleted
    );
    let conflict_run_state: String =
        sqlx::query_scalar("SELECT state FROM watch_runs WHERE id = $1")
            .bind(conflict_run_id)
            .fetch_one(administrator_pool)
            .await
            .unwrap();
    assert_eq!(conflict_run_state, "completed");
    let conflicted_assertion: (Uuid, String, Option<String>, String, i64) = sqlx::query_as(
        "SELECT id, outcome_kind, verdict, quality, \
                (SELECT count(*) FROM assertion_support AS support \
                 WHERE support.tenant_id = assertion.tenant_id \
                   AND support.assertion_id = assertion.id \
                   AND support.support_role = 'conflicting') \
         FROM assertions AS assertion \
         WHERE tenant_id = '00000000-0000-0000-0000-000000000001' \
           AND normalized_username = 'private-search-target' \
           AND site_id = 'managed-test' \
           AND is_current AND withdrawn_at IS NULL",
    )
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(
        (
            conflicted_assertion.1.as_str(),
            conflicted_assertion.2.as_deref(),
            conflicted_assertion.3.as_str(),
            conflicted_assertion.4,
        ),
        ("inconclusive", None, "conflicted", 2)
    );
    let regional_conflict: Vec<(String, String, String, String, i64)> = sqlx::query_as(
        "SELECT regional.region_class, regional.outcome_kind, \
                regional.verdict, regional.quality, count(support.observation_id) \
         FROM regional_assertions AS regional \
         LEFT JOIN regional_assertion_support AS support \
           ON support.tenant_id = regional.tenant_id \
          AND support.regional_assertion_id = regional.id \
         WHERE regional.assertion_id = $1 \
         GROUP BY regional.id \
         ORDER BY regional.region_class",
    )
    .bind(conflicted_assertion.0)
    .fetch_all(administrator_pool)
    .await
    .unwrap();
    assert_eq!(
        regional_conflict,
        vec![
            (
                "jp".to_owned(),
                "definitive".to_owned(),
                "found".to_owned(),
                "verified".to_owned(),
                1,
            ),
            (
                "us".to_owned(),
                "definitive".to_owned(),
                "not_found".to_owned(),
                "verified".to_owned(),
                1,
            ),
        ]
    );
    let regional_lineage: (i64, i64) = sqlx::query_as(
        "SELECT \
            count(*) FILTER (WHERE parent_kind = 'observation' \
                              AND child_kind = 'regional_assertion'), \
            count(*) FILTER (WHERE parent_kind = 'regional_assertion' \
                              AND child_kind = 'assertion' AND child_id = $1) \
         FROM data_lineage_edges \
         WHERE tenant_id = '00000000-0000-0000-0000-000000000001'",
    )
    .bind(conflicted_assertion.0)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert!(regional_lineage.0 >= 3);
    assert_eq!(regional_lineage.1, 2);
    let conflict_account_state: (String, i64) = sqlx::query_as(
        "SELECT target.account_state, count(transition.id) \
         FROM watch_targets AS target \
         LEFT JOIN transitions AS transition \
           ON transition.tenant_id = target.tenant_id \
          AND transition.watch_target_id = target.id \
          AND transition.transition_class = 'account_state' \
         WHERE target.id = $1 \
         GROUP BY target.id",
    )
    .bind(managed_watch_target_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(conflict_account_state, ("found".to_owned(), 1));

    sqlx::query(
        "UPDATE watches \
         SET maximum_age_ms = 1, updated_at = created_at, \
             next_run_at = clock_timestamp() - interval '1 microsecond' \
         WHERE id = $1",
    )
    .bind(managed_watch_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    let verification_run_id = match store.plan_one_watch(&binding).await.unwrap() {
        WatchPlanOutcome::Planned { run_id, .. } => run_id,
        other => panic!("expected a regional verification run, got {other:?}"),
    };
    let verification_job_id = match store
        .expand_one_watch(&binding, &managed_rule)
        .await
        .unwrap()
    {
        ExpandOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected a regional verification job, got {other:?}"),
    };
    let verification_priority: (i16, String) =
        sqlx::query_as("SELECT priority, priority_reason FROM probe_jobs WHERE id = $1")
            .bind(verification_job_id)
            .fetch_one(administrator_pool)
            .await
            .unwrap();
    assert_eq!(verification_priority, (100, "regional_conflict".to_owned()));
    let verification_budget: (i32, i64) = sqlx::query_as(
        "SELECT reserved_probes, reserved_bytes \
         FROM watch_runs WHERE id = $1",
    )
    .bind(verification_run_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(verification_budget.0, 1);
    assert_eq!(
        verification_budget.1,
        i64::try_from(managed_rule.maximum_inspected_bytes_per_search()).unwrap()
    );
    sqlx::query(
        "UPDATE probe_jobs \
         SET state = 'cancelled', updated_at = clock_timestamp(), \
             completed_at = clock_timestamp() \
         WHERE id = $1 AND state = 'queued'",
    )
    .bind(verification_job_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE watch_run_targets \
         SET state = 'cancelled', completed_at = clock_timestamp() \
         WHERE watch_run_id = $1 AND state = 'queued'",
    )
    .bind(verification_run_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE watch_runs \
         SET state = 'cancelled', completed_at = clock_timestamp() \
         WHERE id = $1 AND state = 'running'",
    )
    .bind(verification_run_id)
    .execute(administrator_pool)
    .await
    .unwrap();

    sqlx::query(
        "UPDATE probe_jobs \
         SET updated_at = created_at, \
             lease_expires_at = created_at + interval '1 microsecond' \
         WHERE id = $1",
    )
    .bind(first_job_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    let reclaimed = store
        .claim(&binding, "worker-c", Duration::from_secs(5))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reclaimed.job_id(), first_job_id);
    assert_eq!(reclaimed.attempt_count(), 2);
    let timeout_result = managed_result(
        Verdict::Inconclusive,
        Some(InconclusiveReason::Timeout),
        DomainEvidenceClass::E0NoAccountEvidence,
        &candidate.rule_hash,
        "c",
    );
    assert_eq!(
        store
            .record_result(&first_claim, &timeout_result, 3)
            .await
            .unwrap_err(),
        JobError::StaleLease
    );
    assert_eq!(
        store
            .record_result(&reclaimed, &timeout_result, 3)
            .await
            .unwrap(),
        JobDisposition::RetryScheduled
    );
    sqlx::query(
        "UPDATE probe_jobs SET available_at = clock_timestamp() - interval '1 second' \
         WHERE id = $1",
    )
    .bind(first_job_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    let final_claim = store
        .claim(&binding, "worker-d", Duration::from_secs(5))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(final_claim.attempt_count(), 3);
    assert_eq!(
        store
            .record_result(&final_claim, &timeout_result, 3)
            .await
            .unwrap(),
        JobDisposition::Failed
    );

    assert!(managed_rule.maximum_inspected_bytes_per_search() > 1_024);
    let managed_watch_location = format!("/v1/watches/{}", managed_watch.watch_id.as_str());
    let budget_patch = WatchPatchRequest {
        schema: ProtocolVersion::ApiV1,
        expected_revision: 1,
        state: None,
        maximum_age_ms: Some(1),
        schedule: None,
        probe_budget: Some(ProbeBudget {
            maximum_probes_per_run: 1,
            maximum_bytes_per_run: 1_024,
        }),
        notification_endpoint_ids: None,
        retention_days: None,
    };
    let budget_response = server_request_with(
        &application_pool,
        Method::PATCH,
        &managed_watch_location,
        Some(&api_key_token("aaaaaaaaaaaaaaaa", 0x11)),
        &[("content-type", "application/json")],
        serde_json::to_string(&budget_patch).unwrap(),
    )
    .await;
    assert_eq!(budget_response.status(), StatusCode::OK);
    let budget_resource: WatchResource =
        serde_json::from_value(json_body(budget_response).await).unwrap();
    assert_eq!(budget_resource.revision, 2);
    sqlx::query(
        "UPDATE watches SET \
             updated_at = created_at, \
             next_run_at = clock_timestamp() - interval '1 microsecond' \
         WHERE id = $1",
    )
    .bind(managed_watch_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    let budget_run_id = match store.plan_one_watch(&binding).await.unwrap() {
        WatchPlanOutcome::Planned { run_id, .. } => run_id,
        other => panic!("expected a budget-limited watch run, got {other:?}"),
    };
    assert_eq!(
        store
            .expand_one_watch(&binding, &managed_rule)
            .await
            .unwrap(),
        ExpandOutcome::BudgetExceededCompleted
    );
    let budget_run: (String, i64, i64) = sqlx::query_as(
        "SELECT state, reserved_bytes, maximum_bytes \
         FROM watch_runs WHERE id = $1",
    )
    .bind(budget_run_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(budget_run, ("failed".to_owned(), 0, 1_024));

    let restored_patch = WatchPatchRequest {
        schema: ProtocolVersion::ApiV1,
        expected_revision: 2,
        state: None,
        maximum_age_ms: Some(1),
        schedule: None,
        probe_budget: Some(ProbeBudget {
            maximum_probes_per_run: 1,
            maximum_bytes_per_run: 1_048_576,
        }),
        notification_endpoint_ids: None,
        retention_days: None,
    };
    let restored_response = server_request_with(
        &application_pool,
        Method::PATCH,
        &managed_watch_location,
        Some(&api_key_token("aaaaaaaaaaaaaaaa", 0x11)),
        &[("content-type", "application/json")],
        serde_json::to_string(&restored_patch).unwrap(),
    )
    .await;
    assert_eq!(restored_response.status(), StatusCode::OK);
    let restored_resource: WatchResource =
        serde_json::from_value(json_body(restored_response).await).unwrap();
    assert_eq!(restored_resource.revision, 3);

    tokio::time::sleep(Duration::from_millis(2)).await;
    sqlx::query(
        "UPDATE watches SET \
             updated_at = created_at, \
             next_run_at = clock_timestamp() - interval '1 microsecond' \
         WHERE id = $1",
    )
    .bind(managed_watch_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    let degraded_run_id = match store.plan_one_watch(&binding).await.unwrap() {
        WatchPlanOutcome::Planned { run_id, .. } => run_id,
        other => panic!("expected a degradation watch run, got {other:?}"),
    };
    let degraded_job_id = match store
        .expand_one_watch(&binding, &managed_rule)
        .await
        .unwrap()
    {
        ExpandOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected a degradation probe job, got {other:?}"),
    };
    let degraded_claim = store
        .claim(&binding, "worker-degraded", Duration::from_secs(5))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(degraded_claim.job_id(), degraded_job_id);
    let uncertain = managed_result(
        Verdict::Inconclusive,
        Some(InconclusiveReason::SiteChanged),
        DomainEvidenceClass::E2DifferentialTemplate,
        &candidate.rule_hash,
        "d",
    );
    assert_eq!(
        store
            .record_result(&degraded_claim, &uncertain, 1)
            .await
            .unwrap(),
        JobDisposition::Succeeded
    );
    let degraded_run_state: String =
        sqlx::query_scalar("SELECT state FROM watch_runs WHERE id = $1")
            .bind(degraded_run_id)
            .fetch_one(administrator_pool)
            .await
            .unwrap();
    assert_eq!(degraded_run_state, "completed");
    let degraded_transition: (String, String, String, i64) = sqlx::query_as(
        "SELECT transition.from_state, transition.to_state, \
                transition.confirmation_basis, count(basis.observation_id) \
         FROM transitions AS transition \
         LEFT JOIN transition_basis AS basis \
           ON basis.tenant_id = transition.tenant_id \
          AND basis.transition_id = transition.id \
         WHERE transition.watch_target_id = $1 \
           AND transition.transition_class = 'measurement_health' \
         GROUP BY transition.id \
         ORDER BY max(transition.created_at) DESC \
         LIMIT 1",
    )
    .bind(managed_watch_target_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(
        degraded_transition,
        (
            "healthy".to_owned(),
            "degraded".to_owned(),
            "measurement_health_evidence".to_owned(),
            1,
        )
    );

    tokio::time::sleep(Duration::from_millis(2)).await;
    sqlx::query(
        "UPDATE watches SET \
             updated_at = created_at, \
             next_run_at = clock_timestamp() - interval '1 microsecond' \
         WHERE id = $1",
    )
    .bind(managed_watch_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    let unavailable_run_id = match store.plan_one_watch(&binding).await.unwrap() {
        WatchPlanOutcome::Planned { run_id, .. } => run_id,
        other => panic!("expected an unavailable watch run, got {other:?}"),
    };
    let unavailable_job_id = match store
        .expand_one_watch(&binding, &managed_rule)
        .await
        .unwrap()
    {
        ExpandOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected an unavailable probe job, got {other:?}"),
    };
    let unavailable_claim = store
        .claim(&binding, "worker-unavailable", Duration::from_secs(5))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unavailable_claim.job_id(), unavailable_job_id);
    assert_eq!(
        store
            .record_result(&unavailable_claim, &timeout_result, 1)
            .await
            .unwrap(),
        JobDisposition::Failed
    );
    let unavailable_run_state: String =
        sqlx::query_scalar("SELECT state FROM watch_runs WHERE id = $1")
            .bind(unavailable_run_id)
            .fetch_one(administrator_pool)
            .await
            .unwrap();
    assert_eq!(unavailable_run_state, "failed");
    let unavailable_transition: (String, String, i64, i64) = sqlx::query_as(
        "SELECT transition.from_state, transition.to_state, \
                count(basis.observation_id), \
                count(lineage.id) FILTER (\
                    WHERE lineage.parent_kind = 'probe_job' \
                      AND lineage.parent_id = $2 \
                      AND lineage.purpose = 'measurement_unavailable'\
                ) \
         FROM transitions AS transition \
         LEFT JOIN transition_basis AS basis \
           ON basis.tenant_id = transition.tenant_id \
          AND basis.transition_id = transition.id \
         LEFT JOIN data_lineage_edges AS lineage \
           ON lineage.tenant_id = transition.tenant_id \
          AND lineage.child_kind = 'transition' \
          AND lineage.child_id = transition.id \
         WHERE transition.watch_target_id = $1 \
           AND transition.transition_class = 'measurement_health' \
           AND transition.to_state = 'unavailable' \
         GROUP BY transition.id",
    )
    .bind(managed_watch_target_id)
    .bind(unavailable_job_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(
        unavailable_transition,
        ("degraded".to_owned(), "unavailable".to_owned(), 0, 1)
    );
    let account_state_after_degradation: (String, i64) = sqlx::query_as(
        "SELECT target.account_state, count(transition.id) \
         FROM watch_targets AS target \
         LEFT JOIN transitions AS transition \
           ON transition.tenant_id = target.tenant_id \
          AND transition.watch_target_id = target.id \
          AND transition.transition_class = 'account_state' \
         WHERE target.id = $1 \
         GROUP BY target.id",
    )
    .bind(managed_watch_target_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(account_state_after_degradation, ("found".to_owned(), 1));

    sqlx::query(
        "UPDATE watches SET \
             updated_at = created_at, \
             next_run_at = clock_timestamp() - interval '1 microsecond' \
         WHERE id = $1",
    )
    .bind(managed_watch_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    let cancelled_run_id = match store.plan_one_watch(&binding).await.unwrap() {
        WatchPlanOutcome::Planned { run_id, .. } => run_id,
        other => panic!("expected a cancellable watch run, got {other:?}"),
    };
    let cancelled_job_id = match store
        .expand_one_watch(&binding, &managed_rule)
        .await
        .unwrap()
    {
        ExpandOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected a watch-only managed job, got {other:?}"),
    };
    let pause_patch = WatchPatchRequest {
        schema: ProtocolVersion::ApiV1,
        expected_revision: 3,
        state: Some(WatchStateUpdate::Paused),
        maximum_age_ms: None,
        schedule: None,
        probe_budget: None,
        notification_endpoint_ids: None,
        retention_days: None,
    };
    let pause_response = server_request_with(
        &application_pool,
        Method::PATCH,
        &managed_watch_location,
        Some(&api_key_token("aaaaaaaaaaaaaaaa", 0x11)),
        &[("content-type", "application/json")],
        serde_json::to_string(&pause_patch).unwrap(),
    )
    .await;
    assert_eq!(pause_response.status(), StatusCode::OK);
    let paused_resource: WatchResource =
        serde_json::from_value(json_body(pause_response).await).unwrap();
    assert_eq!(paused_resource.state, WatchState::Paused);
    let cancelled_run: (String, String) = sqlx::query_as(
        "SELECT run.state, target.state \
         FROM watch_runs AS run \
         JOIN watch_run_targets AS target \
           ON target.tenant_id = run.tenant_id \
          AND target.watch_run_id = run.id \
         WHERE run.id = $1",
    )
    .bind(cancelled_run_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(
        cancelled_run,
        ("cancelled".to_owned(), "cancelled".to_owned())
    );
    assert!(
        store
            .claim(&binding, "worker-watch-cancel", Duration::from_secs(5))
            .await
            .unwrap()
            .is_none()
    );
    let cancelled_job_state: String =
        sqlx::query_scalar("SELECT state FROM probe_jobs WHERE id = $1")
            .bind(cancelled_job_id)
            .fetch_one(administrator_pool)
            .await
            .unwrap();
    assert_eq!(cancelled_job_state, "cancelled");

    let observation_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM observations WHERE probe_job_id = $1")
            .bind(second_job_id)
            .fetch_one(administrator_pool)
            .await
            .unwrap();
    let result_event_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM search_events \
         WHERE search_id = $1 AND event_type = 'definitive_result'",
    )
    .bind(Uuid::parse_str(third.search_id.as_str()).unwrap())
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    let first_failures: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM search_events \
         WHERE search_id IN ($1, $2) AND event_type = 'operational_failure'",
    )
    .bind(Uuid::parse_str(first.search_id.as_str()).unwrap())
    .bind(Uuid::parse_str(second.search_id.as_str()).unwrap())
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    let lineage_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM data_lineage_edges \
         WHERE child_kind IN ('probe_job', 'observation', 'search_event') \
           AND purpose IN (\
               'managed_probe_request', 'managed_measurement', \
               'search_result', 'operational_failure'\
           )",
    )
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(observation_count, 1);
    assert_eq!(result_event_count, 1);
    assert_eq!(first_failures, 2);
    assert!(lineage_count >= 7);

    for search in [&first, &second, &third] {
        let polled = server_request(
            &application_pool,
            &format!("/v1/searches/{}", search.search_id.as_str()),
            Some(&api_key_token("aaaaaaaaaaaaaaaa", 0x11)),
        )
        .await;
        let resource: SearchResource = serde_json::from_value(json_body(polled).await).unwrap();
        assert_eq!(resource.state, SearchState::Completed);
        assert_eq!(resource.progress.completed_targets, 1);
        assert!(resource.validate().is_ok());
    }

    let invalid = create_managed_search(
        &application_pool,
        "managed-job-invalid",
        "INVALID TARGET",
        "00000000-0000-0000-0000-000000000031",
    )
    .await;
    assert_eq!(
        store.expand_one(&binding, &managed_rule).await.unwrap(),
        ExpandOutcome::InvalidTargetCompleted
    );
    let invalid_payload: serde_json::Value = sqlx::query_scalar(
        "SELECT payload FROM search_events \
         WHERE search_id = $1 AND event_type = 'operational_failure'",
    )
    .bind(Uuid::parse_str(invalid.search_id.as_str()).unwrap())
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(invalid_payload["data"]["failure"]["kind"], "invalid_target");
    assert!(invalid_payload.to_string().find("not_found").is_none());

    let cancelled = create_managed_search(
        &application_pool,
        "managed-job-cancelled",
        "cancel-target",
        "00000000-0000-0000-0000-000000000031",
    )
    .await;
    let cancelled_job_id = match store.expand_one(&binding, &managed_rule).await.unwrap() {
        ExpandOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected cancellation job, got {other:?}"),
    };
    let cancellation_claim = store
        .claim(&binding, "worker-e", Duration::from_secs(5))
        .await
        .unwrap()
        .unwrap();
    let cancelled_response = server_request_with(
        &application_pool,
        Method::DELETE,
        &format!("/v1/searches/{}", cancelled.search_id.as_str()),
        Some(&api_key_token("aaaaaaaaaaaaaaaa", 0x11)),
        &[],
        String::new(),
    )
    .await;
    assert_eq!(cancelled_response.status(), StatusCode::OK);
    assert_eq!(
        store
            .execute_claim(
                &cancellation_claim,
                &managed_rule,
                current_unix_ms(),
                &tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap_err(),
        JobExecutionError::Cancelled
    );
    assert_eq!(
        store
            .record_rule_unavailable(&cancellation_claim, 3)
            .await
            .unwrap(),
        JobDisposition::Cancelled
    );
    assert!(
        store
            .claim(&binding, "worker-f", Duration::from_secs(5))
            .await
            .unwrap()
            .is_none()
    );
    let cancelled_job_state: String =
        sqlx::query_scalar("SELECT state FROM probe_jobs WHERE id = $1")
            .bind(cancelled_job_id)
            .fetch_one(administrator_pool)
            .await
            .unwrap();
    assert_eq!(cancelled_job_state, "cancelled");

    let confirmation_watch = create_managed_watch(
        &application_pool,
        "confirmation-priority-target",
        "00000000-0000-0000-0000-000000000031",
    )
    .await;
    let confirmation_watch_id = Uuid::parse_str(confirmation_watch.watch_id.as_str()).unwrap();
    let confirmation_watch_target_id: Uuid =
        sqlx::query_scalar("SELECT id FROM watch_targets WHERE watch_id = $1")
            .bind(confirmation_watch_id)
            .fetch_one(administrator_pool)
            .await
            .unwrap();
    let confirmation_baseline_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO assertions (\
            id, tenant_id, normalized_username, site_id, outcome_kind, verdict, \
            quality, evidence_class, observed_at, expires_at, \
            derivation_version, is_current, created_at\
         ) VALUES (\
            $1, '00000000-0000-0000-0000-000000000001', \
            'confirmation-priority-target', 'managed-test', \
            'definitive', 'found', 'verified', 'e4_structured_identity', \
            clock_timestamp() - interval '2 hours', \
            clock_timestamp() - interval '1 hour', 'assertion/v1', false, \
            clock_timestamp() - interval '1 hour'\
         )",
    )
    .bind(confirmation_baseline_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE watch_targets \
         SET account_state = 'found', account_assertion_id = $2, \
             account_state_since = clock_timestamp() - interval '2 hours' \
         WHERE id = $1",
    )
    .bind(confirmation_watch_target_id)
    .bind(confirmation_baseline_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE watches \
         SET updated_at = created_at, \
             next_run_at = clock_timestamp() - interval '1 microsecond' \
         WHERE id = $1",
    )
    .bind(confirmation_watch_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    let confirmation_run_id = match store.plan_one_watch(&binding).await.unwrap() {
        WatchPlanOutcome::Planned { run_id, .. } => run_id,
        other => panic!("expected an account confirmation run, got {other:?}"),
    };
    let confirmation_job_id = match store
        .expand_one_watch(&binding, &managed_rule)
        .await
        .unwrap()
    {
        ExpandOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected an account confirmation probe, got {other:?}"),
    };
    let confirmation_claim = store
        .claim(&binding, "worker-confirmation", Duration::from_secs(5))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(confirmation_claim.job_id(), confirmation_job_id);
    let mut managed_absence = managed_result(
        Verdict::NotFound,
        None,
        DomainEvidenceClass::E3ExplicitEndpoint,
        &candidate.rule_hash,
        "d",
    );
    managed_absence.username = "confirmation-priority-target".to_owned();
    assert_eq!(
        store
            .record_result(&confirmation_claim, &managed_absence, 3)
            .await
            .unwrap(),
        JobDisposition::Succeeded
    );
    let pending_confirmation: (String, String) = sqlx::query_as(
        "SELECT confirmation_status, pending_reason \
         FROM transitions \
         WHERE watch_target_id = $1 \
           AND transition_class = 'account_state'",
    )
    .bind(confirmation_watch_target_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(
        pending_confirmation,
        (
            "pending".to_owned(),
            "second_managed_observation_required".to_owned(),
        )
    );
    let confirmation_run_state: String =
        sqlx::query_scalar("SELECT state FROM watch_runs WHERE id = $1")
            .bind(confirmation_run_id)
            .fetch_one(administrator_pool)
            .await
            .unwrap();
    assert_eq!(confirmation_run_state, "completed");
    tokio::time::sleep(Duration::from_millis(2)).await;
    sqlx::query(
        "UPDATE watches \
         SET maximum_age_ms = 1, updated_at = created_at, \
             next_run_at = clock_timestamp() - interval '1 microsecond' \
         WHERE id = $1",
    )
    .bind(confirmation_watch_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    let follow_up_run_id = match store.plan_one_watch(&binding).await.unwrap() {
        WatchPlanOutcome::Planned { run_id, .. } => run_id,
        other => panic!("expected a managed confirmation follow-up, got {other:?}"),
    };
    let follow_up_job_id = match store
        .expand_one_watch(&binding, &managed_rule)
        .await
        .unwrap()
    {
        ExpandOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected a prioritized confirmation job, got {other:?}"),
    };
    let follow_up_priority: (i16, String) =
        sqlx::query_as("SELECT priority, priority_reason FROM probe_jobs WHERE id = $1")
            .bind(follow_up_job_id)
            .fetch_one(administrator_pool)
            .await
            .unwrap();
    assert_eq!(follow_up_priority, (50, "account_confirmation".to_owned()));
    sqlx::query(
        "UPDATE probe_jobs \
         SET state = 'cancelled', updated_at = clock_timestamp(), \
             completed_at = clock_timestamp() \
         WHERE id = $1 AND state = 'queued'",
    )
    .bind(follow_up_job_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE watch_run_targets \
         SET state = 'cancelled', completed_at = clock_timestamp() \
         WHERE watch_run_id = $1 AND state = 'queued'",
    )
    .bind(follow_up_run_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE watch_runs \
         SET state = 'cancelled', completed_at = clock_timestamp() \
         WHERE id = $1 AND state = 'running'",
    )
    .bind(follow_up_run_id)
    .execute(administrator_pool)
    .await
    .unwrap();

    let _withdrawn = create_managed_search(
        &application_pool,
        "managed-job-withdrawn",
        "private-search-target",
        SECOND_CONSENT_GRANT_ID,
    )
    .await;
    let withdrawn_job_id = match store.expand_one(&binding, &managed_rule).await.unwrap() {
        ExpandOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected consent withdrawal job, got {other:?}"),
    };
    let withdrawn_claim = store
        .claim(&binding, "worker-g", Duration::from_secs(30))
        .await
        .unwrap()
        .unwrap();
    sqlx::query(
        "UPDATE consent_grants SET withdrawn_at = clock_timestamp() \
         WHERE id = $1",
    )
    .bind(Uuid::parse_str(SECOND_CONSENT_GRANT_ID).unwrap())
    .execute(administrator_pool)
    .await
    .unwrap();
    assert_eq!(
        store
            .execute_claim(
                &withdrawn_claim,
                &managed_rule,
                current_unix_ms(),
                &tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap_err(),
        JobExecutionError::Cancelled
    );
    assert_eq!(
        store
            .record_rule_unavailable(&withdrawn_claim, 3)
            .await
            .unwrap(),
        JobDisposition::Cancelled
    );
    let withdrawn_observations: i64 =
        sqlx::query_scalar("SELECT count(*) FROM observations WHERE probe_job_id = $1")
            .bind(withdrawn_job_id)
            .fetch_one(administrator_pool)
            .await
            .unwrap();
    assert_eq!(withdrawn_observations, 0);

    let _degraded = create_managed_search(
        &application_pool,
        "managed-job-degraded",
        "private-search-target",
        "00000000-0000-0000-0000-000000000031",
    )
    .await;
    let degraded_job_id = match store.expand_one(&binding, &managed_rule).await.unwrap() {
        ExpandOutcome::Enqueued { job_id } => job_id,
        other => panic!("expected degraded-rule job, got {other:?}"),
    };
    let degraded_claim = store
        .claim(&binding, "worker-h", Duration::from_secs(30))
        .await
        .unwrap()
        .unwrap();
    sqlx::query(
        "INSERT INTO rule_health_records (\
            id, rule_version_id, region_class, state, evidence_id, \
            evidence_expires_at, summary, recorded_at\
         ) VALUES (\
            $1, $2, 'jp', 'degraded', $3, \
            clock_timestamp() + interval '10 minutes', '{}', clock_timestamp()\
         )",
    )
    .bind(Uuid::new_v4())
    .bind(binding.rule_version_id())
    .bind(Uuid::new_v4())
    .execute(administrator_pool)
    .await
    .unwrap();
    assert_eq!(
        store
            .execute_claim(
                &degraded_claim,
                &managed_rule,
                current_unix_ms(),
                &tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap_err(),
        JobExecutionError::Cancelled
    );
    assert_eq!(
        store
            .record_result(&degraded_claim, &definitive, 3)
            .await
            .unwrap_err(),
        JobError::RuleUnavailable
    );
    let degraded_observations: i64 =
        sqlx::query_scalar("SELECT count(*) FROM observations WHERE probe_job_id = $1")
            .bind(degraded_job_id)
            .fetch_one(administrator_pool)
            .await
            .unwrap();
    assert_eq!(degraded_observations, 0);

    assert_persisted_rule_pack_rotation_and_rollback(
        administrator_pool,
        &store,
        &candidate,
        &managed_rule,
        rule_version_id,
        &initial_rule_trust,
    )
    .await;
    assert_webhook_delivery_boundary(administrator_pool, worker_pool.clone()).await;
    application_pool.close().await;
    store.close().await;
}

fn managed_release_health(
    candidate: &CompiledSiteRule,
    sequence: u64,
    issued_at_unix_ms: i64,
    expires_at_unix_ms: i64,
) -> RuleHealthRecord {
    RuleHealthRecord {
        key: RuleHealthKey {
            site_id: DomainSiteId::new("managed-test"),
            rule_hash: candidate.rule_hash.clone(),
            region: "jp".to_owned(),
        },
        state: RuleHealth::Healthy,
        sequence,
        entered_at_unix_ms: issued_at_unix_ms - 2_000,
        updated_at_unix_ms: issued_at_unix_ms - 1_000,
        consecutive_recovery_passes: 0,
        consecutive_operational_failures: 0,
        last_manifest_hash: Some(MANAGED_MANIFEST_HASH.to_owned()),
        last_engine_hash: Some(MANAGED_ENGINE_HASH.to_owned()),
        last_evidence_expires_at_unix_ms: Some(expires_at_unix_ms + 1_000),
        last_evidence_ids: vec![
            format!("{:064x}", 0x100_u64 + sequence),
            format!("{:064x}", 0x200_u64 + sequence),
        ],
    }
}

fn managed_release_promotion(
    key: &PromotionSigningKey,
    candidate: &CompiledSiteRule,
    pack: &CompiledRulePack,
    previous_rule_pack_hash: Option<&str>,
    sequence: u64,
    issued_at_unix_ms: i64,
    expires_at_unix_ms: i64,
) -> PromotionEnvelope {
    PromotionBuilder::new()
        .build(
            key,
            PromotionBuildRequest {
                sequence,
                candidate,
                rule_pack: pack,
                previous_rule_pack_hash,
                health_records: &[managed_release_health(
                    candidate,
                    sequence,
                    issued_at_unix_ms,
                    expires_at_unix_ms,
                )],
                required_regions: &BTreeSet::from(["jp".to_owned()]),
                issued_at_unix_ms,
                expires_at_unix_ms,
            },
        )
        .unwrap()
}

struct ManagedMetadataRequest<'a> {
    signing_keys: &'a [RulePackMetadataSigningKey],
    trust: RulePackTrustV1,
    pack: &'a CompiledRulePack,
    previous_rule_pack_hash: Option<&'a str>,
    promotion: PromotionEnvelope,
    sequence: u64,
    rollout_stage: RulePackRolloutStage,
    issued_at_unix_ms: i64,
    expires_at_unix_ms: i64,
}

fn managed_release_metadata(request: ManagedMetadataRequest<'_>) -> RulePackMetadataEnvelope {
    let required_regions = BTreeSet::from(["jp".to_owned()]);
    let eligible_workers = if request.rollout_stage == RulePackRolloutStage::Canary {
        BTreeSet::from(["managed-test-worker".to_owned()])
    } else {
        BTreeSet::new()
    };
    RulePackMetadataBuilder::new()
        .build(
            request.signing_keys,
            RulePackMetadataBuildRequest {
                sequence: request.sequence,
                rule_pack: request.pack,
                previous_rule_pack_hash: request.previous_rule_pack_hash,
                required_regions: &required_regions,
                rollout_stage: request.rollout_stage,
                eligible_regions: &required_regions,
                eligible_workers: &eligible_workers,
                issued_at_unix_ms: request.issued_at_unix_ms,
                expires_at_unix_ms: request.expires_at_unix_ms,
                trust: request.trust,
                promotions: &[request.promotion],
            },
        )
        .unwrap()
}

async fn assert_persisted_rule_pack_rotation_and_rollback(
    administrator_pool: &PgPool,
    store: &JobStore,
    first_candidate: &CompiledSiteRule,
    stale_managed_rule: &ManagedRule,
    first_rule_version_id: Uuid,
    initial_trust: &RulePackTrustV1,
) {
    let compiler = RuleCompiler::new();
    let first_pack = compiler
        .compile_pack(std::slice::from_ref(first_candidate))
        .unwrap();
    let mut second_source = first_candidate.source.clone();
    second_source.metadata.notes = "staged replacement".to_owned();
    let second_candidate = compiler
        .compile_source(second_source, Some("managed-test"))
        .unwrap();
    let second_pack = compiler
        .compile_pack(std::slice::from_ref(&second_candidate))
        .unwrap();
    let old_metadata_key =
        RulePackMetadataSigningKey::from_seed("managed-job-test", [9; 32]).unwrap();
    let new_metadata_key =
        RulePackMetadataSigningKey::from_seed("managed-job-next", [10; 32]).unwrap();
    let new_promotion_key = PromotionSigningKey::from_seed("managed-job-next", [10; 32]).unwrap();
    let now = current_unix_ms();
    let promotion_expires_at = now + 10 * 60 * 1_000;
    let metadata_expires_at = promotion_expires_at - 1_000;
    let overlapping_trust = RulePackTrustV1 {
        schema: RULE_PACK_TRUST_V1.to_owned(),
        generation: 2,
        threshold: 2,
        keys: BTreeMap::from([
            (
                old_metadata_key.key_id().to_owned(),
                old_metadata_key.verifying_key_hex(),
            ),
            (
                new_metadata_key.key_id().to_owned(),
                new_metadata_key.verifying_key_hex(),
            ),
        ]),
        expires_at_unix_ms: initial_trust.expires_at_unix_ms + 10 * 60 * 1_000,
    };
    let second_canary = managed_release_metadata(ManagedMetadataRequest {
        signing_keys: &[old_metadata_key.clone(), new_metadata_key.clone()],
        trust: overlapping_trust.clone(),
        pack: &second_pack,
        previous_rule_pack_hash: Some(&first_pack.content_hash),
        promotion: managed_release_promotion(
            &new_promotion_key,
            &second_candidate,
            &second_pack,
            Some(&first_pack.content_hash),
            3,
            now - 500,
            promotion_expires_at,
        ),
        sequence: 3,
        rollout_stage: RulePackRolloutStage::Canary,
        issued_at_unix_ms: now - 500,
        expires_at_unix_ms: metadata_expires_at,
    });
    apply_rule_pack_metadata(
        administrator_pool,
        None,
        &second_canary,
        std::slice::from_ref(&second_candidate),
        now,
    )
    .await
    .unwrap();
    let staged_trust_states: Vec<(i64, String)> =
        sqlx::query_as("SELECT generation, state FROM rule_pack_trust_roots ORDER BY generation")
            .fetch_all(administrator_pool)
            .await
            .unwrap();
    assert_eq!(
        staged_trust_states,
        vec![(1, "active".to_owned()), (2, "staged".to_owned())]
    );
    let staged_registry: (i64, String, String) = sqlx::query_as(
        "SELECT current_trust_generation, \
                encode(active_metadata_id, 'hex'), encode(staged_metadata_id, 'hex') \
         FROM rule_pack_registry WHERE singleton",
    )
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(staged_registry.0, 1);
    assert_eq!(staged_registry.1, stale_managed_rule.metadata_id());
    assert_eq!(staged_registry.2, second_canary.metadata_id);
    let second_general = managed_release_metadata(ManagedMetadataRequest {
        signing_keys: &[old_metadata_key.clone(), new_metadata_key.clone()],
        trust: overlapping_trust.clone(),
        pack: &second_pack,
        previous_rule_pack_hash: Some(&first_pack.content_hash),
        promotion: managed_release_promotion(
            &new_promotion_key,
            &second_candidate,
            &second_pack,
            Some(&first_pack.content_hash),
            4,
            now - 400,
            promotion_expires_at,
        ),
        sequence: 4,
        rollout_stage: RulePackRolloutStage::General,
        issued_at_unix_ms: now - 400,
        expires_at_unix_ms: metadata_expires_at,
    });
    apply_rule_pack_metadata(
        administrator_pool,
        None,
        &second_general,
        std::slice::from_ref(&second_candidate),
        now,
    )
    .await
    .unwrap();
    let activated_trust_states: Vec<(i64, String)> =
        sqlx::query_as("SELECT generation, state FROM rule_pack_trust_roots ORDER BY generation")
            .fetch_all(administrator_pool)
            .await
            .unwrap();
    assert_eq!(
        activated_trust_states,
        vec![(1, "retired".to_owned()), (2, "active".to_owned())]
    );

    let new_only_trust = RulePackTrustV1 {
        schema: RULE_PACK_TRUST_V1.to_owned(),
        generation: 3,
        threshold: 1,
        keys: BTreeMap::from([(
            new_metadata_key.key_id().to_owned(),
            new_metadata_key.verifying_key_hex(),
        )]),
        expires_at_unix_ms: overlapping_trust.expires_at_unix_ms + 10 * 60 * 1_000,
    };
    let rollback = managed_release_metadata(ManagedMetadataRequest {
        signing_keys: &[old_metadata_key, new_metadata_key],
        trust: new_only_trust.clone(),
        pack: &first_pack,
        previous_rule_pack_hash: Some(&second_pack.content_hash),
        promotion: managed_release_promotion(
            &new_promotion_key,
            first_candidate,
            &first_pack,
            Some(&second_pack.content_hash),
            5,
            now - 300,
            promotion_expires_at,
        ),
        sequence: 5,
        rollout_stage: RulePackRolloutStage::Rollback,
        issued_at_unix_ms: now - 300,
        expires_at_unix_ms: metadata_expires_at,
    });
    apply_rule_pack_metadata(
        administrator_pool,
        None,
        &rollback,
        std::slice::from_ref(first_candidate),
        now,
    )
    .await
    .unwrap();
    let validated_rollback = RulePackMetadataVerifier::new()
        .validate_at(&rollback, &new_only_trust, now)
        .unwrap();
    let rollback_rule = ManagedRule::activate(
        &validated_rollback,
        &first_pack,
        "managed-test",
        "jp",
        "managed-test-worker",
        now,
    )
    .unwrap();

    sqlx::query(
        "INSERT INTO rule_health_records (\
            id, rule_version_id, region_class, state, evidence_id, \
            evidence_expires_at, summary, recorded_at\
         ) VALUES (\
            $1, $2, 'jp', 'healthy', $3, \
            to_timestamp($4::double precision / 1000.0), '{}', \
            clock_timestamp()\
         )",
    )
    .bind(Uuid::new_v4())
    .bind(first_rule_version_id)
    .bind(Uuid::new_v4())
    .bind(promotion_expires_at)
    .execute(administrator_pool)
    .await
    .unwrap();
    assert_eq!(
        store.bind_rule(stale_managed_rule).await.unwrap_err(),
        JobError::RuleUnavailable
    );
    assert_eq!(
        store
            .bind_rule(&rollback_rule)
            .await
            .unwrap()
            .rule_version_id(),
        first_rule_version_id
    );
    let registry: (i64, i64, bool, bool, String) = sqlx::query_as(
        "SELECT highest_sequence, current_trust_generation, \
                staged_metadata_id IS NULL, last_known_good_metadata_id IS NULL, \
                encode(active_metadata_id, 'hex') \
         FROM rule_pack_registry WHERE singleton",
    )
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(registry.0, 5);
    assert_eq!(registry.1, 3);
    assert!(registry.2);
    assert!(registry.3);
    assert_eq!(registry.4, rollback.metadata_id);
    let pack_states: Vec<(String, String)> = sqlx::query_as(
        "SELECT encode(pack_hash, 'hex'), state FROM rule_packs \
         WHERE pack_hash IN ($1, $2) ORDER BY encode(pack_hash, 'hex')",
    )
    .bind(hex::decode(&first_pack.content_hash).unwrap())
    .bind(hex::decode(&second_pack.content_hash).unwrap())
    .fetch_all(administrator_pool)
    .await
    .unwrap();
    assert!(pack_states.contains(&(first_pack.content_hash.clone(), "active".to_owned())));
    assert!(pack_states.contains(&(second_pack.content_hash.clone(), "retired".to_owned())));
    let high_water: (i64, String) = sqlx::query_as(
        "SELECT highest_sequence, encode(metadata_id, 'hex') \
         FROM rule_site_promotion_high_water WHERE site_id = 'managed-test'",
    )
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(high_water, (5, rollback.metadata_id.clone()));
    let trust_states: Vec<(i64, String)> =
        sqlx::query_as("SELECT generation, state FROM rule_pack_trust_roots ORDER BY generation")
            .fetch_all(administrator_pool)
            .await
            .unwrap();
    assert_eq!(
        trust_states,
        vec![
            (1, "retired".to_owned()),
            (2, "retired".to_owned()),
            (3, "active".to_owned()),
        ]
    );
    assert_eq!(
        apply_rule_pack_metadata(
            administrator_pool,
            None,
            &second_general,
            std::slice::from_ref(&second_candidate),
            now,
        )
        .await
        .unwrap_err(),
        RuleRegistryError::InvalidArtifact
    );
}

fn delivery_secrets() -> DeliverySecrets {
    DeliverySecrets::new("endpoint-key-1", [7; 32], "signing-key-1", [9; 32]).unwrap()
}

struct CapturedWebhookRequest {
    destination_matches: bool,
    delivery_id: String,
    signature: String,
    signing_key_id: String,
    attempt_count: u32,
    body: Vec<u8>,
}

struct ScriptedWebhookTransport {
    results: Mutex<VecDeque<Result<u16, WebhookSendError>>>,
    requests: Mutex<Vec<CapturedWebhookRequest>>,
}

impl ScriptedWebhookTransport {
    fn new(results: impl IntoIterator<Item = Result<u16, WebhookSendError>>) -> Self {
        Self {
            results: Mutex::new(results.into_iter().collect()),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn requests(&self) -> std::sync::MutexGuard<'_, Vec<CapturedWebhookRequest>> {
        self.requests.lock().unwrap()
    }
}

impl WebhookTransport for ScriptedWebhookTransport {
    fn send<'a>(
        &'a self,
        request: &'a WebhookRequest,
    ) -> Pin<Box<dyn Future<Output = Result<u16, WebhookSendError>> + Send + 'a>> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(CapturedWebhookRequest {
                destination_matches: request.destination()
                    == "https://hooks.example.test/socialname",
                delivery_id: request.delivery_id().to_owned(),
                signature: request.signature().to_owned(),
                signing_key_id: request.signing_key_id().to_owned(),
                attempt_count: request.attempt_count(),
                body: request.body().to_vec(),
            });
            self.results
                .lock()
                .unwrap()
                .pop_front()
                .expect("scripted webhook result")
        })
    }
}

async fn assert_webhook_delivery_boundary(administrator_pool: &PgPool, worker_pool: PgPool) {
    let initial_delivery_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM notification_deliveries")
            .fetch_one(administrator_pool)
            .await
            .unwrap();
    assert!(initial_delivery_count >= 4);
    let unique_logical_keys: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT encode(logical_notification_key, 'hex')) \
         FROM notification_deliveries",
    )
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(unique_logical_keys, initial_delivery_count);

    let store = DeliveryStore::new(worker_pool);
    let secrets = delivery_secrets();
    let retry_then_success =
        ScriptedWebhookTransport::new([Err(WebhookSendError::Timeout), Ok(204)]);
    let now = current_unix_ms();
    let first = process_one_delivery(
        &store,
        &secrets,
        &retry_then_success,
        DeliveryProcessConfig {
            worker_id: "webhook-worker",
            lease: Duration::from_secs(10),
            maximum_attempts: 3,
            timestamp_unix_ms: now,
            cancellation: &tokio_util::sync::CancellationToken::new(),
        },
    )
    .await
    .unwrap();
    let (delivery_id, first_attempt) = match first {
        DeliveryProcessOutcome::RetryScheduled {
            delivery_id,
            attempt_count,
        } => (delivery_id, attempt_count),
        other => panic!("expected retry scheduling, got {other:?}"),
    };
    assert_eq!(first_attempt, 1);
    sqlx::query(
        "UPDATE notification_deliveries \
         SET next_attempt_at = created_at \
         WHERE id = $1",
    )
    .bind(delivery_id)
    .execute(administrator_pool)
    .await
    .unwrap();
    let second = process_one_delivery(
        &store,
        &secrets,
        &retry_then_success,
        DeliveryProcessConfig {
            worker_id: "webhook-worker",
            lease: Duration::from_secs(10),
            maximum_attempts: 3,
            timestamp_unix_ms: now + 1,
            cancellation: &tokio_util::sync::CancellationToken::new(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        second,
        DeliveryProcessOutcome::Delivered {
            delivery_id,
            attempt_count: 2,
        }
    );
    {
        let requests = retry_then_success.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|request| request.destination_matches));
        assert_eq!(requests[0].delivery_id, requests[1].delivery_id);
        assert_eq!(requests[0].body, requests[1].body);
        assert_eq!(requests[0].attempt_count, 1);
        assert_eq!(requests[1].attempt_count, 2);
        assert_eq!(requests[0].signing_key_id, "signing-key-1");
        assert!(requests[0].signature.starts_with("v1="));
        assert_ne!(requests[0].signature, requests[1].signature);
        let payload: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(payload["schema"], "socialname.dev/api/v1");
        assert_eq!(payload["transition"]["confirmation"]["status"], "confirmed");
    }

    let permanent = ScriptedWebhookTransport::new([Ok(400)]);
    let permanently_failed = process_one_delivery(
        &store,
        &secrets,
        &permanent,
        DeliveryProcessConfig {
            worker_id: "webhook-worker",
            lease: Duration::from_secs(10),
            maximum_attempts: 3,
            timestamp_unix_ms: now + 2,
            cancellation: &tokio_util::sync::CancellationToken::new(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        permanently_failed,
        DeliveryProcessOutcome::PermanentlyFailed {
            attempt_count: 1,
            ..
        }
    ));

    let stale_claim = store
        .claim("stale-worker", Duration::from_secs(5), 3)
        .await
        .unwrap()
        .unwrap();
    sqlx::query(
        "UPDATE notification_deliveries \
         SET lease_started_at = '2019-01-01T00:00:00Z', \
             lease_expires_at = '2020-01-01T00:00:00Z' \
         WHERE id = $1",
    )
    .bind(stale_claim.delivery_id())
    .execute(administrator_pool)
    .await
    .unwrap();
    let reclaimed = store
        .claim("reclaim-worker", Duration::from_secs(5), 3)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reclaimed.delivery_id(), stale_claim.delivery_id());
    assert_eq!(reclaimed.attempt_count(), stale_claim.attempt_count() + 1);
    assert_eq!(
        store.record_send_result(&stale_claim, Ok(204), 3).await,
        Err(DeliveryError::StaleLease)
    );
    assert!(matches!(
        store
            .record_send_result(&reclaimed, Ok(204), 3)
            .await
            .unwrap(),
        DeliveryProcessOutcome::Delivered { .. }
    ));

    let exhausted = store
        .claim("crash-worker", Duration::from_secs(5), 1)
        .await
        .unwrap()
        .unwrap();
    sqlx::query(
        "UPDATE notification_deliveries \
         SET lease_started_at = '2019-01-01T00:00:00Z', \
             lease_expires_at = '2020-01-01T00:00:00Z' \
         WHERE id = $1",
    )
    .bind(exhausted.delivery_id())
    .execute(administrator_pool)
    .await
    .unwrap();
    assert!(
        store
            .claim("reclaim-worker", Duration::from_secs(5), 1)
            .await
            .unwrap()
            .is_none()
    );
    let exhausted_state: (String, Option<String>) = sqlx::query_as(
        "SELECT state, last_error_code \
         FROM notification_deliveries WHERE id = $1",
    )
    .bind(exhausted.delivery_id())
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(
        exhausted_state,
        (
            "permanently_failed".to_owned(),
            Some("lease_expired".to_owned())
        )
    );

    let final_delivery_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM notification_deliveries")
            .fetch_one(administrator_pool)
            .await
            .unwrap();
    assert_eq!(final_delivery_count, initial_delivery_count);
    let untraced_deliveries: i64 = sqlx::query_scalar(
        "SELECT count(*) \
         FROM notification_deliveries AS delivery \
         WHERE NOT EXISTS (\
             SELECT 1 FROM data_lineage_edges AS lineage \
             WHERE lineage.tenant_id = delivery.tenant_id \
               AND lineage.parent_kind = 'transition' \
               AND lineage.parent_id = delivery.transition_id \
               AND lineage.child_kind = 'notification_delivery' \
               AND lineage.child_id = delivery.id\
         )",
    )
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(untraced_deliveries, 0);
    let attempt_events: i64 =
        sqlx::query_scalar("SELECT count(*) FROM notification_delivery_attempts")
            .fetch_one(administrator_pool)
            .await
            .unwrap();
    let attempt_lineage: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM data_lineage_edges \
         WHERE child_kind = 'notification_delivery_attempt' \
           AND purpose = 'webhook_attempt'",
    )
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(attempt_lineage, attempt_events);
    let leaked_audit_details: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events \
         WHERE details::text LIKE '%hooks.example%' \
            OR details::text LIKE '%private-search-target%'",
    )
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(leaked_audit_details, 0);

    store.close().await;
}

async fn assert_monitoring_console_boundary(administrator_pool: &PgPool) {
    let application_database_url = env::var(TEST_APPLICATION_DATABASE_URL_ENV)
        .expect("application database URL must accompany the PostgreSQL integration test");
    let application_pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&application_database_url)
        .await
        .unwrap();
    let reader_token = api_key_token("aaaaaaaaaaaaaaaa", 0x11);
    let other_tenant_token = api_key_token("bbbbbbbbbbbbbbbb", 0x22);
    let wrong_scope_token = api_key_token("cccccccccccccccc", 0x33);
    let managed_watch_id: Uuid = sqlx::query_scalar(
        "SELECT target.watch_id \
         FROM transitions AS transition \
         JOIN watch_targets AS target \
           ON target.tenant_id = transition.tenant_id \
          AND target.id = transition.watch_target_id \
         WHERE transition.tenant_id = $1 \
           AND transition.transition_class = 'measurement_health' \
         ORDER BY transition.detected_at DESC \
         LIMIT 1",
    )
    .bind(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap())
    .fetch_one(administrator_pool)
    .await
    .unwrap();

    let wrong_scope = server_request(
        &application_pool,
        "/v1/watches?limit=1",
        Some(&wrong_scope_token),
    )
    .await;
    assert_eq!(wrong_scope.status(), StatusCode::FORBIDDEN);
    assert_api_error(wrong_scope, ApiErrorCode::Forbidden).await;

    let first = server_request(
        &application_pool,
        "/v1/watches?limit=1",
        Some(&reader_token),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let first_page: WatchListPage = serde_json::from_value(json_body(first).await).unwrap();
    assert!(first_page.validate().is_ok());
    assert_eq!(first_page.watches.len(), 1);
    let first_watch_id = first_page.watches[0].watch_id.clone();
    let cursor = first_page.next_cursor.as_ref().unwrap().as_str();

    let second = server_request(
        &application_pool,
        &format!("/v1/watches?limit=1&after={cursor}"),
        Some(&reader_token),
    )
    .await;
    assert_eq!(second.status(), StatusCode::OK);
    let second_page: WatchListPage = serde_json::from_value(json_body(second).await).unwrap();
    assert!(second_page.validate().is_ok());
    assert_eq!(second_page.watches.len(), 1);
    assert_ne!(second_page.watches[0].watch_id, first_watch_id);

    let foreign_cursor = server_request(
        &application_pool,
        &format!("/v1/watches?limit=1&after={managed_watch_id}"),
        Some(&other_tenant_token),
    )
    .await;
    assert_eq!(foreign_cursor.status(), StatusCode::BAD_REQUEST);
    assert_api_error(foreign_cursor, ApiErrorCode::InvalidRequest).await;

    let foreign_page = server_request(
        &application_pool,
        "/v1/watches?limit=50",
        Some(&other_tenant_token),
    )
    .await;
    assert_eq!(foreign_page.status(), StatusCode::OK);
    let foreign_page: WatchListPage =
        serde_json::from_value(json_body(foreign_page).await).unwrap();
    assert!(foreign_page.validate().is_ok());
    assert!(foreign_page.watches.is_empty());

    let foreign_timeline = server_request(
        &application_pool,
        &format!("/v1/watches/{managed_watch_id}/transitions"),
        Some(&other_tenant_token),
    )
    .await;
    assert_eq!(foreign_timeline.status(), StatusCode::NOT_FOUND);
    assert_api_error(foreign_timeline, ApiErrorCode::NotFound).await;

    let timeline = server_request(
        &application_pool,
        &format!("/v1/watches/{managed_watch_id}/transitions?limit=50"),
        Some(&reader_token),
    )
    .await;
    assert_eq!(timeline.status(), StatusCode::OK);
    let timeline_json = json_body(timeline).await;
    let timeline_page: WatchTransitionPage = serde_json::from_value(timeline_json.clone()).unwrap();
    assert!(timeline_page.validate().is_ok());
    assert!(timeline_page.entries.len() >= 3);
    assert!(timeline_page.entries.iter().any(|entry| {
        matches!(
            &entry.transition.change,
            socialname_protocol::TransitionChange::AccountState { .. }
        )
    }));
    assert!(timeline_page.entries.iter().any(|entry| {
        matches!(
            &entry.transition.change,
            socialname_protocol::TransitionChange::MeasurementHealth { .. }
        )
    }));
    let delivery_states = timeline_page
        .entries
        .iter()
        .flat_map(|entry| entry.deliveries.iter())
        .map(|delivery| delivery.state)
        .collect::<Vec<_>>();
    assert!(delivery_states.contains(&socialname_protocol::NotificationDeliveryState::Delivered));
    assert!(
        delivery_states
            .contains(&socialname_protocol::NotificationDeliveryState::PermanentlyFailed)
    );
    let serialized = serde_json::to_string(&timeline_json).unwrap();
    for forbidden in [
        "destination",
        "signature",
        "request_body_sha256",
        "worker_id",
        "hooks.example",
    ] {
        assert!(!serialized.contains(forbidden));
    }

    let first_transition = server_request(
        &application_pool,
        &format!("/v1/watches/{managed_watch_id}/transitions?limit=1"),
        Some(&reader_token),
    )
    .await;
    let first_transition_page: WatchTransitionPage =
        serde_json::from_value(json_body(first_transition).await).unwrap();
    assert_eq!(first_transition_page.entries.len(), 1);
    let transition_cursor = first_transition_page.next_cursor.unwrap();
    let continued = server_request(
        &application_pool,
        &format!(
            "/v1/watches/{managed_watch_id}/transitions?limit=1&after={}",
            transition_cursor.as_str()
        ),
        Some(&reader_token),
    )
    .await;
    let continued_page: WatchTransitionPage =
        serde_json::from_value(json_body(continued).await).unwrap();
    assert_eq!(continued_page.entries.len(), 1);
    assert_ne!(
        continued_page.entries[0].transition.transition_id,
        transition_cursor
    );

    let direct_transition_count: i64 = sqlx::query_scalar(
        "SELECT count(*) \
         FROM transitions AS transition \
         JOIN watch_targets AS target \
           ON target.tenant_id = transition.tenant_id \
          AND target.id = transition.watch_target_id \
         WHERE target.watch_id = $1",
    )
    .bind(managed_watch_id)
    .fetch_one(administrator_pool)
    .await
    .unwrap();
    assert_eq!(
        i64::try_from(timeline_page.entries.len()).unwrap(),
        direct_transition_count
    );

    application_pool.close().await;
}

struct ManagedRuleFixture {
    managed_rule: ManagedRule,
    candidate: CompiledSiteRule,
    trust: RulePackTrustV1,
    canary_metadata: RulePackMetadataEnvelope,
    general_metadata: RulePackMetadataEnvelope,
}

fn managed_rule_fixture() -> ManagedRuleFixture {
    let compiler = RuleCompiler::new();
    let candidate = compiler
        .compile_yaml(MANAGED_JOB_RULE, Some("managed-test"))
        .unwrap();
    let pack = compiler
        .compile_pack(std::slice::from_ref(&candidate))
        .unwrap();
    let now = current_unix_ms();
    let evidence_expires_at = now + 10 * 60 * 1_000;
    let health = RuleHealthRecord {
        key: RuleHealthKey {
            site_id: DomainSiteId::new("managed-test"),
            rule_hash: candidate.rule_hash.clone(),
            region: "jp".to_owned(),
        },
        state: RuleHealth::Healthy,
        sequence: 2,
        entered_at_unix_ms: now - 2_000,
        updated_at_unix_ms: now - 1_000,
        consecutive_recovery_passes: 0,
        consecutive_operational_failures: 0,
        last_manifest_hash: Some(MANAGED_MANIFEST_HASH.to_owned()),
        last_engine_hash: Some(MANAGED_ENGINE_HASH.to_owned()),
        last_evidence_expires_at_unix_ms: Some(evidence_expires_at),
        last_evidence_ids: vec!["3".repeat(64), "4".repeat(64)],
    };
    let required_regions = BTreeSet::from(["jp".to_owned()]);
    let key = PromotionSigningKey::from_seed("managed-job-test", [9; 32]).unwrap();
    let canary_promotion = PromotionBuilder::new()
        .build(
            &key,
            PromotionBuildRequest {
                sequence: 1,
                candidate: &candidate,
                rule_pack: &pack,
                previous_rule_pack_hash: None,
                health_records: std::slice::from_ref(&health),
                required_regions: &required_regions,
                issued_at_unix_ms: now - 500,
                expires_at_unix_ms: evidence_expires_at,
            },
        )
        .unwrap();
    let metadata_key = RulePackMetadataSigningKey::from_seed("managed-job-test", [9; 32]).unwrap();
    let trust = RulePackTrustV1 {
        schema: RULE_PACK_TRUST_V1.to_owned(),
        generation: 1,
        threshold: 1,
        keys: BTreeMap::from([(
            metadata_key.key_id().to_owned(),
            metadata_key.verifying_key_hex(),
        )]),
        expires_at_unix_ms: evidence_expires_at + 10 * 60 * 1_000,
    };
    let canary_metadata = RulePackMetadataBuilder::new()
        .build(
            std::slice::from_ref(&metadata_key),
            RulePackMetadataBuildRequest {
                sequence: 1,
                rule_pack: &pack,
                previous_rule_pack_hash: None,
                required_regions: &required_regions,
                rollout_stage: RulePackRolloutStage::Canary,
                eligible_regions: &required_regions,
                eligible_workers: &BTreeSet::from(["managed-test-worker".to_owned()]),
                issued_at_unix_ms: now - 500,
                expires_at_unix_ms: evidence_expires_at - 1_000,
                trust: trust.clone(),
                promotions: &[canary_promotion],
            },
        )
        .unwrap();
    let general_promotion = PromotionBuilder::new()
        .build(
            &key,
            PromotionBuildRequest {
                sequence: 2,
                candidate: &candidate,
                rule_pack: &pack,
                previous_rule_pack_hash: None,
                health_records: &[health],
                required_regions: &required_regions,
                issued_at_unix_ms: now - 400,
                expires_at_unix_ms: evidence_expires_at,
            },
        )
        .unwrap();
    let general_metadata = RulePackMetadataBuilder::new()
        .build(
            &[metadata_key],
            RulePackMetadataBuildRequest {
                sequence: 2,
                rule_pack: &pack,
                previous_rule_pack_hash: None,
                required_regions: &required_regions,
                rollout_stage: RulePackRolloutStage::General,
                eligible_regions: &required_regions,
                eligible_workers: &BTreeSet::new(),
                issued_at_unix_ms: now - 400,
                expires_at_unix_ms: evidence_expires_at - 1_000,
                trust: trust.clone(),
                promotions: &[general_promotion],
            },
        )
        .unwrap();
    let validated = RulePackMetadataVerifier::new()
        .validate_at(&general_metadata, &trust, now)
        .unwrap();
    let managed = ManagedRule::activate(
        &validated,
        &pack,
        "managed-test",
        "jp",
        "managed-test-worker",
        now,
    )
    .unwrap();
    ManagedRuleFixture {
        managed_rule: managed,
        candidate,
        trust,
        canary_metadata,
        general_metadata,
    }
}

async fn install_managed_rule_fixtures(pool: &PgPool, rule_version_id: Uuid) {
    let now = current_unix_ms();
    sqlx::query(
        "INSERT INTO rule_health_records (\
            id, rule_version_id, region_class, state, evidence_id, \
            evidence_expires_at, summary, recorded_at\
         ) VALUES (\
            $1, $2, 'jp', 'healthy', $3, \
            to_timestamp($4::double precision / 1000.0), '{}', \
            to_timestamp($5::double precision / 1000.0)\
         )",
    )
    .bind(Uuid::new_v4())
    .bind(rule_version_id)
    .bind(Uuid::new_v4())
    .bind(now + 10 * 60 * 1_000)
    .bind(now - 1_000)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO consent_grants (\
            id, tenant_id, membership_id, subject_kind, purpose, \
            collection_profile_version, notice_version, source, granted_at\
         ) VALUES (\
            $1, '00000000-0000-0000-0000-000000000001', \
            '00000000-0000-0000-0000-000000000011', 'account', \
            'private_history', 'profile-v1', 'notice-v1', 'web', \
            '2026-01-01T00:00:00Z'\
         )",
    )
    .bind(Uuid::parse_str(SECOND_CONSENT_GRANT_ID).unwrap())
    .execute(pool)
    .await
    .unwrap();
}

async fn install_worker_role(pool: &PgPool) {
    pool.execute(sqlx::raw_sql(
        r#"
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT FROM pg_roles
                WHERE rolname = 'socialname_migration_test_worker'
            ) THEN
                CREATE ROLE socialname_migration_test_worker
                    LOGIN PASSWORD 'socialname-worker-test-password'
                    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            END IF;
        END
        $$;
        ALTER ROLE socialname_migration_test_worker
            LOGIN PASSWORD 'socialname-worker-test-password'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
        GRANT USAGE ON SCHEMA public TO socialname_migration_test_worker;
        GRANT SELECT ON
            consent_grants, searches, search_targets, search_events, probe_jobs,
            probe_job_consumers, data_lineage_edges, audit_events,
            rule_versions, watches, watch_targets,
            watch_notification_endpoints, notification_endpoints, watch_runs,
            watch_run_targets, observations, assertions, assertion_support,
            regional_assertions, regional_assertion_support, transitions,
            transition_basis, notification_deliveries,
            notification_delivery_attempts
            TO socialname_migration_test_worker;
        GRANT INSERT ON
            search_events, probe_jobs, probe_job_consumers, observations,
            assertions, assertion_support, regional_assertions,
            regional_assertion_support, transitions, transition_basis,
            notification_deliveries, notification_delivery_attempts,
            audit_events, data_lineage_edges, watch_runs, watch_run_targets
            TO socialname_migration_test_worker;
        GRANT UPDATE (state, updated_at, completed_at) ON searches
            TO socialname_migration_test_worker;
        GRANT UPDATE (normalized_username, state, completed_at) ON search_targets
            TO socialname_migration_test_worker;
        GRANT UPDATE (next_run_at, updated_at) ON watches
            TO socialname_migration_test_worker;
        GRANT UPDATE (
            normalized_username, account_state, account_assertion_id,
            account_state_since
        ) ON watch_targets
            TO socialname_migration_test_worker;
        GRANT UPDATE (is_current) ON assertions
            TO socialname_migration_test_worker;
        GRANT UPDATE (
            confirmation_status, confirmation_basis, pending_reason,
            suppression_reason
        ) ON transitions TO socialname_migration_test_worker;
        GRANT UPDATE (state, reserved_bytes, completed_at) ON watch_runs
            TO socialname_migration_test_worker;
        GRANT UPDATE (
            state, probe_job_id, observation_id, reserved_bytes, completed_at
        ) ON watch_run_targets TO socialname_migration_test_worker;
        GRANT UPDATE (
            state, attempt_count, available_at, lease_owner, lease_expires_at,
            last_error_code, priority, updated_at, completed_at
        ) ON probe_jobs TO socialname_migration_test_worker;
        GRANT UPDATE (
            state, attempt_count, next_attempt_at, delivered_at,
            last_error_code, lease_owner, lease_started_at, lease_expires_at
        ) ON notification_deliveries TO socialname_migration_test_worker;
        GRANT EXECUTE ON FUNCTION
            socialname_worker_resolve_rule(
                text, bytea, bytea, text, bytea, bigint, bytea, bigint
            ),
            socialname_worker_rule_version_available(uuid, text),
            socialname_worker_lock_next_target(uuid, text),
            socialname_worker_lock_due_watch(uuid, text),
            socialname_worker_lock_next_watch_target(uuid, text),
            socialname_worker_claim_job(uuid, text, text, integer),
            socialname_worker_lock_claim_consent(uuid, integer, text),
            socialname_worker_claim_webhook_delivery(text, integer, integer)
            TO socialname_migration_test_worker;
        "#,
    ))
    .await
    .unwrap();
}

async fn create_managed_search(
    application_pool: &PgPool,
    idempotency_key: &str,
    username: &str,
    consent_grant_id: &str,
) -> SearchResource {
    let request = SearchCreateRequest {
        schema: ProtocolVersion::ApiV1,
        targets: TargetSelection {
            usernames: vec![Username::new(username).unwrap()],
            site_ids: vec![SiteId::new("managed-test").unwrap()],
        },
        mode: SearchMode::Remote,
        sync: SyncPolicy::Private,
        consent_grant_id: Some(ConsentGrantId::new(consent_grant_id).unwrap()),
        maximum_age_ms: 60_000,
        region_classes: vec![RegionClass::new("jp").unwrap()],
    };
    let response = server_request_with(
        application_pool,
        Method::POST,
        "/v1/searches",
        Some(&api_key_token("aaaaaaaaaaaaaaaa", 0x11)),
        &[
            ("content-type", "application/json"),
            ("idempotency-key", idempotency_key),
        ],
        serde_json::to_string(&request).unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let resource: SearchResource = serde_json::from_value(json_body(response).await).unwrap();
    assert_eq!(resource.state, SearchState::Accepted);
    resource
}

async fn create_managed_watch(
    application_pool: &PgPool,
    username: &str,
    consent_grant_id: &str,
) -> WatchResource {
    let request = WatchCreateRequest {
        schema: ProtocolVersion::ApiV1,
        targets: TargetSelection {
            usernames: vec![Username::new(username).unwrap()],
            site_ids: vec![SiteId::new("managed-test").unwrap()],
        },
        region_classes: vec![RegionClass::new("jp").unwrap()],
        maximum_age_ms: 60_000,
        schedule: WatchSchedule {
            interval_seconds: 300,
            jitter_percent: 20,
        },
        probe_budget: ProbeBudget {
            maximum_probes_per_run: 4,
            maximum_bytes_per_run: 1_048_576,
        },
        notification_endpoint_ids: vec![
            NotificationEndpointId::new("00000000-0000-0000-0000-000000000071").unwrap(),
        ],
        private_history_consent_grant_id: ConsentGrantId::new(consent_grant_id).unwrap(),
        retention_days: 400,
    };
    let response = server_request_with(
        application_pool,
        Method::POST,
        "/v1/watches",
        Some(&api_key_token("aaaaaaaaaaaaaaaa", 0x11)),
        &[("content-type", "application/json")],
        serde_json::to_string(&request).unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    serde_json::from_value(json_body(response).await).unwrap()
}

fn managed_result(
    verdict: Verdict,
    inconclusive_reason: Option<InconclusiveReason>,
    evidence_class: DomainEvidenceClass,
    rule_hash: &str,
    digest_character: &str,
) -> SearchResult {
    SearchResult {
        site_id: "managed-test".to_owned(),
        username: "private-search-target".to_owned(),
        profile_url: Some("https://example.com/u/private-search-target".to_owned()),
        rule_hash: rule_hash.to_owned(),
        classification: Classification {
            verdict,
            inconclusive_reason,
            evidence_class,
            matcher_trace: Vec::new(),
            evidence_digest: digest_character.repeat(64),
        },
        probes: Vec::new(),
    }
}

fn current_unix_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
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
