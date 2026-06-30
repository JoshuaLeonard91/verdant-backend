use std::path::Path;

#[test]
fn local_s2s_smoke_harness_documents_signed_delivery_and_cleanup() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("server-rs should live under the repo root");
    let script_path = repo.join("scripts").join("federation-s2s-smoke.ps1");
    let script = std::fs::read_to_string(&script_path)
        .unwrap_or_else(|error| panic!("{}: {error}", script_path.display()));

    for required in [
        "FEDERATION_S2S_KEY_ID",
        "FEDERATION_S2S_SIGNING_SEED",
        "defaultOffOutboxRows",
        "defaultOffInboundRows",
        "defaultOffRemoteRows",
        "syncSummaryServers",
        "syncSummaryDms",
        "syncSummaryUnauthenticatedStatus",
        "syncSummaryInvalidBearerStatus",
        "Assert-SyncSummaryContentFree",
        "Assert-SyncSummaryVisibility",
        "RunFlutterE2E",
        "flutterFederationE2EStatus",
        "flutter-federation-e2e.ps1",
        "BackendOrigins",
        "http://127.0.0.1:$BackendAPort",
        "http://127.0.0.1:$BackendBPort",
        "metadata-and-membership-handshakes-only",
        "cross-backend messages",
        "federation_peer_keys",
        "federation_peer_routes",
        "/api/sync/summary",
        "/api/federation/v1/events",
        "metadata-and-membership-handshakes-only",
        "federation_inbound_events",
        "federation_remote_messages",
        "No secrets",
        "finally",
    ] {
        assert!(
            script.contains(required),
            "smoke harness should mention `{required}`"
        );
    }

    assert!(
        script.contains("docker run")
            && script.contains("postgres:17-alpine")
            && script.contains("redis:7-alpine"),
        "local harness should provision isolated Postgres and Redis containers"
    );
    assert!(
        script.contains("Start-VerdantServer") && script.contains("Stop-SmokeProcess"),
        "local harness should own backend process lifecycle"
    );
    assert!(
        script.contains("ClientWebSocket") && script.contains("TYPING_START"),
        "local harness should use websocket-originated runtime attempts"
    );

    let results_path = repo
        .join("docs")
        .join("FEDERATION_S2S_BACKEND_TEST_RESULTS.md");
    let results = std::fs::read_to_string(&results_path)
        .unwrap_or_else(|error| panic!("{}: {error}", results_path.display()));
    assert!(results.contains("message_create"));
    assert!(results.contains("Sanitized result shape"));
    assert!(results.contains("Deferred surfaces"));
}

#[test]
fn local_s2s_smoke_docs_label_runtime_delivery_as_server_owned_boundary() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("server-rs should live under the repo root");
    let docs_path = repo
        .join("docs")
        .join("FEDERATION_LOCAL_TWO_BACKEND_SMOKE.md");
    let docs = std::fs::read_to_string(&docs_path)
        .unwrap_or_else(|error| panic!("{}: {error}", docs_path.display()));

    for required in [
        "server-owned backend model",
        "Cross-backend runtime persistence attempts are rejected",
        "server-owned backend model remains the product path",
        "backend's persistence acknowledgement",
    ] {
        assert!(
            docs.contains(required),
            "smoke docs should explain `{required}`"
        );
    }
}

#[test]
fn local_s2s_smoke_harness_exercises_broader_runtime_surface() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("server-rs should live under the repo root");
    let script_path = repo.join("scripts").join("federation-s2s-smoke.ps1");
    let script = std::fs::read_to_string(&script_path)
        .unwrap_or_else(|error| panic!("{}: {error}", script_path.display()));

    for required in [
        "defaultOffRuntimeKinds",
        "message_update",
        "reaction_add",
        "typing_start",
        "presence_update",
        "Assert-DefaultOffRuntimeNotEnqueued",
        "acceptedRuntime",
        "cross-backend messages",
        "admin/runtime persistence",
    ] {
        assert!(
            script.contains(required),
            "broader runtime smoke harness should mention `{required}`"
        );
    }

    let results_path = repo
        .join("docs")
        .join("FEDERATION_S2S_BACKEND_TEST_RESULTS.md");
    let results = std::fs::read_to_string(&results_path)
        .unwrap_or_else(|error| panic!("{}: {error}", results_path.display()));
    for required in [
        "Live two-backend proven",
        "Unit/integration proven only",
        "message_update",
        "reaction_add",
        "typing_start",
        "presence_update",
        "Cross-backend runtime deliveries fail closed",
    ] {
        assert!(
            results.contains(required),
            "broader runtime test results should classify `{required}`"
        );
    }
}

#[test]
fn local_s2s_smoke_harness_exercises_workspace_batch_bootstrap() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("server-rs should live under the repo root");
    let script_path = repo.join("scripts").join("federation-s2s-smoke.ps1");
    let script = std::fs::read_to_string(&script_path)
        .unwrap_or_else(|error| panic!("{}: {error}", script_path.display()));

    for required in [
        "Assert-WorkspaceBootstrap",
        "/api/servers/$ServerId/workspace",
        "/api/servers/$serverBId/workspace",
        "workspaceBootstrapA",
        "workspaceBootstrapB",
        "workspaceCrossBackendStatus",
        "workspaceBatchSecurity",
        "direct-owning-backend-batch-bootstrap",
    ] {
        assert!(
            script.contains(required),
            "smoke harness should prove batch workspace bootstrap with `{required}`"
        );
    }

    let docs_path = repo
        .join("docs")
        .join("FEDERATION_LOCAL_TWO_BACKEND_SMOKE.md");
    let docs = std::fs::read_to_string(&docs_path)
        .unwrap_or_else(|error| panic!("{}: {error}", docs_path.display()));
    for required in [
        "batched workspace bootstrap",
        "`/api/servers/:id/workspace`",
        "cross-backend bearer is rejected",
        "direct owning-backend REST",
    ] {
        assert!(
            docs.contains(required),
            "local two-backend smoke docs should mention `{required}`"
        );
    }
}

#[test]
fn flutter_client_has_real_federation_e2e_entrypoint() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("server-rs should live under the repo root");

    let test_path = repo
        .join("clients")
        .join("flutter-client")
        .join("integration_test")
        .join("federation_runtime_e2e_test.dart");
    let test = std::fs::read_to_string(&test_path)
        .unwrap_or_else(|error| panic!("{}: {error}", test_path.display()));

    for required in [
        "VERDANT_FEDERATION_E2E",
        "VERDANT_E2E_BACKEND_ORIGINS",
        "VERDANT_E2E_BACKENDS_FILE",
        "NetworkProfileStore",
        "HttpInstanceIdentityManifestService",
        "InstanceIdentityStore",
        "_verifyManifestIdentities",
        "InstanceIdentityWarning.apiOriginMismatch",
        "HttpAuthService",
        "ServerSettingsService",
        "VerdantDirectMessagesService",
        "HttpSyncSummaryClient",
        "InactiveBackendRuntimeManager",
        "JoinedBackendRuntimeProfile",
        "setActiveNetwork",
        "disconnects",
        "hydratedMessages",
        "readerCredentialStore",
        "acceptInvite",
        "openDirectMessage",
        "requiresReconnect",
        "networkId",
        "localId",
        "no official relay",
        "HttpFederatedInvitePreviewService",
        "HttpFederatedInviteJoinService",
        "_exerciseFederatedInviteJoin",
        "targetCredentialBeforeJoin",
        "AuthCredentialKind.federatedClient",
        "federated invite does not require target credentials",
    ] {
        assert!(
            test.contains(required),
            "Flutter federation E2E should mention `{required}`"
        );
    }
    for forbidden in [
        "VERDANT_E2E_BACKEND_A_ORIGIN",
        "VERDANT_E2E_BACKEND_B_ORIGIN",
        "VERDANT_E2E_BACKEND_A_EMAIL",
        "VERDANT_E2E_BACKEND_B_EMAIL",
        "VERDANT_E2E_SERVER_ID",
        "VERDANT_E2E_CHANNEL_ID",
    ] {
        assert!(
            !test.contains(forbidden),
            "Flutter federation E2E should not keep legacy per-backend env `{forbidden}`"
        );
    }

    let script_path = repo
        .join("clients")
        .join("flutter-client")
        .join("scripts")
        .join("flutter-federation-e2e.ps1");
    let script = std::fs::read_to_string(&script_path)
        .unwrap_or_else(|error| panic!("{}: {error}", script_path.display()));
    for required in [
        "flutter test",
        "LASTEXITCODE",
        "Flutter federation E2E failed",
        "integration_test/federation_runtime_e2e_test.dart",
        "--dart-define=VERDANT_FEDERATION_E2E=true",
        "VERDANT_E2E_BACKEND_ORIGINS",
        "VERDANT_E2E_BACKENDS_FILE",
    ] {
        assert!(
            script.contains(required),
            "Flutter federation E2E command should mention `{required}`"
        );
    }
    for forbidden in [
        "VERDANT_E2E_BACKEND_A_ORIGIN",
        "VERDANT_E2E_BACKEND_B_ORIGIN",
        "VERDANT_E2E_BACKEND_A_EMAIL",
        "VERDANT_E2E_BACKEND_B_EMAIL",
        "VERDANT_E2E_SERVER_ID",
        "VERDANT_E2E_CHANNEL_ID",
    ] {
        assert!(
            !script.contains(forbidden),
            "Flutter federation E2E command should not pass legacy per-backend env `{forbidden}`"
        );
    }
}

#[test]
fn flutter_client_e2e_proves_durable_membership_survives_target_credential_loss() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("server-rs should live under the repo root");

    let test_path = repo
        .join("clients")
        .join("flutter-client")
        .join("integration_test")
        .join("federation_runtime_e2e_test.dart");
    let test = std::fs::read_to_string(&test_path)
        .unwrap_or_else(|error| panic!("{}: {error}", test_path.display()));

    for required in [
        "HttpFederatedMembershipService",
        "_exerciseFederatedMembershipPersistenceAfterCredentialLoss",
        "restartCredentialStore",
        "federated membership restart does not keep target credentials",
        "listMemberships",
        "refreshCapability",
        "membership.targetApiOrigin",
        "membership.targetServerId",
        "targetCredentialAfterRestart",
        "targetCredentialAfterRemint",
        "credentialKind, AuthCredentialKind.federatedClient",
        "targetServersAfterRemint",
    ] {
        assert!(
            test.contains(required),
            "Flutter federation E2E should prove durable membership credential-loss restart behavior with `{required}`"
        );
    }

    let smoke_docs = std::fs::read_to_string(
        repo.join("docs")
            .join("FEDERATION_LOCAL_TWO_BACKEND_SMOKE.md"),
    )
    .expect("local two-backend smoke docs should be readable");
    for required in [
        "local federated credential is deleted or absent",
        "client restart is simulated with only the home credential",
        "home-backed durable membership list still includes the remote server",
        "opening the federated server refreshes scoped target access through S2S",
    ] {
        assert!(
            smoke_docs.contains(required),
            "local two-backend smoke docs should document durable membership proof: `{required}`"
        );
    }
}
