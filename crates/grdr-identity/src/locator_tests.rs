// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use crate::cred_helpers::{format_docker_credential_get, parse_git_credential_stdin};
use crate::{
    ArtifactScanContext, BrokeredToken, CallbackJwtSigner, Ceiling, ContainmentStatus,
    CredentialLocatorPack, CredentialMode, GitHubAppIssuer, Hs256JwtSigner, HygieneRuleId,
    HygieneSignal, KeychainSecretStore, LinuxKernelKeyringStore, OpenBaoSecretStore,
};

#[test]
fn loads_credential_locator_pack_and_evaluates_h1_to_h12_without_leaking_secrets() {
    let pack_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("packs")
        .join("credential-locator");
    let pack =
        CredentialLocatorPack::load_from_dir(&pack_dir).expect("load packs/credential-locator");
    assert!(pack.locators().len() >= 20);
    assert_eq!(pack.hygiene_rules().len(), 12);

    let hmac_key = b"locator-test-hmac-key";
    let mut signals = BTreeSet::new();
    signals.insert(HygieneSignal::FederationConfigured);
    signals.insert(HygieneSignal::SharedWithHuman);
    let aws_secret = format!("aws_access_key_id = AKIA{}1234", "TESTKEY00000");
    let aws_ctx = ArtifactScanContext {
        artifact_path: r"C:\Users\dev\.aws\credentials".into(),
        readable_by_agent_lineages: vec!["claude-code".into()],
        containment: ContainmentStatus::Uncontained,
        signals,
    };
    let finding = pack
        .scan_artifact(hmac_key, &aws_secret, &aws_ctx)
        .expect("scan aws")
        .expect("matched aws-shared-credentials");
    assert_eq!(finding.locator_id, "aws-shared-credentials");
    assert!(finding.crd_id.starts_with("crd_"));
    assert!(!format!("{finding:?}").contains("TESTKEY00000"));
    assert!(
        finding
            .hygiene_findings
            .iter()
            .any(|h| h.rule_id == HygieneRuleId::H2)
    );
    assert!(
        finding
            .hygiene_findings
            .iter()
            .any(|h| h.rule_id == HygieneRuleId::H6)
    );
    assert!(
        finding
            .hygiene_findings
            .iter()
            .any(|h| h.rule_id == HygieneRuleId::H8)
    );

    let ssh_ctx = ArtifactScanContext {
        artifact_path: "/Users/dev/.ssh/id_ed25519".into(),
        readable_by_agent_lineages: vec!["codex".into()],
        ..ArtifactScanContext::default()
    };
    let ssh_finding = pack
        .scan_artifact(
            hmac_key,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n",
            &ssh_ctx,
        )
        .expect("scan ssh")
        .expect("matched ssh");
    assert!(
        ssh_finding
            .hygiene_findings
            .iter()
            .any(|h| h.rule_id == HygieneRuleId::H4)
    );

    let honey_ctx = ArtifactScanContext {
        artifact_path: "/tmp/.grdr-honeytoken".into(),
        ..ArtifactScanContext::default()
    };
    let honey_finding = pack
        .scan_artifact(hmac_key, "GRDR_HONEY_DECOY_1", &honey_ctx)
        .expect("scan honey")
        .expect("matched honey");
    assert!(honey_finding.honeytoken);
}

#[test]
fn rejects_unknown_locator_yaml_keys_and_extracts_distinct_public_ids() {
    let bad_yaml = r#"
format: grdr.credential-locators.v1
locators:
  - id: bad-loc
    credential_class: model
    store_kind: dotenv
    path_globs:
      - ".env"
    content_regex: "SECRET=.*"
    bogus_unknown_key: oops
"#;
    let hygiene = "format: grdr.credential-hygiene.v1\nrules:\n  - id: H1\n    name: h1\n    default_mode: Watch\n    description: test\n";
    assert!(CredentialLocatorPack::from_yaml_strs(bad_yaml, hygiene).is_err());

    let pack_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("packs")
        .join("credential-locator");
    let pack = CredentialLocatorPack::load_from_dir(&pack_dir).expect("load");
    let f1 = pack
        .scan_artifact(
            b"k",
            r#"{"client_id":"cid-alpha","refresh_token":"secret_rt_1"}"#,
            &ArtifactScanContext {
                artifact_path: "/Users/dev/.config/gcloud/application_default_credentials.json"
                    .into(),
                ..ArtifactScanContext::default()
            },
        )
        .expect("scan 1")
        .expect("match 1");
    let f2 = pack
        .scan_artifact(
            b"k",
            r#"{"client_id":"cid-beta","refresh_token":"secret_rt_2"}"#,
            &ArtifactScanContext {
                artifact_path: "/Users/dev/.config/gcloud/application_default_credentials.json"
                    .into(),
                ..ArtifactScanContext::default()
            },
        )
        .expect("scan 2")
        .expect("match 2");
    assert_ne!(f1.crd_id, f2.crd_id);
}

#[test]
fn validates_store_identifiers_and_helper_input_sanitization() {
    assert!(KeychainSecretStore::new("bad service; rm -rf").is_err());
    assert!(LinuxKernelKeyringStore::new("bad:ns").is_err());

    let err_msg = format!(
        "{}",
        parse_git_credential_stdin("secret_malformed_line").unwrap_err()
    );
    assert!(!err_msg.contains("secret_malformed_line"));

    let now = jiff::Timestamp::from_second(1_760_000_000).expect("ts");
    let tok = BrokeredToken {
        jti: "jti".into(),
        lease_id: "lse".into(),
        mode: CredentialMode::Release,
        token_value: zeroize::Zeroizing::new("secret-tok-xyz".into()),
        non_transferable: true,
        bound_session_id: "ses".into(),
        bound_instance_spiffe_id: "spiffe://o/agi/1".into(),
        bound_device_id: "dev".into(),
        dpop_jkt: None,
        scope_digest: "deg".into(),
        issued_at: now,
        expires_at: now,
        session_label: None,
    };
    assert!(!format!("{tok:?}").contains("secret-tok-xyz"));
    assert!(format_docker_credential_get("ghcr.io", "user\nevil", &tok).is_err());

    assert!(
        OpenBaoSecretStore::new(
            "https://vault.example.com?q=1",
            "secret",
            None,
            None,
            "t",
            false
        )
        .is_err()
    );
    assert!(
        OpenBaoSecretStore::new(
            "https://169.254.169.254/latest",
            "secret",
            None,
            None,
            "t",
            false
        )
        .is_err()
    );
    assert!(
        OpenBaoSecretStore::new("https://[fe80::1]/v1", "secret", None, None, "t", false).is_err()
    );
    assert!(
        OpenBaoSecretStore::new("https://0.0.0.0/v1", "secret", None, None, "t", false).is_err()
    );
    assert!(
        OpenBaoSecretStore::new(
            "https://vault.example.com",
            "secret/../sys",
            None,
            None,
            "t",
            false
        )
        .is_err()
    );
    assert!(
        OpenBaoSecretStore::new(
            "https://vault.example.com",
            "secret",
            Some("transit".into()),
            None,
            "t",
            false
        )
        .is_err()
    );
    assert!(
        OpenBaoSecretStore::new("http://[::1]:8200", "secret", None, None, "tok", true).is_ok()
    );
    assert!(
        OpenBaoSecretStore::new(
            "https://[::ffff:169.254.169.254]/latest",
            "secret",
            None,
            None,
            "t",
            false
        )
        .is_err()
    );
    assert!(
        OpenBaoSecretStore::new(
            "https://[::ffff:0.0.0.0]/v1",
            "secret",
            None,
            None,
            "t",
            false
        )
        .is_err()
    );
    assert!(
        OpenBaoSecretStore::new(
            "http://[::ffff:127.0.0.1]:8200",
            "secret",
            None,
            None,
            "tok",
            true
        )
        .is_ok()
    );
    assert!(
        OpenBaoSecretStore::new(
            "http://[::ffff:127.0.0.1]:8200",
            "secret",
            None,
            None,
            "tok",
            false
        )
        .is_err()
    );
    assert!(
        OpenBaoSecretStore::new("https://127.0.0.1:8200", "secret", None, None, "tok", false)
            .is_err()
    );
    assert!(
        OpenBaoSecretStore::new("https://[::1]:8200", "secret", None, None, "tok", false).is_err()
    );
    assert!(
        OpenBaoSecretStore::new(
            "https://[::ffff:127.0.0.1]:8200",
            "secret",
            None,
            None,
            "tok",
            false
        )
        .is_err()
    );
    assert!(
        OpenBaoSecretStore::new("https://localhost:8200", "secret", None, None, "tok", false)
            .is_err()
    );
    assert!(
        OpenBaoSecretStore::new("https://127.0.0.1:8200", "secret", None, None, "tok", true)
            .is_ok()
    );
    assert!(
        OpenBaoSecretStore::new("https://localhost:8200", "secret", None, None, "tok", true)
            .is_ok()
    );
    let mapped_meta: std::net::SocketAddr = "[::ffff:169.254.169.254]:443".parse().expect("addr");
    assert!(crate::http_security::validate_resolved_ips(&[mapped_meta], false).is_err());
    let rebind_loopback: std::net::SocketAddr = "127.0.0.1:443".parse().expect("addr");
    assert!(crate::http_security::validate_resolved_ips(&[rebind_loopback], false).is_err());
    assert!(crate::http_security::validate_resolved_ips(&[], false).is_err());

    let redacted_url_err = format!(
        "{}",
        OpenBaoSecretStore::new(
            "http://user:secret_pw@vault.internal/v1",
            "secret",
            None,
            None,
            "t",
            false
        )
        .unwrap_err()
    );
    assert!(!redacted_url_err.contains("secret_pw"));

    assert!(
        GitHubAppIssuer::new(
            "https://api.github.com",
            "123/../../x",
            "456",
            vec![],
            BTreeMap::new(),
            Arc::new(Hs256JwtSigner::new(b"k".to_vec())),
            false,
        )
        .is_err()
    );
    assert!(
        crate::issuer_helpers::mint_github_app_jwt(
            "12345",
            &CallbackJwtSigner::new("none", |_| Ok(vec![])),
            1_760_000_000,
        )
        .is_err()
    );

    let empty_ceiling = Ceiling {
        allowed_classes: BTreeSet::new(),
        allowed_accounts: BTreeSet::new(),
        allowed_actions: BTreeSet::new(),
        allowed_resource_prefixes: vec![],
        max_ttl_secs: 900,
        max_depth: 1,
    };
    assert!(crate::issuer_helpers::build_aws_inline_session_policy(&empty_ceiling).is_err());
    assert!(
        crate::issuer_helpers::parse_aws_sts_xml_response(
            "<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>",
            now,
        )
        .is_err()
    );
}
