use serde::Serialize;

use crate::config::Config;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentScanningMetadata {
    pub provider: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificatePinsMetadata {
    pub sha256: Vec<String>,
    pub mode: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceSecurityMetadata {
    pub certificate_pins: CertificatePinsMetadata,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceMetadata {
    pub name: String,
    pub mode: &'static str,
    pub server_version: &'static str,
    pub min_client_version: String,
    pub public_url: String,
    pub api_url: String,
    pub ws_url: String,
    pub cdn_url: Option<String>,
    pub docs_url: String,
    pub registration: &'static str,
    pub billing_mode: &'static str,
    pub email_provider: &'static str,
    pub upload_policy: &'static str,
    pub content_scanning: ContentScanningMetadata,
    pub security: InstanceSecurityMetadata,
    pub official_network_linked: bool,
    pub account_linking: AccountLinkingMetadata,
    pub trusted_hosts: Vec<String>,
    pub capabilities: crate::config::LocalCapabilities,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountLinkingMetadata {
    pub enabled: bool,
    pub role: &'static str,
    pub proof_algorithm: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentUserInstanceInfo {
    pub instance: InstanceMetadata,
    pub instance_admin: bool,
}

fn public_content_scan_provider(raw: &str) -> String {
    let provider = raw.trim().to_ascii_lowercase();
    if provider.is_empty() {
        "none".to_string()
    } else {
        provider
    }
}

pub fn metadata(config: &Config) -> InstanceMetadata {
    let (account_linking_enabled, account_linking_role) = match config.instance_mode {
        crate::config::InstanceMode::Official => {
            (config.federation_link_signing_key_pem.is_some(), "issuer")
        }
        crate::config::InstanceMode::Linked | crate::config::InstanceMode::Federated => {
            (config.federation_link_verify_key_pem.is_some(), "consumer")
        }
        crate::config::InstanceMode::Standalone => (false, "disabled"),
    };

    InstanceMetadata {
        name: config.instance_name.clone(),
        mode: config.instance_mode.as_str(),
        server_version: env!("CARGO_PKG_VERSION"),
        min_client_version: config.min_client_version.clone(),
        public_url: config.instance_public_url.clone(),
        api_url: config.instance_api_url.clone(),
        ws_url: config.instance_ws_url.clone(),
        cdn_url: config.cdn_base_url.clone().filter(|s| !s.trim().is_empty()),
        docs_url: config.instance_docs_url.clone(),
        registration: if config.public_registration_enabled {
            "public"
        } else {
            "invite"
        },
        billing_mode: config.billing_mode.as_str(),
        email_provider: config.email_provider.as_str(),
        upload_policy: config.upload_policy.as_str(),
        content_scanning: ContentScanningMetadata {
            provider: public_content_scan_provider(&config.content_scan_provider),
            enabled: config.content_scan_enabled(),
        },
        security: InstanceSecurityMetadata {
            certificate_pins: CertificatePinsMetadata {
                sha256: config.certificate_sha256_pins.clone(),
                mode: "advisory",
            },
        },
        official_network_linked: config.instance_mode.official_network_linked(),
        account_linking: AccountLinkingMetadata {
            enabled: account_linking_enabled,
            role: account_linking_role,
            proof_algorithm: "RS256",
        },
        trusted_hosts: config.instance_trusted_hosts.clone(),
        capabilities: config.local_capabilities.clone(),
    }
}

pub fn current_user_info(config: &Config, instance_admin: bool) -> CurrentUserInstanceInfo {
    CurrentUserInstanceInfo {
        instance: metadata(config),
        instance_admin,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        CertificatePinsMetadata, ContentScanningMetadata, InstanceSecurityMetadata,
        public_content_scan_provider,
    };

    #[test]
    fn content_scan_provider_is_normalized_for_public_metadata() {
        assert_eq!(public_content_scan_provider(""), "none");
        assert_eq!(public_content_scan_provider(" NONE "), "none");
        assert_eq!(public_content_scan_provider(" Mock "), "mock");
    }

    #[test]
    fn content_scanning_metadata_exposes_only_status_and_provider() {
        let value = serde_json::to_value(ContentScanningMetadata {
            provider: "mock".to_string(),
            enabled: true,
        })
        .unwrap();

        assert_eq!(value, json!({ "provider": "mock", "enabled": true }));
    }

    #[test]
    fn security_metadata_exposes_only_advisory_certificate_pins() {
        let value = serde_json::to_value(InstanceSecurityMetadata {
            certificate_pins: CertificatePinsMetadata {
                sha256: vec![
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                ],
                mode: "advisory",
            },
        })
        .unwrap();

        assert_eq!(
            value,
            json!({
                "certificatePins": {
                    "sha256": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                    "mode": "advisory"
                }
            })
        );
        assert!(value.get("token").is_none());
        assert!(value.get("session").is_none());
    }
}
