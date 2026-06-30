use axum::extract::ConnectInfo;
use axum::http::HeaderMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;

use crate::error::{AppError, AppResult};

const TRUSTED_PROXY_CIDRS_ENV: &str = "TRUSTED_PROXY_CIDRS";
const FORWARDED_CLIENT_IP_HEADER: &str = "do-connecting-ip";
static TRUSTED_PROXY_CIDRS: OnceLock<Vec<TrustedProxy>> = OnceLock::new();

/// Parse a string ID into i64, returning a validation error on failure.
pub fn parse_id(s: &str) -> AppResult<i64> {
    s.parse::<i64>()
        .map_err(|_| AppError::Validation("Invalid ID".into()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedProxy {
    network: IpAddr,
    prefix: u8,
}

impl TrustedProxy {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = ipv4_mask(self.prefix);
                (u32::from(network) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = ipv6_mask(self.prefix);
                (u128::from(network) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

pub fn parse_trusted_proxy_cidrs(raw: &str) -> Result<Vec<TrustedProxy>, String> {
    let mut proxies = Vec::new();
    for entry in raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let (addr, prefix) = match entry.split_once('/') {
            Some((addr, prefix)) => {
                let ip = addr
                    .parse::<IpAddr>()
                    .map_err(|_| format!("invalid proxy CIDR address: {entry}"))?;
                let prefix = prefix
                    .parse::<u8>()
                    .map_err(|_| format!("invalid proxy CIDR prefix: {entry}"))?;
                validate_proxy_prefix(ip, prefix, entry)?;
                (ip, prefix)
            }
            None => {
                let ip = entry
                    .parse::<IpAddr>()
                    .map_err(|_| format!("invalid proxy IP address: {entry}"))?;
                let prefix = match ip {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                (ip, prefix)
            }
        };
        proxies.push(TrustedProxy {
            network: addr,
            prefix,
        });
    }
    Ok(proxies)
}

fn validate_proxy_prefix(ip: IpAddr, prefix: u8, entry: &str) -> Result<(), String> {
    let max = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        return Err(format!("invalid proxy CIDR prefix: {entry}"));
    }
    Ok(())
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn trusted_proxy_cidrs_from_env() -> &'static [TrustedProxy] {
    TRUSTED_PROXY_CIDRS
        .get_or_init(|| match std::env::var(TRUSTED_PROXY_CIDRS_ENV) {
            Ok(raw) => match parse_trusted_proxy_cidrs(&raw) {
                Ok(proxies) => proxies,
                Err(error) => {
                    tracing::warn!(
                        env = TRUSTED_PROXY_CIDRS_ENV,
                        error = %error,
                        "Ignoring invalid trusted proxy configuration"
                    );
                    Vec::new()
                }
            },
            Err(_) => Vec::new(),
        })
        .as_slice()
}

fn is_trusted_proxy_peer(ip: IpAddr, trusted_proxies: &[TrustedProxy]) -> bool {
    trusted_proxies.iter().any(|proxy| proxy.contains(ip))
}

/// Extract the real client IP.
/// Forwarded client IP headers are trusted only from explicitly configured
/// proxy peers. Public clients and unconfigured local peers can set arbitrary
/// headers, so malformed or untrusted header values are ignored.
pub fn extract_client_ip(headers: &HeaderMap, addr: &ConnectInfo<SocketAddr>) -> String {
    extract_client_ip_with_trusted_proxies(headers, addr, trusted_proxy_cidrs_from_env())
}

pub fn extract_client_ip_with_trusted_proxies(
    headers: &HeaderMap,
    addr: &ConnectInfo<SocketAddr>,
    trusted_proxies: &[TrustedProxy],
) -> String {
    let peer_ip = addr.0.ip();
    if is_trusted_proxy_peer(peer_ip, trusted_proxies)
        && let Some(raw_ip) = headers
            .get(FORWARDED_CLIENT_IP_HEADER)
            .and_then(|v| v.to_str().ok())
    {
        let raw_ip = raw_ip.trim();
        match raw_ip.parse::<IpAddr>() {
            Ok(client_ip) => return normalize_ip(client_ip),
            Err(_) => {
                tracing::warn!(
                    peer_ip = %peer_ip,
                    header = FORWARDED_CLIENT_IP_HEADER,
                    "Ignoring malformed forwarded client IP header"
                );
            }
        }
    }
    normalize_ip(peer_ip)
}

fn normalize_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => Ipv4Addr::from(u32::from(ip)).to_string(),
        IpAddr::V6(ip) => Ipv6Addr::from(u128::from(ip)).to_string(),
    }
}

pub mod account_links;
pub mod admin;
pub mod admin_loadtest;
pub mod announcements;
pub mod audit;
pub mod auth;
pub mod billing;
pub mod bots;
pub mod bug_reports;
pub mod categories;
pub mod channel_overrides;
pub mod channels;
pub mod dms;
pub mod email_verify;
pub mod emojis;
pub mod federation;
pub mod federation_memberships;
pub mod feeds;
pub mod instance;
pub mod invite_codes;
pub mod invites;
pub mod link_previews;
pub mod media;
pub mod media_diagnostics;
pub mod messages;
pub mod moderation;
pub mod notifications;
pub mod password_reset;
pub mod pins;
pub mod reactions;
pub mod relationships;
pub mod reorder;
pub mod reports;
pub mod roles;
pub mod server_workspace;
pub mod servers;
pub mod stickers;
pub mod stripe_webhook;
pub mod sync;
pub mod twofa;
pub mod updates;
pub mod uploads;
pub mod users;
pub mod voice;

#[cfg(test)]
mod tests {
    use super::{
        TrustedProxy, extract_client_ip, extract_client_ip_with_trusted_proxies,
        is_trusted_proxy_peer, parse_trusted_proxy_cidrs,
    };
    use axum::extract::ConnectInfo;
    use axum::http::{HeaderMap, HeaderValue};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn trusts_only_explicit_proxy_peers() {
        let trusted = parse_trusted_proxy_cidrs("127.0.0.1/32,10.0.0.0/8,::1/128")
            .expect("proxy CIDRs should parse");
        assert!(is_trusted_proxy_peer(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            &trusted
        ));
        assert!(is_trusted_proxy_peer(
            IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
            &trusted
        ));
        assert!(is_trusted_proxy_peer(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            &trusted
        ));
        assert!(!is_trusted_proxy_peer(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            &trusted
        ));
        assert!(!is_trusted_proxy_peer(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            &[]
        ));
    }

    fn connect_info(raw: &str) -> ConnectInfo<SocketAddr> {
        ConnectInfo(raw.parse().expect("valid socket address"))
    }

    fn forwarded_headers(value: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("do-connecting-ip", HeaderValue::from_static(value));
        headers
    }

    #[test]
    fn loopback_peer_does_not_trust_forwarded_ip_without_explicit_proxy_config() {
        let headers = forwarded_headers("203.0.113.55");
        let peer = connect_info("127.0.0.1:3001");

        assert_eq!(extract_client_ip(&headers, &peer), "127.0.0.1");
    }

    #[test]
    fn public_peer_cannot_spoof_forwarded_ip() {
        let headers = forwarded_headers("198.51.100.22");
        let peer = connect_info("8.8.8.8:443");

        assert_eq!(extract_client_ip(&headers, &peer), "8.8.8.8");
    }

    #[test]
    fn trusted_proxy_peer_uses_normalized_forwarded_ip() {
        let headers = forwarded_headers(" 2001:0db8:0000:0000:0000:0000:0000:0001 ");
        let peer = connect_info("127.0.0.1:3001");
        let trusted = [TrustedProxy {
            network: IpAddr::V4(Ipv4Addr::LOCALHOST),
            prefix: 32,
        }];

        assert_eq!(
            extract_client_ip_with_trusted_proxies(&headers, &peer, &trusted),
            "2001:db8::1"
        );
    }

    #[test]
    fn trusted_proxy_peer_ignores_malformed_forwarded_ip() {
        let headers = forwarded_headers("203.0.113.55, 198.51.100.20");
        let peer = connect_info("127.0.0.1:3001");
        let trusted = [TrustedProxy {
            network: IpAddr::V4(Ipv4Addr::LOCALHOST),
            prefix: 32,
        }];

        assert_eq!(
            extract_client_ip_with_trusted_proxies(&headers, &peer, &trusted),
            "127.0.0.1"
        );
    }

    #[test]
    fn trusted_proxy_cidrs_reject_invalid_prefixes() {
        assert!(parse_trusted_proxy_cidrs("127.0.0.1/33").is_err());
        assert!(parse_trusted_proxy_cidrs("::1/129").is_err());
        assert!(parse_trusted_proxy_cidrs("not-a-proxy").is_err());
    }
}
