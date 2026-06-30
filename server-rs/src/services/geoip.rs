use maxminddb::{Reader, geoip2};
use std::net::IpAddr;
use std::sync::Arc;

use crate::services::session::GeoResult;

/// Default path to the .mmdb file (shipped with the Docker image / repo).
const DEFAULT_DB_PATH: &str = "GeoLite2-City.mmdb";

/// GeoIP lookup service backed by a MaxMind GeoLite2-City database loaded into memory.
#[derive(Clone)]
pub struct GeoIpService {
    reader: Arc<Reader<Vec<u8>>>,
}

impl GeoIpService {
    /// Load the GeoIP database from disk.
    ///
    /// Priority:
    /// 1. If `GEOIP_DB_PATH` env var is set, load from that path.
    /// 2. Otherwise load from `DEFAULT_DB_PATH` (repo / Docker image).
    /// 3. If neither exists, return None (GeoIP disabled).
    pub async fn init() -> Option<Self> {
        let path = std::env::var("GEOIP_DB_PATH")
            .ok()
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| DEFAULT_DB_PATH.to_string());

        Self::from_file(&path).await
    }

    /// Load a .mmdb file from disk into memory.
    async fn from_file(path: &str) -> Option<Self> {
        let path = path.to_string();
        tokio::task::spawn_blocking(move || {
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("Failed to read GeoIP file {path}: {e}");
                    return None;
                }
            };
            let size_kb = bytes.len() / 1024;
            match Reader::from_source(bytes) {
                Ok(reader) => {
                    tracing::info!("GeoIP database loaded from {path} ({size_kb} KB)");
                    Some(GeoIpService {
                        reader: Arc::new(reader),
                    })
                }
                Err(e) => {
                    tracing::warn!("Failed to parse GeoIP file {path}: {e}");
                    None
                }
            }
        })
        .await
        .ok()
        .flatten()
    }

    /// Look up an IP address and return city/region/country.
    pub fn lookup(&self, ip_str: &str) -> GeoResult {
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => return GeoResult::default(),
        };

        // Skip private/loopback IPs
        if ip.is_loopback() || is_private(&ip) {
            return GeoResult::default();
        }

        let lookup_result = match self.reader.lookup(ip) {
            Ok(r) => r,
            Err(_) => return GeoResult::default(),
        };
        match lookup_result.decode::<geoip2::City>() {
            Ok(Some(record)) => {
                let city = record.city.names.english.map(String::from);
                let country = record.country.iso_code.map(String::from);
                let region = record
                    .subdivisions
                    .into_iter()
                    .next()
                    .and_then(|s| s.names.english)
                    .map(String::from);

                GeoResult {
                    city,
                    region,
                    country,
                }
            }
            _ => GeoResult::default(),
        }
    }
}

fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(_) => false,
    }
}
