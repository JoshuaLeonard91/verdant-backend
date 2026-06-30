use axum::http::header::CONTENT_TYPE;
use reqwest::{
    Method, Request, Response, Url,
    dns::{Addrs, Name, Resolve, Resolving},
    redirect,
};
use std::{io, sync::Arc, time::Duration};

use super::auth::{FederationRequestSigner, SignError};
use super::identity::is_public_federation_host;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationPeerEndpoint {
    pub peer_id: String,
    pub api_origin: String,
}

#[derive(Debug, thiserror::Error)]
pub enum FederationClientError {
    #[error("invalid federation peer endpoint")]
    InvalidPeerEndpoint,
    #[error("failed to sign federation request")]
    Sign(#[from] SignError),
    #[error("failed to build federation request")]
    BuildRequest(#[from] reqwest::Error),
    #[error("federation request delivery failed")]
    Delivery(#[source] reqwest::Error),
}

#[derive(Debug, Clone)]
pub struct FederationHttpClient {
    client: reqwest::Client,
    signer: FederationRequestSigner,
}

impl FederationHttpClient {
    pub fn new(client: reqwest::Client, signer: FederationRequestSigner) -> Self {
        Self { client, signer }
    }

    pub fn with_timeout(
        timeout: Duration,
        signer: FederationRequestSigner,
    ) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(redirect::Policy::none())
            .no_proxy()
            .dns_resolver(Arc::new(PublicFederationResolver))
            .build()?;
        Ok(Self::new(client, signer))
    }

    pub fn signed_json_request(
        &self,
        method: Method,
        peer: &FederationPeerEndpoint,
        path_and_query: &str,
        body: Vec<u8>,
        timestamp_ms: i64,
        nonce: &str,
    ) -> Result<Request, FederationClientError> {
        let url = peer_url(peer, path_and_query)?;
        let headers = self.signer.sign(
            method.as_str(),
            path_and_query,
            &peer.peer_id,
            &body,
            timestamp_ms,
            nonce,
        )?;
        let request = self
            .client
            .request(method, url)
            .headers(headers)
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .build()?;
        Ok(request)
    }

    pub async fn send_signed_json_request(
        &self,
        method: Method,
        peer: &FederationPeerEndpoint,
        path_and_query: &str,
        body: Vec<u8>,
        timestamp_ms: i64,
        nonce: &str,
    ) -> Result<Response, FederationClientError> {
        let request =
            self.signed_json_request(method, peer, path_and_query, body, timestamp_ms, nonce)?;
        self.client
            .execute(request)
            .await
            .map_err(FederationClientError::Delivery)
    }
}

fn peer_url(
    peer: &FederationPeerEndpoint,
    path_and_query: &str,
) -> Result<Url, FederationClientError> {
    if !valid_path_and_query(path_and_query) {
        return Err(FederationClientError::InvalidPeerEndpoint);
    }
    let origin =
        Url::parse(&peer.api_origin).map_err(|_| FederationClientError::InvalidPeerEndpoint)?;
    let host = origin
        .host_str()
        .ok_or(FederationClientError::InvalidPeerEndpoint)?;
    if !peer_identity_allows_origin_host(&peer.peer_id, host) {
        return Err(FederationClientError::InvalidPeerEndpoint);
    }
    let scheme_allowed = match origin.scheme() {
        "https" => is_public_federation_host(host),
        "http" => is_loopback_host(host),
        _ => false,
    };
    if !scheme_allowed
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(FederationClientError::InvalidPeerEndpoint);
    }

    origin
        .join(path_and_query)
        .map_err(|_| FederationClientError::InvalidPeerEndpoint)
}

fn valid_path_and_query(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 2048
        && !value.contains('\r')
        && !value.contains('\n')
        && !value.starts_with("//")
}

fn peer_identity_allows_origin_host(peer_id: &str, origin_host: &str) -> bool {
    let Some(peer_host) = peer_id.strip_prefix("host:") else {
        return true;
    };
    let peer_host = peer_host.trim_end_matches('.').to_ascii_lowercase();
    let origin_host = origin_host.trim_end_matches('.').to_ascii_lowercase();
    !peer_host.is_empty()
        && (origin_host == peer_host || origin_host.ends_with(&format!(".{peer_host}")))
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

#[derive(Debug, Clone, Default)]
struct PublicFederationResolver;

impl Resolve for PublicFederationResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = if is_loopback_host(&host) {
                let resolved: Vec<std::net::SocketAddr> =
                    tokio::net::lookup_host((host.as_str(), 0))
                        .await
                        .map_err(|error| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                format!("federation DNS lookup failed: {error}"),
                            )
                        })?
                        .collect();
                if resolved.iter().all(|addr| addr.ip().is_loopback()) && !resolved.is_empty() {
                    resolved
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "localhost federation target resolved outside loopback",
                    )
                    .into());
                }
            } else {
                crate::services::public_net::resolve_public_socket_addrs(&host)
                    .await
                    .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?
            };
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::services::public_net::filter_public_socket_addrs;

    const SOURCE: &str = include_str!("client.rs");

    #[test]
    fn federation_client_installs_guarded_dns_resolver() {
        let builder = SOURCE
            .split("pub fn with_timeout")
            .nth(1)
            .expect("with_timeout builder should exist")
            .split("pub fn signed_json_request")
            .next()
            .expect("signed_json_request follows with_timeout");

        assert!(
            builder.contains("dns_resolver"),
            "federation HTTP client must use a guarded resolver for the actual connect path"
        );
        assert!(
            builder.contains("no_proxy"),
            "federation HTTP client must not allow environment proxies to bypass the guarded resolver"
        );
    }

    #[test]
    fn federation_public_address_filter_rejects_private_dns_results() {
        let addrs = [
            "127.0.0.1:0".parse().unwrap(),
            "10.0.0.1:0".parse().unwrap(),
            "[::ffff:127.0.0.1]:0".parse().unwrap(),
            "[2001:db8::1]:0".parse().unwrap(),
        ];

        assert!(filter_public_socket_addrs("peer.example", addrs).is_err());
    }

    #[test]
    fn federation_public_address_filter_accepts_public_dns_results() {
        let addrs = [
            "93.184.216.34:0".parse().unwrap(),
            "[2606:4700:4700::1111]:0".parse().unwrap(),
        ];

        assert!(filter_public_socket_addrs("peer.example", addrs).is_ok());
    }
}
