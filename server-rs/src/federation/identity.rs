use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

const MAX_PEER_ID_CHARS: usize = 253;
const MAX_REMOTE_USER_ID_CHARS: usize = 256;

pub const REMOTE_PRINCIPAL_PASSWORD_HASH: &str = "!federation-remote-principal-disabled!";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePrincipalProjection {
    pub username: String,
    pub email: String,
    pub password_hash: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePrincipalMetadata {
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RemotePrincipalProjectionError {
    #[error("invalid remote principal identity")]
    InvalidIdentity,
    #[error("invalid remote principal metadata")]
    InvalidMetadata,
}

impl RemotePrincipalMetadata {
    pub fn new(
        username: Option<&str>,
        display_name: Option<&str>,
        avatar_url: Option<&str>,
    ) -> Result<Self, RemotePrincipalProjectionError> {
        if !optional_username(username)
            || !optional_display_name(display_name)
            || !optional_public_avatar_url(avatar_url)
        {
            return Err(RemotePrincipalProjectionError::InvalidMetadata);
        }
        Ok(Self {
            username: username.map(str::to_string),
            display_name: display_name.map(str::to_string),
            avatar_url: avatar_url.map(str::to_string),
        })
    }
}

pub fn remote_principal_projection(
    home_peer_id: &str,
    remote_user_id: &str,
) -> Result<RemotePrincipalProjection, RemotePrincipalProjectionError> {
    if !valid_peer_id(home_peer_id) || !valid_remote_user_id(remote_user_id) {
        return Err(RemotePrincipalProjectionError::InvalidIdentity);
    }

    let digest = Sha256::digest(format!("{home_peer_id}\n{remote_user_id}").as_bytes());
    let hash_hex = hex::encode(digest);
    let email_tag = URL_SAFE_NO_PAD.encode(&digest[..18]);
    Ok(RemotePrincipalProjection {
        username: format!("fed_{}", &hash_hex[..24]),
        email: format!("remote+{email_tag}@federation.invalid"),
        password_hash: REMOTE_PRINCIPAL_PASSWORD_HASH,
    })
}

fn valid_peer_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PEER_ID_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

fn valid_remote_user_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REMOTE_USER_ID_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

fn optional_username(value: Option<&str>) -> bool {
    match value {
        None => true,
        Some(value) => {
            !value.is_empty()
                && value.len() <= 120
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        }
    }
}

fn optional_display_name(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        value.chars().count() <= 120 && !value.contains('\n') && !value.contains('\r')
    })
}

fn optional_public_avatar_url(value: Option<&str>) -> bool {
    value.is_none_or(is_safe_public_profile_url)
}

pub fn is_safe_public_profile_url(value: &str) -> bool {
    if value.len() > 2048 || value.contains('\r') || value.contains('\n') {
        return false;
    }
    let Ok(parsed) = Url::parse(value) else {
        return false;
    };
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return false;
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if !is_public_federation_host(host) {
        return false;
    }
    if parsed.path_segments().is_some_and(|mut segments| {
        segments.any(|segment| segment.eq_ignore_ascii_case("attachments"))
    }) {
        return false;
    }
    true
}

pub fn is_public_federation_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".local") {
        return false;
    }
    let ip_host = lower.trim_start_matches('[').trim_end_matches(']');
    match ip_host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => is_public_ipv4(ip),
        Ok(IpAddr::V6(ip)) => is_public_ipv6(ip),
        Err(_) => true,
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && (18..=19).contains(&b))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xff00) == 0xff00
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}
