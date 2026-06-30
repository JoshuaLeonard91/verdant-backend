use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PublicNetError {
    #[error("target did not resolve to public addresses")]
    UnsafeTarget,
}

pub(crate) async fn resolve_public_socket_addrs(
    host: &str,
) -> Result<Vec<SocketAddr>, PublicNetError> {
    let addresses = tokio::net::lookup_host((host, 0))
        .await
        .map_err(|_| PublicNetError::UnsafeTarget)?;
    filter_public_socket_addrs(host, addresses)
}

pub(crate) fn filter_public_socket_addrs(
    host: &str,
    addresses: impl IntoIterator<Item = SocketAddr>,
) -> Result<Vec<SocketAddr>, PublicNetError> {
    let mut resolved_any = false;
    let mut public = Vec::new();
    for address in addresses {
        resolved_any = true;
        if !is_public_ip(address.ip()) {
            tracing::debug!(
                host = %host,
                "network target resolved to a non-public address"
            );
            return Err(PublicNetError::UnsafeTarget);
        }
        public.push(address);
    }
    if !resolved_any {
        return Err(PublicNetError::UnsafeTarget);
    }
    Ok(public)
}

pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || octets[0] == 0
        || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 240)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || is_ipv4_compatible_ipv6(&segments)
        || is_ipv4_mapped_ipv6(&segments)
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
        || is_nat64_ipv6(&segments)
        || segments[0] == 0x2002
        || is_special_2001_ipv6(&segments)
        || (segments[0] == 0x3fff && (segments[1] & 0xf000) == 0x0000)
        || (segments[0] == 0x0100 && segments[1] == 0x0000))
}

fn is_ipv4_compatible_ipv6(segments: &[u16; 8]) -> bool {
    segments[..6].iter().all(|segment| *segment == 0)
}

fn is_ipv4_mapped_ipv6(segments: &[u16; 8]) -> bool {
    segments[..5].iter().all(|segment| *segment == 0) && segments[5] == 0xffff
}

fn is_nat64_ipv6(segments: &[u16; 8]) -> bool {
    (segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2..6].iter().all(|segment| *segment == 0))
        || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001)
}

fn is_special_2001_ipv6(segments: &[u16; 8]) -> bool {
    segments[0] == 0x2001
        && (segments[1] == 0x0000
            || segments[1] == 0x0002
            || segments[1] == 0x0db8
            || (segments[1] & 0xfff0) == 0x0010
            || (segments[1] & 0xfff0) == 0x0020)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_socket_filter_rejects_private_reserved_and_mapped_addresses() {
        let private = [
            "127.0.0.1:0".parse().unwrap(),
            "10.0.0.1:0".parse().unwrap(),
            "169.254.169.254:0".parse().unwrap(),
            "192.0.2.10:0".parse().unwrap(),
            "[::1]:0".parse().unwrap(),
            "[::ffff:127.0.0.1]:0".parse().unwrap(),
            "[64:ff9b::7f00:1]:0".parse().unwrap(),
            "[64:ff9b:1::7f00:1]:0".parse().unwrap(),
            "[2002:7f00:1::]:0".parse().unwrap(),
            "[2001:db8::1]:0".parse().unwrap(),
            "[100::1]:0".parse().unwrap(),
        ];

        assert_eq!(
            filter_public_socket_addrs("rebind.example", private).unwrap_err(),
            PublicNetError::UnsafeTarget
        );
    }

    #[test]
    fn public_socket_filter_allows_public_addresses() {
        let public = [
            "93.184.216.34:0".parse().unwrap(),
            "[2606:4700:4700::1111]:0".parse().unwrap(),
        ];

        assert!(filter_public_socket_addrs("example.com", public).is_ok());
    }
}
