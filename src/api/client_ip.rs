//! The client address, honoring `X-Forwarded-For` only from trusted proxies
//! and only for the hop the proxy appended.

use axum::http::HeaderMap;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

pub fn resolve(peer: SocketAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let peer_ip = peer.ip();
    if trusted.is_empty() || !trusted.iter().any(|net| net.contains(&peer_ip)) {
        return peer_ip;
    }
    let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) else {
        return peer_ip;
    };
    // Walk from the right: skip every trusted hop, take the first untrusted.
    for candidate in value.split(',').rev() {
        let Ok(ip) = candidate.trim().parse::<IpAddr>() else {
            return peer_ip;
        };
        if !trusted.iter().any(|net| net.contains(&ip)) {
            return ip;
        }
    }
    peer_ip
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn hdr(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(v).unwrap());
        h
    }

    #[test]
    fn peer_wins_without_trusted_proxies() {
        let peer: SocketAddr = "203.0.113.5:1234".parse().unwrap();
        assert_eq!(
            resolve(peer, &hdr("198.51.100.9"), &[]),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn untrusted_peer_header_is_ignored() {
        let peer: SocketAddr = "203.0.113.5:1234".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse().unwrap()];
        assert_eq!(resolve(peer, &hdr("198.51.100.9"), &trusted), peer.ip());
    }

    #[test]
    fn trusted_peer_yields_the_rightmost_untrusted_hop() {
        let peer: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse().unwrap()];
        let h = hdr("1.2.3.4, 198.51.100.9, 10.0.0.7");
        assert_eq!(
            resolve(peer, &h, &trusted),
            "198.51.100.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn garbage_header_falls_back_to_peer() {
        let peer: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse().unwrap()];
        assert_eq!(resolve(peer, &hdr("not-an-ip"), &trusted), peer.ip());
        assert_eq!(resolve(peer, &HeaderMap::new(), &trusted), peer.ip());
    }
}
