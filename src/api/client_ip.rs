//! The client address. `X-Forwarded-For` is believed only as far as the
//! deployment says it should be: either from proxies at known addresses, or
//! for a fixed number of entries appended by infrastructure whose addresses
//! cannot be known in advance, which is the shape of a managed platform.

use axum::http::HeaderMap;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

pub fn resolve(peer: SocketAddr, headers: &HeaderMap, trusted: &[IpNet], hops: u8) -> IpAddr {
    if hops > 0 {
        return resolve_by_hops(peer, headers, hops);
    }
    resolve_by_networks(peer, headers, trusted)
}

/// The entry immediately left of the ones our own infrastructure appended.
fn resolve_by_hops(peer: SocketAddr, headers: &HeaderMap, hops: u8) -> IpAddr {
    let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) else {
        return peer.ip();
    };
    let chain: Vec<&str> = value.split(',').map(str::trim).collect();
    let Some(index) = chain.len().checked_sub(usize::from(hops) + 1) else {
        return peer.ip();
    };
    chain
        .get(index)
        .and_then(|entry| entry.parse::<IpAddr>().ok())
        .unwrap_or_else(|| peer.ip())
}

fn resolve_by_networks(peer: SocketAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
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
            resolve(peer, &hdr("198.51.100.9"), &[], 0),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn untrusted_peer_header_is_ignored() {
        let peer: SocketAddr = "203.0.113.5:1234".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse().unwrap()];
        assert_eq!(resolve(peer, &hdr("198.51.100.9"), &trusted, 0), peer.ip());
    }

    #[test]
    fn trusted_peer_yields_the_rightmost_untrusted_hop() {
        let peer: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse().unwrap()];
        let h = hdr("1.2.3.4, 198.51.100.9, 10.0.0.7");
        assert_eq!(
            resolve(peer, &h, &trusted, 0),
            "198.51.100.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn counting_hops_reaches_past_a_platform_front_end() {
        let peer: SocketAddr = "169.254.1.1:1234".parse().unwrap();
        // What a managed platform presents: the client, then its own entry.
        let h = hdr("203.0.113.9, 169.254.8.8");
        assert_eq!(
            resolve(peer, &h, &[], 1),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        // Two of ours in front.
        let h = hdr("203.0.113.9, 169.254.8.8, 169.254.9.9");
        assert_eq!(
            resolve(peer, &h, &[], 2),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        // A header too short to contain a client entry falls back to the peer,
        // rather than treating our own front end as the client.
        assert_eq!(resolve(peer, &hdr("169.254.8.8"), &[], 1), peer.ip());
        assert_eq!(resolve(peer, &HeaderMap::new(), &[], 1), peer.ip());
        // A forged entry to the left of ours cannot move the answer right.
        let h = hdr("1.1.1.1, 203.0.113.9, 169.254.8.8");
        assert_eq!(
            resolve(peer, &h, &[], 1),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn garbage_header_falls_back_to_peer() {
        let peer: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse().unwrap()];
        assert_eq!(resolve(peer, &hdr("not-an-ip"), &trusted, 0), peer.ip());
        assert_eq!(resolve(peer, &HeaderMap::new(), &trusted, 0), peer.ip());
    }
}
