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

/// A proxy appends the address it received the request *from*, so the one
/// nearest the client appends the client, and each further proxy appends the
/// one before it. With `hops` proxies in front, the client is therefore the
/// entry `hops` places from the right end.
///
/// Counting from the right is what makes this safe: a client can prepend
/// anything it likes, but every forged entry shifts the whole chain left
/// without moving the position we read, so the answer never changes.
fn resolve_by_hops(peer: SocketAddr, headers: &HeaderMap, hops: u8) -> IpAddr {
    let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) else {
        return peer.ip();
    };
    let chain: Vec<&str> = value.split(',').map(str::trim).collect();
    // Too short to hold what the configured number of proxies would have
    // added, so it did not come the way the deployment says it does.
    let Some(index) = chain.len().checked_sub(usize::from(hops)) else {
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
    fn counting_hops_takes_the_entry_the_nearest_proxy_added() {
        let peer: SocketAddr = "169.254.1.1:1234".parse().unwrap();
        let client = "203.0.113.9".parse::<IpAddr>().unwrap();

        // One proxy in front: it appended the client, so the client is last.
        assert_eq!(resolve(peer, &hdr("203.0.113.9"), &[], 1), client);

        // Two in front: the nearer appended the client, the further appended
        // the nearer, so the client is second from the right.
        assert_eq!(resolve(peer, &hdr("203.0.113.9, 10.0.0.7"), &[], 2), client);

        // A header shorter than the deployment describes did not arrive the
        // way it claims, so the socket peer is the only honest answer.
        assert_eq!(resolve(peer, &hdr("203.0.113.9"), &[], 2), peer.ip());
        assert_eq!(resolve(peer, &HeaderMap::new(), &[], 1), peer.ip());
    }

    #[test]
    fn a_forged_prefix_cannot_move_the_answer() {
        let peer: SocketAddr = "169.254.1.1:1234".parse().unwrap();
        let client = "203.0.113.9".parse::<IpAddr>().unwrap();

        // Whatever the caller puts in front of itself, the proxy appends the
        // real address after it, and that is the one read.
        for forged in [
            "198.51.100.1",
            "198.51.100.2, 198.51.100.3",
            "not-an-address",
            "127.0.0.1, 10.0.0.1, 192.168.0.1",
        ] {
            let h = hdr(&format!("{forged}, 203.0.113.9"));
            assert_eq!(
                resolve(peer, &h, &[], 1),
                client,
                "a prefix of {forged:?} must not change the client"
            );
        }

        // The same with a second proxy in front.
        let h = hdr("198.51.100.1, 198.51.100.2, 203.0.113.9, 10.0.0.7");
        assert_eq!(resolve(peer, &h, &[], 2), client);
    }

    #[test]
    fn garbage_header_falls_back_to_peer() {
        let peer: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse().unwrap()];
        assert_eq!(resolve(peer, &hdr("not-an-ip"), &trusted, 0), peer.ip());
        assert_eq!(resolve(peer, &HeaderMap::new(), &trusted, 0), peer.ip());
    }
}
