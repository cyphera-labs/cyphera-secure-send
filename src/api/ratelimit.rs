//! Per-client token buckets. Keys age out so the tables stay bounded.

use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::time::Duration;

use crate::config::RateLimitSettings;

type Limiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

pub struct Limiters {
    pub create: Limiter,
    pub consume: Limiter,
    pub revoke: Limiter,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    Create,
    Consume,
    Revoke,
}

impl Endpoint {
    pub fn as_str(self) -> &'static str {
        match self {
            Endpoint::Create => "create",
            Endpoint::Consume => "consume",
            Endpoint::Revoke => "revoke",
        }
    }
}

fn per_minute(n: u32) -> Limiter {
    let n = NonZeroU32::new(n.max(1)).expect("nonzero");
    RateLimiter::keyed(Quota::per_minute(n))
}

impl Limiters {
    pub fn new(settings: &RateLimitSettings) -> Self {
        Self {
            create: per_minute(settings.create_per_minute),
            consume: per_minute(settings.consume_per_minute),
            revoke: per_minute(settings.revoke_per_minute),
        }
    }

    pub fn check(&self, endpoint: Endpoint, ip: IpAddr) -> bool {
        let limiter = match endpoint {
            Endpoint::Create => &self.create,
            Endpoint::Consume => &self.consume,
            Endpoint::Revoke => &self.revoke,
        };
        limiter.check_key(&ip).is_ok()
    }

    /// Drops buckets that have been idle long enough to be full again.
    pub fn retain_recent(&self) {
        self.create.retain_recent();
        self.consume.retain_recent();
        self.revoke.retain_recent();
    }

    pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(120);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_per_key() {
        let l = Limiters::new(&RateLimitSettings {
            create_per_minute: 2,
            consume_per_minute: 2,
            revoke_per_minute: 2,
        });
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        assert!(l.check(Endpoint::Create, a));
        assert!(l.check(Endpoint::Create, a));
        assert!(!l.check(Endpoint::Create, a));
        assert!(l.check(Endpoint::Create, b));
        assert!(l.check(Endpoint::Consume, a));
    }
}
