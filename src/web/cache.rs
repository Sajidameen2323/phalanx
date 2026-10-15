//! The redirection cache: remembers why each blocked name was blocked, so
//! the block-page server, which only sees a connection to the sinkhole
//! address, can explain it to the user.
//!
//! Entries are keyed by a token handed out on insert (it goes into the block
//! page link) and looked up by name (from the HTTP `Host` header). The cache
//! is bounded and drops its oldest entry first.
//!
//! Blocked ad and tracker names are kept in a separate bounded set without a
//! reason, so the block-page server answers them with an empty response (no
//! warning page inside an ad frame) and they never push real blocks out.

use super::rules::Verdict;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Most entries kept; the oldest is dropped beyond this.
pub const CAPACITY: usize = 1000;

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub token: u32,
    /// The name that was looked up (what the user typed or clicked).
    pub domain: String,
    pub verdict: Verdict,
}

#[derive(Default)]
struct Inner {
    by_token: HashMap<u32, Entry>,
    by_domain: HashMap<String, u32>,
    order: VecDeque<u32>,
    next: u32,
    quiet: HashSet<String>,
    quiet_order: VecDeque<String>,
}

pub struct RedirectionCache {
    inner: Mutex<Inner>,
}

impl Default for RedirectionCache {
    fn default() -> Self {
        Self::new()
    }
}

impl RedirectionCache {
    pub fn new() -> Self {
        // Tokens start at an unpredictable value per run, so a link from an
        // earlier run never names a different, newer block.
        let seed = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.subsec_nanos() ^ (d.as_secs() as u32).rotate_left(16));
        Self { inner: Mutex::new(Inner { next: seed | 1, ..Default::default() }) }
    }

    /// Records (or refreshes) a block and returns its token. Re-blocking a
    /// known name keeps its token and updates the reason.
    pub fn insert(&self, domain: &str, verdict: &Verdict) -> u32 {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&token) = inner.by_domain.get(domain) {
            if let Some(entry) = inner.by_token.get_mut(&token) {
                entry.verdict = verdict.clone();
                return token;
            }
        }
        let mut token = inner.next;
        while token == 0 || inner.by_token.contains_key(&token) {
            token = token.wrapping_add(1);
        }
        inner.next = token.wrapping_add(1);
        inner.by_token.insert(token, Entry { token, domain: domain.to_string(), verdict: verdict.clone() });
        inner.by_domain.insert(domain.to_string(), token);
        inner.order.push_back(token);
        while inner.order.len() > CAPACITY {
            if let Some(old) = inner.order.pop_front() {
                if let Some(entry) = inner.by_token.remove(&old) {
                    inner.by_domain.remove(&entry.domain);
                }
            }
        }
        token
    }

    /// Records a blocked ad or tracker name (no block page for it).
    pub fn insert_quiet(&self, domain: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.quiet.insert(domain.to_string()) {
            inner.quiet_order.push_back(domain.to_string());
            while inner.quiet_order.len() > CAPACITY {
                if let Some(old) = inner.quiet_order.pop_front() {
                    inner.quiet.remove(&old);
                }
            }
        }
    }

    pub fn is_quiet(&self, domain: &str) -> bool {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).quiet.contains(domain)
    }

    pub fn get(&self, token: u32) -> Option<Entry> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).by_token.get(&token).cloned()
    }

    pub fn find(&self, domain: &str) -> Option<Entry> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let token = inner.by_domain.get(domain)?;
        inner.by_token.get(token).cloned()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).by_token.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::rules::{UserLists, WebRules};

    #[test]
    fn bounded_fifo_with_stable_tokens() {
        let rules = WebRules::load(None, &UserLists::default()).unwrap();
        let verdict = rules.classify_domain("blocktest.phalanx.invalid");
        let cache = RedirectionCache::new();
        let first = cache.insert("d0.example", &verdict);
        assert_eq!(cache.insert("d0.example", &verdict), first, "same name keeps its token");
        assert_eq!(cache.find("d0.example").unwrap().token, first);
        for i in 1..=CAPACITY {
            cache.insert(&format!("d{i}.example"), &verdict);
        }
        assert_eq!(cache.len(), CAPACITY);
        assert!(cache.get(first).is_none(), "oldest entry evicted");
        assert!(cache.find("d0.example").is_none());
        let last = cache.find(&format!("d{CAPACITY}.example")).unwrap();
        assert_eq!(cache.get(last.token).unwrap().domain, format!("d{CAPACITY}.example"));
    }

    #[test]
    fn quiet_names_are_bounded_and_separate() {
        let cache = RedirectionCache::new();
        for i in 0..=CAPACITY {
            cache.insert_quiet(&format!("ad{i}.example"));
        }
        assert!(!cache.is_quiet("ad0.example"), "oldest dropped");
        assert!(cache.is_quiet(&format!("ad{CAPACITY}.example")));
        assert!(cache.is_empty(), "no block-page entries");
    }
}
