//! Web protection: blocks malicious sites in the browser and at the DNS
//! level, and finds malicious browser extensions.
//!
//! * [`rules`] classifies domains, URLs, addresses and ports into a
//!   [`Verdict`] (codes 1–3 block, 4–7 say which exclusion allowed it).
//! * [`dnsfilter`] is a local resolver that answers blocked names with a
//!   loopback sinkhole address; [`blockpage`] listens there and redirects
//!   the browser to a block page, using the [`cache`] to explain why.
//! * [`native`] is the browser connector: a native-messaging host the
//!   Phalanx browser extension asks about each page it opens.
//! * [`extensions`] scans Chromium browser profiles for risky or known-bad
//!   extensions and hijacked search/start-page settings, and removes them.

pub mod blockpage;
pub mod cache;
pub mod config;
pub mod dns;
pub mod dnsfilter;
pub mod events;
pub mod extensions;
pub mod hardening;
pub mod native;
pub mod rules;
pub mod url;
pub mod windows_dns;

pub use config::{Mode, WebConfig};
pub use rules::{Verdict, VerdictCode, WebRules};

use std::sync::{Arc, RwLock};

/// Rules shared with running servers; replace the inner `Arc` to reload.
pub type SharedRules = Arc<RwLock<Arc<WebRules>>>;
