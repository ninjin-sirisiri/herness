//! Host-owned engine boundary for herness.
//!
//! Task 8 owns the ChatGPT OAuth and terms-gate implementation. Task 9 adds
//! the pinned pi-rust engine adapter, the host-owned StreamFn bridge, and the
//! durable session checkpoint store. No pi type, JSON, or error crosses the
//! public boundary: the adapter exposes only `herness-core` contracts.

pub mod adapter;
pub mod auth;
mod error;
mod events;
pub mod probe;
mod session_store;
mod stream;

pub use adapter::{PiEngine, PiEngineConfig};
pub use probe::{
    ProbeFailure, ProbeOutcome, ProbeTerminal, ProbeUsage, REAL_CHECK_MAX_OUTPUT_TOKENS,
    REAL_CHECK_PROMPT,
};
pub use stream::{ChatGptModel, ProviderEndpoints};
