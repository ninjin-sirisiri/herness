//! Host-owned engine boundary for herness.
//!
//! Task 8 owns only the ChatGPT OAuth and terms-gate implementation. It is
//! deliberately independent of the legacy pi OAuth helper and of any real HTTP
//! client: token exchange and JWKS retrieval are injected traits, and tests use
//! scripted mocks plus a real loopback callback listener. Task 9 wires the
//! pi-rust engine and the real transport.

pub mod auth;
