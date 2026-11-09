//! Host-owned candidate artifact persistence.
//!
//! H1 never knows where a candidate is stored. The host implements this port
//! over its private H3 storage, resolves the host-issued [`ArtifactHandle`] to
//! that storage, and returns opaque snapshots. The port must persist a write
//! durably before returning success, and must never truncate content.
//!
//! A composition without this capability uses [`UnavailableArtifactPort`] or
//! omits the port entirely. Both paths produce an explicit unsupported
//! capability error; they never produce an empty success.

use std::sync::{Arc, Mutex};

use crate::contracts::artifact::{ArtifactHandle, ArtifactSlot, ArtifactSnapshot};
use crate::contracts::errors::ArtifactFailure;
use crate::tools::FileVersion;

/// Host candidate artifact persistence boundary.
pub trait ArtifactPort {
    /// Reads one immutable snapshot or the current candidate.
    ///
    /// Returns `Ok(None)` only when a candidate slot has not been authored in
    /// this generation. Immutable slots that the host promised but cannot
    /// provide are an error, not an empty read.
    fn read_artifact(
        &mut self,
        handle: &ArtifactHandle,
        artifact: ArtifactSlot,
    ) -> Result<Option<ArtifactSnapshot>, ArtifactFailure>;

    /// Writes one candidate artifact and returns the observed result.
    ///
    /// `expected_version` is the version the executor observed immediately
    /// before the write (`None` when the candidate did not exist). A port that
    /// observes a different current version must reject with
    /// [`ArtifactFailure::VersionConflict`] instead of overwriting it.
    fn write_artifact(
        &mut self,
        handle: &ArtifactHandle,
        artifact: ArtifactSlot,
        content: &str,
        expected_version: Option<&FileVersion>,
    ) -> Result<ArtifactSnapshot, ArtifactFailure>;
}

/// A port with no backing persistence.
///
/// Every call is an explicit unsupported capability, never a successful empty
/// result.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableArtifactPort;

impl ArtifactPort for UnavailableArtifactPort {
    fn read_artifact(
        &mut self,
        _handle: &ArtifactHandle,
        _artifact: ArtifactSlot,
    ) -> Result<Option<ArtifactSnapshot>, ArtifactFailure> {
        Err(ArtifactFailure::Unavailable)
    }

    fn write_artifact(
        &mut self,
        _handle: &ArtifactHandle,
        _artifact: ArtifactSlot,
        _content: &str,
        _expected_version: Option<&FileVersion>,
    ) -> Result<ArtifactSnapshot, ArtifactFailure> {
        Err(ArtifactFailure::Unavailable)
    }
}

/// A thread-safe shared artifact port.
///
/// The engine adapter stores one host port and gives each candidate run a
/// clone of this handle. Calls are serialized; a port that needs finer
/// concurrency can implement its own locking internally and be wrapped as a
/// single value.
#[derive(Clone)]
pub struct SharedArtifactPort {
    inner: Arc<Mutex<Box<dyn ArtifactPort + Send>>>,
}

impl SharedArtifactPort {
    /// Wraps a host artifact port.
    pub fn new(port: Box<dyn ArtifactPort + Send>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(port)),
        }
    }
}

impl ArtifactPort for SharedArtifactPort {
    fn read_artifact(
        &mut self,
        handle: &ArtifactHandle,
        artifact: ArtifactSlot,
    ) -> Result<Option<ArtifactSnapshot>, ArtifactFailure> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .read_artifact(handle, artifact)
    }

    fn write_artifact(
        &mut self,
        handle: &ArtifactHandle,
        artifact: ArtifactSlot,
        content: &str,
        expected_version: Option<&FileVersion>,
    ) -> Result<ArtifactSnapshot, ArtifactFailure> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .write_artifact(handle, artifact, content, expected_version)
    }
}

impl std::fmt::Debug for SharedArtifactPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedArtifactPort").finish_non_exhaustive()
    }
}
