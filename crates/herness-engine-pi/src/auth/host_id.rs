//! Stable `ext_agent_host_id` generation and persistence.
//!
//! The official flow requires a stable, opaque host identifier chosen before
//! the first sign-in. This implementation uses the supported `urn:uuid:<v4>`
//! form. The value is not a secret and is kept in a small app-data file. It is
//! never sent as a credential.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use herness_core::Timestamp;
use uuid::Uuid;

use super::error::HostIdError;

/// Host identifier persisted for this installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostId(String);

impl HostId {
    /// Validates a stored host ID.
    pub fn parse(value: impl Into<String>) -> Result<Self, HostIdError> {
        let value = value.into();
        if value.len() > 512 || value.chars().any(char::is_control) {
            return Err(HostIdError::InvalidStoredValue);
        }
        let supported = value
            .strip_prefix("urn:uuid:")
            .is_some_and(|uuid| Uuid::parse_str(uuid).is_ok())
            || value
                .strip_prefix("urn:ietf:params:oauth:jwk-thumbprint:")
                .is_some_and(|thumbprint| !thumbprint.is_empty())
            || value
                .strip_prefix("did:key:")
                .is_some_and(|key| !key.is_empty());
        if !supported {
            return Err(HostIdError::InvalidStoredValue);
        }
        Ok(Self(value))
    }

    /// Generates the supported UUIDv4 form once.
    pub fn generate() -> Self {
        Self(format!("urn:uuid:{}", Uuid::new_v4()))
    }

    /// Host ID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Injectable persistence for the non-secret host ID.
pub trait HostIdStore: Send + Sync {
    /// Loads a previously persisted value.
    fn load(&self) -> Result<Option<String>, HostIdError>;

    /// Persists a value. The write must be durable before returning.
    fn save(&self, value: &str) -> Result<(), HostIdError>;
}

/// App-data file host-ID store.
///
/// The file is created with owner-only permissions on Unix. It is not a
/// credential store and intentionally has no Keychain dependency.
pub struct FileHostIdStore {
    path: PathBuf,
}

impl FileHostIdStore {
    /// Creates a store at an explicit path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Path used by this store.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl HostIdStore for FileHostIdStore {
    fn load(&self) -> Result<Option<String>, HostIdError> {
        match fs::read_to_string(&self.path) {
            Ok(value) => Ok(Some(value.trim().to_owned())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(HostIdError::ReadFailed),
        }
    }

    fn save(&self, value: &str) -> Result<(), HostIdError> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|_| HostIdError::WriteFailed)?;
        }
        let temp_path = self.path.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            Timestamp::now().as_unix_millis()
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp_path)
            .map_err(|_| HostIdError::WriteFailed)?;
        file.write_all(value.as_bytes())
            .map_err(|_| HostIdError::WriteFailed)?;
        file.sync_all().map_err(|_| HostIdError::WriteFailed)?;
        drop(file);
        fs::rename(&temp_path, &self.path).map_err(|_| {
            let _ = fs::remove_file(&temp_path);
            HostIdError::WriteFailed
        })
    }
}

/// In-memory host-ID store used by tests and hosts that supply their own
/// persistence.
#[derive(Debug, Default, Clone)]
pub struct MemoryHostIdStore {
    value: Arc<Mutex<Option<String>>>,
}

impl MemoryHostIdStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl HostIdStore for MemoryHostIdStore {
    fn load(&self) -> Result<Option<String>, HostIdError> {
        Ok(self
            .value
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone())
    }

    fn save(&self, value: &str) -> Result<(), HostIdError> {
        *self
            .value
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(value.to_owned());
        Ok(())
    }
}

/// Loads or creates exactly one host ID per store.
pub struct HostIdManager {
    store: Arc<dyn HostIdStore>,
    cached: Mutex<Option<HostId>>,
}

impl HostIdManager {
    /// Creates a manager over an injectable store.
    pub fn new(store: Arc<dyn HostIdStore>) -> Self {
        Self {
            store,
            cached: Mutex::new(None),
        }
    }

    /// Returns the persisted host ID, generating and saving it before its first
    /// use when the store is empty.
    pub fn ensure(&self) -> Result<HostId, HostIdError> {
        let mut cached = self
            .cached
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(host_id) = cached.as_ref() {
            return Ok(host_id.clone());
        }
        let host_id = match self.store.load()? {
            Some(stored) => HostId::parse(stored)?,
            None => {
                let generated = HostId::generate();
                self.store.save(generated.as_str())?;
                generated
            }
        };
        *cached = Some(host_id.clone());
        Ok(host_id)
    }
}
