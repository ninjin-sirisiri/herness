//! Narrow macOS Security.framework adapter behind the credential vault trait.

use std::fmt;

use herness_core::{CredentialVault, VAULT_SERVICE, VaultAccount, VaultFailure};

/// Structured failure from a Keychain backend.
///
/// The adapter maps these to [`VaultFailure`] and the core maps them to
/// sanitized [`herness_core::CredentialFailureKind`] values. No error carries
/// secret data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainError {
    /// The operating system denied access.
    Denied,
    /// The keychain is locked.
    Locked,
    /// The keychain is not available.
    Unavailable,
    /// An existing item could not be updated.
    UpdateFailed,
    /// The item already exists.
    DuplicateItem,
    /// The item does not exist.
    MissingItem,
    /// The stored item could not be decoded.
    InvalidData,
}

impl From<KeychainError> for VaultFailure {
    fn from(value: KeychainError) -> Self {
        match value {
            KeychainError::Denied => Self::Denied,
            KeychainError::Locked => Self::Locked,
            KeychainError::Unavailable => Self::Unavailable,
            KeychainError::UpdateFailed => Self::UpdateFailed,
            KeychainError::DuplicateItem => Self::DuplicateItem,
            KeychainError::MissingItem => Self::MissingItem,
            KeychainError::InvalidData => Self::InvalidData,
        }
    }
}

/// Operating-system backing store used by [`MacKeychainVault`].
///
/// The trait exists so the mapping and the no-fallback behavior can be tested
/// without touching the real Keychain. Implementations must not write secrets
/// to ordinary files.
pub trait KeychainBackend: Send + Sync {
    /// Stores or updates one generic-password item.
    fn set(&self, service: &str, account: &str, data: &[u8]) -> Result<(), KeychainError>;

    /// Reads one item. `Ok(None)` means the item does not exist.
    fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, KeychainError>;

    /// Deletes one item. A missing item must be reported as
    /// [`KeychainError::MissingItem`].
    fn delete(&self, service: &str, account: &str) -> Result<(), KeychainError>;
}

/// Credential vault backed by generic-password items in the macOS Keychain.
///
/// The service name is namespaced to herness and every connection/authentication
/// method pair uses a distinct account key. There is no file fallback.
#[derive(Clone)]
pub struct MacKeychainVault<B: KeychainBackend = SystemKeychain> {
    backend: B,
    service: String,
}

impl<B: KeychainBackend> fmt::Debug for MacKeychainVault<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacKeychainVault")
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

impl<B: KeychainBackend> MacKeychainVault<B> {
    /// Creates a vault using the herness Keychain service name.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            service: VAULT_SERVICE.to_owned(),
        }
    }

    /// Keychain service name in use.
    pub fn service(&self) -> &str {
        &self.service
    }
}

impl Default for MacKeychainVault<SystemKeychain> {
    fn default() -> Self {
        Self::new(SystemKeychain)
    }
}

impl<B: KeychainBackend> CredentialVault for MacKeychainVault<B> {
    fn set(&self, account: &VaultAccount, data: &[u8]) -> Result<(), VaultFailure> {
        self.backend
            .set(&self.service, account.as_str(), data)
            .map_err(VaultFailure::from)
    }

    fn get(&self, account: &VaultAccount) -> Result<Option<Vec<u8>>, VaultFailure> {
        self.backend
            .get(&self.service, account.as_str())
            .map_err(VaultFailure::from)
    }

    fn delete(&self, account: &VaultAccount) -> Result<(), VaultFailure> {
        self.backend
            .delete(&self.service, account.as_str())
            .map_err(VaultFailure::from)
    }
}

/// Real macOS Keychain backend.
///
/// This type is compiled on macOS but is not exercised against the real
/// Keychain by normal tests. Task 13 owns the separately approved real-Keychain
/// verification.
#[cfg(target_os = "macos")]
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemKeychain;

#[cfg(target_os = "macos")]
impl KeychainBackend for SystemKeychain {
    fn set(&self, service: &str, account: &str, data: &[u8]) -> Result<(), KeychainError> {
        security_framework::passwords::set_generic_password(service, account, data)
            .map_err(map_write_error)
    }

    fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, KeychainError> {
        use security_framework::passwords::{PasswordOptions, generic_password};

        match generic_password(PasswordOptions::new_generic_password(service, account)) {
            Ok(data) => Ok(Some(data)),
            Err(error) if error.code() == security_framework_sys::base::errSecItemNotFound => {
                Ok(None)
            }
            Err(error) => Err(map_read_error(error)),
        }
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), KeychainError> {
        match security_framework::passwords::delete_generic_password(service, account) {
            Ok(()) => Ok(()),
            Err(error) => Err(map_write_error(error)),
        }
    }
}

/// Placeholder backend on non-macOS builds. H1 is macOS-only; the desktop
/// adapter reports unavailability instead of inventing a file fallback.
#[cfg(not(target_os = "macos"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemKeychain;

#[cfg(not(target_os = "macos"))]
impl KeychainBackend for SystemKeychain {
    fn set(&self, _service: &str, _account: &str, _data: &[u8]) -> Result<(), KeychainError> {
        Err(KeychainError::Unavailable)
    }

    fn get(&self, _service: &str, _account: &str) -> Result<Option<Vec<u8>>, KeychainError> {
        Err(KeychainError::Unavailable)
    }

    fn delete(&self, _service: &str, _account: &str) -> Result<(), KeychainError> {
        Err(KeychainError::Unavailable)
    }
}

#[cfg(target_os = "macos")]
fn map_read_error(error: security_framework::base::Error) -> KeychainError {
    classify(error.code()).unwrap_or(KeychainError::Unavailable)
}

#[cfg(target_os = "macos")]
fn map_write_error(error: security_framework::base::Error) -> KeychainError {
    classify(error.code()).unwrap_or(KeychainError::UpdateFailed)
}

#[cfg(target_os = "macos")]
#[allow(non_upper_case_globals)]
fn classify(code: i32) -> Option<KeychainError> {
    use security_framework_sys::base::{errSecAuthFailed, errSecDuplicateItem, errSecItemNotFound};

    // OSStatus values from Security/SecBase.h. The sys crate exposes only a
    // subset; these are the remaining documented generic-keychain results.
    const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
    const ERR_SEC_USER_CANCELED: i32 = -128;
    const ERR_SEC_NO_SUCH_KEYCHAIN: i32 = -25294;
    const ERR_SEC_INVALID_KEYCHAIN: i32 = -25295;
    const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
    const ERR_SEC_DECODE: i32 = -26275;

    match code {
        errSecItemNotFound => Some(KeychainError::MissingItem),
        errSecDuplicateItem => Some(KeychainError::DuplicateItem),
        errSecAuthFailed => Some(KeychainError::Denied),
        ERR_SEC_INTERACTION_NOT_ALLOWED => Some(KeychainError::Locked),
        ERR_SEC_USER_CANCELED => Some(KeychainError::Denied),
        ERR_SEC_NO_SUCH_KEYCHAIN | ERR_SEC_INVALID_KEYCHAIN | ERR_SEC_NOT_AVAILABLE => {
            Some(KeychainError::Unavailable)
        }
        ERR_SEC_DECODE => Some(KeychainError::InvalidData),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Debug, Default)]
    struct FakeState {
        items: BTreeMap<(String, String), Vec<u8>>,
        next_set: Option<KeychainError>,
        next_get: Option<KeychainError>,
        next_delete: Option<KeychainError>,
        calls: Vec<&'static str>,
    }

    #[derive(Debug, Clone, Default)]
    struct FakeBackend {
        state: Arc<Mutex<FakeState>>,
    }

    impl FakeBackend {
        fn fail_set(&self, error: KeychainError) {
            self.state.lock().unwrap().next_set = Some(error);
        }

        fn fail_get(&self, error: KeychainError) {
            self.state.lock().unwrap().next_get = Some(error);
        }

        fn fail_delete(&self, error: KeychainError) {
            self.state.lock().unwrap().next_delete = Some(error);
        }

        fn calls(&self) -> Vec<&'static str> {
            self.state.lock().unwrap().calls.clone()
        }
    }

    impl KeychainBackend for FakeBackend {
        fn set(&self, service: &str, account: &str, data: &[u8]) -> Result<(), KeychainError> {
            let mut state = self.state.lock().unwrap();
            state.calls.push("set");
            if let Some(error) = state.next_set.take() {
                return Err(error);
            }
            state
                .items
                .insert((service.to_owned(), account.to_owned()), data.to_vec());
            Ok(())
        }

        fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, KeychainError> {
            let mut state = self.state.lock().unwrap();
            state.calls.push("get");
            if let Some(error) = state.next_get.take() {
                return Err(error);
            }
            Ok(state
                .items
                .get(&(service.to_owned(), account.to_owned()))
                .cloned())
        }

        fn delete(&self, service: &str, account: &str) -> Result<(), KeychainError> {
            let mut state = self.state.lock().unwrap();
            state.calls.push("delete");
            if let Some(error) = state.next_delete.take() {
                return Err(error);
            }
            match state
                .items
                .remove(&(service.to_owned(), account.to_owned()))
            {
                Some(_) => Ok(()),
                None => Err(KeychainError::MissingItem),
            }
        }
    }

    fn account() -> VaultAccount {
        VaultAccount::new("connection/00000000-0000-4000-8000-000000000001/api_key")
            .expect("valid account")
    }

    #[test]
    fn generic_password_round_trip_is_namespaced_and_per_account() {
        let backend = FakeBackend::default();
        let vault = MacKeychainVault::new(backend.clone());
        let account = account();
        assert_eq!(vault.service(), VAULT_SERVICE);
        assert!(vault.service().starts_with("com.herness."));

        vault.set(&account, b"secret-bytes").unwrap();
        assert_eq!(vault.get(&account).unwrap(), Some(b"secret-bytes".to_vec()));
        assert_eq!(backend.calls(), vec!["set", "get"]);

        let stored = backend.state.lock().unwrap();
        let ((service, stored_account), bytes) = stored.items.iter().next().unwrap();
        assert_eq!(service, VAULT_SERVICE);
        assert_eq!(stored_account, account.as_str());
        assert_eq!(bytes, b"secret-bytes");
        drop(stored);

        vault.delete(&account).unwrap();
        assert_eq!(vault.get(&account).unwrap(), None);
    }

    #[test]
    fn set_failures_map_to_structured_vault_failures_without_fallback() {
        let cases = [
            (KeychainError::Denied, VaultFailure::Denied),
            (KeychainError::Locked, VaultFailure::Locked),
            (KeychainError::Unavailable, VaultFailure::Unavailable),
            (KeychainError::UpdateFailed, VaultFailure::UpdateFailed),
            (KeychainError::DuplicateItem, VaultFailure::DuplicateItem),
            (KeychainError::InvalidData, VaultFailure::InvalidData),
        ];
        for (backend_error, expected) in cases {
            let backend = FakeBackend::default();
            backend.fail_set(backend_error);
            let vault = MacKeychainVault::new(backend.clone());
            assert_eq!(
                vault.set(&account(), b"secret").unwrap_err(),
                expected,
                "{backend_error:?}"
            );
            assert_eq!(backend.calls(), vec!["set"], "{backend_error:?}");
        }
    }

    #[test]
    fn read_and_delete_failures_map_to_structured_vault_failures() {
        let cases = [
            (KeychainError::Denied, VaultFailure::Denied),
            (KeychainError::Locked, VaultFailure::Locked),
            (KeychainError::MissingItem, VaultFailure::MissingItem),
            (KeychainError::InvalidData, VaultFailure::InvalidData),
        ];
        for (backend_error, expected) in cases {
            let backend = FakeBackend::default();
            backend.fail_get(backend_error);
            let vault = MacKeychainVault::new(backend.clone());
            assert_eq!(
                vault.get(&account()).unwrap_err(),
                expected,
                "get {backend_error:?}"
            );

            let backend = FakeBackend::default();
            backend.fail_delete(backend_error);
            let vault = MacKeychainVault::new(backend);
            assert_eq!(
                vault.delete(&account()).unwrap_err(),
                expected,
                "delete {backend_error:?}"
            );
        }
    }

    #[test]
    fn deleting_a_missing_item_reports_a_structured_failure() {
        let backend = FakeBackend::default();
        let vault = MacKeychainVault::new(backend);
        assert_eq!(
            vault.delete(&account()).unwrap_err(),
            VaultFailure::MissingItem
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn operating_system_status_codes_map_to_structured_keychain_errors() {
        use security_framework_sys::base::{
            errSecAuthFailed, errSecDuplicateItem, errSecItemNotFound,
        };

        assert_eq!(
            classify(errSecItemNotFound),
            Some(KeychainError::MissingItem)
        );
        assert_eq!(
            classify(errSecDuplicateItem),
            Some(KeychainError::DuplicateItem)
        );
        assert_eq!(classify(errSecAuthFailed), Some(KeychainError::Denied));
        assert_eq!(classify(-25308), Some(KeychainError::Locked));
        assert_eq!(classify(-128), Some(KeychainError::Denied));
        assert_eq!(classify(-25294), Some(KeychainError::Unavailable));
        assert_eq!(classify(-26275), Some(KeychainError::InvalidData));
        assert_eq!(classify(-1), None);
    }
}
