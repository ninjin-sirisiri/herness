//! Non-secret ChatGPT account registration directory.
//!
//! Account registrations are keyed by connection + issued client ID + verified
//! subject. They never contain tokens. Task 10/11 may persist this mapping; for
//! Task 8 the default is in-memory and an injectable trait keeps that decision
//! contained.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use herness_core::ConnectionId;

use super::error::AuthError;
use super::types::{ChatGptAccount, ChatGptAccountRef, IssuedClientId};

/// Read/write boundary for non-secret ChatGPT account registrations.
pub trait AccountDirectory: Send + Sync {
    /// Lists saved accounts for one connection in stable order.
    fn accounts(&self, connection: ConnectionId) -> Result<Vec<ChatGptAccount>, AuthError>;

    /// Finds one account by issued client ID and verified subject.
    fn find(
        &self,
        connection: ConnectionId,
        client_id: &IssuedClientId,
        subject: &str,
    ) -> Result<Option<ChatGptAccount>, AuthError>;

    /// Inserts or replaces one account registration.
    fn upsert(&self, account: ChatGptAccount) -> Result<(), AuthError>;

    /// Finds an account by its non-secret selector.
    fn find_ref(
        &self,
        connection: ConnectionId,
        reference: &ChatGptAccountRef,
    ) -> Result<Option<ChatGptAccount>, AuthError> {
        self.find(connection, reference.client_id(), reference.subject())
    }
}

/// In-memory account directory.
type AccountKey = (ConnectionId, String, String);
type AccountMap = BTreeMap<AccountKey, ChatGptAccount>;

/// In-memory account directory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryAccountDirectory {
    inner: Arc<Mutex<AccountMap>>,
}

impl InMemoryAccountDirectory {
    /// Creates an empty directory.
    pub fn new() -> Self {
        Self::default()
    }
}

impl AccountDirectory for InMemoryAccountDirectory {
    fn accounts(&self, connection: ConnectionId) -> Result<Vec<ChatGptAccount>, AuthError> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(inner
            .values()
            .filter(|account| account.connection() == connection)
            .cloned()
            .collect())
    }

    fn find(
        &self,
        connection: ConnectionId,
        client_id: &IssuedClientId,
        subject: &str,
    ) -> Result<Option<ChatGptAccount>, AuthError> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(inner
            .get(&(
                connection,
                client_id.as_str().to_owned(),
                subject.to_owned(),
            ))
            .cloned())
    }

    fn upsert(&self, account: ChatGptAccount) -> Result<(), AuthError> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.insert(
            (
                account.connection(),
                account.client_id().as_str().to_owned(),
                account.subject().to_owned(),
            ),
            account,
        );
        Ok(())
    }
}
