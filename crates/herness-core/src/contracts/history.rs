//! Stable, project-scoped history pagination contracts.
//!
//! A [`HistoryCursor`] is minted by a page for exactly one project. It fixes
//! the upper sequence bound captured when the first page was read, so later
//! pages never mix in newer events. Passing a cursor to a query for another
//! project is rejected instead of silently reading the wrong project's rows.

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::contracts::errors::{ArgumentViolation, CoreError};
use crate::contracts::events::Event;
use crate::contracts::ids::{IdKind, ProjectId};

/// Default number of events in one history page.
pub const DEFAULT_HISTORY_LIMIT: u16 = 100;

/// Largest number of events in one history page.
pub const MAX_HISTORY_LIMIT: u16 = 500;

/// Validated history page size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HistoryLimit(u16);

impl HistoryLimit {
    /// Creates a limit in `1..=500`.
    pub fn new(value: u16) -> Result<Self, CoreError> {
        if value == 0 || value > MAX_HISTORY_LIMIT {
            Err(CoreError::InvalidHistoryLimit {
                value,
                max: MAX_HISTORY_LIMIT,
            })
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the page size.
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl Default for HistoryLimit {
    fn default() -> Self {
        Self(DEFAULT_HISTORY_LIMIT)
    }
}

impl Serialize for HistoryLimit {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(self.0)
    }
}

impl<'de> Deserialize<'de> for HistoryLimit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// A fixed history position bound to the project that minted it.
///
/// The cursor is an exclusive upper bound: a page returns events whose sequence
/// is strictly less than [`HistoryCursor::before_sequence`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryCursor {
    project_id: ProjectId,
    before_sequence: u64,
}

impl HistoryCursor {
    /// Creates a cursor for `project_id` at a positive sequence.
    pub fn new(project_id: ProjectId, before_sequence: u64) -> Result<Self, CoreError> {
        if before_sequence == 0 {
            return Err(CoreError::InvalidValue {
                field: "beforeSequence".to_owned(),
                violation: ArgumentViolation::MustBePositive,
            });
        }
        Ok(Self {
            project_id,
            before_sequence,
        })
    }

    /// Project whose history this cursor addresses.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Exclusive upper sequence bound.
    pub const fn before_sequence(&self) -> u64 {
        self.before_sequence
    }
}

impl<'de> Deserialize<'de> for HistoryCursor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            project_id: ProjectId,
            before_sequence: u64,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.project_id, wire.before_sequence).map_err(de::Error::custom)
    }
}

/// A project-scoped history request.
///
/// `cursor` is the fixed upper bound from the previous page. The store returns
/// events in descending sequence order and never mixes newer events into an
/// already-started page. A cursor minted for another project is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryQuery {
    project_id: ProjectId,
    cursor: Option<HistoryCursor>,
    limit: HistoryLimit,
}

impl HistoryQuery {
    /// Creates a validated history query.
    pub fn new(
        project_id: ProjectId,
        cursor: Option<HistoryCursor>,
        limit: HistoryLimit,
    ) -> Result<Self, CoreError> {
        if let Some(cursor) = cursor
            && cursor.project_id() != project_id
        {
            return Err(CoreError::CrossProjectReference {
                id_kind: IdKind::Project,
                expected: project_id,
                found: cursor.project_id(),
            });
        }
        Ok(Self {
            project_id,
            cursor,
            limit,
        })
    }

    /// Creates the first page query with the default limit.
    pub fn first(project_id: ProjectId) -> Self {
        Self {
            project_id,
            cursor: None,
            limit: HistoryLimit::default(),
        }
    }

    /// Project whose history is requested.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Project-bound upper cursor, fixed by the previous page.
    pub const fn cursor(&self) -> Option<HistoryCursor> {
        self.cursor
    }

    /// Exclusive upper sequence bound, when paging.
    pub const fn before_sequence(&self) -> Option<u64> {
        match self.cursor {
            Some(cursor) => Some(cursor.before_sequence()),
            None => None,
        }
    }

    /// Requested page size.
    pub const fn limit(&self) -> HistoryLimit {
        self.limit
    }
}

impl<'de> Deserialize<'de> for HistoryQuery {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            project_id: ProjectId,
            cursor: Option<HistoryCursor>,
            limit: HistoryLimit,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.project_id, wire.cursor, wire.limit).map_err(de::Error::custom)
    }
}

/// One page of persisted history in descending sequence order.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPage {
    events: Vec<Event>,
    next_cursor: Option<HistoryCursor>,
}

impl HistoryPage {
    /// Creates a history page.
    pub fn new(events: Vec<Event>, next_cursor: Option<HistoryCursor>) -> Result<Self, CoreError> {
        if let Some(cursor) = next_cursor {
            let Some(first) = events.first() else {
                return Err(CoreError::InvalidValue {
                    field: "nextCursor".to_owned(),
                    violation: ArgumentViolation::Invalid {
                        detail: "a cursor requires at least one event".to_owned(),
                    },
                });
            };
            if first.project_id() != cursor.project_id() {
                return Err(CoreError::CrossProjectReference {
                    id_kind: IdKind::Project,
                    expected: first.project_id(),
                    found: cursor.project_id(),
                });
            }
        }
        Ok(Self {
            events,
            next_cursor,
        })
    }

    /// Events in descending sequence order.
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Cursor for the next page, fixed at the last returned sequence.
    pub const fn next_cursor(&self) -> Option<HistoryCursor> {
        self.next_cursor
    }

    /// Next cursor's exclusive upper sequence, when paging.
    pub const fn next_before_sequence(&self) -> Option<u64> {
        match self.next_cursor {
            Some(cursor) => Some(cursor.before_sequence()),
            None => None,
        }
    }
}

impl<'de> Deserialize<'de> for HistoryPage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            events: Vec<Event>,
            next_cursor: Option<HistoryCursor>,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.events, wire.next_cursor).map_err(de::Error::custom)
    }
}
