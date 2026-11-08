//! Host-owned schema migrations.
//!
//! Migrations are embedded from `migrations/`, applied in ascending order, and
//! recorded in the `schema_version` table. Each open runs them in a single
//! immediate transaction: a failure rolls every statement back, leaving the
//! previous database contents and schema version unchanged. A database whose
//! version is newer than this build is rejected before any write.

use rusqlite::{Connection, Transaction, TransactionBehavior, params};

use crate::error::StoreError;
use crate::fault::MigrationPoint;

const LATEST_SCHEMA_VERSION: u32 = 3;

struct Migration {
    version: u32,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "0001_initial",
        sql: include_str!("../migrations/0001_initial.sql"),
    },
    Migration {
        version: 2,
        name: "0002_lookup_indexes",
        sql: include_str!("../migrations/0002_lookup_indexes.sql"),
    },
    Migration {
        version: 3,
        name: "0003_host_state",
        sql: include_str!("../migrations/0003_host_state.sql"),
    },
];

/// Newest schema version this build can migrate to.
pub const fn latest_schema_version() -> u32 {
    LATEST_SCHEMA_VERSION
}

/// Reads the stored schema version without writing anything.
///
/// `Ok(None)` means the database has no user tables and is safe to initialize.
pub(crate) fn read_schema_version(conn: &Connection) -> Result<Option<u32>, StoreError> {
    let has_marker: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version')",
        [],
        |row| row.get(0),
    )?;
    if !has_marker {
        let user_tables: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        if user_tables == 0 {
            return Ok(None);
        }
        return Err(StoreError::ForeignDatabase);
    }

    let rows: i64 = conn.query_row("SELECT COUNT(*) FROM schema_version", [], |row| row.get(0))?;
    if rows != 1 {
        return Err(StoreError::corrupt(
            "schema_version must contain exactly one row",
        ));
    }

    let version: i64 =
        conn.query_row("SELECT version FROM schema_version", [], |row| row.get(0))?;
    let version = u32::try_from(version)
        .map_err(|_| StoreError::corrupt("schema_version must be a non-negative integer"))?;
    if version > LATEST_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchemaVersion {
            found: version,
            supported: LATEST_SCHEMA_VERSION,
        });
    }
    if version == 0 {
        return Err(StoreError::corrupt("schema_version 0 cannot be migrated"));
    }
    Ok(Some(version))
}

/// Applies migrations up to `target_version`.
///
/// The caller must have verified the database is not newer than this build
/// before calling. `fault` is only used by tests.
pub(crate) fn apply(
    conn: &mut Connection,
    target_version: u32,
    fault: Option<MigrationPoint>,
) -> Result<(), StoreError> {
    if target_version > LATEST_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchemaVersion {
            found: target_version,
            supported: LATEST_SCHEMA_VERSION,
        });
    }

    // Point-in-time check outside the transaction keeps unknown newer databases
    // untouched.
    if let Some(found) = read_schema_version(conn)?
        && found > LATEST_SCHEMA_VERSION
    {
        return Err(StoreError::UnsupportedSchemaVersion {
            found,
            supported: LATEST_SCHEMA_VERSION,
        });
    }

    let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = apply_in_transaction(&transaction, target_version, fault);
    match result {
        Ok(()) => transaction.commit().map_err(StoreError::database),
        Err(error) => {
            // Dropping would also roll back, but be explicit and keep the
            // original error if rollback itself fails.
            let _ = transaction.rollback();
            Err(error)
        }
    }
}

fn apply_in_transaction(
    transaction: &Transaction<'_>,
    target_version: u32,
    fault: Option<MigrationPoint>,
) -> Result<(), StoreError> {
    let current = match read_schema_version(transaction)? {
        Some(version) => version,
        None => {
            transaction.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version (version) VALUES (0);",
            )?;
            0
        }
    };

    if current > LATEST_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchemaVersion {
            found: current,
            supported: LATEST_SCHEMA_VERSION,
        });
    }
    if current > target_version {
        return Err(StoreError::MigrationFailed {
            version: current,
            detail: format!("database is already newer than target version {target_version}"),
        });
    }

    for migration in MIGRATIONS
        .iter()
        .filter(|migration| migration.version > current && migration.version <= target_version)
    {
        let statements = split_statements(migration.sql);
        if statements.is_empty() {
            return Err(StoreError::MigrationFailed {
                version: migration.version,
                detail: format!("migration {} is empty", migration.name),
            });
        }

        for (index, statement) in statements.iter().enumerate() {
            transaction
                .execute_batch(statement)
                .map_err(|error| StoreError::MigrationFailed {
                    version: migration.version,
                    detail: error.to_string(),
                })?;

            if let Some(point) = fault
                && point.version == migration.version
                && point.after_statements == index + 1
            {
                return Err(StoreError::InjectedFault {
                    point: "migration-after-statement",
                });
            }
        }

        transaction.execute(
            "UPDATE schema_version SET version = ?1",
            params![migration.version],
        )?;
    }

    Ok(())
}

/// Splits a migration file into individual statements.
///
/// Migration files are host-owned and must not contain semicolons inside string
/// literals or triggers; comments and empty statements are discarded.
fn split_statements(sql: &str) -> Vec<&str> {
    sql.split(';')
        .map(str::trim)
        .filter(|statement| {
            !statement.is_empty()
                && statement
                    .lines()
                    .any(|line| !line.trim_start().starts_with("--") && !line.trim().is_empty())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latest_version_matches_the_migration_list() {
        assert_eq!(
            latest_schema_version(),
            MIGRATIONS.last().expect("migrations exist").version
        );
        assert_eq!(latest_schema_version(), 3);
    }

    #[test]
    fn statements_are_split_without_comments_or_empty_fragments() {
        let statements = split_statements(include_str!("../migrations/0002_lookup_indexes.sql"));
        assert_eq!(statements.len(), 2);
        assert!(statements[0].contains("CREATE INDEX checkpoints_by_project"));
        assert!(statements[1].contains("CREATE INDEX events_by_run"));
    }
}
