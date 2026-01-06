use std::fmt::{Display, Formatter};
use std::sync::PoisonError;
use std::{io, panic};
use crate::tree_store::{FILE_FORMAT_VERSION3};
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The Database is already open. Cannot acquire lock.
    DatabaseAlreadyOpen,
    /// This savepoint is invalid or cannot be created.
    ///
    /// Savepoints become invalid when an older savepoint is restored after it was created,
    /// and savepoints cannot be created if the transaction is "dirty" (any tables have been opened)
    InvalidSavepoint,
    /// [`crate::RepairSession::abort`] was called.
    RepairAborted,
    /// A persistent savepoint was modified
    PersistentSavepointModified,
    /// A persistent savepoint exists
    PersistentSavepointExists,
    /// An Ephemeral savepoint exists
    EphemeralSavepointExists,
    /// A transaction is still in-progress
    TransactionInProgress,
    /// The Database is corrupted
    Corrupted(String),
    /// The database file is in an old file format and must be manually upgraded
    UpgradeRequired(u8),
    /// The value being inserted exceeds the maximum of 3GiB
    ValueTooLarge(usize),
    /// Table types didn't match.
    // TableTypeMismatch {
    //     table: String,
    //     key: TypeName,
    //     value: TypeName,
    // },
    /// The table is a multimap table
    TableIsMultimap(String),
    /// The table is not a multimap table
    TableIsNotMultimap(String),
    // TypeDefinitionChanged {
    //     name: TypeName,
    //     alignment: usize,
    //     width: Option<usize>,
    // },
    /// Table name does not match any table in database
    TableDoesNotExist(String),
    /// Table name already exists in the database
    TableExists(String),
    // Tables cannot be opened for writing multiple times, since they could retrieve immutable &
    // mutable references to the same dirty pages, or multiple mutable references via insert_reserve()
    TableAlreadyOpen(String, &'static panic::Location<'static>),
    Io(io::Error),
    DatabaseClosed,
    /// A previous IO error occurred. The database must be closed and re-opened
    PreviousIo,
    LockPoisoned(&'static panic::Location<'static>),
    // The transaction is still referenced by a table or other object
    // ReadTransactionStillInUse(Box<ReadTransaction>),
}

/// General errors directly from the storage layer
#[derive(Debug)]
#[non_exhaustive]
pub enum StorageError {
    /// The Database is corrupted
    Corrupted(String),
    /// The value being inserted exceeds the maximum of 3GiB
    ValueTooLarge(usize),
    Io(io::Error),
    PreviousIo,
    DatabaseClosed,
    LockPoisoned(&'static panic::Location<'static>),
}



/// Errors related to opening a database
#[derive(Debug)]
#[non_exhaustive]
pub enum DatabaseError {
    /// The Database is already open. Cannot acquire lock.
    DatabaseAlreadyOpen,
    /// [`crate::RepairSession::abort`] was called or repair was aborted for another reason (such as the database being read-only).
    RepairAborted,
    /// The database file is in an old file format and must be manually upgraded
    UpgradeRequired(u8),
    /// Error from RocksDB
    RocksDb(String),

    PropertyNotFound(String),
    // Storage(StorageError),
}

// impl From<StorageError> for DatabaseError {
//     fn from(err: StorageError) -> DatabaseError {
//         DatabaseError::Storage(err)
//     }
// }

impl From<rocksdb::Error> for DatabaseError {
    fn from(err: rocksdb::Error) -> DatabaseError {
        DatabaseError::RocksDb(err.to_string())
    }
}

impl From<io::Error> for DatabaseError {
    fn from(err: io::Error) -> DatabaseError {
        DatabaseError::RocksDb(err.to_string())
    }
}

impl From<DatabaseError> for Error {
    fn from(err: DatabaseError) -> Error {
        match err {
            DatabaseError::DatabaseAlreadyOpen => Error::DatabaseAlreadyOpen,
            DatabaseError::RepairAborted => Error::RepairAborted,
            DatabaseError::UpgradeRequired(x) => Error::UpgradeRequired(x),
            DatabaseError::RocksDb(msg) => Error::Corrupted(msg),
            DatabaseError::PropertyNotFound(prop) => Error::Corrupted(format!("Property not found: {}", prop)),
        }
    }
}

// impl From<io::Error> for DatabaseError {
//     fn from(err: io::Error) -> DatabaseError {
//         DatabaseError::Storage(StorageError::Io(err))
//     }
// }


impl Display for DatabaseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseError::UpgradeRequired(actual) => {
                write!(
                    f,
                    "Manual upgrade required. Expected file format version {FILE_FORMAT_VERSION3}, but file is version {actual}"
                )
            }
            DatabaseError::RepairAborted => {
                write!(f, "Database repair aborted.")
            }
            DatabaseError::DatabaseAlreadyOpen => {
                write!(f, "Database already open. Cannot acquire lock.")
            }
            DatabaseError::RocksDb(msg) => {
                write!(f, "RocksDB error: {}", msg)
            }
            DatabaseError::PropertyNotFound(prop) => {
                write!(f, "Database property not found: {}", prop)
            }
            // DatabaseError::Storage(storage) => storage.fmt(f),
        }
    }
}

impl std::error::Error for DatabaseError {}
