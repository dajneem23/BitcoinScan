use crate::error::DatabaseError;
use rocksdb::{DBCompressionType, DBPinnableSlice, IteratorMode, Options, WriteBatch, DB};
use tracing::info;
use std::fmt::Formatter;
use std::path::Path;

pub const CACHE_SIZE: usize = 1_024 * 1_024 * 1_024; // 1GB
pub(crate) const PAGE_SIZE: usize = 4096;
pub const DEFAULT_DB_PATH: &str = "./data/bitcoin_data";

pub struct Database {
    db: DB,
}

pub struct ReadOnlyDatabase {
    db: DB,
}
pub trait ReadableDatabase {
    /// Helper to access the underlying RocksDB instance.
    fn get_db(&self) -> &DB;

    /// Check if a key exists.
    /// Optimized using `get_pinned` to avoid allocating memory for the result value.
    fn exists<K: AsRef<[u8]>>(&self, key: K) -> Result<bool, DatabaseError> {
        match self.get_db().get_pinned(key) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(DatabaseError::from(e)), // Assumes From impl exists
        }
    }

    /// Standard get. Returns a vector of bytes.
    /// Use this if you actually stored data in the Value field.
    fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<Vec<u8>>, DatabaseError> {
        self.get_db().get(key).map_err(DatabaseError::from)
    }

    /// Zero-copy get. Returns a pinnable slice.
    /// Extremely fast because it points directly to memory in the BlockCache or OS Page Cache.
    fn get_pinned<K: AsRef<[u8]>>(
        &self,
        key: K,
    ) -> Result<Option<DBPinnableSlice<'_>>, DatabaseError> {
        self.get_db().get_pinned(key).map_err(DatabaseError::from)
    }

    /// Batch get. Returns a vector of results.
    /// Essential for high-throughput queries (e.g., checking 100 addresses at once).
    fn multi_get<K: AsRef<[u8]>, I: IntoIterator<Item = K>>(
        &self,
        keys: I,
    ) -> Vec<Result<Option<Vec<u8>>, DatabaseError>> {
        self.get_db()
            .multi_get(keys)
            .into_iter()
            .map(|r| r.map_err(DatabaseError::from))
            .collect()
    }

    /// Iterate over all keys.
    /// Useful for debugging or exporting data.
    fn iter_start(&self) -> rocksdb::DBIterator<'_> {
        self.get_db().iterator(IteratorMode::Start)
    }

    /// Get a database property (e.g., "rocksdb.estimate-num-keys")
    fn get_property(&self, name: &str) -> Option<u64> {
        self.get_db().property_int_value(name).unwrap_or(None)
    }

    fn count_keys(&self) -> Result<u64, DatabaseError> {
        self.get_property("rocksdb.estimate-num-keys")
            .ok_or(DatabaseError::PropertyNotFound(
                "rocksdb.estimate-num-keys".to_string(),
            ))
    }

    /// Lấy N phần tử đầu tiên (A -> Z)
    /// Cực nhanh
    fn first(&self, limit: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>, DatabaseError> {
        let mode = rocksdb::IteratorMode::Start;

        self.get_db()
            .iterator(mode)
            .take(limit)
            .map(|item| {
                item.map(|(k, v)| (k.to_vec(), v.to_vec()))
                    .map_err(DatabaseError::from)
            })
            .collect()
    }

    /// Lấy N phần tử cuối cùng (Z -> A)
    /// Cực nhanh
    fn last(&self, limit: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>, DatabaseError> {
        // IteratorMode::End sẽ đặt con trỏ ở cuối và tự động đi lùi (Reverse Scan)
        let mode = rocksdb::IteratorMode::End;

        self.get_db()
            .iterator(mode)
            .take(limit)
            .map(|item| {
                item.map(|(k, v)| (k.to_vec(), v.to_vec()))
                    .map_err(DatabaseError::from)
            })
            .collect()
    }
}

impl ReadOnlyDatabase {
    pub fn builder() -> Builder {
        Builder::new()
    }
    pub fn create(path: impl AsRef<Path>) -> Result<Database, DatabaseError> {
        Self::builder().create(path)
    }
    /// Opens an existing RocksDB database.
    pub fn open(
        path: impl AsRef<Path>,
        error_if_log_file_exist: bool,
    ) -> Result<Database, DatabaseError> {
        let db = DB::open_for_read_only(&Self::builder().options, path, error_if_log_file_exist)?;
        Ok(Database::new(db))
    }

    fn new(db: DB) -> Self {
        Self { db }
    }
}

impl ReadableDatabase for Database {
    fn get_db(&self) -> &DB {
        &self.db
    }
}

impl Database {
    /// Opens the specified file as a RocksDB database.
    /// * if the file does not exist, or is an empty file, a new database will be initialized in it
    /// * if the file is a valid RocksDB database, it will be opened
    /// * otherwise this function will return an error
    pub fn create(path: impl AsRef<Path>) -> Result<Database, DatabaseError> {
        Self::builder().create(path)
    }

    /// Opens an existing RocksDB database.
    pub fn open(path: impl AsRef<Path>) -> Result<Database, DatabaseError> {
        let db = DB::open(&Self::builder().options, path)?;
        Ok(Database::new(db))
    }

    pub fn new(db: DB) -> Self {
        Self { db }
    }

    pub fn builder() -> Builder {
        Builder::new()
    }

    pub fn begin_write(&self, batch: WriteBatch) -> Result<(), rocksdb::Error> {
        self.db.write(batch)
    }

    // fn begin_read(&self) -> Self::R<'_> {
    //     let txn = self.db.begin_read().unwrap();
    // }

    pub fn compact_range<S: AsRef<[u8]>, E: AsRef<[u8]>>(
        &mut self,
        start: Option<S>,
        end: Option<E>,
    ) -> &mut Self {
        self.db.compact_range(start, end);
        self
    }
}

impl std::fmt::Debug for Database {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Database").finish()
    }
}

/// Configuration builder of a redb [Database].
pub struct Builder {
    pub options: Options,
}

impl Builder {
    /// Construct a new [Builder] with sensible defaults.
    ///
    /// ## Defaults
    ///
    /// - `cache_size_bytes`: 1GiB
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_compression_type(DBCompressionType::Zstd);

        // Tăng tốc độ ghi bằng cách dùng nhiều RAM làm đệm
        opts.set_write_buffer_size(256 * 1024 * 1024); // 256MB Memtable
        opts.set_max_write_buffer_number(4);
        opts.set_target_file_size_base(128 * 1024 * 1024);

        // Tắt WAL (Write Ahead Log) để tốc độ ghi X2 (Chấp nhận rủi ro crash lúc import)
        opts.set_unordered_write(true);

        //EXPERIMENTAL
        // opts.set_compression_options_parallel_threads(3);

        // Số luồng chạy ngầm để nén data xuống đĩa
        opts.set_max_background_jobs(4);

        let mut block_opts = rocksdb::BlockBasedOptions::default();
        block_opts.set_bloom_filter(10.0, false); // 10 bits per key
        block_opts.set_block_cache(&rocksdb::Cache::new_lru_cache(CACHE_SIZE));
        opts.set_block_based_table_factory(&block_opts);

        let result = Self {
            // Default to 4k pages. Benchmarking showed that this was a good default on all platforms,
            // including MacOS with 16k pages. Therefore, users are not allowed to configure it at the moment.
            // It is part of the file format, so can be enabled in the future.
            // repair_callback: Box::new(|_| {}),
            options: opts,
        };

        result
    }

    pub fn set_db_paths(&mut self, paths: &[rocksdb::DBPath]) -> &mut Self {
        self.options.set_db_paths(paths);
        self
    }

    pub fn increase_parallelism(&mut self, parallelism: i32) -> &mut Self {
        self.options.increase_parallelism(parallelism);
        self
    }

    /// Opens the specified path as a RocksDB database.
    /// * if the file does not exist, a new database will be initialized
    /// * if the file is a valid RocksDB database, it will be opened
    /// * otherwise this function will return an error
    pub fn create(&self, path: impl AsRef<Path>) -> Result<Database, DatabaseError> {
        let db = DB::open(&self.options, path)?;
        Ok(Database::new(db))
    }
}
