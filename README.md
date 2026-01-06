# BitcoinScan

A high-performance Bitcoin blockchain data scanner and API server built with Rust.

## Overview

BitcoinScan is a Rust-based project that provides efficient scanning, storage, and querying of Bitcoin blockchain data. It uses RocksDB for fast data storage and retrieval, and provides a REST API for accessing Bitcoin address information.

## Features

- **Fast Data Storage**: Uses RocksDB with multi-threaded support and ZSTD compression
- **REST API**: Query Bitcoin address data through HTTP endpoints
- **Scalable**: Multi-threaded architecture for high-performance operations
- **Tracing & Logging**: Built-in request tracing and structured logging
- **CORS Support**: Configurable CORS for cross-origin requests

## Project Structure

```
BitcoinScan/
├── src/              # Core library code
│   ├── db.rs         # Database implementation
│   ├── error.rs      # Error handling
│   ├── logger.rs     # Logging setup
│   └── tree_store/   # Tree-based storage backend
├── crates/
│   ├── api/          # REST API server
│   └── importer/     # Data import tools
└── data/             # Database storage directory
```

## Installation

### Prerequisites

- Rust 1.70 or later
- Cargo

### Build from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/BitcoinScan.git
cd BitcoinScan

# Build the project
cargo build --release

# Run tests
cargo test
```

## Usage

### Starting the API Server

```bash
cargo run --bin api
```

The server will start on `http://localhost:8082` by default.

### API Endpoints

#### Health Check
```
GET /health
```
Returns: `OK`

#### Count Addresses
```
GET /api/1.0/address/count
```
Returns the total number of addresses in the database.

Response:
```json
{
  "count": 123456789
}
```

#### Get Top Addresses
```
GET /api/1.0/address/top?limit=10
```
Returns the first N addresses from the database.

Query Parameters:
- `limit` (optional, default: 10): Number of addresses to return

Response:
```json
{
  "top_addresses": [...]
}
```

#### Get Last Addresses
```
GET /api/1.0/address/last?limit=10
```
Returns the last N addresses from the database.

#### Get Address Info
```
GET /api/1.0/address/{address}
```
Returns information about a specific address.

## Configuration

The API server can be configured through the `HttpConfig` structure:

```rust
let config = HttpConfig {
    address: "localhost:8082".to_owned(),
    path: "/api".to_owned(),
    version: "1.0".to_owned(),
    cors: HttpCorsConfig::default(),
    tls: HttpTlsConfig::default(),
};
```

## Development

### Running in Development Mode

```bash
cargo run --bin api
```

### Running Tests

```bash
cargo test
```

### Linting

```bash
cargo clippy
```

### Formatting

```bash
cargo fmt
```

## Architecture

### Database Layer
- **RocksDB**: High-performance key-value store
- **Read-only mode**: Optimized for query operations
- **Multi-threaded column families**: Parallel data access

### API Layer
- **Axum**: Modern, ergonomic web framework
- **Tower HTTP**: Middleware for tracing and CORS
- **Tokio**: Async runtime with 16 worker threads

### Logging & Tracing
- **Tracing**: Structured logging and distributed tracing
- **Request tracking**: Automatic request/response logging
- **Error reporting**: Detailed error context

## Performance

- Multi-threaded runtime with 16 worker threads
- Connection pooling for database access
- Efficient binary serialization
- ZSTD compression for data storage

## Dependencies

Key dependencies:
- `axum` - Web framework
- `rocksdb` - Database engine
- `tokio` - Async runtime
- `tracing` - Logging and diagnostics
- `tower-http` - HTTP middleware
- `serde` - Serialization

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License


## Contact

@dajneem23