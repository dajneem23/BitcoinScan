use bitcoin_scan::db::{Database, ReadableDatabase};
use bitcoin_scan::utils::decode_address;
use flate2::read::GzDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use rocksdb::WriteBatch;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader};



/// Import Bitcoin addresses from a gzip-compressed file into the database.
///
/// # Arguments
/// * `file_path` - Path to the .gz file containing Bitcoin addresses (one per line)
/// * `db` - Mutable reference to the Database instance
/// * `batch_size` - Number of addresses to batch before writing to DB
///
/// # Returns
/// Tuple of (new_addresses_count, skipped_duplicates_count)
pub fn import_addresses(
    file_path: &str,
    db: &mut Database,
    batch_size: usize,
) -> Result<(u64, u64), Box<dyn std::error::Error>> {
    println!("📂 Opening GZ Stream: {}", file_path);
    let file = File::open(file_path)?;
    
    // Pipeline: File -> GzDecoder -> BufReader -> Lines
    let decoder = GzDecoder::new(file);
    let reader = BufReader::with_capacity(1024 * 1024, decoder); // 1MB Buffer Read

    let mut batch = WriteBatch::default();
    let mut counter = 0u64;
    let mut skipped = 0u64;

    // Setup Progress Bar
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap(),
    );

    for line_result in reader.lines() {
        if let Ok(line) = line_result {
            let addr_str = line.trim();

            // Decode String -> Raw Bytes
            if let Some(raw_bytes) = decode_address(addr_str) {
                // Check if key already exists
                if !db.exists(&raw_bytes).unwrap_or(false) {
                    // Key: 20 bytes hash, Value: Rỗng (tiết kiệm chỗ)
                    //TODO: add timestamp or source info into value
                    batch.put(&raw_bytes, b"0");
                    counter += 1;
                } else {
                    skipped += 1;
                }
            }

            // Flush batch xuống DB
            if batch.len() >= batch_size {
                db.begin_write(batch)?;
                batch = WriteBatch::default(); // Reset batch
            }

            if counter % 1_000_000 == 0 {
                pb.set_message(format!(
                    "Processed: {}M addrs | New: {} | Skipped: {}",
                    (counter + skipped) / 1_000_000,
                    counter,
                    skipped
                ));
            }
        }
    }

    // Flush nốt những cái còn sót lại
    if batch.len() > 0 {
        db.begin_write(batch)?;
    }

    pb.finish_with_message(format!(
        "✅ Done! New: {} | Skipped duplicates: {}",
        counter, skipped
    ));

    Ok((counter, skipped))
}
