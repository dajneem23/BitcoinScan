mod importer;

use bitcoin_scan::db::{Database, DEFAULT_DB_PATH};
use bitcoin_scan::error::*;

use crate::importer::import_addresses;

fn main() {

    let file_path = "test_10m.gz";
    let batch_size = 50_000; // Ghi mỗi lần 50k địa chỉ

    let mut db = Database::open(&DEFAULT_DB_PATH).expect("Cannot open DB");

    // Import addresses from file
    match import_addresses(file_path, &mut db, batch_size) {
        Ok((new_count, skipped_count)) => {
            // Manual Compaction (Tùy chọn): Nén chặt data lần cuối sau khi import xong
            println!("📦 Compacting database... (This may take a while)");
            db.compact_range(None::<&[u8]>, None::<&[u8]>);
            println!(
                "🎉 All Done. New: {}, Skipped: {}",
                new_count, skipped_count
            );
        }
        Err(e) => {
            eprintln!("❌ Error during import: {}", e);
            std::process::exit(1);
        }
    }
}
