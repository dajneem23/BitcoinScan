use bitcoin_scan::decode_address;

fn main() {
    let test_addresses = vec![
        ("BIP84/P2WPKH", "bc1qyu5v99d8urfxc3vk4ddrcr38yfuz9w8vxycdy6"),
        ("BIP44/P2PKH", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
        ("BIP49/P2SH", "3CPC7uMYxiudp2g9we7bvm9crTBgQN5Rb8"),
    ];
    
    for (bip_type, addr) in test_addresses {
        println!("\n=== {} ===", bip_type);
        println!("Address: {}", addr);
        
        // Debug Base58 decode for addresses starting with 3
        if addr.starts_with('3') {
            if let Ok(decoded) = bs58::decode(addr).into_vec() {
                println!("  Base58 decoded length: {} bytes", decoded.len());
                println!("  Base58 decoded: {:?}", decoded);
                
                if decoded.len() == 25 {
                    use sha2::{Digest, Sha256};
                    let payload = &decoded[..21];
                    let checksum_in_addr = &decoded[21..];
                    let hash1 = Sha256::digest(payload);
                    let hash2 = Sha256::digest(&hash1);
                    
                    println!("  Expected checksum: {:?}", &hash2[..4]);
                    println!("  Address checksum:  {:?}", checksum_in_addr);
                    println!("  Checksums match: {}", &hash2[..4] == checksum_in_addr);
                }
            }
        }
        
        match decode_address(addr) {
            Some(hash) => {
                println!("✓ Decoded successfully!");
                println!("  Hash length: {} bytes", hash.len());
                println!("  Hash (bytes): {:?}", hash);
            }
            None => {
                println!("✗ Failed to decode");
            }
        }
    }
}
