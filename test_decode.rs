use sha2::{Digest, Sha256};

/// Giải mã địa chỉ Bitcoin sang dạng Bytes thô (Raw Hash Payload)
/// - Legacy/P2SH (1..., 3...): Trả về 20 bytes Hash160.
/// - Segwit v0 (bc1q...): Trả về 20 bytes (P2WPKH) hoặc 32 bytes (P2WSH).
/// - Taproot v1 (bc1p...): Trả về 32 bytes (P2TR - Tweaked Key).
pub fn decode_address(addr: &str) -> Option<Vec<u8>> {
    // --- CASE 1: BASE58 (Legacy '1' & Nested Segwit/P2SH '3') ---
    if addr.starts_with('1') || addr.starts_with('3') {
        // Decode Base58
        if let Ok(decoded) = bs58::decode(addr).into_vec() {
            // Cấu trúc chuẩn: [1 byte Version] + [20 bytes Hash] + [4 bytes Checksum] = 25 bytes
            if decoded.len() == 25 {
                // 1. Kiểm tra Checksum để đảm bảo địa chỉ không bị lỗi đánh máy
                // Checksum = 4 bytes đầu của Double-SHA256(Version + Hash)
                let payload = &decoded[..21]; // Version + Hash
                let checksum_in_addr = &decoded[21..];

                let hash1 = Sha256::digest(payload);
                let hash2 = Sha256::digest(&hash1);

                if &hash2[..4] == checksum_in_addr {
                    // Checksum đúng -> Trả về 20 bytes Hash thực sự (Bỏ byte Version đầu tiên)
                    return Some(payload[1..].to_vec());
                }
            }
        }
    }
    // --- CASE 2: BECH32 / BECH32M (Native Segwit 'bc1...') ---
    else if addr.starts_with("bc1") {
        // Decode bech32 address
        if let Ok((_hrp, data, _variant)) = bech32::decode(addr) {
            // Convert from base32 (5-bit) to base256 (8-bit)
            // This properly handles the witness version and program
            let mut bytes = Vec::new();
            let mut buffer = 0u32;
            let mut bits = 0;
            
            for value in data {
                buffer = (buffer << 5) | (value.to_u8() as u32);
                bits += 5;
                
                if bits >= 8 {
                    bits -= 8;
                    bytes.push((buffer >> bits) as u8);
                    buffer &= (1 << bits) - 1;
                }
            }
            
            // Witness program should be: [version byte] + [20 or 32 bytes hash]
            // P2WPKH: version 0 + 20 bytes
            // P2WSH: version 0 + 32 bytes
            // P2TR: version 1 + 32 bytes
            if bytes.len() == 21 || bytes.len() == 33 {
                // Return hash without version byte
                return Some(bytes[1..].to_vec());
            }
        }
    }

    // Không phải định dạng hợp lệ
    None
}

fn main() {
    let test_addresses = vec![
        "bc1qyu5v99d8urfxc3vk4ddrcr38yfuz9w8vxycdy6",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy",
    ];
    
    for addr in test_addresses {
        println!("\n=== Testing address: {} ===", addr);
        
        match decode_address(addr) {
            Some(hash) => {
                println!("✓ Decoded successfully!");
                println!("  Hash length: {} bytes", hash.len());
                println!("  Hash (hex): {}", hex::encode(&hash));
            }
            None => {
                println!("✗ Failed to decode");
            }
        }
    }
}
