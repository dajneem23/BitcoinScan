use sha2::{Digest, Sha256};
use bech32::{FromBase32, ToBase32};


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
        
        // bech32::decode trả về: (HumanReadablePart, Data 5-bit, Variant)
        if let Ok((_hrp, data_u5, _variant)) = bech32::decode(addr) {
            // ⚠️ QUAN TRỌNG: Dữ liệu trả về đang ở dạng 5-bit (u5).
            // Phải convert sang 8-bit (u8) chuẩn của máy tính.
            if let Ok(data_u8) = Vec::<u8>::from_base32(&data_u5) {
                // Cấu trúc Segwit decoded: [1 byte Witness Version] + [Program Hash]

                // Kiểm tra độ dài hợp lệ:
                // - P2WPKH (v0): 1 byte ver + 20 bytes hash = 21 bytes
                // - P2WSH (v0):  1 byte ver + 32 bytes hash = 33 bytes
                // - P2TR (v1):   1 byte ver + 32 bytes hash = 33 bytes
                if data_u8.len() >= 21 && data_u8.len() <= 33 {
                    // Bỏ byte đầu tiên (Witness Version 0x00 hoặc 0x01)
                    // Chỉ lấy phần Hash phía sau để lưu vào DB
                    return Some(data_u8[1..].to_vec());
                }
            }
        }
    }

    // Không phải định dạng hợp lệ
    None
}