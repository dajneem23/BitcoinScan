use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};
use bitcoin_scan::{decode_address, ReadableDatabase};
use serde::Deserialize;

use crate::AppState;

#[derive(Deserialize)]
pub struct TopAddressesQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}
#[derive(Deserialize)]
pub struct LastAddressesQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    10
}

pub async fn count_addresses(State(state): State<AppState>) -> impl IntoResponse {
    let count = state.db.count_keys().unwrap_or(0);
    Json(serde_json::json!({ "count": count }))
}

pub async fn top_addresses(
    State(state): State<AppState>,
    Query(params): Query<TopAddressesQuery>,
) -> impl IntoResponse {
    let addresses = state.db.first(params.limit).unwrap_or_default();
    let result: Vec<serde_json::Value> = addresses
        .into_iter()
        .map(|(k, _v)| {
            serde_json::json!({
                "hex": hex::encode(&k),     // Hiển thị dạng hex: "0000...01"
                // "bytes": k                  // Giữ dạng mảng số nếu cần
            })
        })
        .collect();
    Json(serde_json::json!({ "top_addresses": result }))
}

pub async fn last_addresses(
    State(state): State<AppState>,
    Query(params): Query<LastAddressesQuery>,
) -> impl IntoResponse {
    // Placeholder implementation
    let addresses = state.db.last(params.limit).unwrap_or_default();
    let result: Vec<serde_json::Value> = addresses
        .into_iter()
        .map(|(k, _v)| {
            serde_json::json!({
                "hex": hex::encode(&k),     // Hiển thị dạng hex: "0000...01"
                // "bytes": k                  // Giữ dạng mảng số nếu cần
            })
        })
        .collect();
    Json(serde_json::json!({ "last_addresses": result }))
}
pub async fn address_info(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    // Placeholder implementation

    if let Some(raw_bytes) = decode_address(address.as_str()) {
        // Check if key already exists
        if !state.db.exists(&raw_bytes).unwrap_or(false) {
            return Json(serde_json::json!({ "error": "Address not found" }));
        }
        let info: Option<Vec<u8>> = state.db.get(raw_bytes).unwrap_or(None);
        return Json(serde_json::json!({ "info": info }));
    } else {
        return Json(serde_json::json!({ "error": "Invalid address format" }));
    }
}
