// ============================================================================
// Compression Module - Zstd compression for metrics payload
// ============================================================================

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedPayload {
    /// Original uncompressed size
    pub original_size: usize,

    /// Compressed size
    pub compressed_size: usize,

    /// Compression ratio
    pub compression_ratio: f64,

    /// Compressed data (base64 encoded for JSON transport)
    pub data: String,
}

/// Compress JSON data using Zstd
pub fn compress_json<T: Serialize>(data: &T, level: i32) -> Result<CompressedPayload> {
    // Serialize to JSON
    let json_bytes = serde_json::to_vec(data)?;
    let original_size = json_bytes.len();

    // Compress with Zstd
    let compressed = zstd::encode_all(&json_bytes[..], level)?;
    let compressed_size = compressed.len();

    // Calculate compression ratio
    let compression_ratio = (compressed_size as f64 / original_size as f64) * 100.0;

    // Hex encode for JSON transport
    let data = compressed.iter().map(|b| format!("{:02x}", b)).collect();

    Ok(CompressedPayload {
        original_size,
        compressed_size,
        compression_ratio,
        data,
    })
}

/// Decompress Zstd data back to JSON
pub fn decompress_json<T: for<'de> Deserialize<'de>>(
    payload: &CompressedPayload
) -> Result<T> {
    // Hex decode
    let compressed: Vec<u8> = (0..payload.data.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&payload.data[i..i+2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Hex decode error: {}", e))?;

    // Decompress
    let json_bytes = zstd::decode_all(&compressed[..])?;

    // Deserialize JSON
    let data = serde_json::from_slice(&json_bytes)?;

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_compression() {
        let data = json!({
            "test": "data",
            "numbers": vec![1, 2, 3, 4, 5],
        });

        let compressed = compress_json(&data, 3).unwrap();
        assert!(compressed.compressed_size < compressed.original_size);
        assert!(compressed.compression_ratio < 100.0);

        let decompressed: serde_json::Value = decompress_json(&compressed).unwrap();
        assert_eq!(data, decompressed);
    }
}
