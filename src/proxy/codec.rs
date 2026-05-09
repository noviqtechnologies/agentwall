//! Codec for streaming JSON-RPC over stdio (FR-302)

use bytes::{Buf, BytesMut};
use serde_json::Value;
use std::io;
use tokio_util::codec::{Decoder, Encoder};

pub struct JsonRpcCodec;

impl Decoder for JsonRpcCodec {
    type Item = Value;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        // Try to parse a JSON object from the buffer using StreamDeserializer
        let de = serde_json::Deserializer::from_slice(src);
        let mut stream = de.into_iter::<Value>();
        
        match stream.next() {
            Some(Ok(val)) => {
                let bytes_read = stream.byte_offset();
                src.advance(bytes_read);
                Ok(Some(val))
            }
            Some(Err(e)) if e.is_eof() => {
                // Not enough data yet
                Ok(None)
            }
            None => {
                // Not enough data yet (empty buffer)
                Ok(None)
            }
            Some(Err(e)) => {
                // Try to recover by finding next newline or bracket if parsing fails,
                // but for now, just return error to close the stream.
                // In MCP, messages are usually newline delimited or properly framed.
                // If it's just whitespace at the start, serde_json handles it.
                // However, trailing garbage or incomplete data might cause non-EOF errors.
                
                // Let's implement a simple newline fallback if we fail.
                // MCP stdio is typically newline delimited JSON (NDJSON).
                if let Some(i) = src.iter().position(|&b| b == b'\n') {
                    let line = src.split_to(i + 1);
                    // Try parsing the line
                    match serde_json::from_slice::<Value>(&line) {
                        Ok(v) => return Ok(Some(v)),
                        Err(_) => {
                            // If line fails, it might be partial garbage, just continue to next line
                            return Ok(None);
                        }
                    }
                }

                // If not EOF and no newline, we might be stuck. We'll return an error if it's completely invalid.
                Err(io::Error::new(io::ErrorKind::InvalidData, e))
            }
        }
    }
}

impl Encoder<Value> for JsonRpcCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Value, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = serde_json::to_vec(&item).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        dst.extend_from_slice(&bytes);
        dst.extend_from_slice(b"\n");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use serde_json::json;
    use tokio_util::codec::Decoder;

    #[test]
    fn test_json_rpc_codec_single_message() {
        let mut codec = JsonRpcCodec;
        let mut buf = BytesMut::from(r#"{"jsonrpc": "2.0", "method": "test", "id": 1}"#.as_bytes());
        
        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), json!({"jsonrpc": "2.0", "method": "test", "id": 1}));
        assert!(buf.is_empty());
    }

    #[test]
    fn test_json_rpc_codec_multiple_messages_no_newline() {
        let mut codec = JsonRpcCodec;
        let mut buf = BytesMut::from(r#"{"id":1}{"id":2}"#.as_bytes());
        
        let msg1 = codec.decode(&mut buf).unwrap();
        assert_eq!(msg1.unwrap(), json!({"id": 1}));
        
        let msg2 = codec.decode(&mut buf).unwrap();
        assert_eq!(msg2.unwrap(), json!({"id": 2}));
        
        assert!(buf.is_empty());
    }

    #[test]
    fn test_json_rpc_codec_partial_message() {
        let mut codec = JsonRpcCodec;
        let mut buf = BytesMut::from(r#"{"id":"#.as_bytes());
        
        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_none());
        assert_eq!(buf.len(), 6);
    }
}
