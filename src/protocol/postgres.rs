use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use anyhow::Result;

#[derive(Debug, Clone)]
pub enum PgMessage {
    Startup(StartupMessage),
    Regular(RegularMessage),
    SSLRequest,
}

#[derive(Debug, Clone)]
pub struct StartupMessage {
    pub protocol_version: u32,
    pub parameters: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct RegularMessage {
    pub message_type: u8,
    pub payload: BytesMut,
}

pub struct PostgresCodec {
    // State to track if we are expecting a startup message (first message)
    // or regular messages.
    is_startup: bool,
}

impl PostgresCodec {
    pub fn new() -> Self {
        Self { is_startup: true }
    }

    pub fn new_upstream() -> Self {
        Self { is_startup: false }
    }
}

impl Decoder for PostgresCodec {
    type Item = PgMessage;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if src.len() < 4 {
            return Ok(None);
        }

        // Peek at the length
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[0..4]);
        let length = u32::from_be_bytes(length_bytes) as usize;

        if self.is_startup {
            // Startup packet: [Length (4 bytes)] [Protocol Version (4 bytes)] [Params...]
            // OR SSLRequest: [Length (4 bytes)] [1234 in high 16 bits] [5679 in low 16 bits]
            
            if src.len() < length {
                src.reserve(length - src.len());
                return Ok(None);
            }

            let mut data = src.split_to(length);
            data.advance(4); // Skip length

            let protocol_version = data.get_u32();

            if protocol_version == 80877103 {
                // SSL Request (1234.5679)
                // Do NOT set is_startup = false, because the next message will be the actual StartupMessage
                // (or another SSLRequest if we denied it and they try again, though unlikely)
                return Ok(Some(PgMessage::SSLRequest));
            }

            // Parse Startup Message
            let mut parameters = Vec::new();
            while data.has_remaining() {
                // Read null-terminated strings
                let key = read_cstring(&mut data)?;
                if key.is_empty() { break; }
                let value = read_cstring(&mut data)?;
                parameters.push((key, value));
            }

            self.is_startup = false; // Next messages will be regular
            return Ok(Some(PgMessage::Startup(StartupMessage {
                protocol_version,
                parameters,
            })));

        } else {
            // Regular packet: [Type (1 byte)] [Length (4 bytes)] [Payload...]
            // Note: The length includes the 4 bytes of the length field itself, but NOT the type byte.
            
            if src.len() < 1 {
                return Ok(None);
            }
            
            let message_type = src[0];
            
            if src.len() < 5 {
                return Ok(None);
            }

            let mut length_bytes = [0u8; 4];
            length_bytes.copy_from_slice(&src[1..5]);
            let length = u32::from_be_bytes(length_bytes) as usize;

            // Total frame size = 1 (type) + length
            let frame_len = 1 + length;

            if src.len() < frame_len {
                src.reserve(frame_len - src.len());
                return Ok(None);
            }

            let mut data = src.split_to(frame_len);
            data.advance(5); // Skip Type (1) + Length (4)

            Ok(Some(PgMessage::Regular(RegularMessage {
                message_type,
                payload: data,
            })))
        }
    }
}

impl Encoder<PgMessage> for PostgresCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: PgMessage, dst: &mut BytesMut) -> Result<()> {
        match item {
            PgMessage::Startup(msg) => {
                // Calculate length
                let mut params_len = 0;
                for (k, v) in &msg.parameters {
                    params_len += k.len() + 1 + v.len() + 1;
                }
                params_len += 1; // Final null byte

                let total_len = 4 + 4 + params_len; // Length + ProtoVer + Params

                dst.put_u32(total_len as u32);
                dst.put_u32(msg.protocol_version);
                for (k, v) in &msg.parameters {
                    dst.put_slice(k.as_bytes());
                    dst.put_u8(0);
                    dst.put_slice(v.as_bytes());
                    dst.put_u8(0);
                }
                dst.put_u8(0);
            }
            PgMessage::SSLRequest => {
                dst.put_u32(8);
                dst.put_u32(80877103);
            }
            PgMessage::Regular(msg) => {
                dst.put_u8(msg.message_type);
                dst.put_u32((msg.payload.len() + 4) as u32);
                dst.put_slice(&msg.payload);
            }
        }
        Ok(())
    }
}

fn read_cstring(buf: &mut BytesMut) -> Result<String> {
    let mut bytes = Vec::new();
    while buf.has_remaining() {
        let b = buf.get_u8();
        if b == 0 {
            break;
        }
        bytes.push(b);
    }
    Ok(String::from_utf8(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_decode_startup_message() {
        let mut codec = PostgresCodec::new();
        let mut buf = BytesMut::new();

        // Construct a fake startup message
        // Length (4) + Proto (4) + "user\0postgres\0\0"
        let params = b"user\0postgres\0\0";
        let len = 4 + 4 + params.len() as u32;
        
        buf.put_u32(len);
        buf.put_u32(196608); // Proto ver 3.0
        buf.put_slice(params);

        let result = codec.decode(&mut buf).unwrap().unwrap();

        if let PgMessage::Startup(msg) = result {
            assert_eq!(msg.protocol_version, 196608);
            assert_eq!(msg.parameters[0], ("user".to_string(), "postgres".to_string()));
        } else {
            panic!("Expected Startup message");
        }
    }

    #[test]
    fn test_decode_regular_message() {
        let mut codec = PostgresCodec::new();
        codec.is_startup = false; // Simulate handshake done

        let mut buf = BytesMut::new();
        
        // 'Q' (Query) message
        // Type (1) + Length (4) + "SELECT 1\0"
        let query = b"SELECT 1\0";
        let len = 4 + query.len() as u32;

        buf.put_u8(b'Q');
        buf.put_u32(len);
        buf.put_slice(query);

        let result = codec.decode(&mut buf).unwrap().unwrap();

        if let PgMessage::Regular(msg) = result {
            assert_eq!(msg.message_type, b'Q');
            assert_eq!(msg.payload, BytesMut::from(&query[..]));
        } else {
            panic!("Expected Regular message");
        }
    }
}
