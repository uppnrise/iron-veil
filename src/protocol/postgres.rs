use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use anyhow::Result;

#[derive(Debug, Clone)]
pub enum PgMessage {
    Startup(StartupMessage),
    Regular(RegularMessage),
    RowDescription(RowDescription),
    DataRow(DataRow),
    Query(QueryMessage),
    Parse(ParseMessage),
    SSLRequest,
}

#[derive(Debug, Clone)]
pub struct StartupMessage {
    pub protocol_version: u32,
    pub parameters: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct QueryMessage {
    pub query: String,
}

#[derive(Debug, Clone)]
pub struct ParseMessage {
    pub statement: String,
    pub query: String,
    pub param_types: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct RegularMessage {
    pub message_type: u8,
    pub payload: BytesMut,
}

#[derive(Debug, Clone)]
pub struct RowDescription {
    pub fields: Vec<FieldDescription>,
}

#[derive(Debug, Clone)]
pub struct FieldDescription {
    pub name: String,
    pub table_oid: u32,
    pub column_index: u16,
    pub type_oid: u32,
    pub type_len: i16,
    pub type_modifier: i32,
    pub format_code: i16,
}

#[derive(Debug, Clone)]
pub struct DataRow {
    pub values: Vec<Option<BytesMut>>,
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
            Ok(Some(PgMessage::Startup(StartupMessage {
                protocol_version,
                parameters,
            })))

        } else {
            // Regular packet: [Type (1 byte)] [Length (4 bytes)] [Payload...]
            // Note: The length includes the 4 bytes of the length field itself, but NOT the type byte.
            
            if src.is_empty() {
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

            match message_type {
                b'T' => {
                    // RowDescription
                    let num_fields = data.get_u16();
                    let mut fields = Vec::with_capacity(num_fields as usize);
                    for _ in 0..num_fields {
                        let name = read_cstring(&mut data)?;
                        let table_oid = data.get_u32();
                        let column_index = data.get_u16();
                        let type_oid = data.get_u32();
                        let type_len = data.get_i16();
                        let type_modifier = data.get_i32();
                        let format_code = data.get_i16();
                        
                        fields.push(FieldDescription {
                            name,
                            table_oid,
                            column_index,
                            type_oid,
                            type_len,
                            type_modifier,
                            format_code,
                        });
                    }
                    Ok(Some(PgMessage::RowDescription(RowDescription { fields })))
                }
                b'D' => {
                    // DataRow
                    let num_cols = data.get_u16();
                    let mut values = Vec::with_capacity(num_cols as usize);
                    for _ in 0..num_cols {
                        let len = data.get_i32();
                        if len == -1 {
                            values.push(None);
                        } else {
                            let val = data.split_to(len as usize);
                            values.push(Some(val));
                        }
                    }
                    Ok(Some(PgMessage::DataRow(DataRow { values })))
                }
                b'Q' => {
                    let query = read_cstring(&mut data)?;
                    Ok(Some(PgMessage::Query(QueryMessage { query })))
                }
                b'P' => {
                    let statement = read_cstring(&mut data)?;
                    let query = read_cstring(&mut data)?;
                    let num_params = data.get_u16();
                    let mut param_types = Vec::with_capacity(num_params as usize);
                    for _ in 0..num_params {
                        param_types.push(data.get_u32());
                    }
                    Ok(Some(PgMessage::Parse(ParseMessage { statement, query, param_types })))
                }
                _ => {
                    Ok(Some(PgMessage::Regular(RegularMessage {
                        message_type,
                        payload: data,
                    })))
                }
            }
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
            PgMessage::RowDescription(msg) => {
                dst.put_u8(b'T');
                
                // Calculate length
                let mut len = 4 + 2; // Length + NumFields
                for field in &msg.fields {
                    len += field.name.len() + 1; // Name + Null
                    len += 4 + 2 + 4 + 2 + 4 + 2; // TableOID + ColIdx + TypeOID + TypeLen + TypeMod + Format
                }
                
                dst.put_u32(len as u32);
                dst.put_u16(msg.fields.len() as u16);
                
                for field in &msg.fields {
                    dst.put_slice(field.name.as_bytes());
                    dst.put_u8(0);
                    dst.put_u32(field.table_oid);
                    dst.put_u16(field.column_index);
                    dst.put_u32(field.type_oid);
                    dst.put_i16(field.type_len);
                    dst.put_i32(field.type_modifier);
                    dst.put_i16(field.format_code);
                }
            }
            PgMessage::DataRow(msg) => {
                dst.put_u8(b'D');
                
                // Calculate length
                let mut len = 4 + 2; // Length + NumCols
                for val in &msg.values {
                    len += 4; // ColLen
                    if let Some(v) = val {
                        len += v.len();
                    }
                }
                
                dst.put_u32(len as u32);
                dst.put_u16(msg.values.len() as u16);
                
                for val in &msg.values {
                    if let Some(v) = val {
                        dst.put_i32(v.len() as i32);
                        dst.put_slice(v);
                    } else {
                        dst.put_i32(-1);
                    }
                }
            }
            PgMessage::Query(msg) => {
                dst.put_u8(b'Q');
                let len = 4 + msg.query.len() + 1;
                dst.put_u32(len as u32);
                dst.put_slice(msg.query.as_bytes());
                dst.put_u8(0);
            }
            PgMessage::Parse(msg) => {
                dst.put_u8(b'P');
                let len = 4 + msg.statement.len() + 1 + msg.query.len() + 1 + 2 + (msg.param_types.len() * 4);
                dst.put_u32(len as u32);
                dst.put_slice(msg.statement.as_bytes());
                dst.put_u8(0);
                dst.put_slice(msg.query.as_bytes());
                dst.put_u8(0);
                dst.put_u16(msg.param_types.len() as u16);
                for param in &msg.param_types {
                    dst.put_u32(*param);
                }
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

    #[test]
    fn test_decode_row_description() {
        let mut codec = PostgresCodec::new();
        codec.is_startup = false;
        let mut buf = BytesMut::new();

        // 'T' (RowDescription)
        // Length (4) + NumFields (2) + Field1...
        // Field1: "email"\0 + TableOID(4) + ColIdx(2) + TypeOID(4) + TypeLen(2) + TypeMod(4) + Format(2)
        
        let name = b"email\0";
        let field_len = name.len() + 4 + 2 + 4 + 2 + 4 + 2;
        let total_len = 4 + 2 + field_len;

        buf.put_u8(b'T');
        buf.put_u32(total_len as u32);
        buf.put_u16(1); // 1 field

        buf.put_slice(name);
        buf.put_u32(100); // Table OID
        buf.put_u16(2);   // Col Index
        buf.put_u32(25);  // Type OID (TEXT)
        buf.put_i16(-1);  // Type Len
        buf.put_i32(-1);  // Type Mod
        buf.put_i16(0);   // Format (Text)

        let result = codec.decode(&mut buf).unwrap().unwrap();

        if let PgMessage::RowDescription(msg) = result {
            assert_eq!(msg.fields.len(), 1);
            assert_eq!(msg.fields[0].name, "email");
            assert_eq!(msg.fields[0].table_oid, 100);
        } else {
            panic!("Expected RowDescription");
        }
    }

    #[test]
    fn test_decode_data_row() {
        let mut codec = PostgresCodec::new();
        codec.is_startup = false;
        let mut buf = BytesMut::new();

        // 'D' (DataRow)
        // Length (4) + NumCols (2) + Col1...
        // Col1: Len(4) + "hello"
        
        let val = b"hello";
        let col_len = 4 + val.len();
        let total_len = 4 + 2 + col_len;

        buf.put_u8(b'D');
        buf.put_u32(total_len as u32);
        buf.put_u16(1); // 1 col

        buf.put_i32(val.len() as i32);
        buf.put_slice(val);

        let result = codec.decode(&mut buf).unwrap().unwrap();

        if let PgMessage::DataRow(msg) = result {
            assert_eq!(msg.values.len(), 1);
            assert_eq!(msg.values[0].as_ref().unwrap(), &BytesMut::from(&val[..]));
        } else {
            panic!("Expected DataRow");
        }
    }
}
