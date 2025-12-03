//! MySQL Wire Protocol implementation.
//!
//! This module implements the MySQL client/server protocol for proxying MySQL connections.
//! Reference: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basics.html

use anyhow::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// MySQL packet types and messages
#[derive(Debug, Clone)]
pub enum MySqlMessage {
    /// Initial handshake from server
    Handshake(HandshakeV10),
    /// Client response to handshake
    HandshakeResponse(HandshakeResponse),
    /// Generic packet (passthrough)
    Generic(GenericPacket),
    /// COM_QUERY command
    Query(QueryPacket),
    /// Column definition (in result set)
    ColumnDefinition(ColumnDefinition),
    /// Result set row (text protocol)
    ResultRow(ResultRow),
    /// OK packet
    Ok(OkPacket),
    /// ERR packet
    Err(ErrPacket),
    /// EOF packet (deprecated in 4.1+ but still used)
    Eof(EofPacket),
}

/// MySQL Handshake V10 packet (server -> client)
#[derive(Debug, Clone)]
pub struct HandshakeV10 {
    pub protocol_version: u8,
    pub server_version: String,
    pub connection_id: u32,
    pub auth_plugin_data_part1: [u8; 8],
    pub capability_flags: u32,
    pub character_set: u8,
    pub status_flags: u16,
    pub auth_plugin_data_part2: Vec<u8>,
    pub auth_plugin_name: String,
}

/// Client handshake response
#[derive(Debug, Clone)]
pub struct HandshakeResponse {
    pub capability_flags: u32,
    pub max_packet_size: u32,
    pub character_set: u8,
    pub username: String,
    pub auth_response: Vec<u8>,
    pub database: Option<String>,
    pub auth_plugin_name: Option<String>,
}

/// Generic packet for passthrough
#[derive(Debug, Clone)]
pub struct GenericPacket {
    pub sequence_id: u8,
    pub payload: BytesMut,
}

/// COM_QUERY packet
#[derive(Debug, Clone)]
pub struct QueryPacket {
    pub sequence_id: u8,
    pub query: Bytes,
}

/// Column definition packet (part of result set)
#[derive(Debug, Clone)]
pub struct ColumnDefinition {
    pub sequence_id: u8,
    pub catalog: Bytes,
    pub schema: Bytes,
    pub table: Bytes,
    pub org_table: Bytes,
    pub name: Bytes,
    pub org_name: Bytes,
    pub character_set: u16,
    pub column_length: u32,
    pub column_type: u8,
    pub flags: u16,
    pub decimals: u8,
}

/// Result row packet (text protocol)
#[derive(Debug, Clone)]
pub struct ResultRow {
    pub sequence_id: u8,
    pub values: Vec<Option<BytesMut>>,
}

/// OK packet
#[derive(Debug, Clone)]
pub struct OkPacket {
    pub sequence_id: u8,
    pub affected_rows: u64,
    pub last_insert_id: u64,
    pub status_flags: u16,
    pub warnings: u16,
    pub info: Bytes,
}

/// ERR packet
#[derive(Debug, Clone)]
pub struct ErrPacket {
    pub sequence_id: u8,
    pub error_code: u16,
    pub sql_state: [u8; 5],
    pub error_message: String,
}

/// EOF packet
#[derive(Debug, Clone)]
pub struct EofPacket {
    pub sequence_id: u8,
    pub warnings: u16,
    pub status_flags: u16,
}

// Capability flags
#[allow(dead_code)]
pub const CLIENT_LONG_PASSWORD: u32 = 1;
pub const CLIENT_PROTOCOL_41: u32 = 1 << 9;
pub const CLIENT_SECURE_CONNECTION: u32 = 1 << 15;
pub const CLIENT_PLUGIN_AUTH: u32 = 1 << 19;
pub const CLIENT_DEPRECATE_EOF: u32 = 1 << 24;

/// State machine for MySQL codec
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MySqlState {
    /// Waiting for server handshake
    WaitingHandshake,
    /// Waiting for client handshake response
    WaitingHandshakeResponse,
    /// Normal command phase
    Command,
    /// Reading column definitions in result set
    ReadingColumns { remaining: usize },
    /// Reading rows in result set
    ReadingRows,
}

/// MySQL codec for framing and parsing packets
pub struct MySqlCodec {
    state: MySqlState,
    capability_flags: u32,
    is_client_side: bool,
    column_count: usize,
}

impl MySqlCodec {
    /// Create codec for client-facing connection (proxy as server)
    pub fn new_server() -> Self {
        Self {
            state: MySqlState::WaitingHandshake,
            capability_flags: 0,
            is_client_side: false,
            column_count: 0,
        }
    }

    /// Create codec for upstream connection (proxy as client)
    pub fn new_client() -> Self {
        Self {
            state: MySqlState::WaitingHandshake,
            capability_flags: 0,
            is_client_side: true,
            column_count: 0,
        }
    }

    /// Update capability flags after handshake
    pub fn set_capability_flags(&mut self, flags: u32) {
        self.capability_flags = flags;
    }

    fn uses_deprecate_eof(&self) -> bool {
        self.capability_flags & CLIENT_DEPRECATE_EOF != 0
    }
}

impl Decoder for MySqlCodec {
    type Item = MySqlMessage;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        // MySQL packet header: 3 bytes length + 1 byte sequence id
        if src.len() < 4 {
            return Ok(None);
        }

        // Read packet length (little-endian 3 bytes)
        let payload_len = (src[0] as usize) | ((src[1] as usize) << 8) | ((src[2] as usize) << 16);
        let sequence_id = src[3];

        let total_len = 4 + payload_len;
        if src.len() < total_len {
            src.reserve(total_len - src.len());
            return Ok(None);
        }

        let mut packet = src.split_to(total_len);
        packet.advance(4); // Skip header

        // Dispatch based on state and packet type
        match self.state {
            MySqlState::WaitingHandshake => {
                if self.is_client_side {
                    // We're the client, expecting server handshake
                    let handshake = parse_handshake_v10(&mut packet)?;
                    self.state = MySqlState::WaitingHandshakeResponse;
                    Ok(Some(MySqlMessage::Handshake(handshake)))
                } else {
                    // We're the server, this shouldn't happen
                    Ok(Some(MySqlMessage::Generic(GenericPacket {
                        sequence_id,
                        payload: packet,
                    })))
                }
            }
            MySqlState::WaitingHandshakeResponse => {
                if !self.is_client_side {
                    // We're the server, expecting client response
                    let response = parse_handshake_response(&mut packet, self.capability_flags)?;
                    self.capability_flags = response.capability_flags;
                    self.state = MySqlState::Command;
                    Ok(Some(MySqlMessage::HandshakeResponse(response)))
                } else {
                    // We're the client, expecting OK/ERR after sending our response
                    let first_byte = packet[0];
                    match first_byte {
                        0x00 => {
                            let ok = parse_ok_packet(&mut packet, sequence_id, self.capability_flags)?;
                            self.state = MySqlState::Command;
                            Ok(Some(MySqlMessage::Ok(ok)))
                        }
                        0xff => {
                            let err = parse_err_packet(&mut packet, sequence_id, self.capability_flags)?;
                            Ok(Some(MySqlMessage::Err(err)))
                        }
                        _ => {
                            self.state = MySqlState::Command;
                            Ok(Some(MySqlMessage::Generic(GenericPacket {
                                sequence_id,
                                payload: packet,
                            })))
                        }
                    }
                }
            }
            MySqlState::Command => {
                if packet.is_empty() {
                    return Ok(Some(MySqlMessage::Generic(GenericPacket {
                        sequence_id,
                        payload: packet,
                    })));
                }

                let first_byte = packet[0];

                // Check for COM_QUERY from client
                if !self.is_client_side && first_byte == 0x03 {
                    packet.advance(1);
                    let query = packet.freeze();
                    return Ok(Some(MySqlMessage::Query(QueryPacket {
                        sequence_id,
                        query,
                    })));
                }

                // Check for result set header (column count) from server
                if self.is_client_side && first_byte != 0x00 && first_byte != 0xff && first_byte != 0xfe {
                    // Could be column count (length-encoded int)
                    let (col_count, _) = read_lenenc_int(&packet)?;
                    if col_count > 0 && col_count < 1000 {
                        self.column_count = col_count as usize;
                        self.state = MySqlState::ReadingColumns {
                            remaining: col_count as usize,
                        };
                        return Ok(Some(MySqlMessage::Generic(GenericPacket {
                            sequence_id,
                            payload: packet,
                        })));
                    }
                }

                // OK packet
                if first_byte == 0x00 {
                    let ok = parse_ok_packet(&mut packet, sequence_id, self.capability_flags)?;
                    return Ok(Some(MySqlMessage::Ok(ok)));
                }

                // ERR packet
                if first_byte == 0xff {
                    let err = parse_err_packet(&mut packet, sequence_id, self.capability_flags)?;
                    return Ok(Some(MySqlMessage::Err(err)));
                }

                // EOF packet (0xfe with payload < 9 bytes)
                if first_byte == 0xfe && packet.len() < 9 {
                    let eof = parse_eof_packet(&mut packet, sequence_id)?;
                    return Ok(Some(MySqlMessage::Eof(eof)));
                }

                Ok(Some(MySqlMessage::Generic(GenericPacket {
                    sequence_id,
                    payload: packet,
                })))
            }
            MySqlState::ReadingColumns { remaining } => {
                let first_byte = packet[0];

                // EOF packet marks end of column definitions
                if first_byte == 0xfe && packet.len() < 9 && !self.uses_deprecate_eof() {
                    let eof = parse_eof_packet(&mut packet, sequence_id)?;
                    self.state = MySqlState::ReadingRows;
                    return Ok(Some(MySqlMessage::Eof(eof)));
                }

                // Parse column definition
                let col_def = parse_column_definition(&mut packet, sequence_id)?;
                let new_remaining = remaining.saturating_sub(1);

                if new_remaining == 0 {
                    if self.uses_deprecate_eof() {
                        // No EOF packet, go straight to rows
                        self.state = MySqlState::ReadingRows;
                    }
                    // Otherwise wait for EOF packet
                } else {
                    self.state = MySqlState::ReadingColumns {
                        remaining: new_remaining,
                    };
                }

                Ok(Some(MySqlMessage::ColumnDefinition(col_def)))
            }
            MySqlState::ReadingRows => {
                let first_byte = packet[0];

                // EOF packet marks end of rows
                if first_byte == 0xfe && packet.len() < 9 {
                    let eof = parse_eof_packet(&mut packet, sequence_id)?;
                    self.state = MySqlState::Command;
                    return Ok(Some(MySqlMessage::Eof(eof)));
                }

                // OK packet (with CLIENT_DEPRECATE_EOF)
                if first_byte == 0x00 && self.uses_deprecate_eof() {
                    let ok = parse_ok_packet(&mut packet, sequence_id, self.capability_flags)?;
                    self.state = MySqlState::Command;
                    return Ok(Some(MySqlMessage::Ok(ok)));
                }

                // ERR packet
                if first_byte == 0xff {
                    let err = parse_err_packet(&mut packet, sequence_id, self.capability_flags)?;
                    self.state = MySqlState::Command;
                    return Ok(Some(MySqlMessage::Err(err)));
                }

                // Parse result row
                let row = parse_result_row(&mut packet, sequence_id, self.column_count)?;
                Ok(Some(MySqlMessage::ResultRow(row)))
            }
        }
    }
}

impl Encoder<MySqlMessage> for MySqlCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: MySqlMessage, dst: &mut BytesMut) -> Result<()> {
        match item {
            MySqlMessage::Handshake(h) => encode_handshake_v10(&h, dst),
            MySqlMessage::HandshakeResponse(r) => encode_handshake_response(&r, dst),
            MySqlMessage::Generic(g) => encode_generic(&g, dst),
            MySqlMessage::Query(q) => encode_query(&q, dst),
            MySqlMessage::ColumnDefinition(c) => encode_column_definition(&c, dst),
            MySqlMessage::ResultRow(r) => encode_result_row(&r, dst),
            MySqlMessage::Ok(o) => encode_ok(&o, dst, self.capability_flags),
            MySqlMessage::Err(e) => encode_err(&e, dst, self.capability_flags),
            MySqlMessage::Eof(e) => encode_eof(&e, dst),
        }
        Ok(())
    }
}

// ============================================================================
// Parsing helpers
// ============================================================================

fn read_lenenc_int(buf: &[u8]) -> Result<(u64, usize)> {
    if buf.is_empty() {
        anyhow::bail!("Empty buffer for lenenc int");
    }

    let first = buf[0];
    match first {
        0..=0xfa => Ok((first as u64, 1)),
        0xfc => {
            if buf.len() < 3 {
                anyhow::bail!("Not enough bytes for 2-byte lenenc int");
            }
            Ok(((buf[1] as u64) | ((buf[2] as u64) << 8), 3))
        }
        0xfd => {
            if buf.len() < 4 {
                anyhow::bail!("Not enough bytes for 3-byte lenenc int");
            }
            Ok((
                (buf[1] as u64) | ((buf[2] as u64) << 8) | ((buf[3] as u64) << 16),
                4,
            ))
        }
        0xfe => {
            if buf.len() < 9 {
                anyhow::bail!("Not enough bytes for 8-byte lenenc int");
            }
            let val = (buf[1] as u64)
                | ((buf[2] as u64) << 8)
                | ((buf[3] as u64) << 16)
                | ((buf[4] as u64) << 24)
                | ((buf[5] as u64) << 32)
                | ((buf[6] as u64) << 40)
                | ((buf[7] as u64) << 48)
                | ((buf[8] as u64) << 56);
            Ok((val, 9))
        }
        0xfb => Ok((0, 1)), // NULL in row data
        0xff => anyhow::bail!("Invalid lenenc int marker 0xff"),
    }
}

fn read_lenenc_int_from_buf(buf: &mut BytesMut) -> Result<u64> {
    let (val, consumed) = read_lenenc_int(buf)?;
    buf.advance(consumed);
    Ok(val)
}

fn read_lenenc_string(buf: &mut BytesMut) -> Result<Bytes> {
    let len = read_lenenc_int_from_buf(buf)? as usize;
    if buf.len() < len {
        anyhow::bail!("Not enough bytes for lenenc string");
    }
    Ok(buf.split_to(len).freeze())
}

fn read_null_terminated_string(buf: &mut BytesMut) -> Result<String> {
    let pos = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| anyhow::anyhow!("Missing null terminator"))?;
    let s = String::from_utf8(buf.split_to(pos).to_vec())?;
    buf.advance(1); // Skip null
    Ok(s)
}

fn parse_handshake_v10(buf: &mut BytesMut) -> Result<HandshakeV10> {
    let protocol_version = buf.get_u8();
    let server_version = read_null_terminated_string(buf)?;
    let connection_id = buf.get_u32_le();

    let mut auth_plugin_data_part1 = [0u8; 8];
    buf.copy_to_slice(&mut auth_plugin_data_part1);
    buf.advance(1); // filler

    let capability_flags_lower = buf.get_u16_le() as u32;
    let character_set = buf.get_u8();
    let status_flags = buf.get_u16_le();
    let capability_flags_upper = buf.get_u16_le() as u32;
    let capability_flags = capability_flags_lower | (capability_flags_upper << 16);

    let auth_plugin_data_len = buf.get_u8();
    buf.advance(10); // reserved

    // auth-plugin-data-part-2: max(13, auth_plugin_data_len - 8)
    let part2_len = if capability_flags & CLIENT_SECURE_CONNECTION != 0 {
        std::cmp::max(13, auth_plugin_data_len.saturating_sub(8)) as usize
    } else {
        0
    };
    let auth_plugin_data_part2 = if part2_len > 0 && buf.len() >= part2_len {
        let data = buf.split_to(part2_len).to_vec();
        // Remove trailing null if present
        data.into_iter().take_while(|&b| b != 0).collect()
    } else {
        vec![]
    };

    let auth_plugin_name = if capability_flags & CLIENT_PLUGIN_AUTH != 0 && buf.has_remaining() {
        read_null_terminated_string(buf).unwrap_or_default()
    } else {
        String::new()
    };

    Ok(HandshakeV10 {
        protocol_version,
        server_version,
        connection_id,
        auth_plugin_data_part1,
        capability_flags,
        character_set,
        status_flags,
        auth_plugin_data_part2,
        auth_plugin_name,
    })
}

fn parse_handshake_response(buf: &mut BytesMut, _server_caps: u32) -> Result<HandshakeResponse> {
    let capability_flags = buf.get_u32_le();
    let max_packet_size = buf.get_u32_le();
    let character_set = buf.get_u8();
    buf.advance(23); // reserved

    let username = read_null_terminated_string(buf)?;

    let auth_response = if capability_flags & CLIENT_SECURE_CONNECTION != 0 {
        let len = buf.get_u8() as usize;
        buf.split_to(len).to_vec()
    } else {
        let pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let data = buf.split_to(pos).to_vec();
        if buf.has_remaining() {
            buf.advance(1);
        }
        data
    };

    let database = if buf.has_remaining() {
        Some(read_null_terminated_string(buf).ok().unwrap_or_default())
    } else {
        None
    };

    let auth_plugin_name = if capability_flags & CLIENT_PLUGIN_AUTH != 0 && buf.has_remaining() {
        Some(read_null_terminated_string(buf).ok().unwrap_or_default())
    } else {
        None
    };

    Ok(HandshakeResponse {
        capability_flags,
        max_packet_size,
        character_set,
        username,
        auth_response,
        database,
        auth_plugin_name,
    })
}

fn parse_ok_packet(buf: &mut BytesMut, sequence_id: u8, capability_flags: u32) -> Result<OkPacket> {
    buf.advance(1); // header 0x00
    let affected_rows = read_lenenc_int_from_buf(buf)?;
    let last_insert_id = read_lenenc_int_from_buf(buf)?;

    let (status_flags, warnings) = if capability_flags & CLIENT_PROTOCOL_41 != 0 {
        (buf.get_u16_le(), buf.get_u16_le())
    } else {
        (0, 0)
    };

    let info = buf.split().freeze();

    Ok(OkPacket {
        sequence_id,
        affected_rows,
        last_insert_id,
        status_flags,
        warnings,
        info,
    })
}

fn parse_err_packet(buf: &mut BytesMut, sequence_id: u8, capability_flags: u32) -> Result<ErrPacket> {
    buf.advance(1); // header 0xff
    let error_code = buf.get_u16_le();

    let sql_state = if capability_flags & CLIENT_PROTOCOL_41 != 0 {
        buf.advance(1); // '#' marker
        let mut state = [0u8; 5];
        buf.copy_to_slice(&mut state);
        state
    } else {
        [0u8; 5]
    };

    let error_message = String::from_utf8_lossy(&buf.split()).to_string();

    Ok(ErrPacket {
        sequence_id,
        error_code,
        sql_state,
        error_message,
    })
}

fn parse_eof_packet(buf: &mut BytesMut, sequence_id: u8) -> Result<EofPacket> {
    buf.advance(1); // header 0xfe
    let warnings = if buf.len() >= 2 { buf.get_u16_le() } else { 0 };
    let status_flags = if buf.len() >= 2 { buf.get_u16_le() } else { 0 };

    Ok(EofPacket {
        sequence_id,
        warnings,
        status_flags,
    })
}

fn parse_column_definition(buf: &mut BytesMut, sequence_id: u8) -> Result<ColumnDefinition> {
    let catalog = read_lenenc_string(buf)?;
    let schema = read_lenenc_string(buf)?;
    let table = read_lenenc_string(buf)?;
    let org_table = read_lenenc_string(buf)?;
    let name = read_lenenc_string(buf)?;
    let org_name = read_lenenc_string(buf)?;
    buf.advance(1); // length of fixed fields [0c]
    let character_set = buf.get_u16_le();
    let column_length = buf.get_u32_le();
    let column_type = buf.get_u8();
    let flags = buf.get_u16_le();
    let decimals = buf.get_u8();
    buf.advance(2); // filler

    Ok(ColumnDefinition {
        sequence_id,
        catalog,
        schema,
        table,
        org_table,
        name,
        org_name,
        character_set,
        column_length,
        column_type,
        flags,
        decimals,
    })
}

fn parse_result_row(buf: &mut BytesMut, sequence_id: u8, column_count: usize) -> Result<ResultRow> {
    let mut values = Vec::with_capacity(column_count);

    for _ in 0..column_count {
        if buf.is_empty() {
            values.push(None);
            continue;
        }

        if buf[0] == 0xfb {
            // NULL value
            buf.advance(1);
            values.push(None);
        } else {
            let len = read_lenenc_int_from_buf(buf)? as usize;
            if buf.len() >= len {
                values.push(Some(buf.split_to(len)));
            } else {
                values.push(None);
            }
        }
    }

    Ok(ResultRow { sequence_id, values })
}

// ============================================================================
// Encoding helpers
// ============================================================================

fn write_packet_header(dst: &mut BytesMut, payload_len: usize, sequence_id: u8) {
    dst.put_u8((payload_len & 0xff) as u8);
    dst.put_u8(((payload_len >> 8) & 0xff) as u8);
    dst.put_u8(((payload_len >> 16) & 0xff) as u8);
    dst.put_u8(sequence_id);
}

fn write_lenenc_int(dst: &mut BytesMut, val: u64) {
    if val < 251 {
        dst.put_u8(val as u8);
    } else if val < 65536 {
        dst.put_u8(0xfc);
        dst.put_u16_le(val as u16);
    } else if val < 16777216 {
        dst.put_u8(0xfd);
        dst.put_u8((val & 0xff) as u8);
        dst.put_u8(((val >> 8) & 0xff) as u8);
        dst.put_u8(((val >> 16) & 0xff) as u8);
    } else {
        dst.put_u8(0xfe);
        dst.put_u64_le(val);
    }
}

fn write_lenenc_string(dst: &mut BytesMut, s: &[u8]) {
    write_lenenc_int(dst, s.len() as u64);
    dst.put_slice(s);
}

fn encode_handshake_v10(h: &HandshakeV10, dst: &mut BytesMut) {
    let mut payload = BytesMut::new();
    payload.put_u8(h.protocol_version);
    payload.put_slice(h.server_version.as_bytes());
    payload.put_u8(0);
    payload.put_u32_le(h.connection_id);
    payload.put_slice(&h.auth_plugin_data_part1);
    payload.put_u8(0); // filler
    payload.put_u16_le((h.capability_flags & 0xffff) as u16);
    payload.put_u8(h.character_set);
    payload.put_u16_le(h.status_flags);
    payload.put_u16_le(((h.capability_flags >> 16) & 0xffff) as u16);
    payload.put_u8((h.auth_plugin_data_part2.len() + 8 + 1) as u8);
    payload.put_slice(&[0u8; 10]); // reserved
    payload.put_slice(&h.auth_plugin_data_part2);
    payload.put_u8(0);
    if !h.auth_plugin_name.is_empty() {
        payload.put_slice(h.auth_plugin_name.as_bytes());
        payload.put_u8(0);
    }

    write_packet_header(dst, payload.len(), 0);
    dst.put_slice(&payload);
}

fn encode_handshake_response(r: &HandshakeResponse, dst: &mut BytesMut) {
    let mut payload = BytesMut::new();
    payload.put_u32_le(r.capability_flags);
    payload.put_u32_le(r.max_packet_size);
    payload.put_u8(r.character_set);
    payload.put_slice(&[0u8; 23]); // reserved
    payload.put_slice(r.username.as_bytes());
    payload.put_u8(0);

    if r.capability_flags & CLIENT_SECURE_CONNECTION != 0 {
        payload.put_u8(r.auth_response.len() as u8);
        payload.put_slice(&r.auth_response);
    } else {
        payload.put_slice(&r.auth_response);
        payload.put_u8(0);
    }

    if let Some(ref db) = r.database {
        payload.put_slice(db.as_bytes());
        payload.put_u8(0);
    }

    if let Some(ref plugin) = r.auth_plugin_name {
        payload.put_slice(plugin.as_bytes());
        payload.put_u8(0);
    }

    write_packet_header(dst, payload.len(), 1);
    dst.put_slice(&payload);
}

fn encode_generic(g: &GenericPacket, dst: &mut BytesMut) {
    write_packet_header(dst, g.payload.len(), g.sequence_id);
    dst.put_slice(&g.payload);
}

fn encode_query(q: &QueryPacket, dst: &mut BytesMut) {
    let payload_len = 1 + q.query.len();
    write_packet_header(dst, payload_len, q.sequence_id);
    dst.put_u8(0x03); // COM_QUERY
    dst.put_slice(&q.query);
}

fn encode_column_definition(c: &ColumnDefinition, dst: &mut BytesMut) {
    let mut payload = BytesMut::new();
    write_lenenc_string(&mut payload, &c.catalog);
    write_lenenc_string(&mut payload, &c.schema);
    write_lenenc_string(&mut payload, &c.table);
    write_lenenc_string(&mut payload, &c.org_table);
    write_lenenc_string(&mut payload, &c.name);
    write_lenenc_string(&mut payload, &c.org_name);
    payload.put_u8(0x0c); // length of fixed fields
    payload.put_u16_le(c.character_set);
    payload.put_u32_le(c.column_length);
    payload.put_u8(c.column_type);
    payload.put_u16_le(c.flags);
    payload.put_u8(c.decimals);
    payload.put_u16(0); // filler

    write_packet_header(dst, payload.len(), c.sequence_id);
    dst.put_slice(&payload);
}

fn encode_result_row(r: &ResultRow, dst: &mut BytesMut) {
    let mut payload = BytesMut::new();
    for val in &r.values {
        match val {
            Some(v) => write_lenenc_string(&mut payload, v),
            None => payload.put_u8(0xfb), // NULL
        }
    }

    write_packet_header(dst, payload.len(), r.sequence_id);
    dst.put_slice(&payload);
}

fn encode_ok(o: &OkPacket, dst: &mut BytesMut, capability_flags: u32) {
    let mut payload = BytesMut::new();
    payload.put_u8(0x00);
    write_lenenc_int(&mut payload, o.affected_rows);
    write_lenenc_int(&mut payload, o.last_insert_id);

    if capability_flags & CLIENT_PROTOCOL_41 != 0 {
        payload.put_u16_le(o.status_flags);
        payload.put_u16_le(o.warnings);
    }

    payload.put_slice(&o.info);

    write_packet_header(dst, payload.len(), o.sequence_id);
    dst.put_slice(&payload);
}

fn encode_err(e: &ErrPacket, dst: &mut BytesMut, capability_flags: u32) {
    let mut payload = BytesMut::new();
    payload.put_u8(0xff);
    payload.put_u16_le(e.error_code);

    if capability_flags & CLIENT_PROTOCOL_41 != 0 {
        payload.put_u8(b'#');
        payload.put_slice(&e.sql_state);
    }

    payload.put_slice(e.error_message.as_bytes());

    write_packet_header(dst, payload.len(), e.sequence_id);
    dst.put_slice(&payload);
}

fn encode_eof(e: &EofPacket, dst: &mut BytesMut) {
    let mut payload = BytesMut::new();
    payload.put_u8(0xfe);
    payload.put_u16_le(e.warnings);
    payload.put_u16_le(e.status_flags);

    write_packet_header(dst, payload.len(), e.sequence_id);
    dst.put_slice(&payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_lenenc_int_1byte() {
        let buf = [0x0a];
        let (val, consumed) = read_lenenc_int(&buf).unwrap();
        assert_eq!(val, 10);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_read_lenenc_int_2byte() {
        let buf = [0xfc, 0x01, 0x02];
        let (val, consumed) = read_lenenc_int(&buf).unwrap();
        assert_eq!(val, 0x0201);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn test_read_lenenc_int_3byte() {
        let buf = [0xfd, 0x01, 0x02, 0x03];
        let (val, consumed) = read_lenenc_int(&buf).unwrap();
        assert_eq!(val, 0x030201);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_packet_header_roundtrip() {
        let mut buf = BytesMut::new();
        write_packet_header(&mut buf, 1000, 5);

        assert_eq!(buf.len(), 4);
        let len = (buf[0] as usize) | ((buf[1] as usize) << 8) | ((buf[2] as usize) << 16);
        assert_eq!(len, 1000);
        assert_eq!(buf[3], 5);
    }

    #[test]
    fn test_lenenc_int_roundtrip() {
        for val in [0u64, 100, 300, 70000, 20000000] {
            let mut buf = BytesMut::new();
            write_lenenc_int(&mut buf, val);

            let (decoded, _) = read_lenenc_int(&buf).unwrap();
            assert_eq!(decoded, val);
        }
    }
}
