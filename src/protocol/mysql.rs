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
    /// Payload exactly as received. The proxy only ever edits the two
    /// capability-flag byte pairs, which the encoder patches in place —
    /// rebuilding the whole packet from parsed fields silently drops anything
    /// the parser does not model.
    pub raw: Bytes,
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
    /// The packet exactly as the client sent it, including any trailing
    /// CLIENT_CONNECT_ATTRS block. The proxy does not modify the handshake response, so it is
    /// forwarded verbatim; re-encoding it from the parsed fields silently dropped connection
    /// attributes and the server rejected the result with ER_HANDSHAKE_ERROR (1043).
    pub raw: Bytes,
}

impl HandshakeResponse {
    /// True when this is an SSLRequest (the 32-byte prefix with CLIENT_SSL
    /// set): the client stops here and expects a TLS handshake next.
    pub fn is_ssl_request(&self) -> bool {
        self.raw.len() == 32 && self.capability_flags & CLIENT_SSL != 0
    }
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

/// Column definition packet (part of result set).
/// Parsed for rule matching only; always forwarded verbatim via `raw`.
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
    /// Payload exactly as received; the proxy never modifies it.
    pub raw: Bytes,
}

/// Result row packet (text protocol)
#[derive(Debug, Clone)]
pub struct ResultRow {
    pub sequence_id: u8,
    pub values: Vec<Option<BytesMut>>,
}

/// OK packet. Parsed for logging only; forwarded verbatim via `raw` when the
/// packet came off the wire.
#[derive(Debug, Clone)]
pub struct OkPacket {
    pub sequence_id: u8,
    pub affected_rows: u64,
    pub last_insert_id: u64,
    pub status_flags: u16,
    pub warnings: u16,
    pub info: Bytes,
    /// Payload exactly as received; empty when locally constructed.
    pub raw: Bytes,
}

/// ERR packet. Parsed for logging only; forwarded verbatim via `raw` when the
/// packet came off the wire.
#[derive(Debug, Clone)]
pub struct ErrPacket {
    pub sequence_id: u8,
    pub error_code: u16,
    pub sql_state: [u8; 5],
    pub error_message: String,
    /// Payload exactly as received; empty when locally constructed.
    pub raw: Bytes,
}

impl ErrPacket {
    /// Build a proxy-originated ERR packet (no raw bytes; encoded from fields).
    pub fn proxy_error(sequence_id: u8, error_code: u16, sql_state: &[u8; 5], msg: &str) -> Self {
        Self {
            sequence_id,
            error_code,
            sql_state: *sql_state,
            error_message: msg.to_string(),
            raw: Bytes::new(),
        }
    }
}

/// EOF packet. Parsed for logging only; forwarded verbatim via `raw`.
#[derive(Debug, Clone)]
pub struct EofPacket {
    pub sequence_id: u8,
    pub warnings: u16,
    pub status_flags: u16,
    /// Payload exactly as received; empty when locally constructed.
    pub raw: Bytes,
}

/// Build the 32-byte SSLRequest the proxy sends upstream before starting its
/// own TLS handshake (sequence id 1, immediately after the server handshake).
pub fn build_ssl_request(
    capability_flags: u32,
    max_packet_size: u32,
    character_set: u8,
) -> GenericPacket {
    let mut payload = BytesMut::with_capacity(32);
    payload.put_u32_le(capability_flags | CLIENT_SSL);
    payload.put_u32_le(max_packet_size);
    payload.put_u8(character_set);
    payload.put_slice(&[0u8; 23]);
    GenericPacket {
        sequence_id: 1,
        payload,
    }
}

// Capability flags
pub const CLIENT_SSL: u32 = 1 << 11;
pub const CLIENT_COMPRESS: u32 = 1 << 5;
pub const CLIENT_PROTOCOL_41: u32 = 1 << 9;
pub const CLIENT_CONNECT_WITH_DB: u32 = 1 << 3;
pub const CLIENT_SECURE_CONNECTION: u32 = 1 << 15;
pub const CLIENT_PLUGIN_AUTH: u32 = 1 << 19;
pub const CLIENT_CONNECT_ATTRS: u32 = 1 << 20;
pub const CLIENT_DEPRECATE_EOF: u32 = 1 << 24;

/// caching_sha2_password AuthMoreData status: fast path succeeded; server will
/// send OK next without a client reply.
pub const AUTH_MORE_DATA_FAST_AUTH_SUCCESS: u8 = 0x03;
/// caching_sha2_password AuthMoreData status: full authentication required;
/// client must send the password (or request the server public key).
pub const AUTH_MORE_DATA_FULL_AUTH_REQUIRED: u8 = 0x04;

/// Whether an intermediate auth-phase packet from the server expects a client
/// reply before the next server packet.
///
/// `caching_sha2_password` fast auth success is a single-byte AuthMoreData
/// (`0x01 0x03`) followed immediately by OK — the client does **not** reply.
/// Waiting for a client packet in that case hangs every successful MySQL 8
/// connection through the proxy once the server has the password cached.
pub fn auth_packet_expects_client_reply(payload: &[u8]) -> bool {
    match payload.first().copied() {
        // AuthMoreData (0x01). Only the fast-auth-success status skips a reply.
        Some(0x01) => payload.get(1).copied() != Some(AUTH_MORE_DATA_FAST_AUTH_SUCCESS),
        // AuthSwitchRequest (0xfe during auth) — client must choose plugin / send data.
        Some(0xfe) => true,
        // Unknown intermediate packet: wait for a client reply (fail closed on hang
        // risk rather than dropping a required password exchange).
        _ => true,
    }
}

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

/// Partially reassembled logical packet (payloads of exactly 0xFFFFFF bytes
/// continue in the following packet).
struct PendingLargePacket {
    sequence_id: u8,
    payload: BytesMut,
}

/// MySQL codec for framing and parsing packets
pub struct MySqlCodec {
    state: MySqlState,
    capability_flags: u32,
    is_client_side: bool,
    column_count: usize,
    pending_large: Option<PendingLargePacket>,
}

impl MySqlCodec {
    /// Create codec for client-facing connection (proxy as server)
    pub fn new_server() -> Self {
        Self {
            state: MySqlState::WaitingHandshake,
            capability_flags: 0,
            is_client_side: false,
            column_count: 0,
            pending_large: None,
        }
    }

    /// Create codec for upstream connection (proxy as client)
    pub fn new_client() -> Self {
        Self {
            state: MySqlState::WaitingHandshake,
            capability_flags: 0,
            is_client_side: true,
            column_count: 0,
            pending_large: None,
        }
    }

    /// Client-facing codec resuming after a TLS upgrade: the handshake was
    /// already sent in cleartext, so the next packet is the real response.
    pub fn new_server_awaiting_handshake_response(capability_flags: u32) -> Self {
        Self {
            state: MySqlState::WaitingHandshakeResponse,
            capability_flags,
            is_client_side: false,
            column_count: 0,
            pending_large: None,
        }
    }

    /// Client-facing codec already past authentication (used by tests and by
    /// callers that resume an established session).
    pub fn new_server_awaiting_command() -> Self {
        Self {
            state: MySqlState::Command,
            capability_flags: 0,
            is_client_side: false,
            column_count: 0,
            pending_large: None,
        }
    }

    /// Upstream-facing codec resuming after a TLS upgrade: the server
    /// handshake was already consumed, the auth exchange comes next.
    pub fn new_client_awaiting_auth(capability_flags: u32) -> Self {
        Self {
            state: MySqlState::WaitingHandshakeResponse,
            capability_flags,
            is_client_side: true,
            column_count: 0,
            pending_large: None,
        }
    }

    /// Update capability flags after handshake
    pub fn set_capability_flags(&mut self, flags: u32) {
        self.capability_flags = flags;
    }

    /// Force the codec back into the command phase (proxy loop calls this on
    /// every client command so a desynced response stream cannot persist).
    pub fn set_command_state(&mut self) {
        self.state = MySqlState::Command;
    }

    #[cfg(test)]
    pub fn set_state_for_test(&mut self, state: MySqlState) {
        self.state = state;
    }

    #[cfg(test)]
    pub fn set_column_count_for_test(&mut self, count: usize) {
        self.column_count = count;
    }

    fn uses_deprecate_eof(&self) -> bool {
        self.capability_flags & CLIENT_DEPRECATE_EOF != 0
    }
}

impl Decoder for MySqlCodec {
    type Item = MySqlMessage;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        // Loop so multi-packet (0xFFFFFF continuation) payloads already
        // buffered in `src` are consumed without waiting for more socket data.
        loop {
            // MySQL packet header: 3 bytes length + 1 byte sequence id
            if src.len() < 4 {
                return Ok(None);
            }

            // Read packet length (little-endian 3 bytes)
            let payload_len =
                (src[0] as usize) | ((src[1] as usize) << 8) | ((src[2] as usize) << 16);
            let sequence_id = src[3];

            let total_len = 4 + payload_len;
            if src.len() < total_len {
                src.reserve(total_len - src.len());
                return Ok(None);
            }

            let mut packet = src.split_to(total_len);
            packet.advance(4); // Skip header

            // A payload of exactly 0xFFFFFF continues in the next packet.
            if payload_len == 0xffffff {
                let pending = self
                    .pending_large
                    .get_or_insert_with(|| PendingLargePacket {
                        sequence_id,
                        payload: BytesMut::new(),
                    });
                pending.payload.extend_from_slice(&packet);
                continue;
            }

            let (sequence_id, packet, assembled) = match self.pending_large.take() {
                Some(mut pending) => {
                    pending.payload.extend_from_slice(&packet);
                    (pending.sequence_id, pending.payload, true)
                }
                None => (sequence_id, packet, false),
            };

            return self.dispatch(sequence_id, packet, assembled);
        }
    }
}

impl MySqlCodec {
    fn dispatch(
        &mut self,
        sequence_id: u8,
        mut packet: BytesMut,
        assembled: bool,
    ) -> Result<Option<MySqlMessage>> {
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
                    let first_byte = *packet.first().unwrap_or(&0xffu8);
                    match first_byte {
                        0x00 => {
                            match parse_ok_packet(&packet, sequence_id, self.capability_flags) {
                                Ok(ok) => {
                                    self.state = MySqlState::Command;
                                    Ok(Some(MySqlMessage::Ok(ok)))
                                }
                                // Forwarded verbatim either way; parse is for logging only.
                                Err(_) => {
                                    self.state = MySqlState::Command;
                                    Ok(Some(MySqlMessage::Generic(GenericPacket {
                                        sequence_id,
                                        payload: packet,
                                    })))
                                }
                            }
                        }
                        0xff => match parse_err_packet(&packet, sequence_id, self.capability_flags)
                        {
                            Ok(err) => Ok(Some(MySqlMessage::Err(err))),
                            Err(_) => Ok(Some(MySqlMessage::Generic(GenericPacket {
                                sequence_id,
                                payload: packet,
                            }))),
                        },
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
                if self.is_client_side
                    && first_byte != 0x00
                    && first_byte != 0xff
                    && first_byte != 0xfe
                {
                    // Could be column count (length-encoded int)
                    let (col_count, _) = read_lenenc_int(&packet)?;
                    if col_count > 0 && col_count < 4096 {
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

                // OK / ERR / legacy EOF: parsed for logging only, forwarded
                // verbatim; a parse failure degrades to Generic passthrough.
                if first_byte == 0x00
                    && let Ok(ok) = parse_ok_packet(&packet, sequence_id, self.capability_flags)
                {
                    return Ok(Some(MySqlMessage::Ok(ok)));
                }
                if first_byte == 0xff
                    && let Ok(err) = parse_err_packet(&packet, sequence_id, self.capability_flags)
                {
                    return Ok(Some(MySqlMessage::Err(err)));
                }
                if first_byte == 0xfe
                    && packet.len() < 9
                    && let Ok(eof) = parse_eof_packet(&packet, sequence_id)
                {
                    return Ok(Some(MySqlMessage::Eof(eof)));
                }

                Ok(Some(MySqlMessage::Generic(GenericPacket {
                    sequence_id,
                    payload: packet,
                })))
            }
            MySqlState::ReadingColumns { remaining } => {
                let Some(&first_byte) = packet.first() else {
                    anyhow::bail!("empty MySQL packet while reading column definitions");
                };

                // EOF packet marks end of column definitions
                if first_byte == 0xfe
                    && packet.len() < 9
                    && !self.uses_deprecate_eof()
                    && let Ok(eof) = parse_eof_packet(&packet, sequence_id)
                {
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
                let Some(&first_byte) = packet.first() else {
                    anyhow::bail!("empty MySQL packet while reading result rows");
                };

                // Result-set terminator. With CLIENT_DEPRECATE_EOF this is an OK packet carrying
                // a 0xFE header (affected_rows, last_insert_id, status, warnings, and a
                // session-state blob when CLIENT_SESSION_TRACK is on); without it, a legacy EOF.
                // Both are distinguished from a row whose first value is a 0xFE length-encoded
                // integer by the payload length, not by `len() < 9` — that older test is only
                // valid for legacy EOF and misroutes any terminator carrying session state into
                // parse_result_row, which appends a garbage row and desyncs the connection.
                // A reassembled multi-packet payload (>= 0xFFFFFF) is never a terminator.
                //
                // The proxy does not modify the terminator, so forward the original bytes and
                // parse nothing: re-encoding it is what corrupted it (encode_ok hardcodes a 0x00
                // header, so a 0xFE terminator could not survive a round trip).
                if first_byte == 0xfe && !assembled {
                    self.state = MySqlState::Command;
                    return Ok(Some(MySqlMessage::Generic(GenericPacket {
                        sequence_id,
                        payload: packet,
                    })));
                }

                // ERR packet
                if first_byte == 0xff {
                    self.state = MySqlState::Command;
                    return match parse_err_packet(&packet, sequence_id, self.capability_flags) {
                        Ok(err) => Ok(Some(MySqlMessage::Err(err))),
                        Err(_) => Ok(Some(MySqlMessage::Generic(GenericPacket {
                            sequence_id,
                            payload: packet,
                        }))),
                    };
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
            MySqlMessage::Handshake(h) => {
                encode_handshake_v10(&h, dst);
                // The client-facing codec never decodes a handshake — the proxy forwards the
                // upstream one — so its decoder state must be advanced here. Without this the
                // client's handshake response is decoded in WaitingHandshake state, comes back
                // as Generic, and the connection is aborted.
                if !self.is_client_side && matches!(self.state, MySqlState::WaitingHandshake) {
                    self.state = MySqlState::WaitingHandshakeResponse;
                }
            }
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

fn take_lenenc(buf: &mut &[u8]) -> Result<u64> {
    let (val, consumed) = read_lenenc_int(buf)?;
    *buf = &buf[consumed..];
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
    let raw = Bytes::copy_from_slice(&buf[..]);

    if buf.remaining() < 1 {
        anyhow::bail!("truncated handshake: missing protocol version");
    }
    let protocol_version = buf.get_u8();
    let server_version = read_null_terminated_string(buf)?;
    if buf.remaining() < 4 + 8 + 1 {
        anyhow::bail!("truncated handshake: missing connection id / auth data");
    }
    let connection_id = buf.get_u32_le();

    let mut auth_plugin_data_part1 = [0u8; 8];
    buf.copy_to_slice(&mut auth_plugin_data_part1);
    buf.advance(1); // filler

    if buf.remaining() < 2 + 1 + 2 + 2 + 1 + 10 {
        anyhow::bail!("truncated handshake: missing capability/status fields");
    }
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
        raw,
    })
}

fn parse_handshake_response(buf: &mut BytesMut, _server_caps: u32) -> Result<HandshakeResponse> {
    let raw = Bytes::copy_from_slice(&buf[..]);
    if buf.remaining() < 4 + 4 + 1 + 23 {
        anyhow::bail!("truncated handshake response");
    }
    let capability_flags = buf.get_u32_le();
    let max_packet_size = buf.get_u32_le();
    let character_set = buf.get_u8();
    buf.advance(23); // reserved

    // A 32-byte response with CLIENT_SSL set is an SSLRequest: the client
    // stops here and expects the TLS handshake to begin.
    if !buf.has_remaining() && capability_flags & CLIENT_SSL != 0 {
        return Ok(HandshakeResponse {
            capability_flags,
            max_packet_size,
            character_set,
            username: String::new(),
            auth_response: vec![],
            database: None,
            auth_plugin_name: None,
            raw,
        });
    }

    let username = read_null_terminated_string(buf)?;

    let auth_response = if capability_flags & CLIENT_SECURE_CONNECTION != 0 {
        if buf.remaining() < 1 {
            anyhow::bail!("truncated handshake response: missing auth length");
        }
        let len = buf.get_u8() as usize;
        if buf.remaining() < len {
            anyhow::bail!("truncated handshake response: short auth response");
        }
        buf.split_to(len).to_vec()
    } else {
        let pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let data = buf.split_to(pos).to_vec();
        if buf.has_remaining() {
            buf.advance(1);
        }
        data
    };

    // Only present when CLIENT_CONNECT_WITH_DB is set. Without this check a
    // client that omits a default schema but sets CLIENT_PLUGIN_AUTH has its
    // plugin name misread as the database (harmless for raw forward, wrong for logs).
    let database = if capability_flags & CLIENT_CONNECT_WITH_DB != 0 && buf.has_remaining() {
        Some(read_null_terminated_string(buf).ok().unwrap_or_default())
    } else {
        None
    };

    let auth_plugin_name = if capability_flags & CLIENT_PLUGIN_AUTH != 0 && buf.has_remaining() {
        Some(read_null_terminated_string(buf).ok().unwrap_or_default())
    } else {
        None
    };

    // CLIENT_CONNECT_ATTRS trailing block is intentionally ignored here — the
    // raw packet is forwarded verbatim by the encoder.

    Ok(HandshakeResponse {
        capability_flags,
        max_packet_size,
        character_set,
        username,
        auth_response,
        database,
        auth_plugin_name,
        raw,
    })
}

fn parse_ok_packet(packet: &[u8], sequence_id: u8, capability_flags: u32) -> Result<OkPacket> {
    let raw = Bytes::copy_from_slice(packet);
    let mut buf = packet;
    if buf.is_empty() {
        anyhow::bail!("truncated OK packet");
    }
    buf = &buf[1..]; // header 0x00
    let affected_rows = take_lenenc(&mut buf)?;
    let last_insert_id = take_lenenc(&mut buf)?;

    let (status_flags, warnings) = if capability_flags & CLIENT_PROTOCOL_41 != 0 {
        if buf.len() < 4 {
            anyhow::bail!("truncated OK packet: missing status/warnings");
        }
        let s = u16::from_le_bytes([buf[0], buf[1]]);
        let w = u16::from_le_bytes([buf[2], buf[3]]);
        buf = &buf[4..];
        (s, w)
    } else {
        (0, 0)
    };

    let info = Bytes::copy_from_slice(buf);

    Ok(OkPacket {
        sequence_id,
        affected_rows,
        last_insert_id,
        status_flags,
        warnings,
        info,
        raw,
    })
}

fn parse_err_packet(packet: &[u8], sequence_id: u8, capability_flags: u32) -> Result<ErrPacket> {
    let raw = Bytes::copy_from_slice(packet);
    let mut buf = packet;
    if buf.len() < 3 {
        anyhow::bail!("truncated ERR packet");
    }
    let error_code = u16::from_le_bytes([buf[1], buf[2]]);
    buf = &buf[3..];

    let sql_state = if capability_flags & CLIENT_PROTOCOL_41 != 0 {
        if buf.len() < 6 {
            anyhow::bail!("truncated ERR packet: missing sql state");
        }
        let mut state = [0u8; 5];
        state.copy_from_slice(&buf[1..6]); // skip '#' marker
        buf = &buf[6..];
        state
    } else {
        [0u8; 5]
    };

    let error_message = String::from_utf8_lossy(buf).to_string();

    Ok(ErrPacket {
        sequence_id,
        error_code,
        sql_state,
        error_message,
        raw,
    })
}

fn parse_eof_packet(packet: &[u8], sequence_id: u8) -> Result<EofPacket> {
    let raw = Bytes::copy_from_slice(packet);
    if packet.is_empty() {
        anyhow::bail!("truncated EOF packet");
    }
    let warnings = if packet.len() >= 3 {
        u16::from_le_bytes([packet[1], packet[2]])
    } else {
        0
    };
    let status_flags = if packet.len() >= 5 {
        u16::from_le_bytes([packet[3], packet[4]])
    } else {
        0
    };

    Ok(EofPacket {
        sequence_id,
        warnings,
        status_flags,
        raw,
    })
}

fn parse_column_definition(buf: &mut BytesMut, sequence_id: u8) -> Result<ColumnDefinition> {
    let raw = Bytes::copy_from_slice(&buf[..]);
    let catalog = read_lenenc_string(buf)?;
    let schema = read_lenenc_string(buf)?;
    let table = read_lenenc_string(buf)?;
    let org_table = read_lenenc_string(buf)?;
    let name = read_lenenc_string(buf)?;
    let org_name = read_lenenc_string(buf)?;
    // length-of-fixed-fields byte + 2 charset + 4 length + 1 type + 2 flags
    // + 1 decimals + 2 filler
    if buf.remaining() < 13 {
        anyhow::bail!("truncated column definition: missing fixed fields");
    }
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
        raw,
    })
}

fn parse_result_row(buf: &mut BytesMut, sequence_id: u8, column_count: usize) -> Result<ResultRow> {
    let mut values = Vec::with_capacity(column_count);

    for i in 0..column_count {
        if buf.is_empty() {
            // Silently substituting NULL here corrupted rows (audit H36):
            // fail visible instead of forwarding wrong data.
            anyhow::bail!(
                "malformed ResultRow: buffer exhausted at column {} of {}",
                i,
                column_count
            );
        }

        if buf[0] == 0xfb {
            // NULL value
            buf.advance(1);
            values.push(None);
        } else {
            let len = read_lenenc_int_from_buf(buf)? as usize;
            if buf.len() < len {
                anyhow::bail!(
                    "malformed ResultRow: field length {} exceeds remaining {} at column {}",
                    len,
                    buf.len(),
                    i
                );
            }
            values.push(Some(buf.split_to(len)));
        }
    }

    Ok(ResultRow {
        sequence_id,
        values,
    })
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

/// Write a payload as one or more packets, splitting at the mandatory
/// 0xFFFFFF boundary (a single header would silently truncate the 3-byte
/// length for anything larger).
fn write_packet_chunked(dst: &mut BytesMut, payload: &[u8], first_sequence_id: u8) {
    let mut seq = first_sequence_id;
    let mut rest = payload;
    loop {
        let chunk_len = rest.len().min(0xffffff);
        let (chunk, tail) = rest.split_at(chunk_len);
        write_packet_header(dst, chunk_len, seq);
        dst.put_slice(chunk);
        seq = seq.wrapping_add(1);
        rest = tail;
        if chunk_len < 0xffffff {
            break;
        }
        // A chunk of exactly 0xFFFFFF must be followed by another packet,
        // even an empty one — the next iteration handles both cases.
    }
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
    // Surgical path: forward the original payload, patching only the two
    // capability-flag byte pairs. Rebuilding the whole packet from parsed
    // fields drops anything the parser does not model.
    if !h.raw.is_empty()
        && let Some(nul) = h.raw.get(1..).and_then(|r| r.iter().position(|&b| b == 0))
    {
        // protocol_version(1) + server_version(nul+1) + connection_id(4)
        // + auth_plugin_data_part1(8) + filler(1)
        let off = 1 + nul + 1 + 4 + 8 + 1;
        if h.raw.len() >= off + 7 {
            let mut payload = BytesMut::from(&h.raw[..]);
            let caps = h.capability_flags;
            payload[off] = (caps & 0xff) as u8;
            payload[off + 1] = ((caps >> 8) & 0xff) as u8;
            // charset(1) + status_flags(2) sit between the two pairs
            payload[off + 5] = ((caps >> 16) & 0xff) as u8;
            payload[off + 6] = ((caps >> 24) & 0xff) as u8;
            write_packet_header(dst, payload.len(), 0);
            dst.put_slice(&payload);
            return;
        }
    }

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
    // Forward the client's packet byte-for-byte. Rebuilding it from parsed fields loses the
    // CLIENT_CONNECT_ATTRS block (and mis-handles CLIENT_CONNECT_WITH_DB, which this parser
    // infers from "are there bytes left" rather than from the capability bit), which the
    // server rejects with ER_HANDSHAKE_ERROR.
    if !r.raw.is_empty() {
        write_packet_header(dst, r.raw.len(), 1);
        dst.put_slice(&r.raw);
        return;
    }

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
    write_packet_chunked(dst, &g.payload, g.sequence_id);
}

fn encode_query(q: &QueryPacket, dst: &mut BytesMut) {
    let payload_len = 1 + q.query.len();
    write_packet_header(dst, payload_len, q.sequence_id);
    dst.put_u8(0x03); // COM_QUERY
    dst.put_slice(&q.query);
}

fn encode_column_definition(c: &ColumnDefinition, dst: &mut BytesMut) {
    // Never intentionally modified: forward verbatim when possible.
    if !c.raw.is_empty() {
        write_packet_chunked(dst, &c.raw, c.sequence_id);
        return;
    }

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

    write_packet_chunked(dst, &payload, r.sequence_id);
}

fn encode_ok(o: &OkPacket, dst: &mut BytesMut, capability_flags: u32) {
    // Never intentionally modified: forward verbatim when possible (encode_ok
    // hardcodes a 0x00 header, so e.g. a 0xFE-headed terminator could not
    // survive a field-based round trip).
    if !o.raw.is_empty() {
        write_packet_chunked(dst, &o.raw, o.sequence_id);
        return;
    }

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
    // Never intentionally modified: forward verbatim when possible.
    if !e.raw.is_empty() {
        write_packet_chunked(dst, &e.raw, e.sequence_id);
        return;
    }

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
    // Never intentionally modified: forward verbatim when possible.
    if !e.raw.is_empty() {
        write_packet_chunked(dst, &e.raw, e.sequence_id);
        return;
    }

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

    // ------------------------------------------------------------------
    // Per-variant decode -> encode byte-equality round trips. Every variant
    // the proxy does not intentionally modify must survive unchanged.
    // ------------------------------------------------------------------

    fn packet(payload: &[u8], seq: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + payload.len());
        out.push((payload.len() & 0xff) as u8);
        out.push(((payload.len() >> 8) & 0xff) as u8);
        out.push(((payload.len() >> 16) & 0xff) as u8);
        out.push(seq);
        out.extend_from_slice(payload);
        out
    }

    fn decode_one(codec: &mut MySqlCodec, bytes: &[u8]) -> MySqlMessage {
        let mut src = BytesMut::from(bytes);
        let msg = codec.decode(&mut src).unwrap().unwrap();
        assert!(src.is_empty(), "decode left {} unconsumed bytes", src.len());
        msg
    }

    fn encode_one(codec: &mut MySqlCodec, msg: MySqlMessage) -> Vec<u8> {
        let mut dst = BytesMut::new();
        codec.encode(msg, &mut dst).unwrap();
        dst.to_vec()
    }

    fn sample_handshake_payload() -> Vec<u8> {
        let mut p = Vec::new();
        p.push(0x0a); // protocol 10
        p.extend_from_slice(b"8.4.10\0");
        p.extend_from_slice(&42u32.to_le_bytes());
        p.extend_from_slice(b"abcdefgh"); // auth data part 1
        p.push(0); // filler
        p.extend_from_slice(&0xffffu16.to_le_bytes()); // caps lower (incl CLIENT_SSL)
        p.push(0x21); // charset
        p.extend_from_slice(&0x0002u16.to_le_bytes()); // status
        p.extend_from_slice(&0xc1ffu16.to_le_bytes()); // caps upper
        p.push(21); // auth data len
        p.extend_from_slice(&[0u8; 10]); // reserved
        p.extend_from_slice(b"ijklmnopqrst\0"); // auth data part 2 (13 bytes)
        p.extend_from_slice(b"caching_sha2_password\0");
        p
    }

    #[test]
    fn test_handshake_roundtrip_verbatim_when_unmodified() {
        let bytes = packet(&sample_handshake_payload(), 0);
        let mut client_codec = MySqlCodec::new_client();
        let msg = decode_one(&mut client_codec, &bytes);
        let MySqlMessage::Handshake(h) = msg else {
            panic!("expected handshake");
        };
        assert_eq!(h.server_version, "8.4.10");
        assert_eq!(h.auth_plugin_name, "caching_sha2_password");

        let mut server_codec = MySqlCodec::new_server();
        let encoded = encode_one(&mut server_codec, MySqlMessage::Handshake(h));
        assert_eq!(encoded, bytes, "unmodified handshake must round-trip");
    }

    #[test]
    fn test_handshake_capability_edit_is_surgical() {
        let bytes = packet(&sample_handshake_payload(), 0);
        let mut client_codec = MySqlCodec::new_client();
        let MySqlMessage::Handshake(mut h) = decode_one(&mut client_codec, &bytes) else {
            panic!("expected handshake");
        };
        assert_ne!(h.capability_flags & CLIENT_SSL, 0);
        h.capability_flags &= !CLIENT_SSL;

        let mut server_codec = MySqlCodec::new_server();
        let encoded = encode_one(&mut server_codec, MySqlMessage::Handshake(h));
        assert_eq!(encoded.len(), bytes.len());
        let diffs: Vec<usize> = bytes
            .iter()
            .zip(encoded.iter())
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect();
        // CLIENT_SSL is bit 11 -> second byte of the lower capability pair
        let caps_lower_off = 4 + 1 + 7 + 4 + 8 + 1;
        assert_eq!(
            diffs,
            vec![caps_lower_off + 1],
            "only the touched capability byte may change"
        );
    }

    #[test]
    fn test_column_definition_roundtrip_verbatim() {
        let mut payload = BytesMut::new();
        write_lenenc_string(&mut payload, b"def");
        write_lenenc_string(&mut payload, b"testdb");
        write_lenenc_string(&mut payload, b"u");
        write_lenenc_string(&mut payload, b"users");
        write_lenenc_string(&mut payload, b"x");
        write_lenenc_string(&mut payload, b"email");
        payload.put_u8(0x0c);
        payload.put_u16_le(33);
        payload.put_u32_le(255);
        payload.put_u8(253);
        payload.put_u16_le(0);
        payload.put_u8(0);
        payload.put_u16(0);
        let bytes = packet(&payload, 2);

        let mut codec = MySqlCodec::new_client();
        codec.set_state_for_test(MySqlState::ReadingColumns { remaining: 1 });
        let MySqlMessage::ColumnDefinition(col) = decode_one(&mut codec, &bytes) else {
            panic!("expected column definition");
        };
        assert_eq!(&col.org_name[..], b"email");
        assert_eq!(&col.org_table[..], b"users");

        let mut out_codec = MySqlCodec::new_server();
        let encoded = encode_one(&mut out_codec, MySqlMessage::ColumnDefinition(col));
        assert_eq!(encoded, bytes, "column definition must round-trip verbatim");
    }

    #[test]
    fn test_ok_packet_roundtrip_verbatim() {
        // OK with status flags, warnings and a session-track info blob
        let payload = [
            0x00, 0x01, 0x00, 0x22, 0x00, 0x00, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o',
        ];
        let bytes = packet(&payload, 1);

        let mut codec = MySqlCodec::new_client();
        codec.set_capability_flags(CLIENT_PROTOCOL_41);
        codec.set_state_for_test(MySqlState::Command);
        let MySqlMessage::Ok(ok) = decode_one(&mut codec, &bytes) else {
            panic!("expected OK packet");
        };
        assert_eq!(ok.affected_rows, 1);
        assert_eq!(ok.status_flags, 0x22);

        let mut out_codec = MySqlCodec::new_server();
        out_codec.set_capability_flags(CLIENT_PROTOCOL_41);
        let encoded = encode_one(&mut out_codec, MySqlMessage::Ok(ok));
        assert_eq!(encoded, bytes, "OK packet must round-trip verbatim");
    }

    #[test]
    fn test_err_packet_roundtrip_verbatim() {
        let mut payload = vec![0xff];
        payload.extend_from_slice(&1064u16.to_le_bytes());
        payload.push(b'#');
        payload.extend_from_slice(b"42000");
        payload.extend_from_slice(b"You have an error in your SQL syntax");
        let bytes = packet(&payload, 1);

        let mut codec = MySqlCodec::new_client();
        codec.set_capability_flags(CLIENT_PROTOCOL_41);
        codec.set_state_for_test(MySqlState::Command);
        let MySqlMessage::Err(err) = decode_one(&mut codec, &bytes) else {
            panic!("expected ERR packet");
        };
        assert_eq!(err.error_code, 1064);
        assert_eq!(&err.sql_state, b"42000");

        let mut out_codec = MySqlCodec::new_server();
        out_codec.set_capability_flags(CLIENT_PROTOCOL_41);
        let encoded = encode_one(&mut out_codec, MySqlMessage::Err(err));
        assert_eq!(encoded, bytes, "ERR packet must round-trip verbatim");
    }

    #[test]
    fn test_eof_packet_roundtrip_verbatim() {
        let payload = [0xfe, 0x00, 0x00, 0x22, 0x00];
        let bytes = packet(&payload, 3);

        let mut codec = MySqlCodec::new_client();
        codec.set_state_for_test(MySqlState::Command);
        let MySqlMessage::Eof(eof) = decode_one(&mut codec, &bytes) else {
            panic!("expected EOF packet");
        };
        assert_eq!(eof.status_flags, 0x22);

        let mut out_codec = MySqlCodec::new_server();
        let encoded = encode_one(&mut out_codec, MySqlMessage::Eof(eof));
        assert_eq!(encoded, bytes, "EOF packet must round-trip verbatim");
    }

    #[test]
    fn test_result_row_roundtrip() {
        let mut payload = BytesMut::new();
        write_lenenc_string(&mut payload, b"alice@example.com");
        payload.put_u8(0xfb); // NULL
        write_lenenc_string(&mut payload, b"42");
        let bytes = packet(&payload, 4);

        let mut codec = MySqlCodec::new_client();
        codec.set_state_for_test(MySqlState::ReadingRows);
        codec.set_column_count_for_test(3);
        let MySqlMessage::ResultRow(row) = decode_one(&mut codec, &bytes) else {
            panic!("expected result row");
        };
        assert_eq!(row.values.len(), 3);
        assert!(row.values[1].is_none());

        let mut out_codec = MySqlCodec::new_server();
        let encoded = encode_one(&mut out_codec, MySqlMessage::ResultRow(row));
        assert_eq!(encoded, bytes, "unmodified result row must round-trip");
    }

    #[test]
    fn test_query_roundtrip_verbatim() {
        let mut payload = vec![0x03];
        payload.extend_from_slice(b"SELECT email FROM users");
        let bytes = packet(&payload, 0);

        let mut codec = MySqlCodec::new_server();
        codec.set_state_for_test(MySqlState::Command);
        let MySqlMessage::Query(q) = decode_one(&mut codec, &bytes) else {
            panic!("expected query");
        };
        assert_eq!(&q.query[..], b"SELECT email FROM users");

        let mut out_codec = MySqlCodec::new_client();
        let encoded = encode_one(&mut out_codec, MySqlMessage::Query(q));
        assert_eq!(encoded, bytes, "query must round-trip verbatim");
    }

    #[test]
    fn test_deprecate_eof_terminator_with_session_state_is_forwarded_verbatim() {
        // 0xFE-headed OK terminator larger than 9 bytes (session state blob):
        // the old `len() < 9` test misrouted this into parse_result_row.
        let payload = [
            0xfe, 0x00, 0x00, 0x03, 0x40, 0x00, 0x00, 0x00, 0x11, 0x00, 0x0f, 0x0a, 0x61, 0x75,
            0x74, 0x6f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x03, 0x4f, 0x46, 0x46,
        ];
        assert!(payload.len() > 9);
        let bytes = packet(&payload, 5);

        let mut codec = MySqlCodec::new_client();
        codec.set_capability_flags(CLIENT_PROTOCOL_41 | CLIENT_DEPRECATE_EOF);
        codec.set_state_for_test(MySqlState::ReadingRows);
        let MySqlMessage::Generic(g) = decode_one(&mut codec, &bytes) else {
            panic!("terminator must surface as Generic passthrough");
        };
        assert_eq!(
            codec.state,
            MySqlState::Command,
            "terminator must return the codec to the command phase"
        );

        let mut out_codec = MySqlCodec::new_server();
        let encoded = encode_one(&mut out_codec, MySqlMessage::Generic(g));
        assert_eq!(encoded, bytes, "terminator must be forwarded verbatim");
    }

    #[test]
    fn test_truncated_result_row_is_an_error_not_null() {
        // Field claims 100 bytes but only 3 remain: must error, not fabricate NULLs
        let mut payload = BytesMut::new();
        payload.put_u8(100);
        payload.put_slice(b"abc");
        let bytes = packet(&payload, 4);

        let mut codec = MySqlCodec::new_client();
        codec.set_state_for_test(MySqlState::ReadingRows);
        codec.set_column_count_for_test(2);
        let mut src = BytesMut::from(&bytes[..]);
        let result = codec.decode(&mut src);
        assert!(result.is_err(), "truncated row must be a decode error");
    }

    #[test]
    fn test_empty_packet_mid_result_set_is_an_error_not_a_panic() {
        let bytes = packet(&[], 4);
        let mut codec = MySqlCodec::new_client();
        codec.set_state_for_test(MySqlState::ReadingRows);
        let mut src = BytesMut::from(&bytes[..]);
        assert!(codec.decode(&mut src).is_err());

        let mut codec = MySqlCodec::new_client();
        codec.set_state_for_test(MySqlState::ReadingColumns { remaining: 1 });
        let mut src = BytesMut::from(&bytes[..]);
        assert!(codec.decode(&mut src).is_err());
    }

    #[test]
    fn test_short_handshake_response_is_an_error_not_a_panic() {
        // 5-byte handshake response from a hostile client must not panic
        let bytes = packet(&[0x01, 0x02, 0x03, 0x04, 0x05], 1);
        let mut codec = MySqlCodec::new_server();
        codec.set_state_for_test(MySqlState::WaitingHandshakeResponse);
        let mut src = BytesMut::from(&bytes[..]);
        assert!(codec.decode(&mut src).is_err());
    }

    #[test]
    fn test_auth_packet_expects_client_reply_for_caching_sha2() {
        // Fast auth success: server continues with OK; client must not be waited on.
        assert!(!auth_packet_expects_client_reply(&[
            0x01,
            AUTH_MORE_DATA_FAST_AUTH_SUCCESS
        ]));
        // Full auth required: client sends password / pubkey request.
        assert!(auth_packet_expects_client_reply(&[
            0x01,
            AUTH_MORE_DATA_FULL_AUTH_REQUIRED
        ]));
        // Auth switch request.
        assert!(auth_packet_expects_client_reply(
            b"\xfemysql_native_password\0"
        ));
        // RSA public key payload (AuthMoreData with PEM) needs a client reply next
        // only after full-auth was requested earlier; the packet itself is 0x01+data
        // without the 0x03 status — treat as expecting reply (conservative).
        assert!(auth_packet_expects_client_reply(
            b"\x01-----BEGIN PUBLIC KEY-----"
        ));
    }

    #[test]
    fn test_handshake_response_plugin_auth_without_database() {
        // CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
        // without CLIENT_CONNECT_WITH_DB: trailing string is the plugin, not the DB.
        let caps: u32 = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
        let mut payload = BytesMut::new();
        payload.put_u32_le(caps);
        payload.put_u32_le(16_777_216);
        payload.put_u8(45);
        payload.put_slice(&[0u8; 23]);
        payload.put_slice(b"shipstream\0");
        payload.put_u8(1); // auth response length
        payload.put_u8(0x00);
        payload.put_slice(b"caching_sha2_password\0");

        let mut buf = payload.clone();
        let resp = parse_handshake_response(&mut buf, caps).expect("parse");
        assert_eq!(resp.username, "shipstream");
        assert_eq!(resp.database, None);
        assert_eq!(
            resp.auth_plugin_name.as_deref(),
            Some("caching_sha2_password")
        );
    }

    #[test]
    fn test_handshake_response_with_database_and_plugin() {
        let caps: u32 = CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_PLUGIN_AUTH
            | CLIENT_CONNECT_WITH_DB;
        let mut payload = BytesMut::new();
        payload.put_u32_le(caps);
        payload.put_u32_le(16_777_216);
        payload.put_u8(45);
        payload.put_slice(&[0u8; 23]);
        payload.put_slice(b"shipstream\0");
        payload.put_u8(1);
        payload.put_u8(0x00);
        payload.put_slice(b"shipstream_sample\0");
        payload.put_slice(b"caching_sha2_password\0");

        let mut buf = payload.clone();
        let resp = parse_handshake_response(&mut buf, caps).expect("parse");
        assert_eq!(resp.database.as_deref(), Some("shipstream_sample"));
        assert_eq!(
            resp.auth_plugin_name.as_deref(),
            Some("caching_sha2_password")
        );
    }

    #[test]
    fn test_ssl_request_prefix_is_recognized() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(CLIENT_PROTOCOL_41 | CLIENT_SSL).to_le_bytes());
        payload.extend_from_slice(&16777216u32.to_le_bytes());
        payload.push(0x21);
        payload.extend_from_slice(&[0u8; 23]);
        assert_eq!(payload.len(), 32);
        let bytes = packet(&payload, 1);

        let mut codec = MySqlCodec::new_server();
        codec.set_state_for_test(MySqlState::WaitingHandshakeResponse);
        let MySqlMessage::HandshakeResponse(r) = decode_one(&mut codec, &bytes) else {
            panic!("expected handshake response");
        };
        assert!(r.is_ssl_request());
    }

    #[test]
    fn test_multi_packet_payload_reassembly_and_chunked_encode() {
        // A logical payload of 0xFFFFFF + 5 bytes arrives as two packets and
        // must be reassembled, then re-chunked identically on encode.
        let mut payload = vec![0x41u8; 0xffffff];
        payload.extend_from_slice(b"tail!");

        let mut bytes = packet(&payload[..0xffffff], 4);
        bytes.extend_from_slice(&packet(&payload[0xffffff..], 5));

        // A server-side codec in the command phase surfaces a non-COM_QUERY
        // payload as Generic, which is what we want to observe here.
        let mut codec = MySqlCodec::new_server();
        codec.set_state_for_test(MySqlState::Command);
        let MySqlMessage::Generic(g) = decode_one(&mut codec, &bytes) else {
            panic!("expected generic");
        };
        assert_eq!(g.payload.len(), 0xffffff + 5);
        assert_eq!(g.sequence_id, 4);

        let mut out_codec = MySqlCodec::new_server();
        let encoded = encode_one(&mut out_codec, MySqlMessage::Generic(g));
        assert_eq!(
            encoded, bytes,
            "multi-packet payload must re-chunk identically"
        );
    }

    #[test]
    fn test_chunked_encode_exact_multiple_emits_empty_terminator() {
        let payload = vec![0x42u8; 0xffffff];
        let mut dst = BytesMut::new();
        write_packet_chunked(&mut dst, &payload, 0);
        // One full packet + one empty packet
        assert_eq!(dst.len(), 4 + 0xffffff + 4);
        let tail = &dst[4 + 0xffffff..];
        assert_eq!(tail, &[0x00, 0x00, 0x00, 0x01]);
    }
}
