//! Core packet representation

use std::fmt;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// A network packet in Open Nexus format
///
/// # Example
///
/// ```
/// use onx::core::packet::{NxPacket, LinkType, NxPacketFormat};
/// use time::OffsetDateTime;
///
/// let packet = NxPacket::new(OffsetDateTime::now_utc(), vec![0u8; 64], 64, LinkType::Ethernet);
/// println!("{}", packet.display(NxPacketFormat::OneLine));
/// ```
#[derive(Debug, Clone)]
pub struct NxPacket {
    /// Timestamp when packet was captured
    timestamp: OffsetDateTime,

    /// Raw packet data starting from the link layer header.
    /// The length of this slice is the captured length, which may be
    /// less than `orig_len` if the packet was truncated.
    data: Vec<u8>,

    /// Original packet length (may differ from data.len() if truncated)
    original_len: usize,

    /// Link layer type
    link_type: LinkType,
}

impl NxPacket {
    /// Create a new packet
    pub fn new(
        timestamp: OffsetDateTime,
        data: Vec<u8>,
        original_len: usize,
        link_type: LinkType,
    ) -> Self {
        Self {
            timestamp,
            data,
            original_len,
            link_type,
        }
    }

    /// Get packet data as a slice
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the timestamp when this packet was captured
    pub fn timestamp(&self) -> OffsetDateTime {
        self.timestamp
    }

    /// Check if packet was truncated during capture (i.e. captured length < original length)
    pub fn is_truncated(&self) -> bool {
        self.data.len() < self.original_len
    }

    /// Returns the number of bytes actually stored in this packet.
    /// This may be less than [`NxPacket::original_len()`] if the capture tool applied a snaplen limit.
    pub fn captured_len(&self) -> usize {
        self.data.len()
    }

    /// Returns the original length of the packet as it was on the wire.
    /// This may be greater than [`NxPacket::captured_len()`] if the packet was truncated during capture
    pub fn original_len(&self) -> usize {
        self.original_len
    }
}

// =================================================
// Link layer types
// =================================================

/// Link layer type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// Ethernet (IEEE 802.3)
    Ethernet,
    /// Raw IP (no link layer header)
    RawIp,
    /// Linux "cooked" capture (SLL)
    LinuxSll,
    /// Other/unknown link type
    Other(u32),
}

impl fmt::Display for LinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkType::Ethernet => write!(f, "Ethernet"),
            LinkType::RawIp => write!(f, "Raw IP"),
            LinkType::LinuxSll => write!(f, "Linux SLL"),
            LinkType::Other(n) => write!(f, "Unknown ({})", n),
        }
    }
}

impl LinkType {
    // Convert from PCAP link type constant
    pub(crate) fn from_pcap(link_type: pcap_file::DataLink) -> Self {
        match link_type {
            pcap_file::DataLink::ETHERNET => LinkType::Ethernet,
            pcap_file::DataLink::RAW => LinkType::RawIp,
            pcap_file::DataLink::LINUX_SLL => LinkType::LinuxSll,
            _ => LinkType::Other(u32::from(link_type)),
        }
    }
}

// =================================================
// Packet display and formatting
// =================================================

/// Output format for displaying packets
/// This is used by the `NxPacketDisplay` wrapper to determine how to format the packet for display.
// The enums are intentionally non-exhaustive to allow adding new formats in the future without breaking existing code.
#[non_exhaustive]
pub enum NxPacketFormat {
    /// One line summary (timestamp, link type, length).
    /// Example:
    /// ```ignore
    /// 2024-06-01T12:34:56Z | Ethernet | 128 bytes
    /// ```
    OneLine,
    /// Verbose multi-line format with detailed fields and data preview.
    /// Example:
    /// ```ignore
    /// Timestamp : 2024-06-01T12:34:56Z
    /// Link type : Ethernet
    /// Orig len  : 128 bytes
    /// Cap len   : 128 bytes
    /// Data      : 45 00 00 54 00 00 40 00 40 01 b6 6c c0 a8 01 02 c0 a8 01 01 ...
    /// ```
    Verbose,
    /// Hex dump format showing raw bytes in hex and ASCII (similar to xxd).
    /// Example:
    /// ```ignore
    /// 0000  45 00 00 54 00 00 40 00 40 01 b6 6c c0 a8 01 02 c0 a8 01 01  E..T..@.@..l....
    /// 0010  08 00 4d 5c 00 01 00 01 ... (hex dump of packet data)
    /// ```
    HexDump,
}

pub struct NxPacketDisplay<'a> {
    packet: &'a NxPacket,
    format: NxPacketFormat,
}

impl<'a> fmt::Display for NxPacketDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.format {
            NxPacketFormat::OneLine => write_one_line(f, self.packet),
            NxPacketFormat::Verbose => write_verbose(f, self.packet),
            NxPacketFormat::HexDump => write_hex_dump(f, self.packet),
        }
    }
}

impl NxPacket {
    /// Format this packet for display using the specified format
    pub fn display(&self, format: NxPacketFormat) -> NxPacketDisplay<'_> {
        NxPacketDisplay {
            packet: self,
            format,
        }
    }
}

fn write_one_line(f: &mut fmt::Formatter<'_>, packet: &NxPacket) -> fmt::Result {
    let ts = packet.timestamp.format(&Rfc3339).map_err(|_| fmt::Error)?;
    write!(
        f,
        "{} | {} | {} bytes",
        ts, packet.link_type, packet.original_len
    )
}

fn write_verbose(f: &mut fmt::Formatter<'_>, packet: &NxPacket) -> fmt::Result {
    let ts = packet.timestamp.format(&Rfc3339).map_err(|_| fmt::Error)?;
    writeln!(f, "Timestamp : {}", ts)?;
    writeln!(f, "Link type : {}", packet.link_type)?;
    writeln!(f, "Orig len  : {} bytes", packet.original_len)?;
    writeln!(f, "Cap len   : {} bytes", packet.data.len())?;

    if packet.data.len() < packet.original_len {
        writeln!(
            f,
            "           [truncated: {} bytes missing]",
            packet.original_len - packet.data.len()
        )?;
    }

    if packet.data.is_empty() {
        write!(f, "Data      : (empty)")
    } else {
        let preview = packet
            .data
            .iter()
            .take(16)
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        write!(
            f,
            "Data      : {}{}",
            preview,
            if packet.data.len() > 16 { " ..." } else { "" }
        )
    }
}

fn write_hex_dump(f: &mut fmt::Formatter<'_>, packet: &NxPacket) -> fmt::Result {
    const COLS: usize = 16; // bytes per row

    if packet.data.is_empty() {
        return write!(f, "(empty)");
    }

    for (row_idx, chunk) in packet.data.chunks(COLS).enumerate() {
        // Byte offset at the start of this row
        write!(f, "{:04x}  ", row_idx * COLS)?;

        // Hex columns, split into two groups of 8 with an extra space in the middle
        for (i, byte) in chunk.iter().enumerate() {
            if i == 8 {
                write!(f, " ")?;
            }
            write!(f, "{:02x} ", byte)?;
        }

        // Pad the last (possibly short) row so the ASCII column aligns
        if chunk.len() < COLS {
            let missing = COLS - chunk.len();
            // Each missing byte = 3 chars ("xx "), plus 1 if we never hit the mid-gap
            let pad = missing * 3 + if chunk.len() <= 8 { 1 } else { 0 };
            write!(f, "{:pad$}", "", pad = pad)?;
        }

        // ASCII sidebar: printable chars as-is, everything else as '.'
        write!(f, " ")?;
        for byte in chunk {
            let ch = if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            };
            write!(f, "{}", ch)?;
        }

        // No trailing newline on the very last row
        if row_idx < (packet.data.len().saturating_sub(1)) / COLS {
            writeln!(f)?;
        }
    }

    Ok(())
}
