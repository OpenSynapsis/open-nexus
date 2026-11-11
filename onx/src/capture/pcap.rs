//! Packet capture file (PCAP) handling

use crate::{
    capture::source::PacketSource,
    core::packet::{LinkType, PacketId, RawPacket},
};

use pcap_file::{
    pcap::PcapReader,
    pcapng::{Block, PcapNgReader},
};

use time::OffsetDateTime;

use std::{
    fs::File,
    io::{self, BufReader, Read, Seek},
    path::Path,
};

// ============================================================================
// READING Pcap files (PCAP)
// ============================================================================

/// PCAP file packet source
pub struct PcapSource<R: Read> {
    reader: PcapReader<R>,
}

impl PcapSource<BufReader<File>> {
    /// Create a PcapSource from a file path
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, PcapError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Self::new(reader)
    }
}

impl<R: Read> PcapSource<R> {
    /// Create a PcapSource from a reader
    pub fn new(reader: R) -> Result<Self, PcapError> {
        let pcap_reader = PcapReader::new(reader)?;

        Ok(Self {
            reader: pcap_reader,
        })
    }
}

impl<R: Read> PacketSource for PcapSource<R> {
    type Error = PcapError;
    type PacketIter = PcapPacketIter<R>;

    fn packets(self) -> Self::PacketIter {
        let link_type = LinkType::from_pcap(self.reader.header().datalink);
        PcapPacketIter {
            reader: self.reader,
            link_type,
            next_id: PacketId::FIRST,
        }
    }
}

/// Iterator over packets from a PCAP file
pub struct PcapPacketIter<R: Read> {
    reader: PcapReader<R>,
    link_type: LinkType,
    /// Identity given to the next packet read
    next_id: PacketId,
}

impl<R: Read> Iterator for PcapPacketIter<R> {
    type Item = Result<RawPacket, PcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.next_packet() {
            Some(Ok(pkt)) => {
                let id = self.next_id;
                self.next_id = id.next();

                let timestamp = OffsetDateTime::from_unix_timestamp_nanos(
                    i128::try_from(pkt.timestamp.as_nanos()).unwrap_or(0),
                )
                .unwrap_or(OffsetDateTime::UNIX_EPOCH);

                let packet = RawPacket::new(
                    id,
                    timestamp,
                    pkt.data.to_vec(),
                    pkt.orig_len as usize,
                    self.link_type,
                );

                Some(Ok(packet))
            }
            Some(Err(e)) => Some(Err(PcapError::from_reader(e))),
            None => None,
        }
    }
}

/// Error type for PCAP operations
///
/// `#[non_exhaustive]`: new error cases can be added without a breaking change.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum PcapError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PCAP read error: {0}")]
    ReadError(#[from] pcap_file::PcapError),

    #[error("Unsupported file format")]
    UnsupportedFormat,

    #[error("Missing interface block for interface id {0}")]
    MissingInterface(u32),

    #[error("File is truncated: it ends in the middle of a packet")]
    Truncated,
}

impl PcapError {
    /// Convert an error from the `pcap-file` reader, recognizing truncated files
    fn from_reader(e: pcap_file::PcapError) -> Self {
        match e {
            pcap_file::PcapError::IncompleteBuffer => PcapError::Truncated,
            pcap_file::PcapError::IoError(ref io_error)
                if io_error.kind() == io::ErrorKind::UnexpectedEof =>
            {
                PcapError::Truncated
            }
            other => PcapError::ReadError(other),
        }
    }
}

// ============================================================================
// READING Pcapng files (PCAP Next Generation)
// ============================================================================

/// PCAPNG file packet source
pub struct PcapNgSource<R: Read> {
    reader: PcapNgReader<R>,
}

impl PcapNgSource<BufReader<File>> {
    /// Open a PCAPNG file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, PcapError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Self::new(reader)
    }
}

impl<R: Read> PcapNgSource<R> {
    /// Create a PCAPNG source from a reader
    pub fn new(reader: R) -> Result<Self, PcapError> {
        let pcapng_reader = PcapNgReader::new(reader)?;
        Ok(Self {
            reader: pcapng_reader,
        })
    }
}

impl<R: Read> PacketSource for PcapNgSource<R> {
    type Error = PcapError;
    type PacketIter = PcapNgPacketIter<R>;

    fn packets(self) -> Self::PacketIter {
        PcapNgPacketIter {
            reader: self.reader,
            next_id: PacketId::FIRST,
        }
    }
}

/// Iterator over packets from a PCAPNG file
pub struct PcapNgPacketIter<R: Read> {
    reader: PcapNgReader<R>,
    /// Identity given to the next packet read
    next_id: PacketId,
}

impl<R: Read> Iterator for PcapNgPacketIter<R> {
    type Item = Result<RawPacket, PcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let block = self.reader.next_block()?;
            match block {
                Ok(Block::EnhancedPacket(epb)) => {
                    let id = self.next_id;
                    self.next_id = id.next();

                    let epb = epb.into_owned();
                    let interface = match self.reader.packet_interface(&epb) {
                        Some(iface) => iface,
                        None => return Some(Err(PcapError::MissingInterface(epb.interface_id))),
                    };
                    let timestamp = OffsetDateTime::from_unix_timestamp_nanos(
                        i128::try_from(epb.timestamp.as_nanos()).unwrap_or(0),
                    )
                    .unwrap_or(OffsetDateTime::UNIX_EPOCH);
                    let packet = RawPacket::new(
                        id,
                        timestamp,
                        epb.data.to_vec(),
                        epb.original_len as usize,
                        LinkType::from_pcap(interface.linktype),
                    );
                    return Some(Ok(packet));
                }
                Ok(_) => continue, // Skip non-packet blocks
                Err(e) => return Some(Err(PcapError::from_reader(e))),
            }
        }
    }
}

// ============================================================================
// READING Abstract capture files (auto-detecting PCAP vs PCAPNG)
// ============================================================================

/// Unified iterator over packets from any source
pub enum AnyPacketIter<R: Read> {
    Pcap(PcapPacketIter<R>),
    PcapNg(PcapNgPacketIter<R>),
}

impl<R: Read> Iterator for AnyPacketIter<R> {
    type Item = Result<RawPacket, PcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            AnyPacketIter::Pcap(iter) => iter.next(),
            AnyPacketIter::PcapNg(iter) => iter.next(),
        }
    }
}

pub enum AnyPacketSource<R: Read> {
    Pcap(PcapSource<R>),
    PcapNg(PcapNgSource<R>),
}

impl<R: Read> PacketSource for AnyPacketSource<R> {
    type Error = PcapError;
    type PacketIter = AnyPacketIter<R>;

    fn packets(self) -> Self::PacketIter {
        match self {
            AnyPacketSource::Pcap(s) => AnyPacketIter::Pcap(s.packets()),
            AnyPacketSource::PcapNg(s) => AnyPacketIter::PcapNg(s.packets()),
        }
    }
}

/// Capture file formats recognized by their magic number
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureFormat {
    Pcap,
    PcapNg,
}

impl CaptureFormat {
    /// Recognize a format from the first 4 bytes of a file
    fn detect(magic: [u8; 4]) -> Option<CaptureFormat> {
        match magic {
            // Little-endian, big-endian, then their nanosecond variants
            [0xd4, 0xc3, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0xc3, 0xd4]
            | [0x4d, 0x3c, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0x3c, 0x4d] => Some(CaptureFormat::Pcap),
            // Section Header Block type, the same in both byte orders
            [0x0a, 0x0d, 0x0d, 0x0a] => Some(CaptureFormat::PcapNg),
            _ => None,
        }
    }
}

/// Auto-detect and open PCAP or PCAPNG file
///
/// # Errors
///
/// `PcapError::Io` if the file cannot be opened or read,
/// `PcapError::UnsupportedFormat` if it is neither PCAP nor PCAPNG.
pub fn read_capture_file<P: AsRef<Path>>(
    path: P,
) -> Result<AnyPacketSource<BufReader<File>>, PcapError> {
    // Open once: checking then reopening would report a missing file as an
    // unsupported format, and the file could change between the two opens.
    let mut file = File::open(path)?;

    let mut magic = [0u8; 4];
    if let Err(error) = file.read_exact(&mut magic) {
        return Err(match error.kind() {
            // Shorter than any magic number: not a capture
            io::ErrorKind::UnexpectedEof => PcapError::UnsupportedFormat,
            _ => PcapError::Io(error),
        });
    }
    file.rewind()?;

    let reader = BufReader::new(file);
    match CaptureFormat::detect(magic) {
        Some(CaptureFormat::Pcap) => PcapSource::new(reader).map(AnyPacketSource::Pcap),
        Some(CaptureFormat::PcapNg) => PcapNgSource::new(reader).map(AnyPacketSource::PcapNg),
        None => Err(PcapError::UnsupportedFormat),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a small little-endian PCAP file holding `packet_count` packets of 4 bytes each
    fn pcap_bytes(packet_count: usize) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Global header: magic, version 2.4, timezone, sigfigs, snaplen, link type (Ethernet)
        bytes.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&4u16.to_le_bytes());
        for field in [0u32, 0, 65535, 1] {
            bytes.extend_from_slice(&field.to_le_bytes());
        }

        for _ in 0..packet_count {
            // Packet header: seconds, microseconds, captured length, original length
            for field in [0u32, 0, 4, 4] {
                bytes.extend_from_slice(&field.to_le_bytes());
            }
            bytes.extend_from_slice(&[0xaa; 4]);
        }

        bytes
    }

    #[test]
    fn reads_complete_file() {
        let bytes = pcap_bytes(3);
        let packets: Vec<_> = PcapSource::new(&bytes[..]).unwrap().packets().collect();

        assert_eq!(packets.len(), 3);
        assert!(packets.iter().all(|p| p.is_ok()));
    }

    #[test]
    fn packets_are_numbered_from_one() {
        let bytes = pcap_bytes(3);
        let numbers: Vec<u64> = PcapSource::new(&bytes[..])
            .unwrap()
            .packets()
            .map(|p| p.unwrap().id().number())
            .collect();

        assert_eq!(numbers, vec![1, 2, 3]);
    }

    #[test]
    fn truncated_in_packet_data() {
        let bytes = pcap_bytes(3);
        let truncated = &bytes[..bytes.len() - 2]; // cut the last packet's data in half
        let mut packets = PcapSource::new(truncated).unwrap().packets();

        assert!(packets.next().unwrap().is_ok());
        assert!(packets.next().unwrap().is_ok());
        assert!(matches!(packets.next(), Some(Err(PcapError::Truncated))));
    }

    #[test]
    fn truncated_in_packet_header() {
        let bytes = pcap_bytes(3);
        let truncated = &bytes[..bytes.len() - 10]; // cut inside the last packet's header
        let mut packets = PcapSource::new(truncated).unwrap().packets();

        assert!(packets.next().unwrap().is_ok());
        assert!(packets.next().unwrap().is_ok());
        assert!(matches!(packets.next(), Some(Err(PcapError::Truncated))));
    }

    #[test]
    fn missing_file_is_an_io_error() {
        let result = read_capture_file("does/not/exist.pcap");

        assert!(
            matches!(result, Err(PcapError::Io(ref e)) if e.kind() == io::ErrorKind::NotFound),
            "expected a NotFound I/O error"
        );
    }

    #[test]
    fn detect_formats() {
        assert_eq!(
            CaptureFormat::detect([0xd4, 0xc3, 0xb2, 0xa1]),
            Some(CaptureFormat::Pcap)
        );
        assert_eq!(
            CaptureFormat::detect([0xa1, 0xb2, 0x3c, 0x4d]),
            Some(CaptureFormat::Pcap)
        );
        assert_eq!(
            CaptureFormat::detect([0x0a, 0x0d, 0x0d, 0x0a]),
            Some(CaptureFormat::PcapNg)
        );
        assert_eq!(CaptureFormat::detect(*b"GIF8"), None);
    }

    #[test]
    fn file_shorter_than_a_magic_number_is_unsupported() {
        let path = std::env::temp_dir().join(format!("onx-short-{}.pcap", std::process::id()));
        std::fs::write(&path, [0xd4, 0xc3]).unwrap();

        let result = read_capture_file(&path);
        std::fs::remove_file(&path).unwrap();

        assert!(matches!(result, Err(PcapError::UnsupportedFormat)));
    }
}
