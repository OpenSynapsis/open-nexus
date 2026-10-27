//! Packet capture file (PCAP) handling

use crate::{
    capture::source::PacketSource,
    core::packet::{LinkType, NxPacket},
};

use pcap_file::{
    pcap::PcapReader,
    pcapng::{Block, PcapNgReader},
};

use time::OffsetDateTime;

use std::{
    fs::File,
    io::{self, BufReader, Read},
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

    /// Identify if the file is a PCAP file by trying to parse the header
    pub fn is_pcap_file<P: AsRef<Path>>(path: P) -> bool {
        // Check if the first bytes match the PCAP magic number
        if let Ok(mut file) = File::open(path) {
            let mut magic_number: [u8; 4] = [0u8; 4]; // PCAP global header is 24 bytes
            if file.read_exact(&mut magic_number).is_ok() {
                // Little-endian (most common, e.g. x86 machines)
                return magic_number == [0xd4, 0xc3, 0xb2, 0xa1] ||
                // Big-endian
                magic_number == [0xa1, 0xb2, 0xc3, 0xd4] ||
                // Nanosecond variants
                magic_number == [0x4d, 0x3c, 0xb2, 0xa1] ||
                magic_number == [0xa1, 0xb2, 0x3c, 0x4d];
            }
        }
        false
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
        }
    }
}

/// Iterator over packets from a PCAP file
pub struct PcapPacketIter<R: Read> {
    reader: PcapReader<R>,
    link_type: LinkType,
}

impl<R: Read> Iterator for PcapPacketIter<R> {
    type Item = Result<NxPacket, PcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.next_packet() {
            Some(Ok(pkt)) => {
                let timestamp = OffsetDateTime::from_unix_timestamp_nanos(
                    i128::try_from(pkt.timestamp.as_nanos()).unwrap_or(0),
                )
                .unwrap_or(OffsetDateTime::UNIX_EPOCH);

                let packet = NxPacket::new(
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

    /// Identify if the file is a PCAPNG file by trying to parse the first block
    pub fn is_pcapng_file<P: AsRef<Path>>(path: P) -> bool {
        if let Ok(mut file) = File::open(path) {
            let mut magic_number: [u8; 4] = [0u8; 4];
            if file.read_exact(&mut magic_number).is_ok() {
                // PCAPNG magic number is 0x0A0D0D0A
                return magic_number == [0x0A, 0x0D, 0x0D, 0x0A];
            }
        }
        false
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
        }
    }
}

/// Iterator over packets from a PCAPNG file
pub struct PcapNgPacketIter<R: Read> {
    reader: PcapNgReader<R>,
}

impl<R: Read> Iterator for PcapNgPacketIter<R> {
    type Item = Result<NxPacket, PcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let block = self.reader.next_block()?;
            match block {
                Ok(Block::EnhancedPacket(epb)) => {
                    let epb = epb.into_owned();
                    let interface = match self.reader.packet_interface(&epb) {
                        Some(iface) => iface,
                        None => return Some(Err(PcapError::MissingInterface(epb.interface_id))),
                    };
                    let timestamp = OffsetDateTime::from_unix_timestamp_nanos(
                        i128::try_from(epb.timestamp.as_nanos()).unwrap_or(0),
                    )
                    .unwrap_or(OffsetDateTime::UNIX_EPOCH);
                    let packet = NxPacket::new(
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
    type Item = Result<NxPacket, PcapError>;

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

/// Auto-detect and open PCAP or PCAPNG file
pub fn read_capture_file<P: AsRef<Path>>(
    path: P,
) -> Result<AnyPacketSource<BufReader<File>>, PcapError> {
    // Try PCAP first, then PCAPNG

    if PcapSource::is_pcap_file(&path) {
        PcapSource::from_file(path).map(AnyPacketSource::Pcap)
    } else if PcapNgSource::is_pcapng_file(&path) {
        PcapNgSource::from_file(path).map(AnyPacketSource::PcapNg)
    } else {
        Err(PcapError::UnsupportedFormat)
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
}
