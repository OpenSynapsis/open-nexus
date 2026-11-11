//! Protocol statistics over a stream of decoded packets

use std::cmp::Reverse;
use std::collections::HashMap;

use crate::protocols::{HeaderKind, Packet, Stop};

/// Counts of decoded headers and of stop reasons, updated one packet at a time.
///
/// Like [`CaptureStats`](crate::core::stats::CaptureStats), only counters are
/// stored, never the packets: a capture of any size is summarized in memory
/// proportional to the number of distinct protocols and stop reasons.
#[derive(Debug, Default, Clone)]
pub struct ProtocolStats {
    /// Number of packets added
    packet_count: usize,
    /// Number of headers decoded, by kind (a packet can contain several)
    headers: HashMap<HeaderKind, usize>,
    /// Number of packets whose decoding stopped early, by reason
    stops: HashMap<Stop, usize>,
}

impl ProtocolStats {
    /// Create empty statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one decoded packet to the statistics
    pub fn add(&mut self, packet: &Packet) {
        self.packet_count += 1;

        for p_header in packet.headers() {
            *self.headers.entry(p_header.kind()).or_default() += 1;
        }

        if let Some(stop) = packet.stopped() {
            *self.stops.entry(stop).or_default() += 1;
        }
    }

    /// Returns the number of packets added
    pub fn packet_count(&self) -> usize {
        self.packet_count
    }

    /// Returns the number of headers decoded by kind, most frequent first
    pub fn header_counts(&self) -> Vec<(HeaderKind, usize)> {
        by_frequency(&self.headers)
    }

    /// Returns the number of packets stopped early by reason, most frequent first
    pub fn stop_counts(&self) -> Vec<(Stop, usize)> {
        by_frequency(&self.stops)
    }
}

/// Entries of `counts` sorted by count, highest first, then by key so that
/// the order is the same on every run (`HashMap` iteration order is random).
fn by_frequency<K: Ord + Copy>(counts: &HashMap<K, usize>) -> Vec<(K, usize)> {
    let mut entries = counts
        .iter()
        .map(|(key, count)| (*key, *count))
        .collect::<Vec<_>>();

    entries.sort_by_key(|&(key, count)| (Reverse(count), key));

    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::packet::{LinkType, PacketId, RawPacket};
    use crate::protocols::EtherType;
    use time::OffsetDateTime;

    fn decoded(data: Vec<u8>) -> Packet {
        let len = data.len();
        RawPacket::new(
            PacketId::FIRST,
            OffsetDateTime::UNIX_EPOCH,
            data,
            len,
            LinkType::Ethernet,
        )
        .decode()
    }

    /// Ethernet frame carrying the given EtherType, with a small payload
    fn ethernet(ether_type: u16) -> Packet {
        let mut bytes = vec![0xff; 12];
        bytes.extend_from_slice(&ether_type.to_be_bytes());
        bytes.extend_from_slice(&[0; 20]);
        decoded(bytes)
    }

    #[test]
    fn empty_stats() {
        let stats = ProtocolStats::new();

        assert_eq!(stats.packet_count(), 0);
        assert!(stats.header_counts().is_empty());
        assert!(stats.stop_counts().is_empty());
    }

    #[test]
    fn counts_headers_and_stops() {
        let mut stats = ProtocolStats::new();
        stats.add(&ethernet(0x0806));
        stats.add(&ethernet(0x0806));
        stats.add(&ethernet(0x86dd));
        stats.add(&decoded(vec![0; 5])); // too short for Ethernet

        assert_eq!(stats.packet_count(), 4);
        assert_eq!(stats.header_counts(), vec![(HeaderKind::Ethernet, 3)]);
        assert_eq!(
            stats.stop_counts(),
            vec![
                (Stop::UnsupportedEtherType(EtherType::from(0x0806)), 2),
                (Stop::Truncated(HeaderKind::Ethernet), 1),
                (Stop::UnsupportedEtherType(EtherType::IPV6), 1),
            ]
        );
    }

    #[test]
    fn ties_are_ordered_by_key() {
        let mut counts = HashMap::new();
        counts.insert('b', 1);
        counts.insert('c', 2);
        counts.insert('a', 1);

        assert_eq!(by_frequency(&counts), vec![('c', 2), ('a', 1), ('b', 1)]);
    }
}
