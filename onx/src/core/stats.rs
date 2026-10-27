//! Summary statistics over a stream of packets

use time::OffsetDateTime;

use crate::core::packet::NxPacket;

/// Summary statistics of a capture, updated one packet at a time.
///
/// Only the totals are stored, never the packets themselves,
/// so a capture of any size is summarized in constant memory.
///
/// # Example
///
/// ```
/// use onx::core::packet::{LinkType, NxPacket};
/// use onx::core::stats::CaptureStats;
/// use time::OffsetDateTime;
///
/// let mut stats = CaptureStats::new();
/// let packet = NxPacket::new(OffsetDateTime::now_utc(), vec![0u8; 64], 64, LinkType::Ethernet);
/// stats.add(&packet);
///
/// assert_eq!(stats.packet_count(), 1);
/// assert_eq!(stats.total_bytes(), 64);
/// ```
#[derive(Debug, Default, Clone)]
pub struct CaptureStats {
    /// Number of packets added so far
    packet_count: usize,

    /// Sum of the captured lengths of all packets
    total_bytes: usize,

    /// Timestamp of the first packet added
    first_timestamp: Option<OffsetDateTime>,

    /// Timestamp of the last packet added (in file order, not the latest in time)
    last_timestamp: Option<OffsetDateTime>,
}

impl CaptureStats {
    /// Create empty statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one packet to the statistics
    pub fn add(&mut self, packet: &NxPacket) {
        self.packet_count += 1;
        self.total_bytes += packet.captured_len();

        if self.first_timestamp.is_none() {
            self.first_timestamp = Some(packet.timestamp());
        }
        self.last_timestamp = Some(packet.timestamp());
    }

    /// Returns the number of packets added
    pub fn packet_count(&self) -> usize {
        self.packet_count
    }

    /// Returns the total number of captured bytes
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Returns the average captured size of a packet, or 0 if there are no packets
    pub fn average_size(&self) -> usize {
        if self.packet_count == 0 {
            0
        } else {
            self.total_bytes / self.packet_count
        }
    }

    /// Returns the timestamp of the first packet, if any
    pub fn first_timestamp(&self) -> Option<OffsetDateTime> {
        self.first_timestamp
    }

    /// Returns the timestamp of the last packet, if any
    pub fn last_timestamp(&self) -> Option<OffsetDateTime> {
        self.last_timestamp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::packet::LinkType;

    fn packet_at(unix_seconds: i64, size: usize) -> NxPacket {
        let timestamp = OffsetDateTime::from_unix_timestamp(unix_seconds).unwrap();
        NxPacket::new(timestamp, vec![0u8; size], size, LinkType::Ethernet)
    }

    #[test]
    fn empty_stats() {
        let stats = CaptureStats::new();

        assert_eq!(stats.packet_count(), 0);
        assert_eq!(stats.total_bytes(), 0);
        assert_eq!(stats.average_size(), 0);
        assert_eq!(stats.first_timestamp(), None);
        assert_eq!(stats.last_timestamp(), None);
    }

    #[test]
    fn single_packet() {
        let mut stats = CaptureStats::new();
        stats.add(&packet_at(100, 60));

        assert_eq!(stats.packet_count(), 1);
        assert_eq!(stats.total_bytes(), 60);
        assert_eq!(stats.average_size(), 60);
        assert_eq!(stats.first_timestamp(), stats.last_timestamp());
    }

    #[test]
    fn several_packets() {
        let mut stats = CaptureStats::new();
        stats.add(&packet_at(100, 60));
        stats.add(&packet_at(200, 100));
        stats.add(&packet_at(300, 41));

        assert_eq!(stats.packet_count(), 3);
        assert_eq!(stats.total_bytes(), 201);
        assert_eq!(stats.average_size(), 67);
        assert_eq!(stats.first_timestamp(), Some(packet_at(100, 0).timestamp()));
        assert_eq!(stats.last_timestamp(), Some(packet_at(300, 0).timestamp()));
    }

    #[test]
    fn last_timestamp_follows_file_order() {
        // Captures can contain out-of-order timestamps: "last" means last added
        let mut stats = CaptureStats::new();
        stats.add(&packet_at(300, 10));
        stats.add(&packet_at(100, 10));

        assert_eq!(stats.first_timestamp(), Some(packet_at(300, 0).timestamp()));
        assert_eq!(stats.last_timestamp(), Some(packet_at(100, 0).timestamp()));
    }
}
