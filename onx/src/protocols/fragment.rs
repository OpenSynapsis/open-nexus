//! IP fragmentation information, shared by IPv4 and IPv6

/// Position of an IP packet in a fragmented datagram.
///
/// A non-fragmented packet has offset 0 and no "more fragments" flag. Only
/// the first fragment (offset 0) carries the transport header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fragment {
    /// Offset of the fragment data in the datagram, in 8-byte units (13 bits)
    offset: u16,
    /// More fragments follow this one
    more_fragments: bool,
}

impl Fragment {
    /// A packet that is not fragmented
    pub const NONE: Fragment = Fragment {
        offset: 0,
        more_fragments: false,
    };

    /// Create fragment information from the offset field (8-byte units) and
    /// the "more fragments" flag
    pub(crate) const fn new(offset: u16, more_fragments: bool) -> Self {
        Self {
            offset,
            more_fragments,
        }
    }

    /// Returns the offset of the fragment data in the datagram, in bytes
    pub const fn offset_bytes(self) -> u32 {
        self.offset as u32 * 8
    }

    /// Returns true if more fragments follow this one
    pub const fn more_fragments(self) -> bool {
        self.more_fragments
    }

    /// Returns true if this packet is a fragment of a larger datagram
    pub const fn is_fragmented(self) -> bool {
        self.offset != 0 || self.more_fragments
    }

    /// Returns true if this packet starts its datagram, so carries the
    /// transport header (true for non-fragmented packets)
    pub const fn is_first(self) -> bool {
        self.offset == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_fragmented() {
        assert!(!Fragment::NONE.is_fragmented());
        assert!(Fragment::NONE.is_first());
    }

    #[test]
    fn first_fragment() {
        let fragment = Fragment::new(0, true);
        assert!(fragment.is_fragmented());
        assert!(fragment.is_first());
    }

    #[test]
    fn last_fragment() {
        let fragment = Fragment::new(185, false);
        assert!(fragment.is_fragmented());
        assert!(!fragment.is_first());
        assert_eq!(fragment.offset_bytes(), 1480);
    }
}
