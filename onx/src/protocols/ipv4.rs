//! Internet Protocol version 4

use std::net::Ipv4Addr;

use etherparse::{err::ipv4::HeaderSliceError, Ipv4HeaderSlice};

use crate::protocols::{fragment::Fragment, next::Next, HeaderKind, IpProtocol, Span, Stop};

/// IPv4 header
///
/// Options are not extracted; the header length (options included) is the
/// length of `span`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4 {
    /// Source address
    pub source: Ipv4Addr,
    /// Destination address
    pub destination: Ipv4Addr,
    /// Protocol carried by the packet
    pub protocol: IpProtocol,
    /// Identification of the datagram, shared by its fragments
    pub identification: u16,
    /// Length of the packet (header and payload) announced by the header
    pub total_len: u16,
    /// Position of the packet in a fragmented datagram
    pub fragment: Fragment,
    /// Position of the header in the raw packet
    pub span: Span,
}

impl Ipv4 {
    /// Decode an IPv4 header (options included).
    ///
    /// `bytes` starts at the header; `offset` is its position in the raw
    /// packet. A non-first fragment ends decoding: its payload is the middle
    /// of a datagram, not a header.
    pub(crate) fn decode(bytes: &[u8], offset: u32) -> Result<(Ipv4, Next), Stop> {
        let header_slice = Ipv4HeaderSlice::from_slice(bytes).map_err(|error| match error {
            HeaderSliceError::Len(_) => Stop::Truncated(HeaderKind::Ipv4),
            HeaderSliceError::Content(_) => Stop::Malformed(HeaderKind::Ipv4),
        })?;

        let fragment = Fragment::new(
            header_slice.fragments_offset().value(),
            header_slice.more_fragments(),
        );

        let header_len = u32::from(header_slice.ihl()) * 4;
        let protocol = IpProtocol::from(header_slice.protocol().0);

        let ipv4 = Ipv4 {
            destination: header_slice.destination_addr(),
            source: header_slice.source_addr(),
            protocol,
            identification: header_slice.identification(),
            total_len: header_slice.total_len(),
            fragment,
            span: Span::new(offset, header_len),
        };

        let next_header = if fragment.is_first() {
            Next::IpProtocol(protocol)
        } else {
            Next::End
        };

        Ok((ipv4, next_header))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 20-byte IPv4 header: TCP, 10.0.0.1 -> 10.0.0.2, identification 0x1234,
    /// total length 40, not fragmented (checksum not computed: not checked)
    fn header() -> Vec<u8> {
        vec![
            0x45, 0x00, 0x00, 40, 0x12, 0x34, 0x00, 0x00, 64, 6, 0, 0, //
            10, 0, 0, 1, 10, 0, 0, 2,
        ]
    }

    #[test]
    fn decode_fields() {
        let (ipv4, next) = Ipv4::decode(&header(), 14).unwrap();

        assert_eq!(ipv4.source, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ipv4.destination, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(ipv4.protocol, IpProtocol::TCP);
        assert_eq!(ipv4.identification, 0x1234);
        assert_eq!(ipv4.total_len, 40);
        assert_eq!(ipv4.fragment, Fragment::NONE);
        assert_eq!(ipv4.span, Span::new(14, 20));
        assert_eq!(next, Next::IpProtocol(IpProtocol::TCP));
    }

    #[test]
    fn options_are_part_of_the_span() {
        let mut bytes = header();
        bytes[0] = 0x46; // IHL 6: one 4-byte option word
        bytes.extend_from_slice(&[1, 1, 1, 0]); // NOP, NOP, NOP, End of options

        let (ipv4, _) = Ipv4::decode(&bytes, 0).unwrap();
        assert_eq!(ipv4.span, Span::new(0, 24));
    }

    #[test]
    fn first_fragment_continues() {
        let mut bytes = header();
        bytes[6] = 0x20; // More Fragments flag, offset 0

        let (ipv4, next) = Ipv4::decode(&bytes, 0).unwrap();
        assert_eq!(ipv4.fragment, Fragment::new(0, true));
        assert_eq!(next, Next::IpProtocol(IpProtocol::TCP));
    }

    #[test]
    fn non_first_fragment_ends_decoding() {
        let mut bytes = header();
        bytes[7] = 185; // offset 185 * 8 = 1480 bytes, last fragment

        let (ipv4, next) = Ipv4::decode(&bytes, 0).unwrap();
        assert_eq!(ipv4.fragment, Fragment::new(185, false));
        assert_eq!(next, Next::End);
    }

    #[test]
    fn decode_truncated() {
        assert_eq!(
            Ipv4::decode(&header()[..10], 0),
            Err(Stop::Truncated(HeaderKind::Ipv4))
        );
    }

    #[test]
    fn decode_malformed() {
        let mut bytes = header();
        bytes[0] = 0x65; // version 6 in an IPv4 header

        assert_eq!(
            Ipv4::decode(&bytes, 0),
            Err(Stop::Malformed(HeaderKind::Ipv4))
        );
    }
}
