//! Internet Protocol version 6

use std::net::Ipv6Addr;

use etherparse::{err::ipv6::HeaderSliceError, Ipv6HeaderSlice};

use crate::protocols::{next::Next, HeaderKind, IpProtocol, Span, Stop};

/// IPv6 fixed header (40 bytes)
///
/// Extension headers (Hop-by-Hop, Routing, Fragment, Destination Options)
/// are separate headers in the packet's stack, each with its own span.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6 {
    /// Source address
    pub source: Ipv6Addr,
    /// Destination address
    pub destination: Ipv6Addr,
    /// Header that follows: an extension header or the upper-layer protocol
    pub next_header: IpProtocol,
    /// Length of everything after the fixed header (extensions included),
    /// announced by the header
    pub payload_len: u16,
    /// Flow label (20 bits)
    pub flow_label: u32,
    /// Position of the header in the raw packet
    pub span: Span,
}

impl Ipv6 {
    /// Length of the IPv6 fixed header, in bytes
    const LEN: u32 = 40;

    /// Decode an IPv6 fixed header.
    ///
    /// `bytes` starts at the header; `offset` is its position in the raw
    /// packet.
    pub(crate) fn decode(bytes: &[u8], offset: u32) -> Result<(Ipv6, Next), Stop> {
        // TODO(me): same moves as `Ipv4::decode`, without the fragment and
        // with a fixed length. The flow label is wrapped by etherparse, like
        // the fragment offset was. Use `next_after` for the `Next`.
        let header_slice = Ipv6HeaderSlice::from_slice(bytes).map_err(|error| match error {
            HeaderSliceError::Len(_) => Stop::Truncated(HeaderKind::Ipv6),
            HeaderSliceError::Content(_) => Stop::Malformed(HeaderKind::Ipv6),
        })?;

        let next_header = IpProtocol::from(header_slice.next_header().0);

        let ipv6 = Ipv6 {
            destination: header_slice.destination_addr(),
            source: header_slice.source_addr(),
            next_header,
            payload_len: header_slice.payload_length(),
            flow_label: header_slice.flow_label().value(),
            span: Span::new(offset, Ipv6::LEN),
        };

        Ok((ipv6, next_after(next_header)))
    }
}

/// What follows an IPv6 header or extension header whose next header field
/// is `next_header`.
///
/// Shared by the fixed header and every extension header: they all end with
/// the same kind of next header field.
pub(crate) fn next_after(next_header: IpProtocol) -> Next {
    match next_header {
        IpProtocol::IPV6_HOPOPT
        | IpProtocol::IPV6_ROUTE
        | IpProtocol::IPV6_FRAG
        | IpProtocol::IPV6_OPTS => Next::Ipv6Extension(next_header),
        IpProtocol::IPV6_NONXT => Next::End,
        other => Next::IpProtocol(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 40-byte IPv6 header: flow label 0xabcde, payload length 20, TCP,
    /// fe80::1 -> fe80::2
    fn header() -> Vec<u8> {
        let mut bytes = vec![0x60, 0x0a, 0xbc, 0xde, 0x00, 20, 6, 64];
        bytes.extend_from_slice(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).octets());
        bytes.extend_from_slice(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2).octets());
        bytes
    }

    #[test]
    fn decode_fields() {
        let (ipv6, next) = Ipv6::decode(&header(), 14).unwrap();

        assert_eq!(ipv6.source, Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(ipv6.destination, Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));
        assert_eq!(ipv6.next_header, IpProtocol::TCP);
        assert_eq!(ipv6.payload_len, 20);
        assert_eq!(ipv6.flow_label, 0xabcde);
        assert_eq!(ipv6.span, Span::new(14, 40));
        assert_eq!(next, Next::IpProtocol(IpProtocol::TCP));
    }

    #[test]
    fn decode_truncated() {
        assert_eq!(
            Ipv6::decode(&header()[..39], 0),
            Err(Stop::Truncated(HeaderKind::Ipv6))
        );
    }

    #[test]
    fn decode_malformed() {
        let mut bytes = header();
        bytes[0] = 0x40; // version 4 in an IPv6 header

        assert_eq!(
            Ipv6::decode(&bytes, 0),
            Err(Stop::Malformed(HeaderKind::Ipv6))
        );
    }

    #[test]
    fn extension_headers_are_followed_as_extensions() {
        for extension in [
            IpProtocol::IPV6_HOPOPT,
            IpProtocol::IPV6_ROUTE,
            IpProtocol::IPV6_FRAG,
            IpProtocol::IPV6_OPTS,
        ] {
            assert_eq!(next_after(extension), Next::Ipv6Extension(extension));
        }
    }

    #[test]
    fn no_next_header_ends_decoding() {
        assert_eq!(next_after(IpProtocol::IPV6_NONXT), Next::End);
    }

    #[test]
    fn upper_layer_protocols_are_followed_as_protocols() {
        assert_eq!(
            next_after(IpProtocol::UDP),
            Next::IpProtocol(IpProtocol::UDP)
        );
        assert_eq!(
            next_after(IpProtocol::from(47)),
            Next::IpProtocol(IpProtocol::from(47))
        );
    }
}
