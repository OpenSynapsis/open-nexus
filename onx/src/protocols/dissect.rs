//! The dissection loop: from raw bytes to a stack of decoded headers

use arrayvec::ArrayVec;

use crate::core::packet::{LinkType, RawPacket};
use crate::protocols::{
    next::Next,
    packet::{Packet, MAX_DEPTH},
    EtherType, Ethernet, Header, Ipv4, Ipv6, Stop,
};

impl RawPacket {
    /// Decode the protocol headers of this packet.
    ///
    /// Never fails: decoding keeps the headers decoded so far and records
    /// why it stopped early, if it did ([`Packet::stopped`]).
    pub fn decode(&self) -> Packet {
        let (headers, stopped) = dissect(self.data(), self.link_type());
        Packet::new(
            self.id(),
            self.timestamp(),
            self.original_len(),
            headers,
            stopped,
        )
    }
}

/// Decode headers from `data`, starting with the link layer
fn dissect(data: &[u8], link_type: LinkType) -> (ArrayVec<Header, MAX_DEPTH>, Option<Stop>) {
    let mut headers: ArrayVec<Header, MAX_DEPTH> = ArrayVec::new();
    let mut next = Next::Link(link_type);
    let mut offset: u32 = 0;

    loop {
        let bytes = data.get(offset as usize..).unwrap_or_default();
        let decoded =
            match next {
                Next::Link(LinkType::Ethernet) => Ethernet::decode(bytes, offset)
                    .map(|(ethernet, following)| (Header::Ethernet(ethernet), following)),
                Next::EtherType(EtherType::IPV4) => Ipv4::decode(bytes, offset)
                    .map(|(ipv4, following)| (Header::Ipv4(ipv4), following)),
                Next::EtherType(EtherType::IPV6) => Ipv6::decode(bytes, offset)
                    .map(|(ipv6, following)| (Header::Ipv6(ipv6), following)),
                // Fallbacks
                Next::Link(other_linktype) => {
                    return (headers, Some(Stop::UnsupportedLinkType(other_linktype)))
                }
                Next::EtherType(other_ethertype) => {
                    return (headers, Some(Stop::UnsupportedEtherType(other_ethertype)))
                }
                Next::IpProtocol(other_ipprotocol) => {
                    return (headers, Some(Stop::UnsupportedIpProtocol(other_ipprotocol)))
                }
                Next::Ipv6Extension(other_ipv6ext) => {
                    return (headers, Some(Stop::UnsupportedIpProtocol(other_ipv6ext)))
                }
                Next::End => return (headers, None),
            };
        match decoded {
            Ok((header, following)) => {
                let len = header.span().len();
                if headers.try_push(header).is_err() {
                    return (headers, Some(Stop::TooDeep));
                };
                next = following;
                offset += len;
            }
            Err(stop) => return (headers, Some(stop)),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::packet::PacketId;
    use crate::protocols::{HeaderKind, IpProtocol};
    use time::OffsetDateTime;

    /// Ethernet header, then a 20-byte IPv4 header carrying UDP
    /// (10.0.0.1 -> 10.0.0.2, not fragmented)
    fn ethernet_ipv4() -> Vec<u8> {
        let mut bytes = vec![0xff; 6];
        bytes.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        bytes.extend_from_slice(&[0x08, 0x00]);
        bytes.extend_from_slice(&[
            0x45, 0x00, 0x00, 28, 0x12, 0x34, 0x00, 0x00, 64, 17, 0, 0, //
            10, 0, 0, 1, 10, 0, 0, 2,
        ]);
        bytes
    }

    fn kinds(headers: &[Header]) -> Vec<HeaderKind> {
        headers.iter().map(Header::kind).collect()
    }

    #[test]
    fn stops_on_unsupported_ip_protocol() {
        let (headers, stopped) = dissect(&ethernet_ipv4(), LinkType::Ethernet);

        assert_eq!(
            kinds(&headers),
            vec![HeaderKind::Ethernet, HeaderKind::Ipv4]
        );
        assert_eq!(stopped, Some(Stop::UnsupportedIpProtocol(IpProtocol::UDP)));
    }

    #[test]
    fn truncated_ethernet() {
        let (headers, stopped) = dissect(&ethernet_ipv4()[..10], LinkType::Ethernet);

        assert!(headers.is_empty());
        assert_eq!(stopped, Some(Stop::Truncated(HeaderKind::Ethernet)));
    }

    #[test]
    fn empty_packet() {
        let (headers, stopped) = dissect(&[], LinkType::Ethernet);

        assert!(headers.is_empty());
        assert_eq!(stopped, Some(Stop::Truncated(HeaderKind::Ethernet)));
    }

    #[test]
    fn unsupported_link_type() {
        let (headers, stopped) = dissect(&ethernet_ipv4(), LinkType::Other(147));

        assert!(headers.is_empty());
        assert_eq!(
            stopped,
            Some(Stop::UnsupportedLinkType(LinkType::Other(147)))
        );
    }

    #[test]
    fn raw_packet_decode_keeps_metadata() {
        let raw = RawPacket::new(
            PacketId::FIRST,
            OffsetDateTime::UNIX_EPOCH,
            ethernet_ipv4(),
            1500,
            LinkType::Ethernet,
        );
        let packet = raw.decode();

        assert_eq!(packet.id(), PacketId::FIRST);
        assert_eq!(packet.timestamp(), OffsetDateTime::UNIX_EPOCH);
        assert_eq!(packet.original_len(), 1500);
        assert_eq!(
            kinds(packet.headers()),
            vec![HeaderKind::Ethernet, HeaderKind::Ipv4]
        );
    }
}
