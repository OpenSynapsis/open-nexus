//! Protocol numbers: the values a header uses to name the header that follows

use std::fmt;

/// Protocol carried by an Ethernet frame (IEEE 802 EtherType).
///
/// A newtype rather than an enum: every `u16` is a valid EtherType, and each
/// value has exactly one representation. Known values are associated
/// constants, which can be used as patterns:
///
/// ```
/// use onx::protocols::EtherType;
///
/// let ether_type = EtherType::from(0x86dd);
/// let name = match ether_type {
///     EtherType::IPV4 => "IPv4",
///     EtherType::IPV6 => "IPv6",
///     _ => "other",
/// };
/// assert_eq!(name, "IPv6");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EtherType(u16);

impl EtherType {
    /// Internet Protocol version 4
    pub const IPV4: EtherType = EtherType(0x0800);
    /// Address Resolution Protocol
    pub const ARP: EtherType = EtherType(0x0806);
    /// Internet Protocol version 6
    pub const IPV6: EtherType = EtherType(0x86dd);

    /// Returns the name of a known EtherType
    fn name(self) -> Option<&'static str> {
        match self {
            EtherType::IPV4 => Some("IPv4"),
            EtherType::ARP => Some("ARP"),
            EtherType::IPV6 => Some("IPv6"),
            _ => None,
        }
    }
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        EtherType(value)
    }
}

impl From<EtherType> for u16 {
    fn from(ether_type: EtherType) -> Self {
        ether_type.0
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name}"),
            None => write!(f, "0x{:04x}", self.0),
        }
    }
}

impl fmt::Debug for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EtherType({self} = 0x{:04x})", self.0)
    }
}

/// Protocol carried by an IP packet: the IPv4 "Protocol" field, or the
/// IPv6 "Next Header" field (IANA Assigned Internet Protocol Numbers).
///
/// A newtype rather than an enum, for the same reasons as [`EtherType`]:
/// every `u8` is valid, and each value has exactly one representation.
///
/// ```
/// use onx::protocols::IpProtocol;
///
/// let protocol = IpProtocol::from(17);
/// let has_ports = matches!(protocol, IpProtocol::TCP | IpProtocol::UDP);
/// assert!(has_ports);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IpProtocol(u8);

impl IpProtocol {
    /// IPv6 Hop-by-Hop Options extension header
    pub const IPV6_HOPOPT: IpProtocol = IpProtocol(0);
    /// Internet Control Message Protocol
    pub const ICMP: IpProtocol = IpProtocol(1);
    /// Internet Group Management Protocol
    pub const IGMP: IpProtocol = IpProtocol(2);
    /// Transmission Control Protocol
    pub const TCP: IpProtocol = IpProtocol(6);
    /// User Datagram Protocol
    pub const UDP: IpProtocol = IpProtocol(17);
    /// IPv6 Routing extension header
    pub const IPV6_ROUTE: IpProtocol = IpProtocol(43);
    /// IPv6 Fragment extension header
    pub const IPV6_FRAG: IpProtocol = IpProtocol(44);
    /// Internet Control Message Protocol version 6
    pub const ICMPV6: IpProtocol = IpProtocol(58);
    /// IPv6 No Next Header: nothing follows
    pub const IPV6_NONXT: IpProtocol = IpProtocol(59);
    /// IPv6 Destination Options extension header
    pub const IPV6_OPTS: IpProtocol = IpProtocol(60);

    /// Returns the name of a known IpProtocol
    fn name(self) -> Option<&'static str> {
        match self {
            IpProtocol::IPV6_HOPOPT => Some("IPv6 Hop-by-Hop"),
            IpProtocol::ICMP => Some("ICMP"),
            IpProtocol::IGMP => Some("IGMP"),
            IpProtocol::TCP => Some("TCP"),
            IpProtocol::UDP => Some("UDP"),
            IpProtocol::IPV6_ROUTE => Some("IPv6 Routing"),
            IpProtocol::IPV6_FRAG => Some("IPv6 Fragment"),
            IpProtocol::ICMPV6 => Some("ICMPv6"),
            IpProtocol::IPV6_NONXT => Some("IPv6 No Next Header"),
            IpProtocol::IPV6_OPTS => Some("IPv6 Destination Options"),
            _ => None,
        }
    }
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        IpProtocol(value)
    }
}

impl From<IpProtocol> for u8 {
    fn from(ip_protocol: IpProtocol) -> Self {
        ip_protocol.0
    }
}

impl fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name}"),
            None => write!(f, "{}", self.0),
        }
    }
}

impl fmt::Debug for IpProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IpProtocol({self} = {})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ether_type_round_trips_through_u16() {
        assert_eq!(u16::from(EtherType::from(0x1234)), 0x1234);
    }

    #[test]
    fn known_ether_type_equals_its_constant() {
        // One representation per value: a parsed value equals the constant
        assert_eq!(EtherType::from(0x0800), EtherType::IPV4);
    }

    #[test]
    fn ether_type_display() {
        assert_eq!(EtherType::IPV6.to_string(), "IPv6");
        assert_eq!(EtherType::from(0x1234).to_string(), "0x1234");
    }

    #[test]
    fn ether_type_debug_shows_name_and_value() {
        assert_eq!(format!("{:?}", EtherType::IPV4), "EtherType(IPv4 = 0x0800)");
    }

    #[test]
    fn ip_protocol_round_trips_through_u8() {
        assert_eq!(u8::from(IpProtocol::from(200)), 200);
    }

    #[test]
    fn known_ip_protocol_equals_its_constant() {
        assert_eq!(IpProtocol::from(6), IpProtocol::TCP);
    }

    #[test]
    fn ip_protocol_display() {
        assert_eq!(IpProtocol::ICMPV6.to_string(), "ICMPv6");
        assert_eq!(IpProtocol::from(200).to_string(), "200");
    }

    #[test]
    fn ip_protocol_debug_shows_name_and_value() {
        assert_eq!(format!("{:?}", IpProtocol::UDP), "IpProtocol(UDP = 17)");
    }
}
