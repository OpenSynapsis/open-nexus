//! What to decode after a header

use crate::protocols::EtherType;

/// Hint given by a decoded header about the header that follows it.
///
/// Internal to the dissection loop: users see `Header` and `Stop` only.
/// Each protocol adds the variant it produces (e.g. `IpProtocol` with IPv4,
/// `End` with UDP and TCP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Next {
    /// The next header is identified by an EtherType
    EtherType(EtherType),
}
