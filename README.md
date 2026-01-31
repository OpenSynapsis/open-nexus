# Open Nexus (onx)

[![Crates.io](https://img.shields.io/crates/v/onx.svg)](https://crates.io/crates/onx)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/yourusername/open-nexus#license)

> Flow-based network packet capture and analysis

⚠️ **Status**: Early development (v0.0.1) - Name reservation release

## What is Open Nexus?

Traditional packet capture tools (tcpdump, Wireshark) give you raw packet lists.
Open Nexus indexes packets by **flows**, making filtering and analysis orders of 
magnitude faster.

### Key Concepts

- **Flow-based indexing**: Group packets by connection (5-tuple or protocol definition)
- **Fast search**: Query flows instantly instead of scanning packets
- **Real-time analysis**: TUI interface for live traffic monitoring
- **Multiple formats**: Works with PCAP, export flow-formatted logs or metrics (NetFlow, IPFIX, etc.)

### Roadmap

This is an early development release. Expected milestones:

- **v0.0.x** - Experimental development
- **v0.1.0** - First usable release (Q4 2026)
- **v1.0.0** - Stable API (TBD)

## Installation
```bash
cargo install open-nexus
```

## License

Licensed under either of:

- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## Links

- **Crates.io**: https://crates.io/crates/open-nexus
- **Repository**: https://github.com/OpenSynapsis/open-nexus
- **Issues**: https://github.com/OpenSynapsis/open-nexus/issues