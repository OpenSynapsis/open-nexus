mod common;

use onx::capture::{pcap::read_capture_file, PacketSource};
use onx::core::packet::LinkType;
use onx::protocols::HeaderKind;

/// Every packet of the sample captures decodes without panicking, and
/// Ethernet captures start with an Ethernet header.
#[test]
fn decode_sample_captures() {
    let manifest = match common::load_manifest() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Skipping decode tests: failed to load manifest.json: {e}");
            return;
        }
    };

    for test_file in manifest {
        let path = match common::ensure_test_file(&test_file) {
            Ok(path) => path,
            Err(e) => {
                eprintln!("Skipping {}: {e}", test_file.filename);
                continue;
            }
        };

        let source = read_capture_file(&path).expect("Failed to open capture file");
        for raw in source.packets() {
            let raw = raw.expect("Failed to read packet");
            let packet = raw.decode();

            if raw.link_type() == LinkType::Ethernet && raw.captured_len() >= 14 {
                assert_eq!(
                    packet.headers().first().map(|h| h.kind()),
                    Some(HeaderKind::Ethernet),
                    "packet {} of {}",
                    raw.id(),
                    test_file.filename
                );
            }
        }
    }
}
