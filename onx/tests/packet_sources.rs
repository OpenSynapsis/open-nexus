mod common;

use onx::capture::{pcap::read_capture_file, PacketSource};

#[test]
fn test_pcap_source_from_manifest() {
    let manifest = match common::load_manifest() {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "Skipping manifest tests: Failed to load manifest.json: {}",
                e,
            );
            return;
        }
    };

    for test_file in manifest {
        let pcap_path = match common::ensure_test_file(&test_file) {
            Ok(path) => path,
            Err(e) => {
                eprintln!(
                    "Skipping test for {}: failed to download or verify: {}",
                    test_file.filename, e
                );
                continue;
            }
        };

        let source = read_capture_file(&pcap_path).expect("Failed to open capture file");
        let packets: Vec<_> = source
            .packets()
            .collect::<Result<Vec<_>, _>>()
            .expect("Failed to read packets");

        println!("{}: {}", test_file.filename, packets.len());

        assert_eq!(
            packets.len(),
            test_file.metadata.packet_count,
            "Packet count mismatch for {}",
            test_file.filename
        );

        for pkt in &packets {
            assert!(pkt.captured_len() > 0);
        }

        // Packets are numbered 1..=n with no gap, like Wireshark frame numbers
        // (in PCAPNG, non-packet blocks must not consume a number)
        let numbers: Vec<u64> = packets.iter().map(|p| p.id().number()).collect();
        let expected: Vec<u64> = (1..=packets.len() as u64).collect();
        assert_eq!(
            numbers, expected,
            "Packet numbering mismatch for {}",
            test_file.filename
        );
    }
}

#[test]
fn test_generic_processing() {
    fn count_packets<S: PacketSource>(source: S) -> usize {
        source.packets().filter_map(Result::ok).count()
    }

    // Use the first manifest item for the generic test if available
    let manifest = match common::load_manifest() {
        Ok(m) => m,
        Err(_) => return, // Skip silently if manifest is missing
    };

    let pcap_file = manifest.first().expect("Manifest is empty");
    let pcap_path = match common::ensure_test_file(pcap_file) {
        Ok(path) => path,
        Err(_) => return, // Skip gracefully on network/download errors
    };

    let source = read_capture_file(&pcap_path).unwrap();
    let count = count_packets(source);
    assert_eq!(count, pcap_file.metadata.packet_count);
}
