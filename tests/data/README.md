# Test Data

This directory contains PCAP files for testing.

## Automated Download

Test files are managed directly by the Rust test suite! 
Simply running `cargo test` will automatically:
1. Parse the `manifest.json` file in this directory.
2. Download any missing test captures.
3. Validate the `SHA256` integrity.
4. Execute tests dynamically against the downloaded files.

## Adding New Test Data

If you want to add a new capture to the tests:
1. Upload/locate the capture (e.g. from the Wireshark wiki).
2. Calculate its `SHA256` hash.
3. Add a new entry to `manifest.json` with its metadata (e.g., `packet_count`).
4. Run `cargo test` and it will automatically download and start validating the new file!

## Sources

All test PCAPs are from:
- https://wiki.wireshark.org/SampleCaptures
- Public domain or freely available

Place downloaded files in this directory (`tests/data/`).