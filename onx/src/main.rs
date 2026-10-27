//! Open Nexus CLI

use std::process;

use clap::{Parser, Subcommand};

use onx::{
    capture::{read_capture_file, PacketSource},
    core::{packet::NxPacketFormat, stats::CaptureStats},
};

/// Number of packets shown in the preview after the statistics
const PREVIEW_COUNT: usize = 5;

#[derive(Parser)]
#[command(name = "onx")]
#[command(about = "")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // Read and display PCAP/PCAPNG file
    Read {
        // Path to pcap file
        file: String,

        // Show verbose output
        #[arg(short, long)]
        verbose: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Read { file, verbose } => {
            read_pcap(&file, verbose);
        }
    }
}

fn read_pcap(path: &str, verbose: bool) {
    if verbose {
        println!("Reading: {}", path);
    }
    println!();

    // Check if file exists
    if !std::path::Path::new(path).exists() {
        eprintln!("✗ File not found: {}", path);
        process::exit(1);
    }

    // Open PCAP file
    let pkt_iter = match read_capture_file(path) {
        Ok(source) => source.packets(),
        Err(e) => {
            eprintln!("✗ Error opening file: {}", e);
            process::exit(1);
        }
    };

    // Read packets one at a time: only the statistics and the first few
    // packets are kept in memory, so captures of any size can be read.
    // Reading stops at the first error, keeping what was read before it.
    println!("Parsing packets...");
    let mut stats = CaptureStats::new();
    let mut preview = Vec::with_capacity(PREVIEW_COUNT);
    let mut read_error = None;

    for result in pkt_iter {
        match result {
            Ok(packet) => {
                stats.add(&packet);
                if preview.len() < PREVIEW_COUNT {
                    preview.push(packet);
                }
            }
            Err(e) => {
                read_error = Some(e);
                break;
            }
        }
    }

    // Display summary
    println!();
    match &read_error {
        None => println!("✓ Successfully read {} packets", stats.packet_count()),
        Some(e) => {
            println!("⚠ Read {} packets before an error", stats.packet_count());
            eprintln!("✗ Error reading packet {}: {}", stats.packet_count() + 1, e);
        }
    }
    println!();

    println!("Statistics:");
    println!("  Total packets:  {}", stats.packet_count());
    println!("  Total bytes:    {}", stats.total_bytes());
    println!("  Average size:   {} bytes", stats.average_size());

    if let Some(first) = stats.first_timestamp() {
        println!("  First packet:   {}", first);
    }
    if let Some(last) = stats.last_timestamp() {
        println!("  Last packet:    {}", last);
    }

    // Show first few packets
    println!();
    println!("First {} packets:", PREVIEW_COUNT);
    for pkt in &preview {
        println!("{}", pkt.display(NxPacketFormat::OneLine));
    }

    if stats.packet_count() > PREVIEW_COUNT {
        println!("  ... and {} more", stats.packet_count() - PREVIEW_COUNT);
    }

    // Partial read: the summary above is still useful, but signal the failure
    if read_error.is_some() {
        process::exit(1);
    }
}
