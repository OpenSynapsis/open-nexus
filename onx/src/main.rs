//! Open Nexus CLI

use std::process;

use clap::{Parser, Subcommand};

use onx::{
    capture::{read_capture_file, PacketSource},
    core::packet::NxPacketFormat,
};

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

    // Read all packets
    println!("Parsing packets...");
    let packets: Vec<_> = match pkt_iter.collect::<Result<Vec<_>, _>>() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("✗ Error reading packets: {}", e);
            process::exit(1);
        }
    };

    // Display summary
    println!();
    println!("✓ Successfully read {} packets", packets.len());
    println!();

    // Calculate statistics
    let total_bytes: usize = packets.iter().map(|p| p.captured_len()).sum();
    let avg_size = if !packets.is_empty() {
        total_bytes / packets.len()
    } else {
        0
    };

    println!("Statistics:");
    println!("  Total packets:  {}", packets.len());
    println!("  Total bytes:    {}", total_bytes);
    println!("  Average size:   {} bytes", avg_size);

    if let Some(first) = packets.first() {
        println!("  First packet:   {}", first.timestamp());
    }
    if let Some(last) = packets.last() {
        println!("  Last packet:    {}", last.timestamp());
    }

    // Show first few packets
    println!();
    println!("First 5 packets:");
    for pkt in packets.iter().take(5) {
        println!("{}", pkt.display(NxPacketFormat::OneLine));
    }

    if packets.len() > 5 {
        println!("  ... and {} more", packets.len() - 5);
    }
}
