//! Open Nexus CLI

use std::{
    path::{Path, PathBuf},
    process,
};

use clap::{Parser, Subcommand};

use onx::{
    capture::{read_capture_file, PacketSource},
    core::{packet::DisplayFormat, stats::CaptureStats},
    protocols::ProtocolStats,
};

/// Number of packets shown in the preview after the statistics
const PREVIEW_COUNT: usize = 5;

/// Flow-based network packet analysis.
///
/// Commands are grouped by object (`onx <group> <command>`); each group and
/// command has a short alias, e.g. `onx c i` for `onx capture info`.
/// The CLI is unstable during 0.0.x.
#[derive(Parser)]
#[command(name = "onx", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Capture files (PCAP, PCAPNG)
    #[command(visible_alias = "c")]
    Capture {
        #[command(subcommand)]
        command: CaptureCommand,
    },

    /// Decoded packets
    #[command(visible_alias = "p")]
    Packets {
        #[command(subcommand)]
        command: PacketsCommand,
    },
}

#[derive(Subcommand)]
enum PacketsCommand {
    /// Decode every packet and count protocols and undecoded reasons
    #[command(visible_alias = "s")]
    Stats {
        /// Path to the capture file
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum CaptureCommand {
    /// Summary of a capture: packet count, bytes, time range, first packets
    #[command(visible_alias = "i")]
    Info {
        /// Path to the capture file
        file: PathBuf,

        /// Show verbose output
        #[arg(short, long)]
        verbose: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Capture { command } => match command {
            CaptureCommand::Info { file, verbose } => capture_info(&file, verbose),
        },
        Command::Packets { command } => match command {
            PacketsCommand::Stats { file } => packets_stats(&file),
        },
    }
}

fn packets_stats(path: &Path) {
    let packets = match read_capture_file(path) {
        Ok(source) => source.packets(),
        Err(e) => {
            eprintln!("✗ Error opening {}: {}", path.display(), e);
            process::exit(1);
        }
    };

    // Decode packets one at a time: only counters are kept in memory
    let mut stats = ProtocolStats::new();
    let mut read_error = None;
    for result in packets {
        match result {
            Ok(raw) => stats.add(&raw.decode()),
            Err(e) => {
                read_error = Some(e);
                break;
            }
        }
    }

    println!("Decoded {} packets", stats.packet_count());

    // Labels are rendered first: the column width depends on the longest one
    let headers = labelled(stats.header_counts());
    let stops = labelled(stats.stop_counts());

    // One width for both sections, so that their counts line up
    let width = headers
        .iter()
        .chain(&stops)
        .map(|(label, _)| label.len())
        .max()
        .unwrap_or(0);

    println!();
    println!("Headers:");
    print_rows(&headers, width);

    if !stops.is_empty() {
        println!();
        println!("Not fully decoded:");
        print_rows(&stops, width);
    }

    // Partial read: the statistics above are still useful, but signal the failure
    if let Some(e) = read_error {
        eprintln!();
        eprintln!("✗ Error reading packet {}: {}", stats.packet_count() + 1, e);
        process::exit(1);
    }
}

/// Render the keys of `counts` as labels
fn labelled<K: ToString>(counts: Vec<(K, usize)>) -> Vec<(String, usize)> {
    counts
        .into_iter()
        .map(|(key, count)| (key.to_string(), count))
        .collect()
}

/// Print one `label count` row per entry, labels padded to `width`
fn print_rows(rows: &[(String, usize)], width: usize) {
    for (label, count) in rows {
        println!("  {label:<width$} {count:>8}");
    }
}

fn capture_info(path: &Path, verbose: bool) {
    if verbose {
        println!("Reading: {}", path.display());
    }
    println!();

    // Check if file exists
    if !path.exists() {
        eprintln!("✗ File not found: {}", path.display());
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
    println!("Reading packets...");
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
        println!("{}", pkt.display(DisplayFormat::OneLine));
    }

    if stats.packet_count() > PREVIEW_COUNT {
        println!("  ... and {} more", stats.packet_count() - PREVIEW_COUNT);
    }

    // Partial read: the summary above is still useful, but signal the failure
    if read_error.is_some() {
        process::exit(1);
    }
}
