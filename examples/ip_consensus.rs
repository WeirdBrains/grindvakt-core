//! Public IPv4 agreement rules, offline; pass `--live` to query the real sources.
//!
//! `cargo run --example ip_consensus` (offline) or `cargo run --example ip_consensus -- --live`

use grindvakt_core::ip::{PublicIpConsensus, consensus, extract_ipv4, is_global_ipv4};

#[tokio::main(flavor = "current_thread")]
async fn main() -> grindvakt_core::Result<()> {
    // What four echo services might answer.
    let bodies = [
        "93.184.216.34\n",
        "93.184.216.34",
        "<html>timeout</html>",
        "your ip: 93.184.216.34",
    ];
    let parsed: Vec<_> = bodies.iter().map(|b| extract_ipv4(b)).collect();
    println!("parsed answers: {parsed:?}");
    println!("agreed address: {}", consensus(&parsed)?);

    let split = ["93.184.216.34", "93.184.216.35"].map(extract_ipv4);
    println!(
        "one-to-one split refused: {}",
        consensus(&split).unwrap_err()
    );
    println!(
        "10.0.0.1 global? {}",
        is_global_ipv4("10.0.0.1".parse().unwrap())
    );

    let lookup = PublicIpConsensus::default();
    println!("default sources: {:?}", lookup.sources);
    if std::env::args().any(|a| a == "--live") {
        #[cfg(feature = "public-ip")]
        println!("live result: {}", lookup.resolve().await?);
        #[cfg(not(feature = "public-ip"))]
        println!("build with the public-ip feature for --live");
    }
    Ok(())
}
