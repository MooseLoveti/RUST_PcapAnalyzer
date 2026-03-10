use std::{env, fs::File};
use anyhow::{Context, Result};
use pcap_file::pcap::PcapReader;

fn main() -> Result<()> {
    let path = env::args().nth(1).context("Ex: cargo run -- sample.pcap")?;
    let pcap_file = File::open(path)?;
    let mut reader = PcapReader::new(pcap_file)?;

    println!("{:?}",reader.header());

    let mut i = 0;
    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt?;
        i += 1;
        println!("=== Packet {} ===", i);
        println!("{:#?}", pkt);
    }
    Ok(())
}
