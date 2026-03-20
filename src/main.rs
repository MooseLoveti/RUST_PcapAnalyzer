use std::{env, fs::File, time::UNIX_EPOCH};
use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use pcap_file::pcap::PcapReader;

fn calc(proto_hex: &str) -> i32 {
    match proto_hex {
        "01" => 8,
        "02" => 8,
        "06" => 20,
        "11" => 8,
        "2C" => 8,
        "3A" => 8,
        "3B" => 0,
        "84" => 12,
        "88" => 8,
        _=> 0,
    }
}
fn main() -> Result<()> {
    let path = env::args().nth(1).context("Ex: cargo run -- sample.pcap")?;
    let pcap_file = File::open(path)?;
    let mut reader = PcapReader::new(pcap_file)?;

    println!("{:?}", reader.header());

    let mut i = 0;
    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt?;
        i += 1;
        println!("=== Packet {} ===", i);

        let packet_time = UNIX_EPOCH + pkt.timestamp;
        let local_time: DateTime<Local> = packet_time.into();
        println!("時刻={}", local_time.format("%Y-%m-%d %H:%M:%S%.6f %:z"));
        println!("パケット長={:#?}", pkt.orig_len);
        let bytes = pkt.data.as_ref();
        let hex = bytes.iter()
        .map(|b| format!("{:02X}", b))//幅2ケタ0埋め16進数
        .collect::<Vec<_>>()
        .join(" ");
        let ipv = &hex[0..1]; //4ならIPv4 6ならIPv6
        let ip_size = &hex[1..2]; //4ならランダム 6なら固定30バイト
        let mut head_size = 0;
        let int_ipv: i32 = ipv.parse().unwrap_or(0);
        let int_ip_size: i32 = ip_size.parse().unwrap_or(0);
        if int_ipv == 4 {
            head_size = int_ipv * int_ip_size;
            let protocol = hex.split_whitespace().nth(9).unwrap_or("");
            head_size += calc(protocol);
        } else if int_ipv == 6 {
            head_size = 30;
            let protocol = hex.split_whitespace().nth(6).unwrap_or("");
            head_size += calc(protocol);
        } //head_size以降がペイロード

        if (head_size as usize) <= bytes.len() {
            let payload = &bytes[head_size as usize..]; //末尾まで
            let payload_ascii: String = payload.iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect();
            println!("{}",payload_ascii);
        }
    }

    Ok(())
}
