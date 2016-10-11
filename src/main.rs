#[macro_use]
extern crate log;
extern crate env_logger;

extern crate pcap;
extern crate pnet;

use std::env;

use pnet::packet::Packet;
//use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;

use pnet::packet::ip::IpNextHeaderProtocols;

extern crate tls_parser;
use tls_parser::tls::{TlsMessage,TlsPlaintext,TlsMessageHandshake,parse_tls_raw_record,parse_tls_raw_record_as_plaintext};
use tls_parser::tls_ciphers::TlsCipherSuite;
use tls_parser::tls_extensions::parse_tls_extensions;

extern crate nom;
use nom::IResult;

fn handle_parsed_tls_record(record: &TlsPlaintext) {
    debug!("plaintext: {:?}", record);
    for msg in &record.msg {
        match *msg {
            TlsMessage::Handshake(ref m) => {
                match *m {
                    TlsMessageHandshake::ClientHello(ref content) => {
                        let blah = parse_tls_extensions(content.ext.unwrap_or(b""));
                        debug!("ext {:?}", blah);
                    },
                    TlsMessageHandshake::ServerHello(ref content) => {
                        match TlsCipherSuite::from_id(content.cipher) {
                            Some(c) => info!("Selected cipher: {:?}", c),
                            _ => info!("Unknown cipher 0x{:x}", content.cipher),
                        };
                        let ext = parse_tls_extensions(content.ext.unwrap_or(b""));
                        debug!("ext {:?}", ext);
                    },
                    _ => (),
                }
            },
            _ => (),
        }
    }
}

fn parse_data_as_tls(i: &[u8]) {
    let mut cur_i = i;

    while cur_i.len() > 0 {
        let res_raw = parse_tls_raw_record(cur_i);
        debug!("raw: {:?}",res_raw);
        match res_raw {
            IResult::Done(rem, ref r) => {
                let plaintext = parse_tls_raw_record_as_plaintext(r).unwrap();
                handle_parsed_tls_record(&plaintext);
                cur_i = rem;
            },
            IResult::Incomplete(_) => warn!("Fragmentation required ? {:?}", res_raw),
            IResult::Error(e) => warn!("Parsing failed: {:?}",e),
        }
    }
}

fn callback(ds: usize, packet: pcap::Packet) {
    debug!("----------------------------------------");
    debug!("raw packet: {:?}", packet.data);

    //let ref ether = EthernetPacket::new(packet.data).unwrap();
    let ref ipv4 = Ipv4Packet::new(&packet.data[ds..]).unwrap();
    // debug!("next level proto: {:?}", ipv4.get_next_level_protocol());
    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
        match TcpPacket::new(ipv4.payload()) {
            Some(ref tcp) => {
                //debug!("tcp payload: {:?}", tcp.payload());

                parse_data_as_tls(tcp.payload());
            },
            None => (), // not a TCP packet, ignore
        }
    }
}

fn main() {
    let _ = env_logger::init().unwrap();
    let args: Vec<_> = env::args().collect();
    if args.len() > 1 {
        let mut cap = pcap::Capture::from_file(&args[1]).unwrap();

        let ds = match cap.get_datalink() {
            pcap::Linktype(1) => 14,
            _ => 16,
        };

        while let Ok(packet) = cap.next() {
            callback(ds,packet);
        }
    } else {
        warn!("Usage: <prog> file.pcap");
    }
}
