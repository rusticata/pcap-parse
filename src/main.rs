#[macro_use]
extern crate log;
extern crate env_logger;

extern crate pnet;

extern crate pcap_parser;

use std::collections::HashMap;

use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

extern crate argparse;
use argparse::{ArgumentParser, StoreTrue, Store};

use std::net::IpAddr;

use pnet::packet::PacketSize;
use pnet::packet::Packet;
//use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use pnet::packet::ip::IpNextHeaderProtocols;

use pcap_parser::Capture;

#[macro_use]
extern crate nom;
use nom::HexDisplay;

extern crate rusticata;
use rusticata::{RParser,STREAM_TOCLIENT,STREAM_TOSERVER};

mod registry;
use registry::ParserRegistry;

mod five_tuple;
use five_tuple::{FiveTuple,ToFiveTuple};

struct GlobalState {
    registry: ParserRegistry,
    sessions: HashMap<FiveTuple, Box<RParser>>,
}

impl GlobalState {
    pub fn new() -> GlobalState {
        GlobalState{
            registry: ParserRegistry::new(),
            sessions: HashMap::new(),
        }
    }
}

fn parse_data_as(parser: &mut RParser, i: &[u8], direction: u8)
{
    if i.len() == 0 {
        return;
    }

    // let mut state = TLS_STATE.lock().unwrap();
    // state.parse_tcp_level(i);
    parser.parse(i, direction);
}

fn parse_tcp(ipv4: &Ipv4Packet, tcp: &TcpPacket, _ptype: &String, globalstate: &mut GlobalState) {
    debug!("    TCP {:?}:{} -> {:?}:{}",
           ipv4.get_source(), tcp.get_source(),
           ipv4.get_destination(), tcp.get_destination());
    //debug!("tcp payload: {:?}", tcp.payload());
    let mut payload = tcp.payload();
    // heuristic to catch vss-monitoring extra bytes
    // if ipv4.packet_size() + tcp.packet().len() != (ipv4.get_total_length() as usize) {
    //     info!("ipv4.packet_size: {}", ipv4.packet_size());
    //     info!("tcp.packet.len: {}", tcp.packet().len());
    //     info!("ipv4.get_total_length: {}", ipv4.get_total_length());
    //     let extra = (ipv4.packet_size() + tcp.packet().len()) - (ipv4.get_total_length() as usize);
    //     info!("Removing {} extra bytes",extra);
    //     let new_len = payload.len() - extra;
    //     payload = &payload[0..new_len];
    // };
    // empty payload (e.g. SYN)
    if payload.len() == 0 { return; }

    // get 5-tuple
    let src = ipv4.get_source();
    let dst = ipv4.get_destination();
    let (proto,sport,dport) = (6,tcp.get_source(),tcp.get_destination());
    let mut five_t = FiveTuple{
        proto: proto,
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        src_port: sport,
        dst_port: dport,
    };
    let mut direction : u8 = STREAM_TOSERVER;
    debug!("5T: {:?}", five_t);

    if !globalstate.sessions.contains_key(&five_t) {
        // not found, lookup reverse hash
        let rev_five_t = five_t.get_reverse();
        debug!("rev 5T: {:?}", rev_five_t);
        if globalstate.sessions.contains_key(&rev_five_t) {
            debug!("found reverse hash");
            five_t = rev_five_t;
            direction = STREAM_TOCLIENT;
        } else {
            debug!("Creating new session");
            // probe TCP data
            match ParserRegistry::probe(payload, Some(6)) {
                Some(s) => {
                    debug!("Protocol recognized as {}", s);
                    match globalstate.registry.create(s) {
                        Ok(p)  => {
                            globalstate.sessions.insert(five_t.clone(), p);
                        }
                        Err(_) => error!("Protocol was guessed, but cannot instanciate parser"),
                    }
                },
                None => error!("Could not guess TCP protocol"),
            }
        }

    }

    let pp  = globalstate.sessions.get_mut(&five_t).unwrap();
    let p = &mut (**pp);

    // really parse
    parse_data_as(p, payload, direction);
}

fn parse_udp(ipv4: &Ipv4Packet, udp: &UdpPacket, _ptype: &String, globalstate: &mut GlobalState) {
    debug!("    UDP {:?}:{} -> {:?}:{}",
           ipv4.get_source(), udp.get_source(),
           ipv4.get_destination(), udp.get_destination());
    //debug!("udp payload: {:?}", udp.payload());
    let mut payload = udp.payload();
    // heuristic to catch vss-monitoring extra bytes
    // XXX if ipv4.packet_size() + udp.packet().len() != (ipv4.get_total_length() as usize) {
    // XXX     let extra = (ipv4.packet_size() + udp.packet().len()) - (ipv4.get_total_length() as usize);
    // XXX     info!("Removing {} extra bytes",extra);
    // XXX     let new_len = payload.len() - extra;
    // XXX     payload = &payload[0..new_len];
    // XXX };
    // empty payload
    if payload.len() == 0 { return; }

    // get 5-tuple
    let src = ipv4.get_source();
    let dst = ipv4.get_destination();
    let (proto,sport,dport) = (17,udp.get_source(),udp.get_destination());
    let mut five_t = FiveTuple{
        proto: proto,
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        src_port: sport,
        dst_port: dport,
    };
    let mut direction : u8 = STREAM_TOSERVER;
    debug!("5T: {:?}", five_t);

    if !globalstate.sessions.contains_key(&five_t) {
        // not found, lookup reverse hash
        let rev_five_t = five_t.get_reverse();
        debug!("rev 5T: {:?}", rev_five_t);
        if globalstate.sessions.contains_key(&rev_five_t) {
            debug!("found reverse hash");
            five_t = rev_five_t;
            direction = STREAM_TOCLIENT;
        } else {
            debug!("Creating new session");
            // probe UDP data
            match ParserRegistry::probe(payload, Some(17)) {
                Some(s) => {
                    debug!("Protocol recognized as {}", s);
                    match globalstate.registry.create(s) {
                        Ok(p)  => {
                            globalstate.sessions.insert(five_t.clone(), p);
                        }
                        Err(_) => error!("Protocol was guessed, but cannot instanciate parser"),
                    }
                },
                None => error!("Could not guess UDP protocol"),
            }
        }

    }

    let pp  = globalstate.sessions.get_mut(&five_t).unwrap();
    let p = &mut (**pp);

    // really parse
    parse_data_as(p, payload, direction);
}

fn parse(data:&[u8], ptype: &String, globalstate: &mut GlobalState) {
    debug!("----------------------------------------");
    debug!("raw packet:\n{}", data.to_hex(16));

    //let ref ether = EthernetPacket::new(packet.data).unwrap();
    let ref ipv4 = Ipv4Packet::new(data).unwrap();
    // debug!("next level proto: {:?}", ipv4.get_next_level_protocol());


    match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                parse_tcp(&ipv4, &tcp, ptype, globalstate);
            }
        },
        IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                parse_udp(&ipv4, &udp, ptype, globalstate);
            }
        },
        _ => ()
    }
}

fn get_data_raw<'a>(packet: &'a pcap_parser::Packet) -> &'a[u8] {
    // debug!("data.len: {}, caplen: {}", packet.data.len(), packet.header.caplen);
    let maxlen = packet.header.caplen as usize;
    &packet.data[..maxlen]
}

/// See http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
fn get_data_linux_cooked<'a>(packet: &'a pcap_parser::Packet) -> &'a[u8] {
    // debug!("data.len: {}, caplen: {}", packet.data.len(), packet.header.caplen);
    let maxlen = packet.header.caplen as usize;
    &packet.data[16..maxlen]
}

fn get_data_raw_ipv4<'a>(packet: &'a pcap_parser::Packet) -> &'a[u8] {
    // debug!("data.len: {}, caplen: {}", packet.data.len(), packet.header.caplen);
    let maxlen = packet.header.caplen as usize;
    &packet.data[..maxlen]
}

// BSD loopback encapsulation; the link layer header is a 4-byte field, in host byte order,
// containing a value of 2 for IPv4 packets, a value of either 24, 28, or 30 for IPv6 packets, a
// value of 7 for OSI packets, or a value of 23 for IPX packets. All of the IPv6 values correspond
// to IPv6 packets; code reading files should check for all of them.
// Note that ``host byte order'' is the byte order of the machine on which the packets are
// captured; if a live capture is being done, ``host byte order'' is the byte order of the machine
// capturing the packets, but if a ``savefile'' is being read, the byte order is not necessarily
// that of the machine reading the capture file.
fn get_data_null<'a>(packet: &'a pcap_parser::Packet) -> &'a[u8] {
    // debug!("data.len: {}, caplen: {}", packet.data.len(), packet.header.caplen);
    let maxlen = packet.header.caplen as usize;
    &packet.data[4..maxlen]
}

fn get_data_ethernet<'a>(packet: &'a pcap_parser::Packet) -> &'a[u8] {
    // debug!("data.len: {}, caplen: {}", packet.data.len(), packet.header.caplen);
    let maxlen = packet.header.caplen as usize;
    &packet.data[14..maxlen]
}

fn iter_capture<C: Capture>(cap: &mut C, ptype: &String, mut globalstate: &mut GlobalState) {
    let get_data = match cap.get_datalink() {
        pcap_parser::Linktype(0) => get_data_null,
        pcap_parser::Linktype(1) => get_data_ethernet,
        pcap_parser::Linktype(101) => get_data_raw,
        pcap_parser::Linktype(113) => get_data_linux_cooked,
        pcap_parser::Linktype(228) => get_data_raw_ipv4,
        pcap_parser::Linktype(239) => pcap_parser::get_data_nflog,
        pcap_parser::Linktype(x)   => panic!("Unsupported link type {}", x),
    };
    //
    for packet in cap.iter_packets() {
        let data = get_data(&packet);
        parse(data, ptype, &mut globalstate);
    }
}

fn main() {
    let _ = env_logger::init();

    let mut verbose = false;
    let mut parser = "tls".to_string();
    let mut filename = "".to_string();

    {  // this block limits scope of borrows by ap.refer() method
        let mut ap = ArgumentParser::new();
        ap.set_description("Greet somebody.");
        ap.refer(&mut verbose)
            .add_option(&["-v", "--verbose"], StoreTrue,
            "Be verbose");
        ap.refer(&mut parser)
            .add_option(&["-p","--parser"], Store,
            "Parser to use");
        ap.refer(&mut filename)
            .add_option(&["-f","--file"], Store,
            "File to parse");
        ap.parse_args_or_exit();
    }

    let mut globalstate = GlobalState::new();

    let path = Path::new(&filename);
    let display = path.display();
    let mut file = match File::open(path) {
        // The `description` method of `io::Error` returns a string that
        // describes the error
        Err(why) => panic!("couldn't open {}: {}", display,
                           why.description()),
        Ok(file) => file,
    };

    let mut buffer = Vec::new();
    match file.read_to_end(&mut buffer) {
        Err(why) => panic!("couldn't open {}: {}", display,
                           why.description()),
        Ok(_) => (),
    };

    // try pcap first
    match pcap_parser::PcapCapture::from_file(&buffer) {
        Ok(mut cap) => {
            debug!("PCAP found");
            iter_capture(&mut cap, &parser, &mut globalstate);
            return;
        },
        _e => (), // debug!("probing for PCAP failed: {:?}", e),
    }

    // try pcapng
    match pcap_parser::PcapNGCapture::from_file(&buffer) {
        Ok(mut cap) => {
            iter_capture(&mut cap, &parser, &mut globalstate);
        },
        _e  => (),
    }
}
