#[macro_use]
extern crate log;
extern crate env_logger;

extern crate pnet;

extern crate pcap_parser;

use std::collections::HashMap;

use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[macro_use]
extern crate lazy_static;

extern crate clap;
use clap::{Arg,App,crate_version};

use std::net::IpAddr;

//use pnet::packet::PacketSize;
use pnet::packet::Packet;
//use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use pnet::packet::ip::IpNextHeaderProtocols;

use pcap_parser::{Block, PcapBlockOwned};
use pcap_parser::data::PacketData;
use pcap_parser::traits::PcapReaderIterator;

extern crate nom;
use nom::ErrorKind;
use nom::HexDisplay;

extern crate rusticata;
use rusticata::{RParser,STREAM_TOCLIENT,STREAM_TOSERVER};

mod registry;
use registry::ParserRegistry;

mod five_tuple;
use five_tuple::FiveTuple;

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

fn parse_tcp(src: IpAddr, dst: IpAddr, tcp: &TcpPacket, l4_hint: Option<&str>, globalstate: &mut GlobalState) {
    debug!("    TCP {:?}:{} -> {:?}:{}",
           src, tcp.get_source(),
           dst, tcp.get_destination());
    //debug!("tcp payload: {:?}", tcp.payload());
    let payload = tcp.payload();
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
    let (proto,sport,dport) = (6,tcp.get_source(),tcp.get_destination());
    let mut five_t = FiveTuple{
        proto: proto,
        src: src,
        dst: dst,
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
            match ParserRegistry::probe(payload, Some(6), l4_hint) {
                Some(s) => {
                    debug!("Protocol recognized as {}", s);
                    match globalstate.registry.create(&s) {
                        Ok(p)  => {
                            globalstate.sessions.insert(five_t.clone(), p);
                        }
                        Err(_) => error!("Protocol was guessed, but cannot instanciate parser"),
                    }
                },
                None => { warn!("Could not guess TCP protocol"); return; },
            }
        }

    }

    let pp  = globalstate.sessions.get_mut(&five_t).unwrap();
    let p = &mut (**pp);

    // really parse
    parse_data_as(p, payload, direction);
}

fn parse_udp(src: IpAddr, dst: IpAddr, udp: &UdpPacket, l4_hint: Option<&str>, globalstate: &mut GlobalState) {
    debug!("    UDP {:?}:{} -> {:?}:{}",
           src, udp.get_source(),
           dst, udp.get_destination());
    //debug!("udp payload: {:?}", udp.payload());
    let payload = udp.payload();
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
    let (proto,sport,dport) = (17,udp.get_source(),udp.get_destination());
    let mut five_t = FiveTuple{
        proto: proto,
        src: src,
        dst: dst,
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
            match ParserRegistry::probe(payload, Some(17), l4_hint) {
                Some(s) => {
                    debug!("Protocol recognized as {}", s);
                    match globalstate.registry.create(&s) {
                        Ok(p)  => {
                            globalstate.sessions.insert(five_t.clone(), p);
                        }
                        Err(_) => error!("Protocol was guessed, but cannot instanciate parser"),
                    }
                },
                None => { warn!("Could not guess UDP protocol"); return; },
            }
        }

    }

    let pp  = globalstate.sessions.get_mut(&five_t).unwrap();
    let p = &mut (**pp);

    // really parse
    parse_data_as(p, payload, direction);
}

fn parse(data:&[u8], ptype: Option<&str>, globalstate: &mut GlobalState) {
    debug!("----------------------------------------");
    debug!("raw packet:\n{}", data.to_hex(16));

    if data.is_empty() { return; }

    // check L3 protocol
    match data[0] & 0xf0 {
        0x40 => { // IPv4
            //let ref ether = EthernetPacket::new(packet.data).unwrap();
            let ipv4 = &Ipv4Packet::new(data).unwrap();
            // debug!("next level proto: {:?}", ipv4.get_next_level_protocol());

            let src = IpAddr::V4(ipv4.get_source());
            let dst = IpAddr::V4(ipv4.get_destination());

            match ipv4.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                        parse_tcp(src, dst, &tcp, ptype, globalstate);
                    }
                },
                IpNextHeaderProtocols::Udp => {
                    if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                        parse_udp(src, dst, &udp, ptype, globalstate);
                    }
                },
                _ => ()
            }
        },
        0x60 => { // IPv6
            let ipv6 = &Ipv6Packet::new(data).unwrap();
            debug!("next level proto: {:?}", ipv6.get_next_header());
            let src = IpAddr::V6(ipv6.get_source());
            let dst = IpAddr::V6(ipv6.get_destination());
            match ipv6.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                        parse_tcp(src, dst, &tcp, ptype, globalstate);
                    }
                },
                IpNextHeaderProtocols::Udp => {
                    if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                        parse_udp(src, dst, &udp, ptype, globalstate);
                    }
                },
                _ => ()
            }
        },
        _ => { error!("Unknown layer 3 protocol"); }
    }
}

fn iter_capture<R: Read>(reader: &mut PcapReaderIterator<R>, ptype: Option<&str>, mut globalstate: &mut GlobalState) {
    let mut if_linktypes = Vec::new();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                let packetdata = match block {
                    PcapBlockOwned::NG(Block::SectionHeader(ref _shb)) => {
                        if_linktypes = Vec::new();
                        warn!("consuming {} bytes", offset);
                        reader.consume(offset);
                        continue;
                    },
                    PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
                        if_linktypes.push(idb.linktype);
                        warn!("consuming {} bytes", offset);
                        reader.consume(offset);
                        continue;
                    },
                    PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
                        assert!((epb.if_id as usize) < if_linktypes.len());
                        let linktype = if_linktypes[epb.if_id as usize];
                        pcap_parser::data::get_packetdata(epb.data, linktype, epb.caplen as usize)
                            .expect("Parsing PacketData failed")
                    },
                    PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
                        assert!(if_linktypes.len() > 0);
                        let linktype = if_linktypes[0];
                        let blen = (spb.block_len1 - 16) as usize;
                        pcap_parser::data::get_packetdata(spb.data, linktype, blen)
                            .expect("Parsing PacketData failed")
                    },
                    PcapBlockOwned::LegacyHeader(ref hdr) => {
                        if_linktypes.push(hdr.network);
                        debug!("Legacy pcap,  link type: {}", hdr.network);
                        warn!("consuming {} bytes", offset);
                        reader.consume(offset);
                        continue;
                    },
                    PcapBlockOwned::Legacy(ref b) => {
                        assert!(if_linktypes.len() > 0);
                        let linktype = if_linktypes[0];
                        let blen = b.caplen as usize;
                        pcap_parser::data::get_packetdata(b.data, linktype, blen)
                            .expect("Parsing PacketData failed")
                    },
                    PcapBlockOwned::NG(Block::NameResolution(_)) => {
                        reader.consume(offset);
                        continue;
                    },
                    _ => {
                        debug!("unsupported block");
                        return;
                    }
                };
                let data = match packetdata {
                    PacketData::L2(data) => {
                        assert!(data.len() >= 14);
                        &data[14..]
                    },
                    PacketData::L3(_, data) => data,
                    _ => panic!("unsupported packet data type"),
                };
                parse(data, ptype, &mut globalstate);
                reader.consume(offset);
            }
            Err(ErrorKind::Eof) => break,
            Err(ErrorKind::Complete) => {
                warn!("Could not read complete data block.");
                warn!("Hint: the reader buffer size may be too small, or the input file nay be truncated.");
                break
            },
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
}

fn try_open_capture<'r, R: Read + 'r>(inner: R) -> Result<Box<PcapReaderIterator<R> + 'r>,&'static str> {
    match pcap_parser::create_reader(65536, inner) {
        Ok(r) => Ok(r),
        Err(e) => {
            warn!("Error while creating reader: {:?}", e);
            Err("Format not recognized")
        }
    }
}

fn main() {
    env_logger::init();

    let matches = App::new("Pcap parsing tool")
        .version(crate_version!())
        .author("Pierre Chifflier")
        .about("Parse pcap file and apply application-layer parsers")
        .arg(Arg::with_name("verbose")
             .help("Be verbose")
             .short("v")
             .long("verbose"))
        .arg(Arg::with_name("parser")
             .help("Name of parser to use")
             .short("p")
             .long("parser")
             .takes_value(true))
        .arg(Arg::with_name("INPUT")
             .help("Input file name")
             .required(true)
             .index(1))
        .get_matches();

    let filename = matches.value_of("INPUT").unwrap();
    let parser = matches.value_of("parser");
    let verbose = matches.is_present("verbose");

    let mut globalstate = GlobalState::new();

    let path = Path::new(&filename);
    let display = path.display();
    let file = match File::open(path) {
        // The `description` method of `io::Error` returns a string that
        // describes the error
        Err(why) => panic!("couldn't open {}: {}", display,
                           why.description()),
        Ok(file) => file,
    };

    match try_open_capture(file) {
        Ok(mut cap) => {
            iter_capture(cap.as_mut(), parser, &mut globalstate);
        },
        Err(e) => debug!("Failed to open file: {:?}", e),
    }

    if verbose {
        debug!("Done.");
        debug!("Stats:");
        debug!("    Num sessions: {}", globalstate.sessions.len());
    }
}
