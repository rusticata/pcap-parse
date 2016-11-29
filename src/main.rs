#[macro_use]
extern crate log;
extern crate env_logger;

extern crate pcap;
extern crate pnet;

use std::collections::HashMap;

extern crate argparse;
use argparse::{ArgumentParser, StoreTrue, Store};

use pnet::packet::PacketSize;
use pnet::packet::Packet;
//use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use pnet::packet::ip::IpNextHeaderProtocols;

#[macro_use]
extern crate nom;
use nom::{le_u8,le_u16,IResult};

extern crate rusticata;
use rusticata::IPsecParser;
use rusticata::NtpParser;
use rusticata::TlsParser;
use rusticata::RParser;

fn parse_data_as(parser: &mut RParser, i: &[u8])
{
    if i.len() == 0 {
        return;
    }

    // let mut state = TLS_STATE.lock().unwrap();
    // state.parse_tcp_level(i);
    parser.parse(i,0);
}

fn callback(data:&[u8], p: &mut RParser)
{
    debug!("----------------------------------------");
    debug!("raw packet: {:?}", data);

    //let ref ether = EthernetPacket::new(packet.data).unwrap();
    let ref ipv4 = Ipv4Packet::new(data).unwrap();
    // debug!("next level proto: {:?}", ipv4.get_next_level_protocol());
    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
        match TcpPacket::new(ipv4.payload()) {
            Some(ref tcp) => {
                //debug!("tcp payload: {:?}", tcp.payload());
                let mut payload = tcp.payload();
                // heuristic to catch vss-monitoring extra bytes
                if ipv4.packet_size() + tcp.packet().len() != (ipv4.get_total_length() as usize) {
                    let extra = (ipv4.packet_size() + tcp.packet().len()) - (ipv4.get_total_length() as usize);
                    info!("Removing {} extra bytes",extra);
                    let new_len = payload.len() - extra;
                    payload = &payload[0..new_len];
                };

                // XXX check if data is indeed TLS/...
                parse_data_as(p, payload);
            },
            None => (), // not a TCP packet, ignore
        }
    }
    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
        match UdpPacket::new(ipv4.payload()) {
            Some(ref udp) => {
                let mut payload = udp.payload();
                // heuristic to catch vss-monitoring extra bytes
                if ipv4.packet_size() + udp.packet().len() != (ipv4.get_total_length() as usize) {
                    let extra = (ipv4.packet_size() + udp.packet().len()) - (ipv4.get_total_length() as usize);
                    info!("Removing {} extra bytes",extra);
                    let new_len = payload.len() - extra;
                    payload = &payload[0..new_len];
                };
                // XXX check if data is indeed IPsec/NTP/...
                parse_data_as(p, payload);
            },
            None => (), // not a UDP packet, ignore
        }
    }
}

fn get_data_ethernet<'a>(packet: &'a pcap::Packet) -> &'a[u8] {
    &packet.data[14..]
}

/// See http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
fn get_data_linux_cooked<'a>(packet: &'a pcap::Packet) -> &'a[u8] {
    &packet.data[16..]
}

#[derive(Debug)]
struct NflogTlv<'a> {
    pub l: u16,
    pub t: u16,
    pub v: &'a[u8],
}

named!(parse_nflog_tlv<NflogTlv>,
    do_parse!(
        l: le_u16 >>
        t: le_u16 >>
        v: take!(l-4) >>
        _padding: cond!(l % 4 != 0,take!(4-(l%4))) >>
        ( NflogTlv{l:l,t:t,v:v} )
    )
);

#[derive(Debug)]
struct NflogHdr<'a> {
    pub af: u8,
    pub vers: u8,
    pub res_id: u16,
    pub data: Vec<NflogTlv<'a>>,
}

named!(parse_nflog_header<NflogHdr>,
    dbg_dmp!(
    do_parse!(
        af: le_u8 >>
        v:  le_u8 >>
        id: le_u16 >>
        d:  many0!(parse_nflog_tlv) >>
        (
            NflogHdr{
                af: af,
                vers: v,
                res_id: id,
                data: d,
            }
        )
    )
    )
);

/// See http://www.tcpdump.org/linktypes/LINKTYPE_NFLOG.html
fn get_data_nflog<'a>(packet: &'a pcap::Packet) -> &'a[u8] {
    match parse_nflog_header(packet.data) {
        IResult::Done(_,res) => {
            for v in res.data {
                if v.t == 9 { return v.v; }; // 9: packet payload
            };
            panic!("packet with no payload data");
        },
        e @ _ => panic!("parsing nflog packet header failed: {:?}",e),
    }
}

fn main() {
    let _ = env_logger::init().unwrap();

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

    let mut m : HashMap<String,Box<RParser>> = HashMap::new();
    m.insert("ipsec".to_string(), Box::new(IPsecParser::new(b"IPsec")));
    m.insert("ntp".to_string(), Box::new(NtpParser::new(b"NTP")));
    m.insert("tls".to_string(), Box::new(TlsParser::new(b"TLS")));

    if let Some(mut p) = m.get_mut(&parser) {
        let mut cap = pcap::Capture::from_file(filename).unwrap();
        println!("datalink: {:?}",cap.get_datalink());

        // See http://www.tcpdump.org/linktypes.html
        let get_data = match cap.get_datalink() {
            pcap::Linktype(1) => get_data_ethernet,
            pcap::Linktype(113) => get_data_linux_cooked,
            pcap::Linktype(239) => get_data_nflog,
            _ => panic!("unsupported data link type"),
        };

        while let Ok(packet) = cap.next() {
            let data = get_data(&packet);
            callback(data,&mut (**p));
        }
    } else {
        println!("Unknown parser");
    }
}
