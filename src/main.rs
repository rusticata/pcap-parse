#[macro_use]
extern crate log;
extern crate env_logger;

extern crate pcap;
extern crate pnet;

#[macro_use]
extern crate lazy_static;

use std::sync::Mutex;

use std::env;

use pnet::packet::PacketSize;
use pnet::packet::Packet;
//use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;

use pnet::packet::ip::IpNextHeaderProtocols;

extern crate nom;
use nom::IResult;

extern crate tls_parser;
use tls_parser::tls::{TlsMessage,TlsMessageHandshake,parse_tls_raw_record,parse_tls_record_with_header};
use tls_parser::tls_ciphers::TlsCipherSuite;
use tls_parser::tls_extensions::parse_tls_extensions;
use tls_parser::tls_states::*;

extern crate rusticata;
use rusticata::TlsParserState;

struct PcapTlsParserState {
    buffer: Vec<u8>,
    tls_state: TlsState,
}

impl PcapTlsParserState {
    fn new() -> PcapTlsParserState {
        PcapTlsParserState{
            // capacity is the amount of space allocated, which means elements can be added
            // without reallocating the vector
            buffer: Vec::with_capacity(16384),
            tls_state: TlsState::None,
        }
    }

    fn append_buffer<'b>(self: &mut PcapTlsParserState, buf: &'b[u8]) {
        self.buffer.extend_from_slice(&buf);
    }
}

lazy_static! {
    static ref TLS_STATE : Mutex<TlsParserState<'static>> = Mutex::new(TlsParserState::new(b"boo"));
}

fn handle_parsed_tls_msg(state: &mut PcapTlsParserState, msg: &TlsMessage) {
    debug!("msg: {:?}",*msg);
    match tls_state_transition(state.tls_state, msg) {
        Ok(s)  => state.tls_state = s,
        Err(_) => {
            state.tls_state = TlsState::Invalid;
            warn!("Invalid state transition");
        },
    };
    debug!("New TLS state: {:?}",state.tls_state);
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

fn parse_data_as_tls(i: &[u8]) {
    if i.len() == 0 {
        return;
    }

    let mut state = TLS_STATE.lock().unwrap();

    state.parse_tcp_level(i);
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
                let mut payload = tcp.payload();
                // heuristic to catch vss-monitoring extra bytes
                if ipv4.packet_size() + tcp.packet().len() != (ipv4.get_total_length() as usize) {
                    let extra = (ipv4.packet_size() + tcp.packet().len()) - (ipv4.get_total_length() as usize);
                    info!("Removing {} extra bytes",extra);
                    let new_len = payload.len() - extra;
                    payload = &payload[0..new_len];
                };

                // XXX check if data is indeed TLS
                parse_data_as_tls(payload);
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
