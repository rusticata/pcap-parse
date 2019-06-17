use rusticata::*;
use std::collections::HashMap;

pub struct ParserRegistry {}

lazy_static! {
    static ref BUILDER_MAP: HashMap<&'static str, Box<RBuilder>> = {
        let mut m = HashMap::new();
        m.insert("dns_udp", Box::new(DnsUDPBuilder{}) as Box<_>);
        m.insert("dns_tcp", Box::new(DnsTCPBuilder{}) as Box<_>);
        m.insert("ikev2", Box::new(IPsecBuilder{}) as Box<_>);
        m.insert("ikev2_natt", Box::new(IPsecNatTBuilder{}) as Box<_>);
        m.insert("kerberos_probe_tcp", Box::new(KerberosTCPBuilder{}) as Box<_>);
        m.insert("kerberos_probe_udp", Box::new(KerberosUDPBuilder{}) as Box<_>);
        m.insert("ntp", Box::new(NTPBuilder{}) as Box<_>);
        m.insert("openvpn_tcp", Box::new(OpenVPNTCPBuilder{}) as Box<_>);
        m.insert("openvpn_udp", Box::new(OpenVPNUDPBuilder{}) as Box<_>);
        m.insert("radius", Box::new(RadiusBuilder{}) as Box<_>);
        m.insert("snmpv1", Box::new(SNMPv1Builder{}) as Box<_>);
        m.insert("snmpv2c", Box::new(SNMPv2cBuilder{}) as Box<_>);
        m.insert("snmpv3", Box::new(SNMPv3Builder{}) as Box<_>);
        m.insert("ssh", Box::new(SSHBuilder{}) as Box<_>);
        m.insert("tls", Box::new(TLSBuilder{}) as Box<_>);
        m
    };
}

impl ParserRegistry {
    pub fn create<'a>(&self, s: &str) -> Result<Box<RParser>,&'static str> {
        if let Some(builder) = BUILDER_MAP.get(s) {
            return Ok(builder.new())
        }
        Err("unknown parser type")
    }

    /// Probe data and return protocol if found
    // XXX return a list of protocols if severals are matching ???
    pub fn probe(i:&[u8], l3_hint:Option<u16>, l4_hint:Option<&str>) -> Option<String> {
        if let Some(parser_name) = l4_hint {
            debug!("probe: testing protocol {}", parser_name);
            if let Some(builder) = BUILDER_MAP.get(parser_name) {
                if builder.probe(i) { return Some(parser_name.to_string()); }
            }
            debug!("probe: protocol {} not recognized, using regular tests", parser_name);
        }
        if l3_hint == None || l3_hint == Some(6) {
            if dns_probe_tcp(i) { return Some("dns_tcp".to_string()); }
            if tls_probe(i) { return Some("tls".to_string()); }
            if ssh_probe(i) { return Some("ssh".to_string()); }
            if kerberos_probe_tcp(i) { return Some("kerberos_tcp".to_string()); }
            if openvpn_tcp_probe(i) { return Some("openvpn_tcp".to_string()); }
        }
        if l3_hint == None || l3_hint == Some(17) {
            if dns_probe_udp(i) { return Some("dns_udp".to_string()); }
            if ipsec_probe(i) { return Some("ikev2".to_string()); }
            if ikev2_natt_probe(i) { return Some("ikev2_natt".to_string()); }
            if kerberos_probe_udp(i) { return Some("kerberos_udp".to_string()); }
            if ntp_probe(i) { return Some("ntp".to_string()); }
            if openvpn_udp_probe(i) { return Some("openvpn_udp".to_string()); }
            if snmpv1_probe(i) { return Some("snmpv1".to_string()); }
            if snmpv2c_probe(i) { return Some("snmpv2c".to_string()); }
            if snmpv3_probe(i) { return Some("snmpv3".to_string()); }
        }
        None
    }

    pub fn new() -> ParserRegistry { ParserRegistry{} }
}
