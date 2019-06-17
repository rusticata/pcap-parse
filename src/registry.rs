use rusticata::*;

pub struct ParserRegistry {}

impl ParserRegistry {
    pub fn create_ikev2<'a>() -> IPsecParser<'a> { IPsecParser::new(b"IKEv2") }
    pub fn create_kerberos_tcp<'a>() -> KerberosParserTCP<'a> { KerberosParserTCP::new(b"Kerberos/TCP") }
    pub fn create_kerberos_udp<'a>() -> KerberosParserUDP<'a> { KerberosParserUDP::new(b"Kerberos/UDP") }
    pub fn create_ntp<'a>() -> NtpParser<'a> { NtpParser::new(b"NTP") }
    pub fn create_openvpn_tcp<'a>() -> OpenVPNTCPParser<'a> { OpenVPNTCPParser::new(b"OpenVPN/TCP") }
    pub fn create_openvpn_udp<'a>() -> OpenVPNUDPParser<'a> { OpenVPNUDPParser::new(b"OpenVPN/UDP") }
    pub fn create_radius<'a>() -> RadiusParser<'a> { RadiusParser::new(b"Radius") }
    pub fn create_snmpv1<'a>() -> SNMPParser<'a> { SNMPParser::new(b"SNMPv1", 1) }
    pub fn create_snmpv3<'a>() -> SNMPv3Parser<'a> { SNMPv3Parser::new(b"SNMPv3") }
    pub fn create_ssh<'a>() -> SSHParser<'a> { SSHParser::new(b"SSH") }
    pub fn create_tls<'a>() -> TlsParser<'a> { TlsParser::new(b"TLS") }

    pub fn create<'a>(&self, s: &str) -> Result<Box<RParser>,&'static str> {
        match s {
            "kerberos_tcp" => Ok(Box::new(Self::create_kerberos_tcp())),
            "kerberos_udp" => Ok(Box::new(Self::create_kerberos_udp())),
            "ikev2"        => Ok(Box::new(Self::create_ikev2())),
            "ipsec"        => Ok(Box::new(Self::create_ikev2())),
            "ntp"          => Ok(Box::new(Self::create_ntp())),
            "openvpn_tcp"  => Ok(Box::new(Self::create_openvpn_tcp())),
            "openvpn_udp"  => Ok(Box::new(Self::create_openvpn_udp())),
            "radius"       => Ok(Box::new(Self::create_radius())),
            "snmp"         => Ok(Box::new(Self::create_snmpv1())),
            "snmpv1"       => Ok(Box::new(Self::create_snmpv1())),
            "snmpv3"       => Ok(Box::new(Self::create_snmpv3())),
            "ssh"          => Ok(Box::new(Self::create_ssh())),
            "tls"          => Ok(Box::new(Self::create_tls())),
            _              => Err("unknown parser type")
        }
    }

    /// Probe data and return protocol if found
    // XXX return a list of protocols if severals are matching ???
    pub fn probe(i:&[u8], l3_hint:Option<u16>) -> Option<&'static str> {
        if l3_hint == None || l3_hint == Some(6) {
            if tls_probe(i) { return Some("tls"); }
            if ssh_probe(i) { return Some("ssh"); }
            if kerberos_probe_tcp(i) { return Some("kerberos_tcp"); }
            if openvpn_tcp_probe(i) { return Some("openvpn_tcp"); }
        }
        if l3_hint == None || l3_hint == Some(17) {
            if ipsec_probe(i) { return Some("ikev2"); }
            if kerberos_probe_udp(i) { return Some("kerberos_udp"); }
            if ntp_probe(i) { return Some("ntp"); }
            if openvpn_udp_probe(i) { return Some("openvpn_udp"); }
            if snmp_probe(i) { return Some("snmp"); }
            if snmpv3_probe(i) { return Some("snmpv3"); }
        }
        None
    }

    pub fn new() -> ParserRegistry { ParserRegistry{} }
}
