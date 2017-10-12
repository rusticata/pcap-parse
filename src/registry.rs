use rusticata::{RParser,IPsecParser,NtpParser,RadiusParser,SnmpParser,SnmpV3Parser,SSHParser,TlsParser};
use rusticata::{ipsec_probe,ssh_probe,snmp_probe,snmpv3_probe,tls_probe};

pub struct ParserRegistry {}

impl ParserRegistry {
    pub fn create_ikev2<'a>() -> IPsecParser<'a> { IPsecParser::new(b"IKEv2") }
    pub fn create_ntp<'a>() -> NtpParser<'a> { NtpParser::new(b"NTP") }
    pub fn create_radius<'a>() -> RadiusParser<'a> { RadiusParser::new(b"Radius") }
    pub fn create_snmpv1<'a>() -> SnmpParser<'a> { SnmpParser::new(b"SNMPv1", 1) }
    pub fn create_snmpv3<'a>() -> SnmpV3Parser<'a> { SnmpV3Parser::new(b"SNMPv3") }
    pub fn create_ssh<'a>() -> SSHParser<'a> { SSHParser::new(b"SSH") }
    pub fn create_tls<'a>() -> TlsParser<'a> { TlsParser::new(b"TLS") }

    pub fn create<'a>(&self, s: &str) -> Result<Box<RParser>,&'static str> {
        match s {
            "ikev2"  => Ok(Box::new(Self::create_ikev2())),
            "ipsec"  => Ok(Box::new(Self::create_ikev2())),
            "ntp"    => Ok(Box::new(Self::create_ntp())),
            "radius" => Ok(Box::new(Self::create_radius())),
            "snmp"   => Ok(Box::new(Self::create_snmpv1())),
            "snmpv1" => Ok(Box::new(Self::create_snmpv1())),
            "snmpv3" => Ok(Box::new(Self::create_snmpv3())),
            "ssh"    => Ok(Box::new(Self::create_ssh())),
            "tls"    => Ok(Box::new(Self::create_tls())),
            _        => Err("unknown parser type")
        }
    }

    pub fn create_from_string<'a>(&self, s: &String) -> Result<Box<RParser>,&'static str> {
        self.create(s.as_ref())
    }

    /// Probe data and return protocol if found
    // XXX return a list of protocols if severals are matching ???
    pub fn probe(i:&[u8], l3_hint:Option<u16>) -> Option<&'static str> {
        if l3_hint == None || l3_hint == Some(6) {
            if tls_probe(i) { return Some("tls"); }
            if ssh_probe(i) { return Some("ssh"); }
        }
        if l3_hint == None || l3_hint == Some(17) {
            if ipsec_probe(i) { return Some("ikev2"); }
            if snmp_probe(i) { return Some("snmp"); }
            if snmpv3_probe(i) { return Some("snmpv3"); }
        }
        None
    }

    pub fn new() -> ParserRegistry { ParserRegistry{} }
}
