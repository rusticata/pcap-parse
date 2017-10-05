use rusticata::{RParser,IPsecParser,NtpParser,RadiusParser,SnmpParser,SSHParser,TlsParser};

pub struct ParserRegistry {}

impl ParserRegistry {
    pub fn create_ikev2<'a>() -> IPsecParser<'a> { IPsecParser::new(b"IKEv2") }
    pub fn create_ntp<'a>() -> NtpParser<'a> { NtpParser::new(b"NTP") }
    pub fn create_radius<'a>() -> RadiusParser<'a> { RadiusParser::new(b"Radius") }
    pub fn create_snmp<'a>() -> SnmpParser<'a> { SnmpParser::new(b"Snmp") }
    pub fn create_ssh<'a>() -> SSHParser<'a> { SSHParser::new(b"SSH") }
    pub fn create_tls<'a>() -> TlsParser<'a> { TlsParser::new(b"TLS") }

    pub fn create<'a>(&self, s: &String) -> Result<Box<RParser>,&'static str> {
        match s.as_ref() {
            "ikev2"  => Ok(Box::new(Self::create_ikev2())),
            "ipsec"  => Ok(Box::new(Self::create_ikev2())),
            "ntp"    => Ok(Box::new(Self::create_ntp())),
            "radius" => Ok(Box::new(Self::create_radius())),
            "snmp"   => Ok(Box::new(Self::create_snmp())),
            "ssh"    => Ok(Box::new(Self::create_ssh())),
            "tls"    => Ok(Box::new(Self::create_tls())),
            _        => Err("unknown parser type")
        }
    }

    pub fn new() -> ParserRegistry { ParserRegistry{} }
}
