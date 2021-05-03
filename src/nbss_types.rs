use crate::{be_u48, NetbiosError};
use nom_derive::*;
use rusticata_macros::newtype_enum;
use std::fmt;
use std::net::Ipv4Addr;

/// NetBIOS Name Service Header
#[derive(Debug, PartialEq)]
pub struct NbssHeader {
    pub name_trn_id: u16,
    pub(crate) fields_16_32: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl NbssHeader {
    pub const fn size() -> usize {
        12
    }

    pub fn opcode_r(&self) -> bool {
        self.fields_16_32 & (1 << 15) != 0
    }

    pub fn request(&self) -> bool {
        self.fields_16_32 & (1 << 15) == 0
    }

    pub fn response(&self) -> bool {
        self.fields_16_32 & (1 << 15) != 0
    }

    pub fn opcode(&self) -> u8 {
        (self.fields_16_32 >> 10 & 0b1_1111) as u8
    }

    pub fn nm_flags(&self) -> NMFlags {
        NMFlags((self.fields_16_32 >> 4 & 0b0111_1111) as u8)
    }

    pub fn rcode(&self) -> RCode {
        RCode((self.fields_16_32 & 0b1111) as u8)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NMFlags(pub u8);

newtype_enum! {
    impl debug NMFlags {
        Broadcast = 1,
        RecursionAvailable = 0b1000,
        RecursionDesired = 0b1_0000,
        Truncation = 0b10_0000,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RCode(pub u8);

newtype_enum! {
    impl debug RCode {
        NoErr = 0,
        FmtErr = 0x1,
        SrvErr = 0x2,
        ImpErr = 0x4,
        RfsErr = 0x5,
        ActErr = 0x6,
        CftErr = 0x7,
    }
}

/// NetBIOS Name
#[derive(Debug, PartialEq)]
pub struct NetbiosName {
    pub nb_name: String,
    pub nb_type: NetbiosNameType,
}

impl NetbiosName {
    pub fn from_bytes(i: &[u8]) -> Result<Self, NetbiosError<&'static [u8]>> {
        if i.len() != 16 {
            return Err(NetbiosError::InvalidNameLength);
        }
        let nb_type = NetbiosNameType(i[15]);
        let mut s = String::new();
        for b in &i[..15] {
            // remove padding (stop at first space)
            if *b == 0x20 {
                break;
            }
            s.push(*b as char);
        }
        Ok(NetbiosName {
            nb_name: s,
            nb_type,
        })
    }

    /// Attempt to decode the NetBIOS Name and return the decoded name and type
    pub fn decode(s: &str) -> Result<Self, NetbiosError<&[u8]>> {
        let i = s.as_bytes();
        if i.len() != 32 {
            return Err(NetbiosError::InvalidNameLength);
        }
        let mut s = String::new();
        for idx in (0..32).step_by(2) {
            let c = (i[idx].wrapping_sub(0x41) << 4) | (i[idx + 1].wrapping_sub(0x41) & 0x4f);
            s.push(c as char);
        }
        NetbiosName::from_bytes(s.as_bytes())
    }
}

impl fmt::Display for NetbiosName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}<{:x}>", self.nb_name, self.nb_type.0))
    }
}

/// NetBIOS Name
#[derive(Debug)]
pub struct EncodedName(pub(crate) String);

impl EncodedName {
    /// Attempt to decode the NetBIOS Name and return the decoded name and type
    pub fn decode(&self) -> Result<NetbiosName, NetbiosError<&[u8]>> {
        NetbiosName::decode(&self.0)
    }
}

/// NetBIOS Name Service Name Query
#[derive(Debug)]
pub struct NetbiosQuestion {
    pub qname: EncodedName,
    pub qtype: QType,
    pub qclass: RClass,
}

#[derive(Clone, Copy, PartialEq, Eq, NomBE)]
#[nom(GenericErrors)]
pub struct QType(pub u16);

newtype_enum! {
    impl debug QType {
        NB = 0x0020,
        NBSTAT = 0x0021,
    }
}

/// NetBIOS Name Service Packet
#[derive(Debug)]
pub struct NbssPacket<'a> {
    pub header: NbssHeader,
    pub questions: Vec<NetbiosQuestion>,
    pub rr_answer: Vec<NetbiosResource<'a>>,
    pub rr_authority: Vec<NetbiosResource<'a>>,
    pub rr_additional: Vec<NetbiosResource<'a>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NetbiosNameType(pub u8);

newtype_enum! {
    impl debug NetbiosNameType {
        Workstation = 0,
        DomainMasterBrowser = 0x1b,
        LocalMasterBrowser = 0x1d,
        FileServer = 0x20,
    }
}

#[derive(Debug)]
pub struct NetbiosResource<'a> {
    pub rr_name: EncodedName,
    pub rr_type: RType,
    pub rr_class: RClass,
    pub ttl: u32,
    pub rdata: RData<'a>,
}

#[derive(Clone, Copy, PartialEq, Eq, NomBE)]
#[nom(GenericErrors)]
pub struct RType(pub u16);

newtype_enum! {
    impl debug RType {
        A = 0x0001,
        NS = 0x0002,
        NULL = 0x000A,
        NB = 0x0020,
        NBSTAT = 0x0021,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, NomBE)]
#[nom(GenericErrors)]
pub struct RClass(pub u16);

newtype_enum! {
    impl debug RClass {
        IN = 0x0001,
    }
}

#[derive(Debug, PartialEq)]
pub enum RData<'a> {
    NB {
        nb_flags: u16,
        nb_address: Ipv4Addr,
    },
    NBStat {
        names: Vec<NodeName>,
        stats: NodeStatistics,
    },
    Unknown(&'a [u8]),
}

#[derive(Debug, PartialEq)]
pub struct NodeName {
    pub name: NetbiosName,
    pub name_flags: u16,
}

#[derive(Debug, Default, PartialEq, NomBE)]
#[nom(GenericErrors)]
pub struct NodeStatistics {
    // only 48 bits are used
    #[nom(Parse = "be_u48")]
    pub unit_id: u64,
    pub jumpers: u8,
    pub test_result: u8,
    pub version_number: u16,
    pub stats_period: u16,
    pub num_crc: u16,
    pub num_align_errors: u16,
    pub num_collisions: u16,
    pub num_send_aborts: u16,
    pub num_good_sends: u32,
    pub num_good_recvs: u32,
    pub num_retransmits: u16,
    pub num_no_res_conditions: u16,
    pub num_free_cmd_blocks: u16,
    pub num_total_cmd_blocks: u16,
    pub max_total_cmd_blocks: u16,
    pub num_pending_sessions: u16,
    pub max_pending_sessions: u16,
    pub max_total_sessions: u16,
    pub session_data_packet_size: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_fields() {
        let h = NbssHeader {
            name_trn_id: 0xde2b,
            fields_16_32: 0x0110,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        assert_eq!(h.opcode_r(), false);
        assert!(h.request());
        assert_eq!(h.opcode(), 0);
        assert_eq!(h.nm_flags(), NMFlags(0x11));
        assert!(h.nm_flags().0 & NMFlags::Broadcast.0 != 0);
        assert!(h.nm_flags().0 & NMFlags::RecursionDesired.0 != 0);
        assert_eq!(h.rcode(), RCode::NoErr);
    }
}
