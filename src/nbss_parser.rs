use crate::error::*;
use crate::nbss_types::*;
use crate::nom;
use dns_parser::Name;
use nom::error::ParseError;
use nom::multi::count;
use nom::number::streaming::{be_u16, be_u32, be_u8};
use nom::{bytes::streaming::take, IResult};
use std::net::Ipv4Addr;

pub(crate) fn be_u48<'a, E: ParseError<&'a [u8]>>(i: &'a [u8]) -> IResult<&'a [u8], u64, E> {
    let (i, hb) = be_u32(i)?;
    let (i, lb) = be_u16(i)?;
    let n = ((hb as u64) << 16) | (lb as u64);
    Ok((i, n))
}

/// Parse a NetBIOS Name Service Header
pub fn parse_nbss_header(i: &[u8]) -> Result<NbssHeader> {
    let (rem, bytes) = take(NbssHeader::size())(i)?;
    let name_trn_id = ((bytes[0] as u16) << 8) + (bytes[1]) as u16;
    let fields_16_32 = ((bytes[2] as u16) << 8) + (bytes[3] as u16);
    let qdcount = ((bytes[4] as u16) << 8) + (bytes[5] as u16);
    let ancount = ((bytes[6] as u16) << 8) + (bytes[7] as u16);
    let nscount = ((bytes[8] as u16) << 8) + (bytes[9] as u16);
    let arcount = ((bytes[10] as u16) << 8) + (bytes[11] as u16);
    Ok((
        rem,
        NbssHeader {
            name_trn_id,
            fields_16_32,
            qdcount,
            ancount,
            nscount,
            arcount,
        },
    ))
}

fn parse_node_name(i: &[u8]) -> Result<NodeName> {
    let (rem, b) = take(16usize)(i)?;
    let s = std::string::String::from_utf8_lossy(b);
    let name = NetbiosName::from_bytes(s.as_bytes())?;
    let (rem, name_flags) = be_u16(rem)?;
    Ok((rem, NodeName { name, name_flags }))
}

fn parse_rdata(b: &[u8], rtype: RType) -> Result<RData> {
    match rtype {
        RType::NB => {
            let (rem, nb_flags) = be_u16(b)?;
            let (rem, addr) = take(4usize)(rem)?;
            let nb_address = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
            Ok((
                rem,
                RData::NB {
                    nb_flags,
                    nb_address,
                },
            ))
        }
        RType::NBSTAT => {
            // let (rem, d) = length_data(be_u16)(b)?;
            let (d, num_names) = be_u8(b)?;
            let (rem, names) = count(parse_node_name, num_names as usize)(d)?;
            let (rem, stats) = NodeStatistics::parse(rem)?;
            Ok((rem, RData::NBStat { names, stats }))
        }
        _ => Ok((&[], RData::Unknown(b))),
    }
}

/// Parse a NetBIOS Name Service Packet (query or response)
pub fn parse_nbss_packet(i: &[u8]) -> Result<NbssPacket> {
    let original_data = i;
    let (_, header) = parse_nbss_header(i)?;
    let mut offset = NbssHeader::size();
    let num_questions = header.qdcount as usize;
    // do not allocate with capacity (risk of DoS)
    let mut questions = Vec::new();
    for _ in 0..num_questions {
        let name = Name::scan(&original_data[offset..], original_data)
            .map_err(|_| NetbiosError::InvalidQuestion)?;
        offset += name.byte_len();
        let qname = EncodedName(name.to_string());
        let (rem, qtype) = QType::parse(&original_data[offset..])?;
        let (_, qclass) = RClass::parse(rem)?;
        offset += 4;
        let q = NetbiosQuestion {
            qname,
            qtype,
            qclass,
        };
        questions.push(q);
    }
    let (_, rr_answer) =
        parse_resource_records(header.ancount as usize, original_data, &mut offset)?;
    let (_, rr_authority) =
        parse_resource_records(header.nscount as usize, original_data, &mut offset)?;
    let (_, rr_additional) =
        parse_resource_records(header.arcount as usize, original_data, &mut offset)?;
    Ok((
        &original_data[offset..],
        NbssPacket {
            header,
            questions,
            rr_answer,
            rr_authority,
            rr_additional,
        },
    ))
}

fn parse_resource_records<'a>(
    num_records: usize,
    original_data: &'a [u8],
    offset: &'_ mut usize,
) -> Result<'a, Vec<NetbiosResource<'a>>> {
    let mut resources = Vec::new();
    for _ in 0..num_records {
        let name = Name::scan(&original_data[*offset..], original_data)
            .map_err(|_| NetbiosError::InvalidAnswer)?;
        *offset += name.byte_len();
        let rr_name = EncodedName(name.to_string());
        let data = &original_data[*offset..];
        let (rem, rr_type) = RType::parse(data)?;
        let (rem, rr_class) = RClass::parse(rem)?;
        let (rem, ttl) = be_u32(rem)?;
        let (rem, rd_length) = be_u16(rem)?;
        let (_, b) = take(rd_length as usize)(rem)?;
        let (_, rdata) = parse_rdata(b, rr_type)?;
        *offset += (10 + rd_length) as usize;
        let r = NetbiosResource {
            rr_name,
            rr_type,
            rr_class,
            ttl,
            rdata,
        };
        resources.push(r);
    }
    Ok((&original_data[*offset..], resources))
}
