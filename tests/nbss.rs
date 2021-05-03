use hex_literal::hex;
use netbios_parser::*;
use std::net::Ipv4Addr;

#[test]
fn nbns_request() {
    let data = &hex!(
        "
        2f 53 01 10 00 01 00 00 00 00 00 00 20 46 41 45
        50 46 45 45 42 46 45 45 50 43 41 43 41 43 41 43
        41 43 41 43 41 43 41 43 41 43 41 41 41 00 00 20
        00 01
"
    );
    let (rem, packet) = parse_nbss_packet(data).expect("parse packet");
    assert!(rem.is_empty());
    assert_eq!(packet.questions.len(), 1);
    let name = packet.questions[0].qname.decode().expect("decode name");
    assert_eq!(name.to_string(), "POTATO<0>");
}

#[test]
fn nbns_response() {
    let data = &hex!(
        "
        2f 53 85 80 00 00 00 01 00 00 00 00 20 46 41 45
        50 46 45 45 42 46 45 45 50 43 41 43 41 43 41 43
        41 43 41 43 41 43 41 43 41 43 41 41 41 00 00 20
        00 01 00 03 f4 80 00 06 00 00 c0 a8 01 41            
"
    );
    let (rem, packet) = parse_nbss_packet(data).expect("parse packet");
    assert!(rem.is_empty());
    assert_eq!(packet.rr_answer.len(), 1);
    let answer0 = &packet.rr_answer[0];
    let name = answer0.rr_name.decode().expect("decode name");
    assert_eq!(name.to_string(), "POTATO<0>");
    assert_eq!(
        answer0.rdata,
        RData::NB {
            nb_flags: 0,
            nb_address: Ipv4Addr::new(192, 168, 1, 65)
        }
    );
}

#[test]
fn nbns_request_nbstat() {
    let data = &hex!(
        "
        7c 26 00 00 00 01 00 00 00 00 00 00 20 45 4e 46
        44 45 49 45 50 45 4e 45 46 43 41 43 41 43 41 43
        41 43 41 43 41 43 41 43 41 43 41 41 41 00 00 21
        00 01
"
    );
    let (rem, packet) = parse_nbss_packet(data).expect("parse packet");
    assert!(rem.is_empty());
    assert_eq!(packet.questions.len(), 1);
    let a0 = &packet.questions[0];
    let name = a0.qname.decode().expect("decode name");
    assert_eq!(name.to_string(), "MSHOME<0>");
}

#[test]
fn nbns_response_nbstat() {
    let data = &hex!(
        "
        7c 26 84 00 00 00 00 01 00 00 00 00 20 45 4e 46
        44 45 49 45 50 45 4e 45 46 43 41 43 41 43 41 43
        41 43 41 43 41 43 41 43 41 43 41 41 41 00 00 21
        00 01 00 00 00 00 00 ad 07 48 4d 4e 48 44 2d 54
        49 31 4b 4c 53 20 20 20 00 04 00 48 4d 4e 48 44
        2d 54 49 31 4b 4c 53 20 20 20 03 04 00 48 4d 4e
        48 44 2d 54 49 31 4b 4c 53 20 20 20 20 04 00 01
        02 5f 5f 4d 53 42 52 4f 57 53 45 5f 5f 02 01 84
        00 4d 53 48 4f 4d 45 20 20 20 20 20 20 20 20 20
        1d 04 00 4d 53 48 4f 4d 45 20 20 20 20 20 20 20
        20 20 1e 84 00 4d 53 48 4f 4d 45 20 20 20 20 20
        20 20 20 20 00 84 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00
"
    );
    let (rem, packet) = parse_nbss_packet(data).expect("parse packet");
    assert!(rem.is_empty());
    assert_eq!(packet.rr_answer.len(), 1);
    let answer0 = &packet.rr_answer[0];
    let name = answer0.rr_name.decode().expect("decode name");
    assert_eq!(name.to_string(), "MSHOME<0>");
    if let RData::NBStat { names, stats } = &answer0.rdata {
        assert_eq!(names.len(), 7);
        assert_eq!(*stats, NodeStatistics::default());
    } else {
        panic!("unexpected type");
    }
}
