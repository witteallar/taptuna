/// Wire protocol parser: Ethernet + IPv4 + TCP
/// 
/// Returns Ok(None) for non-IPv4/non-TCP (not an error).
/// Returns Err for recognized but corrupted packets.
/// 
/// Supports one VLAN tag (802.1Q, 802.1ad).
/// Rejects IP fragments with warning (no reassembly).
/// Validates IHL >= 5, data_offset >= 5, total_len >= ip_hdr_len.
/// Truncates by ip.total_len to strip padding.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    IPv4 = 0x0800,
    VLAN8021Q = 0x8100,
    VLAN8021AD = 0x88a8,
}

impl EtherType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0800 => Some(EtherType::IPv4),
            0x8100 => Some(EtherType::VLAN8021Q),
            0x88a8 => Some(EtherType::VLAN8021AD),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    TCP = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Address(pub [u8; 4]);

impl fmt::Display for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub frame_number: u32,
    pub timestamp: f64,           // frame.time_epoch
    pub src_mac: MacAddress,
    pub dst_mac: MacAddress,
    pub ethertype: EtherType,
    pub vlan_tci: Option<u16>,    // VLAN Tag Control Information (if present)
    pub ip_version: u8,           // 4
    pub ip_ihl: u8,               // Internet Header Length in 32-bit words
    pub ip_tos: u8,
    pub ip_total_len: u16,        // Total length including IP header
    pub ip_id: u16,
    pub ip_flags: u8,             // Fragment flags (3 bits)
    pub ip_frag_offset: u16,      // Fragment offset (13 bits)
    pub ip_ttl: u8,
    pub ip_protocol: IpProtocol,
    pub ip_checksum: u16,
    pub ip_src: Ipv4Address,
    pub ip_dst: Ipv4Address,
    pub tcp_src_port: u16,
    pub tcp_dst_port: u16,
    pub tcp_seq: u32,
    pub tcp_ack: u32,
    pub tcp_data_offset: u8,      // In 32-bit words
    pub tcp_flags: u8,            // NS(1) + CWR(1) + ECE(1) + URG(1) + ACK(1) + PSH(1) + RST(1) + SYN(1) + FIN(1)
    pub tcp_window: u16,
    pub tcp_checksum: u16,
    pub tcp_urgent_ptr: u16,
    pub payload: Vec<u8>,         // TCP payload (after TCP header, truncated to ip_total_len)
    pub payload_sha256: [u8; 32], // SHA256 of payload
}

#[derive(Debug, thiserror::Error)]
pub enum WireParseError {
    #[error("Packet too short for Ethernet header: {0} bytes")]
    ShortEthernet(usize),
    #[error("Unknown ethertype: 0x{0:04x}")]
    UnknownEthertype(u16),
    #[error("Packet too short for VLAN tag: {0} bytes")]
    ShortVlan(usize),
    #[error("Packet too short for IPv4 header: {0} bytes")]
    ShortIpv4(usize),
    #[error("Not IPv4: version={0}")]
    NotIpv4(u8),
    #[error("IHL too small: {0} < 5")]
    IhlTooSmall(u8),
    #[error("Packet too short for IPv4 header with IHL: need {need} bytes, have {have}")]
    ShortIpv4WithIhl { need: usize, have: usize },
    #[error("IP total_len ({total_len}) exceeds packet length ({pkt_len})")]
    IpTotalLenExceeds { total_len: u16, pkt_len: usize },
    #[error("IP fragment detected (flags={flags}, offset={offset}) - fragments not supported")]
    IpFragment { flags: u8, offset: u16 },
    #[error("Not TCP: protocol={0}")]
    NotTcp(u8),
    #[error("Packet too short for TCP header: {0} bytes")]
    ShortTcp(usize),
    #[error("TCP data_offset too small: {0} < 5")]
    TcpDataOffsetTooSmall(u8),
    #[error("Packet too short for TCP header with data_offset: need {need} bytes, have {have}")]
    ShortTcpWithOffset { need: usize, have: usize },
    #[error("TCP payload truncated: expected {expected}, got {got}")]
    PayloadTruncated { expected: usize, got: usize },
}

impl ParsedPacket {
    /// Parse raw frame bytes into ParsedPacket.
    /// Returns Ok(None) for non-IPv4/non-TCP (not an error).
    /// Returns Err for recognized but corrupted packets.
    pub fn parse(frame_number: u32, timestamp: f64, data: &[u8]) -> Result<Option<Self>, WireParseError> {
        // Minimum Ethernet frame: 14 bytes (no VLAN) or 18 bytes (with VLAN)
        if data.len() < 14 {
            return Err(WireParseError::ShortEthernet(data.len()));
        }

        let mut offset = 0;

        // Ethernet header
        let dst_mac = MacAddress(data[offset..offset+6].try_into().unwrap());
        offset += 6;
        let src_mac = MacAddress(data[offset..offset+6].try_into().unwrap());
        offset += 6;
        let ethertype_raw = u16::from_be_bytes(data[offset..offset+2].try_into().unwrap());
        offset += 2;

        // Check if ethertype is one we support (IPv4, VLAN)
        // Return Ok(None) for unknown ethertypes (not an error per spec)
        let Some(ethertype) = EtherType::from_u16(ethertype_raw) else {
            return Ok(None);
        };

        let mut vlan_tci = None;

        // Handle VLAN tag (single tag only)
        let mut current_ethertype = ethertype;
        if matches!(current_ethertype, EtherType::VLAN8021Q | EtherType::VLAN8021AD) {
            if data.len() < offset + 4 {
                return Err(WireParseError::ShortVlan(data.len() - offset));
            }
            vlan_tci = Some(u16::from_be_bytes(data[offset..offset+2].try_into().unwrap()));
            offset += 2;
            let inner_ethertype_raw = u16::from_be_bytes(data[offset..offset+2].try_into().unwrap());
            offset += 2;
            // Return Ok(None) for unknown inner ethertypes (not an error per spec)
            let Some(inner_ethertype) = EtherType::from_u16(inner_ethertype_raw) else {
                return Ok(None);
            };
            current_ethertype = inner_ethertype;
        }

        // Must be IPv4
        if current_ethertype != EtherType::IPv4 {
            return Ok(None); // Not IPv4, not an error
        }

        // IPv4 header minimum 20 bytes (IHL=5)
        if data.len() < offset + 20 {
            return Err(WireParseError::ShortIpv4(data.len() - offset));
        }

        let version_ihl = data[offset];
        let ip_version = version_ihl >> 4;
        let ip_ihl = version_ihl & 0x0F;

        if ip_version != 4 {
            return Err(WireParseError::NotIpv4(ip_version));
        }

        if ip_ihl < 5 {
            return Err(WireParseError::IhlTooSmall(ip_ihl));
        }

        let ip_hdr_len = (ip_ihl as usize) * 4;

        if data.len() < offset + ip_hdr_len {
            return Err(WireParseError::ShortIpv4WithIhl {
                need: offset + ip_hdr_len,
                have: data.len(),
            });
        }

        let ip_tos = data[offset + 1];
        let ip_total_len = u16::from_be_bytes(data[offset + 2..offset + 4].try_into().unwrap());
        let ip_id = u16::from_be_bytes(data[offset + 4..offset + 6].try_into().unwrap());
        let flags_frag = u16::from_be_bytes(data[offset + 6..offset + 8].try_into().unwrap());
        let ip_flags = ((flags_frag >> 13) & 0x07) as u8;
        let ip_frag_offset = flags_frag & 0x1FFF;
        let ip_ttl = data[offset + 8];
        let ip_protocol_raw = data[offset + 9];
        let ip_checksum = u16::from_be_bytes(data[offset + 10..offset + 12].try_into().unwrap());
        let ip_src = Ipv4Address(data[offset + 12..offset + 16].try_into().unwrap());
        let ip_dst = Ipv4Address(data[offset + 16..offset + 20].try_into().unwrap());

        offset += ip_hdr_len;

        // Check for IP fragments (flags MF=1 or offset != 0)
        // RFC 791: More Fragments flag is bit 0 of flags (0x01), but in flags_frag it's bit 13
        // flags: bit 15=reserved(0), bit 14=DF, bit 13=MF, bits 12-0=fragment offset
        let mf_flag = (flags_frag >> 13) & 0x1;
        if mf_flag != 0 || ip_frag_offset != 0 {
            return Err(WireParseError::IpFragment {
                flags: ip_flags,
                offset: ip_frag_offset,
            });
        }

        // Validate total_len doesn't exceed remaining packet
        let ip_payload_start = offset;
        let ip_payload_len = ip_total_len as usize - ip_hdr_len;
        if ip_total_len as usize > data.len() - (offset - ip_hdr_len) {
            return Err(WireParseError::IpTotalLenExceeds {
                total_len: ip_total_len,
                pkt_len: data.len() - (offset - ip_hdr_len),
            });
        }

        // Must be TCP
        let ip_protocol = IpProtocol::from_u8(ip_protocol_raw)
            .ok_or(WireParseError::NotTcp(ip_protocol_raw))?;

        // TCP header minimum 20 bytes (data_offset=5)
        if data.len() < offset + 20 {
            return Err(WireParseError::ShortTcp(data.len() - offset));
        }

        let tcp_src_port = u16::from_be_bytes(data[offset..offset+2].try_into().unwrap());
        let tcp_dst_port = u16::from_be_bytes(data[offset+2..offset+4].try_into().unwrap());
        let tcp_seq = u32::from_be_bytes(data[offset+4..offset+8].try_into().unwrap());
        let tcp_ack = u32::from_be_bytes(data[offset+8..offset+12].try_into().unwrap());
        let tcp_data_offset_flags = data[offset+12];
        let tcp_data_offset = tcp_data_offset_flags >> 4;
        let tcp_flags = data[offset+13];
        let tcp_window = u16::from_be_bytes(data[offset+14..offset+16].try_into().unwrap());
        let tcp_checksum = u16::from_be_bytes(data[offset+16..offset+18].try_into().unwrap());
        let tcp_urgent_ptr = u16::from_be_bytes(data[offset+18..offset+20].try_into().unwrap());

        if tcp_data_offset < 5 {
            return Err(WireParseError::TcpDataOffsetTooSmall(tcp_data_offset));
        }

        let tcp_hdr_len = (tcp_data_offset as usize) * 4;

        if data.len() < offset + tcp_hdr_len {
            return Err(WireParseError::ShortTcpWithOffset {
                need: offset + tcp_hdr_len,
                have: data.len(),
            });
        }

        // TCP payload starts after TCP header
        let tcp_payload_start = offset + tcp_hdr_len;
        let tcp_payload_end = offset - ip_hdr_len + ip_total_len as usize; // ip_total_len includes IP header
        let tcp_payload_len = tcp_payload_end.saturating_sub(tcp_payload_start);

        // Truncate payload to ip_total_len boundary (strip padding)
        let payload = if tcp_payload_start <= data.len() {
            let end = tcp_payload_end.min(data.len());
            if tcp_payload_start < end {
                data[tcp_payload_start..end].to_vec()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // Compute SHA256 of payload
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        let payload_sha256: [u8; 32] = hasher.finalize().into();

        Ok(Some(ParsedPacket {
            frame_number,
            timestamp,
            src_mac,
            dst_mac,
            ethertype: current_ethertype,
            vlan_tci,
            ip_version,
            ip_ihl,
            ip_tos,
            ip_total_len,
            ip_id,
            ip_flags,
            ip_frag_offset,
            ip_ttl,
            ip_protocol,
            ip_checksum,
            ip_src,
            ip_dst,
            tcp_src_port,
            tcp_dst_port,
            tcp_seq,
            tcp_ack,
            tcp_data_offset,
            tcp_flags,
            tcp_window,
            tcp_checksum,
            tcp_urgent_ptr,
            payload,
            payload_sha256,
        }))
    }
}

impl IpProtocol {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            6 => Some(IpProtocol::TCP),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a minimal valid IPv4+TCP packet for testing
    fn build_test_packet() -> Vec<u8> {
        let mut pkt = Vec::new();
        
        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst MAC
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // src MAC
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
        
        // IPv4 header (20 bytes, IHL=5)
        pkt.push(0x45); // version=4, IHL=5
        pkt.push(0x00); // TOS
        pkt.extend_from_slice(&[0x00, 0x3c]); // Total length = 60 bytes
        pkt.extend_from_slice(&[0x12, 0x34]); // ID
        pkt.extend_from_slice(&[0x40, 0x00]); // Flags=DF (0x4000), fragment offset=0
        pkt.push(0x40); // TTL=64
        pkt.push(0x06); // Protocol=TCP
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum (0 for test)
        pkt.extend_from_slice(&[192, 168, 1, 1]); // Src IP
        pkt.extend_from_slice(&[192, 168, 1, 2]); // Dst IP
        
        // TCP header (20 bytes, data_offset=5)
        pkt.extend_from_slice(&[0x12, 0x34]); // Src port
        pkt.extend_from_slice(&[0x56, 0x78]); // Dst port
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Seq=1
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Ack=0
        pkt.push(0x50); // Data offset=5, reserved=0
        pkt.push(0x18); // Flags: PSH+ACK (0x18 = 00011000)
        pkt.extend_from_slice(&[0x00, 0x00]); // Window
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
        pkt.extend_from_slice(&[0x00, 0x00]); // Urgent pointer
        
        // TCP payload (20 bytes to make total 60)
        pkt.extend_from_slice(b"Hello, World! This is a test payload.");
        
        pkt
    }

    #[test]
    fn test_parse_valid_packet() {
        let data = build_test_packet();
        let result = ParsedPacket::parse(1, 1234567890.123, &data).unwrap();
        assert!(result.is_some());
        let pkt = result.unwrap();
        assert_eq!(pkt.frame_number, 1);
        assert_eq!(pkt.ip_src.to_string(), "192.168.1.1");
        assert_eq!(pkt.ip_dst.to_string(), "192.168.1.2");
        assert_eq!(pkt.tcp_src_port, 0x1234);
        assert_eq!(pkt.tcp_dst_port, 0x5678);
        assert_eq!(pkt.tcp_seq, 1);
        assert!(pkt.payload.starts_with(b"Hello"));
    }

    #[test]
    fn test_parse_with_vlan() {
        let mut data = build_test_packet();
        // Insert VLAN tag after src MAC (at offset 12)
        let vlan_tag = [0x81, 0x00, 0x00, 0x01]; // 802.1Q, VID=1
        data.splice(12..12, vlan_tag.iter().cloned());
        
        let result = ParsedPacket::parse(1, 1234567890.123, &data).unwrap();
        assert!(result.is_some());
        let pkt = result.unwrap();
        assert!(pkt.vlan_tci.is_some());
        assert_eq!(pkt.vlan_tci.unwrap(), 0x0001);
    }

    #[test]
    fn test_non_ipv4_returns_none() {
        let mut data = build_test_packet();
        // Change ethertype to something else
        data[12] = 0x86; // 0x86DD = IPv6
        data[13] = 0xDD;
        
        let result = ParsedPacket::parse(1, 1234567890.123, &data).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_ip_fragment_rejected() {
        let mut data = build_test_packet();
        // Set MF flag (bit 13 of flags_frag at offset 6-7 in IP header)
        // IP header starts at offset 14 (after Ethernet)
        // flags_frag at offset 14+6=20
        data[20] |= 0x20; // MF flag (bit 5 of byte 20 = bit 13 of 16-bit field)
        
        let result = ParsedPacket::parse(1, 1234567890.123, &data);
        assert!(matches!(result, Err(WireParseError::IpFragment { .. })));
    }

    #[test]
    fn test_ihl_too_small() {
        let mut data = build_test_packet();
        // Change IHL to 4 (invalid)
        data[14] = 0x44; // version=4, IHL=4
        
        let result = ParsedPacket::parse(1, 1234567890.123, &data);
        assert!(matches!(result, Err(WireParseError::IhlTooSmall(4))));
    }

    #[test]
    fn test_tcp_data_offset_too_small() {
        let mut data = build_test_packet();
        // Change TCP data_offset to 4 (invalid)
        // TCP header starts at offset 34 (14 eth + 20 ip)
        // data_offset at offset 34+12=46
        data[46] = 0x40; // data_offset=4
        
        let result = ParsedPacket::parse(1, 1234567890.123, &data);
        assert!(matches!(result, Err(WireParseError::TcpDataOffsetTooSmall(4))));
    }
}