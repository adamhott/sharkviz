use anyhow::{Context, Result};
use clap::Parser;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Write};
use std::path::PathBuf;

// ─── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    author, version,
    about = "Analyze a .pcap file and generate an interactive OSI-layer visualization"
)]
struct Args {
    /// Input .pcap file
    #[arg(short, long)]
    input: PathBuf,

    /// Output HTML report file
    #[arg(short, long, default_value = "report.html")]
    output: PathBuf,

    /// Title shown in the report
    #[arg(short, long, default_value = "Network Capture Analysis")]
    title: String,
}

// ─── OSI Layer Data Structures ────────────────────────────────────────────────

/// Layer 1 — Physical (inferred from frame size and link type)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct L1Info {
    pub frame_size_bytes: u32,
    pub link_type: String,
}

/// Layer 2 — Data Link
#[derive(Debug, Clone, Serialize, Deserialize)]
struct L2Info {
    pub src_mac: String,
    pub dst_mac: String,
    pub ethertype: String,
    pub ethertype_hex: String,
    pub vlan_id: Option<u16>,
    pub frame_type: String, // Ethernet II, 802.1Q, ARP, etc.
}

/// Layer 3 — Network
#[derive(Debug, Clone, Serialize, Deserialize)]
struct L3Info {
    pub protocol: String,           // IPv4, IPv6, ARP
    pub src_ip: String,
    pub dst_ip: String,
    pub ttl: Option<u8>,
    pub hop_limit: Option<u8>,      // IPv6
    pub dscp: Option<u8>,
    pub ecn: Option<u8>,
    pub total_length: Option<u16>,
    pub fragment_offset: Option<u16>,
    pub flags: Option<String>,      // DF, MF
    pub identification: Option<u16>,
    pub header_checksum: Option<String>,
    pub flow_label: Option<u32>,    // IPv6
    pub next_header: Option<u8>,    // IPv6
    pub payload_length: Option<u16>,// IPv6
    pub arp_op: Option<String>,     // ARP REQUEST/REPLY
}

/// Layer 4 — Transport
#[derive(Debug, Clone, Serialize, Deserialize)]
struct L4Info {
    pub protocol: String,           // TCP, UDP, ICMP, ICMPv6
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub service_name: Option<String>,
    // TCP specific
    pub seq_num: Option<u32>,
    pub ack_num: Option<u32>,
    pub flags: Option<String>,      // SYN, ACK, FIN, RST, PSH, URG
    pub window_size: Option<u16>,
    pub checksum: Option<String>,
    pub urgent_ptr: Option<u16>,
    pub data_offset: Option<u8>,
    // UDP specific
    pub udp_length: Option<u16>,
    // ICMP specific
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub icmp_description: Option<String>,
    pub icmp_checksum: Option<String>,
}

/// Layer 5-7 — Session / Presentation / Application (inferred from port/content)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct L7Info {
    pub protocol: Option<String>,   // HTTP, DNS, TLS, DHCP, mDNS, QUIC, etc.
    pub details: Vec<String>,       // Key observations about the PDU
    pub payload_bytes: u32,
    pub payload_preview: String,    // First 64 bytes as printable ASCII
    pub is_encrypted: bool,
}

/// One fully-analyzed packet
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Packet {
    pub frame_number: u64,
    pub timestamp: f64,             // Unix epoch seconds.microseconds
    pub direction: String,          // "out" from src perspective, "in" from dst perspective
    pub l1: L1Info,
    pub l2: Option<L2Info>,
    pub l3: Option<L3Info>,
    pub l4: Option<L4Info>,
    pub l7: Option<L7Info>,
    pub size_bytes: u32,
}

/// A unique conversation between two endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Flow {
    pub src: String,
    pub dst: String,
    pub packets_out: Vec<Packet>,   // src → dst
    pub packets_in: Vec<Packet>,    // dst → src
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub first_seen: f64,
    pub last_seen: f64,
    pub protocol_summary: Vec<String>,
}

/// Top-level report
#[derive(Debug, Serialize, Deserialize)]
struct Report {
    pub title: String,
    pub generated_at: String,
    pub pcap_file: String,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub capture_duration_sec: f64,
    pub sources: Vec<String>,               // all unique sources
    pub flows: HashMap<String, Flow>,       // key: "src||dst"
    pub protocol_histogram: HashMap<String, u64>,
    pub port_histogram: HashMap<String, u64>,
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn fmt_mac(b: &[u8]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5])
}

fn fmt_ipv4(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn fmt_ipv6(b: &[u8]) -> String {
    let groups: Vec<String> = b.chunks(2)
        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
        .collect();
    // Simplistic — compress longest run of zeros
    let full = groups.join(":");
    // Attempt basic :: compression (find longest run of :0000)
    compress_ipv6(&full)
}

fn compress_ipv6(full: &str) -> String {
    // Find longest run of ":0000" groups
    let parts: Vec<&str> = full.split(':').collect();
    if parts.len() != 8 { return full.to_string(); }

    let mut best_start = 0usize;
    let mut best_len = 0usize;
    let mut cur_start = 0usize;
    let mut cur_len = 0usize;

    for (i, p) in parts.iter().enumerate() {
        if *p == "0000" || *p == "0" {
            if cur_len == 0 { cur_start = i; }
            cur_len += 1;
            if cur_len > best_len { best_len = cur_len; best_start = cur_start; }
        } else {
            cur_len = 0;
        }
    }

    if best_len < 2 {
        return parts.iter().map(|p| {
            let trimmed = p.trim_start_matches('0');
            if trimmed.is_empty() { "0" } else { trimmed }
        }).collect::<Vec<_>>().join(":");
    }

    let before: Vec<String> = parts[..best_start].iter().map(|p| {
        let trimmed = p.trim_start_matches('0');
        if trimmed.is_empty() { "0".to_string() } else { trimmed.to_string() }
    }).collect();
    let after: Vec<String> = parts[best_start + best_len..].iter().map(|p| {
        let trimmed = p.trim_start_matches('0');
        if trimmed.is_empty() { "0".to_string() } else { trimmed.to_string() }
    }).collect();

    format!("{}::{}", before.join(":"), after.join(":"))
}

fn ethertype_name(et: u16) -> &'static str {
    match et {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86DD => "IPv6",
        0x8100 => "802.1Q VLAN",
        0x88A8 => "802.1ad QinQ",
        0x8035 => "RARP",
        0x0842 => "Wake-on-LAN",
        0x88CC => "LLDP",
        0x8863 => "PPPoE Discovery",
        0x8864 => "PPPoE Session",
        _ => "Unknown",
    }
}

fn ip_proto_name(proto: u8) -> &'static str {
    match proto {
        1  => "ICMP",
        2  => "IGMP",
        6  => "TCP",
        17 => "UDP",
        41 => "IPv6-in-IPv4",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        89 => "OSPF",
        132 => "SCTP",
        _ => "Unknown",
    }
}

fn port_service(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("FTP-DATA"),
        21 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        25 => Some("SMTP"),
        53 => Some("DNS"),
        67 => Some("DHCP-Server"),
        68 => Some("DHCP-Client"),
        69 => Some("TFTP"),
        80 => Some("HTTP"),
        110 => Some("POP3"),
        119 => Some("NNTP"),
        123 => Some("NTP"),
        143 => Some("IMAP"),
        161 => Some("SNMP"),
        162 => Some("SNMP-Trap"),
        179 => Some("BGP"),
        389 => Some("LDAP"),
        443 => Some("HTTPS/TLS"),
        445 => Some("SMB"),
        465 => Some("SMTPS"),
        514 => Some("Syslog"),
        515 => Some("LPD"),
        587 => Some("SMTP-Submission"),
        636 => Some("LDAPS"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        1080 => Some("SOCKS"),
        1194 => Some("OpenVPN"),
        1433 => Some("MSSQL"),
        1521 => Some("Oracle-DB"),
        3306 => Some("MySQL"),
        3389 => Some("RDP"),
        4500 => Some("IKEv2-NAT"),
        5222 => Some("XMPP"),
        5353 => Some("mDNS"),
        5355 => Some("LLMNR"),
        5432 => Some("PostgreSQL"),
        5060 => Some("SIP"),
        5061 => Some("SIPS"),
        6379 => Some("Redis"),
        6443 => Some("Kubernetes-API"),
        8080 => Some("HTTP-Alt"),
        8443 => Some("HTTPS-Alt"),
        8883 => Some("MQTT-TLS"),
        9000 => Some("Fastcgi/SonarQube"),
        9200 => Some("Elasticsearch"),
        27017 => Some("MongoDB"),
        _ => None,
    }
}

fn icmp_description(t: u8, code: u8) -> String {
    match (t, code) {
        (0, 0) => "Echo Reply".to_string(),
        (3, 0) => "Destination Net Unreachable".to_string(),
        (3, 1) => "Destination Host Unreachable".to_string(),
        (3, 2) => "Destination Protocol Unreachable".to_string(),
        (3, 3) => "Destination Port Unreachable".to_string(),
        (3, 4) => "Fragmentation Needed, DF Set".to_string(),
        (3, 5) => "Source Route Failed".to_string(),
        (4, 0) => "Source Quench (deprecated)".to_string(),
        (5, 0) => "Redirect for Network".to_string(),
        (5, 1) => "Redirect for Host".to_string(),
        (8, 0) => "Echo Request".to_string(),
        (9, 0) => "Router Advertisement".to_string(),
        (10, 0) => "Router Solicitation".to_string(),
        (11, 0) => "TTL Exceeded in Transit".to_string(),
        (11, 1) => "Fragment Reassembly Time Exceeded".to_string(),
        (12, 0) => "IP Header Bad".to_string(),
        (13, 0) => "Timestamp Request".to_string(),
        (14, 0) => "Timestamp Reply".to_string(),
        _ => format!("Type {} Code {}", t, code),
    }
}

fn icmpv6_description(t: u8, code: u8) -> String {
    match (t, code) {
        (1, _)   => "Destination Unreachable".to_string(),
        (2, 0)   => "Packet Too Big".to_string(),
        (3, 0)   => "Hop Limit Exceeded".to_string(),
        (3, 1)   => "Fragment Reassembly Exceeded".to_string(),
        (4, _)   => "Parameter Problem".to_string(),
        (128, 0) => "Echo Request".to_string(),
        (129, 0) => "Echo Reply".to_string(),
        (130, _) => "MLD Query".to_string(),
        (131, _) => "MLD Report".to_string(),
        (132, _) => "MLD Done".to_string(),
        (133, 0) => "NDP Router Solicitation".to_string(),
        (134, 0) => "NDP Router Advertisement".to_string(),
        (135, 0) => "NDP Neighbor Solicitation".to_string(),
        (136, 0) => "NDP Neighbor Advertisement".to_string(),
        (137, 0) => "NDP Redirect".to_string(),
        _ => format!("ICMPv6 Type {} Code {}", t, code),
    }
}

fn tcp_flags_str(flags: u8) -> String {
    let mut out = Vec::new();
    if flags & 0x01 != 0 { out.push("FIN"); }
    if flags & 0x02 != 0 { out.push("SYN"); }
    if flags & 0x04 != 0 { out.push("RST"); }
    if flags & 0x08 != 0 { out.push("PSH"); }
    if flags & 0x10 != 0 { out.push("ACK"); }
    if flags & 0x20 != 0 { out.push("URG"); }
    if flags & 0x40 != 0 { out.push("ECE"); }
    if flags & 0x80 != 0 { out.push("CWR"); }
    if out.is_empty() { "<none>".to_string() } else { out.join("|") }
}

fn ipv4_flags_str(flags: u8) -> String {
    let mut out = Vec::new();
    if flags & 0x2 != 0 { out.push("DF"); }
    if flags & 0x1 != 0 { out.push("MF"); }
    if out.is_empty() { "none".to_string() } else { out.join("|") }
}

fn payload_preview(data: &[u8]) -> String {
    data.iter().take(80)
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
        .collect()
}

fn infer_l7(src_port: Option<u16>, dst_port: Option<u16>, payload: &[u8]) -> Option<L7Info> {
    let preview = payload_preview(payload);
    let payload_bytes = payload.len() as u32;

    // Identify protocol from ports
    let port_proto = dst_port.and_then(port_service)
        .or_else(|| src_port.and_then(port_service));

    // Infer from payload content
    let mut details = Vec::new();
    let mut detected = port_proto.map(str::to_string);
    let mut is_encrypted = false;

    if payload.len() >= 4 {
        // TLS/SSL detection
        if payload[0] == 0x16 && payload[1] == 0x03 {
            let tls_ver = match payload[2] {
                0x00 => "SSLv3",
                0x01 => "TLS 1.0",
                0x02 => "TLS 1.1",
                0x03 => "TLS 1.2",
                0x04 => "TLS 1.3",
                _ => "TLS Unknown",
            };
            detected = Some(format!("TLS ({})", tls_ver));
            is_encrypted = true;
            let record_type = match payload[0] {
                0x14 => "Change Cipher Spec",
                0x15 => "Alert",
                0x16 => "Handshake",
                0x17 => "Application Data",
                _ => "Unknown",
            };
            details.push(format!("TLS Record: {}", record_type));
            if payload[5] == 0x01 { details.push("ClientHello".to_string()); }
            if payload[5] == 0x02 { details.push("ServerHello".to_string()); }
            if payload[5] == 0x0b { details.push("Certificate".to_string()); }
            if payload[5] == 0x0c { details.push("ServerKeyExchange".to_string()); }
            if payload[5] == 0x0e { details.push("ServerHelloDone".to_string()); }
            if payload[5] == 0x10 { details.push("ClientKeyExchange".to_string()); }
            if payload[5] == 0x14 { details.push("Finished".to_string()); }
        }

        // HTTP detection
        let starts_with = |prefix: &[u8]| payload.starts_with(prefix);
        if starts_with(b"GET ") || starts_with(b"POST ") || starts_with(b"PUT ")
            || starts_with(b"DELETE ") || starts_with(b"HEAD ") || starts_with(b"OPTIONS ")
            || starts_with(b"PATCH ") {
            detected = Some("HTTP".to_string());
            // Extract method and path
            let line: String = payload.iter().take(200)
                .take_while(|&&b| b != b'\r' && b != b'\n')
                .map(|&b| b as char).collect();
            details.push(format!("Request: {}", line));
        }
        if starts_with(b"HTTP/") {
            detected = Some("HTTP".to_string());
            let line: String = payload.iter().take(200)
                .take_while(|&&b| b != b'\r' && b != b'\n')
                .map(|&b| b as char).collect();
            details.push(format!("Response: {}", line));
        }

        // DNS detection (port 53 already caught, but confirm by structure)
        if (dst_port == Some(53) || src_port == Some(53)) && payload.len() >= 12 {
            detected = Some("DNS".to_string());
            let flags = u16::from_be_bytes([payload[2], payload[3]]);
            let is_response = (flags >> 15) & 1 == 1;
            let opcode = (flags >> 11) & 0xf;
            let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
            let ancount = u16::from_be_bytes([payload[6], payload[7]]);
            if is_response {
                details.push(format!("DNS Response: {} answers", ancount));
            } else {
                details.push(format!("DNS Query: {} questions (opcode {})", qdcount, opcode));
            }
            let rcode = flags & 0xf;
            if rcode != 0 {
                let rcode_str = match rcode {
                    1 => "Format Error", 2 => "Server Failure",
                    3 => "NXDOMAIN", 4 => "Not Implemented",
                    5 => "Refused", _ => "Unknown Error",
                };
                details.push(format!("RCode: {}", rcode_str));
            }
        }

        // mDNS
        if dst_port == Some(5353) || src_port == Some(5353) {
            detected = Some("mDNS".to_string());
            details.push("Multicast DNS (Bonjour/Avahi)".to_string());
        }

        // DHCP
        if (dst_port == Some(67) || src_port == Some(67) || dst_port == Some(68) || src_port == Some(68))
            && payload.len() >= 236 {
            detected = Some("DHCP".to_string());
            let msg_type = payload[0];
            let dhcp_msg = match msg_type {
                1 => "BOOTREQUEST",
                2 => "BOOTREPLY",
                _ => "Unknown",
            };
            details.push(format!("DHCP {} (op={})", dhcp_msg, msg_type));
            // Check magic cookie
            if payload.len() >= 240 && &payload[236..240] == &[99, 130, 83, 99] {
                // Walk options
                let mut i = 240;
                while i < payload.len() {
                    let opt = payload[i];
                    if opt == 255 { break; } // END
                    if opt == 0 { i += 1; continue; } // PAD
                    if i + 1 >= payload.len() { break; }
                    let len = payload[i+1] as usize;
                    if i + 2 + len > payload.len() { break; }
                    match opt {
                        53 if len >= 1 => {
                            let dhcp_type = match payload[i+2] {
                                1 => "DISCOVER", 2 => "OFFER", 3 => "REQUEST",
                                4 => "DECLINE", 5 => "ACK", 6 => "NAK",
                                7 => "RELEASE", 8 => "INFORM", _ => "Unknown",
                            };
                            details.push(format!("DHCP Message Type: {}", dhcp_type));
                        }
                        12 => {
                            let hostname: String = payload[i+2..i+2+len].iter()
                                .map(|&b| if b.is_ascii_graphic() { b as char } else { '?' })
                                .collect();
                            details.push(format!("Hostname: {}", hostname));
                        }
                        _ => {}
                    }
                    i += 2 + len;
                }
            }
        }

        // NTP
        if (dst_port == Some(123) || src_port == Some(123)) && payload.len() >= 48 {
            detected = Some("NTP".to_string());
            let li = (payload[0] >> 6) & 0x3;
            let vn = (payload[0] >> 3) & 0x7;
            let mode = payload[0] & 0x7;
            let mode_str = match mode {
                1 => "Symmetric Active",
                2 => "Symmetric Passive",
                3 => "Client",
                4 => "Server",
                5 => "Broadcast",
                _ => "Unknown",
            };
            details.push(format!("NTP v{} {} (LI={})", vn, mode_str, li));
        }

        // QUIC detection (UDP, starts with specific patterns)
        if payload.len() >= 5 && (dst_port == Some(443) || src_port == Some(443)) {
            // QUIC long header: first bit = 1, version follows
            if payload[0] & 0x80 != 0 {
                let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
                if version == 0x00000001 || version == 0xff000020 || version == 0x1 {
                    detected = Some("QUIC".to_string());
                    is_encrypted = true;
                    details.push(format!("QUIC v{:#010x}", version));
                }
            }
        }

        // SSH banner
        if starts_with(b"SSH-") {
            detected = Some("SSH".to_string());
            let banner: String = payload.iter().take(50)
                .take_while(|&&b| b != b'\r' && b != b'\n')
                .map(|&b| b as char).collect();
            details.push(format!("Banner: {}", banner));
        }

        // SMTP
        if starts_with(b"220 ") || starts_with(b"250 ") || starts_with(b"EHLO")
            || starts_with(b"HELO") || starts_with(b"MAIL FROM") {
            detected = Some("SMTP".to_string());
            let line: String = payload.iter().take(80)
                .take_while(|&&b| b != b'\r' && b != b'\n')
                .map(|&b| b as char).collect();
            details.push(line);
        }

        // SSDP / UPnP
        if starts_with(b"M-SEARCH ") || starts_with(b"NOTIFY * HTTP") || starts_with(b"HTTP/1.1 200") {
            if dst_port == Some(1900) || src_port == Some(1900) {
                detected = Some("SSDP/UPnP".to_string());
                details.push("UPnP Service Discovery".to_string());
            }
        }
    }

    if payload_bytes == 0 {
        return None;
    }

    Some(L7Info {
        protocol: detected,
        details,
        payload_bytes,
        payload_preview: preview,
        is_encrypted,
    })
}

// ─── Packet Parser ────────────────────────────────────────────────────────────

fn parse_packet(raw: &[u8], frame_num: u64, ts_sec: u32, ts_usec: u32) -> Option<Packet> {
    if raw.len() < 14 { return None; }
    let timestamp = ts_sec as f64 + ts_usec as f64 / 1_000_000.0;
    let frame_size = raw.len() as u32;

    // L2 parsing
    let dst_mac = fmt_mac(&raw[0..6]);
    let dst_mac_raw = &raw[0..6];
    let src_mac = fmt_mac(&raw[6..12]);
    let mut ethertype = u16::from_be_bytes([raw[12], raw[13]]);
    let mut ip_off = 14usize;
    let mut vlan_id: Option<u16> = None;

    // 802.1Q VLAN tag
    if ethertype == 0x8100 && raw.len() >= 18 {
        vlan_id = Some(u16::from_be_bytes([raw[14], raw[15]]) & 0x0fff);
        ethertype = u16::from_be_bytes([raw[16], raw[17]]);
        ip_off = 18;
    }

    let l2 = L2Info {
        src_mac: src_mac.clone(),
        dst_mac: dst_mac.clone(),
        ethertype: ethertype_name(ethertype).to_string(),
        ethertype_hex: format!("0x{:04X}", ethertype),
        vlan_id,
        frame_type: if vlan_id.is_some() { "802.1Q" } else { "Ethernet II" }.to_string(),
    };

    let mut l3: Option<L3Info> = None;
    let mut l4: Option<L4Info> = None;
    let mut l7: Option<L7Info> = None;
    let mut src_addr = src_mac.clone();
    let mut dst_addr = dst_mac.clone();

    match ethertype {
        // ── ARP ──────────────────────────────────────────────────────────────
        0x0806 if raw.len() >= ip_off + 28 => {
            let base = ip_off;
            let op = u16::from_be_bytes([raw[base+6], raw[base+7]]);
            let sha = fmt_mac(&raw[base+8..base+14]);
            let spa = fmt_ipv4(&raw[base+14..base+18]);
            let tha = fmt_mac(&raw[base+18..base+24]);
            let tpa = fmt_ipv4(&raw[base+24..base+28]);
            let op_str = match op {
                1 => "REQUEST", 2 => "REPLY", 3 => "RARP REQUEST", 4 => "RARP REPLY",
                _ => "Unknown",
            };
            src_addr = format!("{} ({})", sha, spa);
            dst_addr = format!("{} ({})", tha, tpa);
            l3 = Some(L3Info {
                protocol: "ARP".to_string(),
                src_ip: spa,
                dst_ip: tpa,
                ttl: None, hop_limit: None, dscp: None, ecn: None,
                total_length: None, fragment_offset: None, flags: None,
                identification: None, header_checksum: None,
                flow_label: None, next_header: None, payload_length: None,
                arp_op: Some(format!("{} ({:?}→{:?})", op_str, sha, tha)),
            });
        }

        // ── IPv4 ─────────────────────────────────────────────────────────────
        0x0800 if raw.len() >= ip_off + 20 => {
            let ihl    = ((raw[ip_off] & 0x0f) as usize) * 4;
            let dscp   = raw[ip_off+1] >> 2;
            let ecn    = raw[ip_off+1] & 0x03;
            let total  = u16::from_be_bytes([raw[ip_off+2], raw[ip_off+3]]);
            let ident  = u16::from_be_bytes([raw[ip_off+4], raw[ip_off+5]]);
            let flags_frag = u16::from_be_bytes([raw[ip_off+6], raw[ip_off+7]]);
            let flags_bits = (flags_frag >> 13) as u8;
            let frag_off   = flags_frag & 0x1fff;
            let ttl    = raw[ip_off+8];
            let proto  = raw[ip_off+9];
            let chksum = u16::from_be_bytes([raw[ip_off+10], raw[ip_off+11]]);
            let src_ip = fmt_ipv4(&raw[ip_off+12..ip_off+16]);
            let dst_ip = fmt_ipv4(&raw[ip_off+16..ip_off+20]);
            src_addr = src_ip.clone();
            dst_addr = dst_ip.clone();

            l3 = Some(L3Info {
                protocol: "IPv4".to_string(),
                src_ip: src_ip.clone(),
                dst_ip: dst_ip.clone(),
                ttl: Some(ttl),
                hop_limit: None,
                dscp: Some(dscp),
                ecn: Some(ecn),
                total_length: Some(total),
                fragment_offset: Some(frag_off),
                flags: Some(ipv4_flags_str(flags_bits)),
                identification: Some(ident),
                header_checksum: Some(format!("0x{:04X}", chksum)),
                flow_label: None, next_header: None, payload_length: None,
                arp_op: None,
            });

            let t_off = ip_off + ihl;
            match proto {
                // TCP
                6 if raw.len() >= t_off + 20 => {
                    let sp  = u16::from_be_bytes([raw[t_off],   raw[t_off+1]]);
                    let dp  = u16::from_be_bytes([raw[t_off+2], raw[t_off+3]]);
                    let seq = u32::from_be_bytes([raw[t_off+4], raw[t_off+5], raw[t_off+6], raw[t_off+7]]);
                    let ack = u32::from_be_bytes([raw[t_off+8], raw[t_off+9], raw[t_off+10], raw[t_off+11]]);
                    let doff = ((raw[t_off+12] >> 4) as usize) * 4;
                    let flags = raw[t_off+13];
                    let win  = u16::from_be_bytes([raw[t_off+14], raw[t_off+15]]);
                    let chk  = u16::from_be_bytes([raw[t_off+16], raw[t_off+17]]);
                    let urg  = u16::from_be_bytes([raw[t_off+18], raw[t_off+19]]);
                    let svc  = port_service(sp).or_else(|| port_service(dp));
                    l4 = Some(L4Info {
                        protocol: "TCP".to_string(),
                        src_port: Some(sp), dst_port: Some(dp),
                        service_name: svc.map(str::to_string),
                        seq_num: Some(seq), ack_num: Some(ack),
                        flags: Some(tcp_flags_str(flags)),
                        window_size: Some(win),
                        checksum: Some(format!("0x{:04X}", chk)),
                        urgent_ptr: Some(urg),
                        data_offset: Some(doff as u8),
                        udp_length: None, icmp_type: None, icmp_code: None,
                        icmp_description: None, icmp_checksum: None,
                    });
                    let payload_off = t_off + doff;
                    if payload_off < raw.len() {
                        l7 = infer_l7(Some(sp), Some(dp), &raw[payload_off..]);
                    }
                }
                // UDP
                17 if raw.len() >= t_off + 8 => {
                    let sp  = u16::from_be_bytes([raw[t_off],   raw[t_off+1]]);
                    let dp  = u16::from_be_bytes([raw[t_off+2], raw[t_off+3]]);
                    let len = u16::from_be_bytes([raw[t_off+4], raw[t_off+5]]);
                    let chk = u16::from_be_bytes([raw[t_off+6], raw[t_off+7]]);
                    let svc = port_service(sp).or_else(|| port_service(dp));
                    l4 = Some(L4Info {
                        protocol: "UDP".to_string(),
                        src_port: Some(sp), dst_port: Some(dp),
                        service_name: svc.map(str::to_string),
                        udp_length: Some(len),
                        checksum: Some(format!("0x{:04X}", chk)),
                        seq_num: None, ack_num: None, flags: None,
                        window_size: None, urgent_ptr: None, data_offset: None,
                        icmp_type: None, icmp_code: None,
                        icmp_description: None, icmp_checksum: None,
                    });
                    let payload_off = t_off + 8;
                    if payload_off < raw.len() {
                        l7 = infer_l7(Some(sp), Some(dp), &raw[payload_off..]);
                    }
                }
                // ICMP
                1 if raw.len() >= t_off + 8 => {
                    let icmp_type = raw[t_off];
                    let icmp_code = raw[t_off+1];
                    let chk = u16::from_be_bytes([raw[t_off+2], raw[t_off+3]]);
                    l4 = Some(L4Info {
                        protocol: "ICMP".to_string(),
                        src_port: None, dst_port: None, service_name: None,
                        seq_num: None, ack_num: None, flags: None,
                        window_size: None, urgent_ptr: None, data_offset: None,
                        udp_length: None,
                        icmp_type: Some(icmp_type),
                        icmp_code: Some(icmp_code),
                        icmp_description: Some(icmp_description(icmp_type, icmp_code)),
                        icmp_checksum: Some(format!("0x{:04X}", chk)),
                        checksum: None,
                    });
                }
                _ => {
                    l4 = Some(L4Info {
                        protocol: ip_proto_name(proto).to_string(),
                        src_port: None, dst_port: None, service_name: None,
                        seq_num: None, ack_num: None, flags: None,
                        window_size: None, urgent_ptr: None, data_offset: None,
                        udp_length: None, icmp_type: None, icmp_code: None,
                        icmp_description: None, icmp_checksum: None, checksum: None,
                    });
                }
            }
        }

        // ── IPv6 ─────────────────────────────────────────────────────────────
        0x86DD if raw.len() >= ip_off + 40 => {
            let vtcfl  = u32::from_be_bytes([raw[ip_off], raw[ip_off+1], raw[ip_off+2], raw[ip_off+3]]);
            let flow   = vtcfl & 0x000fffff;
            let tc     = ((vtcfl >> 20) & 0xff) as u8;
            let dscp   = tc >> 2;
            let ecn    = tc & 0x3;
            let pay_len= u16::from_be_bytes([raw[ip_off+4], raw[ip_off+5]]);
            let next_h = raw[ip_off+6];
            let hop_l  = raw[ip_off+7];
            let src_ip = fmt_ipv6(raw[ip_off+8..ip_off+24].try_into().unwrap_or(&[0u8;16]));
            let dst_ip = fmt_ipv6(raw[ip_off+24..ip_off+40].try_into().unwrap_or(&[0u8;16]));
            src_addr = src_ip.clone();
            dst_addr = dst_ip.clone();

            l3 = Some(L3Info {
                protocol: "IPv6".to_string(),
                src_ip: src_ip.clone(),
                dst_ip: dst_ip.clone(),
                ttl: None,
                hop_limit: Some(hop_l),
                dscp: Some(dscp),
                ecn: Some(ecn),
                total_length: None,
                fragment_offset: None,
                flags: None,
                identification: None,
                header_checksum: None,
                flow_label: Some(flow),
                next_header: Some(next_h),
                payload_length: Some(pay_len),
                arp_op: None,
            });

            let t_off = ip_off + 40;
            match next_h {
                6 if raw.len() >= t_off + 20 => {
                    let sp  = u16::from_be_bytes([raw[t_off],   raw[t_off+1]]);
                    let dp  = u16::from_be_bytes([raw[t_off+2], raw[t_off+3]]);
                    let seq = u32::from_be_bytes([raw[t_off+4], raw[t_off+5], raw[t_off+6], raw[t_off+7]]);
                    let ack = u32::from_be_bytes([raw[t_off+8], raw[t_off+9], raw[t_off+10], raw[t_off+11]]);
                    let doff = ((raw[t_off+12] >> 4) as usize) * 4;
                    let flags = raw[t_off+13];
                    let win  = u16::from_be_bytes([raw[t_off+14], raw[t_off+15]]);
                    let svc  = port_service(sp).or_else(|| port_service(dp));
                    l4 = Some(L4Info {
                        protocol: "TCP".to_string(),
                        src_port: Some(sp), dst_port: Some(dp),
                        service_name: svc.map(str::to_string),
                        seq_num: Some(seq), ack_num: Some(ack),
                        flags: Some(tcp_flags_str(flags)),
                        window_size: Some(win),
                        checksum: None, urgent_ptr: None,
                        data_offset: Some(doff as u8),
                        udp_length: None, icmp_type: None, icmp_code: None,
                        icmp_description: None, icmp_checksum: None,
                    });
                    let payload_off = t_off + doff;
                    if payload_off < raw.len() {
                        l7 = infer_l7(Some(sp), Some(dp), &raw[payload_off..]);
                    }
                }
                17 if raw.len() >= t_off + 8 => {
                    let sp  = u16::from_be_bytes([raw[t_off],   raw[t_off+1]]);
                    let dp  = u16::from_be_bytes([raw[t_off+2], raw[t_off+3]]);
                    let len = u16::from_be_bytes([raw[t_off+4], raw[t_off+5]]);
                    let svc = port_service(sp).or_else(|| port_service(dp));
                    l4 = Some(L4Info {
                        protocol: "UDP".to_string(),
                        src_port: Some(sp), dst_port: Some(dp),
                        service_name: svc.map(str::to_string),
                        udp_length: Some(len),
                        checksum: None, seq_num: None, ack_num: None,
                        flags: None, window_size: None, urgent_ptr: None,
                        data_offset: None, icmp_type: None, icmp_code: None,
                        icmp_description: None, icmp_checksum: None,
                    });
                    let payload_off = t_off + 8;
                    if payload_off < raw.len() {
                        l7 = infer_l7(Some(sp), Some(dp), &raw[payload_off..]);
                    }
                }
                58 if raw.len() >= t_off + 4 => {
                    let icmp_type = raw[t_off];
                    let icmp_code = raw[t_off+1];
                    let chk = u16::from_be_bytes([raw[t_off+2], raw[t_off+3]]);
                    l4 = Some(L4Info {
                        protocol: "ICMPv6".to_string(),
                        src_port: None, dst_port: None, service_name: None,
                        seq_num: None, ack_num: None, flags: None,
                        window_size: None, urgent_ptr: None, data_offset: None,
                        udp_length: None,
                        icmp_type: Some(icmp_type),
                        icmp_code: Some(icmp_code),
                        icmp_description: Some(icmpv6_description(icmp_type, icmp_code)),
                        icmp_checksum: Some(format!("0x{:04X}", chk)),
                        checksum: None,
                    });
                }
                _ => {
                    l4 = Some(L4Info {
                        protocol: ip_proto_name(next_h).to_string(),
                        src_port: None, dst_port: None, service_name: None,
                        seq_num: None, ack_num: None, flags: None,
                        window_size: None, urgent_ptr: None, data_offset: None,
                        udp_length: None, icmp_type: None, icmp_code: None,
                        icmp_description: None, icmp_checksum: None, checksum: None,
                    });
                }
            }
        }
        _ => {}
    }

    // Determine multicast/broadcast
    let is_multicast = dst_mac_raw[0] & 0x01 != 0;
    let is_broadcast = dst_mac == "ff:ff:ff:ff:ff:ff";
    let _ = (is_multicast, is_broadcast); // used implicitly in addr naming

    let l1 = L1Info {
        frame_size_bytes: frame_size,
        link_type: "Ethernet".to_string(),
    };

    Some(Packet {
        frame_number: frame_num,
        timestamp,
        direction: "out".to_string(), // will be fixed in flow assignment
        l1,
        l2: Some(l2),
        l3,
        l4,
        l7,
        size_bytes: frame_size,
    })
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = Args::parse();

    eprintln!("Opening {:?}", args.input);
    let file = File::open(&args.input)
        .with_context(|| format!("Cannot open {:?}", args.input))?;

    let mut reader = LegacyPcapReader::new(65536, BufReader::new(file))
        .context("Not a valid legacy pcap file")?;

    let mut all_packets: Vec<(String, String, Packet)> = Vec::new(); // (src_addr, dst_addr, packet)
    let mut frame_num: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut first_ts: f64 = f64::MAX;
    let mut last_ts: f64 = 0.0;

    eprintln!("Parsing packets...");

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                let pkt_data: Option<(u32, u32, Vec<u8>)> = match block {
                    PcapBlockOwned::LegacyHeader(_) => None,
                    PcapBlockOwned::Legacy(ref pkt) => {
                        frame_num += 1;
                        Some((pkt.ts_sec, pkt.ts_usec, pkt.data.to_vec()))
                    }
                    PcapBlockOwned::NG(_) => None,
                };
                drop(block);
                reader.consume(offset);

                if let Some((ts_sec, ts_usec, raw)) = pkt_data {
                    total_bytes += raw.len() as u64;
                    if let Some(mut pkt) = parse_packet(&raw, frame_num, ts_sec, ts_usec) {
                        if pkt.timestamp < first_ts { first_ts = pkt.timestamp; }
                        if pkt.timestamp > last_ts  { last_ts  = pkt.timestamp; }

                        // Determine source and destination addresses for flow key
                        let src = if let Some(ref l3) = pkt.l3 {
                            l3.src_ip.clone()
                        } else if let Some(ref l2) = pkt.l2 {
                            l2.src_mac.clone()
                        } else {
                            "unknown".to_string()
                        };
                        let dst = if let Some(ref l3) = pkt.l3 {
                            l3.dst_ip.clone()
                        } else if let Some(ref l2) = pkt.l2 {
                            l2.dst_mac.clone()
                        } else {
                            "unknown".to_string()
                        };

                        pkt.direction = "out".to_string();
                        all_packets.push((src, dst, pkt));
                    }
                }
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                if let Err(e) = reader.refill() {
                    return Err(anyhow::anyhow!("refill error: {:?}", e));
                }
            }
            Err(e) => return Err(anyhow::anyhow!("pcap parse error: {:?}", e)),
        }
    }

    eprintln!("Parsed {} packets, building flows...", frame_num);

    // Build flows and protocol histograms
    let mut flows: HashMap<String, Flow> = HashMap::new();
    let mut protocol_histogram: HashMap<String, u64> = HashMap::new();
    let mut port_histogram: HashMap<String, u64> = HashMap::new();
    let mut all_sources: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (src, dst, mut pkt) in all_packets {
        // Update histograms
        if let Some(ref l3) = pkt.l3 {
            *protocol_histogram.entry(l3.protocol.clone()).or_insert(0) += 1;
        }
        if let Some(ref l4) = pkt.l4 {
            *protocol_histogram.entry(l4.protocol.clone()).or_insert(0) += 1;
            if let Some(dp) = l4.dst_port {
                let svc = l4.service_name.clone()
                    .unwrap_or_else(|| format!("{}", dp));
                *port_histogram.entry(svc).or_insert(0) += 1;
            }
        }
        if let Some(ref l7) = pkt.l7 {
            if let Some(ref proto) = l7.protocol {
                *protocol_histogram.entry(proto.clone()).or_insert(0) += 1;
            }
        }

        all_sources.insert(src.clone());

        let size = pkt.size_bytes as u64;

        // Check if reverse flow already exists
        let fwd_key = format!("{}||{}", src, dst);
        let rev_key = format!("{}||{}", dst, src);

        if flows.contains_key(&rev_key) {
            // This is a "reply" packet — goes into packets_in of the reverse flow
            pkt.direction = "in".to_string();
            let flow = flows.get_mut(&rev_key).unwrap();
            flow.bytes_in += size;
            if pkt.timestamp < flow.first_seen { flow.first_seen = pkt.timestamp; }
            if pkt.timestamp > flow.last_seen  { flow.last_seen  = pkt.timestamp; }
            flow.packets_in.push(pkt);
        } else {
            // Forward direction
            pkt.direction = "out".to_string();
            let flow = flows.entry(fwd_key.clone()).or_insert_with(|| Flow {
                src: src.clone(),
                dst: dst.clone(),
                packets_out: Vec::new(),
                packets_in: Vec::new(),
                bytes_out: 0,
                bytes_in: 0,
                first_seen: pkt.timestamp,
                last_seen: pkt.timestamp,
                protocol_summary: Vec::new(),
            });
            flow.bytes_out += size;
            if pkt.timestamp < flow.first_seen { flow.first_seen = pkt.timestamp; }
            if pkt.timestamp > flow.last_seen  { flow.last_seen  = pkt.timestamp; }
            flow.packets_out.push(pkt);
        }
    }

    // Build protocol summaries for each flow
    for flow in flows.values_mut() {
        let mut protos: std::collections::HashSet<String> = std::collections::HashSet::new();
        for pkt in flow.packets_out.iter().chain(flow.packets_in.iter()) {
            if let Some(ref l4) = pkt.l4 {
                protos.insert(l4.protocol.clone());
            }
            if let Some(ref l7) = pkt.l7 {
                if let Some(ref p) = l7.protocol {
                    protos.insert(p.clone());
                }
            }
        }
        flow.protocol_summary = protos.into_iter().collect();
        flow.protocol_summary.sort();
    }

    let mut sources: Vec<String> = all_sources.into_iter().collect();
    sources.sort_by(|a, b| {
        // Sort IPs numerically if possible
        let a_parts: Vec<u8> = a.split('.').filter_map(|p| p.parse().ok()).collect();
        let b_parts: Vec<u8> = b.split('.').filter_map(|p| p.parse().ok()).collect();
        if a_parts.len() == 4 && b_parts.len() == 4 {
            a_parts.cmp(&b_parts)
        } else {
            a.cmp(b)
        }
    });

    let duration = if last_ts > first_ts { last_ts - first_ts } else { 0.0 };

    let report = Report {
        title: args.title.clone(),
        generated_at: chrono_now(),
        pcap_file: args.input.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
        total_packets: frame_num,
        total_bytes,
        capture_duration_sec: duration,
        sources,
        flows,
        protocol_histogram,
        port_histogram,
    };

    eprintln!("Building HTML report...");
    let json_data = serde_json::to_string(&report)?;
    let html = build_html(&json_data, &args.title);

    let mut out = File::create(&args.output)
        .with_context(|| format!("Cannot create {:?}", args.output))?;
    out.write_all(html.as_bytes())?;

    eprintln!("Done! Report written to {:?}", args.output);
    eprintln!("  Flows: {}", report.flows.len());
    eprintln!("  Sources: {}", report.sources.len());
    eprintln!("  Duration: {:.2}s", duration);
    Ok(())
}

fn chrono_now() -> String {
    // Simple timestamp without external dependency
    "Generated".to_string()
}

// ─── HTML Builder ─────────────────────────────────────────────────────────────

fn build_html(json_data: &str, title: &str) -> String {
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root {{
  --bg: #0a0c10;
  --bg2: #0f1218;
  --bg3: #161b24;
  --bg4: #1d2535;
  --border: #1e2940;
  --border2: #243050;
  --text: #c8d4e8;
  --text2: #7a8fb8;
  --text3: #4a5878;
  --accent: #00d4ff;
  --accent2: #0099bb;
  --green: #00e88f;
  --orange: #ff8c42;
  --red: #ff4d6d;
  --purple: #b060ff;
  --yellow: #ffd166;
  --l1: #ff6b6b;
  --l2: #ff8c42;
  --l3: #ffd166;
  --l4: #00e88f;
  --l5: #00d4ff;
  --l6: #b060ff;
  --l7: #ff6bcb;
}}

* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
  font-family: 'JetBrains Mono', monospace;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  overflow-x: hidden;
}}

/* ── Scanline overlay ── */
body::before {{
  content: '';
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0, 212, 255, 0.012) 2px,
    rgba(0, 212, 255, 0.012) 4px
  );
  pointer-events: none;
  z-index: 1000;
}}

/* ── Header ── */
.header {{
  padding: 28px 40px 24px;
  border-bottom: 1px solid var(--border);
  background: linear-gradient(180deg, rgba(0,212,255,0.04) 0%, transparent 100%);
  display: flex;
  align-items: center;
  gap: 24px;
}}
.header-icon {{
  width: 44px; height: 44px;
  background: linear-gradient(135deg, var(--accent), var(--purple));
  border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  font-size: 20px;
  flex-shrink: 0;
}}
.header-title {{
  font-family: 'Syne', sans-serif;
  font-size: 22px;
  font-weight: 800;
  color: #fff;
  letter-spacing: -0.5px;
}}
.header-sub {{
  font-size: 11px;
  color: var(--text3);
  margin-top: 3px;
  letter-spacing: 1px;
  text-transform: uppercase;
}}
.header-stats {{
  margin-left: auto;
  display: flex;
  gap: 28px;
  align-items: center;
}}
.stat-chip {{
  text-align: right;
}}
.stat-chip .val {{
  font-size: 18px;
  font-weight: 700;
  color: var(--accent);
}}
.stat-chip .lbl {{
  font-size: 10px;
  color: var(--text3);
  text-transform: uppercase;
  letter-spacing: 0.8px;
}}

/* ── Main layout ── */
.layout {{
  display: grid;
  grid-template-columns: 320px 1fr;
  height: calc(100vh - 97px);
}}

/* ── Left sidebar ── */
.sidebar {{
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  background: var(--bg2);
  overflow: hidden;
}}
.sidebar-section {{
  padding: 20px 20px 16px;
  border-bottom: 1px solid var(--border);
}}
.sidebar-label {{
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 1.5px;
  color: var(--text3);
  margin-bottom: 10px;
  font-weight: 600;
}}

/* ── Custom selects ── */
.select-wrap {{
  position: relative;
}}
.select-wrap::after {{
  content: '▾';
  position: absolute;
  right: 12px;
  top: 50%;
  transform: translateY(-50%);
  color: var(--accent);
  pointer-events: none;
  font-size: 12px;
}}
select {{
  width: 100%;
  background: var(--bg3);
  border: 1px solid var(--border2);
  border-radius: 8px;
  padding: 10px 32px 10px 14px;
  color: var(--text);
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  appearance: none;
  cursor: pointer;
  transition: border-color 0.2s;
  outline: none;
}}
select:hover {{ border-color: var(--accent2); }}
select:focus {{ border-color: var(--accent); box-shadow: 0 0 0 2px rgba(0,212,255,0.12); }}

.analyze-btn {{
  width: 100%;
  margin-top: 14px;
  padding: 11px;
  background: linear-gradient(135deg, var(--accent), #0088cc);
  border: none;
  border-radius: 8px;
  color: #000;
  font-family: 'Syne', sans-serif;
  font-weight: 700;
  font-size: 13px;
  letter-spacing: 0.5px;
  cursor: pointer;
  transition: opacity 0.2s, transform 0.1s;
}}
.analyze-btn:hover {{ opacity: 0.9; }}
.analyze-btn:active {{ transform: scale(0.98); }}

/* ── Flow info panel ── */
.flow-info {{
  padding: 16px 20px;
  border-bottom: 1px solid var(--border);
  display: none;
}}
.flow-info.visible {{ display: block; }}
.flow-badge {{
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: var(--bg4);
  border-radius: 6px;
  padding: 4px 10px;
  font-size: 11px;
  color: var(--accent);
  margin-bottom: 10px;
  border: 1px solid var(--border2);
}}
.flow-metric {{
  display: flex;
  justify-content: space-between;
  font-size: 11px;
  color: var(--text2);
  padding: 3px 0;
  border-bottom: 1px solid rgba(255,255,255,0.04);
}}
.flow-metric span:last-child {{ color: var(--text); }}
.proto-tags {{
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  margin-top: 10px;
}}
.proto-tag {{
  background: rgba(0, 212, 255, 0.1);
  border: 1px solid rgba(0, 212, 255, 0.25);
  border-radius: 4px;
  padding: 2px 8px;
  font-size: 10px;
  color: var(--accent);
}}

/* ── Protocol histogram ── */
.histo-list {{
  flex: 1;
  overflow-y: auto;
  padding: 16px 20px;
}}
.histo-item {{
  margin-bottom: 8px;
}}
.histo-label {{
  display: flex;
  justify-content: space-between;
  font-size: 10px;
  color: var(--text2);
  margin-bottom: 3px;
}}
.histo-bar-track {{
  height: 4px;
  background: var(--bg4);
  border-radius: 2px;
  overflow: hidden;
}}
.histo-bar-fill {{
  height: 100%;
  background: linear-gradient(90deg, var(--accent), var(--purple));
  border-radius: 2px;
  transition: width 0.6s cubic-bezier(.16,.92,.24,1);
}}

/* ── Main content ── */
.main-content {{
  overflow-y: auto;
  background: var(--bg);
}}

/* ── Empty state ── */
.empty-state {{
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  gap: 16px;
  color: var(--text3);
  text-align: center;
  padding: 40px;
}}
.empty-icon {{
  font-size: 52px;
  opacity: 0.3;
}}
.empty-title {{
  font-family: 'Syne', sans-serif;
  font-size: 18px;
  color: var(--text2);
}}
.empty-sub {{
  font-size: 12px;
  line-height: 1.8;
  max-width: 320px;
}}

/* ── OSI visualization ── */
.osi-container {{
  padding: 28px 32px;
  display: none;
  animation: fadeIn 0.3s ease;
}}
.osi-container.visible {{ display: block; }}

@keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(8px); }} to {{ opacity: 1; transform: translateY(0); }} }}

.viz-header {{
  margin-bottom: 28px;
  display: flex;
  align-items: center;
  gap: 16px;
}}
.flow-arrow {{
  font-family: 'Syne', sans-serif;
  font-size: 16px;
  font-weight: 700;
  display: flex;
  align-items: center;
  gap: 10px;
}}
.flow-addr {{
  padding: 6px 14px;
  background: var(--bg3);
  border: 1px solid var(--border2);
  border-radius: 8px;
  font-size: 13px;
  color: var(--accent);
}}
.flow-arrow-sym {{
  color: var(--text3);
  font-size: 18px;
}}

/* ── OSI panels ── */
.osi-panels {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
  margin-bottom: 32px;
}}

.direction-panel {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 14px;
  overflow: hidden;
}}
.direction-panel-header {{
  padding: 14px 20px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 10px;
}}
.direction-label {{
  font-family: 'Syne', sans-serif;
  font-weight: 700;
  font-size: 13px;
}}
.out-label {{ color: var(--green); }}
.in-label  {{ color: var(--orange); }}
.pkt-count {{
  margin-left: auto;
  font-size: 11px;
  color: var(--text3);
  background: var(--bg4);
  padding: 3px 10px;
  border-radius: 20px;
}}

/* ── OSI Layer stack ── */
.osi-stack {{
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}}

.layer-block {{
  border-radius: 10px;
  overflow: hidden;
  border: 1px solid transparent;
  transition: border-color 0.2s;
  cursor: pointer;
}}
.layer-block:hover {{ border-color: rgba(255,255,255,0.08); }}
.layer-block.expanded {{ border-color: rgba(255,255,255,0.12); }}

.layer-header {{
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  user-select: none;
}}
.layer-num {{
  width: 24px; height: 24px;
  border-radius: 6px;
  display: flex; align-items: center; justify-content: center;
  font-size: 11px;
  font-weight: 700;
  flex-shrink: 0;
}}
.layer-name {{
  font-family: 'Syne', sans-serif;
  font-size: 12px;
  font-weight: 600;
  flex: 1;
}}
.layer-sub {{
  font-size: 10px;
  color: var(--text3);
}}
.layer-chevron {{
  font-size: 10px;
  color: var(--text3);
  transition: transform 0.2s;
}}
.layer-block.expanded .layer-chevron {{ transform: rotate(90deg); }}

.layer-body {{
  display: none;
  padding: 4px 14px 14px;
  background: rgba(0,0,0,0.2);
}}
.layer-block.expanded .layer-body {{ display: block; }}

/* ── Layer color scheme ── */
.l1-block .layer-header {{ background: rgba(255,107,107,0.08); }}
.l1-block .layer-num    {{ background: var(--l1); color: #000; }}
.l1-block .layer-name   {{ color: var(--l1); }}
.l2-block .layer-header {{ background: rgba(255,140,66,0.08); }}
.l2-block .layer-num    {{ background: var(--l2); color: #000; }}
.l2-block .layer-name   {{ color: var(--l2); }}
.l3-block .layer-header {{ background: rgba(255,209,102,0.08); }}
.l3-block .layer-num    {{ background: var(--l3); color: #000; }}
.l3-block .layer-name   {{ color: var(--l3); }}
.l4-block .layer-header {{ background: rgba(0,232,143,0.08); }}
.l4-block .layer-num    {{ background: var(--l4); color: #000; }}
.l4-block .layer-name   {{ color: var(--l4); }}
.l5-block .layer-header {{ background: rgba(0,212,255,0.08); }}
.l5-block .layer-num    {{ background: var(--l5); color: #000; }}
.l5-block .layer-name   {{ color: var(--l5); }}
.l7-block .layer-header {{ background: rgba(255,107,203,0.08); }}
.l7-block .layer-num    {{ background: var(--l7); color: #000; }}
.l7-block .layer-name   {{ color: var(--l7); }}

/* ── Field table ── */
.field-table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 11px;
  margin-top: 4px;
}}
.field-table tr {{
  border-bottom: 1px solid rgba(255,255,255,0.04);
}}
.field-table tr:last-child {{ border: none; }}
.field-table td {{
  padding: 5px 6px;
  vertical-align: top;
}}
.field-table td:first-child {{
  color: var(--text3);
  width: 140px;
  white-space: nowrap;
}}
.field-table td:last-child {{
  color: var(--text);
  font-size: 11px;
  word-break: break-all;
}}
.flag-chip {{
  display: inline-block;
  background: rgba(0,232,143,0.15);
  border: 1px solid rgba(0,232,143,0.3);
  border-radius: 3px;
  padding: 1px 5px;
  font-size: 10px;
  color: var(--green);
  margin: 1px;
}}
.flag-chip.syn  {{ color: var(--accent); background: rgba(0,212,255,0.12); border-color: rgba(0,212,255,0.25); }}
.flag-chip.ack  {{ color: var(--green);  background: rgba(0,232,143,0.12); border-color: rgba(0,232,143,0.25); }}
.flag-chip.fin  {{ color: var(--orange); background: rgba(255,140,66,0.12); border-color: rgba(255,140,66,0.25); }}
.flag-chip.rst  {{ color: var(--red);    background: rgba(255,77,109,0.12);  border-color: rgba(255,77,109,0.25); }}
.flag-chip.psh  {{ color: var(--purple); background: rgba(176,96,255,0.12); border-color: rgba(176,96,255,0.25); }}

.encrypted-badge {{
  display: inline-flex;
  align-items: center;
  gap: 5px;
  background: rgba(176,96,255,0.12);
  border: 1px solid rgba(176,96,255,0.3);
  border-radius: 5px;
  padding: 3px 9px;
  font-size: 10px;
  color: var(--purple);
  margin-bottom: 8px;
}}

.detail-chip {{
  background: var(--bg4);
  border-radius: 4px;
  padding: 3px 8px;
  font-size: 10px;
  color: var(--text2);
  display: inline-block;
  margin: 2px;
}}

.preview-box {{
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 8px 10px;
  font-size: 10px;
  color: var(--text2);
  word-break: break-all;
  line-height: 1.6;
  margin-top: 4px;
  font-family: 'JetBrains Mono', monospace;
}}

/* ── Packet timeline ── */
.timeline-section {{
  margin-top: 8px;
  padding: 0 0 20px 0;
}}
.timeline-title {{
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 1.5px;
  color: var(--text3);
  padding: 0 16px;
  margin-bottom: 12px;
}}
.timeline-wrap {{
  overflow-x: auto;
  padding: 0 16px;
}}
.timeline-grid {{
  display: grid;
  grid-template-columns: repeat(var(--cols, 1), 1fr);
  gap: 4px;
  min-width: max-content;
}}
.pkt-cell {{
  width: 36px; height: 36px;
  border-radius: 6px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 9px;
  font-weight: 600;
  transition: transform 0.1s, opacity 0.1s;
  position: relative;
  border: 1px solid rgba(255,255,255,0.06);
}}
.pkt-cell:hover {{ transform: scale(1.15); opacity: 1 !important; z-index: 10; }}
.pkt-cell.selected {{ outline: 2px solid var(--accent); outline-offset: 1px; }}

/* Direction-based cell colors */
.pkt-cell.out-tcp   {{ background: rgba(0,232,143,0.18); color: var(--green); }}
.pkt-cell.out-udp   {{ background: rgba(0,212,255,0.15); color: var(--accent); }}
.pkt-cell.out-icmp  {{ background: rgba(255,209,102,0.18); color: var(--yellow); }}
.pkt-cell.out-tls   {{ background: rgba(176,96,255,0.18); color: var(--purple); }}
.pkt-cell.out-other {{ background: rgba(255,255,255,0.06); color: var(--text3); }}
.pkt-cell.in-tcp    {{ background: rgba(255,140,66,0.18); color: var(--orange); }}
.pkt-cell.in-udp    {{ background: rgba(0,212,255,0.12); color: var(--accent); }}
.pkt-cell.in-icmp   {{ background: rgba(255,209,102,0.15); color: var(--yellow); }}
.pkt-cell.in-tls    {{ background: rgba(176,96,255,0.15); color: var(--purple); }}
.pkt-cell.in-other  {{ background: rgba(255,255,255,0.05); color: var(--text3); }}

/* ── Tooltip ── */
.tooltip {{
  position: fixed;
  background: var(--bg4);
  border: 1px solid var(--border2);
  border-radius: 8px;
  padding: 10px 14px;
  font-size: 11px;
  color: var(--text);
  pointer-events: none;
  z-index: 9999;
  min-width: 200px;
  max-width: 300px;
  display: none;
  box-shadow: 0 8px 32px rgba(0,0,0,0.5);
  line-height: 1.6;
}}
.tooltip.visible {{ display: block; }}
.tt-row {{ display: flex; justify-content: space-between; gap: 12px; }}
.tt-row .ttk {{ color: var(--text3); }}
.tt-row .ttv {{ color: var(--accent); text-align: right; font-size: 10px; }}

/* ── Packet detail drawer ── */
.pkt-detail {{
  margin-top: 20px;
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 12px;
  overflow: hidden;
  display: none;
  animation: fadeIn 0.2s ease;
}}
.pkt-detail.visible {{ display: block; }}
.pkt-detail-header {{
  padding: 12px 20px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 10px;
  background: var(--bg3);
}}
.pkt-detail-title {{
  font-family: 'Syne', sans-serif;
  font-weight: 700;
  font-size: 13px;
}}
.pkt-detail-close {{
  margin-left: auto;
  background: none;
  border: none;
  color: var(--text3);
  cursor: pointer;
  font-size: 16px;
  line-height: 1;
  padding: 2px 6px;
}}
.pkt-detail-close:hover {{ color: var(--red); }}
.pkt-detail-body {{
  padding: 20px;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 12px;
}}
.pkt-layer-card {{
  background: var(--bg3);
  border-radius: 8px;
  padding: 12px 14px;
  border: 1px solid var(--border);
}}
.plc-title {{
  font-family: 'Syne', sans-serif;
  font-size: 11px;
  font-weight: 700;
  margin-bottom: 8px;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--border);
}}
.plc-row {{
  display: flex;
  gap: 8px;
  margin-bottom: 4px;
  font-size: 10px;
  flex-wrap: wrap;
}}
.plc-key {{ color: var(--text3); flex-shrink: 0; }}
.plc-val {{ color: var(--text); word-break: break-all; }}

/* ── Scrollbar styling ── */
::-webkit-scrollbar {{ width: 6px; height: 6px; }}
::-webkit-scrollbar-track {{ background: var(--bg2); }}
::-webkit-scrollbar-thumb {{ background: var(--border2); border-radius: 3px; }}
::-webkit-scrollbar-thumb:hover {{ background: var(--accent2); }}
</style>
</head>
<body>

<header class="header">
  <div class="header-icon">⬡</div>
  <div>
    <div class="header-title" id="reportTitle">Loading...</div>
    <div class="header-sub" id="reportFile">—</div>
  </div>
  <div class="header-stats" id="headerStats"></div>
</header>

<div class="layout">
  <!-- Sidebar -->
  <aside class="sidebar">
    <div class="sidebar-section">
      <div class="sidebar-label">Source Address</div>
      <div class="select-wrap">
        <select id="srcSelect" onchange="onSrcChange()">
          <option value="">Select a source...</option>
        </select>
      </div>
    </div>
    <div class="sidebar-section">
      <div class="sidebar-label">Destination Address</div>
      <div class="select-wrap">
        <select id="dstSelect" disabled>
          <option value="">Select source first...</option>
        </select>
      </div>
      <button class="analyze-btn" onclick="analyze()" id="analyzeBtn" disabled>
        ▶ ANALYZE FLOW
      </button>
    </div>

    <div class="flow-info" id="flowInfo">
      <div class="flow-badge">⟶ FLOW METRICS</div>
      <div id="flowMetrics"></div>
      <div class="proto-tags" id="flowProtos"></div>
    </div>

    <div class="sidebar-label" style="padding: 14px 20px 6px; font-size:10px; text-transform:uppercase; letter-spacing:1.5px; color:var(--text3);">Protocol Distribution</div>
    <div class="histo-list" id="histoList"></div>
  </aside>

  <!-- Main content -->
  <main class="main-content" id="mainContent">
    <div class="empty-state" id="emptyState">
      <div class="empty-icon">◈</div>
      <div class="empty-title">Select a Flow to Analyze</div>
      <div class="empty-sub">
        Choose a source address and destination, then click Analyze Flow to explore the OSI layers, protocol stack, and packet timeline for that conversation.
      </div>
    </div>
    <div class="osi-container" id="osiContainer"></div>
  </main>
</div>

<div class="tooltip" id="tooltip"></div>

<script>
const DATA = {json_data};

// ─── Init ──────────────────────────────────────────────────────────────────

document.getElementById('reportTitle').textContent = DATA.title;
document.getElementById('reportFile').textContent = DATA.pcap_file;

document.getElementById('headerStats').innerHTML = `
  <div class="stat-chip"><div class="val">${{fmtNum(DATA.total_packets)}}</div><div class="lbl">Packets</div></div>
  <div class="stat-chip"><div class="val">${{fmtBytes(DATA.total_bytes)}}</div><div class="lbl">Total Size</div></div>
  <div class="stat-chip"><div class="val">${{DATA.sources.length}}</div><div class="lbl">Sources</div></div>
  <div class="stat-chip"><div class="val">${{Object.keys(DATA.flows).length}}</div><div class="lbl">Flows</div></div>
  <div class="stat-chip"><div class="val">${{DATA.capture_duration_sec.toFixed(1)}}s</div><div class="lbl">Duration</div></div>
`;

// Populate source select
const srcSel = document.getElementById('srcSelect');
DATA.sources.forEach(src => {{
  const opt = document.createElement('option');
  opt.value = src;
  opt.textContent = src;
  srcSel.appendChild(opt);
}});

// Build protocol histogram
const maxProto = Math.max(...Object.values(DATA.protocol_histogram));
const sortedProtos = Object.entries(DATA.protocol_histogram)
  .sort((a,b) => b[1]-a[1]).slice(0,20);
const histoList = document.getElementById('histoList');
sortedProtos.forEach(([name, count]) => {{
  const pct = Math.round(count/maxProto*100);
  histoList.innerHTML += `
    <div class="histo-item">
      <div class="histo-label"><span>${{name}}</span><span>${{fmtNum(count)}}</span></div>
      <div class="histo-bar-track"><div class="histo-bar-fill" style="width:${{pct}}%"></div></div>
    </div>`;
}});

// ─── Source select handler ─────────────────────────────────────────────────

function onSrcChange() {{
  const src = document.getElementById('srcSelect').value;
  const dstSel = document.getElementById('dstSelect');
  const btn = document.getElementById('analyzeBtn');
  dstSel.innerHTML = '';

  if (!src) {{
    dstSel.innerHTML = '<option value="">Select source first...</option>';
    dstSel.disabled = true;
    btn.disabled = true;
    return;
  }}

  // Find all destinations reachable from this source
  const dests = new Set();
  Object.keys(DATA.flows).forEach(key => {{
    const [s, d] = key.split('||');
    if (s === src) dests.add(d);
    if (d === src) dests.add(s); // reverse flows
  }});

  if (dests.size === 0) {{
    dstSel.innerHTML = '<option value="">No destinations found</option>';
    dstSel.disabled = true;
    btn.disabled = true;
    return;
  }}

  const sorted = [...dests].sort((a,b) => {{
    const aParts = a.split('.').map(Number);
    const bParts = b.split('.').map(Number);
    if (aParts.length === 4 && bParts.length === 4) {{
      for (let i=0; i<4; i++) if (aParts[i]!==bParts[i]) return aParts[i]-bParts[i];
    }}
    return a.localeCompare(b);
  }});

  sorted.forEach(dst => {{
    const opt = document.createElement('option');
    opt.value = dst;
    opt.textContent = dst;
    dstSel.appendChild(opt);
  }});

  dstSel.disabled = false;
  btn.disabled = false;
  document.getElementById('dstSelect').onchange = onDstChange;
  onDstChange();
}}

function onDstChange() {{
  const src = document.getElementById('srcSelect').value;
  const dst = document.getElementById('dstSelect').value;
  if (!src || !dst) return;

  const flow = getFlow(src, dst);
  if (!flow) return;

  const info = document.getElementById('flowInfo');
  const metrics = document.getElementById('flowMetrics');
  const protoTags = document.getElementById('flowProtos');

  const totalPkts = flow.packets_out.length + flow.packets_in.length;
  const dur = (flow.last_seen - flow.first_seen).toFixed(3);

  metrics.innerHTML = `
    <div class="flow-metric"><span>Packets →</span><span>${{flow.packets_out.length}}</span></div>
    <div class="flow-metric"><span>Packets ←</span><span>${{flow.packets_in.length}}</span></div>
    <div class="flow-metric"><span>Bytes →</span><span>${{fmtBytes(flow.bytes_out)}}</span></div>
    <div class="flow-metric"><span>Bytes ←</span><span>${{fmtBytes(flow.bytes_in)}}</span></div>
    <div class="flow-metric"><span>Total Packets</span><span>${{totalPkts}}</span></div>
    <div class="flow-metric"><span>Duration</span><span>${{dur}}s</span></div>
  `;

  protoTags.innerHTML = flow.protocol_summary
    .map(p => `<span class="proto-tag">${{p}}</span>`).join('');

  info.classList.add('visible');
}}

// ─── Main analyze handler ──────────────────────────────────────────────────

function analyze() {{
  const src = document.getElementById('srcSelect').value;
  const dst = document.getElementById('dstSelect').value;
  if (!src || !dst) return;

  const flow = getFlow(src, dst);
  const emptyState = document.getElementById('emptyState');
  const osiCont = document.getElementById('osiContainer');

  emptyState.style.display = 'none';
  osiCont.classList.add('visible');
  osiCont.innerHTML = '';

  // Flow header
  osiCont.innerHTML += `
    <div class="viz-header">
      <div class="flow-arrow">
        <span class="flow-addr">${{src}}</span>
        <span class="flow-arrow-sym">⟷</span>
        <span class="flow-addr">${{dst}}</span>
      </div>
    </div>`;

  // OSI panels
  const panelsDiv = document.createElement('div');
  panelsDiv.className = 'osi-panels';

  panelsDiv.innerHTML = `
    <div class="direction-panel" id="panelOut">
      <div class="direction-panel-header">
        <span style="color:var(--green)">▶</span>
        <span class="direction-label out-label">OUTBOUND</span>
        <span style="font-size:11px;color:var(--text3)">${{src}} → ${{dst}}</span>
        <span class="pkt-count">${{(flow ? flow.packets_out.length : 0)}} packets</span>
      </div>
      <div class="osi-stack" id="stackOut"></div>
    </div>
    <div class="direction-panel" id="panelIn">
      <div class="direction-panel-header">
        <span style="color:var(--orange)">◀</span>
        <span class="direction-label in-label">INBOUND</span>
        <span style="font-size:11px;color:var(--text3)">${{dst}} → ${{src}}</span>
        <span class="pkt-count">${{(flow ? flow.packets_in.length : 0)}} packets</span>
      </div>
      <div class="osi-stack" id="stackIn"></div>
    </div>
  `;
  osiCont.appendChild(panelsDiv);

  if (flow) {{
    buildOsiStack(document.getElementById('stackOut'), flow.packets_out, 'out');
    buildOsiStack(document.getElementById('stackIn'), flow.packets_in, 'in');
  }} else {{
    document.getElementById('stackOut').innerHTML = '<div style="padding:20px;color:var(--text3);font-size:12px;">No outbound packets found</div>';
    document.getElementById('stackIn').innerHTML = '<div style="padding:20px;color:var(--text3);font-size:12px;">No inbound packets found</div>';
  }}

  // Packet timeline
  if (flow) {{
    const timelineDiv = document.createElement('div');
    timelineDiv.className = 'timeline-section';

    const allPkts = [
      ...flow.packets_out.map(p => ({{...p, dir:'out'}})),
      ...flow.packets_in.map(p => ({{...p, dir:'in'}}))
    ].sort((a,b) => a.frame_number - b.frame_number);

    const cols = Math.min(allPkts.length, 32);
    timelineDiv.innerHTML = `
      <div class="timeline-title">Packet Timeline — ${{allPkts.length}} packets total</div>
      <div class="timeline-wrap">
        <div class="timeline-grid" style="--cols:${{cols}}" id="timelineGrid"></div>
      </div>
      <div class="pkt-detail" id="pktDetail">
        <div class="pkt-detail-header">
          <span class="pkt-detail-title">Packet Detail</span>
          <button class="pkt-detail-close" onclick="document.getElementById('pktDetail').classList.remove('visible')">✕</button>
        </div>
        <div class="pkt-detail-body" id="pktDetailBody"></div>
      </div>`;
    osiCont.appendChild(timelineDiv);

    setTimeout(() => {{
      const grid = document.getElementById('timelineGrid');
      allPkts.forEach((pkt, i) => {{
        const cell = document.createElement('div');
        const proto = pktProtoClass(pkt);
        cell.className = `pkt-cell ${{pkt.dir}}-${{proto}}`;
        cell.title = '';
        cell.dataset.idx = i;

        // Protocol label
        const labels = {{'tcp':'TCP','udp':'UDP','icmp':'ICM','tls':'TLS','other':'...'}};
        cell.textContent = labels[proto] || '···';

        cell.addEventListener('mouseenter', (e) => showTooltip(e, pkt));
        cell.addEventListener('mousemove', (e) => moveTooltip(e));
        cell.addEventListener('mouseleave', hideTooltip);
        cell.addEventListener('click', () => showPktDetail(pkt, cell));
        grid.appendChild(cell);
      }});
    }}, 50);
  }}
}}

// ─── OSI Stack builder ─────────────────────────────────────────────────────

function buildOsiStack(container, packets, dir) {{
  if (!packets || packets.length === 0) {{
    container.innerHTML = '<div style="padding:20px;color:var(--text3);font-size:12px;">No packets in this direction</div>';
    return;
  }}

  // Aggregate data across all packets in this direction
  const agg = aggregatePackets(packets);

  const layers = [
    {{ num: 1, cls: 'l1-block', name: 'Physical', sub: 'Bits & Signals', build: () => buildL1(agg) }},
    {{ num: 2, cls: 'l2-block', name: 'Data Link', sub: 'Frames & MACs', build: () => buildL2(agg) }},
    {{ num: 3, cls: 'l3-block', name: 'Network', sub: 'Packets & IPs', build: () => buildL3(agg) }},
    {{ num: 4, cls: 'l4-block', name: 'Transport', sub: 'Segments & Ports', build: () => buildL4(agg) }},
    {{ num: '5–6', cls: 'l5-block', name: 'Session / Presentation', sub: 'Encryption & Encoding', build: () => buildL56(agg) }},
    {{ num: 7, cls: 'l7-block', name: 'Application', sub: 'Protocols & Data', build: () => buildL7(agg) }},
  ];

  layers.forEach(layer => {{
    const body = layer.build();
    if (!body) return;

    const block = document.createElement('div');
    block.className = `layer-block ${{layer.cls}}`;

    block.innerHTML = `
      <div class="layer-header" onclick="toggleLayer(this.parentElement)">
        <div class="layer-num">${{layer.num}}</div>
        <div>
          <div class="layer-name">${{layer.name}}</div>
          <div class="layer-sub">${{layer.sub}}</div>
        </div>
        <div style="margin-left:auto;margin-right:6px" class="layer-sub"></div>
        <div class="layer-chevron">▶</div>
      </div>
      <div class="layer-body">${{body}}</div>`;

    container.appendChild(block);
  }});
}}

function toggleLayer(block) {{
  block.classList.toggle('expanded');
}}

// ─── Aggregate packets into summary data ──────────────────────────────────

function aggregatePackets(packets) {{
  const a = {{
    count: packets.length,
    totalBytes: packets.reduce((s,p) => s+p.size_bytes, 0),
    frameSizes: packets.map(p => p.l1.frame_size_bytes),
    srcMacs: new Set(), dstMacs: new Set(),
    ethertypes: new Set(), vlanIds: new Set(),
    srcIps: new Set(), dstIps: new Set(),
    ttls: new Set(),
    protocols: new Set(),
    srcPorts: new Set(), dstPorts: new Set(),
    services: new Set(),
    tcpFlags: new Set(),
    windowSizes: [],
    icmpTypes: new Set(),
    appProtos: new Set(),
    details: [],
    isEncrypted: false,
    payloadPreviews: [],
  }};

  packets.forEach(p => {{
    if (p.l2) {{
      a.srcMacs.add(p.l2.src_mac);
      a.dstMacs.add(p.l2.dst_mac);
      a.ethertypes.add(p.l2.ethertype);
      if (p.l2.vlan_id != null) a.vlanIds.add(p.l2.vlan_id);
    }}
    if (p.l3) {{
      a.srcIps.add(p.l3.src_ip);
      a.dstIps.add(p.l3.dst_ip);
      a.protocols.add(p.l3.protocol);
      if (p.l3.ttl != null) a.ttls.add(p.l3.ttl);
    }}
    if (p.l4) {{
      a.protocols.add(p.l4.protocol);
      if (p.l4.src_port != null) a.srcPorts.add(p.l4.src_port);
      if (p.l4.dst_port != null) a.dstPorts.add(p.l4.dst_port);
      if (p.l4.service_name) a.services.add(p.l4.service_name);
      if (p.l4.flags) p.l4.flags.split('|').forEach(f => a.tcpFlags.add(f));
      if (p.l4.window_size != null) a.windowSizes.push(p.l4.window_size);
      if (p.l4.icmp_description) a.icmpTypes.add(p.l4.icmp_description);
    }}
    if (p.l7) {{
      if (p.l7.protocol) a.appProtos.add(p.l7.protocol);
      if (p.l7.is_encrypted) a.isEncrypted = true;
      p.l7.details.forEach(d => a.details.push(d));
      if (p.l7.payload_preview) a.payloadPreviews.push(p.l7.payload_preview);
    }}
  }});

  // Unique details
  a.details = [...new Set(a.details)].slice(0, 8);
  a.payloadPreviews = a.payloadPreviews.slice(0, 3);

  const sizes = a.frameSizes;
  a.minSize = Math.min(...sizes);
  a.maxSize = Math.max(...sizes);
  a.avgSize = Math.round(sizes.reduce((s,x)=>s+x,0)/sizes.length);

  return a;
}}

// ─── Layer builders ───────────────────────────────────────────────────────

function buildL1(a) {{
  return `<table class="field-table">
    <tr><td>Packets</td><td>${{a.count}}</td></tr>
    <tr><td>Total bytes</td><td>${{fmtBytes(a.totalBytes)}}</td></tr>
    <tr><td>Frame sizes</td><td>min ${{a.minSize}}B / avg ${{a.avgSize}}B / max ${{a.maxSize}}B</td></tr>
    <tr><td>Link type</td><td>Ethernet IEEE 802.3</td></tr>
    <tr><td>Medium</td><td>802.3 (inferred)</td></tr>
  </table>`;
}}

function buildL2(a) {{
  if (!a.srcMacs.size) return null;
  const vlans = a.vlanIds.size > 0 ? [...a.vlanIds].join(', ') : 'None';
  return `<table class="field-table">
    <tr><td>Src MACs</td><td>${{[...a.srcMacs].join('<br>')}}</td></tr>
    <tr><td>Dst MACs</td><td>${{[...a.dstMacs].join('<br>')}}</td></tr>
    <tr><td>Ethertype(s)</td><td>${{[...a.ethertypes].join(', ')}}</td></tr>
    <tr><td>VLAN IDs</td><td>${{vlans}}</td></tr>
    <tr><td>Frame type</td><td>${{a.vlanIds.size > 0 ? '802.1Q Tagged' : 'Ethernet II (untagged)'}}</td></tr>
  </table>`;
}}

function buildL3(a) {{
  if (!a.srcIps.size) return null;
  const protos = [...a.protocols].filter(p => ['IPv4','IPv6','ARP'].includes(p)).join(', ');
  const ttlList = [...a.ttls].sort((x,y)=>x-y).join(', ');
  return `<table class="field-table">
    <tr><td>Protocol(s)</td><td>${{protos || [...a.protocols].join(', ')}}</td></tr>
    <tr><td>Src IP(s)</td><td>${{[...a.srcIps].join('<br>')}}</td></tr>
    <tr><td>Dst IP(s)</td><td>${{[...a.dstIps].join('<br>')}}</td></tr>
    <tr><td>TTL values</td><td>${{ttlList || 'N/A'}}</td></tr>
  </table>`;
}}

function buildL4(a) {{
  const l4protos = [...a.protocols].filter(p => ['TCP','UDP','ICMP','ICMPv6','SCTP'].includes(p));
  if (!l4protos.length) return null;

  let html = `<table class="field-table">
    <tr><td>Protocol(s)</td><td>${{l4protos.join(', ')}}</td></tr>`;

  if (a.srcPorts.size) {{
    html += `<tr><td>Src ports</td><td>${{[...a.srcPorts].sort((x,y)=>x-y).join(', ')}}</td></tr>`;
  }}
  if (a.dstPorts.size) {{
    html += `<tr><td>Dst ports</td><td>${{[...a.dstPorts].sort((x,y)=>x-y).join(', ')}}</td></tr>`;
  }}
  if (a.services.size) {{
    html += `<tr><td>Services</td><td>${{[...a.services].join(', ')}}</td></tr>`;
  }}
  if (a.tcpFlags.size) {{
    const flagChips = [...a.tcpFlags].filter(f=>f && f!=='<none>').map(f =>
      `<span class="flag-chip ${{f.toLowerCase()}}">${{f}}</span>`).join('');
    html += `<tr><td>TCP flags seen</td><td>${{flagChips}}</td></tr>`;
  }}
  if (a.windowSizes.length) {{
    const minW = Math.min(...a.windowSizes);
    const maxW = Math.max(...a.windowSizes);
    html += `<tr><td>Window sizes</td><td>min ${{minW}} / max ${{maxW}} bytes</td></tr>`;
  }}
  if (a.icmpTypes.size) {{
    html += `<tr><td>ICMP messages</td><td>${{[...a.icmpTypes].join('<br>')}}</td></tr>`;
  }}

  html += '</table>';
  return html;
}}

function buildL56(a) {{
  if (!a.isEncrypted && !a.appProtos.size) return null;
  let html = '';
  if (a.isEncrypted) {{
    html += `<div class="encrypted-badge">🔒 Encrypted payload detected</div><br>`;
  }}
  const tlsProtos = [...a.appProtos].filter(p => p.startsWith('TLS'));
  if (tlsProtos.length) {{
    html += `<table class="field-table">
      <tr><td>Encryption</td><td>${{tlsProtos.join(', ')}}</td></tr>
      <tr><td>Note</td><td>Payload content is encrypted; headers only visible</td></tr>
    </table>`;
  }} else if (a.isEncrypted) {{
    html += `<table class="field-table">
      <tr><td>Encryption</td><td>Detected (unknown protocol)</td></tr>
    </table>`;
  }} else {{
    return null;
  }}
  return html;
}}

function buildL7(a) {{
  if (!a.appProtos.size && !a.details.length) return null;
  let html = '';
  if (a.appProtos.size) {{
    html += `<table class="field-table">
      <tr><td>App protocol(s)</td><td>${{[...a.appProtos].join(', ')}}</td></tr>
    </table>`;
  }}
  if (a.details.length) {{
    html += `<div style="margin-top:8px">`;
    a.details.forEach(d => {{ html += `<span class="detail-chip">${{d}}</span>`; }});
    html += `</div>`;
  }}
  if (a.payloadPreviews.length) {{
    html += `<div style="margin-top:8px;font-size:10px;color:var(--text3);margin-bottom:4px">Payload preview (ASCII):</div>`;
    a.payloadPreviews.slice(0,1).forEach(p => {{
      html += `<div class="preview-box">${{escapeHtml(p)}}</div>`;
    }});
  }}
  return html;
}}

// ─── Packet detail ────────────────────────────────────────────────────────

function showPktDetail(pkt, cell) {{
  document.querySelectorAll('.pkt-cell.selected').forEach(c => c.classList.remove('selected'));
  cell.classList.add('selected');

  const detail = document.getElementById('pktDetail');
  const body = document.getElementById('pktDetailBody');
  detail.classList.add('visible');

  const cards = [];

  // Frame info
  cards.push(layerCard('🔲 Frame', [
    ['#', pkt.frame_number],
    ['Time', pkt.timestamp.toFixed(6) + 's'],
    ['Size', pkt.size_bytes + ' bytes'],
    ['Direction', pkt.direction === 'out' ? '→ Outbound' : '← Inbound'],
    ['Link type', pkt.l1.link_type],
  ]));

  // L2
  if (pkt.l2) {{
    const rows = [
      ['Src MAC', pkt.l2.src_mac],
      ['Dst MAC', pkt.l2.dst_mac],
      ['Ethertype', pkt.l2.ethertype + ' (' + pkt.l2.ethertype_hex + ')'],
      ['Frame type', pkt.l2.frame_type],
    ];
    if (pkt.l2.vlan_id != null) rows.push(['VLAN ID', pkt.l2.vlan_id]);
    cards.push(layerCard('🟠 L2 Data Link', rows));
  }}

  // L3
  if (pkt.l3) {{
    const rows = [
      ['Protocol', pkt.l3.protocol],
      ['Src IP', pkt.l3.src_ip],
      ['Dst IP', pkt.l3.dst_ip],
    ];
    if (pkt.l3.ttl != null) rows.push(['TTL', pkt.l3.ttl]);
    if (pkt.l3.hop_limit != null) rows.push(['Hop Limit', pkt.l3.hop_limit]);
    if (pkt.l3.total_length != null) rows.push(['Total Length', pkt.l3.total_length + ' bytes']);
    if (pkt.l3.flags) rows.push(['IP Flags', pkt.l3.flags]);
    if (pkt.l3.identification != null) rows.push(['ID', '0x' + pkt.l3.identification.toString(16).toUpperCase()]);
    if (pkt.l3.header_checksum) rows.push(['Checksum', pkt.l3.header_checksum]);
    if (pkt.l3.dscp != null) rows.push(['DSCP', pkt.l3.dscp]);
    if (pkt.l3.flow_label != null) rows.push(['Flow Label', '0x' + pkt.l3.flow_label.toString(16)]);
    if (pkt.l3.arp_op) rows.push(['ARP Op', pkt.l3.arp_op]);
    cards.push(layerCard('🟡 L3 Network', rows));
  }}

  // L4
  if (pkt.l4) {{
    const rows = [['Protocol', pkt.l4.protocol]];
    if (pkt.l4.src_port != null) rows.push(['Src Port', pkt.l4.src_port]);
    if (pkt.l4.dst_port != null) rows.push(['Dst Port', pkt.l4.dst_port]);
    if (pkt.l4.service_name) rows.push(['Service', pkt.l4.service_name]);
    if (pkt.l4.flags) rows.push(['TCP Flags', pkt.l4.flags]);
    if (pkt.l4.seq_num != null) rows.push(['Seq', pkt.l4.seq_num]);
    if (pkt.l4.ack_num != null) rows.push(['Ack', pkt.l4.ack_num]);
    if (pkt.l4.window_size != null) rows.push(['Window', pkt.l4.window_size + ' bytes']);
    if (pkt.l4.checksum) rows.push(['Checksum', pkt.l4.checksum]);
    if (pkt.l4.icmp_description) rows.push(['ICMP', pkt.l4.icmp_description]);
    if (pkt.l4.icmp_checksum) rows.push(['ICMP Chk', pkt.l4.icmp_checksum]);
    if (pkt.l4.udp_length != null) rows.push(['UDP Length', pkt.l4.udp_length]);
    cards.push(layerCard('🟢 L4 Transport', rows));
  }}

  // L7
  if (pkt.l7) {{
    const rows = [];
    if (pkt.l7.protocol) rows.push(['Protocol', pkt.l7.protocol]);
    rows.push(['Payload', pkt.l7.payload_bytes + ' bytes']);
    rows.push(['Encrypted', pkt.l7.is_encrypted ? '🔒 Yes' : 'No']);
    if (pkt.l7.details.length) rows.push(['Info', pkt.l7.details.join('; ')]);
    cards.push(layerCard('🟣 L7 Application', rows));
  }}

  body.innerHTML = cards.join('');
  detail.scrollIntoView({{ behavior: 'smooth', block: 'nearest' }});
}}

function layerCard(title, rows) {{
  const rowsHtml = rows.map(([k,v]) =>
    `<div class="plc-row"><span class="plc-key">${{k}}:</span><span class="plc-val">${{escapeHtml(String(v))}}</span></div>`
  ).join('');
  return `<div class="pkt-layer-card"><div class="plc-title">${{title}}</div>${{rowsHtml}}</div>`;
}}

// ─── Tooltip ──────────────────────────────────────────────────────────────

function showTooltip(e, pkt) {{
  const tt = document.getElementById('tooltip');
  const l4p = pkt.l4 ? pkt.l4.protocol : '';
  const svc = pkt.l4 && pkt.l4.service_name ? pkt.l4.service_name : '';
  const ports = pkt.l4 && pkt.l4.src_port
    ? `${{pkt.l4.src_port}} → ${{pkt.l4.dst_port}}` : '—';
  const flags = pkt.l4 && pkt.l4.flags ? pkt.l4.flags : '';
  const app = pkt.l7 && pkt.l7.protocol ? pkt.l7.protocol : '—';
  const detail = pkt.l7 && pkt.l7.details[0] ? pkt.l7.details[0] : '';

  tt.innerHTML = `
    <div class="tt-row"><span class="ttk">Frame</span><span class="ttv">#${{pkt.frame_number}}</span></div>
    <div class="tt-row"><span class="ttk">Size</span><span class="ttv">${{pkt.size_bytes}}B</span></div>
    <div class="tt-row"><span class="ttk">L4</span><span class="ttv">${{l4p}} ${{svc ? '('+svc+')' : ''}}</span></div>
    ${{ports !== '—' ? `<div class="tt-row"><span class="ttk">Ports</span><span class="ttv">${{ports}}</span></div>` : ''}}
    ${{flags ? `<div class="tt-row"><span class="ttk">Flags</span><span class="ttv">${{flags}}</span></div>` : ''}}
    <div class="tt-row"><span class="ttk">App</span><span class="ttv">${{app}}</span></div>
    ${{detail ? `<div style="margin-top:6px;color:var(--text2);font-size:10px">${{escapeHtml(detail.slice(0,60))}}</div>` : ''}}
  `;
  tt.classList.add('visible');
  moveTooltip(e);
}}

function moveTooltip(e) {{
  const tt = document.getElementById('tooltip');
  const x = e.clientX + 14;
  const y = e.clientY - 10;
  const maxX = window.innerWidth - tt.offsetWidth - 10;
  const maxY = window.innerHeight - tt.offsetHeight - 10;
  tt.style.left = Math.min(x, maxX) + 'px';
  tt.style.top  = Math.min(y, maxY) + 'px';
}}

function hideTooltip() {{
  document.getElementById('tooltip').classList.remove('visible');
}}

// ─── Utilities ────────────────────────────────────────────────────────────

function getFlow(src, dst) {{
  const fwd = DATA.flows[src+'||'+dst];
  if (fwd) return fwd;
  // Try reverse — swap packets_in/out perspective
  const rev = DATA.flows[dst+'||'+src];
  if (rev) {{
    return {{
      ...rev,
      src: src, dst: dst,
      packets_out: rev.packets_in,
      packets_in: rev.packets_out,
      bytes_out: rev.bytes_in,
      bytes_in: rev.bytes_out,
    }};
  }}
  return null;
}}

function pktProtoClass(pkt) {{
  if (pkt.l7 && pkt.l7.protocol && pkt.l7.protocol.startsWith('TLS')) return 'tls';
  if (!pkt.l4) return 'other';
  const p = pkt.l4.protocol;
  if (p === 'TCP') return 'tcp';
  if (p === 'UDP') return 'udp';
  if (p === 'ICMP' || p === 'ICMPv6') return 'icmp';
  return 'other';
}}

function fmtNum(n) {{
  return n.toLocaleString();
}}

function fmtBytes(n) {{
  if (n < 1024) return n + 'B';
  if (n < 1048576) return (n/1024).toFixed(1) + 'KB';
  if (n < 1073741824) return (n/1048576).toFixed(1) + 'MB';
  return (n/1073741824).toFixed(2) + 'GB';
}}

function escapeHtml(s) {{
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}}
</script>
</body>
</html>"#,
        title = title,
        json_data = json_data,
    )
}