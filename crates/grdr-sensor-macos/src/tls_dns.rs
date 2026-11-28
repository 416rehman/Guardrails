// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

const TLS_CONTENT_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_EXT_SERVER_NAME: u16 = 0x0000;
const TLS_SNI_HOST_NAME: u8 = 0x00;
const MAX_TLS_RECORD_BYTES: usize = 16_384;
const MAX_HOSTNAME_LEN: usize = 253;

const DNS_HEADER_LEN: usize = 12;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_MAX_POINTER_JUMPS: usize = 16;
const DNS_MAX_LABELS: usize = 127;
const DNS_MAX_QUESTION_RECORDS: u16 = 64;
const DNS_MAX_ANSWER_RECORDS: usize = 64;
const DEFAULT_DNS_CACHE_CAPACITY: usize = 4_096;

struct ByteCursor<'a> {
    slice: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TlsSniPeekResult {
    Found { sni: String },
    NeedMoreBytes,
    NotTls,
    NoSniExtension,
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsParsedPacket {
    pub tx_id: u16,
    pub is_response: bool,
    pub rcode: u8,
    pub query_name: String,
    pub query_type: u16,
    pub answer_ips: Vec<IpAddr>,
    pub cnames: Vec<String>,
    pub min_ttl_secs: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedDomainEntry {
    domain: String,
    expires_epoch_s: u64,
}

#[derive(Debug, Clone)]
pub struct DnsDomainIpCache {
    capacity: usize,
    entries: BTreeMap<IpAddr, CachedDomainEntry>,
}

impl<'a> ByteCursor<'a> {
    const fn new(slice: &'a [u8]) -> Self {
        Self { slice }
    }

    const fn remaining(&self) -> usize {
        self.slice.len()
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.slice.split_at_checked(len)?;
        self.slice = tail;
        Some(head)
    }

    fn read_u8(&mut self) -> Option<u8> {
        let bytes = self.take(1)?;
        bytes.first().copied()
    }

    fn read_u16_be(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        let arr: [u8; 2] = bytes.try_into().ok()?;
        Some(u16::from_be_bytes(arr))
    }

    fn read_u24_be(&mut self) -> Option<u32> {
        let bytes = self.take(3)?;
        let b0 = u32::from(*bytes.first()?);
        let b1 = u32::from(*bytes.get(1)?);
        let b2 = u32::from(*bytes.get(2)?);
        Some((b0 << 16) | (b1 << 8) | b2)
    }
}

impl Default for DnsDomainIpCache {
    fn default() -> Self {
        Self::new(DEFAULT_DNS_CACHE_CAPACITY)
    }
}

impl DnsDomainIpCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(16),
            entries: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn record_response(&mut self, parsed: &DnsParsedPacket, now_epoch_s: u64) {
        if !parsed.is_response || parsed.query_name.is_empty() {
            return;
        }
        let ttl = u64::from(parsed.min_ttl_secs.clamp(1, 86_400));
        let expires_epoch_s = now_epoch_s.saturating_add(ttl);
        for &ip in &parsed.answer_ips {
            if !self.entries.contains_key(&ip) && self.entries.len() >= self.capacity {
                self.evict_one(now_epoch_s);
            }
            self.entries.insert(
                ip,
                CachedDomainEntry {
                    domain: parsed.query_name.clone(),
                    expires_epoch_s,
                },
            );
        }
    }

    pub fn lookup_ip(&mut self, ip: IpAddr, now_epoch_s: u64) -> Option<&str> {
        let expired = self
            .entries
            .get(&ip)
            .is_some_and(|e| e.expires_epoch_s <= now_epoch_s);
        if expired {
            self.entries.remove(&ip);
            return None;
        }
        self.entries.get(&ip).map(|e| e.domain.as_str())
    }

    fn evict_one(&mut self, now_epoch_s: u64) {
        let expired_key = self
            .entries
            .iter()
            .find(|(_, v)| v.expires_epoch_s <= now_epoch_s)
            .map(|(k, _)| *k);
        if let Some(k) = expired_key {
            self.entries.remove(&k);
            return;
        }
        if let Some(oldest_key) = self
            .entries
            .iter()
            .min_by_key(|(_, v)| v.expires_epoch_s)
            .map(|(k, _)| *k)
        {
            self.entries.remove(&oldest_key);
        }
    }
}

pub fn peek_tls_client_hello_sni(raw: &[u8]) -> TlsSniPeekResult {
    if raw.len() < 5 {
        return TlsSniPeekResult::NeedMoreBytes;
    }
    let mut rec = ByteCursor::new(raw);
    let Some(content_type) = rec.read_u8() else {
        return TlsSniPeekResult::NeedMoreBytes;
    };
    let Some(legacy_ver) = rec.read_u16_be() else {
        return TlsSniPeekResult::NeedMoreBytes;
    };
    let Some(record_len_u16) = rec.read_u16_be() else {
        return TlsSniPeekResult::NeedMoreBytes;
    };
    if content_type != TLS_CONTENT_HANDSHAKE || !(0x0300..=0x0304).contains(&legacy_ver) {
        return TlsSniPeekResult::NotTls;
    }
    let record_len = usize::from(record_len_u16);
    if record_len == 0 || record_len > MAX_TLS_RECORD_BYTES {
        return TlsSniPeekResult::Malformed;
    }
    if rec.remaining() < record_len {
        return TlsSniPeekResult::NeedMoreBytes;
    }
    let Some(record_body) = rec.take(record_len) else {
        return TlsSniPeekResult::NeedMoreBytes;
    };

    let mut hs = ByteCursor::new(record_body);
    let Some(hs_type) = hs.read_u8() else {
        return TlsSniPeekResult::Malformed;
    };
    if hs_type != TLS_HANDSHAKE_CLIENT_HELLO {
        return TlsSniPeekResult::NotTls;
    }
    let Some(hello_len_u32) = hs.read_u24_be() else {
        return TlsSniPeekResult::Malformed;
    };
    let Ok(hello_len) = usize::try_from(hello_len_u32) else {
        return TlsSniPeekResult::Malformed;
    };
    let Some(hello_body) = hs.take(hello_len) else {
        return TlsSniPeekResult::NeedMoreBytes;
    };

    let mut ch = ByteCursor::new(hello_body);
    if ch.read_u16_be().is_none() || ch.take(32).is_none() {
        return TlsSniPeekResult::Malformed;
    }
    let Some(session_len) = ch.read_u8() else {
        return TlsSniPeekResult::Malformed;
    };
    if ch.take(usize::from(session_len)).is_none() {
        return TlsSniPeekResult::Malformed;
    }
    let Some(cipher_len) = ch.read_u16_be() else {
        return TlsSniPeekResult::Malformed;
    };
    if cipher_len == 0 || (cipher_len & 1) != 0 || ch.take(usize::from(cipher_len)).is_none() {
        return TlsSniPeekResult::Malformed;
    }
    let Some(comp_len) = ch.read_u8() else {
        return TlsSniPeekResult::Malformed;
    };
    if comp_len == 0 || ch.take(usize::from(comp_len)).is_none() {
        return TlsSniPeekResult::Malformed;
    }
    if ch.remaining() == 0 {
        return TlsSniPeekResult::NoSniExtension;
    }
    let Some(ext_total_len) = ch.read_u16_be() else {
        return TlsSniPeekResult::Malformed;
    };
    let Some(exts_bytes) = ch.take(usize::from(ext_total_len)) else {
        return TlsSniPeekResult::Malformed;
    };

    parse_tls_extensions_for_sni(exts_bytes)
}

fn parse_tls_extensions_for_sni(exts_bytes: &[u8]) -> TlsSniPeekResult {
    let mut exts = ByteCursor::new(exts_bytes);
    while exts.remaining() > 0 {
        let Some(ext_type) = exts.read_u16_be() else {
            return TlsSniPeekResult::Malformed;
        };
        let Some(ext_len) = exts.read_u16_be() else {
            return TlsSniPeekResult::Malformed;
        };
        let Some(ext_body) = exts.take(usize::from(ext_len)) else {
            return TlsSniPeekResult::Malformed;
        };
        if ext_type != TLS_EXT_SERVER_NAME {
            continue;
        }
        let mut sni_cur = ByteCursor::new(ext_body);
        let Some(list_len) = sni_cur.read_u16_be() else {
            return TlsSniPeekResult::Malformed;
        };
        if usize::from(list_len) != sni_cur.remaining() {
            return TlsSniPeekResult::Malformed;
        }
        while sni_cur.remaining() > 0 {
            let Some(name_type) = sni_cur.read_u8() else {
                return TlsSniPeekResult::Malformed;
            };
            let Some(name_len) = sni_cur.read_u16_be() else {
                return TlsSniPeekResult::Malformed;
            };
            let Some(name_bytes) = sni_cur.take(usize::from(name_len)) else {
                return TlsSniPeekResult::Malformed;
            };
            if name_type != TLS_SNI_HOST_NAME {
                continue;
            }
            let Ok(raw_host) = std::str::from_utf8(name_bytes) else {
                return TlsSniPeekResult::Malformed;
            };
            let clean = raw_host.trim().trim_end_matches('.').to_ascii_lowercase();
            if clean.is_empty()
                || clean.len() > MAX_HOSTNAME_LEN
                || !clean
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
            {
                return TlsSniPeekResult::Malformed;
            }
            return TlsSniPeekResult::Found { sni: clean };
        }
        return TlsSniPeekResult::NoSniExtension;
    }
    TlsSniPeekResult::NoSniExtension
}

pub fn parse_dns_packet(packet: &[u8]) -> Option<DnsParsedPacket> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }
    let tx_id = u16::from_be_bytes([*packet.first()?, *packet.get(1)?]);
    let flags = u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]);
    let qdcount = u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]);
    let ancount = u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]);
    let is_response = (flags & 0x8000) != 0;
    let rcode = u8::try_from(flags & 0x000F).ok()?;

    if qdcount > DNS_MAX_QUESTION_RECORDS {
        return None;
    }

    let mut offset = DNS_HEADER_LEN;
    let mut query_name = String::new();
    let mut query_type: u16 = 0;

    for idx in 0..usize::from(qdcount) {
        let (name, next_off) = read_dns_name(packet, offset)?;
        offset = next_off;
        let qtype = read_u16_at(packet, offset)?;
        offset = offset.checked_add(2)?;
        let _qclass = read_u16_at(packet, offset)?;
        offset = offset.checked_add(2)?;
        if idx == 0 {
            query_name = name;
            query_type = qtype;
        }
    }

    let mut answer_ips = Vec::new();
    let mut cnames = Vec::new();
    let mut min_ttl_secs: Option<u32> = None;

    if is_response {
        let an_limit = usize::from(ancount).min(DNS_MAX_ANSWER_RECORDS);
        for _ in 0..an_limit {
            let (_owner, after_name) = read_dns_name(packet, offset)?;
            offset = after_name;
            let rtype = read_u16_at(packet, offset)?;
            let _rclass = read_u16_at(packet, offset.checked_add(2)?)?;
            let ttl = read_u32_at(packet, offset.checked_add(4)?)?;
            let rdlength = usize::from(read_u16_at(packet, offset.checked_add(8)?)?);
            let rdata_start = offset.checked_add(10)?;
            let rdata_end = rdata_start.checked_add(rdlength)?;
            let rdata = packet.get(rdata_start..rdata_end)?;
            offset = rdata_end;

            min_ttl_secs = Some(min_ttl_secs.map_or(ttl, |cur| cur.min(ttl)));
            match rtype {
                DNS_TYPE_A if rdlength == 4 => {
                    let arr: [u8; 4] = rdata.try_into().ok()?;
                    answer_ips.push(IpAddr::V4(Ipv4Addr::from(arr)));
                }
                DNS_TYPE_AAAA if rdlength == 16 => {
                    let arr: [u8; 16] = rdata.try_into().ok()?;
                    answer_ips.push(IpAddr::V6(Ipv6Addr::from(arr)));
                }
                DNS_TYPE_CNAME => {
                    if let Some((cname, _)) = read_dns_name(packet, rdata_start)
                        && !cname.is_empty()
                    {
                        cnames.push(cname);
                    }
                }
                _ => {}
            }
        }
    }

    Some(DnsParsedPacket {
        tx_id,
        is_response,
        rcode,
        query_name,
        query_type,
        answer_ips,
        cnames,
        min_ttl_secs: min_ttl_secs.unwrap_or(0),
    })
}

fn read_dns_name(packet: &[u8], start_offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut cursor = start_offset;
    let mut next_after_name: Option<usize> = None;
    let mut jumps: usize = 0;
    let mut total_len: usize = 0;
    let mut visited_ptrs = [usize::MAX; DNS_MAX_POINTER_JUMPS];

    for _ in 0..DNS_MAX_LABELS {
        let len_byte = *packet.get(cursor)?;
        let tag = len_byte & 0xC0;
        if tag == 0xC0 {
            let second = *packet.get(cursor.checked_add(1)?)?;
            let target = usize::from(u16::from(len_byte & 0x3F) << 8 | u16::from(second));
            if target >= packet.len() || target >= cursor {
                return None;
            }
            if visited_ptrs.contains(&target) {
                return None;
            }
            if jumps >= DNS_MAX_POINTER_JUMPS {
                return None;
            }
            if let Some(slot) = visited_ptrs.get_mut(jumps) {
                *slot = target;
            }
            jumps = jumps.saturating_add(1);
            if next_after_name.is_none() {
                next_after_name = cursor.checked_add(2);
            }
            cursor = target;
            continue;
        }
        if tag != 0 {
            return None;
        }
        let label_len = usize::from(len_byte);
        cursor = cursor.checked_add(1)?;
        if label_len == 0 {
            let resume = next_after_name.unwrap_or(cursor);
            let joined = labels.join(".").to_ascii_lowercase();
            return Some((joined, resume));
        }
        total_len = total_len.saturating_add(label_len).saturating_add(1);
        if total_len > MAX_HOSTNAME_LEN {
            return None;
        }
        let end = cursor.checked_add(label_len)?;
        let raw_label = packet.get(cursor..end)?;
        if raw_label.iter().any(|&b| !is_valid_dns_label_byte(b)) {
            return None;
        }
        let label = std::str::from_utf8(raw_label).ok()?.to_ascii_lowercase();
        labels.push(label);
        cursor = end;
    }
    None
}

const fn is_valid_dns_label_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

fn read_u16_at(packet: &[u8], offset: usize) -> Option<u16> {
    let b0 = *packet.get(offset)?;
    let b1 = *packet.get(offset.checked_add(1)?)?;
    Some(u16::from_be_bytes([b0, b1]))
}

fn read_u32_at(packet: &[u8], offset: usize) -> Option<u32> {
    let b0 = *packet.get(offset)?;
    let b1 = *packet.get(offset.checked_add(1)?)?;
    let b2 = *packet.get(offset.checked_add(2)?)?;
    let b3 = *packet.get(offset.checked_add(3)?)?;
    Some(u32::from_be_bytes([b0, b1, b2, b3]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut exts = Vec::new();
        if let Some(host) = sni {
            let name_bytes = host.as_bytes();
            let list_len = u16::try_from(name_bytes.len().saturating_add(3)).unwrap();
            let ext_len = u16::try_from(name_bytes.len().saturating_add(5)).unwrap();
            exts.extend_from_slice(&TLS_EXT_SERVER_NAME.to_be_bytes());
            exts.extend_from_slice(&ext_len.to_be_bytes());
            exts.extend_from_slice(&list_len.to_be_bytes());
            exts.push(TLS_SNI_HOST_NAME);
            exts.extend_from_slice(&u16::try_from(name_bytes.len()).unwrap().to_be_bytes());
            exts.extend_from_slice(name_bytes);
        }

        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]);
        ch_body.extend_from_slice(&[0xAA; 32]);
        ch_body.push(0);
        ch_body.extend_from_slice(&2u16.to_be_bytes());
        ch_body.extend_from_slice(&[0x13, 0x01]);
        ch_body.push(1);
        ch_body.push(0);
        if !exts.is_empty() {
            ch_body.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
            ch_body.extend_from_slice(&exts);
        }

        let mut hs = Vec::new();
        hs.push(TLS_HANDSHAKE_CLIENT_HELLO);
        let ch_len = u32::try_from(ch_body.len()).unwrap();
        hs.push(((ch_len >> 16) & 0xFF) as u8);
        hs.push(((ch_len >> 8) & 0xFF) as u8);
        hs.push((ch_len & 0xFF) as u8);
        hs.extend_from_slice(&ch_body);

        let mut rec = Vec::new();
        rec.push(TLS_CONTENT_HANDSHAKE);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&u16::try_from(hs.len()).unwrap().to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extracts_tls_sni_and_handles_truncated_or_non_tls() {
        let hello = build_test_client_hello(Some("API.OpenAI.COM."));
        assert_eq!(
            peek_tls_client_hello_sni(&hello),
            TlsSniPeekResult::Found {
                sni: "api.openai.com".into()
            }
        );
        assert_eq!(
            peek_tls_client_hello_sni(&hello[..4]),
            TlsSniPeekResult::NeedMoreBytes
        );
        assert_eq!(
            peek_tls_client_hello_sni(&hello[..hello.len() - 1]),
            TlsSniPeekResult::NeedMoreBytes
        );
        let no_sni = build_test_client_hello(None);
        assert_eq!(
            peek_tls_client_hello_sni(&no_sni),
            TlsSniPeekResult::NoSniExtension
        );
        assert_eq!(
            peek_tls_client_hello_sni(b"GET / HTTP/1.1\r\n\r\n"),
            TlsSniPeekResult::NotTls
        );
    }

    #[test]
    fn parses_dns_response_with_compression_and_updates_domain_cache() {
        let pkt: Vec<u8> = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, b'a',
            b'p', b'i', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x3C, 0x00, 0x04, 198, 51, 100, 7, 0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x78, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let parsed = parse_dns_packet(&pkt).expect("valid dns response");
        assert_eq!(parsed.tx_id, 0x1234);
        assert!(parsed.is_response);
        assert_eq!(parsed.query_name, "api.example.com");
        assert_eq!(parsed.min_ttl_secs, 60);
        assert_eq!(
            parsed.answer_ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                IpAddr::V6("2001:db8::1".parse().unwrap()),
            ]
        );

        let mut cache = DnsDomainIpCache::new(16);
        cache.record_response(&parsed, 1_000);
        assert_eq!(
            cache.lookup_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 1_010),
            Some("api.example.com")
        );
        assert_eq!(
            cache.lookup_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 1_061),
            None
        );
    }

    #[test]
    fn rejects_dns_pointer_loop_and_truncated_packets() {
        let looped: Vec<u8> = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x0C,
            0x00, 0x01, 0x00, 0x01,
        ];
        assert!(parse_dns_packet(&looped).is_none());
        assert!(parse_dns_packet(&[0u8; 5]).is_none());
    }

    #[test]
    fn consumes_more_than_sixteen_questions_and_rejects_excessive_qdcount() {
        let mut pkt: Vec<u8> = vec![0x42, 0x01, 0x81, 0x80, 0x00, 20, 0x00, 0x01, 0, 0, 0, 0];
        for i in 0..20u8 {
            let label = format!("q{:02}", i);
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
            pkt.extend_from_slice(&[0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01]);
        }
        pkt.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 198, 51, 100,
            42,
        ]);
        let parsed = parse_dns_packet(&pkt).expect("parses all 20 questions cleanly");
        assert_eq!(parsed.query_name, "q00.com");
        assert_eq!(
            parsed.answer_ips,
            vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42))]
        );

        let too_many_qd = vec![0x42, 0x02, 0x01, 0x00, 0x00, 65, 0x00, 0x00, 0, 0, 0, 0];
        assert!(parse_dns_packet(&too_many_qd).is_none());
    }

    #[test]
    fn rejects_crlf_slash_and_colon_in_dns_labels() {
        for bad_label in [&b"evil\r\nX-Injected"[..], b"foo/bar", b"host:8080", b"a b"] {
            let mut pkt = vec![0x42, 0x03, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0, 0, 0, 0];
            pkt.push(bad_label.len() as u8);
            pkt.extend_from_slice(bad_label);
            pkt.extend_from_slice(&[0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01]);
            assert!(
                parse_dns_packet(&pkt).is_none(),
                "expected DNS rejection for crafted label {bad_label:?}"
            );
        }
    }
}
