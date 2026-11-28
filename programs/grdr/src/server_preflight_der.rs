// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

// BasicConstraints OID 2.5.29.19 encoded as DER TLV: 06 03 55 1D 13.
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x13];

#[derive(Debug)]
pub(super) struct ParsedCertSummary<'a> {
    pub tbs_full: &'a [u8],
    pub issuer_full: &'a [u8],
    pub subject_full: &'a [u8],
    pub sig_bytes: &'a [u8],
    pub not_before_s: i64,
    pub not_after_s: i64,
    pub is_ca: bool,
}

type DerTlv<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

pub(super) fn parse_x509_der_strict(der: &[u8]) -> Result<ParsedCertSummary<'_>, &'static str> {
    let (cert_tag, cert_val, _, cert_trail) = read_der_tlv(der)?;
    if cert_tag != 0x30 || !cert_trail.is_empty() {
        return Err("Outer certificate is not a single complete SEQUENCE.");
    }
    let (tbs_tag, mut tbs_cursor, tbs_full, after_tbs) = read_der_tlv(cert_val)?;
    if tbs_tag != 0x30 {
        return Err("TBSCertificate is not a SEQUENCE.");
    }
    let (sig_alg_tag, _, _, after_sig_alg) = read_der_tlv(after_tbs)?;
    if sig_alg_tag != 0x30 {
        return Err("Certificate signatureAlgorithm is not a SEQUENCE.");
    }
    let (sig_tag, sig_val, _, sig_trail) = read_der_tlv(after_sig_alg)?;
    if sig_tag != 0x03 || sig_val.first().copied() != Some(0x00) || !sig_trail.is_empty() {
        return Err("Certificate signatureValue is not a valid BIT STRING.");
    }
    let sig_bytes = sig_val.get(1..).unwrap_or(&[]);

    let (first_tag, first_val, _, after_first) = read_der_tlv(tbs_cursor)?;
    if first_tag == 0xA0 {
        let (ver_tag, _, _, ver_trail) = read_der_tlv(first_val)?;
        if ver_tag != 0x02 || !ver_trail.is_empty() {
            return Err("Invalid TBSCertificate version field.");
        }
        tbs_cursor = after_first;
    }
    let (serial_tag, _, _, after_serial) = read_der_tlv(tbs_cursor)?;
    if serial_tag != 0x02 {
        return Err("Invalid TBSCertificate serialNumber tag.");
    }
    let (tbs_sig_tag, _, _, after_tbs_sig) = read_der_tlv(after_serial)?;
    if tbs_sig_tag != 0x30 {
        return Err("Invalid TBSCertificate signature tag.");
    }
    let (issuer_tag, _, issuer_full, after_issuer) = read_der_tlv(after_tbs_sig)?;
    if issuer_tag != 0x30 {
        return Err("Invalid TBSCertificate issuer tag.");
    }
    let (val_tag, validity_bytes, _, after_validity) = read_der_tlv(after_issuer)?;
    if val_tag != 0x30 {
        return Err("Invalid TBSCertificate validity tag.");
    }
    let (subj_tag, _, subject_full, after_subj) = read_der_tlv(after_validity)?;
    if subj_tag != 0x30 {
        return Err("Invalid TBSCertificate subject tag.");
    }
    let (spki_tag, _, _, after_spki) = read_der_tlv(after_subj)?;
    if spki_tag != 0x30 {
        return Err("Invalid TBSCertificate SPKI tag.");
    }

    let (nb_tag, nb_bytes, _, after_nb) = read_der_tlv(validity_bytes)?;
    let (na_tag, na_bytes, _, val_trail) = read_der_tlv(after_nb)?;
    if !val_trail.is_empty() {
        return Err("Validity SEQUENCE contains trailing data.");
    }
    let not_before_s = parse_asn1_time_strict(nb_tag, nb_bytes)?;
    let not_after_s = parse_asn1_time_strict(na_tag, na_bytes)?;
    if not_before_s > not_after_s {
        return Err("Certificate notBefore exceeds notAfter.");
    }
    let is_ca = detect_basic_constraints_ca(after_spki);
    Ok(ParsedCertSummary {
        tbs_full,
        issuer_full,
        subject_full,
        sig_bytes,
        not_before_s,
        not_after_s,
        is_ca,
    })
}

fn detect_basic_constraints_ca(mut rest: &[u8]) -> bool {
    while !rest.is_empty() {
        let Ok((tag, val, _, next)) = read_der_tlv(rest) else {
            break;
        };
        if tag == 0xA3
            && let Ok((exts_tag, mut exts_cursor, _, _)) = read_der_tlv(val)
            && exts_tag == 0x30
        {
            while !exts_cursor.is_empty() {
                let Ok((ext_tag, ext_val, _, ext_next)) = read_der_tlv(exts_cursor) else {
                    break;
                };
                if ext_tag == 0x30 && ext_is_ca_true(ext_val) {
                    return true;
                }
                exts_cursor = ext_next;
            }
        }
        rest = next;
    }
    false
}

fn ext_is_ca_true(ext_val: &[u8]) -> bool {
    let Ok((_, _, oid_full, after_oid)) = read_der_tlv(ext_val) else {
        return false;
    };
    if oid_full != OID_BASIC_CONSTRAINTS {
        return false;
    }
    let Ok((next_tag, next_val, _, after_crit)) = read_der_tlv(after_oid) else {
        return false;
    };
    let oct_val = if next_tag == 0x01 {
        let Ok((oct_tag, v, _, _)) = read_der_tlv(after_crit) else {
            return false;
        };
        if oct_tag != 0x04 {
            return false;
        }
        v
    } else if next_tag == 0x04 {
        next_val
    } else {
        return false;
    };
    let Ok((bc_tag, bc_val, _, _)) = read_der_tlv(oct_val) else {
        return false;
    };
    if bc_tag != 0x30 || bc_val.is_empty() {
        return false;
    }
    let Ok((bool_tag, bool_val, _, _)) = read_der_tlv(bc_val) else {
        return false;
    };
    bool_tag == 0x01 && bool_val == [0xFF]
}

fn read_der_tlv(input: &[u8]) -> Result<DerTlv<'_>, &'static str> {
    let tag = *input.first().ok_or("Truncated DER tag.")?;
    let len_byte = *input.get(1).ok_or("Truncated DER length byte.")?;
    let (len, header_len) = if (len_byte & 0x80) == 0 {
        (usize::from(len_byte), 2usize)
    } else {
        let num_octets = usize::from(len_byte & 0x7F);
        if num_octets == 0 || num_octets > 4 {
            return Err("Indefinite or oversized DER length.");
        }
        let header_end = 2usize
            .checked_add(num_octets)
            .ok_or("DER length overflow.")?;
        let len_slice = input
            .get(2..header_end)
            .ok_or("Truncated DER length octets.")?;
        if len_slice.first().copied() == Some(0) {
            return Err("Non-minimal DER length encoding (leading zero).");
        }
        let mut acc = 0usize;
        for &b in len_slice {
            acc = acc
                .checked_shl(8)
                .and_then(|v| v.checked_add(usize::from(b)))
                .ok_or("DER length overflow.")?;
        }
        if acc < 128 {
            return Err("Non-minimal long-form DER length (<128).");
        }
        (acc, header_end)
    };
    let end = header_len
        .checked_add(len)
        .ok_or("DER length out of bounds.")?;
    let val = input.get(header_len..end).ok_or("Truncated DER value.")?;
    let full = input.get(..end).ok_or("Truncated DER slice.")?;
    let rest = input.get(end..).unwrap_or(&[]);
    Ok((tag, val, full, rest))
}

fn parse_asn1_time_strict(tag: u8, bytes: &[u8]) -> Result<i64, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "Non-UTF8 ASN.1 time.")?;
    let trimmed = text
        .strip_suffix('Z')
        .ok_or("ASN.1 time missing trailing Z.")?;
    if !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Err("ASN.1 time must contain ASCII digits only.");
    }
    let (year, rest) = match tag {
        0x17 if trimmed.len() == 12 => {
            let yy = trimmed
                .get(..2)
                .and_then(|s| s.parse::<i16>().ok())
                .ok_or("Invalid UTCTime year.")?;
            let full_year = if yy >= 50 {
                1900i16.saturating_add(yy)
            } else {
                2000i16.saturating_add(yy)
            };
            (full_year, trimmed.get(2..).unwrap_or(""))
        }
        0x18 if trimmed.len() == 14 => {
            let yyyy = trimmed
                .get(..4)
                .and_then(|s| s.parse::<i16>().ok())
                .ok_or("Invalid GeneralizedTime year.")?;
            if yyyy < 2050 {
                return Err("RFC 5280 requires UTCTime for years before 2050.");
            }
            (yyyy, trimmed.get(4..).unwrap_or(""))
        }
        _ => return Err("Unsupported ASN.1 time tag or length."),
    };
    let parse_two = |start: usize| -> Result<i8, &'static str> {
        let end = start.saturating_add(2);
        rest.get(start..end)
            .and_then(|s| s.parse::<i8>().ok())
            .ok_or("Invalid ASN.1 time component.")
    };
    let dt = jiff::civil::DateTime::new(
        year,
        parse_two(0)?,
        parse_two(2)?,
        parse_two(4)?,
        parse_two(6)?,
        parse_two(8)?,
        0,
    )
    .map_err(|_| "Invalid calendar date/time in ASN.1 time.")?;
    let ts = jiff::tz::TimeZone::UTC
        .to_timestamp(dt)
        .map_err(|_| "Timestamp conversion failed.")?;
    Ok(ts.as_second())
}
