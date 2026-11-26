// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserializer, Serializer};
use std::fmt;

pub trait ProtoEnumCodec: Sized {
    fn to_proto_str(value: i32) -> Option<&'static str>;
    fn from_proto_str(raw: &str) -> Option<i32>;
}

pub fn serialize_enum<E: ProtoEnumCodec, S: Serializer>(
    value: &i32,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if let Some(name) = E::to_proto_str(*value) {
        serializer.serialize_str(name)
    } else {
        serializer.serialize_i32(*value)
    }
}

pub fn deserialize_enum<'de, E: ProtoEnumCodec, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<i32, D::Error> {
    struct EnumVisitor<E>(std::marker::PhantomData<E>);

    impl<E: ProtoEnumCodec> Visitor<'_> for EnumVisitor<E> {
        type Value = i32;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a protobuf enum name string or integer tag")
        }

        fn visit_i64<Err: de::Error>(self, value: i64) -> Result<i32, Err> {
            i32::try_from(value).map_err(|_| Err::custom("enum integer out of i32 range"))
        }

        fn visit_u64<Err: de::Error>(self, value: u64) -> Result<i32, Err> {
            i32::try_from(value).map_err(|_| Err::custom("enum integer out of i32 range"))
        }

        fn visit_str<Err: de::Error>(self, value: &str) -> Result<i32, Err> {
            E::from_proto_str(value)
                .ok_or_else(|| Err::custom(format!("unknown enum value '{value}'")))
        }
    }

    deserializer.deserialize_any(EnumVisitor::<E>(std::marker::PhantomData))
}

pub fn serialize_opt_enum<E: ProtoEnumCodec, S: Serializer>(
    value: &Option<i32>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(v) => serialize_enum::<E, S>(v, serializer),
        None => serializer.serialize_none(),
    }
}

pub fn deserialize_opt_enum<'de, E: ProtoEnumCodec, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<i32>, D::Error> {
    struct OptVisitor<E>(std::marker::PhantomData<E>);

    impl<'de, E: ProtoEnumCodec> Visitor<'de> for OptVisitor<E> {
        type Value = Option<i32>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an optional protobuf enum value")
        }

        fn visit_none<Err: de::Error>(self) -> Result<Option<i32>, Err> {
            Ok(None)
        }

        fn visit_unit<Err: de::Error>(self) -> Result<Option<i32>, Err> {
            Ok(None)
        }

        fn visit_some<D2: Deserializer<'de>>(
            self,
            deserializer: D2,
        ) -> Result<Option<i32>, D2::Error> {
            deserialize_enum::<E, D2>(deserializer).map(Some)
        }
    }

    deserializer.deserialize_option(OptVisitor::<E>(std::marker::PhantomData))
}

pub fn serialize_vec_enum<E: ProtoEnumCodec, S: Serializer>(
    values: &[i32],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut seq = serializer.serialize_seq(Some(values.len()))?;
    for v in values {
        if let Some(name) = E::to_proto_str(*v) {
            seq.serialize_element(name)?;
        } else {
            seq.serialize_element(v)?;
        }
    }
    seq.end()
}

pub fn deserialize_vec_enum<'de, E: ProtoEnumCodec, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<i32>, D::Error> {
    struct VecVisitor<E>(std::marker::PhantomData<E>);

    impl<'de, E: ProtoEnumCodec> Visitor<'de> for VecVisitor<E> {
        type Value = Vec<i32>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a sequence of protobuf enum values")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<i32>, A::Error> {
            let mut out = Vec::new();
            while let Some(elem) = seq.next_element::<EnumSeedOrValue<E>>()? {
                out.push(elem.0);
            }
            Ok(out)
        }
    }

    struct EnumSeedOrValue<E>(i32, std::marker::PhantomData<E>);

    impl<'de, E: ProtoEnumCodec> serde::Deserialize<'de> for EnumSeedOrValue<E> {
        fn deserialize<D2: Deserializer<'de>>(deserializer: D2) -> Result<Self, D2::Error> {
            deserialize_enum::<E, D2>(deserializer).map(|v| Self(v, std::marker::PhantomData))
        }
    }

    deserializer.deserialize_seq(VecVisitor::<E>(std::marker::PhantomData))
}

#[macro_export]
macro_rules! proto_enum_codec {
    (
        $ty:ty,
        $mod_name:ident,
        [
            $( $variant:path => $proto_name:literal $( | $alias:literal )* ),* $(,)?
        ]
    ) => {
        impl $crate::serde_proto::ProtoEnumCodec for $ty {
            fn to_proto_str(value: i32) -> Option<&'static str> {
                match <$ty>::try_from(value).ok()? {
                    $( $variant => Some($proto_name), )*
                }
            }

            fn from_proto_str(raw: &str) -> Option<i32> {
                let trimmed = raw.trim();
                let upper = trimmed.to_ascii_uppercase().replace(['-', '.'], "_");
                let lower = trimmed.to_ascii_lowercase();
                $(
                    if trimmed == $proto_name || upper == $proto_name {
                        return Some($variant as i32);
                    }
                    $(
                        if lower == $alias {
                            return Some($variant as i32);
                        }
                    )*
                )*
                None
            }
        }

        pub mod $mod_name {
            use super::*;
            use serde::{Deserializer, Serializer};

            pub fn serialize<S: Serializer>(value: &i32, s: S) -> Result<S::Ok, S::Error> {
                $crate::serde_proto::serialize_enum::<$ty, S>(value, s)
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<i32, D::Error> {
                $crate::serde_proto::deserialize_enum::<$ty, D>(d)
            }

            pub mod opt {
                use super::*;

                pub fn serialize<S: Serializer>(
                    value: &Option<i32>,
                    s: S,
                ) -> Result<S::Ok, S::Error> {
                    $crate::serde_proto::serialize_opt_enum::<$ty, S>(value, s)
                }

                pub fn deserialize<'de, D: Deserializer<'de>>(
                    d: D,
                ) -> Result<Option<i32>, D::Error> {
                    $crate::serde_proto::deserialize_opt_enum::<$ty, D>(d)
                }
            }

            pub mod vec {
                use super::*;

                pub fn serialize<S: Serializer>(values: &[i32], s: S) -> Result<S::Ok, S::Error> {
                    $crate::serde_proto::serialize_vec_enum::<$ty, S>(values, s)
                }

                pub fn deserialize<'de, D: Deserializer<'de>>(
                    d: D,
                ) -> Result<Vec<i32>, D::Error> {
                    $crate::serde_proto::deserialize_vec_enum::<$ty, D>(d)
                }
            }
        }
    };
}

pub mod bytes_b64_serde {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    const B64_ALPHA: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub(crate) fn encode_b64(input: &[u8]) -> String {
        let mut out = String::with_capacity(input.len().div_ceil(3).saturating_mul(4));
        let alpha =
            |idx: usize| -> char { char::from(B64_ALPHA.get(idx).copied().unwrap_or(b'A')) };
        for chunk in input.chunks(3) {
            let b0 = usize::from(chunk.first().copied().unwrap_or(0));
            let b1 = usize::from(chunk.get(1).copied().unwrap_or(0));
            let b2 = usize::from(chunk.get(2).copied().unwrap_or(0));
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(alpha((triple >> 18) & 0x3f));
            out.push(alpha((triple >> 12) & 0x3f));
            if chunk.len() > 1 {
                out.push(alpha((triple >> 6) & 0x3f));
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(alpha(triple & 0x3f));
            } else {
                out.push('=');
            }
        }
        out
    }

    fn decode_val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b.saturating_sub(b'A')),
            b'a'..=b'z' => Some(b.saturating_sub(b'a').saturating_add(26)),
            b'0'..=b'9' => Some(b.saturating_sub(b'0').saturating_add(52)),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }

    pub(crate) fn decode_b64(raw: &str) -> Result<Vec<u8>, String> {
        let s = raw.trim_end_matches('=');
        let pad_len = raw.len().saturating_sub(s.len());
        if pad_len > 2 || s.contains('=') || s.len() % 4 == 1 {
            return Err("invalid base64 length or padding".into());
        }
        if pad_len > 0 && !raw.len().is_multiple_of(4) {
            return Err("invalid padded base64 length".into());
        }
        let mut vals = Vec::with_capacity(s.len());
        for &b in s.as_bytes() {
            vals.push(decode_val(b).ok_or_else(|| "invalid base64 character".to_owned())?);
        }
        let mut out = Vec::with_capacity(vals.len().saturating_mul(3) / 4);
        for chunk in vals.chunks(4) {
            let (Some(&c0), Some(&c1)) = (chunk.first(), chunk.get(1)) else {
                return Err("invalid base64 chunk".into());
            };
            let v0 = u32::from(c0);
            let v1 = u32::from(c1);
            out.push(((v0 << 2) | (v1 >> 4)) as u8);
            if let Some(&c2) = chunk.get(2) {
                let v2 = u32::from(c2);
                out.push((((v1 & 0x0f) << 4) | (v2 >> 2)) as u8);
                if let Some(&c3) = chunk.get(3) {
                    let v3 = u32::from(c3);
                    out.push((((v2 & 0x03) << 6) | v3) as u8);
                } else if (v2 & 0x03) != 0 {
                    return Err("non-canonical trailing base64 bits".into());
                }
            } else if (v1 & 0x0f) != 0 {
                return Err("non-canonical trailing base64 bits".into());
            }
        }
        Ok(out)
    }

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode_b64(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct BytesVisitor;
        impl<'de> Visitor<'de> for BytesVisitor {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("base64 string or byte array")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
                decode_b64(v).map_err(E::custom)
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
                let mut out = Vec::new();
                while let Some(b) = seq.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        d.deserialize_any(BytesVisitor)
    }

    pub mod opt {
        use super::*;

        pub fn serialize<S: Serializer>(value: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
            match value {
                Some(bytes) => super::serialize(bytes, s),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
            struct OptBytesVisitor;
            impl<'de> Visitor<'de> for OptBytesVisitor {
                type Value = Option<Vec<u8>>;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("optional base64 string or byte array")
                }
                fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                    Ok(None)
                }
                fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                    Ok(None)
                }
                fn visit_some<D2: Deserializer<'de>>(
                    self,
                    d2: D2,
                ) -> Result<Self::Value, D2::Error> {
                    super::deserialize(d2).map(Some)
                }
            }
            d.deserialize_option(OptBytesVisitor)
        }
    }

    pub mod vec {
        use super::*;
        use serde::ser::SerializeSeq;

        pub fn serialize<S: Serializer>(values: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(values.len()))?;
            for v in values {
                seq.serialize_element(&encode_b64(v))?;
            }
            seq.end()
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
            struct VecBytesVisitor;
            impl<'de> Visitor<'de> for VecBytesVisitor {
                type Value = Vec<Vec<u8>>;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("sequence of base64 strings or byte arrays")
                }
                fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                    let mut out = Vec::new();
                    while let Some(elem) = seq.next_element::<B64Elem>()? {
                        out.push(elem.0);
                    }
                    Ok(out)
                }
            }
            struct B64Elem(Vec<u8>);
            impl<'de> serde::Deserialize<'de> for B64Elem {
                fn deserialize<D2: Deserializer<'de>>(d2: D2) -> Result<Self, D2::Error> {
                    super::deserialize(d2).map(B64Elem)
                }
            }
            d.deserialize_seq(VecBytesVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::bytes_b64_serde;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct BoxBytes {
        #[serde(with = "bytes_b64_serde")]
        data: Vec<u8>,
    }

    #[test]
    fn bytes_b64_roundtrips_boundaries_and_rejects_malformed_inputs() {
        for raw in [
            vec![],
            vec![0xff],
            vec![0x14, 0xfb],
            vec![0x14, 0xfb, 0x9c],
            vec![1, 2, 3, 4, 5],
        ] {
            let b = BoxBytes { data: raw.clone() };
            let json = serde_json::to_string(&b).unwrap();
            let decoded: BoxBytes = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded.data, raw);
        }

        for bad in [
            "\"==\"",
            "\"AA=\"",
            "\"AAAA==\"",
            "\"AB==\"",
            "\"AAB=\"",
            "\"!!==\"",
        ] {
            let payload = format!("{{\"data\":{bad}}}");
            assert!(
                serde_json::from_str::<BoxBytes>(&payload).is_err(),
                "expected invalid b64 rejection for {bad}"
            );
        }
    }
}
