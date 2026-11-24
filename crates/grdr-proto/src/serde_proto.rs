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
