// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Dynamic brand resolution from `contracts/interface/brand/brand.toml` (`docs/design/26`).

use std::path::Path;

use serde::{Deserialize, Serialize};

use grdr_model::CodedError;
use grdr_ports::LocalFsPort;
use grdr_schema::brand::{load_embedded_brand_display, parse_brand_display_toml};

const MAX_BRAND_TOML_BYTES: u64 = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerBrand {
    pub product_name: String,
    pub short_name: String,
    pub namespace: String,
}

impl Default for BrokerBrand {
    fn default() -> Self {
        Self::workspace_default()
    }
}

impl BrokerBrand {
    #[must_use]
    pub fn workspace_default() -> Self {
        match load_embedded_brand_display() {
            Ok(b) => Self {
                product_name: b.product_name,
                short_name: b.short_name,
                namespace: b.namespace,
            },
            Err(_) => Self {
                product_name: grdr_strings::BRAND_NAME.to_owned(),
                short_name: grdr_strings::BRAND_SHORT_NAME.to_owned(),
                namespace: "grdr".to_owned(),
            },
        }
    }

    #[must_use]
    pub fn with_product_name(product_name: impl Into<String>) -> Self {
        let name = product_name.into();
        Self {
            product_name: name.clone(),
            short_name: name,
            namespace: "grdr".to_owned(),
        }
    }

    pub fn from_brand_toml_file(path: &Path, fs: &dyn LocalFsPort) -> Result<Self, CodedError> {
        let raw = fs
            .read_bounded_regular_string(path, MAX_BRAND_TOML_BYTES)
            .map_err(|e| {
                CodedError::new(
                    "GRDR-BRK-0005",
                    format!("unsafe or oversized brand manifest {}: {e}", path.display()),
                    "Use a regular non-symlink brand.toml manifest under 64 KiB.",
                )
            })?;
        Self::from_brand_toml_str(&raw)
    }

    pub fn from_brand_toml_str(raw: &str) -> Result<Self, CodedError> {
        let parsed = parse_brand_display_toml(raw).map_err(|err| {
            CodedError::new(
                "GRDR-BRK-0005",
                err,
                "Ensure brand.toml defines valid non-empty [identity]/[display] strings.",
            )
        })?;
        Ok(Self {
            product_name: parsed.product_name,
            short_name: parsed.short_name,
            namespace: parsed.namespace,
        })
    }
}
