// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Multi-label public suffix table and registrable domain extraction (`D-10`).

use std::net::IpAddr;

const MULTI_LABEL_PUBLIC_SUFFIXES: &[&str] = &[
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "me.uk",
    "net.uk",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "gov.au",
    "co.jp",
    "ne.jp",
    "or.jp",
    "ac.jp",
    "go.jp",
    "co.kr",
    "or.kr",
    "com.br",
    "net.br",
    "org.br",
    "com.cn",
    "net.cn",
    "org.cn",
    "gov.cn",
    "edu.cn",
    "ac.cn",
    "co.in",
    "net.in",
    "org.in",
    "co.il",
    "org.il",
    "co.id",
    "com.tw",
    "org.tw",
    "com.hk",
    "com.sg",
    "com.mx",
    "co.nz",
    "net.nz",
    "org.nz",
    "co.za",
    "com.tr",
    "com.ar",
    "com.pl",
    "com.ua",
    "blogspot.com",
    "github.io",
    "gitlab.io",
    "herokuapp.com",
    "pages.dev",
    "workers.dev",
    "vercel.app",
    "netlify.app",
    "fly.dev",
    "s3.amazonaws.com",
    "cloudfront.net",
    "azurewebsites.net",
    "appspot.com",
];

/// Extracts the eTLD+1 registrable domain while preserving one left-hand label on `org_suffixes`.
#[must_use]
pub(crate) fn extract_registrable_domain(host: &str, org_suffixes: &[String]) -> String {
    if host.parse::<IpAddr>().is_ok() {
        return host.to_owned();
    }
    for suffix in org_suffixes {
        let norm = suffix.trim().trim_start_matches('.').to_ascii_lowercase();
        if norm.is_empty() {
            continue;
        }
        if host == norm {
            return norm;
        }
        if let Some(prefix) = host.strip_suffix(&format!(".{norm}")) {
            let label = prefix.rsplit('.').next().unwrap_or(prefix);
            if !label.is_empty() {
                return format!("{label}.{norm}");
            }
            return norm;
        }
    }

    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        return host.to_owned();
    }

    for suffix in MULTI_LABEL_PUBLIC_SUFFIXES {
        if host == *suffix {
            return host.to_owned();
        }
        if let Some(prefix) = host.strip_suffix(&format!(".{suffix}")) {
            let label = prefix.rsplit('.').next().unwrap_or(prefix);
            if !label.is_empty() {
                return format!("{label}.{suffix}");
            }
        }
    }

    if let (Some(a), Some(b)) = (labels.get(labels.len().saturating_sub(2)), labels.last()) {
        return format!("{a}.{b}");
    }
    host.to_owned()
}
