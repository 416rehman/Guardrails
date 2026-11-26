# Guardrails ADR Cryptography & Export Controls Statement

Status: Public technical disclosure (`docs/design/36-legal-brand-and-commercial.md` section 10,
pending counsel confirmation under `counsel-register.yaml` items `L-16` and `L-18`).

## Publicly Available Open-Source Software

Guardrails ADR (`grdr`) source code, policy packs, and reproducible release binaries are
published publicly under open-source licences (`Apache-2.0`; `GPL-2.0-only OR BSD-2-Clause` for
`bpf/`):
- Repository: <https://github.com/416rehman/Guardrails>

## Standard Cryptographic Algorithms Used

Guardrails ADR composes strictly standard, publicly documented cryptographic algorithms via
maintained libraries (`rustls` / `chacha20poly1305` / `ed25519-dalek` / `sha2`), with zero
non-standard or proprietary ciphers:

| Primitive | Algorithm / Standard | Purpose in Guardrails ADR | Source Crate |
|---|---|---|---|
| Signatures | Ed25519 (RFC 8032) | Wire envelopes, TUF/DSSE metadata, audit seals, grant signatures | `crates/grdr-crypto` (`ed25519-dalek`) |
| Authenticated encryption | ChaCha20-Poly1305 (RFC 8439) | Envelope/keystore symmetric sealing (zero non-standard primitives) | `crates/grdr-crypto` (`chacha20poly1305`) |
| Digests & MACs | SHA-256 & HMAC-SHA256 (FIPS 180-4 / RFC 2104) | Content addressing, receipt hashing, HKDF/domain-separated tokens | `crates/grdr-crypto` (`sha2`) |
| Transport security | TLS 1.3 (including standard hybrid key exchange when configured) | Client/agent/server TLS sessions | `rustls` / `reqwest` |
| OS CSPRNG | Platform CSPRNG (`getrandom`) | Nonce and ephemeral key generation | `crates/grdr-crypto` (`getrandom`) |

## Regulatory & Notice Scope

- Publicly available open-source source code and standard cryptography binaries are structured for
  public distribution without proprietary export restrictions, subject to counsel verification of
  BIS/NSA public notification rules and EU dual-use public-domain exemption (`L-16`).
- Any hosted commercial, OEM, MSP, or paid support agreement remains subject to sanctions screening
  against OFAC SDN, EU consolidated, and UK OFSI lists (`L-17`).
- Adversarial efficacy evaluation fixtures are benign EICAR-style stand-in payloads (`L-18`).
