# goldilocks-crypto

> **⚠️ Security Warning**
> This crate has **not been audited**. Do not use in production without a professional
> security review. Use at your own risk.

Rust implementation of **ECgFp5 Schnorr signatures** over the **Goldilocks field** —
designed for ZK-friendly on-chain signature verification.

[![Crates.io](https://img.shields.io/crates/v/goldilocks-crypto)](https://crates.io/crates/goldilocks-crypto)
[![docs.rs](https://img.shields.io/docsrs/goldilocks-crypto)](https://docs.rs/goldilocks-crypto)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](LICENSE-MIT)

---

## Algorithm Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Base field | Goldilocks, `p = 2⁶⁴ − 2³² + 1` | [Goldilocks prime](https://cp4space.hatsya.com/2021/09/01/an-introduction-to-the-goldilocks-prime/) |
| Curve | ECgFp5 — `y² = x³ + 2x + 263` over GF(p⁵) | [github.com/pornin/ecgfp5](https://github.com/pornin/ecgfp5) |
| Scalar field order | `≈ 2²⁵⁴` (256-bit, 4×64-bit limbs) | ECgFp5 spec |
| Hash-to-scalar | Poseidon2 (width 12, 8 full + 22 partial rounds) | [eprint.iacr.org/2023/323](https://eprint.iacr.org/2023/323) |
| Signature scheme | Schnorr | — |
| Key size | 40 bytes (private), 40 bytes (public) | — |
| Signature size | 80 bytes | — |

---

## API

| Item | Kind | Description |
|------|------|-------------|
| `ScalarField` | struct | 256-bit scalar (private key / nonce) |
| `Point` | struct | ECgFp5 curve point (projective coords) |
| `AffinePoint` | struct | ECgFp5 curve point (affine coords) |
| `Signature` | struct | 80-byte Schnorr signature |
| `KeyPair` | struct | Ergonomic keypair with sign/verify methods |
| `sign(sk, msg)` | fn | Sign a 40-byte message with a private key |
| `verify_signature(sig, msg, pk)` | fn | Verify a signature against a public key |
| `batch_verify(sigs, msgs, pks)` | fn | Verify multiple signatures sequentially |
| `validate_public_key(pk)` | fn | Check that bytes represent a valid curve point |

---

## Usage

Add to `Cargo.toml`:

```toml
[dependencies]
goldilocks-crypto = "0.1"
```

### Key generation

```rust
use goldilocks_crypto::{ScalarField, Point};

// Random private key (cryptographically secure)
let private_key = ScalarField::sample_crypto();
let sk_bytes    = private_key.to_bytes_le();          // [u8; 40]

// Derive public key
let public_key  = Point::generator().mul(&private_key);
let pk_bytes    = public_key.encode().to_bytes_le();  // [u8; 40]
```

### Sign and verify

```rust
use goldilocks_crypto::{sign, verify_signature};

// Message must consist of canonical Goldilocks field elements
let message   = [0u8; 40];
let signature = sign(&sk_bytes, &message).unwrap();       // Vec<u8> (80 bytes)
let is_valid  = verify_signature(&signature, &message, &pk_bytes).unwrap();
assert!(is_valid);
```

### Ergonomic `KeyPair` API

```rust
use goldilocks_crypto::KeyPair;

let kp       = KeyPair::generate();
let msg      = [0u8; 40];
let sig      = kp.sign(&msg).unwrap();
let is_valid = kp.verify(&sig, &msg).unwrap();
assert!(is_valid);
```

### Batch verification

```rust
use goldilocks_crypto::batch_verify;

// signatures: Vec<Vec<u8>>, messages: Vec<[u8;40]>, public_keys: Vec<[u8;40]>
let all_valid = batch_verify(&signatures, &messages, &public_keys).unwrap();
```

---

## Dependencies

- [`poseidon-hash`](https://crates.io/crates/poseidon-hash) — Goldilocks field, Poseidon2
  hash, Fp5 extension field
- [`zeroize`](https://docs.rs/zeroize) — private key material is zeroed on drop
- [`subtle`](https://docs.rs/subtle) — constant-time comparisons

---

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
