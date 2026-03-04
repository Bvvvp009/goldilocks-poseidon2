# goldilocks-poseidon2

> **⚠️ Security Warning**
> Neither crate in this repository has been audited. Do not use in production without a
> professional cryptographic security review. Use at your own risk.

Poseidon2 hash and ECgFp5 Schnorr signatures over the Goldilocks field —
ZK-proof-ready cryptographic primitives in Rust.

---

## Crates

| Crate | Version | Description |
|-------|---------|-------------|
| [`poseidon-hash`](poseidon-hash/) | 0.1.4 | Goldilocks field arithmetic, Poseidon2 hash, Fp5 extension, Merkle trees |
| [`goldilocks-crypto`](crypto/) | 0.1.1 | ECgFp5 elliptic curve, Schnorr signatures, batch verification |

---

## Algorithm Parameters

| Parameter | Value | Reference |
|-----------|-------|-----------|
| Field modulus | `p = 2⁶⁴ − 2³² + 1 = 0xffffffff00000001` | [Goldilocks prime](https://cp4space.hatsya.com/2021/09/01/an-introduction-to-the-goldilocks-prime/) |
| Hash function | Poseidon2, width 12, 8 full + 22 partial rounds, S-box `x⁷` | [eprint.iacr.org/2023/323](https://eprint.iacr.org/2023/323) |
| Curve | ECgFp5 — `y² = x³ + 2x + 263` over GF(p⁵) | [github.com/pornin/ecgfp5](https://github.com/pornin/ecgfp5) |
| Signature | Schnorr with Poseidon2 hash-to-scalar | — |
| Key / sig sizes | 40-byte keys, 80-byte signatures | — |

---

## Workspace layout

```
goldilocks-poseidon2/
├── poseidon-hash/   # crate: poseidon-hash 0.1.4
└── crypto/          # crate: goldilocks-crypto 0.1.1
```

---

## Quick start

```toml
[dependencies]
poseidon-hash     = "0.1"
goldilocks-crypto = "0.1"
```

```rust
use poseidon_hash::{Goldilocks, hash_no_pad};
use goldilocks_crypto::KeyPair;

// Hash
let elements = vec![
    Goldilocks::from_canonical_u64(1),
    Goldilocks::from_canonical_u64(2),
];
let hash = hash_no_pad(&elements);   // [Goldilocks; 4]

// Sign / verify
let kp  = KeyPair::generate();
let msg = [0u8; 40];
let sig = kp.sign(&msg).unwrap();
assert!(kp.verify(&sig, &msg).unwrap());
```

---

## Constant provenance

| Constant | Value | Source |
|----------|-------|--------|
| `Goldilocks::MODULUS` | `0xffffffff00000001` | [Goldilocks prime definition](https://cp4space.hatsya.com/2021/09/01/an-introduction-to-the-goldilocks-prime/) |
| `GENERATOR_ECG_FP5_POINT` | see `crypto/src/schnorr.rs` | [ECgFp5 spec](https://github.com/pornin/ecgfp5) |
| Curve coefficient `B` | `(0, 263, 0, 0, 0)` in Fp5 | [ECgFp5 paper §3](https://github.com/pornin/ecgfp5) |
| Scalar field order `N` | `≈ 2²⁵⁴` (4×64-bit limbs) | [ECgFp5 spec](https://github.com/pornin/ecgfp5) |
| Poseidon2 MDS matrix | Circulant, see `poseidon-hash/src/lib.rs` | [Poseidon2 paper §5](https://eprint.iacr.org/2023/323) |

---

## License

Licensed under either of [Apache-2.0](poseidon-hash/LICENSE-APACHE) or
[MIT](poseidon-hash/LICENSE-MIT) at your option.
