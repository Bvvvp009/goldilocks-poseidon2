# poseidon-hash

> **⚠️ Security Warning**
> This crate has **not been audited**. Do not use in production without a professional
> security review. Use at your own risk.

Rust implementation of the **Poseidon2** hash function over the **Goldilocks field** —
a ZK-proof-ready primitive targeting Plonky2 and STARK-based proof systems.

[![Crates.io](https://img.shields.io/crates/v/poseidon-hash)](https://crates.io/crates/poseidon-hash)
[![docs.rs](https://img.shields.io/docsrs/poseidon-hash)](https://docs.rs/poseidon-hash)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](LICENSE-MIT)

---

## Algorithm Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Field modulus (`p`) | `2⁶⁴ − 2³² + 1 = 0xffffffff00000001` | [Goldilocks prime](https://cp4space.hatsya.com/2021/09/01/an-introduction-to-the-goldilocks-prime/) |
| Hash function | Poseidon2 | [eprint.iacr.org/2023/323](https://eprint.iacr.org/2023/323) |
| Sponge width (`t`) | 12 | Plonky2 spec |
| Full rounds (`R_F`) | 8 | Plonky2 spec |
| Partial rounds (`R_P`) | 22 | Plonky2 spec |
| S-box | `x⁷` | Plonky2 spec |
| Output | `HashOut` = `[Goldilocks; 4]` (256-bit) | — |
| Extension field | GF(p⁵) — "Fp5" | [ECgFp5 spec](https://github.com/pornin/ecgfp5) |

---

## Features

- Fast Goldilocks field arithmetic with optimised modular reduction
- Poseidon2 sponge hash compatible with Plonky2 circuit outputs
- `Fp5Element` — quintic extension field for elliptic-curve operations
- Poseidon2-based binary Merkle tree with inclusion proofs
- `no_std`-compatible (default feature set is empty)
- Sensitive field elements zeroed on drop via [`zeroize`](https://docs.rs/zeroize)

---

## API

| Item | Kind | Description |
|------|------|-------------|
| `Goldilocks` | struct | Goldilocks field element (wraps `u64`) |
| `Fp5Element` | struct | Quintic extension field element `[Goldilocks; 5]` |
| `HashOut` | type alias | `[Goldilocks; 4]` — 256-bit hash output |
| `hash_no_pad(input)` | fn | Poseidon2 hash, no padding |
| `hash_to_quintic_extension(input)` | fn | Poseidon2 → `Fp5Element` |
| `MerkleTree::build(leaves)` | fn | Build a complete Poseidon2 Merkle tree |
| `MerkleTree::prove(index)` | fn | Generate sibling-path inclusion proof |
| `MerkleTree::verify(root, proof, leaf)` | fn | Verify an inclusion proof |

---

## Usage

Add to `Cargo.toml`:

```toml
[dependencies]
poseidon-hash = "0.1"
```

### Field arithmetic

```rust
use poseidon_hash::Goldilocks;

let a = Goldilocks::from_canonical_u64(42);
let b = Goldilocks::from_canonical_u64(10);

let sum     = a.add(&b);   // 52
let product = a.mul(&b);   // 420
let diff    = a.sub(&b);   // 32
let inverse = a.inv();     // a⁻¹ mod p
```

### Poseidon2 hashing

```rust
use poseidon_hash::{Goldilocks, hash_no_pad, hash_to_quintic_extension};

let input = vec![
    Goldilocks::from_canonical_u64(1),
    Goldilocks::from_canonical_u64(2),
    Goldilocks::from_canonical_u64(3),
];

let hash_out = hash_no_pad(&input);               // [Goldilocks; 4]
let fp5_hash = hash_to_quintic_extension(&input); // Fp5Element
```

### Merkle tree

```rust
use poseidon_hash::{Goldilocks, hash_no_pad};
use poseidon_hash::merkle::MerkleTree;

let leaves: Vec<_> = (1u64..=8)
    .map(|i| hash_no_pad(&[Goldilocks::from_canonical_u64(i)]))
    .collect();

let tree  = MerkleTree::build(&leaves);   // depth 3 for 8 leaves
let proof = tree.prove(2).unwrap();
assert!(MerkleTree::verify(tree.root(), &proof, leaves[2]));
```

---

## `no_std` support

This crate is `no_std`-compatible. The default feature set is empty. The sole runtime
dependency, `zeroize`, also supports `no_std`. Enable the optional `serde` feature to
add serialisation support (requires `std`).

---

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
