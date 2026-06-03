## Why BLS is special

Signature aggregation is the killer feature. Given n signatures σ₁…σₙ on n messages by n signers:

```
σ_agg = σ₁ + σ₂ + ... + σ   (elliptic curve point addition — O(n))
```

Verification still costs only 2 pairings, not 2n. This is why Ethereum uses BLS12-381 for its beacon chain — thousands of validators sign every slot, but verification is cheap.

Compared to ECDSA/Ed25519:

- BLS sigs are ~2× larger (96 bytes vs 64 bytes on BLS12-381)
- Verification is ~10× slower (pairings are expensive)
- But aggregation makes it vastly more efficient at scale
