---
eip: TBD
title: Signature Aggregation for Authenticators
description: Inline and STARK-aggregated post-quantum authenticators, with dependencies surfaced by the Transaction Context precompile
author: Chris Hunter (@chunter-cb) <chris.hunter@coinbase.com>
discussions-to: TBD
status: Draft
type: Standards Track
category: Core
created: 2026-08-21
requires: 8130
---

## Abstract

> This proposal continues the work of [EIP-8288](https://github.com/ethereum/EIPs/pull/11772)
> (post-quantum signature aggregation — Vitalik Buterin, Thomas Coratger) and
> [EIP-8355](https://github.com/ethereum/EIPs/pull/12048) (FIPS 204 ML-DSA verification precompiles —
> Danno Ferrin), moving their designs into the EIP-8130 context: the aggregation machinery and the
> verification semantics are theirs; the contribution here is hanging both off the authenticator
> abstraction so inline and aggregated are two representations of one actor.

Post-quantum canonical authenticators on [EIP-8130](./eip-8130.md) support two representations of the
same actor: **inline**, where the signature is carried in the auth blob and verified natively at fixed
cost (verification semantics per EIP-8355's FIPS 204 precompiles), and **aggregated**, where the raw
signature travels in a mempool wrapper and the block carries one recursive STARK proving every aggregated
signature at once (proving machinery per EIP-8288). The `actorId` is identical in both, the builder
chooses the representation per transaction, and no migration between the two ever occurs. Aggregation
defers only the cryptographic check: authorization (`actor_config`, scope, expiry, revocation, nonce,
policy) always executes inline and in order. A canonical **aggregation wrapper** authenticator binds
declared third-party signature dependencies into the signed message and composes with an inner
authenticator; the Transaction Context precompile surfaces dependencies to execution via
`isDependencyProven`, giving every account aggregated post-quantum ERC-1271 with no wallet changes. No
transaction fields, frame modes, opcodes, or envelope changes are introduced.

## Motivation

Post-quantum signatures are large (ML-DSA-65: 1,952-byte keys, 3,309-byte signatures; hash-based schemes
larger still) and expensive to verify in the EVM. Two responses exist in draft: verify natively via
precompiles (EIP-8355), or prove signatures once per block in a recursive STARK (EIP-8288). As the
EIP-8355 discussion concluded, these are complements — aggregation solves the recurring data load;
native verification provides standards compliance (HSM and KMS signers), prover-independence, and
availability before and beside any proof system, and "the penalty for staying outside the zk toolbox"
should be bounded gas, not exclusion.

EIP-8130's authenticator abstraction is where the two combine without a seam. Because the transaction
names its authenticator in its first 20 bytes, a node knows before executing anything whether a
transaction verifies now (inline) or joins the block's proof obligation set (aggregated). Because the
`actorId` is derived from the public key identically in both representations, one Keystore actor serves
both paths for life: precompiles and canonical authenticators can ship first, aggregation can land later,
and the only thing that changes is a byte the builder controls. This also removes a migration hazard in
the frame-transaction path, where pre-aggregation PQ users verify via `ARBITRARY` witnesses that are
excluded from aggregation and must re-adopt when it ships.

## Specification

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this document are to be interpreted
as described in RFC 2119 and RFC 8174.

### Constants

| Name | Value |
| --- | --- |
| `INLINE` / `AGGREGATED` | `0x00` / `0x01` (representation byte) |
| `<SCHEME>_INLINE_COST` | TBD per scheme (benchmark-backed; see EIP-8355 gas discussion) |
| `<SCHEME>_AGG_COST` | TBD per scheme |
| `DEP_INTRINSIC_GAS` | TBD per declared dependency |
| `IS_DEP_PROVEN_COST` | warm-`SLOAD`-equivalent |
| `MAX_DEPS_PER_TX` / `MAX_DEPS_PER_WRAPPER` | TBD |
| `AGGREGATION_VK_REGISTRY` | TBD (per-scheme 32-byte verification-key commitments) |

### Scheme authenticators

Each supported scheme is a canonical authenticator: `ML_DSA_44_AUTH`, `ML_DSA_65_AUTH`, `ML_DSA_87_AUTH`
(verification per EIP-8355: pure FIPS 204, compressed public keys expanded during verification, the
32-byte digest passed as the variable-length message, empty `ctx`; domain separation is provided by
EIP-8130's `replaySafeHash`), and `LEANSPHINCS_AUTH` (hash-based, per EIP-8288). Auth blob:

```
sender_auth | payer_auth =
  SCHEME_AUTH (20) ‖ INLINE (1)     ‖ pubkey ‖ signature      // self-contained
  SCHEME_AUTH (20) ‖ AGGREGATED (1) ‖ actorId (32)            // ~53 bytes; pubkey and signature in the wrapper
```

`actorId = keccak256(SCHEME_AUTH ‖ pubkey)` in both representations; the AGGREGATED blob carries the
actorId directly because the block proof's fact index yields it and validation needs only the
`actor_config` lookup — the public key's sole pre-proof role is native verification at mempool
admission, and the mempool wrapper carries it. A builder flipping AGGREGATED → INLINE rewrites the blob
to the self-contained form from the wrapper contents (auth blobs are outside the signed hashes). The
Keystore stores 32 bytes per actor; public keys are never persisted.

- **INLINE:** the authenticator verifies natively at `<SCHEME>_INLINE_COST` and returns the actorId.
  Fully valid on any chain and in any block, independent of any proof system.
- **AGGREGATED:** the authenticator charges `<SCHEME>_AGG_COST`, requires that the block's proof covers
  `(scheme, sig_hash, pubkey)` at this transaction's position (see Block Validity), and returns the same
  actorId. The raw signature is not in the transaction; it travels in the mempool wrapper.

Because auth blobs are excluded from the signed payload hashes (per EIP-8130), the **builder chooses the
representation at inclusion**; the wallet always signs once and always ships the raw signature in the
wrapper. The sender is charged `<SCHEME>_AGG_COST` regardless of representation; an inline inclusion
consumes the difference as uncharged block gas, so aggregation is the builder's incentive and a forced or
naive inline inclusion never penalizes the user.

**Authorization is never aggregated.** The `actor_config` lookup, scope, expiry, revocation, nonce, and
policy checks execute inline at the transaction's position in the block. The block proof is an
order-independent set of cryptographic facts; an actor revoked earlier in the same block still fails at
its position even though its signature was proven.

### The aggregation wrapper authenticator

A canonical wrapper composes aggregation with additional validation conditions and binds declared
dependencies into the signed message:

```
AGG_WRAP (20)
  ‖ repr (1)
  ‖ scheme_auth (20) ‖ pubkey ‖ [signature]
  ‖ deps_commitment (32)                    // keccak256 of the canonical dependency list; 0x00…0 if none
  ‖ inner_authenticator (20) ‖ inner_data   // optional; absent ⇒ no inner condition
```

`AGG_WRAP.authenticate(hash, data)`:

1. Compute `message = keccak256(hash ‖ deps_commitment)`.
2. Verify the scheme signature over `message` — inline natively, or aggregated via the block proof
   covering `(scheme, message, pubkey)`.
3. If an inner authenticator is present, `STATICCALL inner_authenticator(hash, inner_data ‖ verified
   context)` and require success (recent-roots wrapper pattern; the inner authenticator's tier determines
   the composite's mempool tier).
4. Return `keccak256(scheme_auth ‖ pubkey)`.

Binding `deps_commitment` into the signed message closes the malleability hole that would otherwise
follow from auth blobs being unsigned: a relayer or builder that strips, reorders, or inflates the
dependency list breaks signature verification. The representation byte remains outside the message, so
builder representation choice is unaffected. Both the plain scheme authenticators and `AGG_WRAP`
transactions feed the same block proof: the proof is a set of `(scheme, message, pubkey)` facts,
indifferent to what wrapped them.

### Dependencies

A transaction's dependency list is carried in the `AGG_WRAP` data (its canonical schema is how nodes and
the protocol parse it — no new transaction field). Entry kinds:

- `[0x00, hash]` — attested by `sender_auth`; `[0x01, hash]` — attested by `payer_auth`. No additional
  signature: the transaction signature already commits to the hash via `deps_commitment`.
- `[0x02, hash, scheme_auth, pubkey]` — a third party's signature over `hash`, carried in the mempool
  wrapper (aggregated) or inline in the entry (fallback, per-entry representation byte).

Dependencies are charged `DEP_INTRINSIC_GAS` each as intrinsic gas (paid on revert; DoS-priced).
Because `AGG_WRAP` is a canonical authenticator, the protocol parses the dependency list natively from
`sender_auth` (same as it parses `K1_AUTHENTICATOR` at `address(1)` — no EVM). Let `n` be the number of
entries (`n` MUST NOT exceed `MAX_DEPS_PER_TX`). Then:

```
sender_auth_cost += n * DEP_INTRINSIC_GAS
```

This term is part of sender-intrinsic gas and therefore inside `gas_limit` (per EIP-8130: the payer pays
the ETH; both parties sign `gas_limit`). `deps_commitment` is in the signed message, so `n` is not
malleable. `hash` values SHOULD be domain-separated as in EIP-8130's sender signature payload so account
and chain binding are inherent; authorization for a dependency's signer is checked at *use*, not at
declaration — anyone may declare.

**Execution surface.** The Transaction Context precompile gains:

```
isDependencyProven(bytes32 hash, bytes32 actorId) → bool     // IS_DEP_PROVEN_COST
dependencyCount() → uint256
dependencyAt(uint256 i) → (uint8 kind, bytes32 hash, bytes32 actorId)
```

The Keystore's `validateSignature` / `authenticateActor` resolve an `AGGREGATED` signature blob by
querying `isDependencyProven` and then performing the live `actor_config` checks. The aggregated blob for
in-EVM use is compact — `SCHEME_AUTH (20) ‖ AGGREGATED (1) ‖ actorId (32)`, ~53 bytes — since the proof's
fact index is keyed by `(hash, actorId)` and the public key is not required at resolution. Every account
type thereby gains aggregated post-quantum ERC-1271 — Permit, orders, SIWE — with no wallet changes and
no token-contract changes (tokens make the standard 1271 call), and application calldata carries the
~53-byte reference instead of a multi-kilobyte signature. On chains or in blocks without a proof, the
same call succeeds with an inline-representation blob (public key and signature included), verified in
the authenticator contract.

### Mempool wrapper and propagation

(Per EIP-8288, adopted.) Aggregatable transactions propagate as `[tx, deps_payload]`, where
`deps_payload` carries raw signatures (and public keys where not in the body). Nodes verify raw
signatures natively at admission. Mempool nodes MAY replace a set of wrappers' signatures with a
recursive STARK over their union, subject to `MAX_DEPS_PER_WRAPPER`; recursive proofs are verified before
relay. A node MUST retain or be able to re-derive enough to serve either representation to a builder.

### Block validity

(Per EIP-8288, adopted, with its review items resolved as follows.) A block containing aggregated
representations carries:

- one recursive STARK whose public inputs commit to the set of `(scheme, message, pubkey)` facts proven;
- `block_deps_hash` over the **deduplicated, canonically ordered** fact list;
- a `depth_counter` public input bounding recursion: decremented at each recursive step, only base cases
  valid at zero, aggregators set `max(children) + 1`, the block records the top-level value;
- per-scheme verification keys referenced as 32-byte commitments (registry `AGGREGATION_VK_REGISTRY`),
  with verifier data supplied as witness.

A block is invalid if any aggregated-representation authenticator's fact is not covered by the proof.
Blocks with no aggregated transactions carry no proof.

### FOCIL

An inclusion-list entry for an aggregatable transaction is `[tx, deps_payload]` and counts toward IL
size. A builder facing an IL-forced aggregatable transaction MUST include it and MAY satisfy it either by
covering it in the block proof or by including it with the inline representation (absorbing the uncharged
gas difference). Because the wallet always ships the raw signature in the wrapper, **an IL entry is
always satisfiable regardless of prover availability** — censorship resistance does not depend on the
proof system being live. A builder MAY pre-verify natively and MUST NOT include a transaction whose
declared dependency signature fails.

### Sequencing

The inline path (scheme authenticators + EIP-8355-semantics verification) is independently shippable and
useful alone. The aggregated path activates later without user action: same actors, same signatures, the
representation byte flips at the builder. The reverse order is also coherent. No adopter of either path
ever migrates.

## Rationale

**One actor, two representations.** Deriving `actorId` identically in both representations is the load-
bearing choice: it converts "inline vs aggregated" from an account-type decision into a per-transaction
serialization detail owned by the builder, and it makes the EIP-8355-discussion position ("both") a
structural property rather than a coexistence of products.

**Authorization inline.** A block proof is order-independent; authorization is order-dependent
(revocation, expiry, nonces must bind to block position). Splitting exactly at the cryptographic check
preserves both properties and keeps the proof circuit signature-only.

**Deps in the signed message, not the envelope.** Auth blobs are unsigned by design (builder
representation choice); dependencies must not be malleable. Binding a commitment to the dependency list
into the signed message resolves both constraints simultaneously and avoids a transaction-field change —
consistent with EIP-8130's pattern that new validation capability lands in the authenticator slot, so the
envelope and pending transactions are never invalidated.

**Precompile semantics from EIP-8355.** Levels III and V for long-lived account keys; compressed keys
because the recurring cost on EIP-8130 is calldata (keys are never state — the Keystore holds 32 bytes
per actor regardless, which dissolves the stored-key-size question that motivates pre-expanded-key
designs); digest-as-variable-length-message to remain inside FIPS 204 proper; empty `ctx` with domain
separation supplied by `replaySafeHash`. Standard FIPS 204 keeps HSM and Cloud-KMS signers compatible,
which is the inline path's constituency.

**Proving machinery from EIP-8288.** The wrapper, recursive mempool aggregation, `block_deps_hash`,
depth bounding, vk commitments, and the leanSPHINCS/leanSTARK route split are adopted rather than
reinvented; a scheme without a direct circuit aggregates via a client-side STARK wrap (the leanSTARK
route), which is also the agility path for future schemes without consensus changes.

## Backwards Compatibility

No changes to transaction types, the EIP-8130 wire format, signature payloads, or existing
authenticators. Transactions using non-aggregatable authenticators are unaffected. Blocks without
aggregated representations are valid with no proof. This proposal is independent of EIP-8141 and of
EIP-8288's activation there; a chain running both shares proving infrastructure.

## Security Considerations

**Proof soundness is consensus-critical** for blocks carrying aggregated representations; the vk
registry entries are commitments and the verifier data is witness-checked. **Replay:** `message` binds
the EIP-8130 payload hash (and deps commitment); `replaySafeHash` binds account and chain for dependency
hashes. **Dependency authorization at use:** declaring a dependency conveys no authority; consumers
resolve the signer against live `actor_config` at execution. **Griefing:** dependencies are intrinsic-gas
priced and bounded per transaction and wrapper; inline fallback bounds worst-case block verification.
**Revocation exactness:** because authorization is inline, proofs cannot resurrect revoked or expired
actors. **Prover availability:** no liveness dependency — inline is always sufficient for validity,
inclusion lists, and non-8130 chains.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
