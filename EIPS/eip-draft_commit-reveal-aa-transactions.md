---
eip: TBD
title: Commit-Reveal AA Transactions
description: Escrowed commit-reveal for EIP-8130 transactions via wrapper authenticators, with top-of-block enforced revelation
author: Chris Hunter (@chunter-cb) <chris.hunter@coinbase.com>
discussions-to: TBD
status: Draft
type: Standards Track
category: Core
created: 2026-08-23
requires: 1559, 7805, 8130
---

## Abstract

> This proposal continues the work of [EIP-8209](./eip-8209.md) (Commit-Reveal Transaction Frames —
> Alex Forshtat, Shahaf Nacson). The consensus-layer design — escrowed inclusion guarantees,
> top-of-block revelation, attester-observation enforcement, randomized revelation ordering — is
> theirs and is adopted verbatim. The contribution here is the transaction layer: COMMIT and REVEAL
> become canonical wrapper authenticators, so the mechanism requires no transaction-format changes.

This proposal introduces a commit-reveal mechanism for [EIP-8130](./eip-8130.md) AA transactions.
A **commit transaction** in block N−1 records a salted hash of a future transaction's payload and
escrows a fixed gas reservation, without revealing the payload or its sender. A **reveal
transaction** in block N carries the real payload; revelations broadcast within the reveal deadline
are enforced into the top of block N by attester observation (per the [EIP-7805](./eip-7805.md)
fork-choice model), executed in randomized order at base fee only, drawing on the escrow.

Commitment and revelation are signaled by canonical wrapper authenticators (`COMMIT_AUTH`,
`REVEAL_AUTH`) in the existing `authenticator ‖ data` slot. No transaction fields, frame
structures, or opcodes are introduced. The protocol surface is the consensus layer shared with
EIP-8209: commitment records, escrow accounting, a block-validity rule, and an attester
observation duty.

## Motivation

The motivation of EIP-8209 applies unchanged: transactions expose their full contents in the public
mempool before ordering, enabling targeted front-running, sandwiching, and censorship, whose
profitability concentrates block production. A one-slot delay between guaranteed inclusion and
payload revelation removes the attacker's informational advantage without enshrined cryptography,
new participant types, or sub-slot critical-path work. The trade-offs accepted there — inclusion
delay, non-reveal penalty, residual speculative front-running and back-running — are accepted here
identically.

Moving the mechanism to EIP-8130 removes its transaction-layer machinery:

- The COMMIT and REVEAL frame modes become canonical wrapper authenticators: the wire format is
  untouched and pending transactions are unaffected at activation.
- The gas payer is an envelope field validated before execution, so escrow attribution and refund
  destination require no `APPROVE` simulation, and sponsoring commit flows is a signing policy of
  the payer's actor rather than explicit paymaster code support.
- The privacy mode is composed from existing pieces: a shared submitter (nonce-free mode) and a
  shared high-rate payer — the mitigation EIP-8209 recommends, running on EIP-8130's fast path.

Reveal is supposed to be public. Privacy lasts only until the inclusion slot is already bought.

## Specification

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this document are to be
interpreted as described in RFC 2119 and RFC 8174.

### Constants

| Name | Value | Description |
| --- | --- | --- |
| `REVEAL_DEADLINE` | `2` | Seconds into slot N by which revelations must be broadcast for guaranteed inclusion |
| `COMMIT_GAS_RESERVATION` | `1_000_000` | Gas escrowed per commitment |
| `MAX_COMMITS_PER_BLOCK` | `block_gas_limit // COMMIT_GAS_RESERVATION` | Cap on commitments per block |
| `COMMIT_DOMAIN` | TBD | Domain-separation constant for commitments |
| `COMMIT_AUTH` / `REVEAL_AUTH` | TBD | Canonical wrapper authenticator addresses |

`COMMIT_AUTH` and `REVEAL_AUTH` are protocol-recognized sentinels in the same sense as
`K1_AUTHENTICATOR` (`address(1)`): clients parse a `COMMIT_AUTH`- or `REVEAL_AUTH`-prefixed
`sender_auth` natively. The authenticator contract, if any, is a `STATICCALL` that returns an
`actorId`. It MUST NOT escrow, record commitments, or enforce inclusion.

### The committed payload hash

This proposal defines a **new** hash over a subset of the EIP-8130 signed payload. It is not
`replay_id`: `sender_signature_hash` includes the fee fields, which this hash deliberately omits.

```
committed_payload_hash = keccak256(rlp([
    chain_id, sender, nonce_key, nonce_sequence, expiry,
    gas_limit, account_changes, calls
]))

commitment = keccak256(COMMIT_DOMAIN ‖ committed_payload_hash ‖ salt)
```

Field notes:

- Names and encodings MATCH [EIP-8130](./eip-8130.md) (`expiry`, not a `valid_after`/`valid_before`
  pair; `account_changes`; `nonce_key` / `nonce_sequence`).
- `gas_limit` is **inside** the commitment, so a revelation cannot demand a larger execution
  budget than was escrowed.
- `max_fee_per_gas` and `max_priority_fee_per_gas` are **excluded**, so fees are chosen at reveal
  time and priced in block N.
- `metadata` is **excluded** (annotation only; not execution-relevant).
- `payer` on the reveal transaction is **excluded**. Reveal inclusion and calldata
  (`tx_payload_cost`, `sender_auth_cost`) are paid by the reveal transaction's envelope payer
  under ordinary EIP-8130 rules. Only the reserved execution budget is funded from commit-time
  escrow.
- `salt` MUST contain at least 128 bits of unpredictable randomness chosen by the user.
  Low-entropy salts permit dictionary correlation of commitments to candidate payloads.

### Commit transaction (block N−1)

An ordinary EIP-8130 transaction with `calls = []` whose sender authentication begins with the
canonical wrapper:

```
sender_auth = COMMIT_AUTH ‖ rlp([commitment_1, …, commitment_k]) ‖ inner_authenticator ‖ inner_data
```

The wrapper is a **flag plus a schema, not the mechanism**. The protocol reads the commitment list
at validation (static validity: 32 bytes each, `k ≥ 1`). The inner authenticator is the
*submitter's* identity — a shared relayer or pool account in nonce-free mode, or the user
directly — and is evaluated for `actorId` under the standard rules.

`account_changes` on a commit transaction SHOULD be empty. A `COMMIT_AUTH` wrapper MUST NOT wrap
`REVEAL_AUTH`, directly or transitively.

On inclusion, **the protocol** (not the authenticator):

1. Records `(commitment, payer, escrow, block_number, index)` for each commitment, where `index`
   is the commitment's position among this **transaction's** commitments (so two identical hash
   bytes in different transactions are distinct records).
2. Charges the envelope payer `COMMIT_GAS_RESERVATION × max_next_base_fee` per commitment, where
   `max_next_base_fee = base_fee × 1.125` per [EIP-1559](./eip-1559.md). This escrow is a protocol
   charge on the payer **outside the transaction's `gas_limit`**, with the same isolation as
   `payer_auth_cost`: the commit transaction's `gas_limit` covers only its (trivial) empty-`calls`
   execution and is unaffected by the reservation.
3. Charges intrinsic gas, including calldata for the commitment data, normally.

The payer and escrowed amounts appear in the receipt. The payer requires no code support: its
`payer_auth` signs the commit transaction like any other, and willingness to escrow is a policy
of the payer's actor.

### Reveal transaction (block N)

An ordinary EIP-8130 transaction carrying the real `calls`:

```
sender_auth = REVEAL_AUTH ‖ rlp([[block, index_1], …, [block, index_m]]) ‖ salt ‖ inner_authenticator ‖ inner_data
```

Commitment references are `(block_number, index)` pairs, as in EIP-8209.

**Same-transaction extra refs.** All `m` references MUST point at commitments recorded by a
**single** commit transaction in block N−1 (or its missed-slot successor). They MUST store the
**same** 32-byte `commitment` value. Identical copies in one commit list are how a user reserves
`m × COMMIT_GAS_RESERVATION` for one payload (EIP-8209's multi-COMMIT pattern). A reveal MUST NOT
consume another submitter's indices: receipts publish `(block, index)`, and unbound extra refs
would steal foreign escrow and top-of-block gas.

Validity requires:

1. Every referenced commitment exists, is unconsumed, and was recorded in block N−1 (or carried
   forward per Missed Slots).
2. All referenced records come from one commit transaction and share one commitment hash.
3. `keccak256(COMMIT_DOMAIN ‖ committed_payload_hash ‖ salt)`, with `committed_payload_hash`
   computed from **this** reveal transaction, equals that commitment hash.

The inner authenticator is the revealed *sender's* actor and MAY be any authenticator or wrapper,
including `AGG_WRAP`. A transaction using `REVEAL_AUTH` MUST NOT also use `COMMIT_AUTH`.

**Gas.** Execution proceeds under a budget of
`min(gas_limit − sender_intrinsic, m × COMMIT_GAS_RESERVATION)`, priced at block N's actual base
fee with **no priority fee**, paid from escrow. After execution,
`refund = escrowed_total − gas_used × base_fee_N`, paid to the block-N−1 payer(s). Since escrow
was charged at the maximum possible next base fee, it always covers block N's fee.

The reveal transaction is still an EIP-8130 transaction: `tx_payload_cost` (calldata of the real
`calls`) and `sender_auth_cost` are charged to the **reveal** envelope payer under ordinary rules.
Escrow funds only the reserved execution.

### Non-reveal

A commitment not consumed in block N (or its carried-forward successor) expires: the escrow is
retained as charged, no execution occurs, and the commitment is invalid in all future blocks.

### Inclusion enforcement, ordering, block validity, and missed slots

Adopted from EIP-8209 without change:

- **Fork-choice enforcement.** During the first `REVEAL_DEADLINE` seconds of slot N, validators
  listen on the mempool and record observed valid revelations per commitment. At attestation
  time, an attester MUST NOT attest to a block that omits a revelation it observed before the
  deadline, following the EIP-7805 inclusion-list enforcement model.
- **Revelation shuffle.** Reveal transactions execute in an order determined by `RANDAO`,
  independent of commitment inclusion order and payload contents.
- **Block validity.** Block N MUST begin with a contiguous sequence of reveal transactions in
  shuffle order, followed by all other transactions; at most `MAX_COMMITS_PER_BLOCK` commitments
  MAY appear across a block's transactions; every reveal MUST reference existing unconsumed
  commitments that satisfy Same-transaction extra refs.
- **Missed slots.** If slot N produces no block, commitments do not expire and remain revealable
  in the next valid block; a broadcast reveal transaction remains valid until then, so revealing
  after block N−1 is confirmed carries no risk.

### Mempool

Commit transactions follow standard EIP-8130 acceptance; nodes SHOULD track recorded commitments
and index pending reveal transactions by `(block, index)` reference. Reveal transactions received
before their referenced commitments are recorded MAY be held briefly or dropped under local
policy. Nodes and builders retain observed revelations at least through slot N, and carried
commitments across missed slots.

## Rationale

**Wrapper authenticators as flags, protocol as mechanism.** The transaction names its
authenticator in its first 20 bytes, so `COMMIT_AUTH` / `REVEAL_AUTH` give nodes a natively
parseable signal — like the enshrined `K1_AUTHENTICATOR` prefix — from which the protocol runs
the commitment machinery. No wire change, no signature-hash change, no invalidation of pending
transactions at activation. Records, escrow, the block rule, and enforcement are protocol; this
proposal does not pretend otherwise.

**A new committed-payload hash.** `replay_id` binds fees and therefore cannot serve reveal-time
pricing. This proposal defines a fee-excluding domain and keeps `gas_limit` committed so the
escrow bounds what a revelation can demand. `metadata` stays out because it is not executed.
Reveal `payer` stays out because reveal calldata is ordinary EIP-8130 inclusion cost, not the
hidden execution budget.

**Extra refs from one commit list.** `(block, index)` is public in the receipt. If a reveal could
attach arbitrary extra indices, it could spend another user's escrow. Requiring every extra ref
to be a copy of the same hash in the same commit transaction matches EIP-8209's "several COMMIT
frames in one tx" pattern and closes that theft.

**Fixed reservation and two-slot structure.** Unchanged from EIP-8209: a fixed 1M reservation
hides gas requirements within `[0, k × 1M]`; two-slot separation lets revelations be validated
before inclusion; a user may regard the transaction as included at block N−1.

**Payer at the envelope.** The entity that escrows, the amount, and the refund destination are
validated fields, not simulation outputs. This removes EIP-8209's requirement that paymasters
explicitly support commit transactions, and lets its recommended metadata mitigation — a large
shared gas payer — run as an ordinary EIP-8130 payer.

**Privacy is submitter ≠ sender.** A `calls_hash` field on the user's own transaction would leak
the sender at commit time. The commit inner authenticator identifies only the submitter. Users
who want concealment MUST use a shared submitter and a shared payer; self-submit or self-pay
links the user's actor to the commitment.

## Backwards Compatibility

No changes to the EIP-8130 wire format, signature payloads, opcodes, or existing authenticators,
and transactions not using the wrappers are unaffected. This proposal is nonetheless a
**consensus change**: it adds commitment records and escrow accounting, a block-validity rule for
reveal placement and ordering, and an attester observation duty — the same consensus surface as
EIP-8209, with which that infrastructure MAY be shared. "No envelope change" is a claim about the
transaction layer only.

## Security Considerations

The analyses of EIP-8209 apply unchanged and are incorporated: **speculative front-running**
(mitigated by the per-block cap, reservation size, and shuffle randomness; not eliminated),
**back-running** of the post-reveal state (inherent), **strategic payload withholding** (the
withholder forfeits the escrow; the advantage is a top-of-block position purchased at escrow
risk), **shuffle randomness** (RANDAO is builder-predictable at generation; a shuffle committee
is a possible strengthening), and **metadata leakage via the gas payer**.

Specific to this variant:

- **Privacy mode is the shared path.** Shared submitter (commit inner authenticator, nonce-free)
  plus shared payer. Wallets SHOULD default to that path when concealment is the goal.
- **Salt entropy.** ≥128 bits, unpredictable, MUST.
- **Escrow isolation.** The reservation is charged outside `gas_limit`, so a commit transaction
  cannot hide the escrow inside its execution budget. Payers evaluate the reservation as a
  signed, visible liability.
- **Foreign-index theft.** Extra refs are restricted to same-transaction, same-hash copies so a
  reveal cannot consume another party's published `(block, index)`.
- **Attester and builder obligations.** Identical to EIP-8209: per-slot mempool observation for
  attesters; revelation and carryover retention for builders.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
