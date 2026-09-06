# ZEKRA challenge integration — plan and intended workflow

Merging **ZEKRA** (Debes et al., *Zero-Knowledge Control-Flow Attestation*, ASIA CCS '23)
with the Flask blockchain in this repository, so that control-flow attestation becomes a
challenge/response exchange recorded on-chain and judged independently by every node.

---

## 1. What we are building

A node challenges another to prove it executed a program correctly. The challenged node
produces a zk-SNARK proof that its execution path is legal for the program's control-flow
graph, **without revealing the path or the CFG**. Every other node independently verifies
that proof and publishes its own verdict.

That last part is what the blockchain adds. The paper has one verifier; here we get *N*
mutually distrusting ones, an immutable record of the challenge, and an audit trail of who
judged what.

Two properties shape every design decision below:

- **Freshness.** A proof must answer *this* challenge. An old proof is a valid proof of a
  stale statement, so replay defence has to be structural, not an afterthought.
- **Honest ignorance.** A node that cannot judge — no reference on its chain yet, an untrusted
  reference, a verifier crash — **abstains** rather than guessing. Abstention never blocks
  consensus, and a node's own misconfiguration must never let it accuse an honest prover. The
  design goal is to keep this set as small as possible, which is why the verification key is
  embedded in the reference itself (§2) rather than provisioned per node.

---

## 2. The intended workflow

### Step 0 — Program registration (once per program, by the authority)

The program authority extracts the CFG, chooses circuit parameters, compiles the circuit, and
runs `KeyGen`. It then publishes a **signed reference** as an on-chain transaction:

```
{ program_id, h₁, h₃, entry_node, exit_node, vk_b64, circuit_params }   + Ed25519 signature
```

| Field | What it is | Why it is here |
|---|---|---|
| `program_id` | the paper's `@P` | what a challenge names |
| `h₁` | `H(CFG ‖ r₁)` | lets a verifier confirm the right CFG was used without ever seeing it |
| `h₃` | `H(M ‖ r₃)` | the same, for the address→label mapping the circuit translates with |
| `entry_node` / `exit_node` | `n▷` / `n◄`, **numeric labels** (not addresses) | the path must start and end here; the exit node is what marks a *completed* run rather than an early bail-out into an error handler |
| `vk_b64` | the circuit's verification key **itself** (808 bytes) | the key is public by construction and reveals nothing about the CFG, which is a secret witness. Embedding it means no verifier needs a locally provisioned key, so none can abstain — or silently diverge — because its own provisioning drifted |
| `circuit_params` | padding lengths and bitwidths the circuit was compiled with | `h₁` depends on them, so resizing the circuit changes `h₁`; pinning them makes that detectable |
| Ed25519 signature | the authority's signature over the whole record | **anyone can post a transaction.** Unsigned, a node could register a CFG it invented and then produce proofs against it that verify perfectly. The chain gives immutability, not authenticity |

Entry/exit and the two digests are all *expected values* for check (2), which is why none of
them may come from the responder. The paper assumes one entry/exit pair per CFG while noting
real ones may have several; we pin a single pair.

Program materials — CFG, translator, and the blinding secrets `r₁`, `r₃` — are distributed
out of band to licensed prover nodes. **Only the digests go on-chain.** A party with no access
to the program can still verify proofs about it.

### Step 1 — Challenge

A node picks a target and a fresh 253-bit nonce, and submits a `request` transaction:

```
Verifier  ---->  Prover        { @P , nce }
```

The nonce is mined into the chain **before any proof exists**. That ordering is what makes it
a challenge rather than a formality. A nonce-reuse guard rejects a challenge whose nonce
already appeared on-chain.

### Step 2 — Prove

The challenged node sees the request addressed to it, and runs:

```
1. circuit_input_formatter.py    program materials + this nonce  ->  circuit inputs, incl. h₂
2. the compiled xjsnark class    evaluates the circuit           ->  the witness
3. run_prover_raw                witness + proving key           ->  proof.bin
```

`r₂`, the path blinding factor, is sampled **fresh per attestation** — reusing it would make
`h₂` a stable identifier for "this path ran", leaking across attestations. Every nonce and
blinding factor must be under 254 bits: the formatter refuses larger ones by printing a message
and exiting *successfully*, so an out-of-range value fails silently rather than loudly.

Before proving, the node checks that its own materials reproduce the `h₁` and `h₃` the
authority signed. If they do not, it has the wrong program, wrong blinding factor, or wrong
circuit parameters, and it refuses rather than producing a proof nobody can verify.

It replies with a `response` transaction carrying `h₂`, the proof, its public key, and a
signature binding `{program_id, request_hash, nonce, h₂}`.

**The proof goes on-chain in full**, in `proof_b64`. Groth16 proofs are constant-size — 134
bytes, 180 base64 characters — so there is nothing to save by storing a digest and shipping the
proof out of band, and doing so would mean the chain no longer carried the evidence for its own
verdicts. (`function_parameter` holds a 16-character fingerprint of the attestation, but that is
for display in the node UI only; it is never what gets verified.) What is deliberately *not*
carried is `primary_input.bin` — see §3. That omission is about soundness, not size.

### Step 3 — Verify (every other node, independently)

Each node runs all three of the paper's checks:

```
(1)  Vf( Sig , h₂ , tpk ) = 1                             -- the path was signed by the prover's tracer key
(2)  x \ {h₂} == { H(CFG‖r₁) , H(M‖r₃) , n▷ , n◄ , nce }  -- the claim is the right claim
(3)  Verify( vk_C , x , y , π ) = 1                       -- the SNARK
```

All three are required. Check (3) alone is not enough: a replayed proof satisfies it perfectly,
because it is a valid proof — of a stale statement. Check (2) is the entire anti-replay
mechanism.

**Assumption, inherited from ZEKRA.** Check (1) is meaningful in the paper because `tsk` lives
in a trust anchor a software adversary cannot reach, so the recorded path is truthful even on a
compromised prover. We simulate the tracer — as the paper's own evaluation does, deriving sample
paths with angr — and the prover node's key stands in for `tpk`. Check (1) therefore establishes
that the response came from the node that was challenged, not that a tamper-resistant tracer
observed the execution. The trusted-tracer assumption is ZEKRA's and we inherit it unchanged; it
is orthogonal to what this integration adds, which is the verification layer above it.

### Step 4 — Verdict

Each verifier publishes `correct`, `incorrect`, or nothing at all (abstain). Verdicts are
mined into the chain alongside the attestation they judge.

**Role exhaustion.** Independent verifiers number `N − |{challenger, responder}|`. The two
excluded roles are excluded for different reasons:

| Role | Publishes a verdict? | Why |
|---|---|---|
| responder | no | it would be grading its own attestation. An on-chain "correct" signed by the node under scrutiny is worse than no verdict, since a later reader cannot tell it from an independent one |
| challenger | no | it *does* run all three checks, but the verdict is addressed to itself and a node registers only peers — so there is no address to deliver it to (gap #9) |
| miner | **yes** | a miner is normally a disinterested third party, and there is no reason to exclude it |

Including the miner takes care: verification is otherwise triggered only inside
`resolve_conflicts()`, i.e. when a node adopts a chain *longer* than its own, and a miner never
does — its chain is already the longest. `/mine` therefore verifies the block it just mined as a
separate step.

On the six-node deployment that gives four independent verdicts per attestation, and even three
nodes yield one: whichever node is neither challenger nor responder reports, whether or not it
mined.

---

## 3. Option A — the verifier rebuilds the public inputs

The paper treats `x` as one object: the verifier checks its components against the reference
values and verifies the proof against that same `x`. Preserving that property is not automatic
once the verifier is a file-based binary, which is why it gets its own section.

`run_verifier_only` takes the public input as a *file*, so a naive wiring ends up holding two
representations — the values compared against the reference, and the `primary_input.bin` handed
to the binary. Nothing forces them to agree. A dishonest responder could then declare correct
values while shipping a file encoding *different* ones: check (3) passes (the proof genuinely
matches the shipped file), check (2) passes (the declared values look right), and the two are
unrelated. Check (2) becomes decorative, because one object is checked and another is verified.

**Option A keeps `x` single.** The verifier discards anything the responder says about the claim
and builds `primary_input.bin` itself:

```
n▷ , n◄ , h₁ , h₃   <- the authority-signed on-chain reference
nce                 <- the nonce on the request transaction, on-chain
h₂                  <- the responder (the one value that legitimately comes from it)
```

If the proof was generated for any other statement, check (3) fails. **Check (2) therefore
cannot be bypassed, because a lying responder never gets to state the claim.**

This is not a deviation from the paper but the faithful implementation of it. Every component of
`x` except `h₂` is pinned by the reference and the on-chain request, so `x` is fully determined:
"receive it and check every field" and "construct it from what we already know" are the same
statement. Constructing is simply the encoding that cannot be got wrong — a field cannot be left
unchecked, or compared in the wrong order, if it is never accepted in the first place.

`h₂` being responder-supplied is correct: it is `H(EP‖nce‖r₂)`, the commitment to the secret
execution path — precisely what is being attested, and precisely what check (1)'s signature
covers.

**Consequence for the data model:** the response carries no `primary_input_b64`. Its absence
is the point.

### The serialization

`primary_input.bin` is an ASCII count, a newline, then *N* × 32-byte little-endian field
elements in **Montgomery form** (`a·R mod p`, `R = 2²⁵⁶ mod p`), ordered:

```
[ 1 , n▷ , n◄ , nce , h₁ , h₂ , h₃ ]
```

Recovered by decoding real prover output, not from documentation. Reconstruction from the
reference values is byte-identical to what `run_prover_raw` emits.

---

## 4. What we had to decide about the secrets

The formulas (`h₁ = H(CFG‖r₁)`, `h₂ = H(EP‖nce‖r₂)`, `h₃ = H(M‖r₃)`) are the paper's. Two
things it does not settle, which we had to:

**Who creates `r₁` and `r₃`.** The paper never says — they are "random padding", and generating
and distributing reference material is out of scope there. We assign it to the authority:
sampled once when the reference is built, shipped with program materials to licensed provers,
never published. Only `h₁`/`h₃` go on-chain. `_prove_real()` enforces consistency by recomputing
both and refusing to prove on mismatch.

What matters operationally is that `r₁`/`r₃` and `r₂` have different lifetimes:

| | Scope | Regenerated | Created by |
|---|---|---|---|
| `r₁`, `r₃` | per-program | never, while the reference stands | the authority |
| `r₂` | per-attestation | every proof | the prover |
| `nce` | per-challenge | every challenge | the challenging node |

`h₁`/`h₃` are pinned reference values agreed in advance; `h₂` is supplied fresh and signed each
time. That is why `r₂` may be resampled freely and `r₁` may not.

**Collapsing Prover and Worker into one node.** ZEKRA splits them for *resources*, not security.
The prover is assumed to be a low-end embedded device that cannot run Groth16, so proving is
outsourced "without complicating the prover" (§5). The worker is not a safety mechanism: the
paper calls it **semi-dishonest** — the prover hands it the execution path and the blinding
factors and "must trust that the worker keeps the inputs secret", trusted for privacy but
untrusted for proof generation. Weakening that trust assumption is listed as future work.

Merging them therefore *removes* a trust assumption rather than adding one. The Jetsons can
prove for themselves, so `EP` and `r₂` never leave the node that recorded them and there is no
third party to trust with them.

The cost is replication, not exposure. The paper's worker already holds `CFG`, `M`, `r₁`, `r₃`,
so we introduce no new class of holder — but one worker can serve many provers, whereas every
attesting node here needs its own copy. The set of machines able to fabricate a legal path grows
with the number of provers, which is what makes gap #11 (licensing not enforced) matter. The
minimal-TCB motivation does not apply either way: it is an argument about embedded devices, and
these are Jetsons.

This is a separate deviation from the simulated tracer noted in §2, and they should not be
conflated: this one concerns *who holds the program materials*, that one concerns *whether the
recorded path can be trusted*.

### Mapping to the ZEKRA tooling

| Paper | `circuit_input_formatter.py` |
|---|---|
| `nce` | `--nonce-verifier` |
| `r₂` — path blinding, fresh per attestation | `--nonce-path` |
| `r₃` — translator blinding, program secret | `--nonce-translator` |
| `r₁` — CFG blinding, program secret | `--nonce-adjlist` |
| `n▷` / `n◄` | `in_initial_node` / `in_final_node` |
| `h₁ = H(CFG‖r₁)` | `in_encoded_adjlist_digest` |
| `h₂ = H(EP‖nce‖r₂)` | `in_recorded_path_digest` |
| `h₃ = H(M‖r₃)` | `in_translator_digest` |

---

## 5. Data model

### The reference (authority-signed, on-chain)

```json
{
  "reference": {
    "program_id": "crc32",
    "h1": "...", "h3": "...",
    "entry_node": 3, "exit_node": 41,
    "vk_b64": "<base64 of verification_key.bin, 808 bytes>",
    "circuit": {
      "adjlist_len": 64, "adjlist_levels": 9, "path_len": 128,
      "stack_depth": 8, "label_bitwidth": 7,
      "bucket_bitwidth": 4, "address_bitwidth": 32,
      "pruned": true
    }
  },
  "authority_pubkey": "<ed25519 hex>",
  "authority_sig": "<ed25519 hex>"
}
```

On-chain rather than a config file: immutable, timestamped, and identical for every verifier
by construction. Config files drift per node, and this codebase has already shown how silently
divergent per-node state behaves.

### Challenge and response

The challenge is a `request` transaction with `program_id` and the nonce in
`function_parameter`. The response carries `h2`, `proof_b64`, the prover's public key, and the
binding signature.

Note: content-hash dedup cannot detect duplicate *responses*, because Groth16 is randomized
and two honest proofs of the same statement differ byte-wise. Parent-based dedup is used
instead.

---

## 6. CFG pruning — how it touches the chain

Pruning changes the adjacency list and translator, so it changes `h₁` and `h₃`. Everything else
follows from that:

- **The pruned CFG is part of the signed reference, not a prover's local choice.** A prover that
  pruned on its own would compute digests that cannot match, and `_prove_real()` refuses to
  proceed. The authority must prune once and register the result.
- **The reference carries a `circuit.pruned` flag**, so provers format the same files the
  authority did. Without it a pruned program simply cannot be attested — the formatter reads the
  unpruned files and every digest mismatches.
- **Nothing extra leaks.** The reference already publishes circuit dimensions, which reveal about
  as much as the flag; the CFG stays behind a hash. Provers need no extra out-of-band knowledge,
  since the translator shipped with the materials already emits paths in the pruned label space.

**The part that matters for the chain: verifiers cannot see how the CFG was pruned.** A verifier
only ever holds `h₁`, a hash. `prune_cfg.py --mode path` keeps only one recorded trace's nodes
and edges, which guts the forward-edge check; `--mode bidir` (the default) preserves every
branch a different input could take. Nothing in the protocol distinguishes the two, so no amount
of independent verification can catch a badly pruned registration. Soundness for a program rests
entirely on the authority — which is exactly why the pruned CFG must come from it. Pruning also
narrows scope: a hijack *outside* the pruned region yields a valid proof.

> **Open decision.** Widen `circuit.pruned` from a boolean into a signed declaration —
> `{"mode": "bidir", "region": "<name>"}`. A verifier still cannot check it, but because the
> reference is authority-signed and immutable it becomes an *accountable* declaration: an
> auditor can see what security scope each program was registered under. One-line change.

---

## 7. Known gaps

Full list in `ISSUES.md` (15 entries). The ones that matter for attestation:

- **#11 — licensing is not enforced.** Any node holding program materials may attest; nothing
  checks it was *authorised* to. The paper notes (§5) that anyone knowing a CFG can identify
  satisfying paths, so leaked materials mean valid-looking attestations. Currently mitigated
  only by distribution discipline. **Largest remaining security gap.**
- **#10 — only the first response in a block is verified.** A second attestation riding in the
  same block is adopted into permanent history unverified.
- **#3 — no consensus rule behind verdicts.** Verdicts are recorded, but nothing aggregates
  them into a decision.
