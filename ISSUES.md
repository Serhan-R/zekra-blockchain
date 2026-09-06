# blockchain-python-project — Known Issues

Compiled from hands-on testing of `FlaskBlockChain.py` / `control_panel.py` / `launch.py` across a 3-node local network (`192.168.20.30:5000-5002`). Each issue below was directly reproduced during testing unless noted otherwise.

---

## 1. Identity misattribution in `check_and_execute_requests()` ("identity theft")

**Location:** `FlaskBlockChain.py`, `Blockchain.check_and_execute_requests()`

**Description:** Whichever node mines a block containing a `request` transaction executes it and generates the response — regardless of whether that request was actually addressed to that node. The docstring says it "checks the provided blocks for any pending computation requests **directed to this node**," but the code never verifies that; it only checks `transaction_type == 'request'`, not `transaction['recipient']`. On top of that, the response's `sender` field is set to `transaction['recipient']` (the intended answerer) instead of the executing node's own `node_identifier`, so credit is always attributed to whoever was *named* as recipient, never to whoever actually did the work.

**Reproduced:** Repeatedly — challenges between Node 2 and Node 3 (`fibonacci(5)`, `fibonacci(2)`, `sum_natural(9)`, `sum_natural(10)`) were mined on Node 1, an uninvolved third node. Each time, Node 1 computed the answer but the resulting response transaction falsely credited Node 2.

**Impact:** Undermines the core premise of the project (Decentralized Integrity Verification and *Attestation*) — the chain records a claim about who performed a computation with no way to verify or falsify who actually did it.

**Fix:** Gate execution on `transaction['transaction_type'] == 'request' and transaction['recipient'] == node_identifier`. Once this check is in place, `transaction['recipient']` is guaranteed equal to `node_identifier` inside the branch, so the existing `"sender": transaction['recipient']` line becomes correct without further changes. (See issue 2 — this fix alone is not sufficient.)

---

## 2. Silent request loss when a request is mined by the wrong node (regression introduced by fixing #1 alone)

**Location:** `FlaskBlockChain.py`, `Blockchain.new_block()` / `broadcast_mined_transactions()`

**Description:** After adding the recipient check from issue 1, a request mined by an unintended node is correctly *skipped* (no more false credit) — but `broadcast_mined_transactions()` still runs unconditionally right after `new_block()`, wiping that transaction's hash out of **every** node's pool, including the true intended recipient's. The request ends up permanently sealed into the chain, unanswerable forever, with no error or log indicating anything went wrong. This is made worse by the fact that the call to `check_and_execute_requests()` after adopting a synced chain is commented out in `/notify_change` — so even the correct recipient, upon syncing to this chain later, will never automatically notice and process the backlog.

**Reproduced:** Yes — after implementing the fix from issue 1, sent a request from Node 3 to Node 2 and mined it on Node 1. The request is sealed on-chain, identical on every node's copy, with no response ever generated.

**Fix:** Filter `request`-type transactions out of what gets included in a mined block unless `recipient == node_identifier`, so an unaddressed request stays safely behind in the pool instead of being sealed and then wiped. Separately, re-enable (and fix) the `check_and_execute_requests()` call after a successful chain replacement in `/notify_change`, using a proper divergence-point check rather than the current index-based `last_processed_block` bookmark (see discussion below — the bookmark assumes append-only growth and breaks across a chain *replacement*, e.g. after resolving a fork).

---

## 3. No real "voting" or consensus enforcement behind verification

**Location:** `FlaskBlockChain.py`, `Blockchain.resolve_conflicts()` / `validate_response_transaction()`

**Description:** Verification is not a majority-enforced, network-wide decision. Each node's independently recomputed verdict only gates whether *that node* personally adopts a given candidate chain (`if self.validate_response_transaction(last_block): ... new_chain = chain`) — it has no effect on any other node, and disagreeing nodes simply diverge rather than reconciling. The resulting `verification` transactions are purely informational; the only thing that reads them is `/count_verdicts`, a passive tally with zero enforcement (nothing rejects a block, rolls back a chain, or penalizes a node based on the count).

Worse: `validate_response_transaction()` only examines the *last* block of whatever candidate chain is being considered for adoption (`break # Only check the first response transaction` inside a loop over `last_block['transactions']`). A wrong (or falsified) response buried even one block deep is never re-checked, and gets silently absorbed into accepted history the moment a longer chain containing it is adopted by another node.

There's also a coverage gap on the *other* end: `validate_response_transaction()` is only ever called from inside `resolve_conflicts()`, which only runs when a node is deciding whether to adopt a *peer's* longer chain. The node that actually mines a response into a block never calls `resolve_conflicts()` for its own mine — it already has the longest chain the moment it mines, by construction — so it never independently verifies the very response it just sealed into permanent history. Combined with issue 9 (the original requester can never successfully record its own verification either), this means the two nodes with the most direct involvement in a given response — whoever mined it, and whoever asked for it — are both structurally excluded from ever contributing a verdict on it.

**Reproduced:** Yes — confirmed via access-log forensics on a 6-node test. `validate_response_transaction()` makes a distinctive self-request (`GET http://localhost:{port}/id`) that shows up in each node's log as `127.0.0.1 - - "GET /id HTTP/1.1" 200`. In a run where Node 4 mined the response block, every other node's log showed that self-`/id` line at least once around the sync burst that followed — Node 4's log showed it zero times, anywhere. Node 4 never ran the verification check at all for the block it had just mined.

**Impact:** There is no durable guarantee that an incorrect computation result can't become part of permanently accepted history — correctness is only ever spot-checked once, at the moment a chain is the newest thing around, and even that one check is never performed by two of the most relevant parties (the miner of the response block, and the original requester).

---

## 4. Race condition: two nodes mining the same pending content → permanent fork → lost transactions

**Location:** General consequence of `Blockchain.new_block()` / `resolve_conflicts()`; no coordination between nodes when mining.

**Description:** Because pending transactions are broadcast to every peer's pool, more than one node can hold identical content and mine it independently before the first miner's cleanup broadcast (`broadcast_mined_transactions`) reaches the others. This produces two valid, same-length, mutually exclusive blocks. `resolve_conflicts()` only replaces a chain on *strictly greater* length, so a tie is never resolved on its own (see issue 6). Once one branch eventually pulls ahead, the losing branch is discarded wholesale — and since there is no logic to return the losing branch's unique transactions to the pool (unlike real blockchain clients, which requeue orphaned transactions into the mempool on a reorg), any transaction that only existed on the losing fork is silently and permanently lost.

**Reproduced:** Yes — Node 1 and Node 3 both independently mined the same `sum_natural(10)` request, producing two different versions of "block 10." Node 3's branch (containing the `55` response) was confirmed to be a dead-end fork that would be discarded — and its response transaction lost forever — once Node 1's longer chain was adopted network-wide.

---

## 5. `resolve_conflicts()` crashes mid-validation due to leftover debug `print()` statements

**Location:** `FlaskBlockChain.py`, `Blockchain.valid_chain()`

**Description:** `valid_chain()` contains leftover debug logging that dumps the full contents of every block in the candidate chain being validated (`print(f'{last_block}')`, `print(f'{block}')`). When a node's process has its stdout connected to a pipe with no active reader (e.g. due to how the process was originally launched/backgrounded), printing a sufficiently large chain raises an unhandled `BrokenPipeError`, which propagates all the way up through `resolve_conflicts()` and crashes the request with a 500 error before the chain comparison/adoption can complete.

**Reproduced:** Yes — calling `GET /nodes/resolve` on Node 2 crashed with `BrokenPipeError: [Errno 32] Broken pipe` at `print(f'{block}')`, explaining why Node 2 had been stuck several blocks behind Node 1 for the entire test session: every sync attempt was silently dying mid-validation.

**Fix:** Remove the debug `print()` statements from `valid_chain()` — they serve no functional purpose and can take down a core consensus function.

---

## 6. `KeyError: 'index'` in the control panel when mining an empty pool

**Location:** `control_panel.py`, `mine_block()`

**Description:** `/mine` returns HTTP 200 both for a successful mine (`{'message': 'New Block Forged', 'index': ..., ...}`) and for a no-op (`{'message': 'No pending transactions to mine'}`, no `index` key). `mine_block()` only checks the status code before unconditionally reading `mined_data['index']`, so mining a node whose pool is empty crashes the control panel with `KeyError: 'index'` instead of reporting that nothing happened.

**Reproduced:** Yes.

**Fix:** Check for the presence of the `'index'` key (or branch on the `'message'` field) before assuming a block was actually mined.

---

## 7. Notifications can silently fail to deliver, with no retry

**Location:** `FlaskBlockChain.py`, `Blockchain.notify_neighbors()`

```python
try:
    response = requests.post(f'http://{node}/notify_change', json={'last_block_hash': last_block_hash})
except requests.exceptions.RequestException:
    print(f"Failed to notify node {node}")
```

**Description:** Each notification is a fire-and-forget POST wrapped in a try/except that just logs a failure to the console and moves on — no retry, no queued follow-up. A momentarily unreachable peer (restarting, brief LAN hiccup) simply never learns that anything changed. Since chain comparison is purely reactive to receiving a notification, that peer has no way to catch up until some *later*, unrelated mine-and-notify cycle happens to reach it successfully.

The failure detection itself also has a blind spot: the `try`/`except` only catches connection-level exceptions (timeout, connection refused, DNS failure). It does not check `response.status_code` in any `else`/failure branch — the code only prints on a clean `200`:

```python
if response.status_code == 200:
    print(f"Notified node {node}, response: {response.json()}")
```

If the POST is delivered successfully but the receiving node's handling of it fails server-side — for example, `resolve_conflicts()` hitting the `BrokenPipeError` from issue 5 during that specific call, returning a 500 — the sender gets a non-200, non-exception response, and *neither* branch fires. Nothing is printed on either end. The notification looks like it silently vanished, with no way to tell from the sender's side whether it never arrived at all or arrived and crashed the receiver mid-handling.

**Reproduced:** Yes — in a 6-node, 2-Jetson test, Node 1 mined a block and notified all peers; every node adopted the new chain except Node 6, which stayed silently one block behind. Node 1's console gave no indication anything had failed. Manually triggering `GET /nodes/resolve` on Node 6 immediately and successfully resolved it to the correct longer chain — confirming Node 6's own sync logic was working fine, and the failure was specifically in the automatic notify-and-react path (either the POST from Node 1 never landed, or it landed and Node 6's handling of it failed silently per the blind spot above). Nothing in the system surfaced which of the two actually happened.

**Fix:** Also branch on a non-200 status code (not just the exception case) and log it. Longer-term, this is the same underlying gap as issue 2's backlog problem: a purely reactive, one-shot notification with no retry and no periodic reconciliation sweep means any single missed or failed delivery can leave a node desynced indefinitely with zero visibility into why.

---

## 8. No tie-breaking rule for equal-length competing chains

**Location:** `FlaskBlockChain.py`, `Blockchain.resolve_conflicts()`

**Description:** The chain-adoption condition is strictly `length > max_length`. Two valid chains of exactly equal length — the natural outcome of the racing-mine scenario in issue 4 — are never reconciled by this check alone; neither side will adopt the other's chain purely by length comparison, and the fork can persist indefinitely until one side is mined further ahead of the other.

---

## 9. A node can never successfully verify (or otherwise message) itself — silent self-addressing gap

**Location:** `FlaskBlockChain.py`, `Blockchain.register_node()` combined with `Blockchain.validate_response_transaction()`

**Description:** `register_node(address)` populates `self.nodes` (used for chain-sync gossip and notifications) and, separately, attempts to resolve and store the peer's identifier in `self.node_addresses` via a `/id` GET — but a node is never asked to register itself, so `self.node_addresses` never contains an entry for the node's own `node_identifier`. This silently breaks any code path that looks up a destination address by ID when that ID happens to be the node's own. Most concretely: `validate_response_transaction()` sets `request_node_id = response_transaction['recipient']`, which is always the *original requester* of whatever was answered — and the original requester is guaranteed to independently run its own `resolve_conflicts()` / `validate_response_transaction()` cycle on that very same response, since it's just another node on the network. When that happens, `self.node_addresses.get(request_node_id)` resolves to `None` for that one specific node (itself), the `if request_node_address:` guard is silently `False`, and the verification transaction it just computed is simply never sent — no error, no log line indicating anything was skipped.

**Reproduced:** Yes, directly — in a 6-node test (Node 6 → Node 3 request, mined on Node 1, response mined on Node 4), all four other nodes that got the chance to check it correctly generated and delivered a `verification` transaction to Node 6, but Node 6's own verification of the response addressed to itself never appeared anywhere in the network.

**Impact:** The one node with arguably the most direct stake in a given verification — the original requester itself — is structurally the one node whose own verdict can never be recorded on-chain. This isn't a rare edge case; it happens on every single request/response cycle, since the requester always ends up running this exact check against its own incoming response.

**Fix:** Either (a) have each node register itself alongside its peers at startup (add its own address/id into `self.nodes`/`self.node_addresses`), or (b) special-case the lookup wherever this pattern occurs (`validate_response_transaction()`, and `check_and_execute_requests()` if a node can ever be its own request's target) to detect `request_node_id == node_identifier` and handle it locally instead of routing it through an HTTP POST to itself.

---

## 10. Only the first response in a block is ever verified

**Location:** `FlaskBlockChain.py`, `Blockchain.validate_response_transaction()`

**Description:** The function scans the block being adopted for the *first*
`response` transaction and stops (`break  # Only check the first response
transaction`). Any further response in that same block is never checked at all.
With ZEKRA attestations this matters more than it did for the arithmetic
challenges: a second attestation riding along in the same block is adopted into
permanent history with none of the three checks applied to it, and no verdict is
ever published about it. Combined with the existing behaviour of only examining
the *last* block, a response buried one block deep is likewise never re-checked.

**Status:** Known and deliberately deferred. Fixing it means verifying every
response in the block (bounded cost) or every response since the divergence point
(strictest, cost grows with how far behind a node is).

**Impact:** An attacker who can get two responses into one block gets the second
one accepted unverified.

---

## 11. Any node holding program materials may attest; licensing is not enforced

**Location:** `zekra_integration.py`, `verify_attestation()` / `build_zekra_response()`

**Description:** A node can produce a ZEKRA attestation for any program it holds
materials for, and verifiers check only that the responder was the node
challenged and that its signature verifies under its registered key. Nothing
checks whether that node was ever *authorised* to attest for the program. The
ZEKRA paper notes (section 5) that anyone knowing a program's CFG can identify
paths satisfying the circuit, so if program materials leak, any node with a
registered key can produce attestations that verify cleanly.

**Status:** Known and accepted for now. The fix would be to list authorised
prover public keys inside the authority-signed reference and have verifiers
reject attestations from keys not on that list, making the licence
cryptographically enforced rather than a distribution convention.

**Mitigation in place:** program materials (CFG, translator, blinding factors
r1/r3) are distributed only to designated prover nodes, so the set of parties
able to fabricate a legal path is limited by distribution discipline rather than
by cryptography.

---

## 12. Real proving needs a one-time circuit compile on a node with a JDK

**Location:** `zekra_integration.py`, `_prove_real()`

**Description:** `compile_circuit.py` bakes the circuit's input and output
directory paths into the generated Java source and recompiles it, so changing
those paths requires `javac`. Doing that per attestation would be absurd, and
prover nodes may have only a JRE. `_prove_real()` therefore assumes the circuit
was compiled **once** against a fixed working directory (`ZEKRA_CIRCUIT_INPUT_DIR`
/ `ZEKRA_CIRCUIT_OUTPUT_DIR`); every attestation then rewrites its inputs into
that same directory and re-runs the already-compiled class with a plain `java`.

**Status:** By design, but it is a deployment prerequisite that is easy to miss.
A node whose classes were compiled against someone else's paths will write inputs
where the circuit does not read them, and will fail at witness generation rather
than produce a wrong proof.

**Impact:** None on security -- a misconfigured prover produces no witness and
therefore no proof, and an absent proof is not a false attestation. It is purely
a provisioning step: run the compile once per circuit, per prover image.

**Not yet exercised:** the Java witness step could not be run in the device VM
(no `javac`, and the prebuilt classes carry a WSL path from the wikisort ROI
check). Steps 1 and 3 of `_prove_real()` -- the formatter and `run_prover_raw` --
are covered, and the whole verification side is covered by
`test_zekra_real_mode.py` against genuine Groth16 proofs. Step 2 needs a node
with a JDK to close out.

---

## 13. Pruned-CFG programs must be flagged in the reference

**Location:** `zekra_authority.py --pruned`, `zekra_integration.py build_reference()`

**Description:** `circuit_input_formatter.py` reads a different set of files when
given `--pruned`, which changes the adjacency list and therefore h1 and h3. The
authority must record which variant its digests were computed over, otherwise a
prover formats the wrong files and produces digests that do not match the
reference. The reference now carries an optional `circuit.pruned` flag, set by
`zekra_authority.py build --pruned`, and `_prove_real()` passes `--pruned`
through when it is set.

**Status:** Fixed. The flag is omitted when false so references built before it
existed still verify byte-for-byte under the authority signature.

**Impact:** None on security. A mismatch was already caught by `_prove_real()`'s
h1/h3 cross-check against the signed reference, which refuses to proceed; the
flag turns an unprovable program into a provable one rather than closing a hole.

---

## 14. Miners never verified; responders verified themselves

**Location:** `FlaskBlockChain.py`, `validate_response_transaction()`, `/mine`

**Description:** Two opposite faults in the same coupling. Verification ran only inside
`resolve_conflicts()`, i.e. when a node adopts a chain longer than its own.

1. **The miner never verified.** Its own chain is already the longest, so it adopts nothing and
   the verification path never ran for blocks it produced. Not a decision -- a side effect of
   attaching verification to chain adoption rather than block creation. Every attestation lost
   one independent verifier.
2. **The responder verified itself.** When the challenged node adopted the chain carrying its
   own response, nothing stopped it from judging that response and publishing a verdict on its
   own attestation.

**Status:** Both fixed. `validate_response_transaction()` now accepts the chain but publishes no
verdict when the response is our own, and `/mine` calls `verify_mined_block()` on the block it
just produced.

**Impact:** Independent verifiers go from `N - |{challenger, responder, miner}|` to
`N - |{challenger, responder}|` -- four instead of three on the six-node deployment, and one
instead of zero on three nodes. The self-verdict was the more serious of the two: an on-chain
"correct" signed by the node under scrutiny is indistinguishable from an independent one to any
later reader.

**Related:** the challenger still produces no verdict, because the verdict is addressed to
itself and a node registers only peers -- that is gap #9, still open. The same adoption coupling
is also behind gap #10.

---

## 15. Out-of-range nonces silently poisoned an attestation

**Location:** `zekra_integration.py`, `_prove_real()`

**Description:** `circuit_input_formatter.py` rejects any nonce whose bit length is >= 254 --
but it does so by printing a message and calling `sys.exit()` with **no error status**, writing
no output files. `_prove_real()` sampled `r2` with `secrets.randbelow(FIELD_P)`, which is 254
bits roughly **34%** of the time, and `_run()` only checks the return code.

Because the circuit is compiled once against a FIXED input directory, the previous attestation's
`in_*` files were still sitting there. The failure path therefore read the **previous
challenge's** `h2`, signed it as the answer to this challenge, and produced an attestation that
every verifier would reject -- an honest node judged `incorrect` roughly one attestation in
three. The same trap is reachable from the challenge nonce, which the challenger chooses.

**Status:** Fixed, two ways. `sample_blinding()` draws below `2**253` so every value is in range
(253 bits of entropy is ample). Separately, `_prove_real()` now clears `in_*` from the working
directory before formatting and raises if no digest was produced, so any silent formatter failure
becomes a loud error instead of a stale read.

**Impact:** No false ACCEPT -- the stale `h2` did not match the witness, so the proof failed
verification. The damage was to availability and to reputation: honest provers accused of
producing bad attestations, intermittently and for no visible reason.

**Note for deployment:** challenge nonces must also be under 254 bits. 253-bit nonces are the
safe range for every value the formatter takes.

---

## 16. Proof generation blocks the request handler for ~17 seconds

**Location:** `FlaskBlockChain.py`, `check_and_execute_requests()`, called from `/mine` and
`/notify_change`

**Description:** A full `_prove_real()` -- format inputs, generate the witness in Java, run
`run_prover_raw` -- measured **17.2 s** for crc32 at 141,677 constraints, and **3.5 s** for the
same program pruned (`--mode bidir`, 26,140 constraints). It runs synchronously inside the
request handler, so the node is inside an HTTP request for the whole of it.

Note pruning is a five-fold mitigation here, which is a second reason to prune beyond circuit
size -- though it does not remove the need to move proving off the request path.

In mock mode a "proof" is a SHA-256 digest and returns instantly, which is why this has never
been visible: every blockchain-level test so far has run in mock mode.

**Status:** Open. Not yet observed in a joined run (see #18's note on what has and has not been
tested together). The fix is to generate the proof off the request path -- answer the HTTP call
immediately and submit the response transaction when the proof is ready.

**Impact:** A node is unresponsive for ~17 s per attestation, and the delay compounds with #17.

---

## 17. No HTTP timeouts on any inter-node call

**Location:** `FlaskBlockChain.py` -- all 8 `requests.get` / `requests.post` calls

**Description:** None of the inter-node calls pass `timeout=`. `requests` then waits
indefinitely. Mock-mode responses are instant, so this has never mattered.

With real proving it does: a node calling `/notify_change` on a peer that is mid-proof blocks
for that peer's full ~17 s (#16), and a peer that dies mid-proof leaves the caller hanging with
no recovery.

**Status:** Open. A timeout on every inter-node call is a small, self-contained change; the
value has to exceed the worst-case proving time unless #16 is fixed first, which is the better
order.

**Impact:** One slow or dead prover can stall every node that tries to notify it.

---

## 18. Concurrent attestations on one node would clobber each other

**Location:** `zekra_integration.py`, `_prove_real()`

**Description:** `compile_circuit.py` bakes the input and output directory paths into the Java
source, so the circuit is compiled once against a FIXED working directory and every attestation
rewrites its inputs there. Two attestations running at once on the same node therefore overwrite
each other's `in_*` files and witness between the formatter and the prover.

**Status:** Open, and not currently reachable: a node answers one challenge at a time because
proving is synchronous (#16). Fixing #16 by moving proving off the request path would make it
reachable, so the two must be addressed together -- per-attestation working directories, or a
lock serialising proof generation.

**Impact:** Under concurrency, an attestation could be built from another challenge's inputs.
The stale-digest guard added in #15 catches a missing formatter output but not a complete set of
files belonging to a different challenge.

---

## 19. A stale witness could be proved against, yielding a valid proof of the wrong statement

**Location:** `zekra_integration.py`, `_prove_real()` step 2

**Description:** `compile_circuit.py` bakes the input and output directory paths into the Java
source. If the compiled class was built against different directories than
`ZEKRA_CIRCUIT_INPUT_DIR` / `ZEKRA_CIRCUIT_OUTPUT_DIR`, it writes its witness elsewhere and
leaves the configured output directory untouched. `_prove_real()` then found the **previous
attestation's** `zekra_Sample_Run1.in` still sitting there and proved against it.

The result is a cryptographically valid Groth16 proof of the wrong statement. The `h1`/`h3`
cross-check cannot catch it -- that inspects the formatter's output, which was correct; only the
witness is stale. Every verifier rejects the proof, so an honest node is judged `incorrect` with
nothing in its logs to explain why.

Found by the first joined run (`test_real_e2e.py`), where a misconfigured variant produced
exactly this: a real 134-byte proof, three independent `incorrect` verdicts, and no error
anywhere on the prover.

**Status:** Fixed. `_prove_real()` deletes the witness before invoking Java and raises if it does
not reappear, naming the baked-path mismatch as a likely cause. `test_real_e2e.py` additionally
preflights the compiled class against the configured variant.

**Impact:** No false ACCEPT. Same shape as #15 -- an availability and reputation failure, silent
on the prover side. This is the third instance of the same underlying hazard: a fixed working
directory plus a step that can fail without saying so.

**Related:** #12 (the one-time compile), #15 (stale digests), #18 (concurrent attestations). All
four are the fixed-working-directory design; per-attestation directories would close the class.

---

*Compiled from live testing on the 3-node (later expanded to 6-node, 2-Jetson) deployment (`192.168.20.30` / `192.168.20.26`), August 2026.*
