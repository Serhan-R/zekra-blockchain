# Running ZEKRA attestation on the Jetsons

How to go from the current 6-node deployment (`192.168.20.30` / `192.168.20.26`, ports
5000–5002) to one that answers real challenges with real zk-SNARK proofs.

The blockchain side you already know. This covers only what ZEKRA adds: a one-time build, a
one-time per-program setup, the environment each node needs, and the run itself.

For the ZEKRA toolchain itself, `ZEKRA/RUNNING.md` is the reference — it already has the Jetson
notes (including the angr version pin). This document assumes you have followed it.

---

## 0. Read this first — the binaries do not transfer

`run_prover_raw` and friends in `ZEKRA/jsnark/libsnark/build/` are **x86-64 ELF**, built under
WSL. The Jetsons are **aarch64**. Copying them over will fail with `cannot execute binary file`.

```bash
uname -m          # on the Jetson: expect aarch64
```

libsnark must be **built on the Jetson**, which `ZEKRA/setup.sh` does. Budget real time for it;
it is a long compile on a Jetson.

The same applies to nothing else: the Python, the materials, the digests and the reference JSON
are all portable. It is only the compiled binaries.

**Keys are a question mark.** `proving_key_raw.bin` and `verification_key.bin` are serialised
field elements. Both architectures are little-endian so they *should* load fine cross-machine,
but I have not tested it. Safest is to run `run_keygen_raw` on a Jetson. If you want to reuse
the keys you already generated under WSL, verify first: copy them over, run `run_verifier_only`
against an existing proof, and confirm you still get `ACCEPTED` before trusting them.

---

## 1. One-time, on each Jetson

```bash
# ZEKRA toolchain (see ZEKRA/RUNNING.md §1 — this builds libsnark for aarch64)
cd ~/ZEKRA && ./setup.sh

# the JDK is only needed on nodes that will PROVE, but installing it everywhere
# costs nothing and saves a surprise later
sudo apt-get install -y default-jdk

# blockchain deps
pip3 install flask requests cryptography psutil
```

Confirm the toolchain works before going further:

```bash
cd ~/ZEKRA
./jsnark/libsnark/build/libsnark/jsnark_interface/run_verifier_only    # prints usage
javac -version                                                        # not just java
```

`javac`, not `java`. A JRE is not enough — see §2.

---

## 2. One-time per program (do this ONCE, on one machine)

This is the step with the most ways to go wrong, because **`compile_circuit.py` bakes the input
and output directory paths into the Java source**. The circuit is compiled against fixed
directories, and every attestation afterwards rewrites its inputs into those same directories
and re-runs the already-compiled class. Pick the paths now and do not move them.

### 2a. Pick a working directory and compile the circuit

```bash
cd ~/ZEKRA
APP=embench-iot-applications/crc32
WORK=~/zekra_work
mkdir -p $WORK/inputs $WORK/out

# format once to learn the circuit parameters (read the "Considering:" line)
python3 scripts/circuit_input_formatter.py -a $APP \
    --pad-adjlist-to 128 --pad-path-to 192 --output-dir $WORK/inputs
```

Note the reported `ADJLIST_LEVELS`, `LABEL_BITWIDTH`, `BUCKET_BITWIDTH`, `ADDR_BITWIDTH`, then:

```bash
python3 scripts/compile_circuit.py --zekra-dir ./zekra_java/zekra \
    --adjlist-len 128 --adjlist-levels 2 --path-len 192 --stack-depth 8 \
    --label-bitwidth 8 --bucket-bitwidth 5 --address-bitwidth 23 \
    --input-dir $WORK/inputs --output-dir $WORK/out
```

Expect `Successfully compiled the ZEKRA circuit.` If it says **"Circuit was not satisfied with
the inputs"**, the input directory was empty or held inputs for different parameters — format
into `$WORK/inputs` first, then recompile.

> **Consider pruning.** Pruned crc32 is 26,140 constraints and proves in **3.5 s**; unpruned is
> 141,677 and takes **17.2 s**. Since proving currently blocks the node's request handler
> (`ISSUES.md` #16), that difference is worth having. To prune: run `scripts/prune_cfg.py -a $APP`
> (leave `--mode bidir`, the default — see the plan §6 for why the mode matters), add `--pruned`
> to the formatter, and set `circuit.pruned` in the reference (§2c).

### 2b. Generate the keys

```bash
cd ~/ZEKRA
B=./jsnark/libsnark/build/libsnark/jsnark_interface
mkdir -p $WORK/keys $WORK/meta          # run_keygen_raw does NOT create its output dir
$B/run_keygen_raw gg $WORK/out/zekra.arith $WORK/keys
$B/run_setup_serializer $WORK/out/zekra.arith $WORK/meta
```

### 2c. Build and publish the signed reference

The authority key should live on **one** machine — whoever is entitled to define what a program
is. Anyone holding it can register a CFG of their choosing.

```bash
cd ~/blockchain-python-project

# once ever
python3 zekra_authority.py keygen --key authority.pem
# prints ZEKRA_AUTHORITY_PUBKEY=... — every node needs this value

# per program
python3 zekra_authority.py build --key authority.pem --program-id crc32 \
    --from-inputs $WORK/inputs --vk $WORK/keys/verification_key.bin \
    --adjlist-len 128 --adjlist-levels 2 --path-len 192 --stack-depth 8 \
    --label-bitwidth 8 --bucket-bitwidth 5 --address-bitwidth 23 \
    --out reference_crc32.json          # add --pruned if you pruned in 2a

# publish to any node; it gossips like any transaction
python3 zekra_authority.py publish --reference reference_crc32.json \
    --node http://192.168.20.30:5000
```

**It must be mined before any node will use it.** An unmined reference has not been agreed by
anyone.

### 2d. Lay out the program materials on prover nodes

Only nodes that may be *challenged* need these. Verifiers need nothing — the reference carries
the verification key, and the CFG stays behind its hash.

```
~/zekra_programs/
└── crc32/                       # directory name == program_id
    ├── adjlist
    ├── numified_adjlist
    ├── numified_path
    ├── recorded_path
    ├── translator
    └── blinding.json            # {"r1_adjlist": "...", "r3_translator": "..."}
```

`blinding.json` holds the **same** `r1`/`r3` the authority used when it derived `h₁`/`h₃`. Get
them from the formatter run in 2a (`in_nonce_adjlist`, `in_nonce_translator`), or set them
deliberately and pass `--nonce-adjlist` / `--nonce-translator` when building the reference.
If they disagree, the prover recomputes `h₁`/`h₃`, sees the mismatch, and refuses — which is the
correct behaviour but looks like "the prover just won't answer".

Both must be **under 254 bits** (`ISSUES.md` #15).

---

## 3. Environment per node

`launch.py` starts nodes with `subprocess.Popen(..., shell=True)`, which inherits the
environment — so exporting these before launching is enough.

### Every node (provers and verifiers alike)

```bash
export ZEKRA_VERIFIER_MODE=real
export ZEKRA_VERIFIER_BIN=~/ZEKRA/jsnark/libsnark/build/libsnark/jsnark_interface/run_verifier_only
export ZEKRA_AUTHORITY_PUBKEY=<the hex printed by zekra_authority.py keygen>
export ZEKRA_KEY_FILE=~/blockchain-python-project/node_$PORT.pem
```

`ZEKRA_KEY_FILE` must be **per node** — it is that node's identity. Two nodes sharing a key file
is two nodes claiming to be the same prover.

Note there is no `ZEKRA_VERIFICATION_KEY`. Verifiers take the key from the signed reference.

### Prover nodes only

```bash
export ZEKRA_PROGRAM_DIR=~/zekra_programs
export ZEKRA_FORMATTER=~/ZEKRA/scripts/circuit_input_formatter.py
export ZEKRA_CIRCUIT_INPUT_DIR=$WORK/inputs        # MUST match what 2a compiled against
export ZEKRA_CIRCUIT_OUTPUT_DIR=$WORK/out          # likewise
export ZEKRA_JAVA_CP=~/ZEKRA/bin:~/ZEKRA/xjsnark_backend.jar
export ZEKRA_JAVA_CLASS=xjsnark.zekra.zekra
export ZEKRA_JAVA_DIR=~/ZEKRA                      # cwd for the java run
export ZEKRA_PROVER_BIN=~/ZEKRA/jsnark/libsnark/build/libsnark/jsnark_interface/run_prover_raw
export ZEKRA_ARITH=$WORK/out/zekra.arith
export ZEKRA_PROVING_KEY=$WORK/keys/proving_key_raw.bin
export ZEKRA_CIRCUIT_METADATA=$WORK/meta/circuit_metadata.bin
```

The two directory variables are the ones to get right. If they do not match the paths compiled
into the class in 2a, Java writes its witness somewhere else and the node refuses with a message
naming exactly that cause (`ISSUES.md` #19).

---

## 4. Run it

```bash
# on each Jetson, with the exports above in the shell
python3 launch.py                       # or your usual launcher
python3 control_panel.py                # registers the mesh across both Jetsons
```

Check every node agrees on its configuration before challenging anything:

```bash
for n in 192.168.20.30 192.168.20.26; do
  for p in 5000 5001 5002; do
    echo -n "$n:$p  "
    curl -s http://$n:$p/zekra/status | python3 -m json.tool | \
      grep -E '"mode"|verifier_binary_present|provable_programs' | tr '\n' ' '
    echo
  done
done
```

Every node should show `"mode": "real"` and `verifier_binary_present: true`. Only your designated
prover(s) should list anything under `provable_programs` — if a verifier lists a program, it has
materials it should not have.

Then: publish the reference (§2c) → mine → issue a challenge → mine → wait → mine again.

A challenge is an ordinary request transaction:

```json
{ "sender": "<challenger node_id>", "recipient": "<prover node_id>",
  "transaction_type": "request", "function_name": "zekra_attestation",
  "program_id": "crc32", "function_parameter": 7311220001 }
```

The nonce must be fresh, never used on this chain before, and **under 254 bits**.

---

## 5. What success looks like

- the prover answers within roughly 4 s (pruned) or 20 s (unpruned)
- its response carries `proof_b64` of **180 base64 characters** — a real 134-byte Groth16 proof.
  32 bytes means you are still in mock mode
- once mined, every node that is neither the challenger nor the responder publishes a
  `verification` transaction with `function_parameter: "correct"`
- on six nodes that is **four** independent verdicts

Verify locally first if you can. `test_real_e2e.py` runs exactly this flow on five local nodes
and takes under a minute; getting it green on one Jetson before going distributed will save time.

```bash
ZK_JAVA=$WORK python3 test_real_e2e.py
```

---

## 6. When it does not work

| Symptom | Cause |
|---|---|
| `cannot execute binary file` | x86 binaries on ARM — rebuild libsnark on the Jetson (§0) |
| prover never answers, no error | check its log; almost always a path in §3 |
| `no witness at ...` | `ZEKRA_CIRCUIT_*_DIR` does not match what the class was compiled against |
| `our materials produce h1=... but the signed reference says ...` | wrong `blinding.json`, wrong CFG variant, or wrong circuit parameters |
| `the formatter exited cleanly but wrote no digests` | a nonce ≥ 254 bits — the challenge nonce or a blinding factor |
| every node ABSTAINs | reference not mined yet, or `ZEKRA_AUTHORITY_PUBKEY` not matching the signer |
| verdicts say `incorrect` for an honest run | prover and reference disagree — compare `curl /zekra/status` across nodes |
| `javac: command not found` | JRE only; the one-time compile needs a JDK |

The node logs are the first place to look — every refusal above is logged with the reason.

---

## 7. Known limits at this scale

From `ISSUES.md`, the ones that matter once this is live:

- **#16** — proving blocks the request handler for 3.5–17 s. Pruning helps; moving proving off
  the request path is the fix.
- **#17** — no inter-node call sets a timeout. A prover that dies mid-proof leaves its peers
  waiting indefinitely. Worth adding a timeout before running unattended.
- **#18** — one working directory per node, so two concurrent challenges to the same node would
  collide. Keep to one challenge at a time per prover.
- **#11** — any node holding materials can attest; nothing checks it was authorised. Distribution
  discipline is the only control today.
