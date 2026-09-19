#!/usr/bin/env python3
"""
zekra_round_driver_jetson20_prover.py

Variant of zekra_round_driver.py for a single-prover topology: every one of
jetson19's and jetson18's 10 node processes acts as a SENDER (challenger) at
some point, but jetson20's 5 node processes NEVER send a challenge -- they
only ever appear as the RECIPIENT (prover) of a round.

This is otherwise byte-for-byte the same driver: same six-step protocol per
round (see below, unchanged from zekra_round_driver.py), same CSV schema,
same count_verdicts handling, same timing fields. The ONLY thing that changes
is which nodes are eligible to be picked as sender vs. recipient for each
round.

Recipient assignment: sender i (0-indexed across the 10 non-jetson20 nodes)
is paired with jetson20 port (i % 5) -- i.e. round-robin across jetson20's 5
processes, so proving load is spread evenly across all of jetson20's node
processes rather than hammering a single one.

Protocol per round (identical to zekra_round_driver.py -- reproduced here so
this file is self-contained):

    1. POST the ZEKRA request transaction to the SENDER node's own
       /transactions/new. This appends it to the sender's pool, logs
       'request_initiated' on the sender, and broadcasts the pool to every
       registered peer (Blockchain.new_transaction -> notify_transaction_pool_update),
       so every node -- including the recipient -- already has it pending.
       No manual propagation step needed.

    2. GET /mine on the RECIPIENT node (always one of jetson20's 5 processes
       here). Blockchain.new_block() sweeps its pool (now containing the
       request) into a block and broadcasts the new chain to every peer
       (notify_neighbors -> /notify_change). /mine's own handler then calls
       check_and_execute_requests() locally, which -- because this node IS
       the request's recipient -- immediately builds the ZEKRA proof and
       POSTs a 'response' transaction straight back to the sender's
       /transactions/new (again auto-broadcast to every peer).

    3. Poll the SENDER's own /transaction_pool until a 'response' transaction
       with parent == our precomputed request_hash appears (proof generation
       can take up to ~25s for the largest circuits, live -- poll, don't
       assume a fixed delay).

    4. GET /mine on the SENDER node. This seals the response into a block and
       broadcasts it; every peer's /notify_change handler adopts the new
       chain via resolve_conflicts(), which -- as a side effect of checking
       the chain's validity -- runs validate_response_transaction() and so
       independently verifies the proof and POSTs its own 'verification'
       transaction back to the sender. The miner (the sender, here) also
       verifies its own freshly-mined block via verify_mined_block(). So
       this single /mine call is what fans out into every peer's vote --
       no further manual steps.

    5. Poll the SENDER's /transaction_pool until verification transactions
       for this request stop accumulating (or a timeout elapses), then GET
       /mine on the SENDER once more to seal the final majority-decision
       block.

    6. GET /count_verdicts on the SENDER -- same node, right after step 5's
       mine, so there's no propagation delay to wait out.

Run this ON THE LAN (e.g. from jetson20 itself, 192.168.20.34) -- it needs to
reach all three boards on 192.168.20.0/24 directly; this won't work from
anywhere without a route to that subnet.

Usage:
    python3 zekra_round_driver_jetson20_prover.py --apps edn --reps 1 --dry-run
    python3 zekra_round_driver_jetson20_prover.py --apps crc32,nbody,aha-mont64,edn,ud --reps 1
"""
import argparse
import csv
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
from urllib.parse import urlparse

import requests

# Every row written to --out has exactly these columns, regardless of whether
# the round completed -- fixed up front rather than inferred from the first
# result's keys, since an incomplete round's dict has far fewer keys than a
# complete one's, and csv.DictWriter errors on a later row carrying a key the
# first row didn't have.
CSV_FIELDNAMES = [
    "app", "sender_ip", "sender_port", "sender_hash",
    "recipient_ip", "recipient_port", "recipient_hash",
    "request_hash", "complete",
    "driver_t0", "driver_response_wait_s", "driver_verify_wait_s",
    "driver_verify_settle_margin_s", "driver_total_wall_s",
    "n_verifications",
    "count_verdicts_message", "count_verdicts_correct", "count_verdicts_incorrect",
    "count_verdicts_server_ms", "count_verdicts_driver_wall_s", "count_verdicts_error",
]

# Full mesh topology -- kept identical to zekra_round_driver.py's NODES list
# (same IPs/ports/hashes) so preflight() still checks every process on all
# three boards, including jetson20's, which still need to be reachable since
# they're the recipients here.
NODES = [
    {"ip": "192.168.20.34", "port": 5000, "hash": "358eb2e0e8c54bea96e80af82a78de2c"},
    {"ip": "192.168.20.34", "port": 5001, "hash": "6f5d9e3badc34645bdf4a756418d1cc2"},
    {"ip": "192.168.20.34", "port": 5002, "hash": "185d006d04744d88a18bca03f01c4b28"},
    {"ip": "192.168.20.34", "port": 5003, "hash": "589f220099a441ef9fa57adda6c851e3"},
    {"ip": "192.168.20.34", "port": 5004, "hash": "9e9250509e03450295dedf6ff7278b60"},
    {"ip": "192.168.20.30", "port": 5000, "hash": "9fc6f551c53f4e73ac8d8cdb6f996249"},
    {"ip": "192.168.20.30", "port": 5001, "hash": "05a2f61e81bf40dc85abbd1fb414702a"},
    {"ip": "192.168.20.30", "port": 5002, "hash": "ef81bb411be04ff681350d88547dbebd"},
    {"ip": "192.168.20.30", "port": 5003, "hash": "3c0fdeb417234d6fb33be0324d5efd9f"},
    {"ip": "192.168.20.30", "port": 5004, "hash": "63e3244c99424720a55c2cc535659675"},
    {"ip": "192.168.20.29", "port": 5000, "hash": "bfc940daa9a64416b0af83aab4b87ef8"},
    {"ip": "192.168.20.29", "port": 5001, "hash": "a2a53dc0154f4099824c6f2606b0e604"},
    {"ip": "192.168.20.29", "port": 5002, "hash": "fe070da273eb451799214a52420c6b06"},
    {"ip": "192.168.20.29", "port": 5003, "hash": "46f97fde58a54f94ac86c3b740d7a764"},
    {"ip": "192.168.20.29", "port": 5004, "hash": "ed10bf4e7d18484d9544c66bdf84d859"},
]

# jetson20's own address -- the ONLY board whose processes act as prover here.
JETSON20_IP = "192.168.20.34"

# Senders: every node NOT on jetson20 (jetson19's + jetson18's 10 processes).
# Provers: jetson20's own 5 processes -- these NEVER appear as a sender below.
SENDER_NODES = [n for n in NODES if n["ip"] != JETSON20_IP]
PROVER_NODES = [n for n in NODES if n["ip"] == JETSON20_IP]

ZEKRA_FUNCTION_NAME = "zekra_attestation"


def url(node):
    return f"http://{node['ip']}:{node['port']}"


def parse_node_url(url_str):
    """'http://192.168.20.34:5000' -> {'ip': '192.168.20.34', 'port': 5000},
    good enough to pass to url()/mine() -- those only need ip/port."""
    parsed = urlparse(url_str)
    if not parsed.hostname or not parsed.port:
        raise ValueError(f"not a valid http://host:port URL: {url_str!r}")
    return {"ip": parsed.hostname, "port": parsed.port}


def compute_request_hash(sender_hash, recipient_hash, program_id, nonce):
    """
    Mirrors Blockchain.new_transaction()'s own hash computation exactly (same
    keys, same int-cast on function_parameter, sort_keys=True so field order
    doesn't matter), so we know the request_hash BEFORE submitting it --
    /transactions/new's response doesn't return it, and this way we don't
    have to guess it out of a later /chain poll either.
    """
    tx = {
        "sender": sender_hash,
        "recipient": recipient_hash,
        "transaction_type": "request",
        "function_name": ZEKRA_FUNCTION_NAME,
        "function_parameter": int(nonce),
        "program_id": program_id,
    }
    return hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest()


def preflight(nodes):
    print("Preflight: checking all nodes are reachable...")
    ok = True
    for n in nodes:
        try:
            r = requests.get(f"{url(n)}/id", timeout=5)
            if r.status_code != 200 or r.json().get("node_id") != n["hash"]:
                print(f"  [FAIL] {n['ip']}:{n['port']} -- unexpected response: {r.text[:200]}")
                ok = False
            else:
                print(f"  [ok]   {n['ip']}:{n['port']} ({n['hash'][:8]}...)")
        except requests.RequestException as e:
            print(f"  [FAIL] {n['ip']}:{n['port']} -- {e}")
            ok = False
    if not ok:
        print("\nAborting -- fix unreachable/mismatched nodes before running a batch.")
        sys.exit(1)
    print(f"All {len(nodes)} nodes reachable.\n")


def submit_request(sender, recipient, program_id):
    nonce = secrets.randbelow(2**253)
    request_hash = compute_request_hash(sender["hash"], recipient["hash"], program_id, nonce)
    payload = {
        "sender": sender["hash"],
        "recipient": recipient["hash"],
        "transaction_type": "request",
        "function_name": ZEKRA_FUNCTION_NAME,
        "function_parameter": nonce,
        "program_id": program_id,
    }
    r = requests.post(f"{url(sender)}/transactions/new", json=payload, timeout=10)
    r.raise_for_status()
    return request_hash


def mine(node, label):
    r = requests.get(f"{url(node)}/mine", timeout=60)
    r.raise_for_status()
    data = r.json()
    print(f"    mine({label} = {node['ip']}:{node['port']}) -> "
          f"{data.get('message')} ({len(data.get('transactions', []))} tx)")
    return data


def pool_of(node):
    r = requests.get(f"{url(node)}/transaction_pool", timeout=10)
    r.raise_for_status()
    return r.json().get("transaction_pool", [])


def count_verdicts(node, timeout_s):
    r = requests.get(f"{url(node)}/count_verdicts", timeout=timeout_s)
    r.raise_for_status()
    return r.json()


def zekra_status(node, timeout_s=10):
    r = requests.get(f"{url(node)}/zekra/status", timeout=timeout_s)
    r.raise_for_status()
    return r.json()


def reset_chain(node, timeout_s=30):
    """POST /reset_chain -- wipes THIS node's chain+pool back to a fresh
    genesis block (see the route's docstring in FlaskBlockChain.py). Only
    exists on boards running the updated FlaskBlockChain.py -- a 404 here
    means that hasn't been deployed/restarted yet."""
    r = requests.post(f"{url(node)}/reset_chain", timeout=timeout_s)
    r.raise_for_status()
    return r.json()


def reset_chain_all(nodes):
    """Reset EVERY node in `nodes` -- including jetson20's own 5 processes,
    even though they never send. A chain reset must be applied to the whole
    mesh at once: if even one peer is left un-reset, its still-long chain
    gets pulled back into a freshly-reset node the next time any
    /notify_change fires (resolve_conflicts() adopts whichever valid chain is
    longer), silently undoing the reset. Aborts the whole run on any failure
    rather than continuing with a partially-reset, inconsistent mesh."""
    print(f"Resetting chain on all {len(nodes)} node(s)...")
    failed = []
    for n in nodes:
        try:
            data = reset_chain(n)
            print(f"  [ok]   {n['ip']}:{n['port']} -> {data.get('message')} "
                  f"(length={data.get('length')})")
        except requests.RequestException as e:
            print(f"  [FAIL] {n['ip']}:{n['port']} -- {e}")
            failed.append(n)
    if failed:
        print(f"\n[FATAL] chain reset failed on {len(failed)} node(s): "
              + ", ".join(f"{n['ip']}:{n['port']}" for n in failed))
        print("A partial reset is worse than no reset -- the un-reset node(s) above still "
              "hold a long chain that will get pulled back into the reset nodes on the next "
              "/notify_change, silently undoing it. Most likely cause: /reset_chain isn't "
              "deployed/running there yet (needs the updated FlaskBlockChain.py + a node "
              "restart). Fix that and re-run rather than continuing.")
        sys.exit(1)
    print(f"All {len(nodes)} node(s) reset to a fresh genesis block.\n")


def republish_reference(app, authority_script, reference_dir, publish_node_url, timeout_s=60):
    """Re-publish the already-built reference_<app>.json onto the (now fresh)
    chain, via a LOCAL subprocess call to 'python3 zekra_authority.py
    publish' -- mirrors zekra_onboard.ps1's own Step 7 exactly. This does NOT
    re-build the reference (no authority key needed here): the JSON was
    already minted once during onboarding and survives on disk; only its
    ON-CHAIN record was lost by the reset.

    authority_script and reference_dir are independent, absolute paths (NOT
    a single shared directory + cwd) -- zekra_authority.py and the
    reference_<app>.json files do not necessarily live in the same folder
    (on jetson20 they don't: the script lives under ~/ZEKRA_S/zekra-blockchain/
    while the reference JSONs sit directly in ~). Both are invoked/read by
    absolute path, so no cwd assumption is needed either way.

    Only meaningful if this driver is running somewhere that actually has
    both locally -- i.e. jetson20. Aborts the whole run on failure:
    continuing to run an app's rounds with no reference on-chain would just
    produce a pile of confusing timeouts instead of one clear error here.
    """
    ref_path = os.path.join(reference_dir, f"reference_{app}.json")
    cmd = [sys.executable, authority_script, "publish",
           "--reference", ref_path, "--node", publish_node_url]
    print(f"  $ {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        print(f"[FATAL] zekra_authority.py publish timed out after {timeout_s}s for {app!r}")
        sys.exit(1)
    except OSError as e:
        print(f"[FATAL] could not run {authority_script!r} for {app!r}: {e}")
        sys.exit(1)
    if r.stdout:
        print("    " + r.stdout.rstrip().replace("\n", "\n    "))
    if r.returncode != 0:
        print(f"[FATAL] zekra_authority.py publish failed (exit {r.returncode}) for {app!r}")
        if r.stderr:
            print("    " + r.stderr.rstrip().replace("\n", "\n    "))
        print(f"Check that {ref_path} exists, {authority_script} exists, and that "
              f"--publish-node ({publish_node_url}) is reachable.")
        sys.exit(1)


def wait_for_reference_on_chain(nodes, program_id, timeout_s, poll_s=1.0):
    """Poll /zekra/status on every node in `nodes` until each reports
    program_id in its references_on_chain list, or timeout_s elapses.
    :return: list of nodes that never confirmed (empty on full success)."""
    deadline = time.time() + timeout_s
    pending = list(nodes)
    while True:
        still_pending = []
        for n in pending:
            try:
                status = zekra_status(n)
            except requests.RequestException:
                still_pending.append(n)
                continue
            if program_id not in (status.get("references_on_chain") or []):
                still_pending.append(n)
        pending = still_pending
        if not pending or time.time() >= deadline:
            return pending
        time.sleep(poll_s)


def parse_time_taken_ms(time_taken_str):
    """count_verdicts reports its own server-side timing as a free-text
    string -- "12.345 ms" when under a second, "0.4 second" (singular, even
    for >1) otherwise. Parse either shape into a float number of ms, or None
    if the field is missing (the endpoint omits it entirely on the
    'no verification transactions found' early-return) or unrecognized."""
    if not time_taken_str:
        return None
    m = re.match(r"^\s*([\d.]+)\s*ms\s*$", time_taken_str)
    if m:
        return float(m.group(1))
    m = re.match(r"^\s*([\d.]+)\s*second", time_taken_str)
    if m:
        return float(m.group(1)) * 1000.0
    return None


def parse_verdict_counts(message):
    """Best-effort parse of count_verdicts' free-text 'message' into
    (correct, incorrect) ints. Returns (None, None) for the two message
    shapes that carry no counts at all: 'No verification transactions found
    in the blockchain.' (nothing mined yet with any verification tx) and
    'No verdicts found in the latest verification block.' (found a block,
    but its verification tx carried neither 'correct' nor 'incorrect' as
    function_parameter -- shouldn't happen for a real round, but the route
    allows for it)."""
    if not message:
        return None, None
    m = re.search(r"Total:\s*(\d+)", message)
    if m and "All verdicts are correct" in message:
        return int(m.group(1)), 0
    m = re.search(r"Correct:\s*(\d+),\s*Incorrect:\s*(\d+)", message)
    if m:
        return int(m.group(1)), int(m.group(2))
    return None, None


def wait_for_response(sender, request_hash, timeout_s, poll_s=0.25):
    """poll_s defaults tighter than you might expect (0.25s, not 1s):
    whatever we observe here is stamped as t_response and feeds directly into
    driver_response_wait_s, so every second of poll_s is up to a second of
    pure polling lag riding along in that number. There's no fixed dead-time
    to strip out here the way there is in wait_for_verifications_to_settle
    (see its docstring) -- this is just detection jitter, and tightening the
    poll interval is the only lever for it. For a bias-free number, prefer
    the JSONL-derived response_received timestamp (logged the instant the
    HTTP POST lands, zero polling involved) via zekra_timing_report.py."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        pool = pool_of(sender)
        for tx in pool:
            if tx.get("transaction_type") == "response" and tx.get("parent") == request_hash:
                return True
        time.sleep(poll_s)
    return False


def wait_for_verifications_to_settle(sender, request_hash, max_wait_s, quiet_s=3.0, poll_s=0.25):
    """Poll until the number of pending verification tx for this round stops
    growing for `quiet_s` seconds, or max_wait_s elapses -- whichever first.

    Returns (count, last_change) rather than just count. We deliberately keep
    polling for a full quiet_s of silence before returning -- that's an
    operational safety margin, needed so a late-arriving vote isn't missed --
    but that margin is NOT part of how long verification actually took, so it
    must not leak into the reported timing. last_change is the timestamp of
    the last observed count increase, i.e. the moment verification actually
    settled; callers should measure elapsed time against last_change, not
    against when this function returns (which is last_change + quiet_s, plus
    whatever polling lag). See run_round()'s driver_verify_wait_s."""
    deadline = time.time() + max_wait_s
    last_count = -1
    last_change = time.time()
    while time.time() < deadline:
        pool = pool_of(sender)
        count = sum(1 for tx in pool
                    if tx.get("transaction_type") == "verification" and tx.get("parent") == request_hash)
        if count != last_count:
            last_count = count
            last_change = time.time()
        if count > 0 and (time.time() - last_change) >= quiet_s:
            return count, last_change
        time.sleep(poll_s)
    return last_count, last_change


def run_round(app, sender, recipient, response_timeout, verify_timeout, count_verdicts_timeout, dry_run):
    print(f"  [{app}] sender={sender['ip']}:{sender['port']} -> "
          f"recipient={recipient['ip']}:{recipient['port']}")
    if dry_run:
        print("    (dry-run, skipping)")
        return None

    t0 = time.time()
    request_hash = submit_request(sender, recipient, app)
    print(f"    request_hash={request_hash}")

    mine(recipient, "recipient")
    if not wait_for_response(sender, request_hash, response_timeout):
        print(f"    [WARN] no response seen within {response_timeout}s -- skipping rest of round")
        return {"app": app, "request_hash": request_hash, "complete": False}

    t_response = time.time()
    mine(sender, "sender")
    n_verified, t_verified = wait_for_verifications_to_settle(sender, request_hash, verify_timeout)
    t_verify_loop_end = time.time()
    mine(sender, "sender (final)")
    t_final = time.time()

    # t_verified is when the vote count actually last changed -- the real
    # settle instant. wait_for_verifications_to_settle() waits an ADDITIONAL
    # quiet_s (default 3s) of silence after that before returning, purely as
    # an operational safety margin against a late vote, plus whatever polling
    # lag it picked up along the way -- neither of those is verification
    # work, so driver_verify_wait_s below is measured against t_verified, not
    # against when that call returned. The discarded margin is reported
    # separately (driver_verify_settle_margin_s) so it's visible rather than
    # silently dropped.
    settle_margin_s = t_verify_loop_end - t_verified

    print(f"    done: response +{t_response-t0:.1f}s, "
          f"{n_verified} verification(s) +{t_verified-t_response:.1f}s "
          f"(settle margin {settle_margin_s:.1f}s discarded), "
          f"total driver-observed wall time {t_final-t0:.1f}s")

    # count_verdicts on the sender -- it already has the just-sealed final
    # block locally, no propagation wait needed. Read-only, so a failure here
    # is logged but never aborts the round -- the actual attestation result
    # above is already captured.
    t_count_start = time.time()
    cv_message = cv_correct = cv_incorrect = cv_server_ms = cv_error = None
    try:
        cv = count_verdicts(sender, count_verdicts_timeout)
        cv_message = cv.get("message")
        cv_correct, cv_incorrect = parse_verdict_counts(cv_message)
        cv_server_ms = parse_time_taken_ms(cv.get("time_taken_seconds"))
    except requests.RequestException as e:
        cv_error = str(e)
    cv_driver_wall_s = round(time.time() - t_count_start, 4)

    print(f"    count_verdicts(sender) -> {cv_message!r} "
          f"(server {cv_server_ms} ms, driver round-trip {cv_driver_wall_s*1000:.1f} ms)"
          + (f" [ERROR: {cv_error}]" if cv_error else ""))
    if cv_correct is not None and (cv_correct + cv_incorrect) != n_verified:
        print(f"    [WARN] count_verdicts tallied {cv_correct + cv_incorrect} vote(s) "
              f"but the driver saw {n_verified} settle before mining -- a vote likely "
              f"landed in the pool between the settle-check and the final mine")

    return {
        "app": app,
        "sender_ip": sender["ip"], "sender_port": sender["port"], "sender_hash": sender["hash"],
        "recipient_ip": recipient["ip"], "recipient_port": recipient["port"], "recipient_hash": recipient["hash"],
        "request_hash": request_hash,
        "complete": True,
        "driver_t0": t0,
        "driver_response_wait_s": round(t_response - t0, 3),
        "driver_verify_wait_s": round(t_verified - t_response, 3),
        "driver_verify_settle_margin_s": round(settle_margin_s, 3),
        "driver_total_wall_s": round(t_final - t0, 3),
        "n_verifications": n_verified,
        "count_verdicts_message": cv_message,
        "count_verdicts_correct": cv_correct,
        "count_verdicts_incorrect": cv_incorrect,
        "count_verdicts_server_ms": cv_server_ms,
        "count_verdicts_driver_wall_s": cv_driver_wall_s,
        "count_verdicts_error": cv_error,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apps", required=True,
                     help="comma-separated program_ids, e.g. crc32,nbody,aha-mont64,edn,ud")
    ap.add_argument("--reps", type=int, default=1,
                     help="number of full sender sweeps per app (reps=1 -> every jetson18/jetson19 "
                          "node initiates once per app; jetson20 never initiates)")
    ap.add_argument("--response-timeout", type=float, default=120.0,
                     help="max seconds to wait for the prover's response per round")
    ap.add_argument("--verify-timeout", type=float, default=30.0,
                     help="max seconds to wait for verification votes to settle")
    ap.add_argument("--count-verdicts-timeout", type=float, default=15.0,
                     help="max seconds to wait for the post-round /count_verdicts call")
    ap.add_argument("--settle-between-rounds", type=float, default=3.0,
                     help="seconds to pause between rounds so pools/logs settle")
    ap.add_argument("--out", default="zekra_round_manifest_jetson20_prover.csv")
    ap.add_argument("--dry-run", action="store_true", help="print the planned rounds without executing them")
    ap.add_argument("--limit", type=int, default=None,
                     help="stop after this many rounds (use for a quick single-round sanity check)")
    ap.add_argument("--reset-chain-between-apps", action="store_true",
                     help="wipe every node's chain (including jetson20's) to a fresh genesis "
                          "block after each app's rounds finish, then re-publish + re-mine the "
                          "NEXT app's reference onto the fresh chain before continuing -- gets "
                          "each app a zero-length chain for its timing sweep instead of "
                          "accumulating every prior app's rounds/references on one "
                          "ever-growing chain. Requires the /reset_chain route "
                          "(FlaskBlockChain.py) deployed and running on every node (restart "
                          "all node processes after deploying it), and this driver to run "
                          "somewhere that can locally invoke 'python3 zekra_authority.py "
                          "publish' (see --authority-script and --reference-dir) -- e.g. on "
                          "jetson20 itself, where those actually live. NOTE: does NOT reset "
                          "before the FIRST app -- that app runs against whatever chain state "
                          "already exists when you start this script, exactly like today.")
    ap.add_argument("--authority-script", default="~/ZEKRA_S/zekra-blockchain/zekra_authority.py",
                     help="path (on the machine running this driver) to zekra_authority.py -- "
                          "only used with --reset-chain-between-apps")
    ap.add_argument("--reference-dir", default="~",
                     help="directory (on the machine running this driver) containing the "
                          "reference_<app>.json files -- NOT necessarily the same directory as "
                          "--authority-script (e.g. on jetson20 the script lives under "
                          "~/ZEKRA_S/zekra-blockchain/ but the reference JSONs sit directly in "
                          "~) -- only used with --reset-chain-between-apps")
    ap.add_argument("--publish-node", default="http://192.168.20.34:5000",
                     help="node URL to publish + mine the next app's reference to after a "
                          "reset -- only used with --reset-chain-between-apps")
    ap.add_argument("--reset-settle", type=float, default=10.0,
                     help="seconds to pause after a reset+republish before the next app's "
                          "rounds start, letting the reseal propagate -- only used with "
                          "--reset-chain-between-apps")
    ap.add_argument("--reference-verify-timeout", type=float, default=30.0,
                     help="max seconds to wait for the republished reference to show up in "
                          "/zekra/status on every node before aborting -- only used with "
                          "--reset-chain-between-apps")
    args = ap.parse_args()

    apps = [a.strip() for a in args.apps.split(",") if a.strip()]
    authority_script = os.path.expanduser(args.authority_script)
    reference_dir = os.path.expanduser(args.reference_dir)
    publish_node = parse_node_url(args.publish_node)

    if not args.dry_run:
        preflight(NODES)

    print(f"Sender pool ({len(SENDER_NODES)} nodes, jetson19 + jetson18): "
          + ", ".join(f"{n['ip']}:{n['port']}" for n in SENDER_NODES))
    print(f"Prover pool ({len(PROVER_NODES)} nodes, jetson20 only -- never a sender): "
          + ", ".join(f"{n['ip']}:{n['port']}" for n in PROVER_NODES) + "\n")

    results = []
    round_num = 0
    total_rounds = len(apps) * args.reps * len(SENDER_NODES)
    print(f"Planning {total_rounds} round(s): {len(apps)} app(s) x {args.reps} sweep(s) x "
          f"{len(SENDER_NODES)} sender node(s) (jetson20 excluded as sender).\n")
    if args.reset_chain_between_apps:
        print(f"--reset-chain-between-apps is ON: chain resets (all {len(NODES)} nodes, "
              f"including jetson20) after each app; references re-published via "
              f"{authority_script} (reference JSONs from {reference_dir}) to "
              f"{args.publish_node} for every app after the first.\n")

    stop = False
    for app_idx, app in enumerate(apps):
        if stop:
            break
        for rep in range(args.reps):
            if stop:
                break
            for i in range(len(SENDER_NODES)):
                if args.limit is not None and round_num >= args.limit:
                    print(f"\n--limit {args.limit} reached, stopping.")
                    stop = True
                    break
                round_num += 1
                sender = SENDER_NODES[i]
                # Round-robin across jetson20's 5 processes so proving load
                # is spread evenly rather than hammering a single one.
                recipient = PROVER_NODES[i % len(PROVER_NODES)]
                print(f"Round {round_num}/{total_rounds} (rep {rep + 1}/{args.reps})")
                result = run_round(app, sender, recipient, args.response_timeout,
                                    args.verify_timeout, args.count_verdicts_timeout, args.dry_run)
                if result:
                    results.append(result)
                if not args.dry_run:
                    time.sleep(args.settle_between_rounds)

        if args.reset_chain_between_apps and not args.dry_run and not stop:
            is_last = (app_idx == len(apps) - 1)
            next_app = apps[app_idx + 1] if not is_last else None
            print(f"\n=== chain reset after '{app}' "
                  + (f"(preparing fresh chain for next app {next_app!r}) ==="
                     if next_app else "(no next app -- final cleanup reset) ==="))
            reset_chain_all(NODES)
            if next_app is not None:
                print(f"Re-publishing + mining reference for {next_app!r} onto the fresh chain...")
                republish_reference(next_app, authority_script, reference_dir, args.publish_node)
                mine(publish_node, "publish-node (reference reseal)")
                missing = wait_for_reference_on_chain(NODES, next_app, args.reference_verify_timeout)
                if missing:
                    print(f"[FATAL] reference for {next_app!r} never showed up on: "
                          + ", ".join(f"{n['ip']}:{n['port']}" for n in missing))
                    print("Rounds for that app would just abstain/timeout from here -- stopping "
                          "instead of producing misleading data.")
                    sys.exit(1)
                print(f"[ok] reference for {next_app!r} confirmed on all {len(NODES)} node(s).")
            time.sleep(args.reset_settle)

    if results:
        with open(args.out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
            w.writeheader()
            for r in results:
                w.writerow(r)
        n_complete = sum(1 for r in results if r.get("complete"))
        print(f"\nWrote {len(results)} round(s) ({n_complete} complete) to {args.out}")
        print("Now copy every board's ~/zekra_timing.jsonl together and rerun "
              "zekra_timing_report.py to get the real per-stage breakdown -- this "
              "manifest is a cross-check (driver-observed wall time, sender/recipient "
              "identity, node coverage), not a replacement for the on-chain timing log.")


if __name__ == "__main__":
    main()
