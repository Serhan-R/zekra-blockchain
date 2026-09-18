#!/usr/bin/env python3
"""
zekra_round_driver.py

Fully automated driver for ZEKRA attestation rounds -- replaces the manual
control_panel.py menu sequence (create transaction -> pick a node -> mine ->
wait -> mine again -> ...) with a scripted, unattended loop, so a round's
measured latency reflects the system's own timing rather than however fast a
human clicked through the menu between steps.

Protocol (reverse-engineered from FlaskBlockChain.py's own control flow --
SANITY-CHECK THIS against your own experience running it manually before
trusting a full batch; I've read the source carefully but never run this
against your live boards):

    1. POST the ZEKRA request transaction to the SENDER node's own
       /transactions/new. This appends it to the sender's pool, logs
       'request_initiated' on the sender, and broadcasts the pool to every
       registered peer (Blockchain.new_transaction -> notify_transaction_pool_update),
       so every node -- including the recipient -- already has it pending.
       No manual propagation step needed.

    2. GET /mine on the RECIPIENT node. Blockchain.new_block() sweeps its
       pool (now containing the request) into a block and broadcasts the new
       chain to every peer (notify_neighbors -> /notify_change). /mine's own
       handler then calls check_and_execute_requests() locally, which --
       because this node IS the request's recipient -- immediately builds
       the ZEKRA proof and POSTs a 'response' transaction straight back to
       the sender's /transactions/new (again auto-broadcast to every peer).

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
       mine, so there's no propagation delay to wait out: the sender already
       has the just-sealed final block in its own in-process chain state.
       This endpoint is read-only (confirmed by reading FlaskBlockChain.py --
       it scans blockchain.chain in reverse for the most recent block holding
       verification transactions and tallies them; it never calls
       new_block()/proof_of_work(), so it doesn't mine anything itself and
       isn't part of the protocol's own correctness, only a post-hoc tally).
       It self-reports its own server-side timing as a string ("12.3 ms" or
       "0.4 second"), which we parse into a numeric ms figure alongside our
       own driver-measured wall-clock round-trip for that one HTTP call.

Each round is driven end to end with no human in the loop, so the timing
this produces isolates the system's own latency from operator reaction time
between manual steps -- which is very likely the biggest source of the
variance you were seeing (on top of the mesh-size confound already found in
the existing logs: some rounds ran on a 2- or 10-node mesh, not the full 15).

Run this ON THE LAN (e.g. from jetson20 itself, 192.168.20.34) -- it needs to
reach all three boards on 192.168.20.0/24 directly; this won't work from
anywhere without a route to that subnet.

Usage:
    python3 zekra_round_driver.py --apps edn --reps 1 --dry-run   # sanity check the plan first
    python3 zekra_round_driver.py --apps crc32,nbody,aha-mont64,edn,ud --reps 1
"""
import argparse
import csv
import hashlib
import json
import re
import secrets
import sys
import time
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
    "driver_t0", "driver_response_wait_s", "driver_verify_wait_s", "driver_total_wall_s",
    "n_verifications",
    "count_verdicts_message", "count_verdicts_correct", "count_verdicts_incorrect",
    "count_verdicts_server_ms", "count_verdicts_driver_wall_s", "count_verdicts_error",
]

# Edit this if the mesh topology changes. One entry per node process.
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

ZEKRA_FUNCTION_NAME = "zekra_attestation"


def url(node):
    return f"http://{node['ip']}:{node['port']}"


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


def wait_for_response(sender, request_hash, timeout_s, poll_s=1.0):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        pool = pool_of(sender)
        for tx in pool:
            if tx.get("transaction_type") == "response" and tx.get("parent") == request_hash:
                return True
        time.sleep(poll_s)
    return False


def wait_for_verifications_to_settle(sender, request_hash, max_wait_s, quiet_s=3.0, poll_s=1.0):
    """Poll until the number of pending verification tx for this round stops
    growing for `quiet_s` seconds, or max_wait_s elapses -- whichever first."""
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
            return count
        time.sleep(poll_s)
    return last_count


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
    n_verified = wait_for_verifications_to_settle(sender, request_hash, verify_timeout)
    t_verified = time.time()
    mine(sender, "sender (final)")
    t_final = time.time()

    print(f"    done: response +{t_response-t0:.1f}s, "
          f"{n_verified} verification(s) +{t_verified-t_response:.1f}s, "
          f"total driver-observed wall time {t_final-t0:.1f}s")

    # count_verdicts on the sender -- it already has the just-sealed final
    # block locally, no propagation wait needed. Read-only (see module
    # docstring step 6), so a failure here is logged but never aborts the
    # round -- the actual attestation result above is already captured.
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
                     help="number of full node sweeps per app (reps=1 -> every node initiates once per app)")
    ap.add_argument("--response-timeout", type=float, default=120.0,
                     help="max seconds to wait for the prover's response per round")
    ap.add_argument("--verify-timeout", type=float, default=30.0,
                     help="max seconds to wait for verification votes to settle")
    ap.add_argument("--count-verdicts-timeout", type=float, default=15.0,
                     help="max seconds to wait for the post-round /count_verdicts call")
    ap.add_argument("--settle-between-rounds", type=float, default=3.0,
                     help="seconds to pause between rounds so pools/logs settle")
    ap.add_argument("--out", default="zekra_round_manifest.csv")
    ap.add_argument("--dry-run", action="store_true", help="print the planned rounds without executing them")
    ap.add_argument("--limit", type=int, default=None,
                     help="stop after this many rounds (use for a quick single-round sanity check)")
    args = ap.parse_args()

    apps = [a.strip() for a in args.apps.split(",") if a.strip()]

    if not args.dry_run:
        preflight(NODES)

    results = []
    round_num = 0
    total_rounds = len(apps) * args.reps * len(NODES)
    print(f"Planning {total_rounds} round(s): {len(apps)} app(s) x {args.reps} sweep(s) x {len(NODES)} nodes.\n")

    stop = False
    for app in apps:
        if stop:
            break
        for rep in range(args.reps):
            if stop:
                break
            for i in range(len(NODES)):
                if args.limit is not None and round_num >= args.limit:
                    print(f"\n--limit {args.limit} reached, stopping.")
                    stop = True
                    break
                round_num += 1
                sender = NODES[i]
                recipient = NODES[(i + 1) % len(NODES)]
                print(f"Round {round_num}/{total_rounds} (rep {rep + 1}/{args.reps})")
                result = run_round(app, sender, recipient, args.response_timeout,
                                    args.verify_timeout, args.count_verdicts_timeout, args.dry_run)
                if result:
                    results.append(result)
                if not args.dry_run:
                    time.sleep(args.settle_between_rounds)

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
