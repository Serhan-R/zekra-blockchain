"""
local_zekra_test.py

End-to-end local test of the full ZEKRA attestation flow on five nodes --
no Jetsons, no libsnark, no Java.

WHAT IS BEING TESTED
--------------------
  A  honest attestation                    -> every independent verifier says "correct"
  B  lazy prover replays an old proof      -> "incorrect"   (check 2: nonce binding)
  C  response signed with the wrong key    -> "incorrect"   (check 1: signature)
  D  response with an unregistered key     -> "incorrect"   (check 1: key identity)
  E  no reference on chain yet             -> ABSTAIN, no verdicts published
  F  nonce reuse                           -> request refused at creation
  G  sum_natural still works               -> "correct"     (regression guard)
  H  a node answers someone else's challenge -> "incorrect"  (sender vs recipient)
  I  response for a program with no reference -> ABSTAIN, consensus not blocked

WHY FIVE NODES
--------------
Of the nodes involved in a challenge, the miner never verifies (it already holds
the longest chain, so it never runs resolve_conflicts for its own block), the
requester verifies but cannot transmit its verdict (no node has an address entry
for itself), and the responder judging itself proves nothing. Three nodes would
leave zero independent verifiers; five leaves two.

ROLE SEPARATION
---------------
Only the designated prover node is given ZEKRA_PROGRAM_DIR. Every other node can
verify -- it needs nothing but the signed reference -- but cannot prove, and never
sees the program materials. That is ZEKRA's privacy property, and it also means
only one node in this network could fabricate a legal path at all.
"""

import argparse
import copy
import json
import os
import shutil
import subprocess
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from zekra_integration import (  # noqa: E402
    _load_or_create_key, attestation_message, node_public_key_hex, sign_hex,
)
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

HOST = '127.0.0.1'
BASE_PORT = 5000
NODE_COUNT = 5
PROVER_INDEX = 1          # only this node gets program materials
PROGRAM_ID = 'cubic'
WORK = os.environ.get('ZEKRA_TEST_WORK', '/tmp/zekra_local')

results = {}


def log(msg):
    print(f'[test] {msg}', flush=True)


def ok(msg):
    print(f'[ OK ] {msg}', flush=True)
    return True


def fail(msg):
    print(f'[FAIL] {msg}', flush=True)
    return False


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

def build_workspace():
    if os.path.isdir(WORK):
        shutil.rmtree(WORK)
    os.makedirs(WORK)

    authority_key_path = os.path.join(WORK, 'authority.pem')
    authority_key = _load_or_create_key(authority_key_path)
    authority_pub = authority_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()

    # Program materials: ONLY the designated prover gets these.
    programs = os.path.join(WORK, 'programs')
    os.makedirs(os.path.join(programs, PROGRAM_ID))
    with open(os.path.join(programs, PROGRAM_ID, 'path'), 'w') as f:
        f.write('initial_node=3 final_node=41\ncall 4 5\nret 5\ncall 24 86\n')

    log(f'authority public key: {authority_pub[:24]}...')
    return authority_key_path, authority_pub, programs


def launch_nodes(authority_pub, programs_dir):
    log_dir = os.path.join(WORK, 'logs')
    os.makedirs(log_dir, exist_ok=True)
    procs = []
    for i in range(NODE_COUNT):
        port = BASE_PORT + i
        env = dict(os.environ)
        env.update({
            'FLASK_DEBUG': '0',
            'PYTHONUNBUFFERED': '1',
            'ZEKRA_VERIFIER_MODE': 'mock',
            'ZEKRA_AUTHORITY_PUBKEY': authority_pub,
            'ZEKRA_KEY_FILE': os.path.join(WORK, f'node_{port}.pem'),
        })
        # Role separation: only the prover holds program materials.
        if i == PROVER_INDEX:
            env['ZEKRA_PROGRAM_DIR'] = programs_dir
        else:
            env.pop('ZEKRA_PROGRAM_DIR', None)

        path = os.path.join(log_dir, f'node_{port}.log')
        fh = open(path, 'w')
        procs.append({
            'port': port, 'log': path, 'fh': fh,
            'proc': subprocess.Popen(
                [sys.executable, '-u', 'FlaskBlockChain.py', '--port', str(port)],
                stdout=fh, stderr=subprocess.STDOUT, env=env),
        })
    log(f'launched {NODE_COUNT} nodes (prover = port {BASE_PORT + PROVER_INDEX})')
    return procs


def wait_ready(ports, timeout=40):
    deadline = time.time() + timeout
    pending = set(ports)
    while pending and time.time() < deadline:
        for p in sorted(pending):
            try:
                if requests.get(f'http://{HOST}:{p}/id', timeout=2).status_code == 200:
                    pending.discard(p)
            except requests.RequestException:
                pass
        if pending:
            time.sleep(0.4)
    if pending:
        raise RuntimeError(f'nodes never came up: {sorted(pending)}')
    log('all nodes up')


def stop_nodes(procs):
    for e in procs:
        try:
            e['proc'].terminate()
            e['proc'].wait(timeout=5)
        except subprocess.TimeoutExpired:
            e['proc'].kill()
        finally:
            e['fh'].close()
    log('nodes stopped')


def register_all(ports):
    for p in ports:
        peers = [f'http://{HOST}:{o}' for o in ports if o != p]
        r = requests.post(f'http://{HOST}:{p}/nodes/register',
                          json={'nodes': peers}, timeout=15)
        if r.status_code != 201:
            raise RuntimeError(f'registration failed on {p}: {r.text}')
    log('full mesh registered')


# ---------------------------------------------------------------------------
# Chain helpers
# ---------------------------------------------------------------------------

def pool(port):
    return requests.get(f'http://{HOST}:{port}/transaction_pool',
                        timeout=10).json()['transaction_pool']


def chain(port):
    return requests.get(f'http://{HOST}:{port}/chain', timeout=30).json()['chain']


def mine(port):
    d = requests.get(f'http://{HOST}:{port}/mine', timeout=120).json()
    if 'index' in d:
        log(f'mined block {d["index"]} on {port} ({len(d["transactions"])} txs)')
        return d
    log(f'nothing to mine on {port}')
    return None


def post_tx(port, payload):
    return requests.post(f'http://{HOST}:{port}/transactions/new',
                         json=payload, timeout=15)


def all_txs(port):
    out = []
    for b in chain(port):
        out.extend(b['transactions'])
    out.extend(pool(port))
    return out


def verdicts_for(port, request_hash):
    return [t for t in all_txs(port)
            if t.get('transaction_type') == 'verification'
            and t.get('parent') == request_hash]


def wait_for(fn, timeout=30, interval=0.5):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(interval)
    return None


def blockchain_pubkey(port):
    """The public key a node advertises -- what peers registered for it."""
    return requests.get(f'http://{HOST}:{port}/id', timeout=5).json()['zekra_pubkey']


def node_ids(ports):
    ids = {}
    for p in ports:
        j = requests.get(f'http://{HOST}:{p}/id', timeout=5).json()
        ids[p] = j['node_id']
    return ids


def issue_challenge(requester_port, requester_id, prover_id, nonce,
                    program_id=PROGRAM_ID):
    r = post_tx(requester_port, {
        'sender': requester_id, 'recipient': prover_id,
        'transaction_type': 'request', 'function_name': 'zekra_attestation',
        'program_id': program_id, 'function_parameter': nonce,
    })
    if r.status_code != 201:
        raise RuntimeError(f'challenge rejected: {r.text}')


def find_request(port, nonce, program_id=PROGRAM_ID):
    for t in all_txs(port):
        if (t.get('transaction_type') == 'request'
                and t.get('program_id') == program_id
                and str(t.get('function_parameter')) == str(nonce)):
            return t
    return None


def find_response(port, request_hash):
    for t in all_txs(port):
        if (t.get('transaction_type') == 'response'
                and t.get('parent') == request_hash):
            return t
    return None


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

def honest_cycle(ports, ids, nonce, requester_port, miner_port, label,
                 expect='correct'):
    """Challenge -> mine -> prover answers -> mine -> collect verdicts."""
    prover_port = ports[PROVER_INDEX]
    issue_challenge(requester_port, ids[requester_port], ids[prover_port], nonce)
    time.sleep(1)
    if not mine(miner_port):
        return fail(f'{label}: miner had nothing to mine')

    req = find_request(miner_port, nonce)
    if not req:
        return fail(f'{label}: request never reached the chain')

    resp = wait_for(lambda: find_response(requester_port, req['hash']), 30)
    if not resp:
        return fail(f'{label}: prover never answered')
    ok(f'{label}: prover answered (h2={str(resp.get("h2"))[:14]}..., '
       f'signed by {str(resp.get("prover_pubkey"))[:12]}...)')

    time.sleep(1)
    if not mine(miner_port):
        return fail(f'{label}: could not mine the response')

    v = wait_for(lambda: verdicts_for(requester_port, req['hash']) or None, 30)
    return check_verdicts(v, ids[prover_port], expect, label), req, resp


def check_verdicts(verdicts, prover_id, expect, label):
    if not verdicts:
        return fail(f'{label}: no verdicts produced')
    independent = [v for v in verdicts if v.get('sender') != prover_id]
    if not independent:
        return fail(f'{label}: only the responder judged itself')
    values = sorted(v.get('function_parameter') for v in independent)
    for v in verdicts:
        who = 'self' if v.get('sender') == prover_id else 'independent'
        log(f"    {v.get('function_parameter')!r} from {v['sender'][:10]}... ({who})")
    if any(x != expect for x in values):
        return fail(f'{label}: expected every independent verdict {expect!r}, got {values}')
    return ok(f'{label}: all {len(independent)} independent verdict(s) {expect!r}')


def inject_response(requester_port, template, *, parent, nonce, program_id,
                    prover_id, signing_key, h2=None, proof_b64=None,
                    pubkey=None):
    """
    Post a hand-crafted response, impersonating a prover to whatever degree the
    supplied key allows. Used to simulate a dishonest prover.
    """
    h2 = h2 if h2 is not None else template['h2']
    proof_b64 = proof_b64 if proof_b64 is not None else template['proof_b64']
    pub = pubkey or signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    sig = sign_hex(signing_key,
                   attestation_message(program_id, parent, nonce, h2))
    payload = {
        'sender': prover_id, 'recipient': template['recipient'],
        'transaction_type': 'response', 'function_name': 'zekra_attestation',
        'program_id': program_id, 'function_parameter': template['function_parameter'],
        'parent': parent, 'h2': h2, 'proof_b64': proof_b64,
        'prover_pubkey': pub, 'prover_sig': sig,
    }
    return post_tx(requester_port, payload)


def dishonest_cycle(ports, ids, nonce, requester_port, miner_port, label,
                    template, signing_key, nominal_prover_port, *,
                    proof_b64=None, pubkey=None, expect='incorrect'):
    """
    Inject a crafted response and make sure the network rejects it.

    The challenge is addressed to a node that holds NO program materials, so it
    stays silent and our injected response is the only one on the chain. Without
    this the real prover answers honestly, its response is the one
    validate_response_transaction picks up, and the test passes for the wrong
    reason -- which is exactly what happened the first time this was run.
    """
    nominal_prover_id = ids[nominal_prover_port]
    issue_challenge(requester_port, ids[requester_port], nominal_prover_id, nonce)
    time.sleep(0.5)
    mine(miner_port)
    req = find_request(miner_port, nonce)
    if not req:
        return fail(f'{label}: request never reached the chain')

    # Confirm the silence we depend on: a node with no materials must not answer.
    time.sleep(2)
    if find_response(requester_port, req['hash']):
        return fail(f'{label}: a node with no program materials answered anyway')

    r = inject_response(requester_port, template, parent=req['hash'], nonce=nonce,
                        program_id=PROGRAM_ID, prover_id=nominal_prover_id,
                        signing_key=signing_key,
                        proof_b64=proof_b64 or template['proof_b64'], pubkey=pubkey)
    if r.status_code != 201:
        return fail(f'{label}: injection rejected outright: {r.text}')

    time.sleep(1)
    if not mine(miner_port):
        return fail(f'{label}: could not mine the injected response')

    v = wait_for(lambda: verdicts_for(requester_port, req['hash']) or None, 30)
    return check_verdicts(v, nominal_prover_id, expect, label)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    if not os.path.isfile('FlaskBlockChain.py'):
        print('run from the blockchain-python-project directory')
        return 1

    authority_key_path, authority_pub, programs = build_workspace()
    procs = launch_nodes(authority_pub, programs)
    ports = [p['port'] for p in procs]

    try:
        wait_ready(ports)
        register_all(ports)
        ids = node_ids(ports)
        for p in ports:
            role = ' (PROVER)' if p == ports[PROVER_INDEX] else ''
            log(f'port {p} -> {ids[p][:12]}...{role}')

        for p in ports:
            st = requests.get(f'http://{HOST}:{p}/zekra/status', timeout=5).json()
            log(f"port {p}: mode={st['mode']} provable={st['provable_programs']} "
                f"peer_keys={st['known_peer_pubkeys']}")

        # --- E: no reference on chain -> ABSTAIN ---------------------------
        print()
        log('=== SCENARIO E: challenge with NO reference published yet ===')
        prover_port = ports[PROVER_INDEX]
        issue_challenge(ports[2], ids[ports[2]], ids[prover_port], 111111)
        time.sleep(1)
        mine(ports[3])
        req_e = find_request(ports[3], 111111)
        time.sleep(4)
        resp_e = find_response(ports[2], req_e['hash']) if req_e else None
        v_e = verdicts_for(ports[2], req_e['hash']) if req_e else []
        results['E (no reference -> abstain)'] = (
            ok('E: prover refused to answer and no verdicts were published')
            if (resp_e is None and not v_e) else
            fail(f'E: expected silence, got response={bool(resp_e)} verdicts={len(v_e)}'))

        # --- publish the authority-signed reference ------------------------
        print()
        log('=== publishing the authority-signed reference ===')
        ref_path = os.path.join(WORK, 'reference.json')
        subprocess.run([sys.executable, 'zekra_authority.py', 'build',
                        '--key', authority_key_path, '--program-id', PROGRAM_ID,
                        '--h1', '18443643617248465039572904042730594512018223554965634848177493580453807207872',
                        '--h3', '18668427600963117543689159322278257954950148342040917675551891834300673150405',
                        '--entry-node', '3', '--exit-node', '41',
                        '--adjlist-len', '150', '--adjlist-levels', '3',
                        '--path-len', '32', '--stack-depth', '8',
                        '--label-bitwidth', '8', '--bucket-bitwidth', '5',
                        '--address-bitwidth', '23', '--out', ref_path],
                       check=True, capture_output=True)
        subprocess.run([sys.executable, 'zekra_authority.py', 'publish',
                        '--reference', ref_path, '--node', f'http://{HOST}:{ports[0]}'],
                       check=True, capture_output=True)
        time.sleep(1)
        mine(ports[0])
        time.sleep(2)
        seen = [requests.get(f'http://{HOST}:{p}/zekra/status', timeout=5)
                .json()['references_on_chain'] for p in ports]
        results['reference propagated to all nodes'] = (
            ok(f'reference visible on all {len(ports)} nodes')
            if all(PROGRAM_ID in s for s in seen) else
            fail(f'reference not everywhere: {seen}'))

        # --- A: honest attestation -----------------------------------------
        print()
        log('=== SCENARIO A: honest attestation ===')
        outcome = honest_cycle(ports, ids, 4242424242, ports[2], ports[3], 'A')
        if isinstance(outcome, tuple):
            results['A (honest -> correct)'], req_a, resp_a = outcome
        else:
            results['A (honest -> correct)'] = outcome
            req_a = resp_a = None

        if resp_a:
            prover_key = _load_or_create_key(
                os.path.join(WORK, f'node_{ports[PROVER_INDEX]}.pem'))

            # --- B: lazy prover replays an old proof under a fresh nonce ----
            print()
            log('=== SCENARIO B: prover replays an old proof for a NEW nonce ===')
            log('    (correctly signed, so check 1 passes -- only check 2 can catch it)')
            impostor_port = ports[0]          # holds no program materials
            impostor_key = _load_or_create_key(
                os.path.join(WORK, f'node_{impostor_port}.pem'))
            results['B (replayed proof -> incorrect)'] = dishonest_cycle(
                ports, ids, 5353535353, ports[2], ports[3], 'B',
                template=resp_a, signing_key=impostor_key,
                nominal_prover_port=impostor_port)

            # --- C: signed with the wrong key ------------------------------
            print()
            log('=== SCENARIO C: response signed with an attacker key ===')
            attacker_key = Ed25519PrivateKey.generate()
            results['C (forged signature -> incorrect)'] = dishonest_cycle(
                ports, ids, 6464646464, ports[2], ports[3], 'C',
                template=resp_a, signing_key=attacker_key,
                nominal_prover_port=impostor_port,
                pubkey=ids and blockchain_pubkey(impostor_port))

            # --- D: valid signature, but key is not the sender's ------------
            print()
            log('=== SCENARIO D: valid signature under an UNREGISTERED key ===')
            rogue = Ed25519PrivateKey.generate()
            results['D (unregistered key -> incorrect)'] = dishonest_cycle(
                ports, ids, 7575757575, ports[2], ports[3], 'D',
                template=resp_a, signing_key=rogue,
                nominal_prover_port=impostor_port,
                pubkey=rogue.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw).hex())

        # --- H: answering someone else's challenge --------------------------
        if resp_a:
            print()
            log('=== SCENARIO H: node answers a challenge addressed to SOMEONE ELSE ===')
            log('    (validly signed by the impostor, correct nonce, valid proof --')
            log('     only the sender/recipient check can catch this one)')
            import hashlib
            from zekra_integration import canonical

            challenged_port = ports[4]          # holds no materials, stays silent
            impostor2_port = ports[0]           # answers anyway, signing as itself
            impostor2_key = _load_or_create_key(
                os.path.join(WORK, f'node_{impostor2_port}.pem'))
            nonce_h = 8686868686

            issue_challenge(ports[2], ids[ports[2]], ids[challenged_port], nonce_h)
            time.sleep(0.5)
            mine(ports[3])
            req_h = find_request(ports[3], nonce_h)
            time.sleep(2)
            if find_response(ports[2], req_h['hash']):
                results['H (answered by the wrong node -> incorrect)'] = fail(
                    'H: the challenged node answered despite having no materials')
            else:
                # A genuinely well-formed attestation -- just from the wrong node.
                h2_h = resp_a['h2']
                proof_h = __import__('base64').b64encode(hashlib.sha256(
                    b'zekra-mock-proof|' + canonical({'program_id': PROGRAM_ID,
                                                      'h2': str(h2_h),
                                                      'nonce': str(nonce_h)})
                ).digest()).decode('ascii')
                r = inject_response(ports[2], resp_a, parent=req_h['hash'],
                                    nonce=nonce_h, program_id=PROGRAM_ID,
                                    prover_id=ids[impostor2_port],
                                    signing_key=impostor2_key, h2=h2_h,
                                    proof_b64=proof_h)
                if r.status_code != 201:
                    results['H (answered by the wrong node -> incorrect)'] = fail(
                        f'H: injection rejected outright: {r.text}')
                else:
                    time.sleep(1)
                    mine(ports[3])
                    v_h = wait_for(
                        lambda: verdicts_for(ports[2], req_h['hash']) or None, 30)
                    results['H (answered by the wrong node -> incorrect)'] = \
                        check_verdicts(v_h, ids[impostor2_port], 'incorrect', 'H')

        # --- F: nonce reuse -------------------------------------------------
        print()
        log('=== SCENARIO F: reusing a nonce ===')
        # Reissue from a DIFFERENT node. Repeating the identical request would be
        # caught by the content-hash dedup that already existed, so the nonce guard
        # would never run -- which is exactly how this test passed for the wrong
        # reason the first time round. A different sender changes the transaction
        # hash, leaving the nonce guard as the only thing that can catch it.
        before = len([t for t in all_txs(ports[2])
                      if t.get('transaction_type') == 'request'
                      and str(t.get('function_parameter')) == '4242424242'])
        issue_challenge(ports[4], ids[ports[4]], ids[ports[PROVER_INDEX]], 4242424242)
        time.sleep(1)
        after = len([t for t in all_txs(ports[2])
                     if t.get('transaction_type') == 'request'
                     and str(t.get('function_parameter')) == '4242424242'])
        results['F (nonce reuse refused)'] = (
            ok(f'F: reused nonce did not create a second request ({before} -> {after})')
            if after == before else
            fail(f'F: nonce reuse created another request ({before} -> {after})'))

        # --- I: verifier abstains on a program it has no reference for -------
        # Scenario E only proves the PROVER refuses. The verifier-side abstain
        # branch needs an actual response on the chain for a program nobody has a
        # reference for, which only an injected response can produce.
        print()
        log('=== SCENARIO I: response for a program with NO reference -> ABSTAIN ===')
        import base64 as _base64
        import hashlib as _hashlib
        from zekra_integration import canonical as _canonical

        ghost = 'ghost_program'
        ghost_nonce = 9797979797
        ghost_port = ports[0]
        ghost_key = _load_or_create_key(os.path.join(WORK, f'node_{ghost_port}.pem'))

        post_tx(ports[2], {
            'sender': ids[ports[2]], 'recipient': ids[ghost_port],
            'transaction_type': 'request', 'function_name': 'zekra_attestation',
            'program_id': ghost, 'function_parameter': ghost_nonce})
        time.sleep(0.5)
        mine(ports[3])
        req_i = find_request(ports[3], ghost_nonce, program_id=ghost)
        if not req_i:
            results['I (no reference -> verifier abstains)'] = fail(
                'I: ghost request never reached the chain')
        else:
            h2_i = resp_a['h2'] if resp_a else '12345'
            proof_i = _base64.b64encode(_hashlib.sha256(
                b'zekra-mock-proof|' + _canonical({'program_id': ghost,
                                                   'h2': str(h2_i),
                                                   'nonce': str(ghost_nonce)})
            ).digest()).decode('ascii')
            post_tx(ports[2], {
                'sender': ids[ghost_port], 'recipient': ids[ports[2]],
                'transaction_type': 'response', 'function_name': 'zekra_attestation',
                'program_id': ghost, 'function_parameter': 'ghostfingerprint',
                'parent': req_i['hash'], 'h2': h2_i, 'proof_b64': proof_i,
                'prover_pubkey': ghost_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw).hex(),
                'prover_sig': sign_hex(ghost_key, attestation_message(
                    ghost, req_i['hash'], ghost_nonce, h2_i)),
            })
            time.sleep(1)
            mine(ports[3])
            time.sleep(3)
            v_i = verdicts_for(ports[2], req_i['hash'])
            lengths = {p: len(chain(p)) for p in ports}
            if v_i:
                results['I (no reference -> verifier abstains)'] = fail(
                    f'I: expected no verdicts, got '
                    f'{[x.get("function_parameter") for x in v_i]}')
            elif len(set(lengths.values())) != 1:
                results['I (no reference -> verifier abstains)'] = fail(
                    f'I: abstention blocked chain adoption, lengths {lengths}')
            else:
                results['I (no reference -> verifier abstains)'] = ok(
                    f'I: no verdicts published, and every node still adopted the '
                    f'chain (length {list(lengths.values())[0]}) -- abstained '
                    f'without blocking consensus')

        # --- G: arithmetic regression ---------------------------------------
        print()
        log('=== SCENARIO G: sum_natural regression ===')
        r = post_tx(ports[4], {
            'sender': ids[ports[4]], 'recipient': ids[ports[PROVER_INDEX]],
            'transaction_type': 'request', 'function_name': 'sum_natural',
            'function_parameter': 10})
        time.sleep(1)
        mine(ports[3])
        req_g = next((t for t in all_txs(ports[3])
                      if t.get('function_name') == 'sum_natural'
                      and t.get('transaction_type') == 'request'), None)
        resp_g = wait_for(lambda: find_response(ports[4], req_g['hash']), 30) if req_g else None
        if resp_g:
            time.sleep(1)
            mine(ports[3])
            v_g = wait_for(lambda: verdicts_for(ports[4], req_g['hash']) or None, 30)
            results['G (sum_natural regression)'] = check_verdicts(
                v_g, ids[ports[PROVER_INDEX]], 'correct', 'G')
        else:
            results['G (sum_natural regression)'] = fail('G: no arithmetic response')

    finally:
        print()
        log('=' * 66)
        for name, passed in results.items():
            print(f"  {'PASS' if passed else 'FAIL'}  {name}")
        log('=' * 66)
        if args.verbose:
            for e in procs:
                print(f'\n----- {e["log"]} -----')
                e['fh'].flush()
                with open(e['log'], errors='replace') as f:
                    print(f.read()[-4000:])
        stop_nodes(procs)

    return 0 if results and all(results.values()) else 1


if __name__ == '__main__':
    sys.exit(main())
