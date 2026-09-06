#!/usr/bin/python3
"""
test_real_e2e.py -- the joined test.

Everything else runs one half or the other: local_zekra_test.py drives the real
blockchain but with a SHA-256 stand-in for the proof, and test_zekra_real_mode.py
drives real Groth16 proofs but calls verify_attestation() directly. This runs
both halves together for the first time: a node is challenged over HTTP, runs the
actual ZEKRA toolchain to produce a real proof, and the other nodes verify that
proof with libsnark and publish verdicts on chain.

It needs a machine that has been through the one-time circuit compile (issue #12):
a JDK, a compiled circuit, a proving key, and the libsnark binaries. Point
ZK_JAVA at that working directory.

What it asserts:
  * the challenged node produces a REAL proof (134 bytes, not a mock digest)
  * every independent verifier publishes 'correct'
  * a replayed proof under a fresh nonce is rejected by the real verifier
  * nothing hangs -- which is the open question, given proving blocks the
    request handler (#16) and no inter-node call sets a timeout (#17)
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import time

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import zekra_integration as zk

HOST = '127.0.0.1'
BASE_PORT = int(os.environ.get('ZK_BASE_PORT', '5400'))
NODE_COUNT = 5
PROVER_INDEX = 1
PRUNED = os.environ.get('ZK_PRUNED', '1') == '1'
PROGRAM_ID = 'crc32-pruned' if PRUNED else 'crc32-full'
SUF = '_p' if PRUNED else ''
PAD_ADJ, PAD_PATH = ('32', '64') if PRUNED else ('128', '192')
LBL, BKT = ('6', '3') if PRUNED else ('8', '5')
ZK_JAVA = os.environ.get('ZK_JAVA', '/home/claude/zk_java')
WORK = os.environ.get('ZK_WORK', '/tmp/real_e2e')

PASS, FAIL = [], []


def log(m):
    print(f'[e2e] {m}', flush=True)


def ok(m):
    PASS.append(m)
    print(f'[ OK ] {m}', flush=True)
    return True


def fail(m):
    FAIL.append(m)
    print(f'[FAIL] {m}', flush=True)
    return False


def pubhex(k):
    return k.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

def prover_env():
    """Everything _prove_real() needs, pointing at the compiled circuit."""
    return {
        'ZEKRA_FORMATTER': f'{ZK_JAVA}/scripts/circuit_input_formatter.py',
        'ZEKRA_CIRCUIT_INPUT_DIR': f'{ZK_JAVA}/inputs{SUF}',
        'ZEKRA_CIRCUIT_OUTPUT_DIR': f'{ZK_JAVA}/out{SUF}',
        'ZEKRA_JAVA_CP': f'{ZK_JAVA}/bin:{ZK_JAVA}/xjsnark_backend.jar',
        'ZEKRA_JAVA_CLASS': 'xjsnark.zekra.zekra',
        'ZEKRA_JAVA_DIR': ZK_JAVA,
        'ZEKRA_PROVER_BIN': f'{ZK_JAVA}/bin_snark/run_prover_raw',
        'ZEKRA_ARITH': f'{ZK_JAVA}/out{SUF}/zekra.arith',
        'ZEKRA_PROVING_KEY': f'{ZK_JAVA}/keys{SUF}/proving_key_raw.bin',
        'ZEKRA_CIRCUIT_METADATA': f'{ZK_JAVA}/meta{SUF}/circuit_metadata.bin',
    }


def build_reference_envelope(authority_key):
    """Authority derives h1/h3 from the materials it is about to distribute."""
    materials = os.path.join(WORK, 'programs', PROGRAM_ID)
    refgen = os.path.join(WORK, 'refgen')
    os.makedirs(refgen, exist_ok=True)

    r1, r3 = zk.sample_blinding(), zk.sample_blinding()
    with open(os.path.join(materials, 'blinding.json'), 'w') as f:
        json.dump({'r1_adjlist': str(r1), 'r3_translator': str(r3)}, f)

    circuit = dict(adjlist_len=int(PAD_ADJ), adjlist_levels=2, path_len=int(PAD_PATH),
                   stack_depth=8, label_bitwidth=int(LBL), bucket_bitwidth=int(BKT),
                   address_bitwidth=23, pruned=PRUNED)
    subprocess.run(
        [sys.executable, f'{ZK_JAVA}/scripts/circuit_input_formatter.py',
         '-a', materials] + (['--pruned'] if PRUNED else []) + [
         '--pad-adjlist-to', PAD_ADJ, '--pad-path-to', PAD_PATH, '--adjlist-levels', '2',
         '--label-bitwidth', LBL, '--bucket-bitwidth', BKT, '--address-bitwidth', '23',
         '--nonce-adjlist', str(r1), '--nonce-translator', str(r3),
         '--output-dir', refgen],
        capture_output=True, check=True)

    g = lambda n: open(os.path.join(refgen, n)).read().strip()
    with open(f'{ZK_JAVA}/keys{SUF}/verification_key.bin', 'rb') as f:
        vk_b64 = base64.b64encode(f.read()).decode('ascii')

    reference = zk.build_reference(PROGRAM_ID, g('in_encoded_adjlist_digest'),
                                   g('in_translator_digest'),
                                   int(g('in_initial_node')), int(g('in_final_node')),
                                   vk_b64, circuit)
    return zk.sign_reference(reference, authority_key)


def setup():
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(os.path.join(WORK, 'programs', PROGRAM_ID))
    src = f'{ZK_JAVA}/materials'
    for name in ('adjlist', 'numified_adjlist', 'numified_path', 'recorded_path',
                 'translator', 'adjlist_pruned', 'numified_adjlist_pruned',
                 'numified_path_pruned', 'translator_pruned'):
        shutil.copy(os.path.join(src, name),
                    os.path.join(WORK, 'programs', PROGRAM_ID, name))

    authority = Ed25519PrivateKey.generate()
    envelope = build_reference_envelope(authority)
    log(f'reference built: h1={envelope["reference"]["h1"][:18]}..., '
        f'pruned={envelope["reference"]["circuit"].get("pruned")}, '
        f'vk embedded ({len(envelope["reference"]["vk_b64"])} b64 chars)')
    return pubhex(authority), envelope


def launch(authority_pub):
    log_dir = os.path.join(WORK, 'logs')
    os.makedirs(log_dir, exist_ok=True)
    procs = []
    for i in range(NODE_COUNT):
        port = BASE_PORT + i
        env = dict(os.environ)
        env.update({
            'FLASK_DEBUG': '0',
            'PYTHONUNBUFFERED': '1',
            'ZEKRA_VERIFIER_MODE': 'real',                       # <-- the point
            'ZEKRA_VERIFIER_BIN': f'{ZK_JAVA}/bin_snark/run_verifier_only',
            'LD_LIBRARY_PATH': f'{ZK_JAVA}/libs',
            'ZEKRA_AUTHORITY_PUBKEY': authority_pub,
            'ZEKRA_KEY_FILE': os.path.join(WORK, f'node_{port}.pem'),
        })
        # No node is given a local verification key: the reference carries it.
        env.pop('ZEKRA_VERIFICATION_KEY', None)
        if i == PROVER_INDEX:
            env['ZEKRA_PROGRAM_DIR'] = os.path.join(WORK, 'programs')
            env.update(prover_env())
        else:
            env.pop('ZEKRA_PROGRAM_DIR', None)

        path = os.path.join(log_dir, f'node_{port}.log')
        fh = open(path, 'w')
        procs.append({'port': port, 'fh': fh, 'log': path,
                      'proc': subprocess.Popen(
                          [sys.executable, '-u', 'FlaskBlockChain.py',
                           '--port', str(port)],
                          stdout=fh, stderr=subprocess.STDOUT, env=env)})
    log(f'launched {NODE_COUNT} nodes in REAL mode (prover = {BASE_PORT + PROVER_INDEX})')
    return procs


def stop(procs):
    for e in procs:
        try:
            e['proc'].terminate()
            e['proc'].wait(timeout=5)
        except subprocess.TimeoutExpired:
            e['proc'].kill()
        finally:
            e['fh'].close()
    log('nodes stopped')


# ---------------------------------------------------------------------------
# Chain helpers
# ---------------------------------------------------------------------------

def wait_ready(ports, timeout=60):
    deadline, pending = time.time() + timeout, set(ports)
    while pending and time.time() < deadline:
        for p in sorted(pending):
            try:
                if requests.get(f'http://{HOST}:{p}/id', timeout=3).status_code == 200:
                    pending.discard(p)
            except requests.RequestException:
                pass
        if pending:
            time.sleep(0.4)
    if pending:
        raise RuntimeError(f'nodes never came up: {sorted(pending)}')
    log('all nodes up')


def register_all(ports):
    for p in ports:
        peers = [f'http://{HOST}:{o}' for o in ports if o != p]
        requests.post(f'http://{HOST}:{p}/nodes/register',
                      json={'nodes': peers}, timeout=20)
    log('full mesh registered')


def node_ids(ports):
    return {p: requests.get(f'http://{HOST}:{p}/id', timeout=5).json()['node_id']
            for p in ports}


def all_txs(port):
    """Chain AND pool. A response sits in the pool until someone mines it, so a
    chain-only view reports 'the prover never answered' when it plainly did."""
    chain = requests.get(f'http://{HOST}:{port}/chain', timeout=20).json()['chain']
    out = [t for b in chain for t in b['transactions']]
    out.extend(requests.get(f'http://{HOST}:{port}/transaction_pool',
                            timeout=20).json()['transaction_pool'])
    return out


def mine(port, timeout=180):
    r = requests.get(f'http://{HOST}:{port}/mine', timeout=timeout)
    return r.status_code == 200 and 'index' in r.json()


def wait_for(fn, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        v = fn()
        if v:
            return v
        time.sleep(1)
    return None


def find_tx(port, **match):
    for t in all_txs(port):
        if all(str(t.get(k)) == str(v) for k, v in match.items()):
            return t
    return None


def verdicts_for(port, parent):
    return [t for t in all_txs(port)
            if t.get('transaction_type') == 'verification' and t.get('parent') == parent]


# ---------------------------------------------------------------------------

def main():
    # The compiled class has its input/output directories baked in at compile
    # time and can therefore serve exactly ONE circuit variant. Switching between
    # pruned and unpruned needs a recompile. Check it up front: otherwise the
    # symptom is a four-minute wait and 'prover never answered'.
    src = f'{ZK_JAVA}/zekra/zekra.java'
    if os.path.exists(src):
        baked = open(src).read()
        want = f'inputPathPrefix = "./inputs{SUF}/"'
        if want not in baked:
            got = [l.strip() for l in baked.splitlines() if 'inputPathPrefix =' in l]
            print(f'the compiled circuit is built for a different variant.\n'
                  f'  need: {want}\n  have: {got[0] if got else "?"}\n'
                  f'Recompile with compile_circuit.py --input-dir ./inputs{SUF} '
                  f'--output-dir ./out{SUF}, or run with the matching ZK_PRUNED.')
            return 2

    for need in (f'{ZK_JAVA}/out{SUF}/zekra.arith',
                 f'{ZK_JAVA}/keys{SUF}/proving_key_raw.bin',
                 f'{ZK_JAVA}/bin_snark/run_verifier_only'):
        if not os.path.exists(need):
            print(f'missing prerequisite: {need}\n'
                  f'This test needs a machine that has done the one-time circuit '
                  f'compile. Set ZK_JAVA to that directory.')
            return 2

    authority_pub, envelope = setup()
    ports = [BASE_PORT + i for i in range(NODE_COUNT)]
    procs = launch(authority_pub)
    try:
        wait_ready(ports)
        register_all(ports)
        ids = node_ids(ports)
        prover_port = ports[PROVER_INDEX]
        requester_port, miner_port = ports[0], ports[2]

        # --- publish the signed reference --------------------------------
        aid = envelope['authority_pubkey'][:32]
        requests.post(f'http://{HOST}:{ports[0]}/transactions/new', timeout=20, json={
            'sender': aid, 'recipient': aid,
            'transaction_type': zk.REFERENCE_TX_TYPE,
            'function_name': zk.ZEKRA_FUNCTION_NAME,
            'program_id': PROGRAM_ID, 'reference_envelope': envelope})
        time.sleep(1)
        mine(miner_port)
        seen = sum(1 for p in ports
                   if find_tx(p, transaction_type=zk.REFERENCE_TX_TYPE,
                              program_id=PROGRAM_ID))
        (ok if seen == len(ports) else fail)(
            f'reference on all nodes ({seen}/{len(ports)})')

        # --- the actual challenge ----------------------------------------
        nonce = 7311220001
        log(f'challenging {ids[prover_port][:10]}... with nonce {nonce}')
        t0 = time.time()
        requests.post(f'http://{HOST}:{requester_port}/transactions/new', timeout=20,
                      json={'sender': ids[requester_port],
                            'recipient': ids[prover_port],
                            'transaction_type': 'request',
                            'function_name': 'zekra_attestation',
                            'program_id': PROGRAM_ID,
                            'function_parameter': nonce})
        time.sleep(1)
        if not mine(miner_port):
            return fail('challenge could not be mined') or 1
        req = find_tx(miner_port, transaction_type='request',
                      function_parameter=nonce)
        if not req:
            return fail('challenge never reached the chain') or 1

        log('waiting for a REAL proof (formatter -> java -> run_prover_raw)...')
        resp = wait_for(lambda: find_tx(requester_port, transaction_type='response',
                                        parent=req['hash']), 240)
        if not resp:
            return fail('prover never answered -- see logs') or 1
        elapsed = time.time() - t0
        proof = base64.b64decode(resp['proof_b64'])
        ok(f'prover answered in {elapsed:.1f}s with a {len(proof)}-byte proof')
        (ok if len(proof) == 134 else fail)(
            f'proof is a real Groth16 proof, not a mock digest '
            f'({len(proof)} bytes; a mock is 32)')

        time.sleep(1)
        if not mine(miner_port):
            return fail('could not mine the response') or 1

        v = wait_for(lambda: verdicts_for(requester_port, req['hash']) or None, 180)
        if not v:
            return fail('no verdicts published') or 1
        independent = [x for x in v if x.get('sender') != ids[prover_port]]
        for x in v:
            who = 'SELF' if x.get('sender') == ids[prover_port] else 'independent'
            log(f"    {x.get('function_parameter')!r} from {x['sender'][:10]}... ({who})")
        (ok if not any(x.get('sender') == ids[prover_port] for x in v) else fail)(
            'no self-verdict from the responder')
        vals = {x.get('function_parameter') for x in independent}
        (ok if vals == {'correct'} else fail)(
            f'{len(independent)} independent verdict(s), all real-libsnark: {vals}')

        # --- REPLAY: the same real proof, offered against a fresh challenge ---
        # Signed with the prover's own key, so check (1) passes and the SNARK is
        # genuine. Only check (2) -- the nonce we pin from the chain -- can catch
        # this, and only because the verifier builds the public inputs itself.
        log('replaying that proof under a new nonce...')
        replay_nonce = 7311220002
        requests.post(f'http://{HOST}:{requester_port}/transactions/new', timeout=20,
                      json={'sender': ids[requester_port],
                            'recipient': ids[ports[3]],      # a node with NO materials,
                            'transaction_type': 'request',   # so only our injection answers
                            'function_name': 'zekra_attestation',
                            'program_id': PROGRAM_ID,
                            'function_parameter': replay_nonce})
        time.sleep(1)
        mine(miner_port)
        req2 = find_tx(miner_port, transaction_type='request',
                       function_parameter=replay_nonce)
        if not req2:
            return fail('replay challenge never reached the chain') or 1

        prover_key = zk._load_or_create_key(os.path.join(WORK, f'node_{prover_port}.pem'))
        requests.post(f'http://{HOST}:{requester_port}/transactions/new', timeout=20,
                      json={'sender': ids[ports[3]], 'recipient': ids[requester_port],
                            'transaction_type': 'response',
                            'function_name': 'zekra_attestation',
                            'program_id': PROGRAM_ID, 'parent': req2['hash'],
                            'function_parameter': 'replayed',
                            'h2': resp['h2'],                 # old commitment
                            'proof_b64': resp['proof_b64'],   # old, genuine proof
                            'prover_pubkey': zk.public_key_hex(prover_key.public_key())
                            if hasattr(zk, 'public_key_hex') else pubhex(prover_key),
                            'prover_sig': zk.sign_hex(prover_key, zk.attestation_message(
                                PROGRAM_ID, req2['hash'], replay_nonce, resp['h2']))})
        time.sleep(1)
        mine(miner_port)
        v2 = wait_for(lambda: verdicts_for(requester_port, req2['hash']) or None, 180)
        if not v2:
            return fail('replay produced no verdicts') or 1
        vals2 = {x.get('function_parameter') for x in v2}
        for x in v2:
            log(f"    {x.get('function_parameter')!r} from {x['sender'][:10]}...")
        (ok if vals2 == {'incorrect'} else fail)(
            f'replayed proof rejected on chain by real libsnark: {vals2}')

    finally:
        stop(procs)

    print('\n' + '=' * 62)
    for m in PASS:
        print(f'  PASS  {m}')
    for m in FAIL:
        print(f'  FAIL  {m}')
    print(f'  {len(PASS)} passed, {len(FAIL)} failed')
    print('=' * 62)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
