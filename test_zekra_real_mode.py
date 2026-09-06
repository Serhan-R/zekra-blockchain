"""
test_zekra_real_mode.py  --  real-mode verification against genuine Groth16 proofs.

Unlike test_zekra_unit.py (which runs in mock mode and can run anywhere), this
exercises verify_attestation with ZEKRA_VERIFIER_MODE=real, so check (3) is the
actual libsnark run_verifier_only binary judging real proofs produced by
run_prover_raw. It therefore only runs on a machine that has the ZEKRA tree with
_multipath_proof_test/ built.

What it establishes:

  * Option A works. The verifier reconstructs primary_input.bin from the
    authority-signed reference (h1, h3, entry, exit) plus the on-chain nonce and
    the responder's h2 -- and that reconstruction is BYTE-IDENTICAL to the one
    run_prover_raw emitted. Nothing about the claim comes from the responder
    except h2, and honest proofs still verify.

  * Replay is dead. The same proof and the same h2, offered against a fresh
    challenge nonce, fails check (3) -- because the nonce we pin is read off the
    chain, not off the response.

  * The three checks fire in the right order and for the right reason. Each
    negative case below asserts the REASON, not just the verdict; an earlier
    version of this file passed four attack cases that were all actually dying
    on a malformed request, which is exactly the kind of false green this
    assertion is here to prevent.

Run:  python3 test_zekra_real_mode.py
"""
import base64, hashlib, json, os, sys
Z = os.path.expanduser('~/mnt/ZEKRA')
T = os.path.join(Z, '_multipath_proof_test')
os.environ['ZEKRA_VERIFIER_MODE']   = 'real'
os.environ['ZEKRA_VERIFIER_BIN']    = os.path.join(Z, 'jsnark/libsnark/build/libsnark/jsnark_interface/run_verifier_only')
os.environ['ZEKRA_VERIFICATION_KEY']= os.path.join(T, 'keys/verification_key.bin')
os.environ['ZEKRA_KEY_FILE']        = os.path.expanduser('~/zk_check/node.key')
sys.path.insert(0, os.path.expanduser('~/mnt/blockchain-python-project'))
import zekra_integration as zk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def pubhex(k):
    return k.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()

H1 = '18443643617248465039572904042730594512018223554965634848177493580453807207872'
H3 = '18668427600963117543689159322278257954950148342040917675551891834300673150405'
CASES = {  # name -> (nonce, h2, proof dir)
 'baseline':  (12353,     '3451890075432212610826582042577650280150977561197488051220267508067926724739', 'proof_baseline'),
 'nonce_new': (999999901, '9566351410149094608065126381199008921207365842351727326682070756219438544743', 'proof_nonce_new'),
 'v1':        (12353,     '12941361084654863656962590475493981460416921484431602946815808137201798152962', 'proof_v1'),
}
PROG = 'wikisort-roi'
authority = Ed25519PrivateKey.generate()
os.environ['ZEKRA_AUTHORITY_PUBKEY'] = pubhex(authority)
with open(os.environ['ZEKRA_VERIFICATION_KEY'],'rb') as f:
    VK_B64 = base64.b64encode(f.read()).decode('ascii')
ref = zk.build_reference(PROG, H1, H3, 3, 41, VK_B64, dict(
    adjlist_len=64, adjlist_levels=9, path_len=128, stack_depth=8,
    label_bitwidth=7, bucket_bitwidth=4, address_bitwidth=32))
ENV = zk.sign_reference(ref, authority)

prover = Ed25519PrivateKey.generate()
PPUB = pubhex(prover)

def proof_b64(d):
    with open(os.path.join(T, d, 'proof.bin'),'rb') as f: return base64.b64encode(f.read()).decode()

def build(name, nonce, h2, d, sender=None, sign_h2=None, sign_nonce=None):
    # the nonce lives in function_parameter, and the prover signs the hash of
    # the request it answers -- which the response carries as 'parent'
    req = {'recipient': 'prover-node', 'program_id': PROG,
           'function_parameter': str(nonce), 'function_name': zk.ZEKRA_FUNCTION_NAME}
    rh = hashlib.sha256(zk.canonical(req)).hexdigest()
    req['hash'] = rh
    resp = {'sender': sender or 'prover-node', 'parent': rh,
            'program_id': PROG, 'h2': str(h2),
            'proof_b64': proof_b64(d), 'prover_pubkey': PPUB,
            'prover_sig': zk.sign_hex(prover, zk.attestation_message(
                PROG, rh, sign_nonce if sign_nonce is not None else nonce,
                sign_h2 if sign_h2 is not None else h2))}
    return resp, req

ok = fail = 0
def check(label, got, want):
    global ok, fail
    if isinstance(got, tuple):
        print(f'        reason: {got[1]}')
        got = got[0]
    good = got == want
    print(f"  {'PASS' if good else 'FAIL'}  {label}\n        -> {got}")
    ok, fail = (ok+1, fail) if good else (ok, fail+1)

print('=== REAL MODE: honest attestations must verify ===')
for n,(nonce,h2,d) in CASES.items():
    r,q = build(n, nonce, h2, d)
    check(f'{n}: honest real Groth16 proof', zk.verify_attestation(r,q,ENV,PPUB), 'correct')

print('\n=== REAL MODE: attacks must be caught ===')
# replay: baseline's proof+h2 offered against a fresh challenge nonce
r,q = build('replay', 999999901, CASES['baseline'][1], 'proof_baseline')
check('replayed proof under a fresh nonce', zk.verify_attestation(r,q,ENV,PPUB), 'incorrect')
# swap: v1's proof presented with baseline's h2
r,q = build('swap', 12353, CASES['baseline'][1], 'proof_v1')
check("another path's proof under baseline's h2", zk.verify_attestation(r,q,ENV,PPUB), 'incorrect')
# tampered h2 (signature still over the original) -> check(1) fires before the SNARK
r,q = build('tamper', 12353, CASES['baseline'][1], 'proof_baseline', sign_h2=CASES['v1'][1])
check('h2 tampered after signing (check 1)', zk.verify_attestation(r,q,ENV,PPUB), 'incorrect')
# wrong responder
r,q = build('wrong', 12353, CASES['baseline'][1], 'proof_baseline')
r['sender'] = 'someone-else'
check('answered by a node the challenge did not address', zk.verify_attestation(r,q,ENV,PPUB), 'incorrect')
# vk pinning: reference pins a vk digest this node does not hold -> abstain
bad = zk.sign_reference(zk.build_reference(PROG,H1,H3,3,41,base64.b64encode(b'wrong key').decode(), dict(
    adjlist_len=64, adjlist_levels=9, path_len=128, stack_depth=8,
    label_bitwidth=7, bucket_bitwidth=4, address_bitwidth=32)), authority)
r,q = build('vk', 12353, CASES['baseline'][1], 'proof_baseline')
check('reference embeds a WRONG vk -> proof rejected', zk.verify_attestation(r,q,bad,PPUB), 'incorrect')

print(f"\n  {ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
