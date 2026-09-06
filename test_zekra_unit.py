"""
test_zekra_unit.py

Fast unit tests for the parts of the attestation logic that do not need a running
network: reference trust, verification-key pinning, public-input construction, and
signature binding.

These exist because the end-to-end suite can pass for the wrong reason -- twice
now it did. A scenario that never reaches the code it claims to test looks
identical to one that passes. These tests call the functions directly.
"""

import base64
import hashlib
import os
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import zekra_integration as z

PASS, FAIL = [], []


def check(name, condition, detail=''):
    (PASS if condition else FAIL).append(name)
    print(f"  {'PASS' if condition else 'FAIL'}  {name}{(' - ' + detail) if detail else ''}")


def pubhex(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()


CIRCUIT = {'adjlist_len': 150, 'adjlist_levels': 3, 'path_len': 32,
           'stack_depth': 8, 'label_bitwidth': 8, 'bucket_bitwidth': 5,
           'address_bitwidth': 23}
H1 = '18443643617248465039572904042730594512018223554965634848177493580453807207872'
H3 = '18668427600963117543689159322278257954950148342040917675551891834300673150405'
H2 = '3451890075432212610826582042577650280150977561197488051220267508067926724739'
REAL_PI = ('/mnt/user-data/uploads/ZEKRA/_multipath_proof_test/'
           'proof_baseline/primary_input.bin')


def test_reference_trust():
    print('\n=== reference trust ===')
    authority = Ed25519PrivateKey.generate()
    rogue = Ed25519PrivateKey.generate()
    ref = z.build_reference('cubic', H1, H3, 3, 41, 'deadbeef', CIRCUIT)
    good = z.sign_reference(ref, authority)

    r, why = z.verify_reference(good, pubhex(authority))
    check('a correctly signed reference verifies', r is not None, why or '')

    r, why = z.verify_reference(good, pubhex(rogue))
    check('a reference from the WRONG authority is rejected', r is None, why or '')

    # Tamper with the payload but keep the signature: this is the attack that
    # matters, since h1 is what pins the CFG. Changing it would let an attacker
    # declare a graph under which any path is legal.
    tampered = {**good, 'reference': {**ref, 'h1': '12345'}}
    r, why = z.verify_reference(tampered, pubhex(authority))
    check('a reference with a tampered h1 is rejected', r is None, why or '')

    tampered2 = {**good, 'reference': {**ref, 'entry_node': 999}}
    r, why = z.verify_reference(tampered2, pubhex(authority))
    check('a reference with a tampered entry node is rejected', r is None, why or '')

    incomplete = {'reference': ref, 'authority_pubkey': pubhex(authority)}
    r, why = z.verify_reference(incomplete, pubhex(authority))
    check('a reference with no signature is rejected', r is None, why or '')

    no_circuit = z.sign_reference({k: v for k, v in ref.items() if k != 'circuit'},
                                  authority)
    r, why = z.verify_reference(no_circuit, pubhex(authority))
    check('a reference missing circuit params is rejected', r is None, why or '')


def test_vk_embedded():
    print('\n=== verification key: embedded in the reference ===')
    key_bytes = b'pretend verification key'
    ref = z.build_reference('cubic', H1, H3, 3, 41,
                            base64.b64encode(key_bytes).decode(), CIRCUIT)

    check('the reference carries the key itself, not a digest',
          'vk_b64' in ref and 'vk_sha256' not in ref)
    check('the embedded key round-trips',
          base64.b64decode(ref['vk_b64']) == key_bytes)

    # The whole point: with the key signed in, a verifier needs no local key.
    # Assert on which resolution path _verify_real actually took, not on a
    # property of the dict we just built -- both calls below are expected to
    # fail (there is no verifier binary here), so the REASON is the test.
    saved = {k: os.environ.get(k) for k in
             ('ZEKRA_VERIFICATION_KEY', 'ZEKRA_VERIFIER_BIN', 'ZEKRA_VERIFIER_MODE')}
    os.environ['ZEKRA_VERIFICATION_KEY'] = '/nonexistent/verification_key.bin'
    # A real (trivial) binary, so key resolution is actually reached: the
    # verifier-binary check runs first, and would otherwise mask both outcomes.
    os.environ['ZEKRA_VERIFIER_BIN'] = '/bin/true'
    os.environ['ZEKRA_VERIFIER_MODE'] = 'real'
    try:
        x = z.public_inputs({'entry_node': 3, 'exit_node': 41, 'h1': H1, 'h3': H3},
                            12353, H2)

        def why(reference):
            try:
                z._verify_real(x, b'not-a-proof', reference)
                return 'no error raised'
            except z.ZekraVerificationError as e:
                return str(e)

        embedded = why(ref)
        check('an embedded key is used even with no local key configured',
              embedded == 'no error raised', embedded)

        legacy = {k: v for k, v in ref.items() if k != 'vk_b64'}
        legacy['vk_sha256'] = hashlib.sha256(key_bytes).hexdigest()
        check('a legacy reference still needs a local key',
              'no local verification key' in why(legacy), why(legacy))
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_vk_pinning_legacy():
    """
    References mined before vk_b64 existed carry only vk_sha256, and blocks
    cannot be rewritten -- so the digest path must keep working. These are
    hand-built dicts on purpose: build_reference no longer emits this shape.
    """
    print('\n=== verification key pinning (legacy vk_sha256 references) ===')
    with tempfile.TemporaryDirectory() as tmp:
        vk = os.path.join(tmp, 'verification_key.bin')
        with open(vk, 'wb') as f:
            f.write(b'pretend verification key')
        digest = hashlib.sha256(b'pretend verification key').hexdigest()

        def legacy_ref(vk_sha256):
            r = z.build_reference('cubic', H1, H3, 3, 41, '', CIRCUIT)
            r.pop('vk_b64')
            r['vk_sha256'] = vk_sha256
            return r

        old = os.environ.get('ZEKRA_VERIFICATION_KEY')
        os.environ['ZEKRA_VERIFICATION_KEY'] = vk
        try:
            matching = legacy_ref(digest)
            check('matching vk digest is accepted',
                  z._vk_mismatch(matching) is None)

            reason = z._vk_mismatch(legacy_ref('f' * 64))
            check('mismatched vk digest is detected', reason is not None, reason or '')

            os.environ['ZEKRA_VERIFICATION_KEY'] = os.path.join(tmp, 'missing.bin')
            reason = z._vk_mismatch(matching)
            check('a missing verification key is detected', reason is not None,
                  reason or '')

            check('a reference with neither vk field is not blocked',
                  z._vk_mismatch(legacy_ref('')) is None)
        finally:
            if old is None:
                os.environ.pop('ZEKRA_VERIFICATION_KEY', None)
            else:
                os.environ['ZEKRA_VERIFICATION_KEY'] = old


def test_public_inputs():
    print('\n=== public inputs (Option A) ===')
    ref = {'entry_node': 3, 'exit_node': 41, 'h1': H1, 'h3': H3}
    x = z.public_inputs(ref, 12353, H2)
    check('vector is [1, entry, exit, nonce, h1, h2, h3]',
          x == [1, 3, 41, 12353, int(H1), int(H2), int(H3)])

    if os.path.isfile(REAL_PI):
        with open(REAL_PI, 'rb') as f:
            real = f.read()
        check('reconstruction is byte-identical to real libsnark output',
              z.encode_primary_input(x) == real)
        check('decode(encode(v)) == v', z.decode_primary_input(real) == x)
    else:
        print('  SKIP  real primary_input.bin not staged')

    # The point of Option A: a different nonce is a different statement.
    other = z.public_inputs(ref, 12354, H2)
    check('a different nonce produces a different public input vector',
          z.encode_primary_input(other) != z.encode_primary_input(x))
    other_h1 = z.public_inputs({**ref, 'h1': '999'}, 12353, H2)
    check('a different h1 produces a different public input vector',
          z.encode_primary_input(other_h1) != z.encode_primary_input(x))


def test_signature_binding():
    print('\n=== attestation signature binding ===')
    key = Ed25519PrivateKey.generate()
    base = z.attestation_message('cubic', 'reqhash', 12353, H2)
    sig = z.sign_hex(key, base)
    check('a correct signature verifies', z.verify_sig(pubhex(key), base, sig))

    # Each of these must produce a DIFFERENT signed statement, otherwise a
    # signature could be lifted from one challenge onto another.
    for label, msg in (
        ('nonce', z.attestation_message('cubic', 'reqhash', 99999, H2)),
        ('request hash', z.attestation_message('cubic', 'other', 12353, H2)),
        ('program id', z.attestation_message('other', 'reqhash', 12353, H2)),
        ('h2', z.attestation_message('cubic', 'reqhash', 12353, '424242')),
    ):
        check(f'signature does not carry over to a different {label}',
              not z.verify_sig(pubhex(key), msg, sig))

    other_key = Ed25519PrivateKey.generate()
    check('a signature from another key does not verify',
          not z.verify_sig(pubhex(other_key), base, sig))


def test_verify_attestation_paths():
    print('\n=== verify_attestation decision table ===')
    authority = Ed25519PrivateKey.generate()
    prover = Ed25519PrivateKey.generate()
    ref = z.build_reference('cubic', H1, H3, 3, 41, '', CIRCUIT)
    envelope = z.sign_reference(ref, authority)

    old_auth = os.environ.get('ZEKRA_AUTHORITY_PUBKEY')
    os.environ['ZEKRA_AUTHORITY_PUBKEY'] = pubhex(authority)
    os.environ['ZEKRA_VERIFIER_MODE'] = 'mock'
    try:
        request = {'hash': 'req1', 'recipient': 'prover-id', 'sender': 'asker-id',
                   'program_id': 'cubic', 'function_parameter': 4242}
        proof = hashlib.sha256(
            b'zekra-mock-proof|' + z.canonical({'program_id': 'cubic',
                                                'h2': H2, 'nonce': '4242'})).digest()
        import base64
        response = {
            'sender': 'prover-id', 'recipient': 'asker-id', 'parent': 'req1',
            'program_id': 'cubic', 'h2': H2,
            'proof_b64': base64.b64encode(proof).decode(),
            'prover_pubkey': pubhex(prover),
            'prover_sig': z.sign_hex(prover, z.attestation_message(
                'cubic', 'req1', 4242, H2)),
        }

        v, d = z.verify_attestation(response, request, envelope, pubhex(prover))
        check('honest attestation -> correct', v == 'correct', d)

        v, d = z.verify_attestation(response, request, None, pubhex(prover))
        check('no reference -> abstain', v is None, d)

        rogue_env = z.sign_reference(ref, Ed25519PrivateKey.generate())
        v, d = z.verify_attestation(response, request, rogue_env, pubhex(prover))
        check('reference from an untrusted authority -> abstain', v is None, d)

        v, d = z.verify_attestation({**response, 'sender': 'someone-else'},
                                    request, envelope, pubhex(prover))
        check('answered by the wrong node -> incorrect', v == 'incorrect', d)

        v, d = z.verify_attestation(response, {**request, 'function_parameter': 9999},
                                    envelope, pubhex(prover))
        check('nonce changed under the proof -> incorrect', v == 'incorrect', d)

        v, d = z.verify_attestation(response, request, envelope,
                                    pubhex(Ed25519PrivateKey.generate()))
        check('key is not the sender registered key -> incorrect',
              v == 'incorrect', d)

        v, d = z.verify_attestation({**response, 'h2': '999'}, request, envelope,
                                    pubhex(prover))
        check('h2 tampered after signing -> incorrect', v == 'incorrect', d)

        v, d = z.verify_attestation({k: v2 for k, v2 in response.items()
                                     if k != 'prover_sig'},
                                    request, envelope, pubhex(prover))
        check('unsigned response -> incorrect', v == 'incorrect', d)
    finally:
        if old_auth is None:
            os.environ.pop('ZEKRA_AUTHORITY_PUBKEY', None)
        else:
            os.environ['ZEKRA_AUTHORITY_PUBKEY'] = old_auth


def test_find_reference_first_wins():
    """
    The chain-level lookup. Whoever publishes first defines the program, so a
    second reference must never be able to redefine it -- redefining h1 would mean
    swapping in a CFG under which any path is legal.
    """
    print('\n=== find_reference (chain lookup) ===')
    os.environ['ZEKRA_KEY_FILE'] = os.path.join(tempfile.mkdtemp(), 'node.pem')
    authority = Ed25519PrivateKey.generate()
    rogue = Ed25519PrivateKey.generate()
    old_auth = os.environ.get('ZEKRA_AUTHORITY_PUBKEY')
    os.environ['ZEKRA_AUTHORITY_PUBKEY'] = pubhex(authority)
    try:
        import FlaskBlockChain as fb
        bc = fb.Blockchain()

        genuine = z.sign_reference(
            z.build_reference('cubic', H1, H3, 3, 41, '', CIRCUIT), authority)
        shadow = z.sign_reference(
            z.build_reference('cubic', '111', '222', 9, 9, '', CIRCUIT), authority)
        forged = z.sign_reference(
            z.build_reference('cubic', '333', '444', 7, 7, '', CIRCUIT), rogue)

        def block(*envelopes):
            return {'index': len(bc.chain) + 1, 'timestamp': '', 'proof': 0,
                    'previous_hash': '0',
                    'transactions': [{'transaction_type': z.REFERENCE_TX_TYPE,
                                      'program_id': e['reference']['program_id'],
                                      'reference_envelope': e, 'hash': str(i)}
                                     for i, e in enumerate(envelopes)]}

        check('no reference on an empty chain', bc.find_reference('cubic') is None)

        bc.chain.append(block(forged))
        check('a reference from an untrusted authority is not used',
              bc.find_reference('cubic') is None)

        bc.chain.append(block(genuine))
        found = bc.find_reference('cubic')
        check('the genuine reference is found past the forged one',
              found is not None and found['reference']['h1'] == H1)

        bc.chain.append(block(shadow))
        found = bc.find_reference('cubic')
        check('a later reference cannot redefine the program (first wins)',
              found is not None and found['reference']['h1'] == H1,
              f"h1 now {found['reference']['h1'][:12] if found else None}...")

        check('an unknown program has no reference',
              bc.find_reference('nonexistent') is None)
    finally:
        if old_auth is None:
            os.environ.pop('ZEKRA_AUTHORITY_PUBKEY', None)
        else:
            os.environ['ZEKRA_AUTHORITY_PUBKEY'] = old_auth


def main():
    for fn in (test_reference_trust, test_vk_embedded, test_vk_pinning_legacy,
               test_public_inputs,
               test_signature_binding, test_verify_attestation_paths,
               test_find_reference_first_wins):
        fn()
    print('\n' + '=' * 62)
    print(f'  {len(PASS)} passed, {len(FAIL)} failed')
    for f in FAIL:
        print(f'    FAILED: {f}')
    print('=' * 62)
    return 0 if not FAIL else 1


if __name__ == '__main__':
    sys.exit(main())
