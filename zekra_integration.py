"""
zekra_integration.py

Bridge between the Flask blockchain and ZEKRA's zero-knowledge attestation.

This module knows nothing about blocks or consensus. FlaskBlockChain.py imports a
handful of names from it; everything ZEKRA-specific lives here so it stays
independently testable and so a node without the ZEKRA tooling can still run.

===============================================================================
THE THREE CHECKS (ZEKRA paper, Fig. 2)
===============================================================================
A verifier accepts an attestation only if ALL of:

  (1)  Vf(Sig, h2, tpk) = 1
       The path commitment h2 was signed by the prover's key. Without this,
       ANYONE holding the CFG can fabricate a legal path and prove it -- the
       paper says so directly in section 5. The zkSNARK proves a path is LEGAL,
       never that it was EXECUTED. This signature is the only thing tying an
       attestation to a particular party.

  (2)  x \\ {h2} == { h1, h3, n_entry, n_exit, nce }
       The proof's public inputs equal the values WE expect: the reference
       material for this program, and the nonce THIS challenge issued. Without
       this, a proof from an earlier attestation still verifies -- it is a
       perfectly valid proof, just of a stale statement. This is the entire
       anti-replay and right-program mechanism.

  (3)  Verify(vk, x, y, pi) = 1
       The SNARK itself. This is what run_verifier_only does, and it is the ONLY
       one of the three that the previous version of this file implemented.

===============================================================================
HOW CHECK (2) IS ENFORCED: "OPTION A"
===============================================================================
A verifier must never take public inputs from the party it is verifying. So we
do NOT accept a primary_input.bin from the responder. We BUILD it, from:

    n_entry, n_exit, h1, h3   <- the authority-signed on-chain reference
    nce                       <- the nonce on the request transaction, on-chain
    h2                        <- the responder (see below)

and hand our own construction to the verifier. If the proof was generated for any
other statement -- different program, different nonce, replayed from last week --
the SNARK check fails. Check (2) therefore cannot be bypassed by a lying
responder, because a lying responder never gets to state the claim.

h2 is the one value that legitimately comes from the responder: it is
H(EP || nce || r2), a commitment to the secret execution path. That is precisely
what is being attested, and it is exactly what check (1)'s signature covers.

The wire format was determined empirically from real libsnark output and is
verified by a round-trip test against a genuine primary_input.bin:

    b"<count>\\n" followed by <count> 32-byte little-endian field elements
    in MONTGOMERY form (value * 2^256 mod p)

    element order:  [0]=1 (constant)  [1]=n_entry  [2]=n_exit
                    [3]=nce  [4]=h1  [5]=h2  [6]=h3

===============================================================================
WHAT THIS DOES AND DOES NOT PROVE
===============================================================================
With a real trusted tracer, check (1) means "this path was recorded by attested
hardware on the prover". We do not have one: paths come from the extractor. So
here, check (1) means "this response was produced by the node that claims to have
produced it" -- node authentication, not execution attestation.

That is still worth having, and not only as scaffolding: the chain currently has
no signatures at all, so any node can POST a response naming someone else as
sender. This closes that. When a real tracer arrives, only the key's provenance
changes; none of the verification logic does.

===============================================================================
CONFIGURATION (environment variables)
===============================================================================
ZEKRA_VERIFIER_MODE      "real" or "mock" (default: real if the binary exists)
ZEKRA_VERIFIER_BIN       path to run_verifier_only
ZEKRA_VERIFICATION_KEY   path to verification_key.bin
ZEKRA_KEY_FILE           this node's Ed25519 signing key (created if absent)
ZEKRA_AUTHORITY_KEY_FILE authority signing key -- ONLY on the authority node
ZEKRA_AUTHORITY_PUBKEY   authority public key (hex) that references must carry
ZEKRA_PROGRAM_DIR        directory of program materials this node can prove for
ZEKRA_VERIFIER_TIMEOUT   seconds (default 120)
"""

import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

ZEKRA_FUNCTION_NAME = 'zekra_attestation'
REFERENCE_TX_TYPE = 'reference'

# BN254 / alt_bn128 scalar field -- the field the ZEKRA circuit is defined over.
FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
_MONT_R = (2 ** 256) % FIELD_P

# The circuit parameters an attestation is bound to. A proof is only meaningful
# against the circuit it was compiled for, so these travel inside the signed
# reference: a mismatch would otherwise surface as an unexplained rejection.
CIRCUIT_PARAM_KEYS = (
    'adjlist_len', 'adjlist_levels', 'path_len', 'stack_depth',
    'label_bitwidth', 'bucket_bitwidth', 'address_bitwidth',
)


class ZekraVerificationError(Exception):
    """
    The verifier could not reach a clean accept/reject conclusion -- missing
    binary, crash, timeout, unusable reference.

    Distinct from a proof being REJECTED. A rejection is a verdict about the
    responder; an error here means "this node is not in a position to judge",
    which the caller turns into an abstention rather than an accusation.
    """


class ZekraProofError(Exception):
    """This node could not produce a proof for a request."""


# ---------------------------------------------------------------------------
# Configuration helpers (read at call time so tests can adjust env freely)
# ---------------------------------------------------------------------------

def _env(name, default=''):
    return os.environ.get(name, default)


def verifier_mode():
    explicit = _env('ZEKRA_VERIFIER_MODE').strip().lower()
    if explicit in ('real', 'mock'):
        return explicit
    binary = _env('ZEKRA_VERIFIER_BIN')
    return 'real' if binary and os.path.isfile(binary) else 'mock'


def status():
    """Diagnostic snapshot, served by /zekra/status."""
    binary, vk = _env('ZEKRA_VERIFIER_BIN'), _env('ZEKRA_VERIFICATION_KEY')
    return {
        'mode': verifier_mode(),
        'verifier_binary': binary or None,
        'verifier_binary_present': bool(binary) and os.path.isfile(binary),
        'verification_key': vk or None,
        'verification_key_present': bool(vk) and os.path.isfile(vk),
        'node_pubkey': node_public_key_hex(),
        'authority_pubkey': _env('ZEKRA_AUTHORITY_PUBKEY') or None,
        'is_authority': bool(_env('ZEKRA_AUTHORITY_KEY_FILE')),
        'program_dir': _env('ZEKRA_PROGRAM_DIR') or None,
        'provable_programs': sorted(available_programs()),
    }


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

def _load_or_create_key(path):
    """
    Load an Ed25519 private key, creating it on first use.

    Persistent by design: the key is this node's attestation identity, so it must
    survive restarts. (node_identifier does not, which is a separate problem --
    see the note in the reference-lookup code.) The alternative, generating a
    fresh key per process, is simpler but silently changes who the node claims to
    be every time it restarts.
    """
    if path and os.path.isfile(path):
        with open(path, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    key = Ed25519PrivateKey.generate()
    if path:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or '.', exist_ok=True)
        with open(path, 'wb') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()))
        os.chmod(path, 0o600)
    return key


_node_key = None


def node_private_key():
    global _node_key
    if _node_key is None:
        _node_key = _load_or_create_key(_env('ZEKRA_KEY_FILE'))
    return _node_key


def node_public_key_hex():
    return node_private_key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()


def _pubkey_from_hex(hex_str):
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))


def sign_hex(private_key, message):
    return private_key.sign(message).hex()


def verify_sig(pubkey_hex, message, signature_hex):
    try:
        _pubkey_from_hex(pubkey_hex).verify(bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Reference material
# ---------------------------------------------------------------------------

def canonical(obj):
    """Deterministic bytes for signing. Sorted keys, no incidental whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()


def build_reference(program_id, h1, h3, entry_node, exit_node, vk_b64,
                    circuit_params):
    """
    Assemble the reference the authority signs.

    vk_b64 carries the verification key ITSELF, not a digest of it. The key is
    public by construction -- it exists so anyone can verify -- and it reveals
    nothing about the CFG, which is a secret witness rather than part of the
    circuit. Publishing it (808 bytes, once per program) means a verifier needs
    no locally provisioned key at all, so it can never abstain because of its own
    misconfiguration, and a rejection becomes an unambiguous statement about the
    responder.

    An earlier version published vk_sha256 instead. That bought nothing: the
    authority signature is already fully load-bearing for soundness through h1 --
    anyone able to sign a reference can name a CFG they wrote themselves and
    prove against it -- so withholding the key did not narrow a compromise. It
    also allowed a signed reference to contradict itself once both fields
    existed. Verification still ACCEPTS references carrying only vk_sha256,
    because references already mined cannot be rewritten.
    """
    missing = [k for k in CIRCUIT_PARAM_KEYS if k not in circuit_params]
    if missing:
        raise ValueError(f'circuit params missing: {missing}')
    circuit = {k: int(circuit_params[k]) for k in CIRCUIT_PARAM_KEYS}
    # Optional, and only present when true, so references built before this
    # existed still verify byte-for-byte. It tells the prover to feed
    # circuit_input_formatter.py the pruned CFG files -- pruning changes the
    # adjacency list, hence h1 and h3, so the authority has to pin which of the
    # two variants its digests were computed over. Getting it wrong is not a
    # security hole (the prover's own h1/h3 cross-check refuses to proceed), but
    # without it a pruned program simply cannot be attested.
    if circuit_params.get('pruned'):
        circuit['pruned'] = True
    return {
        'program_id': program_id,
        'h1': str(h1),
        'h3': str(h3),
        'entry_node': int(entry_node),
        'exit_node': int(exit_node),
        'vk_b64': vk_b64,
        'circuit': circuit,
    }


def sign_reference(reference, authority_key):
    """Produce the signed envelope that goes on-chain."""
    return {
        'reference': reference,
        'authority_pubkey': authority_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw).hex(),
        'authority_sig': sign_hex(authority_key, canonical(reference)),
    }


def verify_reference(envelope, expected_authority_pubkey=None):
    """
    Check a reference envelope's authority signature.

    :return: (reference_dict, None) if trustworthy, else (None, reason)

    A reference that fails here is treated as ABSENT, not as evidence against
    anyone -- it says the publisher is untrustworthy, which is not a statement
    about the node being verified.
    """
    if not isinstance(envelope, dict):
        return None, 'reference envelope is not an object'
    reference = envelope.get('reference')
    pubkey = envelope.get('authority_pubkey')
    sig = envelope.get('authority_sig')
    if not (isinstance(reference, dict) and pubkey and sig):
        return None, 'reference envelope is incomplete'

    expected = expected_authority_pubkey or _env('ZEKRA_AUTHORITY_PUBKEY')
    if expected and pubkey.lower() != expected.lower():
        return None, (f'reference signed by {pubkey[:16]}... but this node only '
                      f'trusts {expected[:16]}...')

    if not verify_sig(pubkey, canonical(reference), sig):
        return None, 'authority signature does not verify'

    for key in ('program_id', 'h1', 'h3', 'entry_node', 'exit_node'):
        if key not in reference:
            return None, f'reference is missing {key}'
    circuit = reference.get('circuit') or {}
    missing = [k for k in CIRCUIT_PARAM_KEYS if k not in circuit]
    if missing:
        return None, f'reference circuit params missing: {missing}'

    return reference, None


# ---------------------------------------------------------------------------
# Public inputs -- Option A
# ---------------------------------------------------------------------------

def public_inputs(reference, nonce, h2):
    """
    The public input vector x, in the circuit's own order.

    Everything except h2 is pinned by us. h2 is the responder's commitment to the
    execution path, which is the thing being attested.
    """
    return [
        1,
        int(reference['entry_node']),
        int(reference['exit_node']),
        int(nonce),
        int(reference['h1']),
        int(h2),
        int(reference['h3']),
    ]


def encode_primary_input(values):
    """
    Serialise field elements the way libsnark's operator<< does.

    ASCII count, newline, then one 32-byte little-endian Montgomery-form
    (value * 2^256 mod p) element each. Verified by round-tripping a real
    primary_input.bin produced by run_prover_raw.
    """
    out = bytearray(f'{len(values)}\n'.encode())
    for v in values:
        out += (((int(v) % FIELD_P) * _MONT_R) % FIELD_P).to_bytes(32, 'little')
    return bytes(out)


def decode_primary_input(blob):
    """Inverse of encode_primary_input. Used by the round-trip test."""
    nl = blob.index(b'\n')
    count = int(blob[:nl])
    body = blob[nl + 1:]
    if len(body) != count * 32:
        raise ValueError(f'expected {count * 32} bytes of field elements, '
                         f'got {len(body)}')
    r_inv = pow(_MONT_R, -1, FIELD_P)
    return [((int.from_bytes(body[i * 32:(i + 1) * 32], 'little') * r_inv)
             % FIELD_P) for i in range(count)]


# ---------------------------------------------------------------------------
# The prover's signed statement (check 1)
# ---------------------------------------------------------------------------

def attestation_message(program_id, request_hash, nonce, h2):
    """
    Exactly what a prover signs.

    Covers h2 (the path commitment, as the paper requires) AND the challenge it
    answers. Signing h2 alone would let a signature be lifted onto a different
    request; binding the request hash and nonce makes the signature answer one
    specific challenge and no other.
    """
    return canonical({
        'program_id': program_id,
        'request_hash': request_hash,
        'nonce': str(nonce),
        'h2': str(h2),
    })


# ---------------------------------------------------------------------------
# Program materials (prover side only)
# ---------------------------------------------------------------------------

def program_dir(program_id):
    root = _env('ZEKRA_PROGRAM_DIR')
    if not root:
        return None
    path = os.path.join(root, program_id)
    return path if os.path.isdir(path) else None


def available_programs():
    """
    Programs this node can PROVE for.

    Deliberately narrow. Only a node that may be challenged for a program needs
    its CFG and blinding factors r1/r3; verifiers need nothing but the digests.
    Keeping materials off verifier nodes preserves ZEKRA's CFG privacy and
    shrinks the set of parties who could fabricate a legal path at all.
    """
    root = _env('ZEKRA_PROGRAM_DIR')
    if not root or not os.path.isdir(root):
        return []
    return [d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))]


# ---------------------------------------------------------------------------
# Proof generation (mock / real)
# ---------------------------------------------------------------------------

def generate_attestation(program_id, request_hash, nonce, reference):
    """
    Produce an attestation for a challenge.

    :return: dict with h2, proof_b64, prover_pubkey, prover_sig
    :raises ZekraProofError: if this node holds no materials for the program
    """
    materials = program_dir(program_id)
    if materials is None:
        raise ZekraProofError(
            f'no program materials for {program_id!r} on this node -- it is not a '
            f'designated prover for that program')

    if verifier_mode() == 'mock':
        h2, proof = _prove_mock(program_id, nonce, materials)
    else:
        h2, proof = _prove_real(program_id, nonce, materials, reference)

    key = node_private_key()
    return {
        'h2': str(h2),
        'proof_b64': base64.b64encode(proof).decode('ascii'),
        'prover_pubkey': node_public_key_hex(),
        'prover_sig': sign_hex(
            key, attestation_message(program_id, request_hash, nonce, h2)),
    }


def sample_blinding():
    """
    A blinding factor / nonce the ZEKRA tooling will actually accept.

    circuit_input_formatter.py rejects any nonce whose bit length is >= 254 --
    and it does so by printing a message and calling sys.exit() with NO error
    status, producing no output files. A caller that only checks the return code
    sees success and then reads whatever digests were left in the working
    directory by the previous attestation.

    secrets.randbelow(FIELD_P) is 254 bits about a third of the time, so sampling
    over the full field would silently poison roughly one attestation in three.
    Sampling below 2**253 keeps every value inside what the formatter accepts,
    and 253 bits of entropy is ample for a blinding factor.
    """
    return secrets.randbelow(1 << 253)


def _mock_r2(materials):
    """
    The path blinding factor r2. Fresh per attestation, as the paper requires.

    In the real pipeline this is --nonce-path and is sampled by the prover's
    tracer. Freshness is what stops h2 from being a stable identifier for
    "this program ran this path", which would leak across attestations.
    """
    return sample_blinding()


def _prove_mock(program_id, nonce, materials):
    """
    Stand-in prover for testing without libsnark.

    h2 simulates H(EP || nce || r2): it commits to a path, the challenge nonce,
    and a fresh blinding factor. The 'proof' is a digest over the full public
    input tuple, so the mock verifier can only accept it when every pinned value
    matches -- which makes replay and wrong-program genuinely testable.
    """
    with open(os.path.join(materials, 'path'), 'rb') as f:
        execution_path = f.read()

    r2 = _mock_r2(materials)
    h2 = int.from_bytes(
        hashlib.sha256(canonical({'ep': execution_path.decode('utf-8', 'replace'),
                                  'nce': str(nonce), 'r2': str(r2)})).digest(),
        'big') % FIELD_P
    proof = hashlib.sha256(
        b'zekra-mock-proof|' + canonical({'program_id': program_id,
                                          'h2': str(h2),
                                          'nonce': str(nonce)})).digest()
    return h2, proof


def _run(cmd, cwd=None, timeout=None, what='command'):
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout or int(_env('ZEKRA_PROVER_TIMEOUT', '1800')))
    except subprocess.TimeoutExpired as e:
        raise ZekraProofError(f'{what} timed out') from e
    except OSError as e:
        raise ZekraProofError(f'could not run {what}: {e}') from e
    if r.returncode != 0:
        raise ZekraProofError(
            f'{what} failed (exit {r.returncode})\n--- stdout ---\n{r.stdout[-2000:]}\n'
            f'--- stderr ---\n{r.stderr[-2000:]}')
    return r.stdout


def _prove_real(program_id, nonce, materials, reference):
    """
    Generate a genuine ZEKRA attestation with the real toolchain.

    Pipeline, per challenge:

      1. circuit_input_formatter.py   program materials + THIS challenge's nonce
                                      -> in_* files, including h2
      2. the compiled xjsnark class   evaluates the circuit on those inputs
                                      -> zekra_Sample_Run1.in (the witness)
      3. run_prover_raw               witness + proving key -> proof.bin

    IMPORTANT -- why there is no javac here. compile_circuit.py bakes the input
    and output directory paths into the Java source and recompiles, so changing
    them needs a JDK. Doing that per attestation would be absurd, and provers may
    not have a JDK at all. Instead the circuit is compiled ONCE against a fixed
    working directory (ZEKRA_CIRCUIT_INPUT_DIR / ZEKRA_CIRCUIT_OUTPUT_DIR), and
    every attestation writes its inputs into that same directory and re-runs the
    already-compiled class with a plain JRE.

    Circuit parameters come from the authority-signed REFERENCE, not from local
    config. They must match the circuit the proving key was generated for, and the
    reference is the only thing every party agrees on.

    r1 (adjlist blinding) and r3 (translator blinding) are secret and live with
    the program materials. r2 (path blinding) is sampled fresh per attestation --
    reusing it would make h2 a stable identifier for "this path ran", leaking
    across attestations.
    """
    formatter = _env('ZEKRA_FORMATTER')
    in_dir = _env('ZEKRA_CIRCUIT_INPUT_DIR')
    out_dir = _env('ZEKRA_CIRCUIT_OUTPUT_DIR')
    java_cp = _env('ZEKRA_JAVA_CP')
    java_class = _env('ZEKRA_JAVA_CLASS', 'xjsnark.zekra.zekra')
    java_home = _env('ZEKRA_JAVA_DIR')          # where bin/ and the jar live
    prover = _env('ZEKRA_PROVER_BIN')
    arith = _env('ZEKRA_ARITH')
    pk = _env('ZEKRA_PROVING_KEY')
    meta = _env('ZEKRA_CIRCUIT_METADATA')

    missing = [n for n, v in (('ZEKRA_FORMATTER', formatter),
                              ('ZEKRA_CIRCUIT_INPUT_DIR', in_dir),
                              ('ZEKRA_CIRCUIT_OUTPUT_DIR', out_dir),
                              ('ZEKRA_JAVA_CP', java_cp),
                              ('ZEKRA_PROVER_BIN', prover),
                              ('ZEKRA_ARITH', arith),
                              ('ZEKRA_PROVING_KEY', pk),
                              ('ZEKRA_CIRCUIT_METADATA', meta)) if not v]
    if missing:
        raise ZekraProofError(f'real prover is not configured: {", ".join(missing)} '
                              f'not set')

    circuit = reference.get('circuit') or {}
    params = {k: circuit.get(k) for k in CIRCUIT_PARAM_KEYS}
    if any(v is None for v in params.values()):
        raise ZekraProofError('reference does not pin the circuit parameters')

    # Secret blinding factors, shipped with the program materials.
    r1, r3 = _program_blinding(materials)
    r2 = sample_blinding()

    os.makedirs(in_dir, exist_ok=True)
    os.makedirs(out_dir, exist_ok=True)

    # ---- 1. format the circuit inputs for THIS nonce ----------------------
    # Wipe the working directory first. The circuit is compiled once against a
    # FIXED input directory, so last attestation's in_* files are sitting right
    # where this one's are about to go. circuit_input_formatter.py can bail out
    # after printing a message while still exiting 0 (it does exactly that for an
    # out-of-range nonce), and a caller that only checks the exit status would
    # then read the PREVIOUS challenge's digests and sign them as this one's.
    # Removing them first turns any such failure into a loud FileNotFoundError.
    for stale in os.listdir(in_dir) if os.path.isdir(in_dir) else []:
        if stale.startswith('in_'):
            os.remove(os.path.join(in_dir, stale))

    _run([sys.executable, formatter, '-a', materials]
         + (['--pruned'] if circuit.get('pruned') else []) +
         ['--pad-adjlist-to', str(params['adjlist_len']),
          '--pad-path-to', str(params['path_len']),
          '--adjlist-levels', str(params['adjlist_levels']),
          '--label-bitwidth', str(params['label_bitwidth']),
          '--bucket-bitwidth', str(params['bucket_bitwidth']),
          '--address-bitwidth', str(params['address_bitwidth']),
          '--nonce-verifier', str(nonce),
          '--nonce-path', str(r2),
          '--nonce-adjlist', str(r1),
          '--nonce-translator', str(r3),
          '--output-dir', in_dir],
         what='circuit_input_formatter.py')

    digest_path = os.path.join(in_dir, 'in_recorded_path_digest')
    if not os.path.isfile(digest_path):
        raise ZekraProofError(
            f'the formatter exited cleanly but wrote no digests to {in_dir}. It '
            f'refuses out-of-range nonces this way -- check that nce and the '
            f'blinding factors are all under 254 bits.')
    with open(digest_path) as f:
        h2 = int(f.read().strip())

    # Sanity: the digests we just produced must match what the authority signed.
    # If they do not, this node's program materials are not the program the
    # network agreed on, and any proof we generate would be rejected by everyone.
    for name, key in (('in_encoded_adjlist_digest', 'h1'),
                      ('in_translator_digest', 'h3')):
        with open(os.path.join(in_dir, name)) as f:
            produced = f.read().strip()
        if produced != str(reference[key]):
            # Show head AND tail: these are 77-digit field elements, and two
            # different ones very often share a long prefix. Truncating to a
            # prefix alone prints two identical-looking numbers in the one
            # message whose whole job is to show they differ.
            def _brief(v):
                v = str(v)
                return v if len(v) <= 28 else f'{v[:14]}...{v[-10:]}'
            raise ZekraProofError(
                f'our materials produce {key}={_brief(produced)} but the signed '
                f'reference says {_brief(reference[key])} -- wrong program, '
                f'wrong blinding factor, or wrong circuit parameters')

    # ---- 2. evaluate the circuit to get the witness -----------------------
    # Delete any existing witness first, for the same reason the inputs are
    # cleared above. compile_circuit.py BAKES the output path into the Java
    # source, so if the compiled class was built against a different directory
    # than ZEKRA_CIRCUIT_OUTPUT_DIR it writes its witness elsewhere and leaves
    # this one untouched -- and a leftover witness from an earlier attestation
    # would then be proved against, yielding a perfectly valid proof of the
    # WRONG statement. The h1/h3 cross-check cannot catch that: it inspects the
    # formatter's output, which was correct; only the witness is stale.
    witness = os.path.join(out_dir, 'zekra_Sample_Run1.in')
    if os.path.isfile(witness):
        os.remove(witness)

    _run(['java', '-Xmx4g', '-cp', java_cp, java_class],
         cwd=java_home or None, what='xjsnark witness generation')

    if not os.path.isfile(witness):
        raise ZekraProofError(
            f'no witness at {witness}. Either the circuit was not satisfied (an '
            f'unsatisfied circuit writes no witness, which usually means the '
            f'execution path is illegal for the referenced CFG), or the compiled '
            f'class writes elsewhere -- it has its input and output directories '
            f'baked in at compile time, and they must match '
            f'ZEKRA_CIRCUIT_INPUT_DIR / ZEKRA_CIRCUIT_OUTPUT_DIR.')

    # ---- 3. prove ----------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        _run([prover, arith, pk, meta, witness, tmp], what='run_prover_raw')
        proof_path = os.path.join(tmp, 'proof.bin')
        if not os.path.isfile(proof_path):
            raise ZekraProofError(f'run_prover_raw produced no proof in {tmp}')
        with open(proof_path, 'rb') as f:
            proof = f.read()
        # NOTE: run_prover_raw also writes primary_input.bin. We deliberately
        # discard it -- verifiers rebuild the public inputs themselves (Option A),
        # so shipping ours would be pointless at best and a way to smuggle a
        # different claim at worst.

    return h2, proof


def _program_blinding(materials):
    """
    The program's secret blinding factors r1 and r3.

    These live with the program materials because they are part of what a
    licensee receives, and they must stay off verifier nodes: publishing them
    alongside the digests would let anyone recompute h1 from a candidate CFG and
    strip the statistical hiding the paper relies on.
    """
    path = os.path.join(materials, 'blinding.json')
    if not os.path.isfile(path):
        raise ZekraProofError(
            f'no blinding.json in {materials} -- the program materials must carry '
            f'the r1/r3 the reference digests were computed with')
    with open(path) as f:
        data = json.load(f)
    try:
        return int(data['r1_adjlist']), int(data['r3_translator'])
    except (KeyError, TypeError, ValueError) as e:
        raise ZekraProofError(f'blinding.json is malformed: {e}') from e


# ---------------------------------------------------------------------------
# Verification -- checks (1), (2), (3)
# ---------------------------------------------------------------------------

def verify_attestation(response, request, reference_envelope, prover_pubkey=None):
    """
    Run all three ZEKRA checks against a response transaction.

    :param response: the response transaction (carries h2, proof, signature)
    :param request:  the request transaction it answers (carries nonce, program)
    :param reference_envelope: the signed reference from the chain, or None
    :param prover_pubkey: the sender's registered public key, if the caller has
        one. When given, the response's embedded key must match it -- otherwise a
        responder could simply attach a key it just made up.

    :return: (verdict, detail) where verdict is 'correct', 'incorrect', or None
             to abstain.
    """
    program_id = response.get('program_id')

    # --- the reference must be present and trustworthy ----------------------
    if reference_envelope is None:
        return None, (f'no reference for program {program_id!r} on our chain yet '
                      f'-- abstaining rather than blaming the responder')
    reference, why = verify_reference(reference_envelope)
    if reference is None:
        return None, f'reference is not trustworthy ({why}) -- abstaining'

    # --- the responder must be the node that was actually challenged --------
    # Without this, node X can answer a challenge addressed to node Y, sign it
    # perfectly well with X's own key, and every check below passes -- crediting
    # X with an attestation that Y was asked for. That is issue 1 (identity
    # misattribution) reappearing at the attestation layer: a valid signature
    # proves WHO signed, not that they were the one asked.
    if response.get('sender') != request.get('recipient'):
        return 'incorrect', (f"response came from {str(response.get('sender'))[:12]}... "
                             f"but the challenge was addressed to "
                             f"{str(request.get('recipient'))[:12]}...")

    # --- the response must answer THIS request, for THIS program ------------
    if request.get('program_id') != program_id:
        return 'incorrect', (f"response is for program {program_id!r} but the "
                             f"request asked for {request.get('program_id')!r}")
    if reference['program_id'] != program_id:
        return None, (f"reference is for {reference['program_id']!r}, not "
                      f'{program_id!r} -- abstaining')

    nonce = request.get('function_parameter')
    if nonce is None:
        return 'incorrect', 'request carries no nonce'

    h2 = response.get('h2')
    if h2 is None:
        return 'incorrect', 'response carries no path commitment h2'
    try:
        int(h2)
    except (TypeError, ValueError):
        return 'incorrect', f'h2 is not an integer: {h2!r}'

    # --- CHECK (1): the prover signed this exact statement -------------------
    sig = response.get('prover_sig')
    pubkey = response.get('prover_pubkey')
    if not sig or not pubkey:
        return 'incorrect', 'response is not signed'
    if prover_pubkey and pubkey.lower() != prover_pubkey.lower():
        return 'incorrect', ('response is signed with a key that is not the '
                             "sender's registered key")
    message = attestation_message(program_id, response.get('parent'), nonce, h2)
    if not verify_sig(pubkey, message, sig):
        return 'incorrect', 'prover signature does not verify (check 1)'

    # --- CHECK (2): build the public inputs OURSELVES ------------------------
    # Nothing from the responder except h2. A replayed proof fails here because
    # the nonce we pin comes from the request on the chain, not from the response.
    try:
        x = public_inputs(reference, nonce, h2)
    except (TypeError, ValueError) as e:
        return 'incorrect', f'could not build public inputs: {e}'

    proof_b64 = response.get('proof_b64')
    if not proof_b64:
        return 'incorrect', 'response carries no proof'
    try:
        proof = base64.b64decode(proof_b64, validate=True)
    except (ValueError, TypeError) as e:
        return 'incorrect', f'proof is not valid base64: {e}'

    # --- LEGACY references only: our local key must be the pinned one ---------
    # References that carry vk_b64 need none of this -- we verify with the key
    # the authority signed, so there is nothing to disagree with. This branch
    # exists solely for references mined before vk_b64, which cannot be
    # rewritten. There, a vk for a different circuit rejects every honest proof,
    # and publishing "incorrect" would slander honest provers for OUR
    # misconfiguration, so it abstains instead.
    if verifier_mode() == 'real' and not (reference or {}).get('vk_b64'):
        mismatch = _vk_mismatch(reference)
        if mismatch:
            return None, f'{mismatch} -- abstaining rather than blaming the responder'

    # --- CHECK (3): the SNARK ------------------------------------------------
    try:
        ok = _verify_proof(x, proof, program_id, nonce, h2, reference)
    except ZekraVerificationError as e:
        return None, f'verifier could not run ({e}) -- abstaining'

    return ('correct', 'all three checks passed') if ok else \
           ('incorrect', 'SNARK verification failed (check 3)')


def _vk_mismatch(reference):
    """
    Is our local verification key the one this reference was issued against?

    LEGACY. Only reached for references that carry vk_sha256 and no vk_b64.
    New references ship the key itself, leaving nothing to compare.

    :return: a reason string if it is not usable, else None.
    """
    expected = (reference or {}).get('vk_sha256')
    if not expected:
        return None                      # reference predates vk pinning
    vk = _env('ZEKRA_VERIFICATION_KEY')
    if not vk or not os.path.isfile(vk):
        return f'verification key not found at {vk!r}'
    with open(vk, 'rb') as f:
        actual = hashlib.sha256(f.read()).hexdigest()
    if actual.lower() != expected.lower():
        return (f'our verification key is {actual[:16]}... but the reference for '
                f'{reference.get("program_id")!r} was issued against '
                f'{expected[:16]}...')
    return None


def _warn_if_local_vk_differs(signed_vk_bytes):
    """
    Log when a locally configured key disagrees with the signed one.

    Not a verdict input. The signed key is what we verify with either way -- this
    only tells an operator their local provisioning has drifted, which used to
    surface as an inexplicable abstention.
    """
    local = _env('ZEKRA_VERIFICATION_KEY')
    if not local or not os.path.isfile(local):
        return
    with open(local, 'rb') as f:
        if f.read() != signed_vk_bytes:
            print(f'Note: local verification key {local} differs from the one '
                  f'signed into the reference; verifying with the signed key.')


def _verify_proof(x, proof, program_id, nonce, h2, reference=None):
    if verifier_mode() == 'mock':
        expected = hashlib.sha256(
            b'zekra-mock-proof|' + canonical({'program_id': program_id,
                                              'h2': str(h2),
                                              'nonce': str(nonce)})).digest()
        # Constant-time compare is not security-critical for a mock, but the
        # binding is: the digest covers the nonce, so a replayed proof fails.
        return secrets.compare_digest(proof, expected)
    return _verify_real(x, proof, reference)


def _verify_real(x, proof, reference=None):
    """
    Invoke run_verifier_only with OUR OWN primary_input.bin (Option A).

    The verification key comes from the authority-signed reference when it
    carries one. The reference is the authority on which circuit a program uses;
    a locally configured key is the weaker source, so the signed key wins and any
    divergence is logged rather than allowed to decide the verdict. Only
    references predating vk_b64 fall back to ZEKRA_VERIFICATION_KEY.

    exit 0 -> ACCEPTED, 1 -> REJECTED, anything else -> the verifier failed.
    """
    binary = _env('ZEKRA_VERIFIER_BIN')
    if not binary or not os.path.isfile(binary):
        raise ZekraVerificationError(f'verifier binary not found: {binary!r}')

    signed_vk = (reference or {}).get('vk_b64')
    vk_bytes = None
    if signed_vk:
        try:
            vk_bytes = base64.b64decode(signed_vk, validate=True)
        except (ValueError, TypeError) as e:
            raise ZekraVerificationError(
                f'reference carries an unusable vk_b64: {e}')
        if not vk_bytes:
            raise ZekraVerificationError('reference carries an empty vk_b64')
        _warn_if_local_vk_differs(vk_bytes)
    else:
        local = _env('ZEKRA_VERIFICATION_KEY')
        if not local or not os.path.isfile(local):
            raise ZekraVerificationError(
                f'reference carries no vk_b64 and no local verification key '
                f'was found at {local!r}')
        with open(local, 'rb') as f:
            vk_bytes = f.read()

    try:
        timeout = int(_env('ZEKRA_VERIFIER_TIMEOUT', '120'))
    except ValueError:
        timeout = 120

    with tempfile.TemporaryDirectory() as tmp:
        pi_path = os.path.join(tmp, 'primary_input.bin')
        proof_path = os.path.join(tmp, 'proof.bin')
        vk = os.path.join(tmp, 'verification_key.bin')
        with open(vk, 'wb') as f:
            f.write(vk_bytes)
        with open(pi_path, 'wb') as f:
            f.write(encode_primary_input(x))
        with open(proof_path, 'wb') as f:
            f.write(proof)
        try:
            result = subprocess.run([binary, 'gg', vk, pi_path, proof_path],
                                    capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            raise ZekraVerificationError(f'verifier timed out after {timeout}s') from e
        except OSError as e:
            raise ZekraVerificationError(f'could not execute {binary!r}: {e}') from e

    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise ZekraVerificationError(
        f'verifier exited {result.returncode}\n--- stdout ---\n{result.stdout}\n'
        f'--- stderr ---\n{result.stderr}')


def attestation_fingerprint(h2, proof_b64):
    """Short display value for the transaction's function_parameter slot."""
    return hashlib.sha256(f'{h2}|{proof_b64}'.encode()).hexdigest()[:16]
