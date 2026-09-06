#!/usr/bin/python3
"""
zekra_authority.py

Create and publish the authority-signed reference material for an attested
program.

WHY AN AUTHORITY
----------------
Every verifier needs {h1, h3, n_entry, n_exit, vk, circuit params} to check an
attestation, and all of them must agree on those values. If any node could
publish a reference, whoever published first would define what "program cubic"
means -- and since a reference pins the CFG digest, controlling it means being
able to declare a CFG under which any path is legal. So references are signed by
a designated authority (in the paper's terms, the party that produced the program
and its reference materials), and nodes only trust references carrying that key.

WHAT IS AND IS NOT PUBLISHED
----------------------------
Published (public, on-chain):  h1, h3, n_entry, n_exit, the vk itself, circuit params
NOT published (secret, given only to nodes that must PROVE for this program):
                               the CFG itself, the translator M, and the blinding
                               factors r1 and r3

That split is what preserves ZEKRA's privacy goal. A verifier can check an
attestation knowing only digests; it never learns the program's control-flow
graph. It also shrinks the set of parties able to fabricate a legal path to the
designated provers -- who are also the only ones holding a signing key that would
make such a fabrication verifiable.

Note h1 is NOT a function of the program alone. It is H(encoded_padded_CFG || r1),
so it also depends on the adjacency-list padding, the encoding parameters
(adjlist-levels, bucket-bitwidth) and r1. Measured: changing the padding, the
levels, the bucket bitwidth or r1 each changes h1; changing the verifier nonce or
the path nonce does not. That is exactly why the circuit parameters are signed
into the reference -- resize the circuit and h1 must be republished, and a
mismatch would otherwise show up as an unexplained rejection.

USAGE
-----
  # one-time: create the authority key
  zekra_authority.py keygen --key authority.pem

  # build a signed reference from circuit_input_formatter.py output
  zekra_authority.py build --key authority.pem --program-id cubic \\
      --from-inputs ./formatted_inputs --vk ./keys/verification_key.bin \\
      --adjlist-len 150 --adjlist-levels 3 --path-len 32 --stack-depth 8 \\
      --label-bitwidth 8 --bucket-bitwidth 5 --address-bitwidth 23 \\
      --out reference_cubic.json

  # publish it to a running node (any node; it gossips like any transaction)
  zekra_authority.py publish --reference reference_cubic.json \\
      --node http://127.0.0.1:5000
"""

import argparse
import base64
import hashlib
import json
import os
import sys

import requests

from zekra_integration import (
    CIRCUIT_PARAM_KEYS, REFERENCE_TX_TYPE, ZEKRA_FUNCTION_NAME, build_reference,
    sign_reference, verify_reference, _load_or_create_key,
)


def read_value(inputs_dir, name):
    path = os.path.join(inputs_dir, name)
    with open(path) as f:
        return f.read().strip()


def cmd_keygen(args):
    if os.path.exists(args.key) and not args.force:
        print(f'{args.key} already exists (use --force to overwrite)')
        return 1
    if args.force and os.path.exists(args.key):
        os.remove(args.key)
    key = _load_or_create_key(args.key)
    from cryptography.hazmat.primitives import serialization
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    print(f'authority key written to {args.key}')
    print(f'authority public key: {pub}')
    print('\nSet this on every node so it only trusts references from you:')
    print(f'  export ZEKRA_AUTHORITY_PUBKEY={pub}')
    return 0


def cmd_build(args):
    key = _load_or_create_key(args.key)

    if args.from_inputs:
        h1 = read_value(args.from_inputs, 'in_encoded_adjlist_digest')
        h3 = read_value(args.from_inputs, 'in_translator_digest')
        entry = int(read_value(args.from_inputs, 'in_initial_node'))
        exit_node = int(read_value(args.from_inputs, 'in_final_node'))
    else:
        missing = [n for n, v in (('--h1', args.h1), ('--h3', args.h3),
                                  ('--entry-node', args.entry_node),
                                  ('--exit-node', args.exit_node)) if v is None]
        if missing:
            print(f'without --from-inputs you must supply: {", ".join(missing)}')
            return 2
        h1, h3 = args.h1, args.h3
        entry, exit_node = args.entry_node, args.exit_node

    # The verification key goes in whole, not as a digest. It is public by
    # construction and only 808 bytes, and shipping it means no verifier ever
    # needs a locally provisioned key -- so none can abstain because its own
    # provisioning drifted.
    vk_b64 = ''
    if args.vk:
        with open(args.vk, 'rb') as f:
            vk_b64 = base64.b64encode(f.read()).decode('ascii')
    else:
        print('warning: no --vk given. Verifiers will have to fall back to a '
              'locally configured verification key.')

    circuit = {k: getattr(args, k) for k in CIRCUIT_PARAM_KEYS}
    missing = [k for k, v in circuit.items() if v is None]
    circuit['pruned'] = bool(args.pruned)
    if missing:
        print(f'missing circuit parameters: {", ".join("--" + m.replace("_", "-") for m in missing)}')
        return 2

    reference = build_reference(args.program_id, h1, h3, entry, exit_node,
                                vk_b64, circuit)
    envelope = sign_reference(reference, key)

    checked, why = verify_reference(envelope, envelope['authority_pubkey'])
    if checked is None:
        print(f'refusing to write a reference that does not verify: {why}')
        return 1

    with open(args.out, 'w') as f:
        json.dump(envelope, f, indent=2)
    print(f'signed reference for {args.program_id!r} written to {args.out}')
    print(f'  h1         : {h1}')
    print(f'  h3         : {h3}')
    print(f'  entry/exit : {entry} -> {exit_node}')
    print(f'  vk         : {str(len(vk_b64)) + " b64 chars, embedded" if vk_b64 else "(none supplied)"}')
    print(f'  circuit    : {circuit}')
    return 0


def cmd_publish(args):
    with open(args.reference) as f:
        envelope = json.load(f)

    reference, why = verify_reference(envelope, envelope.get('authority_pubkey'))
    if reference is None:
        print(f'refusing to publish an invalid reference: {why}')
        return 1

    authority_id = envelope['authority_pubkey'][:32]
    payload = {
        'sender': authority_id,
        'recipient': authority_id,
        'transaction_type': REFERENCE_TX_TYPE,
        'function_name': ZEKRA_FUNCTION_NAME,
        'program_id': reference['program_id'],
        'reference_envelope': envelope,
    }
    r = requests.post(f'{args.node.rstrip("/")}/transactions/new', json=payload,
                      timeout=15)
    if r.status_code != 201:
        print(f'publish failed: {r.status_code} {r.text}')
        return 1
    print(f'reference for {reference["program_id"]!r} submitted to {args.node}')
    print('It must be MINED before any node will use it -- an unmined reference '
          'has not been agreed by anyone.')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('keygen', help='create the authority signing key')
    p.add_argument('--key', required=True)
    p.add_argument('--force', action='store_true')
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser('build', help='build and sign a reference')
    p.add_argument('--key', required=True)
    p.add_argument('--program-id', required=True)
    p.add_argument('--from-inputs', help='directory of circuit_input_formatter output')
    p.add_argument('--h1'); p.add_argument('--h3')
    p.add_argument('--entry-node', type=int); p.add_argument('--exit-node', type=int)
    p.add_argument('--vk', help='verification_key.bin, embedded in the reference')
    for k in CIRCUIT_PARAM_KEYS:
        p.add_argument(f'--{k.replace("_", "-")}', type=int, dest=k)
    p.add_argument('--pruned', action='store_true',
                   help='these digests were computed over the pruned CFG files; '
                        'provers must pass --pruned to the formatter too')
    p.add_argument('--out', required=True)
    p.set_defaults(func=cmd_build)

    p = sub.add_parser('publish', help='submit a reference to a node')
    p.add_argument('--reference', required=True)
    p.add_argument('--node', required=True)
    p.set_defaults(func=cmd_publish)

    args = parser.parse_args()
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
