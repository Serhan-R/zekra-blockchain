import base64
import hashlib
import json
import time
from datetime import datetime
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request

import zekra_integration
from zekra_integration import (
    REFERENCE_TX_TYPE,
    ZEKRA_FUNCTION_NAME,
    ZekraProofError,
    attestation_fingerprint,
    generate_attestation,
    node_public_key_hex,
    verify_attestation,
    verify_reference,
)


class Blockchain:
    def __init__(self):
        # self.current_transactions = []
        self.chain = []
        self.nodes = set()
        self.node_addresses = {}
        # node_identifier -> Ed25519 public key (hex), learned at registration.
        self.node_pubkeys = {}
        self.transaction_pool = []

        self.last_processed_block = 0

        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)

    def register_node(self, address):
        """
        Add a new node to the list of nodes and fetch its unique identifier.

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """
        parsed_url = urlparse(address)
        node_address = parsed_url.netloc if parsed_url.netloc else parsed_url.path

        # Add the node's address to the set of nodes
        self.nodes.add(node_address)

        # Attempt to fetch the node's unique identifier via the /id endpoint
        try:
            response = requests.get(f'http://{node_address}/id')
            if response.status_code == 200:
                node_identifier = response.json().get('node_id')
                if node_identifier:
                    # Store the identifier: address mapping
                    self.node_addresses[node_identifier] = node_address
                    # ...and the peer's ZEKRA attestation key. Check (1) compares
                    # the key on a response against the one registered here, so a
                    # responder cannot simply attach a key it invented.
                    peer_pubkey = response.json().get('zekra_pubkey')
                    if peer_pubkey:
                        self.node_pubkeys[node_identifier] = peer_pubkey
                    print(f"Registered node {node_address} with identifier {node_identifier}")
                else:
                    print(f"Failed to retrieve identifier for node {node_address}")
            else:
                print(f"Failed to retrieve identifier for node {node_address}, status code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to node {node_address}: {e}")

    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        # NOTE: this function used to print every block of every candidate chain
        # it validated. Those debug prints were removed (issues doc #5): they
        # served no purpose, and writing that much output to a pipe with no
        # reader raised an unhandled BrokenPipeError that propagated up through
        # resolve_conflicts() and killed the sync mid-validation -- which is why
        # a node could sit silently stuck several blocks behind for an entire
        # session. With ZEKRA attestations on the chain they would also dump
        # hundreds of base64 characters of proof payload per block.

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], block['previous_hash']):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):

                    last_block = chain[-1]
                    if self.validate_response_transaction(last_block):
                        max_length = length
                        new_chain = chain
                    else:
                        print(f"Rejected chain from {node} due to an invalid response transaction.")

        # Replace our chain if we discovered a new, valid chain longer than ours 
        # Update the last_processed_block to the last processed blocked on the new chain
        if new_chain:
            for index, (block1, block2) in enumerate(zip(new_chain, self.chain)):
                if self.hash(block1) != self.hash(block2):
                    self.last_processed_block = max(index-1, 0) # if tthey differ in index 0 then it should not become -1
                    break
            self.chain = new_chain
            return True

        return False

    def find_reference(self, program_id):
        """
        The authority-signed reference material for a program, from our own chain.

        FIRST VALID ONE WINS. Later references for the same program_id are
        ignored, so a program's identity cannot be redefined after the fact by
        publishing a second one -- an attacker who could would be able to swap in
        a CFG of their choosing and make any path legal.

        Only mined references count. Something sitting in the pool has not been
        agreed by anyone yet.

        :return: the signed envelope, or None if we have no trustworthy reference
        """
        for block in self.chain:
            for tx in block['transactions']:
                if tx.get('transaction_type') != REFERENCE_TX_TYPE:
                    continue
                envelope = tx.get('reference_envelope')
                if not envelope:
                    continue
                reference, why = verify_reference(envelope)
                if reference is None:
                    print(f"Ignoring untrustworthy reference on chain: {why}")
                    continue
                if reference.get('program_id') == program_id:
                    return envelope
        return None

    def validate_response_transaction(self, last_block):
        """
        Validate the first response transaction in the last added block.

        :param last_block: The latest block in the chain.
        :return: True if the first response transaction is valid, False otherwise.
        """

        # Find the first response transaction in the last block
        response_transaction = None
        for transaction in last_block['transactions']:
            if transaction['transaction_type'] == "response":
                response_transaction = transaction
                break  # Only check the first response transaction

        # If no response transaction is found, return True (nothing to validate)
        if not response_transaction:
            return True

        # We answered this challenge ourselves. Accept the chain -- there is
        # nothing wrong with it -- but publish no verdict: a responder grading its
        # own attestation is not verification, and an on-chain "correct" signed by
        # the very node under scrutiny is worse than no verdict at all, because a
        # later reader cannot tell it apart from an independent one.
        if response_transaction.get('sender') == node_identifier:
            print('Not verifying our own response -- our verdict on it would not '
                  'be independent.')
            return True

            # Find the matching request transaction in the **entire chain**
        parent_hash = response_transaction.get('parent')
        request_transaction = None

        for block in self.chain:
            for transaction in block['transactions']:
                if transaction.get('hash') == parent_hash:  # Match request transaction
                    request_transaction = transaction
                    break
            if request_transaction:
                break  # Stop searching once found

        # If no matching request transaction is found, reject the chain
        if not request_transaction:
            return False

            # Recompute expected response result
        function_name = request_transaction.get('function_name')
        function_parameter = request_transaction.get('function_parameter')

        if function_name == ZEKRA_FUNCTION_NAME:
            # ZEKRA attestations cannot be validated by recomputing and comparing:
            # Groth16 proofs are randomised, so two equally valid proofs of the same
            # statement differ byte for byte. Instead we run all three checks from
            # the paper: the prover's signature (1), the public inputs against the
            # authority-signed reference and THIS request's nonce (2), and the SNARK
            # itself (3).
            program_id = response_transaction.get('program_id')
            reference_envelope = self.find_reference(program_id)
            verification_response, detail = verify_attestation(
                response_transaction,
                request_transaction,
                reference_envelope,
                prover_pubkey=self.node_pubkeys.get(response_transaction.get('sender')),
            )
            print(f"ZEKRA [{program_id}]: {verification_response or 'ABSTAIN'} -- {detail}")

            if verification_response is None:
                # Abstention: we are not in a position to judge -- no trustworthy
                # reference on our chain yet, or our own verifier could not run.
                # That is a statement about US, not evidence against the responder,
                # so we neither publish a verdict nor block the chain. A node whose
                # tooling is broken must not silently freeze itself out of consensus,
                # and must not slander an honest peer either.
                return True

            is_valid = (verification_response == "correct")
        else:
            function_map = {
                "fibonacci": self.calculate_fibonacci,
                "hash_test": self.hash_n_times,
                "factorial": self.calculate_factorial,
                "sum_natural": self.sum_natural,
            }

            # If function is invalid, reject the chain
            if function_name not in function_map:
                return False

            expected_result = function_map[function_name](function_parameter)

            if response_transaction['function_parameter'] == expected_result:
                verification_response = "correct"
            else:
                verification_response = "incorrect"

            is_valid = (verification_response == "correct")

        # We get the this node's hash (node_id)
        try:
            response = requests.get(f"http://localhost:{port}/id")
            if response.status_code == 200:
                node_id = response.json().get("node_id", None)
                if not node_id:
                    print("Error: Could not retrieve node identifier from /id endpoint.")
                    return False
            else:
                print(f"Error fetching node identifier, status: {response.status_code}")
                return False
        except requests.RequestException as e:
            print(f"Error contacting node for identifier: {e}")
            return False

        request_node_id = response_transaction['recipient']
        # Create the verification transaction
        verification_transaction = {
            "sender": node_id,  # The verifying node
            "recipient": request_node_id,
            "transaction_type": "verification",
            "function_name": function_name,
            "function_parameter": verification_response,
            "parent": parent_hash,
        }

        request_node_address = self.node_addresses.get(request_node_id)

        # Send the response transaction if the recipient address is found
        if request_node_address:
            coordinator_node_url = f'http://{request_node_address}/transactions/new'

            print("Verification Transaction Before Sending:", verification_transaction)
            try:
                response = requests.post(
                    coordinator_node_url,
                    json=verification_transaction,
                    headers={"Content-Type": "application/json"}
                )
                if response.status_code == 201:
                    print(
                        f"Verification transaction sent to node {request_node_id}: {response.json()}")
                else:
                    print(
                        f"Failed to send verification to {request_node_id}: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"Error sending verification to node {request_node_id}: {e}")

        # Check if the response result is correct
        return is_valid

    def verify_mined_block(self, block):
        """
        Run verification over a block THIS node just mined.

        Verification is otherwise triggered only inside resolve_conflicts(), i.e.
        when a node adopts a chain longer than its own. A miner never does that --
        its chain is already the longest -- so without this the miner silently
        skipped verification for every block it produced. That was a side effect
        of attaching verification to chain adoption, not a decision: a miner is
        normally a disinterested third party, and excluding it threw away one
        independent verifier per attestation for no reason.

        Mining a block that contains your own response does not entitle you to
        judge it; validate_response_transaction() enforces that for every path.

        Unlike the resolve_conflicts() path, the return value is discarded: that
        boolean decides whether to ACCEPT a peer's chain, and we are not deciding
        whether to accept our own. We only want the verdict it publishes.
        """
        self.validate_response_transaction(block)

    def notify_neighbors(self):
        """
        Notify all neighbors that the blockchain has been updated by sending the hash of the latest block.
        """
        last_block_hash = self.hash(self.last_block)
        for node in self.nodes:
            try:
                response = requests.post(f'http://{node}/notify_change', json={'last_block_hash': last_block_hash})
                if response.status_code == 200:
                    print(f"Notified node {node}, response: {response.json()}")
            except requests.exceptions.RequestException:
                print(f"Failed to notify node {node}")

    def notify_transaction_pool_update(self):
        """
        Notify all neighbors that the transaction pool has been updated.
        """
        for node in self.nodes:
            try:
                response = requests.post(f'http://{node}/update_transaction_pool',
                                         json={'transaction_pool': self.transaction_pool})
                if response.status_code == 200:
                    print(f"Notified node {node} of transaction pool update.")
            except requests.exceptions.RequestException:
                print(f"Failed to notify node {node} of transaction pool update.")

    def new_block(self, proof, previous_hash):
        """
        Create a new Block, append it to the chain, and broadcast the change.

        Sweeps the ENTIRE current transaction pool into this block (not just
        transactions related to whatever triggered mining), appends the block
        to self.chain, then clears self.transaction_pool.

        Before returning, this method also handles all peer notification for
        the mine as a side effect:
        - notify_neighbors(): tells every registered peer the last-block hash
          has changed, so they can decide whether to resolve_conflicts().
        - notify_transaction_pool_update(): pushes this node's now-emptied
         pool to every peer.
        - broadcast_mined_transactions(transactions_to_add): tells every peer
         to remove these transaction hashes from their own local pools,
            since they've now been sealed into this block.

        Callers should NOT call notify_neighbors() or notify_transaction_pool_update()
        again after this returns -- that would just duplicate the broadcasts this
        method already performs.

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of the previous Block
        :return: The newly created and appended block (dict)
        """

        # Create a copy of transactions to add to the block
        transactions_to_add = self.transaction_pool.copy()

        block = {
            'index': len(self.chain) + 1,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'transactions': transactions_to_add,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        self.chain.append(block)

        # Clear the transaction pool since all transactions were added to the block
        self.transaction_pool = []

        self.notify_neighbors()
        self.notify_transaction_pool_update()

        self.broadcast_mined_transactions(transactions_to_add)
        return block

    def broadcast_mined_transactions(self, mined_transactions):
        """
        Broadcast the list of mined transactions to all nodes.
        """
        for node in self.nodes:
            try:
                response = requests.post(
                    f'http://{node}/remove_mined_transactions',
                    json={'mined_transactions': [tx['hash'] for tx in mined_transactions]},
                    headers={'Content-Type': 'application/json'}
                )
                if response.status_code == 200:
                    print(f"Successfully removed mined transactions from node {node}")
                else:
                    print(f"Failed to remove mined transactions from node {node}: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"Error removing mined transactions from node {node}: {e}")

    def new_transaction(self, sender, recipient, transaction_type="standard", function_name=None,
                        function_parameter=None, parent=None, program_id=None,
                        h2=None, proof_b64=None, prover_pubkey=None,
                        prover_sig=None, reference_envelope=None):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param function_name: Name of the function to execute (optional)
        :param function_parameter: Parameter for the function (optional)
        :param parent: The hash of the challenge transaction (only for response transactions)
        :param program_id: which attested program a ZEKRA request/response concerns
        :param h2: the prover's execution-path commitment H(EP||nce||r2)
        :param proof_b64: base64-encoded ZEKRA proof
        :param prover_pubkey: the prover's Ed25519 public key (hex)
        :param prover_sig: the prover's signature over the attestation statement
        :param reference_envelope: authority-signed reference material (reference txs)
        :return: The index of the Block that will hold this transaction

        Note there is deliberately NO primary_input field. Public inputs are
        reconstructed by each verifier from the on-chain reference and the request's
        nonce (Option A) -- a verifier must never take the claim it is checking from
        the party being checked.
        """

        # function_parameter is an integer for ordinary challenges, but not always:
        #   - verification transactions carry the string "correct"/"incorrect"
        #   - ZEKRA responses carry a proof fingerprint (hex string); the actual
        #     payload travels in proof_b64/primary_input_b64
        # A ZEKRA *request* still carries an integer (the verifier's nonce), so it
        # deliberately keeps the cast.
        skip_int_cast = (
            transaction_type in ("verification", REFERENCE_TX_TYPE)
            or (function_name == ZEKRA_FUNCTION_NAME and transaction_type == "response")
        )
        if function_parameter is not None and not skip_int_cast:
            try:
                function_parameter = int(function_parameter)
            except ValueError:
                raise ValueError('function_parameter must be an integer')

        transaction = {
            'sender': sender,
            'recipient': recipient,
            'transaction_type': transaction_type,
        }

        if function_name:
            transaction['function_name'] = function_name
        if function_parameter is not None:
            transaction['function_parameter'] = function_parameter
        if transaction_type == "response" or transaction_type == "verification":
            transaction['parent'] = parent

        # ZEKRA payload. Added BEFORE the hash is computed, so the transaction hash
        # commits to the proof and the signature -- tampering with either yields a
        # different hash and therefore a different transaction.
        if program_id:
            transaction['program_id'] = program_id
        if h2 is not None:
            transaction['h2'] = str(h2)
        if proof_b64:
            transaction['proof_b64'] = proof_b64
        if prover_pubkey:
            transaction['prover_pubkey'] = prover_pubkey
        if prover_sig:
            transaction['prover_sig'] = prover_sig
        if reference_envelope:
            transaction['reference_envelope'] = reference_envelope

        # Compute the hash for the transaction (excluding the hash field itself)
        transaction_hash = hashlib.sha256(json.dumps(transaction, sort_keys=True).encode()).hexdigest()
        transaction['hash'] = transaction_hash  # Add the computed hash to the transaction

        # Check for duplicates in the transaction pool and the blockchain
        if any(tx['hash'] == transaction_hash for tx in self.transaction_pool):
            print(f"Transaction already in pool: {transaction_hash}")
            return self.last_block['index'] + 1

        if any(tx['hash'] == transaction_hash for block in self.chain for tx in block['transactions']):
            print(f"Transaction already in blockchain: {transaction_hash}")
            return self.last_block['index'] + 1

        # A challenger must never reissue a nonce. Freshness is the whole point of
        # nce: if a nonce is reused, a proof made for the earlier challenge still
        # satisfies check (2) and can be replayed. Random 254-bit nonces never
        # collide by accident, so this defends against a MALICIOUS challenger
        # colluding with a prover -- cheap insurance in a network where any node
        # may issue challenges.
        if transaction_type == "request" and function_name == ZEKRA_FUNCTION_NAME:
            def _same_challenge(tx):
                return (tx.get('transaction_type') == 'request'
                        and tx.get('function_name') == ZEKRA_FUNCTION_NAME
                        and tx.get('program_id') == program_id
                        and str(tx.get('function_parameter')) == str(function_parameter))

            if (any(_same_challenge(tx) for tx in self.transaction_pool)
                    or any(_same_challenge(tx)
                           for block in self.chain for tx in block['transactions'])):
                print(f"Rejecting ZEKRA request: nonce {function_parameter} has "
                      f"already been used for program {program_id!r}")
                return self.last_block['index'] + 1

        # Content-hash deduplication above cannot protect ZEKRA responses: proof
        # generation is randomized, so re-answering the same request produces a
        # different proof and therefore a different hash. Deduplicate those on the
        # request they answer (parent hash) instead, so one challenge collects at
        # most one answer.
        if transaction_type == "response" and function_name == ZEKRA_FUNCTION_NAME and parent:
            def _answers_same_request(tx):
                return (tx.get('transaction_type') == 'response'
                        and tx.get('function_name') == ZEKRA_FUNCTION_NAME
                        and tx.get('parent') == parent)

            if any(_answers_same_request(tx) for tx in self.transaction_pool):
                print(f"ZEKRA response for request {parent} already in pool; dropping duplicate.")
                return self.last_block['index'] + 1

            if any(_answers_same_request(tx)
                   for block in self.chain for tx in block['transactions']):
                print(f"ZEKRA response for request {parent} already on chain; dropping duplicate.")
                return self.last_block['index'] + 1

        self.transaction_pool.append(transaction)
        self.notify_transaction_pool_update()
        return self.last_block['index'] + 1

    def check_and_execute_requests(self):
        """
        Checks the provided blocks for any pending computation requests directed to this node and executes them.
        """
        # Only process blocks added after the last processed block
        new_blocks = self.chain[self.last_processed_block + 1:]

        for block in new_blocks:
            for transaction in block['transactions']:
                if transaction['transaction_type'] == 'request' and transaction['recipient'] == node_identifier:
                    function_name = transaction.get('function_name')
                    function_parameter = transaction.get('function_parameter')
                    if not function_name or function_parameter is None:
                        continue

                    if function_name == ZEKRA_FUNCTION_NAME:
                        response_transaction = self.build_zekra_response(transaction)
                    else:
                        function_map = {
                            "fibonacci": self.calculate_fibonacci,
                            "hash_test": self.hash_n_times,
                            "factorial": self.calculate_factorial,
                            "sum_natural": self.sum_natural,
                        }
                        if function_name not in function_map:
                            continue

                        # Execute the function and prepare result
                        result = function_map[function_name](function_parameter)
                        response_transaction = {
                            "sender": transaction['recipient'],
                            "recipient": transaction['sender'],
                            "transaction_type": "response",
                            "function_name": function_name,
                            "function_parameter": result,
                            "parent": transaction['hash'],
                        }

                    if response_transaction is None:
                        # We were addressed but could not answer (e.g. proof generation
                        # failed). Leave last_processed_block alone for this one and
                        # move on -- the request stays visible on-chain unanswered
                        # rather than being silently marked as handled.
                        continue

                    recipient_node_identifier = transaction['sender']
                    recipient_node_address = self.node_addresses.get(recipient_node_identifier)

                    # Send the response transaction if the recipient address is found
                    if recipient_node_address:
                        recipient_node_url = f'http://{recipient_node_address}/transactions/new'

                        print("Response Transaction Before Sending:",
                              self.summarize_transaction(response_transaction))
                        try:
                            response = requests.post(
                                recipient_node_url,
                                json=response_transaction,
                                headers={"Content-Type": "application/json"}
                            )
                            if response.status_code == 201:
                                print(
                                    f"Response transaction sent to node {recipient_node_identifier}: {response.json()}")
                            else:
                                print(
                                    f"Failed to send response to {recipient_node_identifier}: {response.status_code}")
                        except requests.exceptions.RequestException as e:
                            print(f"Error sending response to node {recipient_node_identifier}: {e}")

        # Update the last processed block index to the latest block in the chain
        self.last_processed_block = len(self.chain) - 1

    def build_zekra_response(self, request_transaction):
        """
        Produce a signed ZEKRA attestation answering a challenge addressed to us.

        :return: a response transaction dict, or None if we cannot answer (we hold
            no materials for this program, or have no trustworthy reference). We
            return None rather than sending something bogus -- an unanswered
            request is visibly unanswered, whereas a fabricated one is not.
        """
        program_id = request_transaction.get('program_id')
        nonce = request_transaction.get('function_parameter')
        request_hash = request_transaction.get('hash')

        envelope = self.find_reference(program_id)
        if envelope is None:
            print(f"ZEKRA: cannot answer {request_hash}: no trustworthy reference "
                  f"for program {program_id!r} on our chain")
            return None
        reference, why = verify_reference(envelope)
        if reference is None:
            print(f"ZEKRA: cannot answer {request_hash}: reference untrustworthy ({why})")
            return None

        try:
            attestation = generate_attestation(program_id, request_hash, nonce, reference)
        except ZekraProofError as e:
            print(f"ZEKRA: cannot answer {request_hash}: {e}")
            return None

        return {
            "sender": request_transaction['recipient'],
            "recipient": request_transaction['sender'],
            "transaction_type": "response",
            "function_name": ZEKRA_FUNCTION_NAME,
            "program_id": program_id,
            # The slot that normally holds a numeric answer holds a short
            # fingerprint, so the control panel has something to display.
            "function_parameter": attestation_fingerprint(
                attestation['h2'], attestation['proof_b64']),
            "parent": request_hash,
            "h2": attestation['h2'],
            "proof_b64": attestation['proof_b64'],
            "prover_pubkey": attestation['prover_pubkey'],
            "prover_sig": attestation['prover_sig'],
        }

    @staticmethod
    def summarize_transaction(transaction):
        """
        Console-friendly copy of a transaction with bulky proof payloads elided.

        Printing a full ZEKRA response would dump hundreds of base64 characters into
        the node log on every single response, which buries everything else.
        """
        summary = dict(transaction)
        for field in ('proof_b64', 'prover_sig', 'reference_envelope'):
            if field in summary and summary[field] is not None:
                summary[field] = f"<{len(summary[field])} base64 chars>"
        return summary

    @staticmethod
    def calculate_fibonacci(n):
        """
        Calculate the n. term of the Fibonacci sequence

        :param n: The term of the Fibonacci sequence to calculate
        :return: The nth term
        """
        if n <= 0:
            return 0
        elif n == 1:
            return 1
        else:
            a, b = 0, 1
            for _ in range(2, n + 1):
                a, b = b, a + b
            return b

    @staticmethod
    def hash_n_times(n):
        """
        Hash a predefined internal hash n times

        :param n: Number of times to hash the base hash
        :return: Resulting hash after N times
        """
        base_hash = "internalhashvalue"
        current_hash = hashlib.sha256(base_hash.encode()).hexdigest()
        for _ in range(n - 1):
            current_hash = hashlib.sha256(current_hash.encode()).hexdigest()
        return current_hash

    @staticmethod
    def calculate_factorial(n):
        """
        Calculate the factorial of a given number.

        :param n: The term to calculate the factorial for
        :return: The factorial of n
        """
        if n < 0:
            return "Undefined for negative values"
        result = 1
        for i in range(2, n + 1):
            result *= i
        return result

    @staticmethod
    def sum_natural(n):
        """
        Calculate the sum of all natural numbers up to n.

        :param n: The number up to which the sum is calculated
        :return: The sum of all natural numbers up to n
        """
        if n < 0:
            return "Undefined for negative values"
        return n * (n + 1) // 2

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof

        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        print(proof)
        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.

        """

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"


# Instantiate the Node
app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()


@app.route('/mine', methods=['GET'])
def mine():
    # Only mine if there are pending transactions
    if not blockchain.transaction_pool:
        return jsonify({'message': 'No pending transactions to mine'}), 200

    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    # After mining the block, check and execute any requests directed to this node
    blockchain.check_and_execute_requests()

    # ...and verify it, which no other code path does for a block we mined
    # ourselves (see verify_mined_block). Peers reach the same verification when
    # they adopt this block via resolve_conflicts(); the miner never adopts, so
    # without this call its verdict would simply be missing.
    blockchain.verify_mined_block(block)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'transaction_type']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.new_transaction(
        sender=values['sender'],
        recipient=values['recipient'],
        transaction_type=values.get('transaction_type', "request"),
        function_name=values.get('function_name'),
        function_parameter=values.get('function_parameter'),
        parent=values.get('parent', None),
        program_id=values.get('program_id'),
        h2=values.get('h2'),
        proof_b64=values.get('proof_b64'),
        prover_pubkey=values.get('prover_pubkey'),
        prover_sig=values.get('prover_sig'),
        reference_envelope=values.get('reference_envelope'),
    )

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201


@app.route('/zekra/status', methods=['GET'])
def zekra_status():
    """
    Report this node's ZEKRA configuration.

    Diagnostic endpoint: tells you at a glance whether a node is running the real
    libsnark verifier or the mock, and whether the binary / verification key /
    placeholder artifacts it was pointed at actually exist on disk. Without this,
    a misconfigured node silently abstains from every verdict and looks identical
    to one that simply was not asked to verify.
    """
    info = zekra_integration.status()
    info['known_peer_pubkeys'] = len(blockchain.node_pubkeys)
    info['references_on_chain'] = sorted({
        tx['reference_envelope']['reference']['program_id']
        for block in blockchain.chain for tx in block['transactions']
        if tx.get('transaction_type') == REFERENCE_TX_TYPE and tx.get('reference_envelope')
    })
    return jsonify(info), 200


@app.route('/remove_mined_transactions', methods=['POST'])
def remove_mined_transactions():
    values = request.get_json()
    mined_transactions = values.get('mined_transactions')

    if mined_transactions is None:
        return 'Missing mined transactions data', 400

    # Remove mined transactions from the pool
    blockchain.transaction_pool = [
        tx for tx in blockchain.transaction_pool
        if tx['hash'] not in mined_transactions
    ]

    response = {
        'message': 'Mined transactions removed successfully',
    }
    return jsonify(response), 200


@app.route('/id', methods=['GET'])
def get_node_id():
    # Retrieve the unique identifier of the node, plus the Ed25519 public key
    # peers need in order to check this node's attestation signatures (check 1).
    response = {'node_id': node_identifier,
                'zekra_pubkey': node_public_key_hex()}
    return jsonify(response), 200


@app.route('/transaction_pool', methods=['GET'])
def get_transaction_pool():
    """
    Return the current transaction pool
    """
    response = {
        'transaction_pool': blockchain.transaction_pool
    }
    return jsonify(response), 200


@app.route('/notify_change', methods=['POST'])
def notify_change():
    values = request.get_json()

    if 'last_block_hash' not in values:
        return 'Missing last_block_hash', 400

    last_block_hash = values['last_block_hash']
    local_last_block_hash = blockchain.hash(blockchain.last_block)

    # Check if the local chain is already synchronized
    if last_block_hash != local_last_block_hash:
        # If hashes differ, synchronize the chain by fetching from the notifying node
        replaced = blockchain.resolve_conflicts()
        if replaced:
            # After updating the chain, check and execute requests in the new blocks
            blockchain.check_and_execute_requests()
            return jsonify({'message': 'Chain updated successfully'}), 200
        else:
            return jsonify({'message': 'No update needed, chain is already up to date'}), 200

    return jsonify({'message': 'Chain already up to date'}), 200


@app.route('/update_transaction_pool', methods=['POST'])
def update_transaction_pool():
    values = request.get_json()
    new_transactions = values.get('transaction_pool')

    if new_transactions is None:
        return 'Missing transaction pool data', 400

    # Check if transactions are already in the blockchain
    existing_transaction_hashes = set()
    for block in blockchain.chain:
        for tx in block['transactions']:
            existing_transaction_hashes.add(tx['hash'])

    # Only add transactions that aren't in the blockchain or current pool
    for tx in new_transactions:
        if tx['hash'] not in existing_transaction_hashes and tx not in blockchain.transaction_pool:
            blockchain.transaction_pool.append(tx)

    response = {
        'message': 'Transaction pool updated successfully',
    }
    return jsonify(response), 200


@app.route('/count_verdicts', methods=['GET'])
def count_verdicts():
    start_time = time.perf_counter()  # Start timing the request

    # Find the latest block with verification transactions
    verification_block = None
    for block in reversed(blockchain.chain):
        for transaction in block['transactions']:
            if transaction['transaction_type'] == "verification":
                verification_block = block
                break
        if verification_block:
            break

    if not verification_block:
        return jsonify({"message": "No verification transactions found in the blockchain."}), 200

    correct_count = 0
    incorrect_count = 0

    # Count verdicts in the verification block
    for transaction in verification_block['transactions']:
        if transaction['transaction_type'] == "verification":
            if transaction['function_parameter'] == "correct":
                correct_count += 1
            elif transaction['function_parameter'] == "incorrect":
                incorrect_count += 1

    # Prepare the response message
    if correct_count == 0 and incorrect_count == 0:
        verdict_message = "No verdicts found in the latest verification block."
    elif incorrect_count == 0:
        verdict_message = f"All verdicts are correct - Total: {correct_count}"
    else:
        verdict_message = f"Verdict summary - Correct: {correct_count}, Incorrect: {incorrect_count}"

    # Calculate the time taken for the counting process
    elapsed_time = time.perf_counter() - start_time

    # Convert to milliseconds if the time is less than 1 second
    if elapsed_time < 1:
        final_time = f"{round(elapsed_time * 1000, 3)} ms"
    else:
        final_time = f"{round(elapsed_time, 3)} second"

    response = {
        "message": verdict_message,
        "time_taken_seconds": final_time
    }

    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        blockchain.check_and_execute_requests()
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200


if __name__ == '__main__':
    import os
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    # Flask's debug mode starts a reloader, which runs the real server in a CHILD
    # process. That child outlives its parent when the parent is killed, which is
    # how orphaned nodes end up holding ports. Set FLASK_DEBUG=0 to run a single
    # process -- the local test harness relies on this so it can clean up after
    # itself.
    debug_mode = os.environ.get('FLASK_DEBUG', '1') != '0'

    app.run(host='0.0.0.0', port=port, debug=debug_mode)