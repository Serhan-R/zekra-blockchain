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

        # ---------------------------------------------------------------
        # Incremental chain indices.
        #
        # new_transaction(), validate_response_transaction(),
        # find_reference(), and the /update_transaction_pool,
        # /zekra/status, /count_verdicts routes all used to answer their
        # question by walking self.chain from the genesis block, every
        # single call. On a long-running mesh that chain never resets, so
        # every one of those became slower as the run went on -- this is
        # what showed up as the growing "Network/other" residual.
        #
        # These attributes are pure caches: self.chain remains the source
        # of truth, and _rebuild_indices() can always reconstruct every one
        # of them from it. They are updated incrementally in exactly two
        # places -- _index_block() at the end of new_block() (one new
        # block, O(block size)) and _rebuild_indices() in resolve_conflicts()
        # (the whole chain replaced by a peer's, O(new chain length), but
        # only on an actual fork switch, not per transaction).
        #
        # IMPORTANT: anything that mutates self.chain directly instead of
        # going through new_block()/resolve_conflicts() (this exists in at
        # least one place -- test_zekra_unit.py's
        # test_find_reference_first_wins builds blocks by hand and appends
        # them straight onto bc.chain) MUST call self._rebuild_indices()
        # afterward, or these caches silently go stale.
        # ---------------------------------------------------------------
        self.chain_tx_hashes = set()          # every tx hash ever mined
        self.chain_hash_index = {}            # tx hash -> tx (for parent lookups)
        self.chain_challenge_keys = set()     # (program_id, str(nonce)) already used
        self.chain_response_parents = set()   # parent hashes already answered
        self.chain_references = {}            # program_id -> first VALID reference envelope
        # program_id -> True for every reference tx seen, valid or not -- kept
        # separate from chain_references because /zekra/status's
        # "references_on_chain" field has always reported anything with a
        # reference_envelope, trustworthy or not (it's a "what's been pushed
        # to my chain" diagnostic, not "what can I prove with"), and
        # collapsing the two would quietly change that endpoint's output.
        self.chain_all_reference_program_ids = set()
        self.last_verification_block_index = None  # for count_verdicts()

        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)

    def _index_transaction(self, tx, block_index):
        """
        Fold one mined transaction into the incremental chain indices.
        Called only from _index_block(). See the indices' declaration in
        __init__ for why these exist.
        """
        h = tx.get('hash')
        if h:
            self.chain_tx_hashes.add(h)
            self.chain_hash_index[h] = tx

        tx_type = tx.get('transaction_type')
        function_name = tx.get('function_name')

        if tx_type == 'request' and function_name == ZEKRA_FUNCTION_NAME:
            self.chain_challenge_keys.add(
                (tx.get('program_id'), str(tx.get('function_parameter'))))

        if tx_type == 'response' and function_name == ZEKRA_FUNCTION_NAME and tx.get('parent'):
            self.chain_response_parents.add(tx.get('parent'))

        if tx_type == REFERENCE_TX_TYPE and tx.get('reference_envelope'):
            envelope = tx['reference_envelope']
            # Mirrors find_reference()'s original contract exactly: verify
            # once, and "first valid one wins" -- never overwrite an
            # already-cached reference for this program_id. Blocks are
            # always indexed in chain order (new_block() appends in order;
            # _rebuild_indices() walks self.chain in order), so the first
            # valid reference seen here is the same one the original
            # scan-every-call implementation would have returned.
            reference, why = verify_reference(envelope)
            if reference is None:
                print(f"Ignoring untrustworthy reference on chain: {why}")
            else:
                program_id = reference.get('program_id')
                if program_id is not None and program_id not in self.chain_references:
                    self.chain_references[program_id] = envelope
            # Unconditional, regardless of validity -- see the attribute's
            # own comment in __init__.
            inner_ref = envelope.get('reference') if isinstance(envelope, dict) else None
            if isinstance(inner_ref, dict) and inner_ref.get('program_id') is not None:
                self.chain_all_reference_program_ids.add(inner_ref['program_id'])

        if tx_type == 'verification':
            self.last_verification_block_index = block_index

    def _index_block(self, block):
        for tx in block.get('transactions', []):
            self._index_transaction(tx, block.get('index'))

    def _rebuild_indices(self):
        """
        Recompute every chain index from scratch. Only called from
        resolve_conflicts() when self.chain is replaced wholesale by a
        longer chain from a peer -- a fork-resolution event, not something
        that happens per transaction or per mine -- and by anything else
        that mutates self.chain directly (see the warning in __init__).
        """
        self.chain_tx_hashes = set()
        self.chain_hash_index = {}
        self.chain_challenge_keys = set()
        self.chain_response_parents = set()
        self.chain_references = {}
        self.chain_all_reference_program_ids = set()
        self.last_verification_block_index = None
        for block in self.chain:
            self._index_block(block)

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
        Determine if a given blockchain is valid, from genesis.

        :param chain: A blockchain
        :return: True if valid, False if not
        """
        if not chain:
            return True
        return self._valid_suffix(chain, 0)

    def _valid_suffix(self, chain, from_index):
        """
        Same walk as valid_chain(), but starting at from_index instead of 0 --
        i.e. it trusts chain[from_index] as already-validated and only checks
        the linkage/proof-of-work from there to the end.

        Why this exists: resolve_conflicts() used to call valid_chain(chain)
        on every candidate from scratch, re-deriving every previous_hash link
        and re-running valid_proof() for the ENTIRE chain, every single time
        any neighbour had one more block than us -- on a long mesh run that
        is O(chain length) work repeated on every mine(). But self.chain is
        always kept valid as an invariant (it's either the genesis block, or
        it was only ever replaced by a candidate that already passed this
        exact validation), so if a candidate's block at our own tip's index
        has the same hash as our own tip, the ENTIRE prefix up to there is
        guaranteed identical -- a block's hash recursively commits to its
        previous_hash, which commits to the block before that, and so on
        back to genesis, so one hash match is sound proof the whole shared
        history matches (this relies on the exact same SHA-256 collision
        resistance every proof-of-work check here already depends on, not a
        new assumption). resolve_conflicts() uses that to call this with
        from_index = len(self.chain) - 1 instead of calling valid_chain(),
        turning the common "one neighbour mined one more block" case into
        O(new blocks) instead of O(whole chain), while still falling back to
        a full valid_chain() call whenever the tip hashes don't match (a
        real fork, or no local chain yet) -- see resolve_conflicts() for the
        fallback. The `length > max_length` comparison itself is untouched;
        this only changes how cheaply a candidate that passes it gets
        verified.

        NOTE: this function used to print every block of every candidate
        chain it validated. Those debug prints were removed (issues doc #5):
        they served no purpose, and writing that much output to a pipe with
        no reader raised an unhandled BrokenPipeError that propagated up
        through resolve_conflicts() and killed the sync mid-validation --
        which is why a node could sit silently stuck several blocks behind
        for an entire session. With ZEKRA attestations on the chain they
        would also dump hundreds of base64 characters of proof payload per
        block.
        """
        last_block = chain[from_index]
        current_index = from_index + 1

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

        Timing note: this fans out to every registered neighbour, SEQUENTIALLY,
        and each of those calls can itself be slow (single-threaded Flask on
        the peer, a growing chain payload to serialize/transmit, or that peer
        being mid-resolve_conflicts() itself). None of that was previously
        visible anywhere -- log_timing_event() only ever recorded
        mining/proof_generation/verification. Total wall time here, plus the
        per-neighbour breakdown, is logged as its own 'resolve_conflicts'
        stage so it can be correlated against total_latency_ms instead of
        silently vanishing into it.

        Two changes from the original version, both aimed at the same O(chain
        length)-per-call cost, neither touching the `length > max_length`
        rule itself (still a straight length comparison, not proof-of-work):

        1. A neighbour is asked for a cheap /chain/tip (just {length,
           tip_hash}) first. The full chain body -- which only grows over a
           long mesh run -- is only fetched from neighbours that actually
           claim to be longer, instead of being transmitted and JSON-decoded
           on every single resolve_conflicts() call regardless of whether it
           was ever going to be used. This is the same idea as Bitcoin
           exchanging small headers before deciding whether to pull a full
           block body.
        2. A candidate chain that IS longer is checked against our own tip's
           hash first. If it matches (see _valid_suffix()'s docstring for why
           a single hash match certifies the whole shared prefix), only the
           new tail blocks get walked through valid_proof() -- not the whole
           candidate from genesis. A real fork (tip hash doesn't match) still
           falls back to the original full valid_chain() from-genesis check,
           so correctness for the rare divergent case is unchanged.

        Sequential-per-neighbour and single-threaded Flask are NOT changed
        here -- that's a separate, larger concurrency change with its own
        risk (shared self.chain/self.nodes state), not something to fold
        into a validation-cost fix silently.
        """
        _rc_t0 = time.time()
        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours -- same rule as
        # before, just checked against a small /chain/tip body first.
        max_length = len(self.chain)
        our_tip_hash = self.hash(self.chain[-1]) if self.chain else None

        _per_neighbor_ms = {}
        _per_neighbor_full_fetch = {}
        _fast_path_validations = 0
        _full_validations = 0

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            _n_t0 = time.time()
            _per_neighbor_full_fetch[node] = False
            try:
                tip_response = requests.get(f'http://{node}/chain/tip')
            except requests.exceptions.RequestException:
                print(f"Failed to reach {node} for /chain/tip")
                _per_neighbor_ms[node] = round((time.time() - _n_t0) * 1000, 1)
                continue

            if tip_response.status_code != 200:
                _per_neighbor_ms[node] = round((time.time() - _n_t0) * 1000, 1)
                continue

            tip_info = tip_response.json()
            neighbor_length = tip_info.get('length', 0)
            neighbor_tip_hash = tip_info.get('tip_hash')

            # Cheap check first, exactly the same comparison as before --
            # skip the full-body fetch entirely if they're not longer.
            if neighbor_length <= max_length:
                _per_neighbor_ms[node] = round((time.time() - _n_t0) * 1000, 1)
                continue

            _per_neighbor_full_fetch[node] = True
            response = requests.get(f'http://{node}/chain')
            _per_neighbor_ms[node] = round((time.time() - _n_t0) * 1000, 1)

            if response.status_code != 200:
                continue

            body = response.json()
            length = body['length']
            chain = body['chain']

            # Re-check against the (possibly-updated-by-an-earlier-neighbour)
            # running max_length, same as the original single-shot check.
            if length <= max_length:
                continue

            if (our_tip_hash is not None
                    and neighbor_tip_hash is not None
                    and len(chain) > len(self.chain)
                    and self.hash(chain[len(self.chain) - 1]) == our_tip_hash):
                # Shared prefix confirmed identical to our own already-valid
                # chain -- only validate the blocks this peer added.
                candidate_ok = self._valid_suffix(chain, len(self.chain) - 1)
                _fast_path_validations += 1
            else:
                # No local chain, or their chain diverges before our tip --
                # a real fork. Fall back to full from-genesis validation.
                candidate_ok = self.valid_chain(chain)
                _full_validations += 1

            if candidate_ok:
                last_block = chain[-1]
                if self.validate_response_transaction(last_block):
                    max_length = length
                    new_chain = chain
                else:
                    print(f"Rejected chain from {node} due to an invalid response transaction.")

        # Replace our chain if we discovered a new, valid chain longer than ours
        # Update the last_processed_block to the last processed blocked on the new chain
        replaced = False
        if new_chain:
            for index, (block1, block2) in enumerate(zip(new_chain, self.chain)):
                if self.hash(block1) != self.hash(block2):
                    self.last_processed_block = max(index-1, 0) # if tthey differ in index 0 then it should not become -1
                    break
            self.chain = new_chain
            self._rebuild_indices()
            replaced = True

        zekra_integration.log_timing_event(
            'resolve_conflicts', node=node_identifier,
            duration_ms=(time.time() - _rc_t0) * 1000,
            chain_length=len(self.chain), replaced=replaced,
            neighbor_count=len(neighbours), per_neighbor_fetch_ms=_per_neighbor_ms,
            per_neighbor_full_fetch=_per_neighbor_full_fetch,
            fast_path_validations=_fast_path_validations,
            full_validations=_full_validations)

        return replaced

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
        # O(1): chain_references is maintained incrementally by
        # _index_transaction() (called from new_block()/resolve_conflicts())
        # and already only ever holds the first VALID reference seen per
        # program_id, verified once at indexing time -- see its declaration
        # in __init__ for the full reasoning. This used to walk the entire
        # chain, re-verifying every reference transaction's signature, on
        # every single call.
        return self.chain_references.get(program_id)

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

            # Find the matching request transaction. O(1) via chain_hash_index
            # (tx hash -> tx, maintained incrementally -- see __init__) instead
            # of walking every block in self.chain looking for a hash match.
        parent_hash = response_transaction.get('parent')
        request_transaction = self.chain_hash_index.get(parent_hash)

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
                node=node_identifier,
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
            _net_t0 = time.time()
            try:
                response = requests.post(
                    coordinator_node_url,
                    json=verification_transaction,
                    headers={"Content-Type": "application/json"}
                )
                zekra_integration.log_timing_event(
                    'verification_delivery_post',
                    program_id=response_transaction.get('program_id'),
                    request_hash=parent_hash,
                    duration_ms=(time.time() - _net_t0) * 1000,
                    node=node_identifier, http_status=response.status_code)
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

        Timing note: this loop is sequential and blocking, and each neighbour's
        /notify_change handler runs its OWN resolve_conflicts() inline before
        replying (see notify_change() below) -- so this call does not return
        until every neighbour has finished its own consensus fan-out. That
        makes this the wall-clock cost a mine() call actually pays for
        propagation, none of which showed up in any previously-logged stage.
        Logged here as 'notify_neighbors_cascade', with a per-neighbour
        breakdown, so it can be correlated against total_latency_ms.
        """
        last_block_hash = self.hash(self.last_block)
        _cascade_t0 = time.time()
        _per_neighbor_ms = {}
        for node in self.nodes:
            _n_t0 = time.time()
            try:
                response = requests.post(f'http://{node}/notify_change', json={'last_block_hash': last_block_hash})
                if response.status_code == 200:
                    print(f"Notified node {node}, response: {response.json()}")
            except requests.exceptions.RequestException:
                print(f"Failed to notify node {node}")
            _per_neighbor_ms[node] = round((time.time() - _n_t0) * 1000, 1)
        zekra_integration.log_timing_event(
            'notify_neighbors_cascade', node=node_identifier,
            duration_ms=(time.time() - _cascade_t0) * 1000,
            last_block_hash=last_block_hash, neighbor_count=len(self.nodes),
            per_neighbor_ms=_per_neighbor_ms)

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
        self._index_block(block)

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

        if transaction_hash in self.chain_tx_hashes:
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
                    or (program_id, str(function_parameter)) in self.chain_challenge_keys):
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

            if parent in self.chain_response_parents:
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

        print(f"[ZEKRA-DEBUG2] last_processed_block={self.last_processed_block} chain_len={len(self.chain)} new_blocks={len(new_blocks)}")

        for block in new_blocks:
            for transaction in block['transactions']:
                print(f"[ZEKRA-DEBUG] tx_type={transaction.get('transaction_type')!r} recipient={transaction.get('recipient')!r} me={node_identifier!r} match={transaction.get('recipient')==node_identifier}")
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
                        _net_t0 = time.time()
                        try:
                            response = requests.post(
                                recipient_node_url,
                                json=response_transaction,
                                headers={"Content-Type": "application/json"}
                            )
                            zekra_integration.log_timing_event(
                                'response_delivery_post',
                                program_id=response_transaction.get('program_id'),
                                request_hash=response_transaction.get('parent'),
                                duration_ms=(time.time() - _net_t0) * 1000,
                                node=node_identifier, http_status=response.status_code)
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
        print(f"[ZEKRA-DEBUG3] build_zekra_response called for request_hash={request_transaction.get('hash')!r} program_id={request_transaction.get('program_id')!r}")
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
            attestation = generate_attestation(program_id, request_hash, nonce, reference,
                                                node=node_identifier)
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
    print(f"[ZEKRA-DEBUG0] /mine called, pool_size={len(blockchain.transaction_pool)}")
    if not blockchain.transaction_pool:
        return jsonify({'message': 'No pending transactions to mine'}), 200

    _pool_snapshot = list(blockchain.transaction_pool)

    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    _timing_t0 = time.time()
    proof = blockchain.proof_of_work(last_block)
    _mining_ms = (time.time() - _timing_t0) * 1000

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    for _tx in _pool_snapshot:
        if _tx.get('transaction_type') in ('request', 'response', 'verification'):
            zekra_integration.log_timing_event(
                'mining', program_id=_tx.get('program_id'),
                request_hash=(_tx.get('hash')
                              if _tx.get('transaction_type') == 'request'
                              else _tx.get('parent')),
                duration_ms=_mining_ms, node=node_identifier,
                block_index=block['index'], mined_tx_type=_tx.get('transaction_type'))

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

    if (values.get('transaction_type') == 'request'
            and values.get('function_name') == ZEKRA_FUNCTION_NAME
            and blockchain.transaction_pool):
        _new_tx = blockchain.transaction_pool[-1]
        zekra_integration.log_timing_event(
            'request_initiated', program_id=values.get('program_id'),
            request_hash=_new_tx.get('hash'), duration_ms=0, node=node_identifier)

    # Ground-truth network-arrival timestamps for response/verification
    # transactions -- logged the instant the HTTP POST lands here, so unlike
    # the driver's own polling loop this has zero detection lag. duration_ms
    # is 0 (a timestamp marker, same convention as request_initiated above);
    # the actual delivery latency is the gap between this and the sender's
    # own *_delivery_post event, or between this and the round's earlier
    # stage timestamps.
    if values.get('transaction_type') == 'response':
        zekra_integration.log_timing_event(
            'response_received', program_id=values.get('program_id'),
            request_hash=values.get('parent'), duration_ms=0, node=node_identifier)
    elif values.get('transaction_type') == 'verification':
        zekra_integration.log_timing_event(
            'verification_received', program_id=values.get('program_id'),
            request_hash=values.get('parent'), duration_ms=0, node=node_identifier)

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
    # O(1): chain_all_reference_program_ids is maintained incrementally
    # (see Blockchain.__init__) and reports the same thing this used to
    # compute by walking the whole chain -- every program_id with a
    # reference_envelope on chain, valid or not.
    info['references_on_chain'] = sorted(blockchain.chain_all_reference_program_ids)
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

    # Check if transactions are already in the blockchain. O(1) set lookup
    # per transaction via chain_tx_hashes (maintained incrementally -- see
    # Blockchain.__init__) instead of rebuilding this set by walking the
    # whole chain on every call. This endpoint is hit by every peer's
    # notify_transaction_pool_update() broadcast after every single mine,
    # so this was the single most frequently paid O(chain-length) cost in
    # the whole codebase -- one full chain walk per peer per mine, not just
    # per mine.
    existing_transaction_hashes = blockchain.chain_tx_hashes

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

    # Find the latest block with verification transactions. O(1) via
    # last_verification_block_index (maintained incrementally -- see
    # Blockchain.__init__) instead of scanning backward from the chain tip
    # on every call. Block indices are 1-based and contiguous (new_block()
    # always sets 'index' to len(self.chain) + 1), so the block's position
    # in the list is index - 1.
    verification_block = None
    if blockchain.last_verification_block_index is not None:
        verification_block = blockchain.chain[blockchain.last_verification_block_index - 1]

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

    # Correlate this call to its round for the JSONL timing log. A
    # verification transaction carries no program_id/request_hash of its own
    # (see FlaskBlockChain.py's validate_response_transaction -- it's built
    # from parent_hash alone), so pull them from the original request
    # transaction via chain_hash_index (O(1), same cache the rest of the
    # optimization uses) rather than re-scanning anything.
    _first_verification = next(
        (t for t in verification_block['transactions'] if t['transaction_type'] == 'verification'),
        None)
    _request_hash = _first_verification.get('parent') if _first_verification else None
    _request_tx = blockchain.chain_hash_index.get(_request_hash) if _request_hash else None
    zekra_integration.log_timing_event(
        'count_verdicts',
        program_id=(_request_tx or {}).get('program_id'),
        request_hash=_request_hash,
        duration_ms=elapsed_time * 1000,
        node=node_identifier,
        correct=correct_count, incorrect=incorrect_count)

    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/chain/tip', methods=['GET'])
def chain_tip():
    """
    Cheap sibling of /chain: just this node's chain length and tip hash, with
    no chain body serialized. resolve_conflicts() hits this on every neighbour
    first, and only falls through to a full /chain fetch for a neighbour that
    actually claims to be longer -- so a stable mesh isn't re-transmitting
    and re-decoding the entire (ever-growing) chain from every neighbour on
    every single mine(), just to find out most of them aren't longer.
    """
    response = {
        'length': len(blockchain.chain),
        'tip_hash': blockchain.hash(blockchain.chain[-1]) if blockchain.chain else None,
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
