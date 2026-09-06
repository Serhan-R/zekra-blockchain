import hashlib
import json
import random
from datetime import datetime
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request


class Blockchain:
    def __init__(self):
        # self.current_transactions = []
        self.chain = []
        self.nodes = set()
        self.node_addresses = {}
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

        print("Checking the chain is valid")

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
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
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            # TODO: Transaction pool overwrite!!!
            return True

        return False

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
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        transactions_to_add = self.transaction_pool

        block = {
            'index': len(self.chain) + 1,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'transactions': transactions_to_add,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        self.chain.append(block)

        # Remove mined transactions from the pool
        self.transaction_pool = [transaction for transaction in self.transaction_pool if
                                 transaction not in transactions_to_add]

        # Notify neighbors after adding a new block
        self.notify_neighbors()

        # Notify neighbors about the updated transaction pool
        self.notify_transaction_pool_update()
        # Reset the current list of transactions
        # self.current_transactions = []

        return block

    def new_transaction(self, sender, recipient, transaction_type="standard", function_name=None,
                        function_parameter=None, parent=None):

        if function_parameter is not None:
            try:
                function_parameter = int(function_parameter)
            except ValueError:
                raise ValueError('function_parameter must be an integer')
        """ 
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param function_name: Name of the function to execute (optional)
        :param function_parameter: Parameter for the function (optional)
        :param parent: The hash of the challenge transaction (only for response transactions)
        :return: The index of the Block that will hold this transaction
        """
        transaction = {
            'sender': sender,
            'recipient': recipient,
            'transaction_type': transaction_type,
        }

        if function_name:
            transaction['function_name'] = function_name
        if function_parameter is not None:
            transaction['function_parameter'] = function_parameter
        if transaction_type == "response":
            transaction['parent'] = parent

        # Compute the hash for the transaction (excluding the hash field itself)
        transaction_hash = hashlib.sha256(json.dumps(transaction, sort_keys=True).encode()).hexdigest()
        transaction['hash'] = transaction_hash  # Add the computed hash to the transaction

        # Prevent duplicate transactions
        if transaction in self.transaction_pool or any(transaction in block['transactions'] for block in self.chain):
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
                if transaction['transaction_type'] == 'request':
                    function_name = transaction.get('function_name')
                    function_parameter = transaction.get('function_parameter')
                    if function_name and function_parameter is not None:
                        function_map = {
                            "fibonacci": self.calculate_fibonacci,
                            "hash_test": self.hash_n_times,
                            "factorial": self.calculate_factorial,
                            "sum_natural": self.sum_natural,
                        }
                        if function_name in function_map:
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

                            recipient_node_identifier = transaction['sender']
                            recipient_node_address = self.node_addresses.get(recipient_node_identifier)

                            # Send the response transaction if the recipient address is found
                            if recipient_node_address:
                                recipient_node_url = f'http://{recipient_node_address}/transactions/new'

                                print("Response Transaction Before Sending:", response_transaction)
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
        # self.notify_transaction_pool_update()
        self.last_processed_block = len(self.chain) - 1

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

    def verify_request_response(self, request_hash, coordinator_id):
        """
        Verify a specific request-response pair by recomputing the result and comparing it.

        :param request_hash: The hash of the request transaction to verify
        :return: 1 if valid, 0 if invalid
        """
        # Search for the request transaction in the blockchain
        request_transaction = None
        for block in self.chain:
            for transaction in block['transactions']:
                if transaction.get('hash') == request_hash:
                    request_transaction = transaction
                    break
            if request_transaction:
                break

        if not request_transaction:
            return {'error': 'Request transaction not found'}, 404

        # Find the linked response transaction
        parent_hash = request_hash
        response_transaction = None
        for block in self.chain:
            for transaction in block['transactions']:
                if transaction.get('parent') == parent_hash:
                    response_transaction = transaction
                    break
            if response_transaction:
                break

        if not response_transaction:
            return {'error': 'Response transaction not found'}, 404

        # Recompute the function result locally
        function_name = request_transaction.get('function_name')
        function_parameter = request_transaction.get('function_parameter')

        if not function_name or function_parameter is None:
            return {'error': 'Invalid request transaction'}, 400

        function_map = {
            "fibonacci": self.calculate_fibonacci,
            "hash_test": self.hash_n_times,
            "factorial": self.calculate_factorial,
            "sum_natural": self.sum_natural,
        }

        if function_name not in function_map:
            return {'error': 'Unsupported function'}, 400

        recomputed_result = function_map[function_name](function_parameter)

        # We get the coordinator's hash (coordinator_id)
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

        # Create the verification transaction
        verification_transaction = {
            "sender": node_id,  # The verifying node
            "recipient": coordinator_id,  # Coordinator node
            "transaction_type": "verification",
            "function_name": function_name,
            "function_parameter": recomputed_result,
        }

        coordinator_node_address = self.node_addresses.get(coordinator_id)

        # Send the response transaction if the recipient address is found
        if coordinator_node_address:
            coordinator_node_url = f'http://{coordinator_node_address}/transactions/new'

            print("Verification Transaction Before Sending:", verification_transaction)
            try:
                response = requests.post(
                    coordinator_node_url,
                    json=verification_transaction,
                    headers={"Content-Type": "application/json"}
                )
                if response.status_code == 201:
                    print(
                        f"Verification transaction sent to node {coordinator_id}: {response.json()}")
                else:
                    print(
                        f"Failed to send verification to {coordinator_id}: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"Error sending verification to node {coordinator_id}: {e}")

        return {"verification_transaction": verification_transaction}, 200

    @staticmethod
    def get_random_odd_number(max_value):
        """
        Generate a random odd number less than the given max_value.
        """
        odd_numbers = [n for n in range(3, max_value) if n % 2 == 1]
        return random.choice(odd_numbers) if odd_numbers else 3  # Default to 1 if no odd numbers are available

    def select_nodes(self, count):
        """
        Randomly select 'count' number of nodes from the network.
        """
        return random.sample(self.nodes, count)

    def trigger_verification(self, transaction_hash):
        """
        Coordinator sends verification requests to a random odd number of selected nodes for the given transaction hash.
        """
        print(f"Starting verification for transaction hash: {transaction_hash}")
        num_nodes = len(self.nodes)
        if num_nodes < 4:
            print("Not enough nodes for verification.")
            return False

        # Get a random odd number less than the total number of nodes
        odd_count = Blockchain.get_random_odd_number(num_nodes)
        selected_nodes = self.select_nodes(odd_count)

        print(f"Selected nodes for verification: {selected_nodes}")

        # We get the coordinator's hash (coordinator_id)
        try:
            response = requests.get(f"http://localhost:{port}/id")
            if response.status_code == 200:
                coordinator_id = response.json().get("node_id", None)
                if not coordinator_id:
                    print("Error: Could not retrieve node identifier from /id endpoint.")
                    return False
            else:
                print(f"Error fetching node identifier, status: {response.status_code}")
                return False
        except requests.RequestException as e:
            print(f"Error contacting node for identifier: {e}")
            return False

        for node in selected_nodes:
            try:
                response = requests.post(f"http://{node}/verify_request",
                                         json={"request_hash": transaction_hash, "coordinator_id": coordinator_id})
                print(f"Response from node {node}: {response.status_code}, {response.text}")

            except requests.RequestException as e:
                print(f"Error contacting node {node} for verification: {e}")

        # Majority decision
        print(f"Verification transactions for {transaction_hash} will be recorded in the blockchain.")
        return True

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

    # Notify neighbors after mining a new block
    blockchain.notify_neighbors()

    # Notify neighbors about the updated transaction pool
    blockchain.notify_transaction_pool_update()

    # After mining the block, check and execute any requests directed to this node
    blockchain.check_and_execute_requests()

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
    )

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201


@app.route('/id', methods=['GET'])
def get_node_id():
    # Retrieve the unique identifier of the node
    response = {'node_id': node_identifier}
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
            # blockchain.check_and_execute_requests(
            # blockchain.chain[-(len(blockchain.chain) - len(blockchain.chain[:])):])
            return jsonify({'message': 'Chain updated successfully'}), 200
        else:
            return jsonify({'message': 'No update needed, chain is already up to date'}), 200

    return jsonify({'message': 'Chain already up to date'}), 200


@app.route('/update_transaction_pool', methods=['POST'])
def update_transaction_pool():
    values = request.get_json()
    updated_pool = values.get('transaction_pool')

    if updated_pool is None:
        return 'Missing transaction pool data', 400

    # Update the node's local transaction pool
    blockchain.transaction_pool = updated_pool

    response = {
        'message': 'Transaction pool updated successfully',
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


@app.route('/verify_request', methods=['POST'])
def verify_request():
    values = request.get_json()
    request_hash = values.get('request_hash')
    coordinator_id = values.get('coordinator_id')

    if not request_hash:
        return 'Missing request_hash', 400

    result, status = blockchain.verify_request_response(request_hash, coordinator_id)
    return jsonify(result), status


@app.route('/trigger_verification', methods=['POST'])
def trigger_verification():
    values = request.get_json()

    transaction_hash = values.get('transaction_hash')
    if not transaction_hash:
        return jsonify({'error': 'Missing transaction_hash'}), 400

    result = blockchain.trigger_verification(transaction_hash)
    if result:
        return jsonify({'message': f'Transaction {transaction_hash} verified successfully.'}), 200
    else:
        return jsonify({'message': f'Transaction {transaction_hash} verification failed.'}), 400


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
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
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port, debug=True)