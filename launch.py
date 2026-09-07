import subprocess
import requests
import os
import psutil
import random
import time
from FlaskBlockChain import Blockchain

import socket

# Edit this if your checkout on this Jetson isn't at this path -- it's the
# only place that needs to change.
PROJECT_DIR = "/home/jetson/blockchain-python-project"


def get_ip_address():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        # Connect to an external address (Google's DNS) without sending data
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

print(f"My IP Address: {get_ip_address()}")

# -------------------- Node Management Functions -------------------- #
def launch_nodes(node_count, base_port=5000):
    processes = []
    file_path = f"{PROJECT_DIR}/ip_port_list.txt"
    with open(file_path, "w") as file:
        file.write("")  # Empty the file
    ip = get_ip_address()

    for i in range(node_count):
        port = base_port + i
        log_path = f"{PROJECT_DIR}/node_{port}.log"
        command = f'bash -c "python3 -u {PROJECT_DIR}/FlaskBlockChain.py --port {port} > {log_path} 2>&1 &"'
        print(command)

        # Each node signs its responses/verdicts with ZEKRA_KEY_FILE as its
        # identity key. All nodes launched here share this process's
        # environment by default, which would give every node on this
        # Jetson the SAME identity -- a verifier couldn't tell them apart,
        # and either node could produce a signature that looks like the
        # other's. Give each one its own key file, per port, so that even
        # if ZEKRA_KEY_FILE is exported before running this script, each
        # node still gets a distinct identity.
        node_env = os.environ.copy()
        node_env["ZEKRA_KEY_FILE"] = f"{PROJECT_DIR}/node_{port}.pem"

        # Execute the command
        process = subprocess.Popen(
            command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=node_env,
        )
        with open(file_path, "a") as file:
            file.write(f"{ip}:{port}\n")
        
        # Wait for the node to be ready
        max_retries = 5
        retry_count = 0
        while retry_count < max_retries:
            try:
                response = requests.get(f"http://localhost:{port}/id")
                if response.status_code == 200:
                    print(f"Node at port {port} is ready")
                    break
            except requests.RequestException:
                retry_count += 1
                time.sleep(2)  # Wait 2 seconds before retrying
                if retry_count == max_retries:
                    print(f"Warning: Node at port {port} may not be fully initialized")
        
        processes.append((port, process))
        print(f"Node launched at http://localhost:{port}")

    # Additional delay to ensure all nodes are fully initialized
    time.sleep(5)
    return processes


def register_nodes(ports):
    base_url = "http://localhost"
    registration_success = True
    failed_registrations = []

    for port in ports:
        node_url = f"{base_url}:{port}"
        for other_port in ports:
            try:
                response = requests.post(
                    f"{node_url}/nodes/register",
                    json={"nodes": [f"{base_url}:{other_port}"]}
                )
                if response.status_code != 201:
                    # Registration failed for this specific node
                    failed_registrations.append((port, other_port))
                    registration_success = False
            except requests.RequestException as e:
                print(f"Failed to register node {other_port} to {port}: {e}")
                failed_registrations.append((port, other_port))
                registration_success = False

    if registration_success:
        print("All nodes are successfully registered with each other.")
    else:
        print("Some nodes failed to register. Details:")
        for port, other_port in failed_registrations:
            print(f"  Node {port} failed to register Node {other_port}")


def terminate_nodes(processes):
    print("\nTerminating all nodes...")
    for port, process in processes:
        try:
            process.terminate()
            process.wait(timeout=5)
            print(f"Node at http://localhost:{port} terminated.")
        except subprocess.TimeoutExpired:
            print(f"Node at http://localhost:{port} did not terminate in time. Killing it.")
            process.kill()
            process.wait()
        except Exception as e:
            print(f"Error while terminating node at http://localhost:{port}: {e}")

    clean_ports([p[0] for p in processes])


def clean_ports(ports):
    for port in ports:
        for proc in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
            try:
                cmdline = proc.info["cmdline"]
                if cmdline and any(str(port) in arg for arg in cmdline):
                    proc.kill()
                    print(f"Killed leftover process on port {port}.")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue


# -------------------- Blockchain Interaction Functions -------------------- #

def assign_coordinator(ports):
    """
    Randomly assign a coordinator from the available nodes.
    """
    if not ports:
        print("No nodes available to assign as coordinator.")
        return None
    coordinator = random.choice(ports)
    print(f"Coordinator assigned: Node {coordinator}")
    return coordinator


def manual_verify_latest_block(ports):
    """
    Manually verify all transactions in the latest block.
    """

    coordinator_port = assign_coordinator(ports)
    chain = fetch_chain(coordinator_port)
    if not chain:
        print("Could not fetch blockchain.")
        return

    latest_block = chain[-2]
    print(f"Latest Block Index: {latest_block['index']}")
    for transaction in latest_block['transactions']:
        transaction_hash = transaction['hash']
        print(f"Verifying transaction {transaction_hash}...")

        # Call the trigger_verification endpoint
        try:
            response = requests.post(
                f"http://localhost:{coordinator_port}/trigger_verification",
                json={"transaction_hash": transaction_hash}
            )
            if response.status_code == 200:
                print(response.json()['message'])
            else:
                print(f"Verification failed: {response.json().get('message', 'Unknown error')}")
        except requests.RequestException as e:
            print(f"Error during verification: {e}")


def verify_whole_blockchain(ports):
    """
    Manually verify all request-response pairs in the entire blockchain.
    """
    coordinator_port = assign_coordinator(ports)  # Pick a coordinator node
    chain = fetch_chain(coordinator_port)

    if not chain:
        print("Could not fetch blockchain.")
        return

    print("\n--- Verifying Entire Blockchain ---")

    request_response_map = {}
    for block in chain[1:]:  # Skip Genesis Block
        for transaction in block['transactions']:
            tx_hash = transaction['hash']
            if transaction['transaction_type'] == "request":
                request_response_map[tx_hash] = None
            elif transaction['transaction_type'] == "response":
                parent_hash = transaction.get('parent')
                if parent_hash:
                    request_response_map[parent_hash] = tx_hash  # Link response to request

    for request_hash, response_hash in request_response_map.items():
        print(f"\nVerifying Request {request_hash}...")

        if response_hash is None:
            print(f"Pending: Response transaction for request {request_hash} has not been mined yet.")
            continue

        print(f"Verifying response {response_hash}...")

        try:
            response = requests.post(
                f"http://localhost:{coordinator_port}/trigger_verification",
                json={"transaction_hash": request_hash}
            )
            if response.status_code == 200:
                print(f"{response.json()['message']}")
            else:
                print(f"Verification failed: {response.json().get('message', 'Unknown error')}")
        except requests.RequestException as e:
            print(f"Error during verification: {e}")

    print("\nBlockchain Verification Complete")


def fetch_chain(port):
    try:
        response = requests.get(f"http://localhost:{port}/chain")
        if response.status_code == 200:
            return response.json()['chain']
        else:
            print(f"Failed to fetch chain from port {port}. Response: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"Error fetching chain from port {port}: {e}")
        return None


def verify_request(port, request_hash):
    try:
        response = requests.post(
            f"http://localhost:{port}/verify_request",
            json={"request_hash": request_hash}
        )
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Failed to verify request. Response: {response.status_code}, {response.text}")
            return None
    except requests.RequestException as e:
        print(f"Error verifying request at port {port}: {e}")
        return None


def get_node_hashes(ports):
    node_hashes = {}
    for port in ports:
        try:
            response = requests.get(f"http://localhost:{port}/id")
            if response.status_code == 200:
                node_hash = response.json().get("node_id")
                node_hashes[port] = node_hash
                print(f"Node {port} -> Hash: {node_hash}")
            else:
                print(f"Failed to fetch ID for node {port}")
        except requests.RequestException as e:
            print(f"Error fetching ID for node {port}: {e}")
    return node_hashes


def create_transaction(ports, node_hashes):
    print("\n--- Create a Transaction ---")
    print(f"Available nodes: {', '.join(map(str, ports))}")
    sender_port = int(input("Enter sender node port: ").strip())
    recipient_port = int(input("Enter recipient node port: ").strip())
    function_name = input("Enter function name (e.g., fibonacci, sum_natural): ").strip()
    function_parameter = input("Enter function parameter (integer): ").strip()

    sender_hash = node_hashes.get(sender_port)
    recipient_hash = node_hashes.get(recipient_port)

    if not sender_hash or not recipient_hash:
        print("Error: Invalid sender or recipient port.")
        return

    transaction_data = {
        "sender": sender_hash,
        "recipient": recipient_hash,
        "transaction_type": "request",
        "function_name": function_name,
        "function_parameter": int(function_parameter),
    }

    node_url = f"http://localhost:{recipient_port}/transactions/new"
    try:
        response = requests.post(node_url, json=transaction_data)
        if response.status_code == 201:
            print("Transaction successfully created:", response.json())
        else:
            print("Failed to create transaction:", response.text)
    except requests.RequestException as e:
        print(f"Error sending transaction to node {recipient_port}: {e}")


def display_blockchain(chain):
    print("\n--- Blockchain ---")
    for block in chain:
        print(f"Block {block['index']}:")
        print(f"  Hash: {Blockchain.hash(block)}")
        print(f"  Previous Hash: {block['previous_hash']}")
        print(f"  Timestamp: {block['timestamp']}")
        print(f"  Transactions: {len(block['transactions'])} transactions")
        print("-" * 40)


def inspect_block(block):
    """
    Display details of a selected block.
    """
    print("\n--- Block Details ---")
    print(f"Index       : {block['index']}")
    print(f"Timestamp   : {block['timestamp']}")
    print(f"Previous Hash: {block['previous_hash']}")
    print(f"Proof       : {block['proof']}")
    print(f"Transactions: {len(block['transactions'])} transactions")

    if block["transactions"]:
        print("\n--- Transactions ---")
        for tx in block["transactions"]:
            print(f"  - Sender      : {tx['sender']}")
            print(f"    Recipient   : {tx['recipient']}")
            print(f"    Type        : {tx['transaction_type']}")
            if 'function_name' in tx:
                print(f"    Function    : {tx['function_name']}({tx['function_parameter']})")
            if 'parent' in tx:
                print(f"    Parent Hash : {tx['parent']}")
            print(f"    Hash        : {tx['hash']}")
            print("-" * 40)


def display_transaction_pool(transaction_pool):
    print("\n--- Transaction Pool ---")
    if not transaction_pool:
        print("The transaction pool is empty.")
    else:
        for i, transaction in enumerate(transaction_pool, start=1):
            print(f"Transaction {i}:")
            print(f"  Sender      : {transaction['sender']}")
            print(f"  Recipient   : {transaction['recipient']}")
            print(f"  Type        : {transaction['transaction_type']}")
            if 'function_name' in transaction:
                print(f"  Function    : {transaction['function_name']}({transaction['function_parameter']})")
            if 'parent' in transaction:
                print(f"  Parent Hash : {transaction['parent']}")
            print(f"  Hash        : {transaction['hash']}")
            print("-" * 40)


def show_running_nodes(ports):
    """
    Display the available running nodes and allow the user to inspect a specific node.
    """
    while True:
        print("\n--- Available Running Nodes ---")
        for i, port in enumerate(ports, start=1):
            print(f"{i}. Node at port {port}")

        print(f"{len(ports) + 1}. Go back")
        print("--------------------------------")

        choice = input("Enter the number of the node you want to inspect (or select Go Back): ").strip()

        if not choice.isdigit():
            print("Invalid input. Please enter a number.")
            continue

        choice = int(choice)

        if 1 <= choice <= len(ports):
            selected_port = ports[choice - 1]
            try:
                response = requests.get(f"http://localhost:{selected_port}/id")
                if response.status_code == 200:
                    node_id = response.json().get("node_id", "Unknown ID")
                    print(f"\nNode at port {selected_port} has ID: {node_id}\n")
                else:
                    print(f"Failed to fetch ID for node at port {selected_port}.")
            except requests.RequestException as e:
                print(f"Error contacting node at port {selected_port}: {e}")

        elif choice == len(ports) + 1:
            return  # Go back to display menu

        else:
            print("Invalid choice. Please try again.")


def mine_block(node_url):
    try:
        response = requests.get(f"{node_url}/mine")
        if response.status_code == 200:
            mined_data = response.json()
            print("\n--- Block Mined Successfully ---")
            print(f"Block Index       : {mined_data['index']}")
            print(f"Previous Hash     : {mined_data['previous_hash']}")
            print(f"Proof             : {mined_data['proof']}")
            print(f"Number of Transactions: {len(mined_data['transactions'])}")
            if len(mined_data['transactions']) > 0:
                print("\nTransactions:")
                for tx in mined_data['transactions']:
                    print(f"  - Sender      : {tx['sender']}")
                    print(f"    Recipient   : {tx['recipient']}")
                    print(f"    Function    : {tx['function_name']}({tx['function_parameter']})")
                    print(f"    Hash        : {tx['hash']}")
                    if 'parent' in tx and tx['parent']:
                        print(f"    Parent Hash : {tx['parent']}")
                    print()
        else:
            print(f"Failed to mine block: {response.status_code} - {response.text}")
    except requests.RequestException as e:
        print(f"Error during mining: {e}")


# -------------------- Interactive Menu -------------------- #

def display_menu(base_port, ports):
    while True:
        print("\n--- Display Menu ---")
        print("1. Display the blockchain")
        print("2. Inspect a specific block")
        print("3. Display transaction pool")
        print("4. Show running nodes")
        print("5. Go back to main menu")
        print("--------------------------------")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            chain = fetch_chain(base_port)
            if chain:
                display_blockchain(chain)

        elif choice == "2":
            chain = fetch_chain(base_port)  # Fetch blockchain from the first node
            if not chain:
                print("Error fetching the blockchain.")
                continue

            print("\nAvailable Blocks:")
            for i, block in enumerate(chain, start=1):
                print(f"  {i}. Block {block['index']} - Hash: {Blockchain.hash(block)}")

            selected_block = input("\nEnter the number of the block you want to inspect: ").strip()

            if not selected_block.isdigit():
                print("Invalid input. Please enter a valid number.")
                continue

            selected_block = int(selected_block) - 1  # Convert to zero-based index

            if 0 <= selected_block < len(chain):
                inspect_block(chain[selected_block])  # Pass the block to inspect_block
            else:
                print("Invalid block number. Please try again.")

        elif choice == "3":
            response = requests.get(f"http://localhost:{base_port}/transaction_pool")
            if response.status_code == 200:
                display_transaction_pool(response.json().get('transaction_pool', []))
            else:
                print("Failed to fetch the transaction pool.")

        elif choice == "4":
            show_running_nodes(ports)

        elif choice == "5":
            return  # Go back to the main menu
        else:
            print("Invalid choice. Please try again.")


def interactive_menu():
    node_count = int(input("How many nodes do you want to launch? "))
    base_port = 5000
    launched_nodes = launch_nodes(node_count)

    print("Registering nodes with each other...")
    time.sleep(3)

    ports = [base_port + i for i in range(node_count)]
    #register_nodes(ports)

    print("Fetching node identifiers...")
    node_hashes = get_node_hashes(ports)

    while True:
        print("\n--- Blockchain Manager Menu ---")
        print("1. Create a transaction")
        print("2. Mine a block")
        print("3. Display options")
        print("4. Verify the latest request-response blocks")
        print("5. Terminate all nodes")
        print("--------------------------------")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            create_transaction(ports, node_hashes)

        elif choice == "2":
            # List all available nodes
            print("\nAvailable nodes:")
            for port in ports:
                print(f"Node at port {port}")
            # Ask user for the node to mine on
            selected_port = input("Enter the port of the node to mine on: ").strip()
            if int(selected_port) in ports:
                mine_block(f"http://localhost:{selected_port}")
            else:
                print("Invalid port selected. Please try again.")

        elif choice == "3":
            display_menu(base_port, ports)

        elif choice == "4":
            manual_verify_latest_block(ports)

        # elif choice == "7":
        #    verify_whole_blockchain(ports)

        elif choice == "5":
            terminate_nodes(launched_nodes)
            break
        else:
            print("Invalid choice. Please try again.")




if __name__ == "__main__":

    node_count = int(input("How many nodes do you want to launch? "))
    #base_port = 5000
    launched_nodes = launch_nodes(node_count)
    get_ip_address()


    print(launched_nodes)
    #time.sleep(3)
    #project_dir = "/home/jetson/blockchain-python-project"
    #port = 5000
    #command = f'bash -c  " python3 /home/jetson/blockchain-python-project/FlaskBlockChain.py --port {port} &"'

    # Execute the command
    #process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #time.sleep(3)
    #print(process)
    #stdout, stderr = process.communicate()

    # Check if the command was successful
    #if process.returncode == 0:
    #    print(f"Node launched successfully on port {port}")
    #    print(stdout.decode())
    #else:
    #    print(f"Error launching node on port {port}")
    #    print(stderr.decode())
    