import subprocess
import requests
import os
import psutil
import random
import secrets
import time
from FlaskBlockChain import Blockchain


# -------------------- Node Management Functions -------------------- #
def launch_nodes(node_count, base_port=5000):
    processes = []
    #project_dir = "/home/eren/folderr1/FlaskBlockChain"
    #venv_activate = "source /home/eren/folderr1/venv/bin/activate"

    for i in range(node_count):
        port = base_port + i
        command = f"""
        bash -c "
        python3 FlaskBlockChain.py --port {port}
        "
        """
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        processes.append((port, process))
        # print(f"Node launched at http://localhost:{port}")

    return processes


def register_nodes(nodes):
    registration_success = True
    for node in nodes:
        for other_node in nodes:
            if other_node != node:
                try:
                    response = requests.post(
                    f"http://{node['ip']}:{node['port']}/nodes/register",
                    json={"nodes": [f"http://{other_node['ip']}:{other_node['port']}"]}
                    )
                    if response.status_code != 201:
                        print(f"Registration failed for node {other_node['ip']}:{other_node['port']}.")
                        registration_success = False
                except requests.RequestException as e:
                    print(f"Error while registering node {other_node['ip']}:{other_node['port']} {e}")
                    registration_success = False
    if registration_success:
        print("All nodes are successfully registered with each other.")
        time.sleep(2)
    else:
        print("WARNING: Some nodes failed to register")


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


def manual_verify_latest_block(nodes):
    """
    Manually verify all transactions in the latest block.
    """

    #coordinator_port = assign_coordinator(ports)
    #fixed "coordinator" for now
    url = f"http://{nodes[0]['ip']}:{nodes[0]['port']}"
    chain = fetch_chain(url)
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
                f"http://{url}/trigger_verification",
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


def fetch_chain(URL):
    try:
        response = requests.get(f"{URL}/chain")
        if response.status_code == 200:
            return response.json()['chain']
        else:
            print(f"Failed to fetch chain from port {URL}. Response: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"Error fetching chain from port {URL}: {e}")
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


def get_node_hash(IP,port):
    try:
        response = requests.get(f"http://{IP}:{port}/id")
        if response.status_code == 200:
            node_hash = response.json().get("node_id")
            print(f"Node {IP}:{port} -> Hash: {node_hash}")
        else:
            print(f"Failed to fetch ID for node {port}")
    except requests.RequestException as e:
        print(f"Error fetching ID for node {port}: {e}")
    return node_hash


def create_transaction(nodes):
    print("\n--- Create a Transaction ---")
    print(f"Available nodes:")
    for node in nodes:
        print(f"Node IP: {node['ip']}, Port: {node['port']}, Hash: {node['hash']}")
    sender_hash = input("Enter sender node hash: ").strip()
    recipient_hash = input("Enter recipient node hash: ").strip()
    function_name = input("Enter function name (e.g., fibonacci, sum_natural, zekra_attestation): ").strip()

    # A ZEKRA challenge needs a program_id (so the prover knows which reference
    # to answer against -- see zekra_integration.build_zekra_response(), which
    # otherwise finds no reference and silently refuses to answer) and a nonce
    # that's fresh and under 254 bits (ISSUES.md #15). Every other function_name
    # keeps working exactly as before.
    program_id = None
    if function_name == "zekra_attestation":
        program_id = input(
            "Enter program id (must already be published AND MINED as a signed "
            "reference, e.g. crc32): "
        ).strip()
        function_parameter = input(
            "Enter nonce (integer, must be fresh -- leave blank to generate one): "
        ).strip()
        if not function_parameter:
            function_parameter = str(secrets.randbelow(2 ** 253))
            print(f"Generated nonce: {function_parameter}")
    else:
        function_parameter = input("Enter function parameter (integer): ").strip()

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
    if program_id:
        transaction_data["program_id"] = program_id
    print(f"Creating transaction: {transaction_data}")
    for node in nodes:
        if node['hash'] == sender_hash:
            sender_ip = node['ip']
            sender_port = node['port']
    node_url = f"http://{sender_ip}:{sender_port}/transactions/new"
    try:
        response = requests.post(node_url, json=transaction_data)
        if response.status_code == 201:
            print("Transaction successfully created:", response.json())
        else:
            print("Failed to create transaction:", response.text)
    except requests.RequestException as e:
        print(f"Error sending transaction to node {sender_ip}:{sender_port}: {e}")


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


def show_running_nodes(nodes):
    """
    Display the available running nodes and allow the user to inspect a specific node.
    """
    while True:
        for node in nodes:
            print(f"Node IP: {node['ip']}, Port: {node['port']}, Hash: {node['hash']}")

        print(f"{len(nodes) + 1}. Go back")
        print("--------------------------------")

        choice = input("Enter the number of the node you want to inspect (or select Go Back): ").strip()

        if not choice.isdigit():
            print("Invalid input. Please enter a number.")
            continue

        choice = int(choice)

        if 1 <= choice <= len(nodes):
            selected_node = nodes[choice - 1]
            try:
                url = f"http://{selected_node['ip']}:{selected_node['port']}"
                response = requests.get(f"{url}/id")
                if response.status_code == 200:
                    node_id = response.json().get("node_id", "Unknown ID")
                    print(f"\nNode at {selected_node['ip']}:{selected_node['port']} has ID: {node_id}\n")
                else:
                    print(f"Failed to fetch ID for node at {selected_node['ip']}:{selected_node['port']}.")
            except requests.RequestException as e:
                print(f"Error contacting node at port at {selected_node['ip']}:{selected_node['port']}: {e}")

        elif choice == len(nodes) + 1:
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
                    # print(f"  - Sender      : {tx['sender']}")
                    # print(f"    Recipient   : {tx['recipient']}")
                    # print(f"    Function    : {tx['function_name']}({tx['function_parameter']})")
                    # print(f"    Hash        : {tx['hash']}")
                    # if 'parent' in tx and tx['parent']:
                    #     print(f"    Parent Hash : {tx['parent']}")
                    print(tx)
        else:
            print(f"Failed to mine block: {response.status_code} - {response.text}")
    except requests.RequestException as e:
        print(f"Error during mining: {e}")


def manual_count_verdicts(URL):
    """
    Make a request to the /count_verdicts endpoint of the given node and display the result.
    """
    start_time = time.time()
    print(f"\n--- Counting Verdicts at {URL} ---")
    try:
        response = requests.get(f"{URL}/count_verdicts")
        end_time = time.time()
        if response.status_code == 200:
            result = response.json()
            print(f"{result['message']}")
            print(f"Compute time Taken: {result['time_taken_seconds']}", "Total time taken: ", end_time - start_time)
        else:
            print(f"Failed to count verdicts at node {URL}. Status: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error during manual verdict counting at node {URL}: {e}")


# -------------------- Interactive Menu -------------------- #

def display_menu(nodes):
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
            url = f"http://{nodes[0]['ip']}:{nodes[0]['port']}"
            chain = fetch_chain(url)
            if chain:
                display_blockchain(chain)
        #TODO: keep checking this
        elif choice == "2":
            url = f"http://{nodes[0]['ip']}:{nodes[0]['port']}"
            chain = fetch_chain(url)  # Fetch blockchain from the first node
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
            url = f"http://{nodes[0]['ip']}:{nodes[0]['port']}"
            response = requests.get(f"{url}/transaction_pool")
            if response.status_code == 200:
                display_transaction_pool(response.json().get('transaction_pool', []))
            else:
                print("Failed to fetch the transaction pool.")

        elif choice == "4":
            show_running_nodes(nodes)

        elif choice == "5":
            return  # Go back to the main menu
        else:
            print("Invalid choice. Please try again.")


def interactive_menu():
    f = open("config.txt", "r")
    node_data =  f.readlines() # [IP:port, IP:port, ...]
    nodes = []
    for entry in node_data:
        node_info = {}
        ip, port = entry.split(":")
        node_info['ip'] = str(ip)
        node_info['port'] = int(port)
        node_info['hash'] = str(get_node_hash(str(ip), int(port)))
        nodes.append(node_info)
    print("Registering nodes with each other...")
    print(nodes)
    register_nodes(nodes) 
    while True:
        time.sleep(2)
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\n--- Blockchain Manager Menu ---")
        print("1. Create a transaction")
        print("2. Mine a block")
        print("3. Display options")
        print("4. Verify the latest request-response blocks")
        print("5. Terminate control panel")
        print("--------------------------------")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            create_transaction(nodes)

        elif choice == "2":
            # List all available nodes
            print(f"Available nodes:")
            for node in nodes:
                print(f"Node IP: {node['ip']}, Port: {node['port']}, Hash: {node['hash']}")
            # Ask user for the node to mine on
            selected_node_hash = input("Enter hash  the node to mine on: ").strip()
            for node in nodes:
                if node['hash'] == selected_node_hash:
                    selected_ip = node['ip']
                    selected_port = node['port']
            if selected_ip is not None:
                mine_block(f"http://{selected_ip}:{selected_port}")
            else:
                print("Invalid port selected. Please try again.")

        elif choice == "3":
            display_menu(nodes)

        elif choice == "4":
            URL = f"http://{nodes[0]['ip']}:{nodes[0]['port']}"
            manual_count_verdicts(URL)

        elif choice == "5":
            return
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    interactive_menu()