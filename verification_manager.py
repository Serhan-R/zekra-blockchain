import requests


def fetch_chain(port):
    """
    Fetch the blockchain data from a given node.
    """
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


def extract_request_hashes(chain):
    """
    Extract all request hashes from the blockchain.
    """
    request_hashes = []
    for block in chain:
        for transaction in block['transactions']:
            if transaction['transaction_type'] == 'request' and 'hash' in transaction:
                request_hashes.append(transaction['hash'])
    return request_hashes


def verify_request(port, request_hash):
    """
    Verify a specific request hash at a given node.
    """
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


def main():
    print("=== Request Verification Script ===")
    port = input("Enter the port of the node (e.g., 5000): ").strip()  # Who is going to be the verifier?

    print("\nFetching blockchain data...")
    chain = fetch_chain(port)
    if not chain:
        print("Could not fetch blockchain. Exiting.")
        return

    print("\nExtracting request hashes...")
    request_hashes = extract_request_hashes(chain)
    if not request_hashes:
        print("No request transactions found in the blockchain. Exiting.")
        return

    print("\nFound the following request hashes:")
    for i, request_hash in enumerate(request_hashes):
        print(f"{i + 1}: {request_hash}")

    choice = input("\nEnter the number of the request hash to verify, or 'all' to verify all: ").strip()
    if choice.lower() == 'all':
        print("\nVerifying all request hashes...")
        for request_hash in request_hashes:
            result = verify_request(port, request_hash)
            print(f"Hash: {request_hash} -> Result: {result}")
    else:
        try:
            index = int(choice) - 1
            if 0 <= index < len(request_hashes):
                request_hash = request_hashes[index]
                print(f"\nVerifying request hash: {request_hash}...")
                result = verify_request(port, request_hash)
                print(f"Result: {result}")
            else:
                print("Invalid selection. Exiting.")
        except ValueError:
            print("Invalid input. Exiting.")


if __name__ == "__main__":
    main()
