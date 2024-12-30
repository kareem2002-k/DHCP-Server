import socket
import threading
import sys
import json
import uuid
import time

# Server Configuration
HOST = '0.0.0.0'  # Listen on all available interfaces
PORT = 65432      # Non-privileged port

# DHCP Configuration
IP_POOL_START = '192.168.1.100'
IP_POOL_END = '192.168.1.200'
LEASE_TIME = 20  # Lease time in seconds (adjusted to 20 for demo)
OFFER_TIMEOUT = 300  # Time in seconds to hold an offer before releasing

authenticated_clients = {}
ip_leases = {}
ip_offers = {}
lock = threading.Lock()

# Function to convert IP address to integer
def ip_to_int(ip):
    parts = list(map(int, ip.split('.')))
    return parts[0] << 24 | parts[1] << 16 | parts[2] << 8 | parts[3]

# Function to convert integer to IP address
def int_to_ip(ip_int):
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"

# Function to generate IP pool
def generate_ip_pool(start_ip, end_ip):
    start = ip_to_int(start_ip)
    end = ip_to_int(end_ip)
    return [int_to_ip(ip) for ip in range(start, end + 1)]

ip_pool = generate_ip_pool(IP_POOL_START, IP_POOL_END)

# Function to insert IP into ip_pool in sorted order
def insert_ip_sorted(ip_pool, ip):
    ip_int = ip_to_int(ip)
    # Binary search for the correct insertion point
    left = 0
    right = len(ip_pool)
    while left < right:
        mid = (left + right) // 2
        if ip_to_int(ip_pool[mid]) < ip_int:
            left = mid + 1
        else:
            right = mid
    ip_pool.insert(left, ip)

# Function to handle client connections
def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    try:
        # Authentication Process
        conn.sendall(b"Username: ")
        username = conn.recv(1024).decode().strip()
        conn.sendall(b"Password: ")
        password = conn.recv(1024).decode().strip()

        # Simple Authentication (For Demo Purposes)
        if authenticate(username, password):
            with lock:
                authenticated_clients[addr] = username
            conn.sendall(b"Authentication Successful.\n")
            print(f"[AUTHENTICATED] {addr} as {username}")
        else:
            conn.sendall(b"Authentication Failed. Connection Closing.\n")
            print(f"[FAILED AUTH] {addr}")
            conn.close()
            return

        # Communication Loop
        while True:
            data = conn.recv(4096)
            if not data:
                break
            try:
                message = json.loads(data.decode())
                handle_dhcp_message(conn, addr, message)
            except json.JSONDecodeError:
                response = {"type": "ERROR", "message": "Invalid message format."}
                conn.sendall(json.dumps(response).encode())
    except ConnectionResetError:
        print(f"[DISCONNECTED] {addr} unexpectedly disconnected.")
    finally:
        with lock:
            if addr in authenticated_clients:
                del authenticated_clients[addr]
            # Release IP lease if exists
            if addr in ip_leases:
                released_ip = ip_leases[addr]['ip']
                insert_ip_sorted(ip_pool, released_ip)
                client_id = ip_leases[addr]['client_id']
                del ip_leases[addr]
                print(f"[LEASE RELEASED] {released_ip} released from {client_id} ({addr})")
            # Release offered IP if exists
            if addr in ip_offers:
                released_ip = ip_offers[addr]['ip']
                insert_ip_sorted(ip_pool, released_ip)
                client_id = ip_offers[addr]['client_id']
                del ip_offers[addr]
                print(f"[OFFER RELEASED] {released_ip} released from {client_id} ({addr})")
        conn.close()
        print(f"[CONNECTION CLOSED] {addr}")

# Simple Authentication Function
def authenticate(username, password):
    # In a real-world scenario, replace this with secure authentication
    valid_credentials = {
        'admin': 'adminpass',
        'user': 'userpass'
    }
    return valid_credentials.get(username) == password

# Function to handle DHCP messages
def handle_dhcp_message(conn, addr, message):
    msg_type = message.get("type")
    client_id = message.get("client_id", str(addr))
    print(f"[DHCP MESSAGE] {msg_type} from {client_id}")

    if msg_type == "DHCP_DISCOVER":
        # Offer an IP address without assigning it
        offer_ip = offer_ip_address(addr, client_id)
        if offer_ip:
            response = {
                "type": "DHCP_OFFER",
                "client_id": client_id,
                "offered_ip": offer_ip,
                "lease_time": LEASE_TIME,
                "options": {
                    "subnet_mask": "255.255.255.0",       # Option 1
                    "router": "192.168.1.1",              # Option 3
                    "dns_server": "8.8.8.8",              # Option 6
                    "domain_name": "example.com",         # Option 15
                    "dhcp_server_identifier": "192.168.1.1"  # Option 54
                }
            }
            conn.sendall(json.dumps(response).encode())
            print(f"[DHCP OFFER] Offered IP {offer_ip} to {client_id}")
        else:
            response = {
                "type": "DHCP_NACK",
                "message": "No available IP addresses.",
                "error_message": "IP pool exhausted."
            }
            conn.sendall(json.dumps(response).encode())
            print(f"[DHCP NACK] No available IP for {client_id}")

    elif msg_type == "DHCP_REQUEST":
        requested_ip = message.get("requested_ip")
        # Option 50: Requested IP Address
        requested_ip_option = message.get("options", {}).get("requested_ip")
        if requested_ip_option:
            requested_ip = requested_ip_option
        if handle_dhcp_request(addr, client_id, requested_ip):
            assigned_ip = ip_leases[addr]['ip']
            response = {
                "type": "DHCP_ACK",
                "client_id": client_id,
                "assigned_ip": assigned_ip,
                "lease_time": LEASE_TIME,
                "options": {
                    "subnet_mask": "255.255.255.0",       # Option 1
                    "router": "192.168.1.1",              # Option 3
                    "dns_server": "8.8.8.8",              # Option 6
                    "domain_name": "example.com",         # Option 15
                    "dhcp_server_identifier": "192.168.1.1",  # Option 54
                    "renewal_time": LEASE_TIME / 2,       # Option 58
                    "rebinding_time": (LEASE_TIME * 7) / 8  # Option 59
                }
            }
            conn.sendall(json.dumps(response).encode())
            print(f"[DHCP ACK] Assigned IP {assigned_ip} to {client_id}")
        else:
            response = {
                "type": "DHCP_NACK",
                "message": "Requested IP is invalid or unavailable.",
                "error_message": f"The IP address {requested_ip} is invalid or already in use."
            }
            conn.sendall(json.dumps(response).encode())
            print(f"[DHCP NACK] Invalid IP {requested_ip} requested by {client_id}")

    elif msg_type == "DHCP_RELEASE":
        # Handle DHCP_RELEASE message
        released_ip = message.get("released_ip")
        if handle_dhcp_release(addr, client_id, released_ip):
            response = {
                "type": "DHCP_RELEASE_ACK",
                "message": f"IP {released_ip} has been released."
            }
            conn.sendall(json.dumps(response).encode())
            print(f"[DHCP RELEASE] Released IP {released_ip} from {client_id} ({addr})")
        else:
            response = {
                "type": "DHCP_NACK",
                "message": "Release failed. IP not found or not assigned to client.",
                "error_message": f"The IP address {released_ip} is not assigned to you."
            }
            conn.sendall(json.dumps(response).encode())
            print(f"[DHCP RELEASE FAILED] {released_ip} not found for {client_id} ({addr})")

    else:
        response = {"type": "ERROR", "message": "Unknown DHCP message type."}
        conn.sendall(json.dumps(response).encode())
        print(f"[ERROR] Unknown DHCP message type from {client_id}")

# Function to offer an IP address
def offer_ip_address(addr, client_id):
    with lock:
        # Check if client already has an offer
        if addr in ip_offers:
            return ip_offers[addr]['ip']

        # Assign the first available IP (smallest) by popping the first element
        if ip_pool:
            offered_ip = ip_pool.pop(0)
            ip_offers[addr] = {
                "ip": offered_ip,
                "client_id": client_id,
                "offer_time": time.time()
            }
            # Start a timer to release the offer if not requested within OFFER_TIMEOUT
            threading.Thread(target=offer_timeout_handler, args=(addr,), daemon=True).start()
            return offered_ip
        else:
            return None

# Function to handle DHCP_REQUEST
def handle_dhcp_request(addr, client_id, requested_ip):
    with lock:
        # Check if there is an existing offer for this client
        if addr not in ip_offers:
            return False
        offered_ip = ip_offers[addr]['ip']
        if requested_ip != offered_ip:
            return False
        # Assign the IP by moving it from offers to leases
        ip_leases[addr] = {
            "ip": requested_ip,
            "lease_expiry": time.time() + LEASE_TIME,
            "client_id": client_id
        }
        del ip_offers[addr]
        return True

# Function to handle DHCP_RELEASE
def handle_dhcp_release(addr, client_id, released_ip):
    with lock:
        # Verify if the IP is leased to this client
        lease = ip_leases.get(addr)
        if lease and lease['ip'] == released_ip:
            # Release the IP
            insert_ip_sorted(ip_pool, released_ip)
            del ip_leases[addr]
            return True
        else:
            return False

# Function to handle offer timeout
def offer_timeout_handler(addr):
    time.sleep(OFFER_TIMEOUT)
    with lock:
        if addr in ip_offers:
            released_ip = ip_offers[addr]['ip']
            insert_ip_sorted(ip_pool, released_ip)
            print(f"[OFFER EXPIRED] {released_ip} released from {ip_offers[addr]['client_id']} ({addr})")
            del ip_offers[addr]

# Function to start the server
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((HOST, PORT))
    except socket.error as e:
        print(f"[ERROR] Bind failed. {e}")
        sys.exit()

    server.listen()
    print(f"[LISTENING] Server is listening on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        client_thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

# Function to display server status
def display_status():
    print("Server CLI Commands:")
    print(" - status: Display active connections and authenticated users.")
    print(" - leases: Display current IP leases.")
    print(" - offers: Display current IP offers.")
    print(" - help: Show available commands.")
    print(" - exit: Shut down the server.")
    while True:
        cmd = input(">> ").strip().lower()
        if cmd == "status":
            with lock:
                print(f"Active Connections: {len(authenticated_clients)}")
                for addr, user in authenticated_clients.items():
                    print(f" - {addr}: {user}")
        elif cmd == "leases":
            with lock:
                print(f"Current IP Leases: {len(ip_leases)}")
                for addr, lease in ip_leases.items():
                    lease_time_remaining = int(lease['lease_expiry'] - time.time())
                    print(f" - {lease['client_id']} ({addr}): {lease['ip']} (Expires in {lease_time_remaining} seconds)")
        elif cmd == "offers":
            with lock:
                print(f"Current IP Offers: {len(ip_offers)}")
                for addr, offer in ip_offers.items():
                    offer_time_remaining = int(OFFER_TIMEOUT - (time.time() - offer['offer_time']))
                    print(f" - {offer['client_id']} ({addr}): {offer['ip']} (Offer expires in {offer_time_remaining} seconds)")
        elif cmd == "help":
            print("Available Commands:")
            print(" - status: Display active connections and authenticated users.")
            print(" - leases: Display current IP leases.")
            print(" - offers: Display current IP offers.")
            print(" - help: Show available commands.")
            print(" - exit: Shut down the server.")
        elif cmd == "exit":
            print("Shutting down the server.")
            sys.exit()
        else:
            print("Unknown command. Type 'help' to see available commands.")

# Function to release expired leases
def lease_manager():
    while True:
        time.sleep(10)  # Check every 10 seconds
        current_time = time.time()
        with lock:
            expired_leases = [addr for addr, lease in ip_leases.items() if lease['lease_expiry'] < current_time]
            for addr in expired_leases:
                released_ip = ip_leases[addr]['ip']
                insert_ip_sorted(ip_pool, released_ip)
                client_id = ip_leases[addr]['client_id']
                del ip_leases[addr]
                print(f"[LEASE EXPIRED] {released_ip} released from {client_id} ({addr})")

if __name__ == "__main__":
    # Start server, lease manager, and status display in separate threads
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()

    lease_thread = threading.Thread(target=lease_manager, daemon=True)
    lease_thread.start()

    # Start CLI for server status
    display_status()
