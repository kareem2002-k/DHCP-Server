import socket
import threading
import sys
import json
import uuid
import time
import os
import shutil
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("dhcp_server.log"),
        logging.StreamHandler()
    ]
)

# Server Configuration
HOST = '0.0.0.0'  # Listen on all available interfaces
PORT = 65432      # Non-privileged port

# DHCP Configuration
DEFAULT_CONFIG = {
    "IP_POOL_START": "192.168.1.100",
    "IP_POOL_END": "192.168.1.200",
    "LEASE_TIME": 3600,      # Lease time in seconds (1 hour)
    "OFFER_TIMEOUT": 300     # Time in seconds to hold an offer before releasing
}

DB_FILE = 'dhcp_lease_db.json'

authenticated_clients = {}    # Maps addr_str to username
ip_leases = {}                # Maps client_id to lease details
ip_offers = {}                # Maps client_id to offer details
ip_pool = []
config = DEFAULT_CONFIG.copy()
lock = threading.Lock()

# Mapping from addr_str to client_id
addr_to_client_id = {}

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

# Function to convert address tuple to string
def addr_to_str(addr):
    return f"{addr[0]}:{addr[1]}"

# Function to insert IP into ip_pool in sorted order
def insert_ip_sorted(ip_pool_list, ip):
    ip_int = ip_to_int(ip)
    # Binary search for the correct insertion point
    left = 0
    right = len(ip_pool_list)
    while left < right:
        mid = (left + right) // 2
        if ip_to_int(ip_pool_list[mid]) < ip_int:
            left = mid + 1
        else:
            right = mid
    ip_pool_list.insert(left, ip)

# Function to load the database from JSON file
def load_database():
    global ip_pool, ip_leases, ip_offers, config
    if os.path.exists(DB_FILE):
        try:
            shutil.copy(DB_FILE, DB_FILE + ".bak")  # Create a backup
            with open(DB_FILE, 'r') as f:
                data = json.load(f)
                ip_pool = data.get("ip_pool", generate_ip_pool(DEFAULT_CONFIG["IP_POOL_START"], DEFAULT_CONFIG["IP_POOL_END"]))
                ip_leases = data.get("ip_leases", {})
                # Convert lease_expiry and offer_time to float if necessary
                for lease in ip_leases.values():
                    lease['lease_expiry'] = float(lease['lease_expiry'])
                ip_offers = data.get("ip_offers", {})
                for offer in ip_offers.values():
                    offer['offer_time'] = float(offer['offer_time'])
                config = data.get("config", DEFAULT_CONFIG.copy())
            logging.info("Loaded lease database from JSON.")
        except (json.JSONDecodeError, ValueError) as e:
            logging.error(f"Failed to load database: {e}")
            if os.path.exists(DB_FILE + ".bak"):
                shutil.copy(DB_FILE + ".bak", DB_FILE)  # Restore from backup
                logging.info("Restored lease database from backup.")
                load_database()  # Attempt to load again
            else:
                ip_pool = generate_ip_pool(config["IP_POOL_START"], config["IP_POOL_END"])
                ip_leases = {}
                ip_offers = {}
                save_database()
                logging.info("Initialized new lease database.")
    else:
        with lock:
            ip_pool = generate_ip_pool(config["IP_POOL_START"], config["IP_POOL_END"])
            ip_leases = {}
            ip_offers = {}
        save_database()
        logging.info("Initialized new lease database.")

# Function to save the database to JSON file atomically
def save_database():
    with lock:
        data = {
            "ip_pool": ip_pool,
            "ip_leases": ip_leases,
            "ip_offers": ip_offers,
            "config": config
        }
        try:
            temp_file = DB_FILE + ".tmp"
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=4)
            os.replace(temp_file, DB_FILE)  # Atomic operation
            logging.info("Saved lease database to JSON.")
        except Exception as e:
            logging.error(f"Failed to save database: {e}")

# Function to handle client connections
def handle_client(conn, addr):
    addr_str = addr_to_str(addr)
    logging.info(f"New connection from {addr_str}.")
    try:
        # Authentication Process
        conn.sendall(b"Username: ")
        username = conn.recv(1024).decode().strip()
        conn.sendall(b"Password: ")
        password = conn.recv(1024).decode().strip()

        # Simple Authentication (For Demo Purposes)
        if authenticate(username, password):
            with lock:
                authenticated_clients[addr_str] = username
            conn.sendall(b"Authentication Successful.\n")
            logging.info(f"Authenticated {addr_str} as {username}.")
        else:
            conn.sendall(b"Authentication Failed. Connection Closing.\n")
            logging.warning(f"Failed authentication attempt from {addr_str}.")
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
                logging.error(f"Received invalid JSON from {addr_str}.")
    except ConnectionResetError:
        logging.warning(f"Connection reset by {addr_str}.")
    finally:
        handle_client_disconnection(addr)
        conn.close()
        logging.info(f"Connection closed for {addr_str}.")

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
    addr_str = addr_to_str(addr)
    msg_type = message.get("type")
    client_id = message.get("client_id", addr_str)  # Use addr_str as default if client_id not provided
    logging.info(f"Received DHCP message '{msg_type}' from {client_id} ({addr_str}).")

    if msg_type == "DHCP_DISCOVER":
        # Offer an IP address without assigning it
        offer_ip = offer_ip_address(client_id)
        if offer_ip:
            response = {
                "type": "DHCP_OFFER",
                "client_id": client_id,
                "offered_ip": offer_ip,
                "lease_time": config["LEASE_TIME"],
                "subnet_mask": "255.255.255.0",
                "router": "192.168.1.1",
                "dns_server": "8.8.8.8"
            }
            conn.sendall(json.dumps(response).encode())
            logging.info(f"Offered IP {offer_ip} to {client_id} ({addr_str}).")
            # Map addr_str to client_id
            with lock:
                addr_to_client_id[addr_str] = client_id
            save_database()
        else:
            response = {
                "type": "DHCP_NACK",
                "message": "No available IP addresses."
            }
            conn.sendall(json.dumps(response).encode())
            logging.warning(f"No available IP to offer to {client_id} ({addr_str}).")

    elif msg_type == "DHCP_REQUEST":
        requested_ip = message.get("requested_ip")
        if handle_dhcp_request(client_id, requested_ip):
            assigned_ip = ip_leases[client_id]['ip']
            response = {
                "type": "DHCP_ACK",
                "client_id": client_id,
                "assigned_ip": assigned_ip,
                "lease_time": config["LEASE_TIME"]
            }
            conn.sendall(json.dumps(response).encode())
            logging.info(f"Assigned IP {assigned_ip} to {client_id} ({addr_str}).")
            save_database()
        else:
            response = {
                "type": "DHCP_NACK",
                "message": "Requested IP is invalid or unavailable."
            }
            conn.sendall(json.dumps(response).encode())
            logging.warning(f"Invalid IP {requested_ip} requested by {client_id} ({addr_str}).")

    else:
        response = {"type": "ERROR", "message": "Unknown DHCP message type."}
        conn.sendall(json.dumps(response).encode())
        logging.error(f"Unknown DHCP message type '{msg_type}' from {client_id} ({addr_str}).")

# Function to offer an IP address
def offer_ip_address(client_id):
    with lock:
        # Check if client already has an offer
        if client_id in ip_offers:
            return ip_offers[client_id]['ip']

        # Check if client already has a lease
        if client_id in ip_leases:
            return ip_leases[client_id]['ip']

        # Assign the first available IP (smallest) by popping the first element
        if ip_pool:
            offered_ip = ip_pool.pop(0)
            ip_offers[client_id] = {
                "ip": offered_ip,
                "client_id": client_id,
                "offer_time": time.time()
            }
            # Start a timer to release the offer if not requested within OFFER_TIMEOUT
            threading.Thread(target=offer_timeout_handler, args=(client_id,), daemon=True).start()
            logging.info(f"Offered IP {offered_ip} to {client_id}.")
            return offered_ip
        else:
            return None

# Function to handle DHCP_REQUEST
def handle_dhcp_request(client_id, requested_ip):
    with lock:
        # Check if there is an existing offer for this client
        if client_id not in ip_offers:
            logging.warning(f"No existing offer for {client_id}.")
            return False
        offered_ip = ip_offers[client_id]['ip']
        if requested_ip != offered_ip:
            logging.warning(f"Requested IP {requested_ip} does not match offered IP {offered_ip} for {client_id}.")
            return False
        # Assign the IP by moving it from offers to leases
        ip_leases[client_id] = {
            "ip": requested_ip,
            "lease_expiry": time.time() + config["LEASE_TIME"],
            "client_id": client_id
        }
        del ip_offers[client_id]
        logging.info(f"Assigned IP {requested_ip} to {client_id}.")
        return True

# Function to handle offer timeout
def offer_timeout_handler(client_id):
    time.sleep(config["OFFER_TIMEOUT"])
    with lock:
        if client_id in ip_offers:
            released_ip = ip_offers[client_id]['ip']
            insert_ip_sorted(ip_pool, released_ip)
            logging.info(f"Offer expired: Released IP {released_ip} from {client_id}.")
            del ip_offers[client_id]
            save_database()

# Function to start the server
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((HOST, PORT))
        logging.info(f"Server bound to {HOST}:{PORT}.")
    except socket.error as e:
        logging.error(f"Bind failed: {e}")
        sys.exit(1)

    server.listen()
    logging.info(f"Server is listening on {HOST}:{PORT}.")

    while True:
        conn, addr = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        client_thread.start()
        with lock:
            active_connections = threading.active_count() - 1  # Subtract main thread
        logging.info(f"Active Connections: {active_connections}")

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
                for client_id, lease in ip_leases.items():
                    lease_time_remaining = int(lease['lease_expiry'] - time.time())
                    lease_time_remaining = max(lease_time_remaining, 0)
                    print(f" - {lease['client_id']}: {lease['ip']} (Expires in {lease_time_remaining} seconds)")
        elif cmd == "offers":
            with lock:
                print(f"Current IP Offers: {len(ip_offers)}")
                for client_id, offer in ip_offers.items():
                    offer_time_remaining = int(config["OFFER_TIMEOUT"] - (time.time() - offer['offer_time']))
                    offer_time_remaining = max(offer_time_remaining, 0)
                    print(f" - {offer['client_id']}: {offer['ip']} (Offer expires in {offer_time_remaining} seconds)")
        elif cmd == "help":
            print("Available Commands:")
            print(" - status: Display active connections and authenticated users.")
            print(" - leases: Display current IP leases.")
            print(" - offers: Display current IP offers.")
            print(" - help: Show available commands.")
            print(" - exit: Shut down the server.")
        elif cmd == "exit":
            print("Shutting down the server.")
            logging.info("Server shutting down via CLI command.")
            save_database()
            sys.exit()
        else:
            print("Unknown command. Type 'help' to see available commands.")

# Function to release expired leases
def lease_manager():
    while True:
        time.sleep(10)  # Check every 10 seconds
        current_time = time.time()
        with lock:
            expired_leases = [client_id for client_id, lease in ip_leases.items() if lease['lease_expiry'] < current_time]
            for client_id in expired_leases:
                released_ip = ip_leases[client_id]['ip']
                insert_ip_sorted(ip_pool, released_ip)
                del ip_leases[client_id]
                logging.info(f"Lease expired: Released IP {released_ip} from {client_id}.")
            if expired_leases:
                save_database()

# Function to handle client disconnection
def handle_client_disconnection(addr):
    addr_str = addr_to_str(addr)
    with lock:
        # Retrieve client_id using addr_str
        client_id = addr_to_client_id.get(addr_str)

        if client_id:
            # Remove from authenticated_clients
            if addr_str in authenticated_clients:
                del authenticated_clients[addr_str]

            # Release IP lease if exists
            if client_id in ip_leases:
                released_ip = ip_leases[client_id]['ip']
                insert_ip_sorted(ip_pool, released_ip)
                del ip_leases[client_id]
                logging.info(f"Lease released: {released_ip} from {client_id}.")
            
            # Release offered IP if exists
            if client_id in ip_offers:
                released_ip = ip_offers[client_id]['ip']
                insert_ip_sorted(ip_pool, released_ip)
                del ip_offers[client_id]
                logging.info(f"Offer released: {released_ip} from {client_id}.")

            # Remove the addr_str to client_id mapping
            del addr_to_client_id[addr_str]
            save_database()
        else:
            logging.info(f"No client_id found for {addr_str} during disconnection.")

if __name__ == "__main__":
    try:
        # Load existing database or initialize a new one
        load_database()

        # Start server, lease manager, and status display in separate threads
        server_thread = threading.Thread(target=start_server, daemon=True)
        server_thread.start()

        lease_thread = threading.Thread(target=lease_manager, daemon=True)
        lease_thread.start()

        # Start CLI for server status
        display_status()
    except KeyboardInterrupt:
        print("\nShutting down the server.")
        logging.info("Server shutting down via KeyboardInterrupt.")
        save_database()
        sys.exit()
