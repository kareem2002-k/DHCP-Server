import socket
import json
import uuid
import time
import sys

# Client Configuration
SERVER_HOST = '127.0.0.1'  # Replace with server's IP if different
SERVER_PORT = 65432

# DHCP Message Types
DHCP_DISCOVER = "DHCP_DISCOVER"
DHCP_OFFER = "DHCP_OFFER"
DHCP_REQUEST = "DHCP_REQUEST"
DHCP_ACK = "DHCP_ACK"
DHCP_NACK = "DHCP_NACK"
DHCP_RELEASE = "DHCP_RELEASE"
ERROR = "ERROR"

class DHCPClient:
    def __init__(self, server_host, server_port, username, password):
        self.server_host = server_host
        self.server_port = server_port
        self.username = username
        self.password = password
        self.client_id = str(uuid.uuid4())
        self.assigned_ip = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        try:
            self.sock.connect((self.server_host, self.server_port))
            print(f"[CONNECTED] Connected to DHCP server at {self.server_host}:{self.server_port}")
        except socket.error as e:
            print(f"[ERROR] Could not connect to server: {e}")
            sys.exit()

    def authenticate(self):
        try:
            # Receive "Username: " prompt
            prompt = self.sock.recv(1024).decode()
            if "Username" in prompt:
                self.sock.sendall((self.username + "\n").encode())
                print(f"[AUTH] Sent username: {self.username}")

            # Receive "Password: " prompt
            prompt = self.sock.recv(1024).decode()
            if "Password" in prompt:
                self.sock.sendall((self.password + "\n").encode())
                print(f"[AUTH] Sent password.")

            # Receive authentication response
            response = self.sock.recv(1024).decode()
            print(f"[AUTH RESPONSE] {response.strip()}")
            if "Successful" not in response:
                print("[AUTH FAILED] Exiting.")
                self.sock.close()
                sys.exit()
        except socket.error as e:
            print(f"[ERROR] Authentication failed: {e}")
            self.sock.close()
            sys.exit()

    def send_message(self, message):
        try:
            self.sock.sendall(json.dumps(message).encode())
            print(f"[SENT] {message['type']} message sent.")
        except socket.error as e:
            print(f"[ERROR] Failed to send message: {e}")
            self.sock.close()
            sys.exit()

    def receive_message(self):
        try:
            data = self.sock.recv(4096)
            if not data:
                print("[DISCONNECTED] Server closed the connection.")
                self.sock.close()
                sys.exit()
            message = json.loads(data.decode())
            print(f"[RECEIVED] {message['type']} message received.")
            return message
        except json.JSONDecodeError:
            print("[ERROR] Received invalid JSON.")
            return None
        except socket.error as e:
            print(f"[ERROR] Failed to receive message: {e}")
            self.sock.close()
            sys.exit()

    def dhcp_discover(self):
        message = {
            "type": DHCP_DISCOVER,
            "client_id": self.client_id,
            "options": {
                "parameter_request_list": [
                    "subnet_mask",
                    "router",
                    "dns_server",
                    "domain_name",
                    "hostname",
                    "renewal_time",
                    "rebinding_time"
                ],
                "hostname": "test-client",
                "client_identifier": self.client_id
            }
        }
        self.send_message(message)

    def dhcp_request(self, requested_ip=None):
        options = {
            "client_identifier": self.client_id
        }
        if requested_ip:
            options["requested_ip"] = requested_ip  # Option 50
        message = {
            "type": DHCP_REQUEST,
            "client_id": self.client_id,
            "requested_ip": requested_ip if requested_ip else "",
            "options": options
        }
        self.send_message(message)

    def dhcp_release(self):
        if not self.assigned_ip:
            print("[RELEASE] No IP assigned to release.")
            return
        message = {
            "type": DHCP_RELEASE,
            "client_id": self.client_id,
            "released_ip": self.assigned_ip
        }
        self.send_message(message)

    def perform_dhcp_handshake(self, request_specific_ip=None, simulate_error=False):
        # Step 1: DHCP_DISCOVER
        self.dhcp_discover()

        # Step 2: Receive DHCP_OFFER
        offer = self.receive_message()
        if offer and offer.get("type") == DHCP_OFFER:
            print(f"[OFFER] Offered IP: {offer.get('offered_ip')}")
            print(f"[OFFER] Lease Time: {offer.get('lease_time')} seconds")
            print("[OFFER] DHCP Options:")
            for key, value in offer.get("options", {}).items():
                print(f"  - {key}: {value}")

            # Optionally request a specific IP to simulate error
            if simulate_error:
                requested_ip = "192.168.1.999"  # Invalid IP to trigger DHCP_NACK
                print(f"[TEST] Requesting invalid IP: {requested_ip}")
                self.dhcp_request(requested_ip=requested_ip)
            else:
                # Step 3: DHCP_REQUEST
                requested_ip = request_specific_ip if request_specific_ip else offer.get("offered_ip")
                self.dhcp_request(requested_ip=requested_ip)

                # Step 4: Receive DHCP_ACK or DHCP_NACK
                response = self.receive_message()
                if response:
                    if response.get("type") == DHCP_ACK:
                        self.assigned_ip = response.get("assigned_ip")
                        print(f"[ACK] IP Assigned: {self.assigned_ip}")
                        print(f"[ACK] Lease Time: {response.get('lease_time')} seconds")
                        print("[ACK] DHCP Options:")
                        for key, value in response.get("options", {}).items():
                            print(f"  - {key}: {value}")
                    elif response.get("type") == DHCP_NACK:
                        print(f"[NACK] Message: {response.get('message')}")
                        print(f"[NACK] Error Message: {response.get('error_message')}")
                    else:
                        print("[ERROR] Unexpected response type.")
        elif offer and offer.get("type") == DHCP_NACK:
            print(f"[NACK] Message: {offer.get('message')}")
            print(f"[NACK] Error Message: {offer.get('error_message')}")
        else:
            print("[ERROR] Did not receive DHCP_OFFER.")

    def close_connection(self):
        self.sock.close()
        print("[CLOSED] Connection closed.")

def print_menu():
    print("\nDHCP Client Menu:")
    print("1. Perform DHCP Handshake (Request Offered IP)")
    print("2. Perform DHCP Handshake (Request Specific IP)")
    print("3. Perform DHCP Handshake (Simulate Error - Request Invalid IP)")
    print("4. Release IP Lease")
    print("5. Exit")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <username> <password>")
        sys.exit()

    username = sys.argv[1]
    password = sys.argv[2]

    client = DHCPClient(SERVER_HOST, SERVER_PORT, username, password)
    client.connect()
    client.authenticate()

    while True:
        print_menu()
        choice = input("Select an option (1-5): ").strip()

        if choice == '1':
            print("\n[TEST] Performing DHCP Handshake (Request Offered IP)...")
            client.perform_dhcp_handshake()
        elif choice == '2':
            specific_ip = input("Enter the specific IP you want to request (e.g., 192.168.1.150): ").strip()
            print(f"\n[TEST] Performing DHCP Handshake (Request Specific IP: {specific_ip})...")
            client.perform_dhcp_handshake(request_specific_ip=specific_ip)
        elif choice == '3':
            print("\n[TEST] Performing DHCP Handshake (Simulate Error - Request Invalid IP)...")
            client.perform_dhcp_handshake(simulate_error=True)
        elif choice == '4':
            print("\n[TEST] Releasing IP Lease...")
            client.dhcp_release()
            response = client.receive_message()
            if response.get("type") == "DHCP_RELEASE_ACK":
                print(f"[RELEASE ACK] {response.get('message')}")
                client.assigned_ip = None
            elif response.get("type") == "DHCP_NACK":
                print(f"[RELEASE NACK] {response.get('message')}")
                print(f"[RELEASE NACK] Error Message: {response.get('error_message')}")
            else:
                print("[ERROR] Unexpected response during release.")
        elif choice == '5':
            print("\n[EXIT] Exiting DHCP Client.")
            client.close_connection()
            sys.exit()
        else:
            print("[ERROR] Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
