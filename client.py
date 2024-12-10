import socket
import sys
import json
import uuid
import threading

# Server Configuration
SERVER_HOST = '127.0.0.1'  # Server's IP address
SERVER_PORT = 65432        # Server's port

# Function to start the client
def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((SERVER_HOST, SERVER_PORT))
    except socket.error as e:
        print(f"[ERROR] Connection failed. {e}")
        sys.exit()

    try:
        # Authentication Process
        username_prompt = client.recv(1024).decode()
        username = input(username_prompt)
        client.sendall(username.encode())

        password_prompt = client.recv(1024).decode()
        password = input(password_prompt)
        client.sendall(password.encode())

        auth_response = client.recv(1024).decode()
        print(auth_response.strip())
        if "Failed" in auth_response:
            client.close()
            sys.exit()

        # Generate a unique client identifier
        client_id = str(uuid.uuid4())

        # Start a thread to listen for server messages
        listener_thread = threading.Thread(target=listen_to_server, args=(client,), daemon=True)
        listener_thread.start()

        # Send DHCP_DISCOVER message
        dhcp_discover = {
            "type": "DHCP_DISCOVER",
            "client_id": client_id
        }
        client.sendall(json.dumps(dhcp_discover).encode())
        print("[DHCP] Sent DHCP_DISCOVER")

        # Communication Loop
        while True:
            message = input("You: ")
            if message.lower() == "exit":
                print("Disconnecting from the server.")
                break
            # For simplicity, send regular messages
            client.sendall(message.encode())
    except KeyboardInterrupt:
        print("\nDisconnecting from the server.")
    finally:
        client.close()

# Function to listen for server messages
def listen_to_server(client):
    while True:
        try:
            data = client.recv(4096)
            if not data:
                break
            try:
                message = json.loads(data.decode())
                handle_server_message(client, message)
            except json.JSONDecodeError:
                print("[ERROR] Received invalid message format from server.")
        except ConnectionResetError:
            print("[ERROR] Server closed the connection.")
            break

# Function to handle server messages
def handle_server_message(client, message):
    msg_type = message.get("type")
    if msg_type == "DHCP_OFFER":
        offered_ip = message.get("offered_ip")
        print(f"[DHCP OFFER] Offered IP: {offered_ip}")
        # Send DHCP_REQUEST
        dhcp_request = {
            "type": "DHCP_REQUEST",
            "client_id": message.get("client_id"),
            "requested_ip": offered_ip
        }
        client.sendall(json.dumps(dhcp_request).encode())
        print("[DHCP] Sent DHCP_REQUEST")
    elif msg_type == "DHCP_ACK":
        assigned_ip = message.get("assigned_ip")
        lease_time = message.get("lease_time")
        print(f"[DHCP ACK] IP {assigned_ip} assigned for {lease_time} seconds.")
    elif msg_type == "DHCP_NACK":
        nack_message = message.get("message")
        print(f"[DHCP NACK] {nack_message}")
    elif msg_type == "ERROR":
        error_message = message.get("message")
        print(f"[ERROR] {error_message}")
    else:
        # Handle other message types or regular messages
        print(f"[SERVER] {message}")

if __name__ == "__main__":
    start_client()
