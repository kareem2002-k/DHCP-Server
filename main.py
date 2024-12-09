import socket
import threading
import sys
import signal

DHCP_SERVER_PORT = 67
TCP_CONTROL_PORT = 8080

running = True

def signal_handler(sig, frame):
    global running
    print("Shutting down server...")
    running = False
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

class DHCPServer:
    def __init__(self, dhcp_port=DHCP_SERVER_PORT, tcp_port=TCP_CONTROL_PORT):
        self.dhcp_port = dhcp_port
        self.tcp_port = tcp_port
        self.dhcp_socket = None
        self.tcp_socket = None
        self.threads = []
        
    def start(self):
        print("[INFO] Starting DHCP server...")
        # Start UDP DHCP server thread
        udp_thread = threading.Thread(target=self.handle_dhcp, daemon=True)
        udp_thread.start()
        self.threads.append(udp_thread)

        # Start TCP server thread for user authentication/CLI
        tcp_thread = threading.Thread(target=self.handle_tcp_control, daemon=True)
        tcp_thread.start()
        self.threads.append(tcp_thread)

    def handle_dhcp(self):
        """ Listen for DHCP packets on UDP port 67 """
        try:
            self.dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.dhcp_socket.bind(('0.0.0.0', self.dhcp_port))
            print(f"[INFO] DHCP UDP server listening on port {self.dhcp_port}...")

            while running:
                try:
                    data, addr = self.dhcp_socket.recvfrom(1024)
                    print(f"[DHCP] Received data from {addr}: {data.hex()}")
                    
                    # Parse the DHCP message
                    dhcp_message = self.parse_dhcp_message(data)
                    
                    # Send appropriate response
                    self.send_dhcp_response(dhcp_message, addr)
                    
                except socket.timeout:
                    continue
                except OSError:
                    break
        except Exception as e:
            print(f"[ERROR] DHCP server error: {e}")
        finally:
            if self.dhcp_socket:
                self.dhcp_socket.close()

    def parse_dhcp_message(self, data):
        # Placeholder for parsing DHCP message
        print("[DEBUG] Parsing DHCP message...")
        # TODO: Implement actual parsing logic
        return {}

    def send_dhcp_response(self, dhcp_message, addr):
        # Example implementation for sending a DHCP response
        print("[DEBUG] Sending DHCP response...")

        # Construct a simple DHCP offer message (this is a placeholder)
        dhcp_offer = b'\x02' + b'\x01' * 239  # Example DHCP offer packet

        try:
            self.dhcp_socket.sendto(dhcp_offer, addr)
            print(f"[DHCP] Sent DHCP offer to {addr}")
        except Exception as e:
            print(f"[ERROR] Failed to send DHCP response to {addr}: {e}")

    def handle_tcp_control(self):
        """ Listen for TCP connections for configuration/authentication (if needed) """
        try:
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_socket.bind(('0.0.0.0', self.tcp_port))
            self.tcp_socket.listen(5)
            print(f"[INFO] TCP control server listening on port {self.tcp_port}...")

            while running:
                try:
                    client_socket, client_addr = self.tcp_socket.accept()
                    print(f"[CONTROL] Connection from {client_addr}")
                    client_thread = threading.Thread(
                        target=self.handle_control_client,
                        args=(client_socket, client_addr),
                        daemon=True
                    )
                    client_thread.start()
                except OSError:
                    break

        except Exception as e:
            print(f"[ERROR] TCP control server error: {e}")
        finally:
            if self.tcp_socket:
                self.tcp_socket.close()

    def handle_control_client(self, client_socket, client_addr):
        with client_socket:
            try:
                client_socket.sendall(b"Welcome to the DHCP server control interface.\n")
                client_socket.sendall(b"Type 'status' to see server status, or 'quit' to disconnect.\n")
            except ConnectionAbortedError:
                print(f"[CONTROL] Client at {client_addr} aborted the connection.")
                return
            except ConnectionResetError:
                print(f"[CONTROL] Connection with {client_addr} reset by peer.")
                return

            while running:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    command = data.decode('utf-8').strip().lower()

                    if command == 'status':
                        status_msg = "Server is running.\n"
                        client_socket.sendall(status_msg.encode('utf-8'))
                    elif command == 'quit':
                        client_socket.sendall(b"Goodbye.\n")
                        break
                    else:
                        client_socket.sendall(b"Unknown command.\n")
                except (ConnectionAbortedError, ConnectionResetError):
                    print(f"[CONTROL] Connection with {client_addr} ended unexpectedly.")
                    break


def main():
    global running  # Declare global before usage
    server = DHCPServer()
    server.start()
    print("[INFO] Server started. Press Ctrl+C to stop.")

    try:
        while running:
            cmd = input("server> ").strip().lower()
            if cmd == 'status':
                print("[INFO] DHCP server running and listening.")
            elif cmd in ('quit', 'exit'):
                running = False
            else:
                print("[INFO] Unknown command. Available: status, quit")

    except KeyboardInterrupt:
        pass
    finally:
        print("[INFO] Stopping the server...")
        running = False

if __name__ == '__main__':
    main()
