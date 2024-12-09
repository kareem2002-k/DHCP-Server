import socket
import threading
import sys
import signal
import struct
import random
import uuid

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
TCP_CONTROL_PORT = 8080

running = True

def signal_handler(sig, frame):
    global running
    print("\nShutting down server...")
    running = False
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

class DHCPServer:
    def __init__(self, dhcp_port=DHCP_SERVER_PORT, tcp_port=TCP_CONTROL_PORT, server_ip=None):
        self.dhcp_port = dhcp_port
        self.tcp_port = tcp_port
        self.server_ip = server_ip or self.get_server_ip()
        self.dhcp_socket = None
        self.tcp_socket = None
        self.threads = []

        # Simple IP pool for demonstration: 192.168.1.100 - 192.168.1.110
        self.ip_pool = [f"192.168.1.{i}" for i in range(100, 111)]
        self.leases = {}  # MAC -> IP
        self.offers = {}  # MAC -> IP offered but not yet confirmed

    def get_server_ip(self):
        """
        Retrieves the server's IP address based on the active network interface.
        """
        try:
            # Create a dummy socket to get the local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Connect to a public DNS server to determine the outbound interface
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            print(f"[INFO] Server IP determined as: {ip}")
            return ip
        except Exception as e:
            print(f"[ERROR] Could not determine server IP: {e}")
            sys.exit(1)

    def start(self):
        print("[INFO] Starting DHCP server...")
        udp_thread = threading.Thread(target=self.handle_dhcp, daemon=True)
        udp_thread.start()
        self.threads.append(udp_thread)

        tcp_thread = threading.Thread(target=self.handle_tcp_control, daemon=True)
        tcp_thread.start()
        self.threads.append(tcp_thread)

    def handle_dhcp(self):
        """ Listen for DHCP packets on UDP port 67 """
        try:
            self.dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.dhcp_socket.bind(('', self.dhcp_port))
            print(f"[INFO] DHCP UDP server listening on port {self.dhcp_port}...")

            while running:
                try:
                    data, addr = self.dhcp_socket.recvfrom(2048)
                    print("[DEBUG] Packet received from", addr, "length:", len(data))
                    if not data:
                        continue

                    # Parse incoming DHCP packet
                    msg_type = self.get_dhcp_message_type(data)
                    client_mac = self.get_mac_from_data(data)
                    print(f"[DHCP] Received message type {msg_type} from {client_mac}")

                    if msg_type == 1:  # DHCPDISCOVER
                        self.handle_discover(data, client_mac)
                    elif msg_type == 3:  # DHCPREQUEST
                        self.handle_request(data, client_mac)
                    # Additional message types like DHCPRELEASE (7) can be handled similarly.

                except socket.timeout:
                    continue
                except OSError:
                    break
        except Exception as e:
            print(f"[ERROR] DHCP server error: {e}")
        finally:
            if self.dhcp_socket:
                self.dhcp_socket.close()

    def handle_tcp_control(self):
        """ Listen for TCP connections for configuration/authentication (if needed) """
        try:
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_socket.bind((self.server_ip, self.tcp_port))
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
            except (ConnectionAbortedError, ConnectionResetError):
                return

            while running:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    command = data.decode('utf-8').strip().lower()

                    if command == 'status':
                        status_msg = f"Server IP: {self.server_ip}\nLeases: {self.leases}\nOffers: {self.offers}\n"
                        client_socket.sendall(status_msg.encode('utf-8'))
                    elif command == 'quit':
                        client_socket.sendall(b"Goodbye.\n")
                        break
                    else:
                        client_socket.sendall(b"Unknown command.\n")
                except (ConnectionAbortedError, ConnectionResetError):
                    break

    # ---------------------------
    # DHCP HANDLERS AND HELPERS
    # ---------------------------

    def handle_discover(self, data, client_mac):
        # Find an IP to offer
        offered_ip = self.select_ip_for_client(client_mac)
        if not offered_ip:
            print("[ERROR] No available IPs to offer.")
            # In a real scenario, you might just not respond to DISCOVER if no IP is available
            return

        self.offers[client_mac] = offered_ip
        print(f"[DHCP] Offering IP {offered_ip} to {client_mac}")
        packet = self.build_dhcp_packet(data, client_mac, offered_ip, msg_type=2)  # DHCPOFFER = 2
        # Broadcast the offer
        self.dhcp_socket.sendto(packet, ('255.255.255.255', DHCP_CLIENT_PORT))

    def handle_request(self, data, client_mac):
        requested_ip = self.offers.get(client_mac)
        if not requested_ip:
            # Client is requesting an IP we didn't offer or state got lost
            # Send DHCPNAK = 6
            print(f"[ERROR] Client {client_mac} requested unknown IP.")
            nak_packet = self.build_dhcp_packet(data, client_mac, "0.0.0.0", msg_type=6)
            self.dhcp_socket.sendto(nak_packet, ('255.255.255.255', DHCP_CLIENT_PORT))
            return

        # If we got here, we know what we offered
        # Assign the IP to the client
        self.leases[client_mac] = requested_ip
        # Remove from offers, since it's now confirmed
        del self.offers[client_mac]
        print(f"[DHCP] Acknowledging IP {requested_ip} for {client_mac}")
        ack_packet = self.build_dhcp_packet(data, client_mac, requested_ip, msg_type=5)  # DHCPACK = 5
        self.dhcp_socket.sendto(ack_packet, ('255.255.255.255', DHCP_CLIENT_PORT))

    def select_ip_for_client(self, client_mac):
        # If client already has a lease
        if client_mac in self.leases:
            return self.leases[client_mac]

        # If client already offered an IP but not completed request
        if client_mac in self.offers:
            return self.offers[client_mac]

        # Pick a free IP
        for ip in self.ip_pool:
            if ip not in self.leases.values() and ip not in self.offers.values():
                return ip
        return None

    def get_mac_from_data(self, data):
        # BOOTP fields: op(1), htype(1), hlen(1), hops(1),
        # xid(4), secs(2), flags(2), ciaddr(4), yiaddr(4),
        # siaddr(4), giaddr(4), chaddr(16)
        # chaddr is at offset 28 and length 16 bytes (first 6 are MAC)
        if len(data) < 28 + 16:
            return "00:00:00:00:00:00"  # Invalid MAC
        chaddr = data[28:28+16]
        mac_addr = chaddr[0:6]
        return ':'.join('{:02x}'.format(b) for b in mac_addr)

    def get_dhcp_message_type(self, data):
        # DHCP options start after BOOTP fixed fields (236 bytes total: 0-236),
        # first four bytes of options are DHCP magic cookie: 99.130.83.99
        # Then options are TLV: Type(1), Length(1), Value(L).
        # DHCP message type option is code 53, length 1, value = message type.
        # We’ll parse until we find 53 or hit end/end option (255).
        if len(data) < 240:
            return None  # Not enough data
        cookie = data[236:240]
        if cookie != b'\x63\x82\x53\x63':
            return None  # Not a valid DHCP packet

        idx = 240
        while idx < len(data):
            opt = data[idx]
            if opt == 255:  # End
                break
            if opt == 0:  # Padding
                idx += 1
                continue
            if idx + 1 >= len(data):
                break  # Malformed packet
            length = data[idx + 1]
            if idx + 2 + length > len(data):
                break  # Malformed packet
            value = data[idx + 2:idx + 2 + length]
            if opt == 53:  # DHCP Message Type
                return value[0]
            idx += 2 + length
        return None

    def build_dhcp_packet(self, request_data, client_mac, ip, msg_type):
        # This is a simplified way to build a DHCP reply.
        # In real code, you must build a proper BOOTP header + options.
        # For demonstration only:

        # Extract fields from request to reuse
        # BOOTP fixed: we can copy most fields from the request and modify yiaddr and message type.
        if len(request_data) < 240:
            print("[ERROR] Malformed DHCP packet.")
            return b''

        op = 2  # reply
        htype = 1
        hlen = 6
        hops = 0

        # Extract XID, a unique transaction ID from request
        xid = request_data[4:8]
        secs = request_data[8:10]
        flags = request_data[10:12]
        ciaddr = request_data[12:16]
        yiaddr = socket.inet_aton(ip)
        siaddr = socket.inet_aton(self.server_ip)
        giaddr = request_data[16:20]

        # chaddr (client MAC) is same as from request
        chaddr_bytes = bytes.fromhex(client_mac.replace(':', ''))
        chaddr = chaddr_bytes + b'\x00' * (16 - len(chaddr_bytes))

        # BOOTP fixed header
        try:
            bootp = struct.pack('!BBBB4sHH4s4s4s4s16s192x',
                                op, htype, hlen, hops, xid, 
                                int.from_bytes(secs, byteorder='big'), 
                                int.from_bytes(flags, byteorder='big'), 
                                ciaddr, yiaddr, siaddr, giaddr, chaddr)
        except struct.error as e:
            print(f"[ERROR] Failed to pack BOOTP header: {e}")
            return b''

        # DHCP magic cookie
        magic_cookie = b'\x63\x82\x53\x63'

        # DHCP options: message type (53)
        dhcp_msg_type_opt = b'\x35\x01' + bytes([msg_type])

        # Server identifier (54) - required
        server_id_opt = b'\x36\x04' + socket.inet_aton(self.server_ip)

        # Lease time (51) - 1 hour for demo
        lease_time_opt = b'\x33\x04' + struct.pack('!I', 3600)

        # Subnet mask (1) - 255.255.255.0
        subnet_mask_opt = b'\x01\x04' + socket.inet_aton('255.255.255.0')

        # Router (3) - server's IP
        router_opt = b'\x03\x04' + socket.inet_aton(self.server_ip)

        # DNS (6) - Google DNS for demo
        dns_opt = b'\x06\x04' + socket.inet_aton('8.8.8.8')

        # End option
        end_opt = b'\xff'

        options = dhcp_msg_type_opt + server_id_opt + lease_time_opt + subnet_mask_opt + router_opt + dns_opt + end_opt

        return bootp + magic_cookie + options

def main():
    global running
    # Initialize DHCP Server with the server's actual IP address
    # If you want to specify a different IP, change the 'server_ip' variable below
    server_ip = None  # Set to None to auto-detect
    server = DHCPServer(server_ip=server_ip)
    server.start()
    print("[INFO] Server started. Press Ctrl+C to stop.")

    try:
        while running:
            cmd = input("server> ").strip().lower()
            if cmd == 'status':
                print("[INFO] DHCP server running and listening.")
                print(f"Leases: {server.leases}")
                print(f"Offers: {server.offers}")
            elif cmd in ('quit', 'exit'):
                running = False
                break
            else:
                print("[INFO] Unknown command. Available: status, quit")
    except KeyboardInterrupt:
        pass
    finally:
        print("[INFO] Stopping the server...")
        running = False
        sys.exit(0)

if __name__ == '__main__':
    main()
