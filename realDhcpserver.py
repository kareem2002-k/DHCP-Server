#!/usr/bin/env python3
import socket
import struct
import time
import sys
import ipaddress  # for broadcast address calculation

# ------------------ DHCP SERVER SETTINGS ------------------ #
SERVER_IP            = "172.23.208.1"
SERVER_PORT          = 67                 # Standard DHCP/BOOTP server port
CLIENT_PORT          = 68                 # Standard DHCP/BOOTP client port
NETWORK_MASK         = "255.255.240.0"
DEFAULT_GATEWAY      = "172.23.208.1"
DNS_SERVER           = "8.8.8.8"
DOMAIN_NAME          = "example.com"
LEASE_TIME           = 120                # Lease time in seconds
RENEWAL_TIME         = LEASE_TIME // 2
REBINDING_TIME       = (LEASE_TIME * 7) // 8

# Dynamically calculate broadcast IP from SERVER_IP and NETWORK_MASK
def get_broadcast_address(ip_str, mask_str):
    """Calculate the broadcast address given an IP and subnet mask."""
    network = ipaddress.ip_network(f"{ip_str}/{mask_str}", strict=False)
    return str(network.broadcast_address)

BROADCAST_IP = get_broadcast_address(SERVER_IP, NETWORK_MASK)
print(f"[DEBUG] Using BROADCAST_IP = {BROADCAST_IP}")

# IP pool range
IP_POOL_START = "172.23.208.100"
IP_POOL_END   = "172.23.208.200"

# ------------------ GLOBALS ------------------ #
leases = {}  # key: client_mac_str, val: { 'ip': '...', 'expiry': ... }
ip_pool = [] # list of available IP strings

# ------------------ UTILS ------------------ #
def ip_to_int(ip_str):
    parts = [int(x) for x in ip_str.split('.')]
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

def int_to_ip(ip_int):
    return ".".join([
        str((ip_int >> 24) & 0xFF),
        str((ip_int >> 16) & 0xFF),
        str((ip_int >> 8) & 0xFF),
        str(ip_int & 0xFF)
    ])

def generate_ip_pool(start_ip, end_ip):
    """Generate a sorted list of IPs in the given range."""
    start = ip_to_int(start_ip)
    end   = ip_to_int(end_ip)
    return [int_to_ip(ip) for ip in range(start, end + 1)]

def insert_ip_sorted(ip_list, ip):
    """Insert an IP address back into the pool in sorted order."""
    target_int = ip_to_int(ip)
    left, right = 0, len(ip_list)
    while left < right:
        mid = (left + right) // 2
        mid_int = ip_to_int(ip_list[mid])
        if mid_int < target_int:
            left = mid + 1
        else:
            right = mid
    ip_list.insert(left, ip)

def get_mac_str(data, offset=28):
    """Extract MAC address from the packet (offset=28 for DHCP)."""
    return ":".join(["{:02x}".format(x) for x in data[offset:offset+6]])

# ------------------ DHCP PACKET PARSING & BUILDING ------------------ #
def parse_dhcp_packet(data):
    """Parse a raw DHCP packet (UDP payload)."""
    if len(data) < 240:
        print("[DEBUG] Packet too short to be a valid DHCP packet.")
        return None

    packet = {}
    (
        packet['op'],
        packet['htype'],
        packet['hlen'],
        packet['hops'],
        packet['xid'],
        packet['secs'],
        packet['flags'],
        packet['ciaddr'],
        packet['yiaddr'],
        packet['siaddr'],
        packet['giaddr']
    ) = struct.unpack('!BBBBIHHIIII', data[:28])

    # chaddr is 16 bytes; MAC is first 6 bytes
    packet['chaddr'] = data[28:28+16]
    packet['client_mac_str'] = get_mac_str(data, 28)

    magic_cookie = data[236:240]
    if magic_cookie != b'\x63\x82\x53\x63':
        print("[DEBUG] Missing or invalid DHCP magic cookie.")
        return None

    # Parse DHCP options
    packet['options'] = {}
    options_data = data[240:]
    idx = 0
    while idx < len(options_data):
        opt_type = options_data[idx]
        if opt_type == 255:  # END option
            break
        elif opt_type == 0: # PAD
            idx += 1
            continue
        else:
            if idx+1 >= len(options_data):
                break
            opt_len = options_data[idx+1]
            if idx + 2 + opt_len > len(options_data):
                break
            opt_val = options_data[idx+2:idx+2+opt_len]
            packet['options'][opt_type] = opt_val
            idx += 2 + opt_len

    return packet

def build_dhcp_packet(msg_type, transaction_id, your_ip, client_mac_str,
                      server_id=SERVER_IP, requested_ip="0.0.0.0"):
    """Build a minimal DHCP packet for OFFER/ACK responses."""
    yiaddr_int = ip_to_int(your_ip)
    siaddr_int = ip_to_int(server_id)
    giaddr_int = 0

    mac_bytes = bytes(int(x, 16) for x in client_mac_str.split(":"))

    # DHCP header
    op = 2  # BOOTREPLY
    htype = 1
    hlen = 6
    hops = 0
    secs = 0
    flags = 0x8000  # **Set the broadcast flag**

    dhcp_header = struct.pack(
        '!BBBBIHHIIII16s192s',
        op, htype, hlen, hops, transaction_id, secs, flags,
        0,               # ciaddr
        yiaddr_int,      # yiaddr
        siaddr_int,      # siaddr
        giaddr_int,      # giaddr
        mac_bytes + b'\x00' * (16 - len(mac_bytes)),
        b'\x00'*192
    )

    magic_cookie = b'\x63\x82\x53\x63'

    # DHCP options
    options = b''

    # Option 53: DHCP Message Type
    options += b'\x35\x01' + bytes([msg_type])
    # Option 54: DHCP Server Identifier
    options += b'\x36\x04' + socket.inet_aton(server_id)
    # Option 51: IP Address Lease Time
    options += b'\x33\x04' + struct.pack('!I', LEASE_TIME)
    # Option 1: Subnet Mask
    options += b'\x01\x04' + socket.inet_aton(NETWORK_MASK)
    # Option 3: Router
    options += b'\x03\x04' + socket.inet_aton(DEFAULT_GATEWAY)
    # Option 6: DNS Server
    options += b'\x06\x04' + socket.inet_aton(DNS_SERVER)
    # Option 15: Domain Name
    domain_encoded = DOMAIN_NAME.encode('ascii')
    options += bytes([15, len(domain_encoded)]) + domain_encoded
    # Option 58: Renewal Time
    options += b'\x3a\x04' + struct.pack('!I', RENEWAL_TIME)
    # Option 59: Rebinding Time
    options += b'\x3b\x04' + struct.pack('!I', REBINDING_TIME)

    # End
    options += b'\xff'

    return dhcp_header + magic_cookie + options

# ------------------ IP ADDRESS ALLOCATION ------------------ #
def get_free_ip():
    """Get the next free IP from the pool (if available)."""
    print("[DEBUG] get_free_ip() called.")
    if not ip_pool:
        print("[DEBUG] IP pool is empty!")
        return None
    ip_addr = ip_pool.pop(0)
    print(f"[DEBUG] get_free_ip() returning {ip_addr}")
    return ip_addr

def release_ip(ip):
    """Return an IP address to the free pool."""
    print(f"[DEBUG] release_ip({ip}) called.")
    insert_ip_sorted(ip_pool, ip)

# ------------------ DHCP SERVER MAIN LOOP ------------------ #
def dhcp_server():
    """Listen on UDP port 67 for DHCP packets, respond accordingly."""
    print(f"[DEBUG] Binding DHCP server to {SERVER_IP}:{SERVER_PORT}")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    try:
        # Bind to port 67 on the specific server IP
        server_socket.bind((SERVER_IP, SERVER_PORT))
    except Exception as e:
        print(f"[ERROR] Could not bind to UDP port {SERVER_PORT} on {SERVER_IP}: {e}")
        sys.exit(1)

    print(f"[DHCP SERVER] Listening on {SERVER_IP}:{SERVER_PORT} (UDP)")

    while True:
        try:
            data, addr = server_socket.recvfrom(1024)
            if not data:
                continue

            packet = parse_dhcp_packet(data)
            if not packet:
                continue

            client_mac_str = packet['client_mac_str']
            xid = packet['xid']
            options = packet['options']

            if 53 not in options:
                print("[DEBUG] No DHCP message type found in packet.")
                continue

            msg_type = options[53][0]
            # 1 = DHCPDISCOVER, 3 = DHCPREQUEST, 4=DECLINE, 5=ACK, 6=NAK, 7=RELEASE, 8=INFORM
            if msg_type == 1:
                # DHCPDISCOVER -> DHCPOFFER
                print(f"[DISCOVER] From {client_mac_str} XID=0x{xid:08x}")

                # ALLOCATION LOGIC
                offered_ip = None
                if client_mac_str in leases:
                    offered_ip = leases[client_mac_str]['ip']
                    print(f"[DEBUG] Client already had lease: {offered_ip}")
                else:
                    offered_ip = get_free_ip()
                    if offered_ip is None:
                        # Provide fallback for testing
                        offered_ip = "172.23.208.250"
                        print("[DEBUG] Fallback IP assigned:", offered_ip)

                print("[DEBUG] About to build DHCPOFFER with IP =", offered_ip)
                reply = build_dhcp_packet(
                    msg_type=2,      # DHCPOFFER
                    transaction_id=xid,
                    your_ip=offered_ip,
                    client_mac_str=client_mac_str
                )
                try:
                    server_socket.sendto(reply, (BROADCAST_IP, CLIENT_PORT))
                    print(f"[OFFER] Offering {offered_ip} to {client_mac_str} XID=0x{xid:08x}")
                except Exception as e:
                    print(f"[ERROR] Failed to send DHCPOFFER: {e}")

            elif msg_type == 3:
                # DHCPREQUEST -> DHCPACK or DHCPNAK
                print(f"[REQUEST] From {client_mac_str} XID=0x{xid:08x}")
                requested_ip = None
                req_server_ip = None

                if 50 in options:
                    requested_ip = socket.inet_ntoa(options[50])
                if 54 in options:
                    req_server_ip = socket.inet_ntoa(options[54])

                print(f"[DEBUG] Requested IP={requested_ip}, Server ID in packet={req_server_ip}")

                # If the client is selecting an IP from *this* server
                if req_server_ip is None or req_server_ip == SERVER_IP:
                    if not requested_ip:
                        # Maybe client has an existing lease
                        if client_mac_str in leases:
                            requested_ip = leases[client_mac_str]['ip']
                        if not requested_ip:
                            print("  [REQUEST] No requested IP found. Ignoring.")
                            continue

                    # Validate the IP
                    in_pool = (requested_ip in ip_pool)
                    in_lease = any(
                        (leases[mac]['ip'] == requested_ip) for mac in leases if mac != client_mac_str
                    )
                    if in_lease:
                        # IP in use -> NAK
                        nak_packet = build_dhcp_packet(
                            msg_type=6,  # DHCPNAK
                            transaction_id=xid,
                            your_ip="0.0.0.0",
                            client_mac_str=client_mac_str
                        )
                        server_socket.sendto(nak_packet, (BROADCAST_IP, CLIENT_PORT))
                        print(f"  [NAK] IP {requested_ip} is in use, sent NAK to {client_mac_str}")
                        continue
                    else:
                        # If IP was free in the pool, remove it
                        if in_pool:
                            print("[DEBUG] Removing requested IP from pool:", requested_ip)
                            ip_pool.remove(requested_ip)

                    # Record or update the lease
                    leases[client_mac_str] = {
                        'ip': requested_ip,
                        'expiry': time.time() + LEASE_TIME
                    }

                    # Send DHCPACK
                    ack_packet = build_dhcp_packet(
                        msg_type=5,  # DHCPACK
                        transaction_id=xid,
                        your_ip=requested_ip,
                        client_mac_str=client_mac_str
                    )
                    try:
                        server_socket.sendto(ack_packet, (BROADCAST_IP, CLIENT_PORT))
                        print(f"  [ACK] Assigned {requested_ip} to {client_mac_str} XID=0x{xid:08x}")
                    except Exception as e:
                        print(f"[ERROR] Failed to send DHCPACK: {e}")
                else:
                    # Client requesting from another DHCP server
                    print(f"  [REQUEST IGNORED] Client {client_mac_str} wants server {req_server_ip}")

            elif msg_type == 7:
                # DHCPRELEASE
                print(f"[RELEASE] from {client_mac_str}")
                if client_mac_str in leases:
                    released_ip = leases[client_mac_str]['ip']
                    del leases[client_mac_str]
                    release_ip(released_ip)
                    print(f"  [RELEASED] IP {released_ip} from {client_mac_str}")
                else:
                    print(f"  [RELEASE] No lease found for {client_mac_str}")

            elif msg_type == 4:
                # DHCPDECLINE
                print(f"[DECLINE] from {client_mac_str}")
                if client_mac_str in leases:
                    declined_ip = leases[client_mac_str]['ip']
                    del leases[client_mac_str]
                    release_ip(declined_ip)
                    print(f"  [DECLINED] Freed {declined_ip} from {client_mac_str}")

            elif msg_type == 8:
                # DHCPINFORM
                print(f"[INFORM] from {client_mac_str}")
                inform_ack = build_dhcp_packet(
                    msg_type=5,  # DHCPACK
                    transaction_id=xid,
                    your_ip="0.0.0.0",
                    client_mac_str=client_mac_str
                )
                server_socket.sendto(inform_ack, (BROADCAST_IP, CLIENT_PORT))
                print(f"  [ACK to INFORM] Sent config to {client_mac_str}")

            else:
                print(f"[UNKNOWN] DHCP message type {msg_type} from {client_mac_str}")
        except Exception as e:
            print(f"[ERROR] Exception in main loop: {e}")
# ------------------ MAIN ------------------ #
if __name__ == "__main__":
    # Initialize the IP pool
    ip_pool = generate_ip_pool(IP_POOL_START, IP_POOL_END)
    print(f"[INIT] IP Pool size: {len(ip_pool)}")
    print(f"[INIT] First 5 IPs in pool: {ip_pool[:5]} ...")

    # -------------- NO LEASE MANAGER THREAD --------------
    # We remove the concurrency to avoid deadlocks. 
    # If you need lease expiration, handle it manually or in an external cron job.

    # Start DHCP server (blocking call)
    dhcp_server()
