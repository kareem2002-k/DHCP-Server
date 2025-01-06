#!/usr/bin/env python3
import socket
import struct
import threading
from datetime import datetime, timedelta
import json
import time
import sys
import ipaddress  # for broadcast address calculation
import logging

# ------------------ DHCP SERVER SETTINGS ------------------ #
SERVER_IP = '192.168.1.1'  # The IP address of your server
SERVER_PORT = 67            # Standard DHCP/BOOTP server port
CLIENT_PORT = 68            # Standard DHCP/BOOTP client port
NETWORK_MASK = "255.255.255.0"
DEFAULT_GATEWAY = "192.168.1.1"
DNS_SERVER = "8.8.8.8"
DOMAIN_NAME = "example.com"
LEASE_TIME = 86400         # Lease time in seconds (24 hours)
RENEWAL_TIME = LEASE_TIME // 2
REBINDING_TIME = (LEASE_TIME * 7) // 8

# JSON files for persistence
IP_POOL_FILE = 'ip_pool.json'
LEASE_DATABASE_FILE = 'lease_database.json'
OFFERED_IPS_FILE = 'offered_ips.json'  # To track offered but not yet acknowledged IPs

# Threading lock (Reentrant Lock)
LOCK = threading.RLock()

# DHCP Message Types
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7
DHCP_INFORM = 8

# ------------------ GLOBALS ------------------ #
leases = {}      # key: client_mac_str, val: { 'ip': '...', 'expiry': ... }
ip_pool = {}     # key: ip_str, value: "available" | "offered" | "in_use"
offered_ips = {} # key: client_mac_str, value: ip_str

# ------------------ LOGGING CONFIGURATION ------------------ #
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("dhcp_server.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# ------------------ UTILITIES ------------------ #

def load_json_data():
    global ip_pool, leases, offered_ips
    # Load IP Pool
    try:
        with open(IP_POOL_FILE, "r") as file:
            ip_pool = json.load(file)
            logging.info(f"Loaded {IP_POOL_FILE}")
    except FileNotFoundError:
        ip_pool = {"192.168.1." + str(i): "available" for i in range(100, 200)}
        save_json_data(IP_POOL_FILE, ip_pool)
        logging.info(f"{IP_POOL_FILE} not found. Initialized with default data.")

    # Load Lease Database
    try:
        with open(LEASE_DATABASE_FILE, "r") as file:
            leases = json.load(file)
            logging.info(f"Loaded {LEASE_DATABASE_FILE}")
    except FileNotFoundError:
        leases = {}
        save_json_data(LEASE_DATABASE_FILE, leases)
        logging.info(f"{LEASE_DATABASE_FILE} not found. Initialized with default data.")

    # Load Offered IPs
    try:
        with open(OFFERED_IPS_FILE, "r") as file:
            offered_ips = json.load(file)
            logging.info(f"Loaded {OFFERED_IPS_FILE}")
    except FileNotFoundError:
        offered_ips = {}
        save_json_data(OFFERED_IPS_FILE, offered_ips)
        logging.info(f"{OFFERED_IPS_FILE} not found. Initialized with default data.")

def save_json_data(file_path, data):
    with LOCK:
        try:
            with open(file_path, 'w') as file:
                json.dump(data, file, indent=4)
                logging.info(f"Saved data to {file_path}")
        except Exception as e:
            logging.error(f"Failed to save {file_path}: {e}")

def ip_to_int(ip_str):
    return int(ipaddress.IPv4Address(ip_str))

def int_to_ip(ip_int):
    return str(ipaddress.IPv4Address(ip_int))

def generate_ip_pool(start_ip, end_ip):
    """Generate a dictionary of IPs in the given range, all marked as 'available'."""
    start = ip_to_int(start_ip)
    end = ip_to_int(end_ip)
    pool = {}
    for ip_int in range(start, end + 1):
        ip_str = int_to_ip(ip_int)
        pool[ip_str] = "available"
    return pool

# Set BROADCAST_IP to '255.255.255.255' for maximum compatibility
BROADCAST_IP = '255.255.255.255'
logging.debug(f"Using BROADCAST_IP = {BROADCAST_IP}")

def get_mac_str(data, offset=28):
    """Extract MAC address from the packet (offset=28 for DHCP)."""
    if len(data) < offset + 6:
        logging.debug("Not enough data to extract MAC address.")
        return '00:00:00:00:00:00'
    return ":".join(["{:02x}".format(x) for x in data[offset:offset+6]])

def parse_dhcp_packet(data):
    """Parse a raw DHCP packet (UDP payload)."""
    if len(data) < 240:
        logging.debug("Packet too short to be a valid DHCP packet.")
        return None

    packet = {}
    try:
        # Unpack the fixed parts of the DHCP packet
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

        # Extract the client MAC address
        packet['chaddr'] = data[28:28+16]
        packet['client_mac_str'] = get_mac_str(data, 28)

        # Verify the magic cookie
        magic_cookie = data[236:240]
        if magic_cookie != b'\x63\x82\x53\x63':
            logging.debug("Missing or invalid DHCP magic cookie.")
            return None

        # Parse DHCP options
        packet['options'] = {}
        options_data = data[240:]
        idx = 0
        while idx < len(options_data):
            opt_type = options_data[idx]
            if opt_type == 255:  # END option
                break
            elif opt_type == 0:  # PAD option
                idx += 1
                continue
            else:
                if idx + 1 >= len(options_data):
                    logging.debug("Option length exceeds data length.")
                    break
                opt_len = options_data[idx + 1]
                if idx + 2 + opt_len > len(options_data):
                    logging.debug("Option value exceeds data length.")
                    break
                opt_val = options_data[idx + 2:idx + 2 + opt_len]
                packet['options'][opt_type] = opt_val
                idx += 2 + opt_len

        # Ensure 'mac' is always set
        if 'client_mac_str' in packet and packet['client_mac_str']:
            packet['mac'] = packet['client_mac_str']
        else:
            packet['mac'] = '00:00:00:00:00:00'  # Default MAC if extraction fails
            logging.debug("MAC address extraction failed. Setting to default '00:00:00:00:00:00'.")

        logging.debug(f"Parsed packet: op={packet['op']}, mac={packet['mac']}, xid=0x{packet['xid']:08x}")
        return packet
    except struct.error as e:
        logging.error(f"Failed to unpack DHCP packet: {e}")
        return None

def create_dhcp_packet(op, xid, yiaddr, mac_addr, msg_type):
    """Build a minimal DHCP packet for OFFER/ACK/NAK responses."""
    yiaddr_int = ip_to_int(yiaddr)
    siaddr_int = ip_to_int(SERVER_IP)
    giaddr_int = 0

    try:
        mac_bytes = bytes(int(x, 16) for x in mac_addr.split(":"))
    except ValueError as e:
        logging.error(f"Invalid MAC address format: {e}")
        return None

    # DHCP header
    op = 2  # BOOTREPLY
    htype = 1
    hlen = 6
    hops = 0
    secs = 0
    flags = 0x8000  # Broadcast flag

    try:
        dhcp_header = struct.pack(
            '!BBBBIHHIIII16s192s',
            op, htype, hlen, hops, xid, secs, flags,
            0,               # ciaddr
            yiaddr_int,      # yiaddr
            siaddr_int,      # siaddr
            giaddr_int,      # giaddr
            mac_bytes + b'\x00' * (16 - len(mac_bytes)),
            b'\x00' * 192
        )
    except struct.error as e:
        logging.error(f"Failed to pack DHCP header: {e}")
        return None

    magic_cookie = b'\x63\x82\x53\x63'

    # DHCP options
    options = b''

    # Option 53: DHCP Message Type
    options += b'\x35\x01' + bytes([msg_type])
    # Option 54: DHCP Server Identifier
    options += b'\x36\x04' + socket.inet_aton(SERVER_IP)
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

    dhcp_packet = dhcp_header + magic_cookie + options

    logging.debug(f"DHCP Packet Length: {len(dhcp_packet)} bytes")

    return dhcp_packet

def get_requested_ip(packet):
    # Try to get requested IP from DHCP options
    if 50 in packet['options']:  # Option 50 is Requested IP Address
        return socket.inet_ntoa(packet['options'][50])
    return None

def handle_dhcp_discover(server_socket, packet):
    client_mac = packet['mac']
    xid = packet['xid']
    logging.info(f"DHCP DISCOVER from {client_mac}")

    # Check if this MAC already has a lease
    if client_mac in leases:
        available_ip = leases[client_mac]['ip']
        logging.debug(f"Client {client_mac} already has lease: {available_ip}")
    else:
        # Find new available IP
        available_ip = None
        with LOCK:
            for ip, status in ip_pool.items():
                if status == "available" and not any(lease['ip'] == ip for lease in leases.values()):
                    available_ip = ip
                    ip_pool[ip] = "offered"
                    offered_ips[client_mac] = ip
                    save_json_data(IP_POOL_FILE, ip_pool)
                    logging.debug(f"IP {ip} offered to {client_mac}")
                    break

    if available_ip:
        response = create_dhcp_packet(2, xid, available_ip, client_mac, DHCP_OFFER)
        if response is None:
            logging.error(f"Failed to create DHCP OFFER for {available_ip} to {client_mac}")
            return
        try:
            server_socket.sendto(response, (BROADCAST_IP, CLIENT_PORT))
            logging.info(f"Offered {available_ip} to {client_mac} XID=0x{xid:08x}")
        except Exception as e:
            logging.error(f"Failed to send DHCPOFFER: {e}")

def handle_dhcp_request(server_socket, packet):
    client_mac = packet['mac']
    xid = packet['xid']
    logging.info(f"DHCP REQUEST from {client_mac}")

    # Get the requested IP
    requested_ip = get_requested_ip(packet)
    if not requested_ip and client_mac in offered_ips:
        requested_ip = offered_ips[client_mac]
    elif client_mac in leases:
        requested_ip = leases[client_mac]['ip']

    # Verify IP is available or already assigned to this MAC
    if requested_ip and (
        ip_pool.get(requested_ip) == "offered" or 
        (client_mac in leases and leases[client_mac]['ip'] == requested_ip)
    ):
        with LOCK:
            response = create_dhcp_packet(2, xid, requested_ip, client_mac, DHCP_ACK)
            if response is None:
                logging.error(f"Failed to create DHCP ACK for {requested_ip} to {client_mac}")
                return
            try:
                server_socket.sendto(response, (BROADCAST_IP, CLIENT_PORT))
                logging.info(f"Assigned {requested_ip} to {client_mac} XID=0x{xid:08x}")
            except Exception as e:
                logging.error(f"Failed to send DHCPACK: {e}")

            # Update lease database
            ip_pool[requested_ip] = "in_use"
            leases[client_mac] = {
                "ip": requested_ip,
                "lease_expiration": (datetime.now() + timedelta(seconds=LEASE_TIME)).isoformat()
            }
            if client_mac in offered_ips:
                del offered_ips[client_mac]
            save_json_data(IP_POOL_FILE, ip_pool)
            save_json_data(LEASE_DATABASE_FILE, leases)
    else:
        # Send NAK if requested IP is not available
        response = create_dhcp_packet(2, xid, '0.0.0.0', client_mac, DHCP_NAK)
        if response is None:
            logging.error(f"Failed to create DHCP NAK for {client_mac}")
            return
        try:
            server_socket.sendto(response, (BROADCAST_IP, CLIENT_PORT))
            logging.info(f"Sent NAK to {client_mac} for IP {requested_ip}")
        except Exception as e:
            logging.error(f"Failed to send DHCPNAK: {e}")

def lease_manager():
    """Background thread to manage lease expiration."""
    while True:
        time.sleep(60)  # Check every minute
        current_time = datetime.now()
        with LOCK:
            expired_leases = [mac for mac, lease in leases.items() if datetime.fromisoformat(lease['lease_expiration']) < current_time]
            for mac in expired_leases:
                ip = leases[mac]['ip']
                del leases[mac]
                ip_pool[ip] = "available"
                logging.info(f"Lease expired for {mac}, IP {ip} released.")
            if expired_leases:
                save_json_data(IP_POOL_FILE, ip_pool)
                save_json_data(LEASE_DATABASE_FILE, leases)

def start_server():
    load_json_data()

    # Start lease manager thread
    lease_thread = threading.Thread(target=lease_manager, daemon=True)
    lease_thread.start()
    logging.info("Started lease manager thread.")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind(('', SERVER_PORT))
    except Exception as e:
        logging.error(f"Could not bind to UDP port {SERVER_PORT}: {e}")
        sys.exit(1)

    logging.info(f"DHCP Server is running on {SERVER_IP}:{SERVER_PORT}...")

    while True:
        try:
            data, addr = server_socket.recvfrom(1024)
            packet = parse_dhcp_packet(data)

            if not packet:
                continue

            logging.debug(f"Received packet from address: {addr}")
            try:
                client_mac = packet['mac']
                logging.debug(f"Client MAC: {client_mac}")
            except KeyError:
                logging.error("'mac' key missing in packet.")
                continue

            if 53 in packet['options']:
                msg_type = packet['options'][53][0]
                if msg_type == DHCP_DISCOVER:
                    handle_dhcp_discover(server_socket, packet)
                elif msg_type == DHCP_REQUEST:
                    handle_dhcp_request(server_socket, packet)
                # Add handlers for other message types as needed

        except Exception as e:
            logging.error(f"Exception in main loop: {e}")

if __name__ == "__main__":
    start_server()