#!/usr/bin/env python3
import socket
import struct
import threading
from datetime import datetime, timedelta
import json
import time
import sys
import ipaddress
import logging
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

# ------------------ DHCP MESSAGE TYPE CONSTANTS ------------------ #
DHCP_DISCOVER = 1    # Client requests IP address
DHCP_OFFER = 2       # Server offers IP address
DHCP_REQUEST = 3     # Client requests offered IP address
DHCP_DECLINE = 4     # Client declines offered IP address
DHCP_ACK = 5         # Server acknowledges IP address
DHCP_NAK = 6         # Server denies IP address request
DHCP_RELEASE = 7     # Client releases IP address
DHCP_INFORM = 8      # Client requests local configuration parameters




# ------------------ BOOTP MESSAGE TYPE CONSTANTS ------------------ #
BOOTREQUEST = 1  # Client message
BOOTREPLY = 2    # Server message

# ------------------ DHCP OPTION CONSTANTS ------------------ #
OPTION_SUBNET_MASK = 1
OPTION_ROUTER = 3
OPTION_DNS_SERVER = 6
OPTION_DOMAIN_NAME = 15
OPTION_REQUESTED_IP = 50
OPTION_MESSAGE_TYPE = 53
OPTION_SERVER_IDENTIFIER = 54
OPTION_PARAMETER_REQUEST_LIST = 55
OPTION_LEASE_TIME = 51
OPTION_RENEWAL_TIME = 58
OPTION_REBINDING_TIME = 59
OPTION_VENDOR_CLASS_IDENTIFIER = 60
OPTION_END = 255


# ------------------ DHCP SERVER SETTINGS ------------------ #
DEFAULT_CONFIG = {
    "SERVER_IP": "192.168.1.1",
    "SERVER_PORT": 67,
    "CLIENT_PORT": 68,
    "NETWORK_MASK": "255.255.255.0",
    "DEFAULT_GATEWAY": "192.168.1.1",
    "DNS_SERVER": "8.8.8.8",
    "ADDITIONAL_DNS_SERVERS": ["8.8.4.4"],
    "TIME_SERVER": "192.168.1.2",     # Option 4 (Time Server)
    "NAME_SERVER": "192.168.1.3",     # Option 44 (NetBIOS/WINS Server)
    "DOMAIN_NAME": "example.com",
    "VENDOR_ID": "PythonDHCP",
    "LEASE_TIME": 86400,
    "RENEWAL_TIME": 43200,  # LEASE_TIME // 2
    "REBINDING_TIME": 75600  # (LEASE_TIME * 7) // 8
}

CONFIG_FILE = 'dhcp_config.json'

# ------------------ GLOBALS ------------------ #
leases = {}
ip_pool = {}
offered_ips = {}
config = {}

# ------------------ LOGGING CONFIGURATION ------------------ #
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("dhcp_server.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# ------------------ UTILITIES ------------------ #

LOCK = threading.RLock()

def load_config():
    """Load server configuration from JSON file or initialize with defaults."""
    global config
    try:
        with open(CONFIG_FILE, "r") as file:
            loaded_config = json.load(file)
            logging.info("Configuration loaded.")
            
            # Merge loaded_config with DEFAULT_CONFIG
            config = DEFAULT_CONFIG.copy()
            config.update(loaded_config)
            
            # Identify and log any missing keys
            missing_keys = [k for k in DEFAULT_CONFIG if k not in loaded_config]
            for key in missing_keys:
                logging.warning(f"'{key}' not found in config. Setting to default: {DEFAULT_CONFIG[key]}")
            
            save_config()  # Save the updated config with default values for missing keys
    except FileNotFoundError:
        config = DEFAULT_CONFIG.copy()
        save_config()
        logging.info("Default configuration initialized.")
    except json.JSONDecodeError:
        logging.error("Error decoding configuration file. Using default settings.")
        config = DEFAULT_CONFIG.copy()
        save_config()

def save_config():
    """Save server configuration to JSON file."""
    with LOCK:
        try:
            with open(CONFIG_FILE, 'w') as file:
                json.dump(config, file, indent=4)
                logging.info("Configuration saved.")
        except Exception as e:
            logging.error(f"Failed to save configuration: {e}")

def load_json_data():
    """Load data from JSON files with error handling."""
    global ip_pool, leases, offered_ips

    def load_file(filename, default_value):
        try:
            with open(filename, "r") as file:
                data = json.load(file)
                logging.info(f"Loaded {filename}")
                return data
        except FileNotFoundError:
            logging.info(f"{filename} not found. Initializing with default data.")
            save_json_data(filename, default_value)
            return default_value
        except json.JSONDecodeError:
            logging.error(f"Error decoding {filename}. Using default data.")
            return default_value

    # Load IP Pool
    default_pool = {f"192.168.1.{i}": "available" for i in range(100, 200)}
    ip_pool = load_file('ip_pool.json', default_pool)

    # Load Lease Database
    leases = load_file('lease_database.json', {})

    # Load Offered IPs
    offered_ips = load_file('offered_ips.json', {})

def save_json_data(file_path, data):
    """Save data to JSON file with error handling."""
    with LOCK:
        try:
            with open(file_path, 'w') as file:
                json.dump(data, file, indent=4)
                logging.info(f"Saved data to {file_path}")
        except Exception as e:
            logging.error(f"Failed to save {file_path}: {e}")

def ip_to_int(ip_str):
    """Convert IP address string to integer."""
    return int(ipaddress.IPv4Address(ip_str))

def int_to_ip(ip_int):
    """Convert integer to IP address string."""
    return str(ipaddress.IPv4Address(ip_int))

def get_mac_str(data, offset=28):
    """Extract MAC address from packet data."""
    if len(data) < offset + 6:
        logging.debug("Not enough data to extract MAC address.")
        return '00:00:00:00:00:00'
    return ":".join(["{:02x}".format(x) for x in data[offset:offset+6]])

def calculate_broadcast_address():
    """Calculate broadcast address based on network configuration."""
    try:
        network = ipaddress.IPv4Network(f"{config['SERVER_IP']}/{config['NETWORK_MASK']}", strict=False)
        return str(network.broadcast_address)
    except ValueError as e:
        logging.error(f"Error calculating broadcast address: {e}")
        return '255.255.255.255'

def is_ip_in_range(ip):
    """Check if IP is within the configured network range."""
    try:
        network = ipaddress.IPv4Network(f"{config['SERVER_IP']}/{config['NETWORK_MASK']}", strict=False)
        return ipaddress.IPv4Address(ip) in network
    except ValueError:
        return False

def cleanup_expired_offers():
    """Remove expired offers from offered_ips."""
    with LOCK:
        current_time = time.time()
        expired = [
            mac for mac in offered_ips.keys()
            if offered_ips[mac].get('timestamp', 0) + 60 < current_time
        ]
        for mac in expired:
            ip = offered_ips[mac].get('ip')
            if ip and ip in ip_pool:
                ip_pool[ip] = 'available'
            del offered_ips[mac]
        if expired:
            save_json_data('ip_pool.json', ip_pool)
            save_json_data('offered_ips.json', offered_ips)

def validate_packet(packet):
    """Validate DHCP packet structure and contents."""
    required_fields = ['op', 'htype', 'hlen', 'xid', 'mac']
    return all(field in packet for field in required_fields)

def get_option_name(option_code):
    """Convert DHCP option code to human-readable name."""
    options = {
        1: "Subnet Mask",
        3: "Router",
        4: "Time Server",
        6: "DNS Servers",
        15: "Domain Name",
        42: "NTP Servers",
        44: "NetBIOS Name Server",
        46: "NetBIOS Node Type",
        51: "Lease Time",
        53: "DHCP Message Type",
        54: "DHCP Server Identifier",
        58: "Renewal Time (T1)",
        59: "Rebinding Time (T2)",
        60: "Vendor Class Identifier",
        # Add more as needed
    }
    return options.get(option_code, f"Option {option_code}")

def format_options_debug(options):
    """Format DHCP options for debug logging."""
    return ", ".join(f"{get_option_name(k)}={v}" for k, v in options.items())

# ------------------ PACKET HANDLING ------------------ #

def parse_dhcp_packet(data):
    """Parse a raw DHCP packet with enhanced error handling and options parsing."""
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

        # Extract client hardware address (MAC)
        packet['chaddr'] = data[28:28+16]
        packet['mac'] = get_mac_str(data, 28)

        # Server hostname and boot filename (usually empty)
        packet['sname'] = data[44:108]
        packet['file'] = data[108:236]

        # Verify magic cookie
        magic_cookie = data[236:240]
        if magic_cookie != b'\x63\x82\x53\x63':
            logging.debug("Invalid DHCP magic cookie.")
            return None

        # Parse DHCP options
        packet['options'] = {}
        options_data = data[240:]
        idx = 0
        
        while idx < len(options_data):
            opt_type = options_data[idx]
            
            # Handle end and pad options
            if opt_type == 255:  # END
                break
            if opt_type == 0:    # PAD
                idx += 1
                continue
                
            # Ensure we have enough data for length byte
            if idx + 1 >= len(options_data):
                logging.debug("Truncated option field.")
                break
                
            opt_len = options_data[idx + 1]
            
            # Validate option length
            if idx + 2 + opt_len > len(options_data):
                logging.debug(f"Option {opt_type} claims length {opt_len} but packet too short.")
                break
                
            opt_val = options_data[idx + 2:idx + 2 + opt_len]
            
            # Special handling for common options
            if opt_type == 53:  # DHCP Message Type
                packet['msg_type'] = opt_val[0] if opt_val else 0
            elif opt_type == 50:  # Requested IP Address
                packet['requested_ip'] = socket.inet_ntoa(opt_val) if len(opt_val) == 4 else None
            elif opt_type == 61:  # Client Identifier
                packet['client_id'] = opt_val.hex()
            elif opt_type == 12:  # Hostname
                packet['hostname'] = opt_val.decode('ascii', 'ignore')
            
            packet['options'][opt_type] = opt_val
            idx += 2 + opt_len

        # Log parsed packet details
        logging.debug(
            f"Parsed DHCP packet: type={packet.get('msg_type', 'unknown')}, "
            f"mac={packet['mac']}, xid=0x{packet['xid']:08x}"
        )
        
        return packet

    except struct.error as e:
        logging.error(f"Failed to unpack DHCP packet: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error parsing DHCP packet: {e}")
        return None

def create_dhcp_packet(op, xid, yiaddr, mac_addr, msg_type):
    """
    Create a DHCP packet with comprehensive options.
    """
    try:
        # Convert string MAC to bytes
        mac_bytes = bytes.fromhex(mac_addr.replace(':', ''))
        
        # Convert IP addresses to network format
        yiaddr_int = ip_to_int(yiaddr)
        siaddr_int = ip_to_int(config['SERVER_IP'])
        
        # Create DHCP header
        header = struct.pack(
            '!BBBBIHHIIII16s64s128s4s',
            op,                     # Message op code
            1,                      # Hardware type (Ethernet)
            6,                      # Hardware address length
            0,                      # Hops
            xid,                    # Transaction ID
            0,                      # Seconds elapsed
            0x8000,                # Flags (broadcast)
            0,                      # Client IP address
            yiaddr_int,            # 'Your' IP address
            siaddr_int,            # Next server IP address
            0,                      # Relay agent IP address
            mac_bytes + b'\x00' * 10,  # Client hardware address
            b'\x00' * 64,          # Server host name
            b'\x00' * 128,         # Boot file name
            b'\x63\x82\x53\x63'    # Magic cookie
        )

        # Build options
        options = []
        
        # Essential options
        options.extend([
            bytes([53, 1, msg_type]),                         # DHCP Message Type
            bytes([54, 4]) + socket.inet_aton(config['SERVER_IP']),     # Server Identifier
            bytes([51, 4]) + struct.pack('!I', config['LEASE_TIME']),   # IP Address Lease Time
            bytes([1, 4]) + socket.inet_aton(config['NETWORK_MASK']),   # Subnet Mask
            bytes([3, 4]) + socket.inet_aton(config['DEFAULT_GATEWAY']),# Router (Default Gateway)
        ])

        # DNS Servers
        dns_servers = [config['DNS_SERVER']] + config['ADDITIONAL_DNS_SERVERS']
        dns_bytes = b''.join(socket.inet_aton(ip) for ip in dns_servers)
        options.append(bytes([6, len(dns_bytes)]) + dns_bytes)  # Option 6

        # Domain Name
        if config['DOMAIN_NAME']:
            domain_bytes = config['DOMAIN_NAME'].encode('ascii')
            options.append(bytes([15, len(domain_bytes)]) + domain_bytes)

        # Time Server (Option 4) - if set
        if config['TIME_SERVER']:
            try:
                options.append(bytes([4, 4]) + socket.inet_aton(config['TIME_SERVER']))
            except OSError:
                pass  # If TIME_SERVER is not a valid IP, skip

        # NTP Servers (Option 42) - if you want to provide an NTP server:
        if config['TIME_SERVER']:
            try:
                options.append(bytes([42, 4]) + socket.inet_aton(config['TIME_SERVER']))
            except OSError:
                pass

        # NetBIOS Name Server (Option 44) - if provided
        if config['NAME_SERVER']:
            try:
                options.append(bytes([44, 4]) + socket.inet_aton(config['NAME_SERVER']))
            except OSError:
                pass
        
        # NetBIOS Node Type (Option 46) - 0x8 = Hybrid
        options.append(bytes([46, 1, 0x08]))

        # Broadcast Address
        broadcast_addr = calculate_broadcast_address()
        options.append(bytes([28, 4]) + socket.inet_aton(broadcast_addr))

        # Renewal and Rebinding
        options.extend([
            bytes([58, 4]) + struct.pack('!I', config['RENEWAL_TIME']),    # T1
            bytes([59, 4]) + struct.pack('!I', config['REBINDING_TIME']),  # T2
        ])

        # Vendor Identifier
        if config['VENDOR_ID']:
            vendor_bytes = config['VENDOR_ID'].encode('ascii')
            options.append(bytes([60, len(vendor_bytes)]) + vendor_bytes)

        # End option
        options.append(b'\xff')

        # Combine all parts
        packet = header + b''.join(options)

        # Ensure a minimum length (some clients expect at least 300 bytes)
        if len(packet) < 300:
            packet += b'\x00' * (300 - len(packet))

        logging.debug(
            f"Created DHCP packet: type={msg_type}, "
            f"yiaddr={yiaddr}, mac={mac_addr}, "
            f"size={len(packet)} bytes"
        )
        
        return packet

    except Exception as e:
        logging.error(f"Failed to create DHCP packet: {e}")
        return None

# ------------------ DHCP MESSAGE HANDLERS ------------------ #

def handle_dhcp_discover(server_socket, packet, ui=None):
    """Handle DHCP DISCOVER messages."""
    client_mac = packet['mac']
    xid = packet['xid']
    logging.info(f"DHCP DISCOVER from {client_mac}")
    print(f"[DHCP] DISCOVER received from MAC: {client_mac}")

    cleanup_expired_offers()  # Cleanup any expired offers

    # Check existing lease
    if client_mac in leases:
        available_ip = leases[client_mac]['ip']
        logging.debug(f"Found existing lease for {client_mac}: {available_ip}")
    else:
        # Find new available IP
        available_ip = None
        requested_ip = get_requested_ip(packet)

        with LOCK:
            # First try to give requested IP if available
            if requested_ip and requested_ip in ip_pool and ip_pool[requested_ip] == "available":
                available_ip = requested_ip
            
            # If not, find first available IP
            if not available_ip:
                for ip, status in ip_pool.items():
                    if status == "available":
                        available_ip = ip
                        break

            if available_ip:
                ip_pool[available_ip] = "offered"
                offered_ips[client_mac] = {
                    'ip': available_ip,
                    'timestamp': time.time()
                }
                save_json_data('ip_pool.json', ip_pool)
                save_json_data('offered_ips.json', offered_ips)

    if available_ip:
        print(f"[DHCP] Offering IP {available_ip} to MAC: {client_mac}")
        response = create_dhcp_packet(2, xid, available_ip, client_mac, DHCP_OFFER)
        if response:
            try:
                server_socket.sendto(response, (calculate_broadcast_address(), config['CLIENT_PORT']))
                logging.info(f"Sent DHCP OFFER: {available_ip} to {client_mac}")
                if ui:
                    ui.refresh_data()
            except Exception as e:
                logging.error(f"Failed to send DHCP OFFER: {e}")
    else:
        logging.error(f"No available IP addresses for {client_mac}")
        print("[DHCP] No available IP addresses to offer")

def handle_dhcp_request(server_socket, packet, ui=None):
    """Handle DHCP REQUEST messages."""
    client_mac = packet['mac']
    xid = packet['xid']
    logging.info(f"DHCP REQUEST from {client_mac} with XID {xid}")
    print(f"[DHCP] REQUEST received from MAC: {client_mac} with XID {xid}")

    # Extract requested IP and server identifier
    requested_ip = get_requested_ip(packet)
    server_id = get_server_id(packet)

    logging.debug(f"Requested IP: {requested_ip}")
    logging.debug(f"Server Identifier: {server_id}")

    if not requested_ip or not server_id:
        logging.warning(f"Missing requested IP or server identifier in DHCP REQUEST from {client_mac}")
        send_dhcp_nak(server_socket, xid, client_mac)
        return

    # Validate server identifier matches the server's IP
    if server_id != config['SERVER_IP']:
        logging.warning(f"Server ID mismatch: Expected {config['SERVER_IP']}, got {server_id}")
        send_dhcp_nak(server_socket, xid, client_mac)
        return

    with LOCK:
        if client_mac in offered_ips:
            offered_ip = offered_ips[client_mac]['ip']
            logging.debug(f"Offered IP for {client_mac}: {offered_ip}")
            if requested_ip == offered_ip and ip_pool.get(requested_ip) == "offered":
                # Valid request
                send_dhcp_ack(server_socket, xid, client_mac, requested_ip)
                return
            else:
                logging.warning(f"Requested IP {requested_ip} does not match offered IP {offered_ip} for {client_mac}")
        else:
            logging.warning(f"No offered IP found for MAC {client_mac}")

    # If validation fails, send DHCP NAK
    send_dhcp_nak(server_socket, xid, client_mac)


def handle_dhcp_release(packet, ui=None):
    """Handle DHCP RELEASE messages."""
    client_mac = packet['mac']
    logging.info(f"DHCP RELEASE from {client_mac}")
    print(f"[DHCP] RELEASE received from MAC: {client_mac}")

    with LOCK:
        if client_mac in leases:
            ip = leases[client_mac]['ip']
            del leases[client_mac]
            ip_pool[ip] = "available"
            save_json_data('ip_pool.json', ip_pool)
            save_json_data('lease_database.json', leases)
            logging.info(f"Released IP {ip} from {client_mac}")
            print(f"[DHCP] IP {ip} released from MAC: {client_mac}")
            if ui:
                ui.refresh_data()

def handle_dhcp_inform(server_socket, packet, ui=None):
    """Handle DHCP INFORM messages."""
    client_mac = packet['mac']
    xid = packet['xid']
    logging.info(f"DHCP INFORM from {client_mac}")
    print(f"[DHCP] INFORM received from MAC: {client_mac}")

    # Send ACK with configuration information (but no IP assignment)
    response = create_dhcp_packet(2, xid, '0.0.0.0', client_mac, DHCP_ACK)
    if response:
        try:
            server_socket.sendto(response, (calculate_broadcast_address(), config['CLIENT_PORT']))
            logging.info(f"Sent DHCP ACK (INFORM) to {client_mac}")
            print(f"[DHCP] INFORM ACK sent to MAC: {client_mac}")
            if ui:
                ui.refresh_data()
        except Exception as e:
            logging.error(f"Failed to send DHCP ACK (INFORM): {e}")

def lease_manager(ui=None):
    """Background thread to manage lease expiration."""
    while True:
        try:
            time.sleep(60)  # Check every minute
            current_time = datetime.now()
            
            with LOCK:
                expired_leases = [
                    mac for mac, lease in leases.items()
                    if datetime.fromisoformat(lease['lease_expiration']) < current_time
                ]
                
                for mac in expired_leases:
                    ip = leases[mac]['ip']
                    del leases[mac]
                    ip_pool[ip] = "available"
                    logging.info(f"Lease expired for {mac}, IP {ip} released")
                    print(f"[DHCP] Lease expired for MAC: {mac}, IP {ip} is now available")
                
                if expired_leases:
                    save_json_data('ip_pool.json', ip_pool)
                    save_json_data('lease_database.json', leases)
                    if ui:
                        ui.refresh_data()
        
        except Exception as e:
            logging.error(f"Error in lease manager: {e}")

def get_requested_ip(packet):
    """Extract the requested IP address from DHCP options."""
    options = packet.get('options', {})
    if OPTION_REQUESTED_IP in options:
        return socket.inet_ntoa(options[OPTION_REQUESTED_IP])
    return None

def get_server_id(packet):
    """Extract the server identifier from DHCP options."""
    options = packet.get('options', {})
    if OPTION_SERVER_IDENTIFIER in options:
        return socket.inet_ntoa(options[OPTION_SERVER_IDENTIFIER])
    return None

def send_dhcp_ack(server_socket, xid, mac, ip):
    """Send DHCPACK to the client."""
    response = create_dhcp_packet(BOOTREPLY, xid, ip, mac, DHCP_ACK)
    if response:
        try:
            server_socket.sendto(response, (calculate_broadcast_address(), config['CLIENT_PORT']))
            logging.info(f"Sent DHCP ACK: {ip} to {mac}")
            # Update lease and IP pool
            ip_pool[ip] = "in_use"
            leases[mac] = {
                "ip": ip,
                "lease_expiration": (datetime.now() + timedelta(seconds=config['LEASE_TIME'])).isoformat()
            }
            del offered_ips[mac]
            save_json_data('ip_pool.json', ip_pool)
            save_json_data('lease_database.json', leases)
            save_json_data('offered_ips.json', offered_ips)
            if ui:
                ui.refresh_data()
        except Exception as e:
            logging.error(f"Failed to send DHCP ACK: {e}")

def send_dhcp_nak(server_socket, xid, mac):
    """Send DHCPNAK to the client."""
    response = create_dhcp_packet(BOOTREPLY, xid, '0.0.0.0', mac, DHCP_NAK)
    if response:
        try:
            server_socket.sendto(response, (calculate_broadcast_address(), config['CLIENT_PORT']))
            logging.info(f"Sent DHCP NAK to {mac}")
        except Exception as e:
            logging.error(f"Failed to send DHCP NAK: {e}")


def disconnect_device(mac_address, ui=None):
    """Manually disconnect a device by releasing its IP."""
    with LOCK:
        if mac_address in leases:
            ip = leases[mac_address]['ip']
            del leases[mac_address]
            ip_pool[ip] = "available"
            save_json_data('ip_pool.json', ip_pool)
            save_json_data('lease_database.json', leases)
            logging.info(f"Manually disconnected {mac_address}, IP {ip} released")
            messagebox.showinfo("Disconnected", f"Device {mac_address} disconnected.\nIP {ip} is now available.")
            if ui:
                ui.refresh_data()
        else:
            messagebox.showwarning("Not Found", f"No lease found for MAC address {mac_address}.")

# ------------------ DHCP SERVER ------------------ #

def start_server(server_ui=None):
    """Start the DHCP server."""
    # Load saved data and configuration
    load_config()
    load_json_data()

    # Start lease manager thread
    lease_thread = threading.Thread(target=lease_manager, args=(server_ui,), daemon=True)
    lease_thread.start()
    logging.info("Lease manager thread started")

    # Create and configure server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        # Binding to '' (all interfaces) on port SERVER_PORT 
        # ensures we can receive broadcasts properly.
        server_socket.bind(('', config['SERVER_PORT']))
        logging.info(f"DHCP Server started on {config['SERVER_IP']}:{config['SERVER_PORT']}")
        print(f"[DHCP] Server started on {config['SERVER_IP']}:{config['SERVER_PORT']}")
        if server_ui:
            server_ui.update_status("Server running", "green")
    except Exception as e:
        logging.error(f"Failed to bind to port {config['SERVER_PORT']}: {e}")
        if server_ui:
            server_ui.update_status(f"Failed to start server: {e}", "red")
        return

    while True:
        try:
            data, addr = server_socket.recvfrom(2048)
            packet = parse_dhcp_packet(data)

            if not packet:
                continue

            if not validate_packet(packet):
                logging.warning("Received invalid DHCP packet")
                continue

            # Handle different DHCP message types (RFC2131)
            if 53 in packet['options']:
                msg_type = packet['options'][53][0]
                if msg_type == 1:  # DHCP_DISCOVER
                    handle_dhcp_discover(server_socket, packet, server_ui)
                elif msg_type == 3:  # DHCP_REQUEST
                    handle_dhcp_request(server_socket, packet, server_ui)
                elif msg_type == 7:  # DHCP_RELEASE
                    handle_dhcp_release(packet, server_ui)
                elif msg_type == 8:  # DHCP_INFORM
                    handle_dhcp_inform(server_socket, packet, server_ui)
                elif msg_type == 4:  # DHCP_DECLINE
                    # Minimal handling of DECLINE: usually means client found IP conflict
                    logging.warning(f"DHCP DECLINE from {packet['mac']} - IP conflict suspected")
                    print(f"[DHCP] DECLINE from MAC: {packet['mac']} - possible IP conflict")
                else:
                    logging.warning(f"Unhandled DHCP message type: {msg_type}")

        except Exception as e:
            logging.error(f"Error in main server loop: {e}")
            if server_ui:
                server_ui.update_status(f"Error: {e}", "red")

# ------------------ TKINTER UI ------------------ #

class DHCPServerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Python DHCP Server")
        self.root.geometry("900x600")
        self.root.resizable(False, False)

        # Define colors
        self.bg_color = "#2E3440"
        self.fg_color = "#D8DEE9"
        self.button_color = "#4C566A"
        self.selected_color = "#81A1C1"
        self.error_color = "#BF616A"

        self.root.configure(bg=self.bg_color)

        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TFrame", background=self.bg_color)
        style.configure("TButton",
                        foreground=self.fg_color,
                        background=self.button_color,
                        font=("Helvetica", 10, "bold"))
        style.map("TButton",
                  background=[('active', self.selected_color)])
        style.configure("Treeview",
                        background="#3B4252",
                        foreground=self.fg_color,
                        fieldbackground="#3B4252",
                        font=("Helvetica", 10))
        style.configure("Treeview.Heading",
                        background="#434C5E",
                        foreground=self.fg_color,
                        font=("Helvetica", 10, "bold"))
        style.configure("TLabel", foreground=self.fg_color, background=self.bg_color, font=("Helvetica", 10, "bold"))

        # Server Control Frame
        control_frame = ttk.LabelFrame(main_frame, text="Server Controls", padding="10")
        control_frame.pack(fill=tk.X, pady=5)

        self.start_button = ttk.Button(control_frame, text="Start Server", command=self.start_server)
        self.start_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_button = ttk.Button(control_frame, text="Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.config_button = ttk.Button(control_frame, text="Configure Server", command=self.configure_server)
        self.config_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.status_label = ttk.Label(control_frame, text="Server stopped", foreground="red")
        self.status_label.pack(side=tk.LEFT, padx=20)

        # Tab Control
        tab_control = ttk.Notebook(main_frame)
        tab_control.pack(fill=tk.BOTH, expand=True, pady=10)

        # Connected Devices Tab
        self.devices_tab = ttk.Frame(tab_control)
        tab_control.add(self.devices_tab, text='Connected Devices')

        self.devices_tree = ttk.Treeview(self.devices_tab, columns=("MAC Address", "IP Address", "Lease Expiration"), show='headings', selectmode='browse')
        self.devices_tree.heading("MAC Address", text="MAC Address")
        self.devices_tree.heading("IP Address", text="IP Address")
        self.devices_tree.heading("Lease Expiration", text="Lease Expiration")
        self.devices_tree.column("MAC Address", width=200, anchor='center')
        self.devices_tree.column("IP Address", width=150, anchor='center')
        self.devices_tree.column("Lease Expiration", width=200, anchor='center')
        self.devices_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.devices_tab, orient="vertical", command=self.devices_tree.yview)
        self.devices_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Context menu for disconnecting devices
        self.devices_menu = tk.Menu(self.devices_tree, tearoff=0)
        self.devices_menu.add_command(label="Disconnect", command=self.disconnect_selected_device)
        self.devices_tree.bind("<Button-3>", self.show_devices_menu)

        # Available IPs Tab
        self.available_tab = ttk.Frame(tab_control)
        tab_control.add(self.available_tab, text='Available IPs')

        self.available_tree = ttk.Treeview(self.available_tab, columns=("IP Address", "Status"), show='headings')
        self.available_tree.heading("IP Address", text="IP Address")
        self.available_tree.heading("Status", text="Status")
        self.available_tree.column("IP Address", width=200, anchor='center')
        self.available_tree.column("Status", width=100, anchor='center')
        self.available_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Add scrollbar
        scrollbar2 = ttk.Scrollbar(self.available_tab, orient="vertical", command=self.available_tree.yview)
        self.available_tree.configure(yscroll=scrollbar2.set)
        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)

        # DHCP Options Tab
        self.options_tab = ttk.Frame(tab_control)
        tab_control.add(self.options_tab, text='DHCP Options')

        self.options_text = tk.Text(self.options_tab, wrap=tk.NONE, bg="#3B4252", fg=self.fg_color, font=("Helvetica", 10))
        self.options_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.options_text.config(state=tk.DISABLED)

        # Refresh Button
        refresh_button = ttk.Button(main_frame, text="Refresh Now", command=self.refresh_data)
        refresh_button.pack(pady=5)

        # Initialize UI with current data
        self.refresh_data()

        # Server thread
        self.server_thread = None
        self.server_running = False

    def start_server(self):
        if not self.server_running:
            self.server_thread = threading.Thread(target=start_server, args=(self,), daemon=True)
            self.server_thread.start()
            self.server_running = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.update_status("Server running", "green")
            logging.info("Server started via UI")

    def stop_server(self):
        if self.server_running:
            # Gracefully stopping the server requires additional implementation.
            # For demonstration, we'll notify the user.
            messagebox.showinfo("Info", "Stopping the server is not implemented.")
            logging.info("Stop server requested via UI, but not implemented.")

    def configure_server(self):
        """Open a configuration dialog to update server settings."""
        config_window = tk.Toplevel(self.root)
        config_window.title("Configure DHCP Server")
        config_window.geometry("400x500")
        config_window.configure(bg=self.bg_color)

        # Define labels and entry fields
        fields = [
            ("Server IP", "SERVER_IP"),
            ("Network Mask", "NETWORK_MASK"),
            ("Default Gateway", "DEFAULT_GATEWAY"),
            ("DNS Server", "DNS_SERVER"),
            ("Additional DNS Servers (comma-separated)", "ADDITIONAL_DNS_SERVERS"),
            ("Time Server", "TIME_SERVER"),
            ("NetBIOS Name Server", "NAME_SERVER"),
            ("Domain Name", "DOMAIN_NAME"),
            ("Vendor ID", "VENDOR_ID"),
            ("Lease Time (seconds)", "LEASE_TIME"),
            ("Renewal Time (seconds)", "RENEWAL_TIME"),
            ("Rebinding Time (seconds)", "REBINDING_TIME"),
        ]

        entries = {}

        for idx, (label_text, key) in enumerate(fields):
            label = ttk.Label(config_window, text=label_text, background=self.bg_color, foreground=self.fg_color)
            label.grid(row=idx, column=0, padx=10, pady=5, sticky='w')

            if key == "ADDITIONAL_DNS_SERVERS":
                initial = ", ".join(config.get(key, []))
            else:
                initial = str(config.get(key, ""))

            entry = ttk.Entry(config_window, width=40)
            entry.insert(0, initial)
            entry.grid(row=idx, column=1, padx=10, pady=5)
            entries[key] = entry

        def save_configuration():
            with LOCK:
                try:
                    for key, entry in entries.items():
                        value = entry.get().strip()
                        if key == "ADDITIONAL_DNS_SERVERS":
                            config[key] = [ip.strip() for ip in value.split(",") if ip.strip()]
                        elif key in ["LEASE_TIME", "RENEWAL_TIME", "REBINDING_TIME"]:
                            config[key] = int(value)
                        else:
                            config[key] = value
                    save_config()
                    messagebox.showinfo("Success", "Configuration updated successfully.")
                    logging.info("Configuration updated via UI.")
                    config_window.destroy()
                    self.refresh_data()
                except ValueError:
                    messagebox.showerror("Error", "Lease times must be integers.")
                except Exception as e:
                    logging.error(f"Error updating configuration: {e}")
                    messagebox.showerror("Error", f"Failed to update configuration: {e}")

        save_button = ttk.Button(config_window, text="Save", command=save_configuration)
        save_button.grid(row=len(fields), column=0, columnspan=2, pady=20)

    def update_status(self, message, color="black"):
        self.status_label.config(text=message, foreground=color)

    def refresh_data(self):
        """Refresh the data displayed in the UI."""
        with LOCK:
            # Update Connected Devices
            for item in self.devices_tree.get_children():
                self.devices_tree.delete(item)
            for mac, lease in leases.items():
                self.devices_tree.insert("", tk.END, values=(mac, lease['ip'], lease['lease_expiration']))

            # Update Available IPs
            for item in self.available_tree.get_children():
                self.available_tree.delete(item)
            for ip, status in ip_pool.items():
                self.available_tree.insert("", tk.END, values=(ip, status))

            # Update DHCP Options
            self.options_text.config(state=tk.NORMAL)
            self.options_text.delete(1.0, tk.END)
            self.options_text.insert(tk.END, f"Subnet Mask: {config.get('NETWORK_MASK', 'Not Set')}\n")
            self.options_text.insert(tk.END, f"Router (Default Gateway): {config.get('DEFAULT_GATEWAY', 'Not Set')}\n")
            dns_servers = config.get('DNS_SERVER', 'Not Set')
            additional_dns = ", ".join(config.get('ADDITIONAL_DNS_SERVERS', []))
            self.options_text.insert(tk.END, f"DNS Servers: {dns_servers}, {additional_dns}\n")
            self.options_text.insert(tk.END, f"Time Server: {config.get('TIME_SERVER', 'Not Set')}\n")
            self.options_text.insert(tk.END, f"NetBIOS Name Server: {config.get('NAME_SERVER', 'Not Set')}\n")
            self.options_text.insert(tk.END, f"Domain Name: {config.get('DOMAIN_NAME', 'Not Set')}\n")
            self.options_text.insert(tk.END, f"Vendor ID: {config.get('VENDOR_ID', 'Not Set')}\n")
            self.options_text.insert(tk.END, f"Lease Time: {config.get('LEASE_TIME', 'Not Set')} seconds\n")
            self.options_text.insert(tk.END, f"Renewal Time (T1): {config.get('RENEWAL_TIME', 'Not Set')} seconds\n")
            self.options_text.insert(tk.END, f"Rebinding Time (T2): {config.get('REBINDING_TIME', 'Not Set')} seconds\n")
            self.options_text.config(state=tk.DISABLED)


    def show_devices_menu(self, event):
        """Show context menu on right-click."""
        selected_item = self.devices_tree.identify_row(event.y)
        if selected_item:
            self.devices_tree.selection_set(selected_item)
            self.devices_menu.post(event.x_root, event.y_root)

    def disconnect_selected_device(self):
        """Disconnect the selected device."""
        selected_item = self.devices_tree.selection()
        if selected_item:
            mac_address = self.devices_tree.item(selected_item, 'values')[0]
            confirm = messagebox.askyesno("Confirm Disconnect", f"Are you sure you want to disconnect {mac_address}?")
            if confirm:
                disconnect_device(mac_address, self)

    def run(self):
        """Run the Tkinter main loop."""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.root.destroy()
            logging.info("UI closed by user")

# ------------------ MAIN ------------------ #

if __name__ == "__main__":
    # Initialize Tkinter UI
    root = tk.Tk()
    ui = DHCPServerUI(root)
    try:
        ui.run()
    except KeyboardInterrupt:
        logging.info("Server shutting down...")
        print("[DHCP] Server shutting down...")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)
