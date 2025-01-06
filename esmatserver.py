import socket
import struct
import threading
from datetime import datetime, timedelta
import json
import time

# Constants
SERVER_IP = '192.168.1.1'  # The IP address of your server
SERVER_PORT = 67
CLIENT_PORT = 68
IP_POOL_FILE = 'ip_pool.json'
LEASE_DATABASE_FILE = 'lease_database.json'
CONFIG_FILE = 'client_config.json'
DEFAULT_LEASE_DURATION = 86400  # 24 hours in seconds
LOCK = threading.Lock()

# DHCP Message Types
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7

# Global dictionaries
IP_POOL = {}
LEASE_DATABASE = {}
OFFERED_IPS = {}  # Track offered IPs: {mac_address: ip_address}

def load_json_data():
    global IP_POOL, LEASE_DATABASE
    try:
        with open(IP_POOL_FILE, "r") as file:
            IP_POOL = json.load(file)
    except FileNotFoundError:
        IP_POOL = {"192.168.1." + str(i): "available" for i in range(100, 200)}
        save_json_data(IP_POOL_FILE, IP_POOL)
    
    try:
        with open(LEASE_DATABASE_FILE, "r") as file:
            LEASE_DATABASE = json.load(file)
    except FileNotFoundError:
        LEASE_DATABASE = {}
        save_json_data(LEASE_DATABASE_FILE, LEASE_DATABASE)
    
    return IP_POOL, LEASE_DATABASE


def save_json_data(file_path, data):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

def parse_dhcp_packet(data):
    if len(data) < 240:
        return None
    
    packet = {}
    packet['op'] = data[0]
    packet['htype'] = data[1]
    packet['hlen'] = data[2]
    packet['xid'] = struct.unpack('!I', data[4:8])[0]
    packet['mac'] = ':'.join('%02x' % b for b in data[28:34])
    
    # Parse DHCP options
    options = data[240:]
    i = 0
    packet['options'] = {}
    while i < len(options):
        if options[i] == 255:  # End option
            break
        if options[i] == 0:  # Pad option
            i += 1
            continue
        opt_code = options[i]
        opt_len = options[i + 1]
        opt_data = options[i + 2:i + 2 + opt_len]
        packet['options'][opt_code] = opt_data
        i += 2 + opt_len
    
    return packet

def create_dhcp_packet(op, xid, yiaddr, mac_addr, msg_type):
    packet = bytearray(240)
    
    # Message type
    packet[0] = op
    # Hardware type: Ethernet
    packet[1] = 1
    # Hardware address length
    packet[2] = 6
    # Hops
    packet[3] = 0
    # Transaction ID
    packet[4:8] = struct.pack('!I', xid)
    # Seconds elapsed
    packet[8:10] = b'\x00\x00'
    # Bootp flags
    packet[10:12] = b'\x00\x00'
    # Client IP address
    packet[12:16] = b'\x00\x00\x00\x00'
    # Your (client) IP address
    packet[16:20] = socket.inet_aton(yiaddr)
    # Next server IP address
    packet[20:24] = socket.inet_aton(SERVER_IP)
    # Relay agent IP address
    packet[24:28] = b'\x00\x00\x00\x00'
    # Client MAC address
    packet[28:34] = bytes.fromhex(mac_addr.replace(':', ''))
    
    # Magic cookie: DHCP
    packet[236:240] = b'\x63\x82\x53\x63'
    
    # Add DHCP message type option
    packet.extend([53, 1, msg_type])
    
    # Add server identifier option
    packet.extend([54, 4])
    packet.extend(socket.inet_aton(SERVER_IP))
    
    # Add IP address lease time option (24 hours)
    packet.extend([51, 4])
    packet.extend(struct.pack('!I', DEFAULT_LEASE_DURATION))
    
    # Add subnet mask option
    packet.extend([1, 4])
    packet.extend(socket.inet_aton('255.255.255.0'))
    
    # Add router option
    packet.extend([3, 4])
    packet.extend(socket.inet_aton(SERVER_IP))
    
    # Add DNS server option
    packet.extend([6, 4])
    packet.extend(socket.inet_aton('8.8.8.8'))
    
    # End option
    packet.append(255)
    
    return packet

def get_requested_ip(packet):
    # Try to get requested IP from DHCP options
    if 50 in packet['options']:  # Option 50 is Requested IP Address
        return socket.inet_ntoa(packet['options'][50])
    return None



def start_server():
    load_json_data()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('', SERVER_PORT))
    
    print(f"[INFO] DHCP Server is running on {SERVER_IP}:{SERVER_PORT}...")
    
    while True:
        try:
            data, addr = server_socket.recvfrom(1024)
            packet = parse_dhcp_packet(data)
            
            if not packet:
                continue
            
            print(f"[DEBUG] Received packet from address: {addr}")
            print(f"[DEBUG] Client MAC: {packet['mac']}")
            
            if 53 in packet['options'] and packet['options'][53][0] == DHCP_DISCOVER:
                print(f"[INFO] DHCP DISCOVER from {packet['mac']}")
                
                # Check if this MAC already has a lease
                if packet['mac'] in LEASE_DATABASE:
                    available_ip = LEASE_DATABASE[packet['mac']]['ip']
                else:
                    # Find new available IP
                    available_ip = None
                    with LOCK:
                        for ip, status in IP_POOL.items():
                            if status == "available" and not any(lease['ip'] == ip for lease in LEASE_DATABASE.values()):
                                available_ip = ip
                                IP_POOL[ip] = "offered"
                                OFFERED_IPS[packet['mac']] = ip
                                save_json_data(IP_POOL_FILE, IP_POOL)
                                break
                
                if available_ip:
                    response = create_dhcp_packet(2, packet['xid'], available_ip, 
                                               packet['mac'], DHCP_OFFER)
                    server_socket.sendto(response, ('255.255.255.255', CLIENT_PORT))
                    print(f"[INFO] DHCP OFFER {available_ip} to {packet['mac']}")
            
            elif 53 in packet['options'] and packet['options'][53][0] == DHCP_REQUEST:
                print(f"[INFO] DHCP REQUEST from {packet['mac']}")
                
                # Get the requested IP
                requested_ip = get_requested_ip(packet)
                if not requested_ip and packet['mac'] in OFFERED_IPS:
                    requested_ip = OFFERED_IPS[packet['mac']]
                elif packet['mac'] in LEASE_DATABASE:
                    requested_ip = LEASE_DATABASE[packet['mac']]['ip']
                
                # Verify IP is available or already assigned to this MAC
                if requested_ip and (
                    IP_POOL.get(requested_ip) == "offered" or 
                    (packet['mac'] in LEASE_DATABASE and LEASE_DATABASE[packet['mac']]['ip'] == requested_ip)
                ):
                    with LOCK:
                        response = create_dhcp_packet(2, packet['xid'], requested_ip,
                                                   packet['mac'], DHCP_ACK)
                        server_socket.sendto(response, ('255.255.255.255', CLIENT_PORT))
                        print(f"[INFO] DHCP ACK {requested_ip} to {packet['mac']}")
                        
                        # Update lease database
                        IP_POOL[requested_ip] = "in use"
                        LEASE_DATABASE[packet['mac']] = {
                            "ip": requested_ip,
                            "lease_expiration": str(datetime.now() + timedelta(seconds=DEFAULT_LEASE_DURATION))
                        }
                        if packet['mac'] in OFFERED_IPS:
                            del OFFERED_IPS[packet['mac']]
                        save_json_data(IP_POOL_FILE, IP_POOL)
                        save_json_data(LEASE_DATABASE_FILE, LEASE_DATABASE)
                else:
                    # Send NAK if requested IP is not available
                    response = create_dhcp_packet(2, packet['xid'], '0.0.0.0',
                                               packet['mac'], DHCP_NAK)
                    server_socket.sendto(response, ('255.255.255.255', CLIENT_PORT))
                    print(f"[INFO] DHCP NAK to {packet['mac']}")
            
        except Exception as e:
            print(f"[ERROR] {str(e)}")

if __name__ == "__main__":
    start_server()