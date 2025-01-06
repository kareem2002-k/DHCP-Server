#!/usr/bin/env python3
import socket
import struct
import random
import sys
import time
import threading
import ipaddress

# DHCP Constants
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
BOOTREQUEST = 1
BOOTREPLY = 2

# DHCP Message Types
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7
DHCP_INFORM = 8

# DHCP Options
OPTION_MESSAGE_TYPE = 53
OPTION_SERVER_IDENTIFIER = 54
OPTION_REQUESTED_IP = 50
OPTION_PARAMETER_REQUEST_LIST = 55
OPTION_END = 255

# BOOTP Fields Offsets
OP_OFFSET = 0
HTYPE_OFFSET = 1
HLEN_OFFSET = 2
HOPS_OFFSET = 3
XID_OFFSET = 4
SECS_OFFSET = 8
FLAGS_OFFSET = 10
CIADDR_OFFSET = 12
YIADDR_OFFSET = 16
SIADDR_OFFSET = 20
GIADDR_OFFSET = 24
CHADDR_OFFSET = 28
SNAME_OFFSET = 44
FILE_OFFSET = 108
MAGIC_COOKIE_OFFSET = 236
OPTIONS_OFFSET = 240

# Magic Cookie
MAGIC_COOKIE = b'\x63\x82\x53\x63'

def generate_mac():
    """Generate a random MAC address."""
    mac = [0x00, 0x16, 0x3e,
           random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    return ':'.join(['%02x' % b for b in mac])

def mac2bytes(mac_str):
    """Convert MAC address string to bytes."""
    return bytes.fromhex(mac_str.replace(':', ''))

def create_dhcp_discover(mac, xid):
    """Create a DHCPDISCOVER packet."""
    # BOOTP Header Fields
    op = BOOTREQUEST
    htype = 1  # Ethernet
    hlen = 6   # MAC length
    hops = 0
    xid = xid
    secs = 0
    flags = 0x8000  # Broadcast flag
    ciaddr = 0
    yiaddr = 0
    siaddr = 0
    giaddr = 0
    chaddr = mac2bytes(mac) + b'\x00' * 10  # 16 bytes
    sname = b'\x00' * 64
    file = b'\x00' * 128

    # Pack BOOTP Header
    bootp = struct.pack('!BBBBIHHIIII16s64s128s',
                        op, htype, hlen, hops, xid, secs, flags,
                        ciaddr, yiaddr, siaddr, giaddr,
                        chaddr, sname, file)

    # DHCP Options
    options = [
        OPTION_MESSAGE_TYPE, 1, DHCP_DISCOVER,
        OPTION_PARAMETER_REQUEST_LIST, 4, 1, 3, 6, 15,
        OPTION_END
    ]
    options_bytes = bytes(options)

    # Ensure Magic Cookie is present
    packet = bootp + MAGIC_COOKIE + options_bytes
    return packet

def create_dhcp_request(mac, xid, requested_ip, server_id):
    """Create a DHCPREQUEST packet."""
    # BOOTP Header Fields
    op = BOOTREQUEST
    htype = 1  # Ethernet
    hlen = 6   # MAC length
    hops = 0
    xid = xid
    secs = 0
    flags = 0x8000  # Broadcast flag
    ciaddr = 0
    yiaddr = 0
    siaddr = 0
    giaddr = 0
    chaddr = mac2bytes(mac) + b'\x00' * 10  # 16 bytes
    sname = b'\x00' * 64
    file = b'\x00' * 128

    # Pack BOOTP Header
    bootp = struct.pack('!BBBBIHHIIII16s64s128s',
                        op, htype, hlen, hops, xid, secs, flags,
                        ciaddr, yiaddr, siaddr, giaddr,
                        chaddr, sname, file)

    # DHCP Options
    options = [
        OPTION_MESSAGE_TYPE, 1, DHCP_REQUEST,
        OPTION_SERVER_IDENTIFIER, 4
    ] + list(socket.inet_aton(server_id)) + [
        OPTION_REQUESTED_IP, 4
    ] + list(socket.inet_aton(requested_ip)) + [
        OPTION_PARAMETER_REQUEST_LIST, 4, 1, 3, 6, 15,
        OPTION_END
    ]
    options_bytes = bytes(options)

    # Ensure Magic Cookie is present
    packet = bootp + MAGIC_COOKIE + options_bytes
    return packet

def create_dhcp_release(mac, client_ip, server_id, xid):
    """Create a DHCPRELEASE packet."""
    # BOOTP Header Fields
    op = BOOTREQUEST
    htype = 1  # Ethernet
    hlen = 6   # MAC length
    hops = 0
    xid = xid
    secs = 0
    flags = 0x8000  # Broadcast flag
    ciaddr = socket.inet_aton(client_ip)[0]
    yiaddr = 0
    siaddr = 0
    giaddr = 0
    chaddr = mac2bytes(mac) + b'\x00' * 10  # 16 bytes
    sname = b'\x00' * 64
    file = b'\x00' * 128

    # Pack BOOTP Header
    bootp = struct.pack('!BBBBIHHIIII16s64s128s',
                        op, htype, hlen, hops, xid, secs, flags,
                        ciaddr, yiaddr, siaddr, giaddr,
                        chaddr, sname, file)

    # DHCP Options
    options = [
        OPTION_MESSAGE_TYPE, 1, DHCP_RELEASE,
        OPTION_SERVER_IDENTIFIER, 4
    ] + list(socket.inet_aton(server_id)) + [
        OPTION_END
    ]
    options_bytes = bytes(options)

    # Ensure Magic Cookie is present
    packet = bootp + MAGIC_COOKIE + options_bytes
    return packet

def parse_dhcp_offer(packet, xid, mac):
    """Parse DHCPOFFER packet."""
    # Unpack BOOTP fields
    bootp_fields = struct.unpack('!BBBBIHHIIII16s64s128s', packet[:236])
    offered_ip = socket.inet_ntoa(struct.pack('!I', bootp_fields[8]))
    # Extract DHCP options
    options = packet[OPTIONS_OFFSET:]
    message_type = None
    server_id = None
    for i in range(0, len(options)):
        option = options[i]
        if option == OPTION_MESSAGE_TYPE:
            message_type = options[i+2]
            i += options[i+1] + 2
        elif option == OPTION_SERVER_IDENTIFIER:
            server_id = socket.inet_ntoa(options[i+2:i+6])
            i += options[i+1] + 2
        elif option == OPTION_END:
            break
        else:
            i += options[i+1] + 2
    if message_type != DHCP_OFFER:
        print("[Error] Not a DHCPOFFER packet.")
        return None, None
    return offered_ip, server_id

def parse_dhcp_ack(packet, xid, mac):
    """Parse DHCPACK packet."""
    # Unpack BOOTP fields
    bootp_fields = struct.unpack('!BBBBIHHIIII16s64s128s', packet[:236])
    assigned_ip = socket.inet_ntoa(struct.pack('!I', bootp_fields[8]))
    # Extract DHCP options
    options = packet[OPTIONS_OFFSET:]
    message_type = None
    lease_time = None
    for i in range(0, len(options)):
        option = options[i]
        if option == OPTION_MESSAGE_TYPE:
            message_type = options[i+2]
            i += options[i+1] + 2
        elif option == 51:  # Lease Time
            lease_time = struct.unpack('!I', options[i+2:i+6])[0]
            i += options[i+1] + 2
        elif option == OPTION_END:
            break
        else:
            i += options[i+1] + 2
    if message_type != DHCP_ACK:
        print("[Error] Not a DHCPACK packet.")
        return None, None
    return assigned_ip, lease_time

def send_dhcp_discover(sock, mac, xid, broadcast_address):
    """Send DHCPDISCOVER message."""
    discover_packet = create_dhcp_discover(mac, xid)
    sock.sendto(discover_packet, (broadcast_address, DHCP_SERVER_PORT))
    print("[DHCP Client] Sent DHCPDISCOVER")

def send_dhcp_request(sock, mac, xid, requested_ip, server_id, broadcast_address):
    """Send DHCPREQUEST message."""
    request_packet = create_dhcp_request(mac, xid, requested_ip, server_id)
    sock.sendto(request_packet, (broadcast_address, DHCP_SERVER_PORT))
    print("[DHCP Client] Sent DHCPREQUEST")

def send_dhcp_release(sock, mac, xid, client_ip, server_id, broadcast_address):
    """Send DHCPRELEASE message."""
    release_packet = create_dhcp_release(mac, client_ip, server_id, xid)
    sock.sendto(release_packet, (broadcast_address, DHCP_SERVER_PORT))
    print("[DHCP Client] Sent DHCPRELEASE")

def receive_dhcp_offer(sock, xid, mac, timeout=10):
    """Receive DHCPOFFER message."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            data, addr = sock.recvfrom(1024)
            received_xid = struct.unpack('!I', data[4:8])[0]
            received_mac = ':'.join(['%02x' % b for b in data[28:34]])
            if received_xid == xid and received_mac.lower() == mac.lower():
                offered_ip, server_id = parse_dhcp_offer(data, xid, mac)
                if offered_ip and server_id:
                    return offered_ip, server_id
        except socket.timeout:
            continue
        except Exception as e:
            print(f"[Error] {e}")
    return None, None

def receive_dhcp_ack(sock, xid, mac, timeout=10):
    """Receive DHCPACK message."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            data, addr = sock.recvfrom(1024)
            received_xid = struct.unpack('!I', data[4:8])[0]
            received_mac = ':'.join(['%02x' % b for b in data[28:34]])
            if received_xid == xid and received_mac.lower() == mac.lower():
                assigned_ip, lease_time = parse_dhcp_ack(data, xid, mac)
                if assigned_ip and lease_time:
                    return assigned_ip, lease_time
        except socket.timeout:
            continue
        except Exception as e:
            print(f"[Error] {e}")
    return None, None

def main():
    if len(sys.argv) > 1 and sys.argv[1].lower() == 'release':
        if len(sys.argv) != 4:
            print("Usage: python dhcp_client.py release <MAC_ADDRESS> <SERVER_IP>")
            sys.exit(1)
        mac_address = sys.argv[2]
        server_ip = sys.argv[3]
        client_ip = input("Enter the IP address to release: ")
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('', DHCP_CLIENT_PORT))
        # Generate a random xid
        xid = random.randint(1, 900000)
        # Determine broadcast address
        broadcast_address = '255.255.255.255'
        send_dhcp_release(sock, mac_address, xid, client_ip, server_ip, broadcast_address)
        sock.close()
        sys.exit(0)

    # Generate a random MAC address
    mac_address = generate_mac()
    print(f"[DHCP Client] Using MAC Address: {mac_address}")

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(('', DHCP_CLIENT_PORT))
    sock.settimeout(5)

    # Generate a random transaction ID
    xid = random.randint(1, 900000)
    print(f"[DHCP Client] Transaction ID: {xid}")

    # Determine broadcast address
    broadcast_address = '255.255.255.255'

    # Send DHCPDISCOVER
    send_dhcp_discover(sock, mac_address, xid, broadcast_address)

    # Receive DHCPOFFER
    print("[DHCP Client] Waiting for DHCPOFFER...")
    offered_ip, server_id = receive_dhcp_offer(sock, xid, mac_address)
    if not offered_ip:
        print("[DHCP Client] No DHCPOFFER received.")
        sock.close()
        sys.exit(1)
    print(f"[DHCP Client] Received DHCPOFFER: IP {offered_ip} from Server {server_id}")

    # Send DHCPREQUEST
    send_dhcp_request(sock, mac_address, xid, offered_ip, server_id, broadcast_address)

    # Receive DHCPACK
    print("[DHCP Client] Waiting for DHCPACK...")
    assigned_ip, lease_time = receive_dhcp_ack(sock, xid, mac_address)
    if not assigned_ip:
        print("[DHCP Client] No DHCPACK received.")
        sock.close()
        sys.exit(1)
    print(f"[DHCP Client] Received DHCPACK: IP {assigned_ip}, Lease Time: {lease_time} seconds")

    # Simulate lease duration
    print(f"[DHCP Client] Successfully acquired IP: {assigned_ip} with lease time {lease_time} seconds.")
    print("[DHCP Client] Press Ctrl+C to release the IP and exit.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[DHCP Client] Releasing IP...")
        release_ip = assigned_ip
        send_dhcp_release(sock, mac_address, xid, release_ip, server_id, broadcast_address)
        sock.close()
        print(f"[DHCP Client] Sent DHCPRELEASE for IP {release_ip} to Server {server_id}")
        sys.exit(0)

if __name__ == "__main__":
    main()
