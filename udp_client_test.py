from scapy.all import (
    sendp,
    sniff,
    Ether,
    IP,
    UDP,
    BOOTP,
    DHCP,
    get_if_list,
    get_if_hwaddr,
    conf,
    RandInt  # Added RandInt here

)
import sys

def mac2str(mac):
    """
    Converts a MAC address string to bytes.
    """
    try:
        return bytes.fromhex(mac.replace(':', '').replace('-', ''))
    except ValueError as e:
        print(f"[ERROR] Invalid MAC address format: {mac} ({e})")
        sys.exit(1)

def get_dhcp_option(options, key):
    """
    Helper function to get a specified DHCP option value.
    options is a list of tuples like [('message-type', 2), ('server_id', '192.168.1.1'), 'end']
    """
    try:
        for opt in options:
            if isinstance(opt, tuple) and opt[0] == key:
                return opt[1]
    except Exception as e:
        print(f"[ERROR] Exception while retrieving DHCP option '{key}': {e}")
    return None

def main():
        # Turn off Scapy's verbose mode for cleaner output
        conf.verb = 0

        # List available interfaces
        interfaces = get_if_list()
        if not interfaces:
            print("[ERROR] No network interfaces found.")
            sys.exit(1)

        print("Available interfaces with MAC addresses:")
        for iface in interfaces:
            try:
                mac = get_if_hwaddr(iface)
                print(f"- {iface}, MAC: {mac}")
            except Exception as e:
                print(f"- {iface}, MAC: Could not retrieve ({e})")

        # Prompt user to select an interface
        iface = input("Enter the interface name to use: ").strip()
        if iface not in interfaces:
            print(f"[ERROR] Interface '{iface}' not found. Exiting.")
            sys.exit(1)

        # Use the interface's actual MAC address
        try:
            client_mac = get_if_hwaddr(iface)
        except Exception as e:
            print(f"[ERROR] Failed to retrieve MAC address for interface '{iface}': {e}")
            sys.exit(1)
        print(f"Using MAC: {client_mac}")

        # Construct a DHCPDISCOVER packet:
        try:
            dhcp_discover = (
                Ether(dst="ff:ff:ff:ff:ff:ff", src=client_mac)/
                IP(src="0.0.0.0", dst="255.255.255.255")/
                UDP(sport=68, dport=67)/
                BOOTP(chaddr=mac2str(client_mac), xid=RandInt(), flags=0x8000)/  # flags=0x8000 sets the broadcast bit
                DHCP(options=[("message-type","discover"),("end")])
            )
        except Exception as e:
            print(f"[ERROR] Failed to construct DHCPDISCOVER packet: {e}")
            sys.exit(1)

        # Send DHCPDISCOVER
        try:
            print("[CLIENT] Sending DHCPDISCOVER...")
            sendp(dhcp_discover, iface=iface, verbose=False)
        except PermissionError:
            print("[ERROR] Permission denied. Please run the script as Administrator.")
            sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Failed to send DHCPDISCOVER packet: {e}")
            sys.exit(1)

        # Wait for DHCPOFFER
        try:
            print("[CLIENT] Waiting for DHCPOFFER...")
            offer = sniff(filter="udp and (port 67 or port 68)", iface=iface, timeout=5, count=1)
            if not offer:
                print("[ERROR] No DHCPOFFER received. Check server logs or configuration.")
                sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Failed to sniff for DHCPOFFER: {e}")
            sys.exit(1)

        # Process DHCPOFFER
        try:
            offer_pkt = offer[0]
            if not offer_pkt.haslayer(DHCP):
                print("[ERROR] Received packet does not contain DHCP layer.")
                sys.exit(1)

            dhcp_offer_options = offer_pkt[DHCP].options
            offered_ip = offer_pkt[BOOTP].yiaddr
            print(f"[CLIENT] Received DHCPOFFER with IP: {offered_ip}")
        except Exception as e:
            print(f"[ERROR] Failed to process DHCPOFFER packet: {e}")
            sys.exit(1)

        # Extract Server ID
        try:
            server_id = get_dhcp_option(dhcp_offer_options, 'server_id')
            if not server_id:
                print("[ERROR] No server identifier found in DHCPOFFER. Cannot proceed with DHCPREQUEST.")
                sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Failed to extract server_id from DHCPOFFER: {e}")
            sys.exit(1)

        # Construct DHCPREQUEST packet
        try:
            dhcp_request = (
                Ether(dst="ff:ff:ff:ff:ff:ff", src=client_mac)/
                IP(src="0.0.0.0", dst="255.255.255.255")/
                UDP(sport=68, dport=67)/
                BOOTP(chaddr=mac2str(client_mac), xid=offer_pkt[BOOTP].xid, flags=0x8000)/
                DHCP(options=[
                    ("message-type","request"),
                    ("requested_addr", offered_ip),
                    ("server_id", server_id),
                    ("end")
                ])
            )
        except Exception as e:
            print(f"[ERROR] Failed to construct DHCPREQUEST packet: {e}")
            sys.exit(1)

        # Send DHCPREQUEST
        try:
            print("[CLIENT] Sending DHCPREQUEST...")
            sendp(dhcp_request, iface=iface, verbose=False)
        except PermissionError:
            print("[ERROR] Permission denied. Please run the script as Administrator.")
            sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Failed to send DHCPREQUEST packet: {e}")
            sys.exit(1)

        # Wait for DHCPACK
        try:
            print("[CLIENT] Waiting for DHCPACK...")
            ack = sniff(filter="udp and (port 67 or port 68)", iface=iface, timeout=5, count=1)
            if not ack:
                print("[ERROR] No DHCPACK received. Check server logs or if a DHCPNAK was sent.")
                sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Failed to sniff for DHCPACK: {e}")
            sys.exit(1)

        # Process DHCPACK
        try:
            ack_pkt = ack[0]
            if not ack_pkt.haslayer(DHCP):
                print("[ERROR] Received packet does not contain DHCP layer.")
                sys.exit(1)

            ack_options = ack_pkt[DHCP].options
            acked_ip = ack_pkt[BOOTP].yiaddr
            msg_type = get_dhcp_option(ack_options, 'message-type')

            if msg_type == 5:
                print(f"[CLIENT] Received DHCPACK. Leased IP: {acked_ip}")
            elif msg_type == 6:
                print("[CLIENT] Received DHCPNAK. The request was denied.")
            else:
                print("[CLIENT] Received unexpected DHCP message type.")
        except Exception as e:
            print(f"[ERROR] Failed to process DHCPACK packet: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
