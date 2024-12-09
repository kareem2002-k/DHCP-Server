import socket

HOST = '127.0.0.1'   # server address
PORT = 67            # DHCP server port

def main():
    # Create a UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        # We can send any arbitrary data for testing
        test_data = b'This is a test DHCP packet'
        
        # Send the data to the server
        s.sendto(test_data, (HOST, PORT))
        print(f"Sent UDP packet to {HOST}:{PORT}")

        # The server code as written doesn't send a response
        # If we wanted to try receiving, we could attempt s.recv
        # but in this test, we only verify by server console output.
        # Example (optional):
        s.settimeout(2.0)
        try:
            data, addr = s.recvfrom(1024)
            print("Received response:", data)
        except socket.timeout:
            print("No response received (expected, since server isn't implemented to respond).")

if __name__ == "__main__":
    main()
