import socket

HOST = '127.0.0.1'  # The DHCP server's control interface IP (localhost)
PORT = 8080         # The TCP control port

def main():
    # Create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Connect to the server
        s.connect((HOST, PORT))
        
        # Receive the initial welcome messages
        welcome = s.recv(1024).decode('utf-8')
        instructions = s.recv(1024).decode('utf-8')
        print("Server says:")
        print(welcome, end='')
        print(instructions, end='')
        
        # Send the "status" command to check DHCP leases
        s.sendall(b'status\n')
        response = s.recv(2048).decode('utf-8')
        print("Status response:", response, end='')
        
        # You can add more tests here if needed, for example sending invalid commands:
        # s.sendall(b'unknowncommand\n')
        # print("Response to unknown command:", s.recv(1024).decode('utf-8'), end='')

        # Send the "quit" command to close the connection
        s.sendall(b'quit\n')
        goodbye = s.recv(1024).decode('utf-8')
        print("Server says:", goodbye, end='')

if __name__ == "__main__":
    main()
