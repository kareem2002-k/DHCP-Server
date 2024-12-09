import socket

HOST = '127.0.0.1'  # server address
PORT = 8080         # TCP control port you set in the server

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
        
        # Send the "status" command
        s.sendall(b'status\n')
        response = s.recv(1024).decode('utf-8')
        print("Status response:", response, end='')
        
        # Send the "quit" command
        s.sendall(b'quit\n')
        goodbye = s.recv(1024).decode('utf-8')
        print("Server says:", goodbye, end='')

if __name__ == "__main__":
    main()
