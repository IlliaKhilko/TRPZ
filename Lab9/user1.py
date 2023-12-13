import socket

def create_client_socket():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return client_socket

def connect_to_server(client_socket, host, port):
    client_socket.connect((host, port))

def send_command(client_socket, command):
    client_socket.sendall(command.encode())

def receive_response(client_socket):
    response = client_socket.recv(1024).decode()
    return response

def main():
    host = "localhost"
    port = 5559

    client_socket = create_client_socket()

    try:
        connect_to_server(client_socket, host, port)

        while True:
            command = input("Enter a command (or 'exit' to quit): ")

            if command.lower() == 'exit':
                break

            send_command(client_socket, command)
            response = receive_response(client_socket)
            print(response)

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        client_socket.close()

if __name__ == '__main__':
    main()
