# server.py
import socket

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', 8080))
server.listen(5)

print("Server listening on port 8080")

while True:
    client, addr = server.accept()

    # Use loop to receive data until we find the end of headers
    request = b""
    while True:
        chunk = client.recv(1024)
        if not chunk:
            break
        request += chunk
        # Check if we've received the end of the headers
        if b"\r\n\r\n" in request:
            break

    print(f"Received request:\n{request.decode()}\n")

    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 13\r\n"
        b"\r\n"
        b"Hello, World!"
    )

    client.sendall(response)
    client.close()
