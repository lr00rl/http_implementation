# client.py
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 8080))

request = (
    b"GET / HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

sock.sendall(request)

# Use loop to receive all response data
response = b""
while True:
    chunk = sock.recv(1024)
    if not chunk:
        break
    response += chunk

print(response.decode())
sock.close()
