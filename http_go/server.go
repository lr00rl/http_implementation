// server.go
package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
)

func main() {
	listener, _ := net.Listen("tcp", ":8080")
	defer listener.Close()

	fmt.Println("Server listening on port 8080")

	for {
		conn, _ := listener.Accept()
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	var requestBuffer bytes.Buffer
	tempBuffer := make([]byte, 1024) // Read in 1KB chunks

	for {
		n, err := conn.Read(tempBuffer)
		if err != nil {
			if err != io.EOF {
				fmt.Println("Read error:", err)
			}
			break
		}

		requestBuffer.Write(tempBuffer[:n])

		// Check if we've received the end of the headers
		if bytes.Contains(requestBuffer.Bytes(), []byte("\r\n\r\n")) {
			break
		}
	}

	fmt.Printf("Received request:\n%s\n", requestBuffer.String())

	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: 13\r\n" +
		"\r\n" +
		"Hello, World!"

	conn.Write([]byte(response))
}
