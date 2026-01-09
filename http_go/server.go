// server.go
package main

import (
    "fmt"
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

    buffer := make([]byte, 4096)
    conn.Read(buffer)
	// print request:


    response := "HTTP/1.1 200 OK\r\n" +
                "Content-Type: text/plain\r\n" +
                "Content-Length: 13\r\n" +
                "\r\n" +
                "Hello, World!"

    conn.Write([]byte(response))
}
