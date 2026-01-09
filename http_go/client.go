// client.go
package main

import (
    "fmt"
    "net"
)

func main() {
    conn, _ := net.Dial("tcp", "localhost:8080")
    defer conn.Close()

    request := "GET / HTTP/1.1\r\n" +
               "Host: localhost\r\n" +
               "Connection: close\r\n" +
               "\r\n"

    conn.Write([]byte(request))

    buffer := make([]byte, 4096)
    n, _ := conn.Read(buffer)
    fmt.Printf("Received response:\n%s\n", string(buffer[:n]))
}
