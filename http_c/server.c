// server.c
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 4096

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE + 1];
    memset(buffer, 0, BUFFER_SIZE);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_fd, 10);

    printf("Server listening on port %d\n", PORT);

    while(1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
        char buffer[BUFFER_SIZE] = {0};
        int total_bytes_received = 0;
        int bytes_received;

        // Read until we find the end of headers (\r\n\r\n) or the buffer is (almost) full
        while ((bytes_received = read(client_fd, buffer + total_bytes_received, BUFFER_SIZE - total_bytes_received - 1)) > 0) {
            total_bytes_received += bytes_received;
            buffer[total_bytes_received] = '\0'; // Null-terminate for strstr
            // Check if we've received the end of the headers
            if (strstr(buffer, "\r\n\r\n") != NULL) {
                break;
            }
            // Break if the buffer is full but we still haven't found the end of headers
            if (total_bytes_received >= BUFFER_SIZE - 1) {
                // Buffer is full, but we haven't found the end of headers.
                // This could be treated as an error (e.g., 413 Payload Too Large).
                // For simplicity, we'll just break.
                break;
            }
        }
        
        if (bytes_received < 0) {
            perror("read");
            close(client_fd);
            continue;
        }

        printf("Received request:\n%s\n", buffer);

        const char *response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 13\r\n"
            "\r\n"
            "Hello, World!";

        write(client_fd, response, strlen(response));
        close(client_fd);
    }

    close(server_fd);
    return 0;
}
