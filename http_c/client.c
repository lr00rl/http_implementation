// client.c
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    struct sockaddr_in server_addr;

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(80);
    inet_pton(AF_INET, "54.80.48.62", &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        return 1;
    }

    const char *request =
        "GET /uuid HTTP/1.1\r\n"
        "Host: httpbin.org\r\n"
        "Connection: close\r\n"
        "\r\n";

    if (send(sock, request, strlen(request), 0) < 0) {
        perror("send");
        return 1;
    }

    char buffer[4096];
    int bytes = recv(sock, buffer, sizeof(buffer)-1, 0);
    if (bytes < 0) {
        perror("recv");
        return 1;
    }
    buffer[bytes] = '\0';
    printf("%s\n", buffer);

    close(sock);
    return 0;
}
