// client.c - HTTPS client for httpbin.org
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include "tls_client.h"

int main() {
    const char *hostname = "httpbin.org";
    const char *port = "443";

    printf("Resolving %s...\n", hostname);

    // DNS resolution
    struct addrinfo hints, *result, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo(hostname, port, &hints, &result);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return 1;
    }

    // Try each address until we successfully connect
    int sock = -1;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) {
            continue;
        }

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            printf("Connected to %s:%s\n", hostname, port);
            break;
        }

        close(sock);
        sock = -1;
    }

    freeaddrinfo(result);

    if (sock < 0) {
        fprintf(stderr, "Could not connect to %s:%s\n", hostname, port);
        return 1;
    }

    // Initialize TLS client
    tls_client_t tls_client;
    if (tls_client_init(&tls_client) < 0) {
        fprintf(stderr, "Failed to initialize TLS client\n");
        close(sock);
        return 1;
    }

    // Perform TLS handshake
    printf("Starting TLS handshake...\n");
    if (tls_client_connect(&tls_client, sock, hostname) < 0) {
        fprintf(stderr, "TLS handshake failed\n");
        tls_client_close(&tls_client);
        close(sock);
        return 1;
    }

    // Send HTTP GET request
    const char *request =
        "GET /get HTTP/1.1\r\n"
        "Host: httpbin.org\r\n"
        "User-Agent: simple-https-client/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n";

    printf("\nSending HTTP request...\n");
    if (tls_client_write(&tls_client, request, strlen(request)) < 0) {
        fprintf(stderr, "Failed to send request\n");
        tls_client_close(&tls_client);
        close(sock);
        return 1;
    }

    // Receive and print response
    printf("\nReceiving response:\n");
    printf("----------------------------------------\n");

    char buffer[4096];
    int total_bytes = 0;
    while (1) {
        int bytes = tls_client_read(&tls_client, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) {
            break;
        }
        buffer[bytes] = '\0';
        printf("%s", buffer);
        total_bytes += bytes;
    }

    printf("\n----------------------------------------\n");
    printf("Total bytes received: %d\n", total_bytes);

    // Cleanup
    tls_client_close(&tls_client);
    close(sock);

    return 0;
}
