# HTTP and HTTPS Implementations

This repository contains simple client and server implementations for HTTP and HTTPS in various programming languages.

## Directory Structure

*   `http_c/`: C implementation of an HTTP server and client.
*   `http_go/`: Go implementation of an HTTP server and client.
*   `http_python/`: Python implementation of an HTTP server and client.
*   `http_rust/`: Rust implementation of an HTTP server and client.
*   `https_c/`: C implementation of an HTTPS server and client using OpenSSL.

## How to Run

### C (HTTP)

**Server:**
```bash
gcc http_c/server.c -o http_c/server
./http_c/server
```

**Client:**
```bash
gcc http_c/client.c -o http_c/client
./http_c/client
```

### Go (HTTP)

**Server:**
```bash
go run http_go/server.go
```

**Client:**
```bash
go run http_go/client.go
```

### Python (HTTP)

**Server:**
```bash
python3 http_python/server.py
```

**Client:**
```bash
python3 http_python/client.py
```

### Rust (HTTP)

**Server:**
```bash
rustc http_rust/server.rs -o http_rust/server
./http_rust/server
```

**Client:**
```bash
rustc http_rust/client.rs -o http_rust/client
./http_rust/client
```

### C (HTTPS)

This implementation requires OpenSSL.

1.  **Navigate to the directory:**
    ```bash
    cd https_c
    ```

2.  **Build the server and client:**
    ```bash
    make
    ```

3.  **Run the server:**
    ```bash
    ./server
    ```

4.  **In a new terminal, run the client:**
    ```bash
    ./client
    ```
