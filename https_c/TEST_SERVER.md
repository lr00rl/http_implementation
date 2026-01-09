# Testing the HTTPS Server

This document explains how to test the custom TLS server implementation.

## Quick Start

### Terminal 1: Start the Server

```bash
cd https_c
./https_server
```

The server will start listening on port 4433 by default.

### Terminal 2: Test with the Custom Client

Since this is an educational TLS implementation with a simplified certificate,
standard tools like `curl` or browsers will reject the connection. Instead,
you can test with the custom client (which also uses simplified TLS):

```bash
cd https_c
# Modify client.c to connect to localhost:4433 instead of example.com
```

## Testing Methodology

### Option 1: Using OpenSSL s_client (Will Fail Certificate Validation)

You can use OpenSSL's s_client to see the TLS handshake, but it will fail
certificate validation since we're using a placeholder certificate:

```bash
openssl s_client -connect localhost:4433 -tls1_2
```

Expected behavior:
- The handshake will start
- You'll see certificate errors (expected)
- The connection may be refused due to invalid certificate

### Option 2: Using netcat to see raw traffic

```bash
nc localhost 4433
```

Then manually type a TLS ClientHello (not practical, but shows the server
is listening).

### Option 3: Create a Test Client

The best way to test is to create a simple test client that connects to
localhost instead of example.com.

## Server Behavior

The server will:

1. Accept incoming TCP connections
2. Perform TLS 1.2 handshake:
   - Receive ClientHello
   - Send ServerHello
   - Send Certificate (placeholder)
   - Send ServerKeyExchange (ECDHE)
   - Send ServerHelloDone
   - Receive ClientKeyExchange
   - Receive ChangeCipherSpec
   - Receive Finished (encrypted)
   - Send ChangeCipherSpec
   - Send Finished (encrypted)
3. Receive encrypted HTTP request
4. Send encrypted HTTP response
5. Close connection

## Expected Output

When a client connects, you should see output like:

```

