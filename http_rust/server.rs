// server.rs
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

fn handle_client(mut stream: TcpStream) {
    // Use loop to receive data until we find the end of headers
    let mut request_buffer = Vec::new();
    let mut temp_buffer = [0u8; 1024];

    loop {
        match stream.read(&mut temp_buffer) {
            Ok(0) => break, // Connection closed
            Ok(n) => {
                request_buffer.extend_from_slice(&temp_buffer[..n]);
                // Check if we've received the end of the headers
                if request_buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(e) => {
                eprintln!("Read error: {}", e);
                return;
            }
        }
    }

    println!(
        "Received request:\n{}\n",
        String::from_utf8_lossy(&request_buffer)
    );

    let response = b"HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain\r\n\
                     Content-Length: 13\r\n\
                     \r\n\
                     Hello, World!";

    stream.write_all(response).unwrap();
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    println!("Server listening on port 8080");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                std::thread::spawn(|| handle_client(stream));
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }
}
