// client.rs
use std::io::{Read, Write};
use std::net::TcpStream;

fn main() {
    let mut stream = TcpStream::connect("127.0.0.1:8080").unwrap();

    let request = b"GET / HTTP/1.1\r\n\
                    Host: localhost\r\n\
                    Connection: close\r\n\
                    \r\n";

    stream.write_all(request).unwrap();

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).unwrap();

    println!("{}", String::from_utf8_lossy(&buffer));
}
