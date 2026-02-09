//! Local proxy for forwarding requests

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use anyhow::Result;

/// Forward HTTP request to local server
pub async fn forward_http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
    
    // Build request
    let mut request = format!("{} {} HTTP/1.1\r\nHost: localhost:{}\r\n", method, path, port);
    for (key, value) in headers {
        request.push_str(&format!("{}: {}\r\n", key, value));
    }
    
    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    
    stream.write_all(request.as_bytes()).await?;
    if let Some(body) = body {
        stream.write_all(body).await?;
    }
    
    // Read response
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    
    // Parse response (simplified - just return raw)
    Ok((200, vec![], response))
}
