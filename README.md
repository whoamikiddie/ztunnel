# ZTunnel

**Self-hosted secure tunnel** - Expose local services to the internet like ngrok, but on your own infrastructure.

```
+--------+    HTTPS     +---------------+    WebSocket    +--------+    HTTP     +------------+
| Users  | -----------> | Relay Server  | <-------------> | Client | ----------> | Local App  |
+--------+              +---------------+                 +--------+             +------------+
                         (your VPS)                       (your machine)        (localhost:3000)
```

## Quick Start

### 1. Start the Relay Server (on your VPS)

```bash
# Using Docker
docker run -d -p 8080:8080 -e ZTUNNEL_DOMAIN=yourdomain.com ghcr.io/yourusername/ztunnel-relay

# Or build from source
cargo build --release -p ztunnel-relay
./target/release/ztunnel-relay
```

### 2. Run the Client (on your machine)

```bash
# Expose local port 3000
./ztunnel http 3000 --relay wss://relay.yourdomain.com/tunnel

# Output:
# ╔══════════════════════════════════════════════════════════════╗
# ║  🚀 ZTunnel Active                                           ║
# ╠══════════════════════════════════════════════════════════════╣
# ║  Public URL: https://abc123.yourdomain.com                   ║
# ║  Local:      http://localhost:3000                           ║
# ╚══════════════════════════════════════════════════════════════╝
```

### 3. Usage Examples

```bash
# HTTP tunnel with custom subdomain
ztunnel http 3000 --subdomain myapp
# → https://myapp.yourdomain.com

# TCP tunnel (SSH, databases, etc.)
ztunnel tcp 22
# → tcp://relay.yourdomain.com:54321

# With verbose logging
ztunnel http 8080 -v
```

## Deployment

### Option 1: Fly.io (Free Tier)

```bash
cd relay
flyctl launch
flyctl secrets set ZTUNNEL_DOMAIN=yourdomain.com
flyctl deploy
```

### Option 2: Docker Compose

```yaml
# docker-compose.yml
services:
  relay:
    build: ./relay
    ports:
      - "8080:8080"
      - "443:443"
    environment:
      - ZTUNNEL_DOMAIN=yourdomain.com
      - RUST_LOG=info
```

### Option 3: Systemd Service

```bash
sudo cp target/release/ztunnel-relay /usr/local/bin/
sudo cp deploy/ztunnel-relay.service /etc/systemd/system/
sudo systemctl enable --now ztunnel-relay
```

## DNS Setup

Add these records to your domain:

| Type   | Name   | Value           |
|--------|--------|-----------------|
| A      | relay  | `<server-ip>`   |
| A      | *      | `<server-ip>`   |

## Building

```bash
# Build everything
cargo build --release

# Build client only
cargo build --release -p ztunnel

# Build relay only  
cargo build --release -p ztunnel-relay

# Build libzcrypto (C++ crypto library)
cd libzcrypto && cmake -B build && cmake --build build
```

## Architecture

- **libzcrypto**: C++ + x86-64 ASM cryptographic library (ChaCha20, Poly1305, X25519, HKDF)
- **ztunnel-relay**: Rust async server handling tunnel connections
- **ztunnel**: Rust CLI client for creating tunnels
- **ztunnel-shared**: Shared protocol and types

## Security

- End-to-end encryption using ChaCha20-Poly1305
- X25519 key exchange with forward secrecy
- Timing-attack resistant crypto (constant-time operations)
- Relay server cannot decrypt traffic

## License

MIT
