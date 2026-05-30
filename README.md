<h1 align="center">AND CHAT</h1>
<p align="center">
  <strong>End-to-End Encrypted · Server-Free · NAT Traversal</strong>
</p>
<p align="center">
  <i>Serverless, end-to-end encrypted P2P terminal chat application.</i>
</p>

---

### 🔒 What is it?
**AND Chat** is a peer-to-peer (P2P) terminal chat application that lets two or more people communicate directly and securely — **without any central server**.

*   **Ultimate Privacy:** Every connection is encrypted using **TLS 1.3 + ECDSA P-256**. Messages never pass through a server; they travel directly to the other party.
*   **Smart Connectivity:** Built-in **STUN, UPnP, and UDP Hole Punching** allow devices hidden behind strict NAT firewalls to connect to each other effortlessly.

---

### ✨ Features

| Feature | Description |
| :--- | :--- |
| 🔒 **TLS 1.3 E2E Encryption** | A unique ECDSA certificate is generated dynamically for every single session. |
| 🌐 **NAT Traversal** | Full STUN, UPnP, and UDP Hole Punching support for seamless P2P connections. |
| 📡 **Multi-peer** | Connect and chat with multiple peers simultaneously. |
| 🔒 **Private Messaging** | Send direct, private messages using the `@username` syntax. |
| 👥 **Group Management** | Create custom groups, add members, and manage them on the fly. |
| ⭐ **Favorites & Blocking** | Keep a saved peer list with starring and blocking mechanics. |
| 📋 **Message History** | In-session message log to keep track of your conversations. |
| 📊 **Statistics** | Real-time tracking of bytes sent/received and active connection counts. |
| 💾 **Auto-save** | Peer info and configurations are automatically persisted to `peers.conf`. |

---

### 🚀 Installation & Quick Start

#### Requirements
*   **Go 1.21+** must be installed on your system.

#### Steps
```bash
# 1. Clone the repository
git clone [https://github.com/yourusername/and-chat.git](https://github.com/yourusername/and-chat.git)
cd and-chat

# 2. Tidy dependencies (Standard library only, no extras needed!)
go mod tidy

# 3. Run the application
go run main.go
💡 Tip: Alternatively, you can build a standalone binary:

Bash
go build -o and-chat main.go
./and-chat


---

### ⚙️ First Run
When the app starts, the following workflow happens automatically:
1. A unique TLS certificate is generated for the active session.
2. You will be prompted to enter a username.
3. NAT Traversal initializes via a STUN query.
4. A secure listener opens on port `:8888`.

```text
👉 Enter your chat name (max 32 characters): Alice
[System] ✓ Certificate Fingerprint: a1b2c3d4e5f6...
[System] 🌍 Public IP: 85.12.34.56:8888

🚀 Secure Layer Active! Connected as Alice.
