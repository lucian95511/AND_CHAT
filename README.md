<div align="center">
╔════════════════════════════════════════════════════════════╗
║                        AND CHAT                            ║
║     End-to-End Encrypted · Server-Free · NAT Traversal     ║
╚════════════════════════════════════════════════════════════╝
AND Chat
Serverless, end-to-end encrypted P2P terminal chat
Show Image
Show Image
Show Image
Show Image
</div>

🔐 What is it?
AND Chat is a peer-to-peer terminal chat application that lets two or more people communicate directly and securely — without any central server.

Every connection is encrypted with TLS 1.3 + ECDSA P-256
Messages never pass through a server; they go directly to the other party
STUN, UPnP, and UDP Hole Punching allow devices behind NAT to connect to each other


✨ Features
FeatureDescription🔒 TLS 1.3 E2E EncryptionA unique ECDSA certificate is generated for every session🌍 NAT TraversalSTUN + UPnP + UDP Hole Punching support📡 Multi-peerConnect to multiple peers simultaneously🔒 Private MessagingSend direct messages with @username👥 Group ManagementCreate groups, add members, manage them⭐ Favorites & BlockingSaved peer list with starring and blocking📋 Message HistoryIn-session message log📊 StatisticsBytes sent/received, connection counts💾 Auto-savePeer info persisted to peers.conf

🚀 Installation
Requirements

Go 1.21+ must be installed.

Steps
bash# 1. Clone the repo
git clone https://github.com/yourusername/and-chat.git
cd and-chat

# 2. Tidy dependencies (standard library only, no extras needed)
go mod tidy

# 3. Run
go run main.go
Or build a standalone binary:
bashgo build -o and-chat main.go
./and-chat

⚙️ First Run
When the app starts, the following happens automatically:
1. A TLS certificate is generated for this session
2. You enter a username
3. NAT Traversal initializes (STUN query)
4. Listener opens on port :8888
5. Chat is ready!
👉 Enter your chat name (max 32 characters): Alice
[System] ✓ Certificate Fingerprint: a1b2c3d4e5f6...
[System] 🌍 Public IP: 85.12.34.56:8888
--------------------------------------------------
🚀 Secure Layer Active! Connected as Alice.

📖 Command Reference
📡 Connection
bash/connect <IP>               # Connect to a peer via TLS 1.3
/connect-all                # Connect to all saved peers
/disconnect <IP>            # Disconnect from a peer
/disconnect-all             # Close all connections
/list                       # List connected peers
💬 Messaging
bash# Broadcast — sent to all connected peers
Hello everyone!

# Private message — sent only to the specified user
@Bob Hey, how are you?
💾 Peer Management
bash/save <IP> <Name>           # Save a peer with a nickname
/saved                      # List saved peers
/remove <IP or Name>        # Remove a saved peer
/remove-all                 # Remove all saved peers
/star <IP>                  # Add / remove from favorites
/block <IP>                 # Block a user
/unblock <IP>               # Unblock a user
/blocked                    # View blocked users
🌍 NAT Traversal
bash/nat-info                   # Show public IP and NAT details
/upnp-test                  # Test UPnP port mapping
/hole-punch <IP>            # Attempt connection via Hole Punching
👥 Groups
bash/create-group <Name>        # Create a new group
/groups                     # List your groups
/add-member <GroupID> <IP>  # Add a member to a group
👤 Profile & Status
bash/whoami                     # View your own info
/profile <IP>               # View a connected peer's profile
/set-status <Message>       # Set your status message
📊 System
bash/history                    # Show last 50 messages
/stats                      # Session statistics
/security                   # Encryption and certificate info
/clear                      # Clear the screen
/help                       # List all commands
/exit                       # Safe exit

🌐 How Two Users Connect
Local Network (LAN)
If both parties are on the same network, the local IP is enough:
bash# Person A — IP: 192.168.1.10
./and-chat
# Username: Alice

# Person B
./and-chat
# Username: Bob
/connect 192.168.1.10
Over the Internet (WAN)
1. Person A runs /nat-info → gets their Public IP
2. Shares the Public IP with Person B (e.g. 85.12.34.56:8888)
3. Set up port forwarding on the router: 8888 → local IP
   OR it happens automatically if the router supports UPnP
4. Person B: /connect 85.12.34.56

💡 Tip: If a direct connection fails, try  to attempt UDP Hole Punching./hole-punch <IP>


🔒 Security Architecture
┌─────────────┐   TLS 1.3 + ECDSA P-256   ┌─────────────┐
│   Person A  │ ◄────────────────────────► │   Person B  │
│   (client)  │   End-to-end encrypted     │   (client)  │
└─────────────┘                            └─────────────┘
       │                                          │
       └──────────────── Direct ─────────────────┘
                      (no server)

A new ECDSA key pair and certificate is generated for every session
The certificate fingerprint is displayed on startup and can be verified manually with your peer
InsecureSkipVerify: true is used because certificates are self-signed; trust is established via fingerprint comparison
Messages are written to  — can be disabled in the source if preferredchat.log


📁 File Structure
and-chat/
├── main.go         # Full application source
├── peers.conf      # Saved peer list (auto-created)
├── chat.log        # Message log (auto-created)
└── groups.conf     # Group data reference

🛠️ Technical Details
ParameterValueListen port:8888TLS versionTLS 1.3 (minimum)Key typeECDSA P-256Certificate validity365 daysMax message length4,096 charactersMax username length32 charactersPing interval10 secondsConnection timeout7 seconds

🤝 Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you'd like to change.
bashgit checkout -b feature/your-feature
git commit -m "feat: description"
git push origin feature/your-feature

📄 License
This project is licensed under the MIT License.