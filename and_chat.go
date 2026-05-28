package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	chatPort            = ":8888"
	pingInterval        = 10 * time.Second
	readTimeout         = 30 * time.Second
	writeTimeout        = 10 * time.Second
	maxMessageLength    = 4096
	maxUsernameLength   = 32
	tlsCertValidityDays = 365
	configFile          = "peers.conf"
	logFile             = "chat.log"
	groupsFile          = "groups.conf"
)

type STUNResponse struct {
	PublicIP   string `json:"public_ip"`
	PublicPort int    `json:"public_port"`
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
}

type NATInfo struct {
	PublicIP   string
	PublicPort int
	LocalIP    string
	LocalPort  int
	NATType    string
}

type STUNClient struct {
	serverAddress string
	timeout       time.Duration
}

func NewSTUNClient(serverAddress string) *STUNClient {
	return &STUNClient{
		serverAddress: serverAddress,
		timeout:       5 * time.Second,
	}
}

func (sc *STUNClient) GetPublicAddress() (*NATInfo, error) {
	client := &http.Client{
		Timeout: sc.timeout,
	}

	resp, err := client.Get(fmt.Sprintf("http://%s/stun", sc.serverAddress))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var stunResp STUNResponse
	if err := json.NewDecoder(resp.Body).Decode(&stunResp); err != nil {
		return nil, err
	}

	natInfo := &NATInfo{
		PublicIP:   stunResp.PublicIP,
		PublicPort: stunResp.PublicPort,
		LocalIP:    stunResp.LocalIP,
		LocalPort:  stunResp.LocalPort,
		NATType:    "Full Cone",
	}

	return natInfo, nil
}

type UPnPController struct {
	mu         sync.RWMutex
	enabled    bool
	mappedPort int
}

func NewUPnPController() *UPnPController {
	return &UPnPController{
		enabled:    false,
		mappedPort: 0,
	}
}

func (uc *UPnPController) MapPort(externalPort, internalPort int, protocol string) error {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	fmt.Printf("[UPnP] Port Mapping: %d (%s) -> %d (Internal)\n", externalPort, protocol, internalPort)
	uc.enabled = true
	uc.mappedPort = externalPort

	return nil
}

func (uc *UPnPController) UnmapPort(externalPort int, protocol string) error {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	fmt.Printf("[UPnP] Port Unmapping: %d (%s)\n", externalPort, protocol)
	uc.enabled = false
	uc.mappedPort = 0

	return nil
}

func (uc *UPnPController) IsEnabled() bool {
	uc.mu.RLock()
	defer uc.mu.RUnlock()
	return uc.enabled
}

type HolePunchingManager struct {
	mu            sync.RWMutex
	localIP       string
	publicIP      string
	localPort     int
	publicPort    int
	punchAttempts map[string]int
	maxAttempts   int
	punchInterval time.Duration
}

func NewHolePunchingManager(localIP string, publicIP string, localPort, publicPort int) *HolePunchingManager {
	return &HolePunchingManager{
		localIP:       localIP,
		publicIP:      publicIP,
		localPort:     localPort,
		publicPort:    publicPort,
		punchAttempts: make(map[string]int),
		maxAttempts:   5,
		punchInterval: 200 * time.Millisecond,
	}
}

func (hpm *HolePunchingManager) SendPunchPacket(targetIP string, targetPort int) error {
	hpm.mu.Lock()
	attempts := hpm.punchAttempts[targetIP]
	hpm.punchAttempts[targetIP] = attempts + 1
	hpm.mu.Unlock()

	if attempts >= hpm.maxAttempts {
		return fmt.Errorf("maximum punch attempts exceeded")
	}

	addr := net.UDPAddr{
		Port: targetPort,
		IP:   net.ParseIP(targetIP),
	}

	conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write([]byte("PUNCH"))
	if err != nil {
		return err
	}

	fmt.Printf("[Hole Punch] Punch packet sent to %s:%d (attempt %d)\n", targetIP, targetPort, attempts+1)
	return nil
}

func (hpm *HolePunchingManager) AttemptPunch(targetIP string, targetPort int) error {
	for i := 0; i < hpm.maxAttempts; i++ {
		if err := hpm.SendPunchPacket(targetIP, targetPort); err != nil {
			fmt.Printf("[Hole Punch] ⚠️ Error connecting to %s:%d: %v\n", targetIP, targetPort, err)
		}
		time.Sleep(hpm.punchInterval)
	}
	return nil
}

type EndpointManager struct {
	mu           sync.RWMutex
	stunClient   *STUNClient
	upnpControl  *UPnPController
	holePunch    *HolePunchingManager
	natInfo      *NATInfo
	lastRefresh  time.Time
	refreshTimer *time.Timer
}

func NewEndpointManager(stunServer string) *EndpointManager {
	return &EndpointManager{
		stunClient:  NewSTUNClient(stunServer),
		upnpControl: NewUPnPController(),
		natInfo:     nil,
		lastRefresh: time.Now(),
	}
}

func (em *EndpointManager) RefreshNATInfo() (*NATInfo, error) {
	em.mu.Lock()
	defer em.mu.Unlock()

	natInfo, err := em.stunClient.GetPublicAddress()
	if err != nil {
		return nil, fmt.Errorf("STUN query failed: %v", err)
	}

	em.natInfo = natInfo

	em.holePunch = NewHolePunchingManager(
		natInfo.LocalIP,
		natInfo.PublicIP,
		natInfo.LocalPort,
		natInfo.PublicPort,
	)

	em.lastRefresh = time.Now()

	fmt.Printf("[NAT] Public IP: %s:%d | Local IP: %s:%d\n",
		natInfo.PublicIP, natInfo.PublicPort,
		natInfo.LocalIP, natInfo.LocalPort)

	return natInfo, nil
}

func (em *EndpointManager) SetupPortMapping(internalPort int) error {
	em.mu.RLock()
	upnp := em.upnpControl
	em.mu.RUnlock()

	if err := upnp.MapPort(internalPort, internalPort, "TCP"); err != nil {
		fmt.Printf("[UPnP] ⚠️ Port mapping failed: %v\n", err)
		fmt.Println("[UPnP] 💡 Please configure port forwarding manually on your router")
		return err
	}

	return nil
}

func (em *EndpointManager) GetNATInfo() *NATInfo {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return em.natInfo
}

func (em *EndpointManager) GetHolePunch() *HolePunchingManager {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return em.holePunch
}

type MessageType string

const (
	MSG_NORMAL  MessageType = "normal"
	MSG_NOTICE  MessageType = "notice"
	MSG_SYSTEM  MessageType = "system"
	MSG_EMOJI   MessageType = "emoji"
	MSG_PRIVATE MessageType = "private"
)

type Message struct {
	Type      MessageType       `json:"type"`
	From      string            `json:"from"`
	To        string            `json:"to,omitempty"`
	Content   string            `json:"content"`
	Timestamp time.Time         `json:"timestamp"`
	ID        string            `json:"id,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type UserStatus string

const (
	STATUS_ONLINE  UserStatus = "online"
	STATUS_AWAY    UserStatus = "away"
	STATUS_DND     UserStatus = "dnd"
	STATUS_OFFLINE UserStatus = "offline"
)

type UserProfile struct {
	Username  string
	Status    UserStatus
	StatusMsg string
	LastSeen  time.Time
	PublicKey string
}

type PeerInfo struct {
	IP           string
	Name         string
	ConnectedAt  time.Time
	LastActivity time.Time
	Status       UserStatus
	StatusMsg    string
	MessageCount int
	IsTyping     bool
	Profile      *UserProfile
	PublicIP     string
	PublicPort   int
}

type SavedPeer struct {
	IP      string
	Name    string
	SavedAt time.Time
	Blocked bool
	Starred bool
}

type Group struct {
	ID        string
	Name      string
	Members   map[string]*PeerInfo
	CreatedAt time.Time
	Admin     string
	IsActive  bool
}

type PeerStats struct {
	TotalMessages    int
	TotalConnections int
	SessionStart     time.Time
	BytesSent        int64
	BytesReceived    int64
	SuccessfulNATs   int
	FailedNATs       int
}

type PeerManager struct {
	mu              sync.RWMutex
	peers           map[string]net.Conn
	peerInfo        map[string]*PeerInfo
	name            string
	profile         *UserProfile
	tlsConfig       *tls.Config
	tlsServerConfig *tls.Config
	shutdown        chan struct{}
	messageLog      []Message
	maxLogSize      int
	logger          *log.Logger
	certFingerprint string
	savedPeers      map[string]*SavedPeer
	logFile         *os.File
	stats           PeerStats
	groups          map[string]*Group
	commandHistory  []string
	maxHistorySize  int
	blockedUsers    map[string]bool
	favorites       map[string]bool
	endpointMgr     *EndpointManager
	natInfo         *NATInfo
}

func NewPeerManager(name string, tlsCfg *tls.Config, tlsServerCfg *tls.Config) *PeerManager {
	logFile, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	profile := &UserProfile{
		Username:  name,
		Status:    STATUS_ONLINE,
		StatusMsg: "Hello! 👋",
		LastSeen:  time.Now(),
	}

	endpointMgr := NewEndpointManager("stun.l.google.com:19302")

	return &PeerManager{
		peers:           make(map[string]net.Conn),
		peerInfo:        make(map[string]*PeerInfo),
		name:            name,
		profile:         profile,
		tlsConfig:       tlsCfg,
		tlsServerConfig: tlsServerCfg,
		shutdown:        make(chan struct{}),
		messageLog:      make([]Message, 0, 1000),
		maxLogSize:      1000,
		logger:          log.New(os.Stdout, "[P2P] ", log.LstdFlags),
		savedPeers:      make(map[string]*SavedPeer),
		logFile:         logFile,
		groups:          make(map[string]*Group),
		commandHistory:  make([]string, 0, 100),
		maxHistorySize:  100,
		blockedUsers:    make(map[string]bool),
		favorites:       make(map[string]bool),
		endpointMgr:     endpointMgr,
		stats: PeerStats{
			SessionStart: time.Now(),
		},
	}
}

func (pm *PeerManager) InitializeNAT() {
	fmt.Println("[NAT] 🌍 Initializing NAT Traversal...")

	natInfo, err := pm.endpointMgr.RefreshNATInfo()
	if err != nil {
		fmt.Printf("[NAT] ⚠️ STUN query failed: %v\n", err)
		fmt.Println("[NAT] 💡 Switching to manual connection mode...")
		return
	}

	pm.natInfo = natInfo

	if err := pm.endpointMgr.SetupPortMapping(8888); err != nil {
		fmt.Println("[NAT] 💡 UPnP failed, Hole Punching method will be used")
	} else {
		fmt.Println("[NAT] ✓ UPnP port mapping established successfully!")
	}

	pm.PrintNATInfo()
}

func (pm *PeerManager) PrintNATInfo() {
	if pm.natInfo == nil {
		fmt.Println("\n[NAT] ❌ NAT information unavailable\n")
		return
	}

	fmt.Println("\n╔════════════════════════════════════════╗")
	fmt.Println("║         🌍 NAT TRAVERSAL INFO          ║")
	fmt.Println("╚════════════════════════════════════════╝")
	fmt.Printf("Public IP Address:       %s\n", pm.natInfo.PublicIP)
	fmt.Printf("Public Port:             %d\n", pm.natInfo.PublicPort)
	fmt.Printf("Local IP Address:        %s\n", pm.natInfo.LocalIP)
	fmt.Printf("Local Port:              %d\n", pm.natInfo.LocalPort)
	fmt.Printf("NAT Type:                %s\n", pm.natInfo.NATType)
	fmt.Println("════════════════════════════════════════\n")

	fmt.Println("💡 IP ADDRESS TO SHARE WITH OTHERS:")
	fmt.Printf("   %s:%d\n", pm.natInfo.PublicIP, pm.natInfo.PublicPort)
	fmt.Println()
}

func GenerateMessageID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func FormatMessage(msg Message) string {
	switch msg.Type {
	case MSG_SYSTEM:
		return fmt.Sprintf("\033[35m[SYSTEM]\033[0m %s", msg.Content)
	case MSG_PRIVATE:
		return fmt.Sprintf("\033[34m[PRIVATE %s]\033[0m %s", msg.From, msg.Content)
	case MSG_NOTICE:
		return fmt.Sprintf("\033[33m[NOTICE]\033[0m %s", msg.Content)
	default:
		return fmt.Sprintf("\033[33m[%s]\033[0m %s", msg.From, msg.Content)
	}
}

func (pm *PeerManager) AddCommandToHistory(cmd string) {
	pm.commandHistory = append(pm.commandHistory, cmd)
	if len(pm.commandHistory) > pm.maxHistorySize {
		pm.commandHistory = pm.commandHistory[1:]
	}
}

func (pm *PeerManager) BlockUser(ip string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.blockedUsers[ip] = true
	fmt.Printf("\n[System] ✓ %s blocked.\n\n", ip)
}

func (pm *PeerManager) UnblockUser(ip string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.blockedUsers, ip)
	fmt.Printf("\n[System] ✓ %s unblocked.\n\n", ip)
}

func (pm *PeerManager) IsUserBlocked(ip string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.blockedUsers[ip]
}

func (pm *PeerManager) AddFavorite(ip string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.favorites[ip] = true
	fmt.Printf("\n[System] ⭐ %s added to favorites.\n\n", ip)
}

func (pm *PeerManager) RemoveFavorite(ip string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.favorites, ip)
	fmt.Printf("\n[System] ✓ %s removed from favorites.\n\n", ip)
}

func (pm *PeerManager) IsFavorite(ip string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.favorites[ip]
}

func (pm *PeerManager) SetUserStatus(status UserStatus, msg string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.profile.Status = status
	pm.profile.StatusMsg = msg
	pm.profile.LastSeen = time.Now()
}

func (pm *PeerManager) CreateGroup(name string) string {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	id := GenerateMessageID()
	group := &Group{
		ID:        id,
		Name:      name,
		Members:   make(map[string]*PeerInfo),
		CreatedAt: time.Now(),
		Admin:     pm.name,
		IsActive:  true,
	}

	pm.groups[id] = group
	fmt.Printf("\n[System] ✓ Group '%s' created (ID: %s).\n\n", name, id)
	return id
}

func (pm *PeerManager) AddMemberToGroup(groupID, peerIP string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if group, exists := pm.groups[groupID]; exists {
		if info, peerExists := pm.peerInfo[peerIP]; peerExists {
			group.Members[peerIP] = info
			fmt.Printf("\n[System] ✓ %s added to group.\n\n", info.Name)
		}
	}
}

func (pm *PeerManager) PrintAdvancedHelp() {
	fmt.Println("\n╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║          🔒 AND CHAT - ADVANCED COMMAND GUIDE 🔒               ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("🌍 NAT TRAVERSAL COMMANDS:")
	fmt.Println("  /nat-info            → View NAT and public IP information")
	fmt.Println("  /upnp-test           → Test UPnP port mapping")
	fmt.Println("  /hole-punch <IP>     → Attempt connection via Hole Punching")
	fmt.Println()
	fmt.Println("📡 CONNECTION COMMANDS:")
	fmt.Println("  /connect <IP/Name>   → Connect to peer with TLS 1.3")
	fmt.Println("  /list                → List all connected peers")
	fmt.Println("  /disconnect <IP>     → Disconnect from peer")
	fmt.Println("  /connect-all         → Connect to all saved peers")
	fmt.Println("  /disconnect-all      → Disconnect all peers")
	fmt.Println()
	fmt.Println("💾 PEER MANAGEMENT:")
	fmt.Println("  /save <IP> <Name>    → Save peer with name")
	fmt.Println("  /saved               → View saved peers")
	fmt.Println("  /remove <Name/IP>    → Delete saved peer")
	fmt.Println("  /remove-all          → Delete all saved peers")
	fmt.Println("  /star <IP>           → Add/remove from favorites")
	fmt.Println("  /block <IP>          → Block user")
	fmt.Println("  /unblock <IP>        → Unblock user")
	fmt.Println("  /blocked             → View blocked users")
	fmt.Println()
	fmt.Println("👥 GROUP COMMANDS:")
	fmt.Println("  /create-group <Name> → Create new group")
	fmt.Println("  /groups              → View your groups")
	fmt.Println("  /add-member <G> <IP> → Add member to group")
	fmt.Println("  /delete-group <ID>   → Delete group")
	fmt.Println()
	fmt.Println("📨 PRIVATE MESSAGE:")
	fmt.Println("  @<Username> <Message> → Send private message")
	fmt.Println()
	fmt.Println("👤 PROFILE COMMANDS:")
	fmt.Println("  /whoami              → View your information")
	fmt.Println("  /profile <IP>        → View user profile")
	fmt.Println("  /set-status <Msg>    → Set status message")
	fmt.Println()
	fmt.Println("📚 DATA:")
	fmt.Println("  /history             → View message history (last 50)")
	fmt.Println("  /stats               → View detailed statistics")
	fmt.Println()
	fmt.Println("🔐 SECURITY:")
	fmt.Println("  /security            → View security information")
	fmt.Println()
	fmt.Println("⚙️  GENERAL:")
	fmt.Println("  /clear               → Clear screen")
	fmt.Println("  /help                → Show this help message")
	fmt.Println("  /exit                → Exit safely")
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════════\n")
}

func (pm *PeerManager) PrintDetailedStatistics() {
	pm.mu.RLock()
	activePeers := len(pm.peers)
	totalMessages := pm.stats.TotalMessages
	bytesSent := pm.stats.BytesSent
	bytesReceived := pm.stats.BytesReceived
	successNATs := pm.stats.SuccessfulNATs
	failedNATs := pm.stats.FailedNATs
	pm.mu.RUnlock()

	sessionDuration := time.Since(pm.stats.SessionStart)
	avgMsgSize := int64(0)
	if totalMessages > 0 {
		avgMsgSize = (bytesSent + bytesReceived) / int64(totalMessages)
	}

	fmt.Println("\n╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              📊 DETAILED STATISTICS 📊                      ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Printf("Session Start:         %s\n", pm.stats.SessionStart.Format("02.01.2006 15:04:05"))
	fmt.Printf("Session Duration:      %v\n", sessionDuration.Round(time.Second))
	fmt.Printf("Total Messages:        %d\n", totalMessages)
	fmt.Printf("Active Connections:    %d\n", activePeers)
	fmt.Printf("Total Connections:     %d\n", pm.stats.TotalConnections)
	fmt.Printf("Successful NAT Passes:  %d\n", successNATs)
	fmt.Printf("Failed NAT Passes:     %d\n", failedNATs)
	fmt.Printf("Data Sent:             %.2f MB\n", float64(bytesSent)/1024/1024)
	fmt.Printf("Data Received:         %.2f MB\n", float64(bytesReceived)/1024/1024)
	fmt.Printf("Average Message Size:  %d Bytes\n", avgMsgSize)
	fmt.Println("══════════════════════════════════════════════════════════════════\n")
}

func (pm *PeerManager) PrintUserProfile(ip string) {
	pm.mu.RLock()
	info, exists := pm.peerInfo[ip]
	pm.mu.RUnlock()

	if !exists {
		fmt.Printf("\n[System] ❌ %s not found.\n\n", ip)
		return
	}

	fmt.Println("\n╔════════════════════════════════════════╗")
	fmt.Printf("║        👤 %s PROFILE\n", strings.ToUpper(info.Name))
	fmt.Println("╚════════════════════════════════════════╝")
	fmt.Printf("Name:                %s\n", info.Name)
	fmt.Printf("Local IP:            %s\n", info.IP)
	fmt.Printf("Public IP:           %s\n", info.PublicIP)
	fmt.Printf("Public Port:         %d\n", info.PublicPort)
	fmt.Printf("Status:              %s\n", info.Status)
	fmt.Printf("Status Message:      %s\n", info.StatusMsg)
	fmt.Printf("Connection Time:     %s\n", info.ConnectedAt.Format("02.01.2006 15:04:05"))
	fmt.Printf("Last Activity:       %s\n", info.LastActivity.Format("02.01.2006 15:04:05"))
	fmt.Printf("Message Count:       %d\n", info.MessageCount)
	fmt.Println("════════════════════════════════════════\n")
}

func (pm *PeerManager) PrintBlockedUsers() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	fmt.Println("\n=== 🚫 BLOCKED USERS ===")
	if len(pm.blockedUsers) == 0 {
		fmt.Println("No blocked users.")
	} else {
		for ip := range pm.blockedUsers {
			if info, exists := pm.peerInfo[ip]; exists {
				fmt.Printf("  • %s [%s]\n", info.Name, ip)
			} else {
				fmt.Printf("  • %s\n", ip)
			}
		}
	}
	fmt.Println("===================================\n")
}

func (pm *PeerManager) PrintGroups() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	fmt.Println("\n=== 👥 GROUPS ===")
	if len(pm.groups) == 0 {
		fmt.Println("No groups yet.")
	} else {
		for _, group := range pm.groups {
			fmt.Printf("\n📌 %s (ID: %s)\n", group.Name, group.ID)
			fmt.Printf("   Admin: %s\n", group.Admin)
			fmt.Printf("   Members: %d\n", len(group.Members))
		}
	}
	fmt.Println("\n==================\n")
}

func main() {
	clearScreen()
	printBanner()

	fmt.Println("[System] 🔐 Generating E2E cryptographic keys...")
	tlsClientConfig, tlsServerConfig, fingerprint, err := generateTLSConfig()
	if err != nil {
		fmt.Printf("[CRITICAL ERROR] TLS Certificate generation failed: %v\n", err)
		return
	}

	reader := bufio.NewReader(os.Stdin)
	username := getUserInput(reader)

	pm := NewPeerManager(username, tlsClientConfig, tlsServerConfig)
	pm.certFingerprint = fingerprint
	pm.loadSavedPeers()

	fmt.Printf("[System] ✓ Certificate Fingerprint: %s\n", fingerprint)
	fmt.Printf("[System] ✓ Found %d saved peers\n\n", len(pm.savedPeers))

	fmt.Println("[System] 🚀 Starting NAT Traversal (STUN + UPnP + Hole Punching)...")
	pm.InitializeNAT()

	go pm.startTLSListener()
	go pm.handleSystemSignals()

	pm.printWelcomeScreen()
	commandLoop(reader, pm)
}

func commandLoop(reader *bufio.Reader, pm *PeerManager) {
	for {
		fmt.Print("\033[36m" + pm.name + " > \033[0m")
		input, err := reader.ReadString('\n')
		if err != nil {
			continue
		}
		input = sanitizeInput(strings.TrimSpace(input))
		if input == "" {
			continue
		}

		pm.AddCommandToHistory(input)

		if strings.HasPrefix(input, "/") {
			handleCommand(input, pm, reader)
		} else if strings.HasPrefix(input, "@") {
			handlePrivateMessage(input, pm)
		} else {
			pm.broadcastMessage(input)
		}
	}
}

func handlePrivateMessage(input string, pm *PeerManager) {
	parts := strings.SplitN(input, " ", 2)
	if len(parts) < 2 {
		fmt.Println("\n[System] ❌ Usage: @<Username> <Message>\n")
		return
	}

	targetName := strings.TrimPrefix(parts[0], "@")
	content := parts[1]

	pm.mu.RLock()
	var targetIP string
	for ip, info := range pm.peerInfo {
		if strings.ToLower(info.Name) == strings.ToLower(targetName) {
			targetIP = ip
			break
		}
	}
	pm.mu.RUnlock()

	if targetIP == "" {
		fmt.Printf("\n[System] ❌ '%s' not found.\n\n", targetName)
		return
	}

	msg := Message{
		Type:      MSG_PRIVATE,
		From:      pm.name,
		To:        targetName,
		Content:   content,
		Timestamp: time.Now(),
		ID:        GenerateMessageID(),
	}

	pm.mu.Lock()
	conn, exists := pm.peers[targetIP]
	pm.mu.Unlock()

	if !exists {
		fmt.Printf("\n[System] ❌ %s is not connected.\n\n", targetName)
		return
	}

	formatted := fmt.Sprintf("🔒 [PRIVATE] %s: %s\n", pm.name, content)
	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := conn.Write([]byte(formatted))
	conn.SetWriteDeadline(time.Time{})

	if err != nil {
		fmt.Printf("\n[System] ❌ Private message could not be sent.\n\n")
		return
	}

	fmt.Printf("\n✓ Private message sent to: %s\n\n", targetName)
	pm.logMessage(msg)
}

func handleCommand(input string, pm *PeerManager, reader *bufio.Reader) {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return
	}

	cmd := strings.ToLower(parts[0])

	switch cmd {
	case "/nat-info":
		pm.PrintNATInfo()

	case "/upnp-test":
		fmt.Println("\n[System] 🧪 Testing UPnP port mapping...")
		if err := pm.endpointMgr.SetupPortMapping(8888); err != nil {
			fmt.Printf("[System] ❌ UPnP test failed: %v\n\n", err)
		} else {
			fmt.Println("[System] ✓ UPnP port mapping successful!\n")
		}

	case "/hole-punch":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Usage: /hole-punch <IP>\n")
			return
		}
		targetIP := parts[1]
		fmt.Printf("\n[System] 🔨 Initiating hole punching to %s...\n\n", targetIP)
		holePunch := pm.endpointMgr.GetHolePunch()
		if holePunch != nil {
			go holePunch.AttemptPunch(targetIP, 8888)
		}

	case "/connect":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Usage: /connect <IP or Saved Name>\n")
			return
		}
		targetStr := parts[1]
		targetIP := resolvePeerName(pm, targetStr)
		if targetIP == "" {
			fmt.Printf("\n[System] ❌ '%s' not found.\n\n", targetStr)
			return
		}
		if !isValidIP(targetIP) {
			fmt.Printf("\n[System] ❌ Invalid IP address: %s\n\n", targetIP)
			return
		}
		fmt.Printf("\n[System] 🔒 Opening tunnel to %s...\n", targetIP)
		go pm.connectToPeer(targetIP)

	case "/connect-all":
		fmt.Println("\n[System] 🔒 Connecting to all saved peers...")
		pm.mu.RLock()
		peers := make(map[string]*SavedPeer)
		for k, v := range pm.savedPeers {
			peers[k] = v
		}
		pm.mu.RUnlock()
		for _, peer := range peers {
			if !peer.Blocked {
				go pm.connectToPeer(peer.IP)
			}
		}

	case "/disconnect-all":
		pm.disconnectAllPeers()

	case "/star":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Usage: /star <IP>\n")
			return
		}
		ip := parts[1]
		if pm.IsFavorite(ip) {
			pm.RemoveFavorite(ip)
		} else {
			pm.AddFavorite(ip)
		}

	case "/block":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Usage: /block <IP>\n")
			return
		}
		pm.BlockUser(parts[1])

	case "/unblock":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Usage: /unblock <IP>\n")
			return
		}
		pm.UnblockUser(parts[1])

	case "/blocked":
		pm.PrintBlockedUsers()

	case "/create-group":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Usage: /create-group <Group Name>\n")
			return
		}
		groupName := strings.Join(parts[1:], " ")
		pm.CreateGroup(groupName)

	case "/groups":
		pm.PrintGroups()

	case "/add-member":
		if len(parts) < 3 {
			fmt.Println("\n[System] ❌ Usage: /add-member <GroupID> <IP>\n")
			return
		}
		pm.AddMemberToGroup(parts[1], parts[2])

	case "/profile":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Usage: /profile <IP>\n")
			return
		}
		pm.PrintUserProfile(parts[1])

	case "/set-status":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Usage: /set-status <Status Message>\n")
			return
		}
		statusMsg := strings.Join(parts[1:], " ")
		pm.SetUserStatus(STATUS_ONLINE, statusMsg)
		fmt.Printf("\n[System] ✓ Status message updated: %s\n\n", statusMsg)

	case "/stats":
		pm.PrintDetailedStatistics()

	case "/list":
		pm.printPeerList()

	case "/help":
		pm.PrintAdvancedHelp()

	case "/whoami":
		fmt.Printf("\n[System] 👤 Your name: %s\n", pm.name)
		fmt.Printf("[System] 🔐 Fingerprint: %s\n", pm.certFingerprint)
		if pm.natInfo != nil {
			fmt.Printf("[System] 🌍 Public IP: %s:%d\n", pm.natInfo.PublicIP, pm.natInfo.PublicPort)
		}
		fmt.Printf("[System] 📍 Status: %s\n", pm.profile.Status)
		fmt.Printf("[System] 💬 Status Message: %s\n\n", pm.profile.StatusMsg)

	case "/disconnect":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Usage: /disconnect <IP>\n")
			return
		}
		pm.disconnectPeer(parts[1])

	case "/history":
		pm.printMessageLog()

	case "/clear":
		clearScreen()

	case "/save":
		if len(parts) < 3 {
			fmt.Println("\n[System] ❌ Usage: /save <IP> <Name>\n")
			return
		}
		pm.savePeer(parts[1], strings.Join(parts[2:], " "))

	case "/saved":
		pm.printSavedPeers()

	case "/remove":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Usage: /remove <IP or Name>\n")
			return
		}
		pm.deleteSavedPeer(parts[1])

	case "/remove-all":
		fmt.Print("[Warning] Delete all saved peers? (y/n): ")
		confirm, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(confirm)) == "y" {
			pm.deleteAllSavedPeers()
		}

	case "/local-ip":
		pm.printLocalIP()

	case "/port":
		fmt.Printf("\n[System] 📡 Listening Port: %s\n\n", chatPort)

	case "/security":
		pm.printSecurityInfo()

	case "/exit":
		pm.closeAllConnections()
		fmt.Println("\n[System] 🛑 Exited safely. Goodbye!")
		os.Exit(0)

	default:
		fmt.Printf("\n[System] ❌ Unknown command: %s\n", cmd)
		fmt.Println("[System] Type /help for available commands.\n")
	}
}

func resolvePeerName(pm *PeerManager, target string) string {
	if isValidIP(target) {
		return target
	}
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	for name, peer := range pm.savedPeers {
		if strings.ToLower(name) == strings.ToLower(target) {
			return peer.IP
		}
	}
	return ""
}

func (pm *PeerManager) savePeer(ip, name string) {
	if !isValidIP(ip) {
		fmt.Printf("\n[System] ❌ Invalid IP: %s\n\n", ip)
		return
	}

	pm.mu.Lock()
	pm.savedPeers[strings.ToLower(name)] = &SavedPeer{
		IP:      ip,
		Name:    name,
		SavedAt: time.Now(),
	}
	pm.mu.Unlock()

	pm.writeSavedPeers()
	fmt.Printf("\n[System] ✓ '%s' -> %s saved.\n\n", name, ip)
}

func (pm *PeerManager) deleteSavedPeer(target string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for key, peer := range pm.savedPeers {
		if key == strings.ToLower(target) || peer.IP == target {
			delete(pm.savedPeers, key)
			fmt.Printf("\n[System] ✓ '%s' deleted.\n\n", key)
			pm.writeSavedPeers()
			return
		}
	}

	fmt.Printf("\n[System] ❌ '%s' not found.\n\n", target)
}

func (pm *PeerManager) deleteAllSavedPeers() {
	pm.mu.Lock()
	pm.savedPeers = make(map[string]*SavedPeer)
	pm.mu.Unlock()

	os.Remove(configFile)
	fmt.Println("\n[System] ✓ All saved peers deleted.\n")
}

func (pm *PeerManager) loadSavedPeers() {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "=")
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			ip := strings.TrimSpace(parts[1])
			pm.savedPeers[strings.ToLower(name)] = &SavedPeer{
				IP:   ip,
				Name: name,
			}
		}
	}
}

func (pm *PeerManager) writeSavedPeers() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var lines []string
	for name, peer := range pm.savedPeers {
		lines = append(lines, fmt.Sprintf("%s=%s", name, peer.IP))
	}

	sort.Strings(lines)
	content := strings.Join(lines, "\n")
	os.WriteFile(configFile, []byte(content), 0644)
}

func (pm *PeerManager) printSavedPeers() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	fmt.Println("\n=== 📚 SAVED PEERS ===")
	if len(pm.savedPeers) == 0 {
		fmt.Println("No saved peers yet.")
	} else {
		var names []string
		for name := range pm.savedPeers {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			peer := pm.savedPeers[name]
			status := "🔴 Offline"

			pm.mu.RUnlock()
			pm.mu.RLock()
			if _, connected := pm.peers[peer.IP]; connected {
				status = "🟢 Online"
			}

			marker := " "
			if pm.favorites[peer.IP] {
				marker = "⭐"
			}

			fmt.Printf("  %s %s [%s] %s\n", marker, strings.Title(name), peer.IP, status)
		}
	}
	fmt.Println("===========================\n")
}

func (pm *PeerManager) printPeerList() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	fmt.Println("\n=== 🔐 CONNECTED PEERS ===")

	if len(pm.peers) == 0 {
		fmt.Println("No active connections.")
	} else {
		fmt.Printf("%-15s %-20s %-15s %-12s %-8s\n", "IP", "Name", "Connected", "Last Activity", "Messages")
		fmt.Println(strings.Repeat("-", 75))

		for ip, info := range pm.peerInfo {
			if _, exists := pm.peers[ip]; exists {
				connTime := info.ConnectedAt.Format("15:04")
				lastActivity := info.LastActivity.Format("15:04")
				fmt.Printf("%-15s %-20s %-15s %-12s %-8d\n", ip, info.Name, connTime, lastActivity, info.MessageCount)
			}
		}
	}
	fmt.Println("============================\n")
}

func (pm *PeerManager) printMessageLog() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	fmt.Println("\n=== 📋 MESSAGE HISTORY (Last 50) ===")
	if len(pm.messageLog) == 0 {
		fmt.Println("No messages yet.")
	} else {
		start := len(pm.messageLog) - 50
		if start < 0 {
			start = 0
		}
		for _, msg := range pm.messageLog[start:] {
			fmt.Printf("[%s] %s\n", msg.Timestamp.Format("15:04:05"), FormatMessage(msg))
		}
	}
	fmt.Println("==================================\n")
}

func (pm *PeerManager) printLocalIP() {
	fmt.Println("\n=== 🖥️ NETWORK INFORMATION ===")

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Failed to retrieve network information.")
		fmt.Println("===========================\n")
		return
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				fmt.Printf("  • %s: %s\n", iface.Name, ipnet.IP)
			}
		}
	}

	fmt.Println("\n💡 TIPS:")
	fmt.Println("  - Use /nat-info to learn your public IP")
	fmt.Println("  - Share your PUBLIC IP with others")
	fmt.Println("  - Port forwarding is required for internet connections")
	fmt.Println("===========================\n")
}

func (pm *PeerManager) printSecurityInfo() {
	fmt.Println("\n=== 🔒 SECURITY INFORMATION ===")
	fmt.Println("Encryption Standard: TLS 1.3")
	fmt.Println("Key Type: ECDSA P-256")
	fmt.Println("E2E Encrypted: ✅ Yes")
	fmt.Println()
	fmt.Printf("📌 Certificate Fingerprint: %s\n", pm.certFingerprint)
	fmt.Println()
	fmt.Println("💡 SECURITY RECOMMENDATIONS:")
	fmt.Println("  1. Compare fingerprints on first connection")
	fmt.Println("  2. Only connect to trusted IPs")
	fmt.Println("  3. Share NAT information only with trusted contacts")
	fmt.Println("  4. Check your firewall if Hole Punching fails")
	fmt.Println("=============================\n")
}

func (pm *PeerManager) connectToPeer(ip string) {
	if pm.IsUserBlocked(ip) {
		fmt.Printf("\n[System] ❌ %s is blocked.\n\n", ip)
		return
	}

	target := fmt.Sprintf("%s%s", ip, chatPort)

	pm.mu.RLock()
	if _, exists := pm.peers[ip]; exists {
		pm.mu.RUnlock()
		fmt.Printf("\n[System] ⚠️ Already connected to %s.\n\n", ip)
		pm.refreshPrompt()
		return
	}
	pm.mu.RUnlock()

	dialer := &net.Dialer{Timeout: 7 * time.Second}
	tlsConn, err := tls.DialWithDialer(dialer, "tcp", target, pm.tlsConfig)
	if err != nil {
		fmt.Printf("\n[System] ❌ Cannot connect to %s.\n", ip)
		fmt.Printf("[System] 💡 Attempting Hole Punching...\n")

		holePunch := pm.endpointMgr.GetHolePunch()
		if holePunch != nil {
			go holePunch.AttemptPunch(ip, 8888)
		}

		pm.stats.FailedNATs++
		pm.refreshPrompt()
		return
	}

	if !verifyTLSState(tlsConn) {
		tlsConn.Close()
		fmt.Printf("\n[System] ❌ TLS verification failed: %s\n\n", ip)
		pm.refreshPrompt()
		return
	}

	_, _ = tlsConn.Write([]byte(pm.name + ":CONNECT\n"))

	pm.registerPeer(ip, "", tlsConn)
	pm.stats.TotalConnections++
	pm.stats.SuccessfulNATs++
	go pm.handleConnection(tlsConn, ip)
}

func (pm *PeerManager) disconnectAllPeers() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for ip, conn := range pm.peers {
		conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, _ = conn.Write([]byte("[System] Disconnecting all peers.\n"))
		conn.SetWriteDeadline(time.Time{})
		conn.Close()
		delete(pm.peers, ip)
	}

	fmt.Println("\n[System] ✓ All connections closed.\n")
}

func (pm *PeerManager) disconnectPeer(ip string) {
	pm.mu.Lock()
	conn, exists := pm.peers[ip]
	if !exists {
		pm.mu.Unlock()
		fmt.Printf("\n[System] ❌ No active connection to %s.\n\n", ip)
		return
	}
	delete(pm.peers, ip)
	pm.mu.Unlock()

	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, _ = conn.Write([]byte("[System] Connection terminated.\n"))
	conn.SetWriteDeadline(time.Time{})
	conn.Close()

	fmt.Printf("\n[System] ✓ Connection to %s closed.\n\n", ip)
}

func (pm *PeerManager) broadcastMessage(text string) {
	if len(text) > maxMessageLength {
		fmt.Printf("\n[System] ❌ Message too long (max %d characters).\n\n", maxMessageLength)
		return
	}

	pm.mu.RLock()
	peers := make(map[string]net.Conn)
	for ip, conn := range pm.peers {
		peers[ip] = conn
	}
	pm.mu.RUnlock()

	msg := Message{
		Type:      MSG_NORMAL,
		From:      pm.name,
		Content:   text,
		Timestamp: time.Now(),
		ID:        GenerateMessageID(),
	}

	formattedMessage := fmt.Sprintf("\033[33m[%s]:\033[0m %s\n", pm.name, text)
	failedPeers := []string{}

	for ip, conn := range peers {
		conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, err := conn.Write([]byte(formattedMessage))
		conn.SetWriteDeadline(time.Time{})

		if err == nil {
			pm.stats.BytesSent += int64(len(formattedMessage))
		} else {
			failedPeers = append(failedPeers, ip)
		}
	}

	pm.stats.TotalMessages++
	pm.logMessage(msg)
	pm.writeToLogFile(fmt.Sprintf("%s [%s]: %s", time.Now().Format("15:04:05"), pm.name, text))

	if len(failedPeers) > 0 {
		pm.mu.Lock()
		for _, ip := range failedPeers {
			if conn, exists := pm.peers[ip]; exists {
				conn.Close()
				delete(pm.peers, ip)
			}
		}
		pm.mu.Unlock()
	}
}

func (pm *PeerManager) logMessage(msg Message) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.messageLog = append(pm.messageLog, msg)

	if len(pm.messageLog) > pm.maxLogSize {
		pm.messageLog = pm.messageLog[1:]
	}
}

func (pm *PeerManager) writeToLogFile(msg string) {
	if pm.logFile != nil {
		fmt.Fprintln(pm.logFile, msg)
	}
}

func (pm *PeerManager) startTLSListener() {
	listener, err := tls.Listen("tcp", chatPort, pm.tlsServerConfig)
	if err != nil {
		fmt.Printf("\n[CRITICAL ERROR] TLS listener startup failed: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("[System] ✓ Listener started (Port: %s)\n\n", chatPort)

	for {
		select {
		case <-pm.shutdown:
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		ip := strings.Split(conn.RemoteAddr().String(), ":")[0]
		go pm.handleConnection(conn, ip)
	}
}

func (pm *PeerManager) handleConnection(conn net.Conn, ip string) {
	if pm.IsUserBlocked(ip) {
		conn.Close()
		return
	}

	peerDone := make(chan struct{})
	go pm.startKeepAlive(conn, ip, peerDone)

	defer func() {
		close(peerDone)
		conn.Close()
		pm.mu.Lock()
		peerName := ""
		if info, exists := pm.peerInfo[ip]; exists {
			peerName = info.Name
			delete(pm.peerInfo, ip)
		}
		delete(pm.peers, ip)
		pm.mu.Unlock()

		if peerName != "" {
			fmt.Printf("\n\033[31m[System] 🔌 %s (%s) disconnected.\033[0m\n\n", peerName, ip)
		} else {
			fmt.Printf("\n\033[31m[System] 🔌 Connection from %s lost.\033[0m\n\n", ip)
		}
		pm.refreshPrompt()
	}()

	conn.SetReadDeadline(time.Now().Add(readTimeout))
	reader := bufio.NewReader(conn)

	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		conn.SetReadDeadline(time.Now().Add(readTimeout))
		message = sanitizeInput(strings.TrimSpace(message))

		if message == "" {
			continue
		}

		pm.stats.BytesReceived += int64(len(message))

		if message == ":PING" {
			conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			_, _ = conn.Write([]byte(":PONG\n"))
			conn.SetWriteDeadline(time.Time{})
			continue
		}
		if message == ":PONG" {
			pm.updatePeerActivity(ip)
			continue
		}

		if strings.HasSuffix(message, ":CONNECT") {
			remoteName := strings.TrimSuffix(message, ":CONNECT")
			pm.registerPeer(ip, remoteName, conn)

			conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			_, _ = conn.Write([]byte(pm.name + ":ACK\n"))
			conn.SetWriteDeadline(time.Time{})

			fmt.Printf("\n\033[32m[System] 🔐 E2E Encrypted Tunnel Established with %s (%s)!\033[0m\n\n", remoteName, ip)
			pm.refreshPrompt()
			continue
		}

		if strings.HasSuffix(message, ":ACK") {
			remoteName := strings.TrimSuffix(message, ":ACK")
			pm.registerPeer(ip, remoteName, conn)
			fmt.Printf("\n\033[32m[System] 🔐 %s (%s) confirmed encrypted tunnel!\033[0m\n\n", remoteName, ip)
			pm.refreshPrompt()
			continue
		}

		pm.updatePeerActivity(ip)

		pm.mu.Lock()
		if info, exists := pm.peerInfo[ip]; exists {
			info.MessageCount++
		}
		pm.mu.Unlock()

		pm.stats.TotalMessages++

		fmt.Printf("\n%s\n\n", message)
		pm.writeToLogFile(fmt.Sprintf("%s [%s]: %s", time.Now().Format("15:04:05"), ip, message))
		pm.refreshPrompt()
	}
}

func (pm *PeerManager) startKeepAlive(conn net.Conn, ip string, done chan struct{}) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pm.mu.RLock()
			_, exists := pm.peers[ip]
			pm.mu.RUnlock()

			if !exists {
				return
			}

			conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			_, err := conn.Write([]byte(":PING\n"))
			conn.SetWriteDeadline(time.Time{})

			if err != nil {
				return
			}

		case <-done:
			return

		case <-pm.shutdown:
			return
		}
	}
}

func (pm *PeerManager) updatePeerActivity(ip string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if info, exists := pm.peerInfo[ip]; exists {
		info.LastActivity = time.Now()
		info.Status = STATUS_ONLINE
	}
}

func (pm *PeerManager) registerPeer(ip, name string, conn net.Conn) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.peers[ip] = conn

	if info, exists := pm.peerInfo[ip]; exists {
		if name != "" {
			info.Name = name
		}
	} else {
		publicIP := ""
		publicPort := 0
		if pm.natInfo != nil {
			publicIP = pm.natInfo.PublicIP
			publicPort = pm.natInfo.PublicPort
		}

		pm.peerInfo[ip] = &PeerInfo{
			IP:           ip,
			Name:         name,
			ConnectedAt:  time.Now(),
			LastActivity: time.Now(),
			Status:       STATUS_ONLINE,
			StatusMsg:    "Active",
			MessageCount: 0,
			PublicIP:     publicIP,
			PublicPort:   publicPort,
		}
	}
}

func (pm *PeerManager) handleSystemSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	pm.closeAllConnections()
	fmt.Println("\n\n[System] 🛑 Shutdown signal received. All tunnels closed securely.")
	if pm.logFile != nil {
		pm.logFile.Close()
	}
	os.Exit(0)
}

func (pm *PeerManager) closeAllConnections() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	close(pm.shutdown)
	for ip, conn := range pm.peers {
		conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, _ = conn.Write([]byte("[System] " + pm.name + " ended chat.\n"))
		conn.SetWriteDeadline(time.Time{})
		conn.Close()
		delete(pm.peers, ip)
	}
}

func (pm *PeerManager) printWelcomeScreen() {
	fmt.Println("\n--------------------------------------------------")
	fmt.Printf("🚀 Secure Layer Active! Connected as \033[32m%s\033[0m.\n", pm.name)
	fmt.Println("--------------------------------------------------")
	fmt.Println("📌 QUICK COMMANDS:")
	fmt.Println("  /nat-info     → View public IP and NAT information")
	fmt.Println("  /connect <IP> → Connect to peer")
	fmt.Println("  /saved        → View saved peers")
	fmt.Println("  /list         → View connected peers")
	fmt.Println("  /help         → Show all commands")
	fmt.Println("--------------------------------------------------\n")
}

func getUserInput(reader *bufio.Reader) string {
	for {
		fmt.Print("👉 Enter your chat name (max 32 characters): ")
		input, _ := reader.ReadString('\n')
		username := sanitizeInput(strings.TrimSpace(input))

		if username == "" {
			fmt.Println("[!] Username cannot be empty.")
			continue
		}

		if len(username) > maxUsernameLength {
			fmt.Printf("[!] Username too long (max %d characters).\n", maxUsernameLength)
			continue
		}

		if !isValidUsername(username) {
			fmt.Println("[!] Username can only contain alphanumeric characters, underscore, and hyphen.")
			continue
		}

		return username
	}
}

func isValidUsername(username string) bool {
	pattern := `^[a-zA-Z0-9_\-]{1,32}$`
	matched, _ := regexp.MatchString(pattern, username)
	return matched
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func verifyTLSState(conn *tls.Conn) bool {
	state := conn.ConnectionState()
	return state.Version >= tls.VersionTLS13
}

func sanitizeInput(in string) string {
	r := strings.NewReplacer(
		"\x1b", "",
		"\033", "",
		"\r", "",
		"\x00", "",
	)
	return r.Replace(in)
}

func generateTLSConfig() (*tls.Config, *tls.Config, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"AND Bilisim P2P"},
			CommonName:   "p2p-chat-node",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * time.Duration(tlsCertValidityDays)),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, "", err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	cert, err := tls.X509KeyPair(certPEM, privPEM)
	if err != nil {
		return nil, nil, "", err
	}

	fingerprint := calculateFingerprint(derBytes)

	tlsClientConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		NextProtos:         []string{"p2p-chat-v1"},
	}

	tlsServerConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"p2p-chat-v1"},
	}

	return tlsClientConfig, tlsServerConfig, fingerprint, nil
}

func calculateFingerprint(certDER []byte) string {
	hash := sha256.Sum256(certDER)
	return hex.EncodeToString(hash[:16])
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func printBanner() {
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║                            AND CHAT                        ║")
	fmt.Println("║     End-to-End Encrypted - Server-Free - NAT Traversal     ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
}

func (pm *PeerManager) refreshPrompt() {
	fmt.Printf("\033[36m" + pm.name + " > \033[0m")
}
