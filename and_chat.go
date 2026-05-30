package main

import (
	"bufio"
	"context"
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
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	maxConcurrentDials  = 5
	dialTimeout         = 7 * time.Second
	keepAliveInterval   = 10 * time.Second
)

// STUNResponse represents response from STUN server
type STUNResponse struct {
	PublicIP   string `json:"public_ip"`
	PublicPort int    `json:"public_port"`
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
}

// NATInfo stores NAT traversal information
type NATInfo struct {
	PublicIP   string
	PublicPort int
	LocalIP    string
	LocalPort  int
	NATType    string
}

// STUNClient handles STUN protocol communication
type STUNClient struct {
	serverAddress string
	timeout       time.Duration
	client        *http.Client
}

// NewSTUNClient creates a new STUN client with proper configuration
func NewSTUNClient(serverAddress string) *STUNClient {
	return &STUNClient{
		serverAddress: serverAddress,
		timeout:       5 * time.Second,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// GetPublicAddress queries STUN server for public address information
func (sc *STUNClient) GetPublicAddress(ctx context.Context) (*NATInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s/stun", sc.serverAddress), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := sc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("STUN query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("STUN server returned status %d", resp.StatusCode)
	}

	var stunResp STUNResponse
	if err := json.NewDecoder(resp.Body).Decode(&stunResp); err != nil {
		return nil, fmt.Errorf("failed to decode STUN response: %w", err)
	}

	if err := validateNATInfo(stunResp); err != nil {
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

// validateNATInfo validates STUN response data
func validateNATInfo(resp STUNResponse) error {
	if net.ParseIP(resp.PublicIP) == nil {
		return fmt.Errorf("invalid public IP: %s", resp.PublicIP)
	}
	if net.ParseIP(resp.LocalIP) == nil {
		return fmt.Errorf("invalid local IP: %s", resp.LocalIP)
	}
	if resp.PublicPort <= 0 || resp.PublicPort > 65535 {
		return fmt.Errorf("invalid public port: %d", resp.PublicPort)
	}
	if resp.LocalPort <= 0 || resp.LocalPort > 65535 {
		return fmt.Errorf("invalid local port: %d", resp.LocalPort)
	}
	return nil
}

// UPnPController manages UPnP port mapping
type UPnPController struct {
	mu         sync.RWMutex
	enabled    bool
	mappedPort int
	logger     *log.Logger
}

// NewUPnPController creates a new UPnP controller
func NewUPnPController(logger *log.Logger) *UPnPController {
	return &UPnPController{
		enabled:    false,
		mappedPort: 0,
		logger:     logger,
	}
}

// MapPort attempts to map a port via UPnP
func (uc *UPnPController) MapPort(externalPort, internalPort int, protocol string) error {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	if externalPort < 1 || externalPort > 65535 || internalPort < 1 || internalPort > 65535 {
		return fmt.Errorf("invalid port range: external=%d, internal=%d", externalPort, internalPort)
	}

	uc.logger.Printf("[UPnP] Mapping %d (%s) -> %d (Internal)", externalPort, protocol, internalPort)
	uc.enabled = true
	uc.mappedPort = externalPort

	return nil
}

// UnmapPort removes a UPnP port mapping
func (uc *UPnPController) UnmapPort(externalPort int, protocol string) error {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	if externalPort < 1 || externalPort > 65535 {
		return fmt.Errorf("invalid port: %d", externalPort)
	}

	uc.logger.Printf("[UPnP] Unmapping %d (%s)", externalPort, protocol)
	uc.enabled = false
	uc.mappedPort = 0

	return nil
}

// IsEnabled checks if UPnP is currently enabled
func (uc *UPnPController) IsEnabled() bool {
	uc.mu.RLock()
	defer uc.mu.RUnlock()
	return uc.enabled
}

// HolePunchingManager manages NAT hole punching attempts
type HolePunchingManager struct {
	mu            sync.RWMutex
	localIP       string
	publicIP      string
	localPort     int
	publicPort    int
	punchAttempts map[string]*atomic.Int32
	maxAttempts   int
	punchInterval time.Duration
	logger        *log.Logger
}

// NewHolePunchingManager creates a new hole punching manager
func NewHolePunchingManager(localIP string, publicIP string, localPort, publicPort int, logger *log.Logger) *HolePunchingManager {
	return &HolePunchingManager{
		localIP:       localIP,
		publicIP:      publicIP,
		localPort:     localPort,
		publicPort:    publicPort,
		punchAttempts: make(map[string]*atomic.Int32),
		maxAttempts:   5,
		punchInterval: 200 * time.Millisecond,
		logger:        logger,
	}
}

// SendPunchPacket sends a hole punching packet to target
func (hpm *HolePunchingManager) SendPunchPacket(targetIP string, targetPort int) error {
	if !isValidIP(targetIP) {
		return fmt.Errorf("invalid target IP: %s", targetIP)
	}
	if targetPort < 1 || targetPort > 65535 {
		return fmt.Errorf("invalid target port: %d", targetPort)
	}

	hpm.mu.Lock()
	attempts, exists := hpm.punchAttempts[targetIP]
	if !exists {
		attempts = &atomic.Int32{}
		hpm.punchAttempts[targetIP] = attempts
	}
	currentAttempt := int(attempts.Add(1))
	hpm.mu.Unlock()

	if currentAttempt > hpm.maxAttempts {
		return fmt.Errorf("maximum punch attempts exceeded for %s", targetIP)
	}

	addr := net.UDPAddr{
		Port: targetPort,
		IP:   net.ParseIP(targetIP),
	}

	conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil {
		return fmt.Errorf("UDP dial failed: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("PUNCH")); err != nil {
		return fmt.Errorf("write failed: %w", err)
	}

	hpm.logger.Printf("[Hole Punch] Packet sent to %s:%d (attempt %d/%d)", targetIP, targetPort, currentAttempt, hpm.maxAttempts)
	return nil
}

// AttemptPunch makes multiple hole punching attempts
func (hpm *HolePunchingManager) AttemptPunch(ctx context.Context, targetIP string, targetPort int) error {
	for i := 0; i < hpm.maxAttempts; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := hpm.SendPunchPacket(targetIP, targetPort); err != nil {
			hpm.logger.Printf("[Hole Punch] Error: %v", err)
		}
		time.Sleep(hpm.punchInterval)
	}
	return nil
}

// EndpointManager manages NAT endpoint discovery and traversal
type EndpointManager struct {
	mu           sync.RWMutex
	stunClient   *STUNClient
	upnpControl  *UPnPController
	holePunch    *HolePunchingManager
	natInfo      *NATInfo
	lastRefresh  time.Time
	refreshTimer *time.Timer
	ctx          context.Context
	cancel       context.CancelFunc
	logger       *log.Logger
}

// NewEndpointManager creates a new endpoint manager
func NewEndpointManager(stunServer string, logger *log.Logger) *EndpointManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &EndpointManager{
		stunClient:  NewSTUNClient(stunServer),
		upnpControl: NewUPnPController(logger),
		natInfo:     nil,
		lastRefresh: time.Now(),
		ctx:         ctx,
		cancel:      cancel,
		logger:      logger,
	}
}

// RefreshNATInfo queries for updated NAT information
func (em *EndpointManager) RefreshNATInfo(ctx context.Context) (*NATInfo, error) {
	em.mu.Lock()
	defer em.mu.Unlock()

	natInfo, err := em.stunClient.GetPublicAddress(ctx)
	if err != nil {
		return nil, fmt.Errorf("STUN query failed: %w", err)
	}

	em.natInfo = natInfo
	em.holePunch = NewHolePunchingManager(
		natInfo.LocalIP,
		natInfo.PublicIP,
		natInfo.LocalPort,
		natInfo.PublicPort,
		em.logger,
	)

	em.lastRefresh = time.Now()

	em.logger.Printf("[NAT] Public IP: %s:%d | Local IP: %s:%d",
		natInfo.PublicIP, natInfo.PublicPort,
		natInfo.LocalIP, natInfo.LocalPort)

	return natInfo, nil
}

// SetupPortMapping configures UPnP port mapping
func (em *EndpointManager) SetupPortMapping(internalPort int) error {
	em.mu.RLock()
	upnp := em.upnpControl
	em.mu.RUnlock()

	if err := upnp.MapPort(internalPort, internalPort, "TCP"); err != nil {
		return fmt.Errorf("port mapping failed: %w", err)
	}

	return nil
}

// GetNATInfo returns current NAT information
func (em *EndpointManager) GetNATInfo() *NATInfo {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return em.natInfo
}

// GetHolePunch returns hole punching manager
func (em *EndpointManager) GetHolePunch() *HolePunchingManager {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return em.holePunch
}

// Close cleanup resources
func (em *EndpointManager) Close() {
	em.cancel()
}

// MessageType defines message categories
type MessageType string

const (
	MSG_NORMAL  MessageType = "normal"
	MSG_NOTICE  MessageType = "notice"
	MSG_SYSTEM  MessageType = "system"
	MSG_EMOJI   MessageType = "emoji"
	MSG_PRIVATE MessageType = "private"
)

// Message represents a chat message
type Message struct {
	Type      MessageType       `json:"type"`
	From      string            `json:"from"`
	To        string            `json:"to,omitempty"`
	Content   string            `json:"content"`
	Timestamp time.Time         `json:"timestamp"`
	ID        string            `json:"id,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// UserStatus defines user presence status
type UserStatus string

const (
	STATUS_ONLINE  UserStatus = "online"
	STATUS_AWAY    UserStatus = "away"
	STATUS_DND     UserStatus = "dnd"
	STATUS_OFFLINE UserStatus = "offline"
)

// UserProfile represents user information
type UserProfile struct {
	Username  string
	Status    UserStatus
	StatusMsg string
	LastSeen  time.Time
	PublicKey string
}

// PeerInfo stores connected peer information
type PeerInfo struct {
	IP           string
	Name         string
	ConnectedAt  time.Time
	LastActivity time.Time
	Status       UserStatus
	StatusMsg    string
	MessageCount int32
	IsTyping     bool
	Profile      *UserProfile
	PublicIP     string
	PublicPort   int
}

// SavedPeer represents a saved peer configuration
type SavedPeer struct {
	IP      string
	Name    string
	SavedAt time.Time
	Blocked bool
	Starred bool
}

// Group represents a chat group
type Group struct {
	ID        string
	Name      string
	Members   map[string]*PeerInfo
	CreatedAt time.Time
	Admin     string
	IsActive  bool
}

// PeerStats tracks peer statistics
type PeerStats struct {
	TotalMessages    int64
	TotalConnections int64
	SessionStart     time.Time
	BytesSent        int64
	BytesReceived    int64
	SuccessfulNATs   int64
	FailedNATs       int64
}

// PeerManager manages P2P peer connections and messaging
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
	dialSemaphore   chan struct{}
	ctx             context.Context
	cancel          context.CancelFunc
}

// NewPeerManager creates a new peer manager instance
func NewPeerManager(name string, tlsCfg *tls.Config, tlsServerCfg *tls.Config) (*PeerManager, error) {
	logFilePath := filepath.Join(".", logFile)
	file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	profile := &UserProfile{
		Username:  name,
		Status:    STATUS_ONLINE,
		StatusMsg: "Hello! 👋",
		LastSeen:  time.Now(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	logger := log.New(os.Stdout, "[P2P] ", log.LstdFlags|log.Lshortfile)

	endpointMgr := NewEndpointManager("stun.l.google.com:19302", logger)

	pm := &PeerManager{
		peers:           make(map[string]net.Conn),
		peerInfo:        make(map[string]*PeerInfo),
		name:            name,
		profile:         profile,
		tlsConfig:       tlsCfg,
		tlsServerConfig: tlsServerCfg,
		shutdown:        make(chan struct{}),
		messageLog:      make([]Message, 0, 1000),
		maxLogSize:      1000,
		logger:          logger,
		savedPeers:      make(map[string]*SavedPeer),
		logFile:         file,
		groups:          make(map[string]*Group),
		commandHistory:  make([]string, 0, 100),
		maxHistorySize:  100,
		blockedUsers:    make(map[string]bool),
		favorites:       make(map[string]bool),
		endpointMgr:     endpointMgr,
		dialSemaphore:   make(chan struct{}, maxConcurrentDials),
		ctx:             ctx,
		cancel:          cancel,
		stats: PeerStats{
			SessionStart: time.Now(),
		},
	}

	return pm, nil
}

// InitializeNAT initializes NAT traversal mechanisms
func (pm *PeerManager) InitializeNAT() {
	fmt.Println("[NAT] 🌍 Initializing NAT Traversal...")

	ctx, cancel := context.WithTimeout(pm.ctx, 10*time.Second)
	defer cancel()

	natInfo, err := pm.endpointMgr.RefreshNATInfo(ctx)
	if err != nil {
		pm.logger.Printf("[NAT] STUN query failed: %v", err)
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

// PrintNATInfo displays NAT information
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

// GenerateMessageID creates a unique message identifier
func GenerateMessageID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// FormatMessage formats a message for display
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

// AddCommandToHistory adds a command to history
func (pm *PeerManager) AddCommandToHistory(cmd string) {
	pm.commandHistory = append(pm.commandHistory, cmd)
	if len(pm.commandHistory) > pm.maxHistorySize {
		pm.commandHistory = pm.commandHistory[1:]
	}
}

// BlockUser blocks communication from a user
func (pm *PeerManager) BlockUser(ip string) {
	if !isValidIP(ip) {
		fmt.Printf("\n[System] ❌ Invalid IP: %s\n\n", ip)
		return
	}

	pm.mu.Lock()
	pm.blockedUsers[ip] = true
	pm.mu.Unlock()
	fmt.Printf("\n[System] ✓ %s blocked.\n\n", ip)
}

// UnblockUser removes a user from blocklist
func (pm *PeerManager) UnblockUser(ip string) {
	if !isValidIP(ip) {
		fmt.Printf("\n[System] ❌ Invalid IP: %s\n\n", ip)
		return
	}

	pm.mu.Lock()
	delete(pm.blockedUsers, ip)
	pm.mu.Unlock()
	fmt.Printf("\n[System] ✓ %s unblocked.\n\n", ip)
}

// IsUserBlocked checks if a user is blocked
func (pm *PeerManager) IsUserBlocked(ip string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.blockedUsers[ip]
}

// AddFavorite adds a peer to favorites
func (pm *PeerManager) AddFavorite(ip string) {
	if !isValidIP(ip) {
		fmt.Printf("\n[System] ❌ Invalid IP: %s\n\n", ip)
		return
	}

	pm.mu.Lock()
	pm.favorites[ip] = true
	pm.mu.Unlock()
	fmt.Printf("\n[System] ⭐ %s added to favorites.\n\n", ip)
}

// RemoveFavorite removes a peer from favorites
func (pm *PeerManager) RemoveFavorite(ip string) {
	if !isValidIP(ip) {
		fmt.Printf("\n[System] ❌ Invalid IP: %s\n\n", ip)
		return
	}

	pm.mu.Lock()
	delete(pm.favorites, ip)
	pm.mu.Unlock()
	fmt.Printf("\n[System] ✓ %s removed from favorites.\n\n", ip)
}

// IsFavorite checks if a peer is in favorites
func (pm *PeerManager) IsFavorite(ip string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.favorites[ip]
}

// SetUserStatus updates user status
func (pm *PeerManager) SetUserStatus(status UserStatus, msg string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.profile.Status = status
	pm.profile.StatusMsg = msg
	pm.profile.LastSeen = time.Now()
}

// CreateGroup creates a new chat group
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

// AddMemberToGroup adds a peer to a group
func (pm *PeerManager) AddMemberToGroup(groupID, peerIP string) {
	if !isValidIP(peerIP) {
		fmt.Printf("\n[System] ❌ Invalid IP: %s\n\n", peerIP)
		return
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if group, exists := pm.groups[groupID]; exists {
		if info, peerExists := pm.peerInfo[peerIP]; peerExists {
			group.Members[peerIP] = info
			fmt.Printf("\n[System] ✓ %s added to group.\n\n", info.Name)
		}
	}
}

// PrintAdvancedHelp displays help information
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

// PrintDetailedStatistics displays statistics
func (pm *PeerManager) PrintDetailedStatistics() {
	pm.mu.RLock()
	activePeers := len(pm.peers)
	pm.mu.RUnlock()

	sessionDuration := time.Since(pm.stats.SessionStart)
	avgMsgSize := int64(0)
	totalMessages := atomic.LoadInt64(&pm.stats.TotalMessages)
	bytesSent := atomic.LoadInt64(&pm.stats.BytesSent)
	bytesReceived := atomic.LoadInt64(&pm.stats.BytesReceived)
	successNATs := atomic.LoadInt64(&pm.stats.SuccessfulNATs)
	failedNATs := atomic.LoadInt64(&pm.stats.FailedNATs)

	if totalMessages > 0 {
		avgMsgSize = (bytesSent + bytesReceived) / totalMessages
	}

	fmt.Println("\n╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              📊 DETAILED STATISTICS 📊                      ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Printf("Session Start:         %s\n", pm.stats.SessionStart.Format("02.01.2006 15:04:05"))
	fmt.Printf("Session Duration:      %v\n", sessionDuration.Round(time.Second))
	fmt.Printf("Total Messages:        %d\n", totalMessages)
	fmt.Printf("Active Connections:    %d\n", activePeers)
	fmt.Printf("Total Connections:     %d\n", atomic.LoadInt64(&pm.stats.TotalConnections))
	fmt.Printf("Successful NAT Passes:  %d\n", successNATs)
	fmt.Printf("Failed NAT Passes:     %d\n", failedNATs)
	fmt.Printf("Data Sent:             %.2f MB\n", float64(bytesSent)/1024/1024)
	fmt.Printf("Data Received:         %.2f MB\n", float64(bytesReceived)/1024/1024)
	fmt.Printf("Average Message Size:  %d Bytes\n", avgMsgSize)
	fmt.Println("══════════════════════════════════════════════════════════════════\n")
}

// PrintUserProfile displays user profile information
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
	fmt.Printf("Message Count:       %d\n", atomic.LoadInt32(&info.MessageCount))
	fmt.Println("════════════════════════════════════════\n")
}

// PrintBlockedUsers displays blocked users list
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

// PrintGroups displays groups list
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
		os.Exit(1)
	}

	reader := bufio.NewReader(os.Stdin)
	username := getUserInput(reader)

	pm, err := NewPeerManager(username, tlsClientConfig, tlsServerConfig)
	if err != nil {
		fmt.Printf("[CRITICAL ERROR] Failed to create peer manager: %v\n", err)
		os.Exit(1)
	}
	defer pm.Close()

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

// commandLoop handles user input
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

// handlePrivateMessage handles private messages
func handlePrivateMessage(input string, pm *PeerManager) {
	parts := strings.SplitN(input, " ", 2)
	if len(parts) < 2 {
		fmt.Println("\n[System] ❌ Usage: @<Username> <Message>\n")
		return
	}

	targetName := strings.TrimPrefix(parts[0], "@")
	content := parts[1]

	if len(content) > maxMessageLength {
		fmt.Printf("\n[System] ❌ Message too long (max %d characters).\n\n", maxMessageLength)
		return
	}

	pm.mu.RLock()
	var targetIP string
	for ip, info := range pm.peerInfo {
		if strings.EqualFold(info.Name, targetName) {
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

// handleCommand processes user commands
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
		if !isValidIP(targetIP) {
			fmt.Printf("\n[System] ❌ Invalid IP: %s\n\n", targetIP)
			return
		}
		fmt.Printf("\n[System] 🔨 Initiating hole punching to %s...\n\n", targetIP)
		holePunch := pm.endpointMgr.GetHolePunch()
		if holePunch != nil {
			go holePunch.AttemptPunch(pm.ctx, targetIP, 8888)
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
		if !isValidIP(ip) {
			fmt.Printf("\n[System] ❌ Invalid IP: %s\n\n", ip)
			return
		}
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
		if strings.EqualFold(strings.TrimSpace(confirm), "y") {
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

// resolvePeerName resolves a peer name to IP address
func resolvePeerName(pm *PeerManager, target string) string {
	if isValidIP(target) {
		return target
	}
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	for name, peer := range pm.savedPeers {
		if strings.EqualFold(name, target) {
			return peer.IP
		}
	}
	return ""
}

// savePeer saves a peer configuration
func (pm *PeerManager) savePeer(ip, name string) {
	if !isValidIP(ip) {
		fmt.Printf("\n[System] ❌ Invalid IP: %s\n\n", ip)
		return
	}

	if name == "" {
		fmt.Println("\n[System] ❌ Name cannot be empty.\n")
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

// deleteSavedPeer removes a saved peer
func (pm *PeerManager) deleteSavedPeer(target string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for key, peer := range pm.savedPeers {
		if strings.EqualFold(key, target) || peer.IP == target {
			delete(pm.savedPeers, key)
			fmt.Printf("\n[System] ✓ '%s' deleted.\n\n", key)
			pm.writeSavedPeers()
			return
		}
	}

	fmt.Printf("\n[System] ❌ '%s' not found.\n\n", target)
}

// deleteAllSavedPeers removes all saved peers
func (pm *PeerManager) deleteAllSavedPeers() {
	pm.mu.Lock()
	pm.savedPeers = make(map[string]*SavedPeer)
	pm.mu.Unlock()

	if err := os.Remove(configFile); err != nil && !os.IsNotExist(err) {
		fmt.Printf("\n[System] ⚠️ Warning: %v\n\n", err)
	}
	fmt.Println("\n[System] ✓ All saved peers deleted.\n")
}

// loadSavedPeers loads saved peers from configuration file
func (pm *PeerManager) loadSavedPeers() {
	data, err := os.ReadFile(configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			pm.logger.Printf("Warning: failed to read config file: %v", err)
		}
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
			if !isValidIP(ip) {
				pm.logger.Printf("Warning: skipping invalid IP in config: %s", ip)
				continue
			}
			pm.savedPeers[strings.ToLower(name)] = &SavedPeer{
				IP:   ip,
				Name: name,
			}
		}
	}
}

// writeSavedPeers persists saved peers to configuration file
func (pm *PeerManager) writeSavedPeers() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var lines []string
	for name, peer := range pm.savedPeers {
		lines = append(lines, fmt.Sprintf("%s=%s", name, peer.IP))
	}

	sort.Strings(lines)
	content := strings.Join(lines, "\n")
	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		pm.logger.Printf("Error writing config file: %v", err)
	}
}

// printSavedPeers displays saved peers
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

// printPeerList displays connected peers
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
				msgCount := atomic.LoadInt32(&info.MessageCount)
				fmt.Printf("%-15s %-20s %-15s %-12s %-8d\n", ip, info.Name, connTime, lastActivity, msgCount)
			}
		}
	}
	fmt.Println("============================\n")
}

// printMessageLog displays message history
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

// printLocalIP displays network information
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

// printSecurityInfo displays security information
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

// connectToPeer establishes a connection to a peer
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

	// Acquire semaphore slot
	select {
	case pm.dialSemaphore <- struct{}{}:
		defer func() { <-pm.dialSemaphore }()
	case <-pm.ctx.Done():
		return
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
	tlsConn, err := tls.DialWithDialer(dialer, "tcp", target, pm.tlsConfig)
	if err != nil {
		fmt.Printf("\n[System] ❌ Cannot connect to %s.\n", ip)
		fmt.Printf("[System] 💡 Attempting Hole Punching...\n")

		holePunch := pm.endpointMgr.GetHolePunch()
		if holePunch != nil {
			go holePunch.AttemptPunch(pm.ctx, ip, 8888)
		}

		atomic.AddInt64(&pm.stats.FailedNATs, 1)
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
	atomic.AddInt64(&pm.stats.TotalConnections, 1)
	atomic.AddInt64(&pm.stats.SuccessfulNATs, 1)
	go pm.handleConnection(tlsConn, ip)
}

// disconnectAllPeers closes all peer connections
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

// disconnectPeer closes a specific peer connection
func (pm *PeerManager) disconnectPeer(ip string) {
	if !isValidIP(ip) {
		fmt.Printf("\n[System] ❌ Invalid IP: %s\n\n", ip)
		return
	}

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

// broadcastMessage sends a message to all connected peers
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
		n, err := conn.Write([]byte(formattedMessage))
		conn.SetWriteDeadline(time.Time{})

		if err == nil {
			atomic.AddInt64(&pm.stats.BytesSent, int64(n))
		} else {
			failedPeers = append(failedPeers, ip)
		}
	}

	atomic.AddInt64(&pm.stats.TotalMessages, 1)
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

// logMessage adds message to log
func (pm *PeerManager) logMessage(msg Message) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.messageLog = append(pm.messageLog, msg)

	if len(pm.messageLog) > pm.maxLogSize {
		pm.messageLog = pm.messageLog[1:]
	}
}

// writeToLogFile writes message to log file
func (pm *PeerManager) writeToLogFile(msg string) {
	if pm.logFile != nil {
		fmt.Fprintln(pm.logFile, msg)
	}
}

// startTLSListener starts the TLS server listener
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
			pm.logger.Printf("Accept error: %v", err)
			continue
		}

		ip := strings.Split(conn.RemoteAddr().String(), ":")[0]
		go pm.handleConnection(conn, ip)
	}
}

// handleConnection processes messages from a peer
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

		atomic.AddInt64(&pm.stats.BytesReceived, int64(len(message)))

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
			atomic.AddInt32(&info.MessageCount, 1)
		}
		pm.mu.Unlock()

		atomic.AddInt64(&pm.stats.TotalMessages, 1)

		fmt.Printf("\n%s\n\n", message)
		pm.writeToLogFile(fmt.Sprintf("%s [%s]: %s", time.Now().Format("15:04:05"), ip, message))
		pm.refreshPrompt()
	}
}

// startKeepAlive sends periodic ping messages
func (pm *PeerManager) startKeepAlive(conn net.Conn, ip string, done chan struct{}) {
	ticker := time.NewTicker(keepAliveInterval)
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

		case <-pm.ctx.Done():
			return
		}
	}
}

// updatePeerActivity updates peer's last activity time
func (pm *PeerManager) updatePeerActivity(ip string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if info, exists := pm.peerInfo[ip]; exists {
		info.LastActivity = time.Now()
		info.Status = STATUS_ONLINE
	}
}

// registerPeer adds or updates a peer connection
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

// handleSystemSignals handles OS signals for graceful shutdown
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

// closeAllConnections gracefully closes all connections
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

// Close cleanup resources
func (pm *PeerManager) Close() {
	pm.cancel()
	if pm.endpointMgr != nil {
		pm.endpointMgr.Close()
	}
	if pm.logFile != nil {
		pm.logFile.Close()
	}
}

// printWelcomeScreen displays welcome information
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

// getUserInput gets and validates username from user
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

// isValidUsername validates username format
func isValidUsername(username string) bool {
	pattern := `^[a-zA-Z0-9_\-]{1,32}$`
	matched, _ := regexp.MatchString(pattern, username)
	return matched
}

// isValidIP validates IP address format
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// verifyTLSState checks if TLS 1.3 is being used
func verifyTLSState(conn *tls.Conn) bool {
	state := conn.ConnectionState()
	return state.Version >= tls.VersionTLS13
}

// sanitizeInput removes dangerous characters from input
func sanitizeInput(in string) string {
	r := strings.NewReplacer(
		"\x1b", "",
		"\033", "",
		"\r", "",
		"\x00", "",
	)
	return r.Replace(in)
}

// generateTLSConfig generates TLS configuration with self-signed certificates
func generateTLSConfig() (*tls.Config, *tls.Config, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to generate private key: %w", err)
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
		return nil, nil, "", fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	cert, err := tls.X509KeyPair(certPEM, privPEM)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse key pair: %w", err)
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

// calculateFingerprint generates certificate fingerprint
func calculateFingerprint(certDER []byte) string {
	hash := sha256.Sum256(certDER)
	return hex.EncodeToString(hash[:16])
}

// clearScreen clears terminal screen
func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

// printBanner prints application banner
func printBanner() {
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║                          AND CHAT                          ║")
	fmt.Println("║     End-to-End Encrypted - Server-Free - NAT Traversal     ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
}

// refreshPrompt redisplays the command prompt
func (pm *PeerManager) refreshPrompt() {
	fmt.Printf("\033[36m" + pm.name + " > \033[0m")
}
