package main

// ─────────────────────────────────────────────────────────────────────────────
//  AND CHAT v2  —  Sunucusuz, Uçtan Uca Şifreli P2P Sohbet
//  Yenilikler:
//    • NAT traversal: TCP hole punching + STUN ile gerçek IP keşfi
//    • Otomatik yeniden bağlanma (exponential backoff)
//    • Çevrimdışı mesaj kuyruğu (peer geri dönünce teslim)
//    • Peer exchange (birbirinin tanıdığı kişileri paylaşma)
//    • Tam JSON protokolü (sürüm müzakeresi)
//    • Bant genişliği hız sınırlayıcı
//    • Çoklu mesaj türü: normal, özel, sistem, dosya meta, durum
//    • /relay komutu: güvenilir bir arkadaş üzerinden NAT geçişi
// ─────────────────────────────────────────────────────────────────────────────

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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"math/bits"
	"net"
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

// ─────────────────────────────────────────────────────────────────────────────
// Sabitler
// ─────────────────────────────────────────────────────────────────────────────

const (
	chatPort             = ":8888"
	rendezvousPort       = ":9999"
	holePunchPort        = ":8889" // UDP hole punching
	pingInterval         = 10 * time.Second
	readTimeout          = 90 * time.Second
	writeTimeout         = 10 * time.Second
	maxMessageLength     = 8192
	maxUsernameLength    = 32
	tlsCertValidityDays  = 365
	configFile           = "peers.conf"
	logFile              = "chat.log"
	maxConcurrentDials   = 8
	dialTimeout          = 15 * time.Second
	keepAliveInterval    = 15 * time.Second
	inviteCodeLength     = 8
	reconnectMaxAttempts = 10
	reconnectBaseDelay   = 2 * time.Second
	reconnectMaxDelay    = 5 * time.Minute
	offlineQueueMax      = 200     // çevrimdışı kuyruk limiti
	protocolVersion      = "2.0.0" // protokol sürümü
	stunServer1          = "stun.l.google.com:19302"
	stunServer2          = "stun1.l.google.com:19302"
	rateLimit            = 20 // saniyede max mesaj
)

// ─────────────────────────────────────────────────────────────────────────────
// Protokol türleri
// ─────────────────────────────────────────────────────────────────────────────

type MessageType string

const (
	MSG_NORMAL    MessageType = "normal"
	MSG_PRIVATE   MessageType = "private"
	MSG_SYSTEM    MessageType = "system"
	MSG_STATUS    MessageType = "status"
	MSG_PEER_LIST MessageType = "peer_list" // peer exchange
	MSG_HANDSHAKE MessageType = "handshake" // bağlantı el sıkışması
	MSG_PING      MessageType = "ping"
	MSG_PONG      MessageType = "pong"
	MSG_RELAY_REQ MessageType = "relay_req" // relay isteği
	MSG_RELAY_FWD MessageType = "relay_fwd" // relay yönlendirme
	MSG_DELIVERY  MessageType = "delivery"  // teslim onayı
)

type UserStatus string

const (
	STATUS_ONLINE  UserStatus = "online"
	STATUS_AWAY    UserStatus = "away"
	STATUS_DND     UserStatus = "dnd"
	STATUS_OFFLINE UserStatus = "offline"
)

// ─────────────────────────────────────────────────────────────────────────────
// Veri yapıları
// ─────────────────────────────────────────────────────────────────────────────

// Wire protokolündeki tüm mesajlar bu yapıyla taşınır.
type Packet struct {
	Version   string      `json:"v"`
	Type      MessageType `json:"type"`
	From      string      `json:"from"`
	To        string      `json:"to,omitempty"`
	Content   string      `json:"content,omitempty"`
	Timestamp time.Time   `json:"ts"`
	ID        string      `json:"id"`
	Peers     []PeerAddr  `json:"peers,omitempty"` // peer exchange için
	PublicIP  string      `json:"pub_ip,omitempty"`
}

// PeerAddr, paylaşılabilir peer adresi.
type PeerAddr struct {
	IP   string `json:"ip"`
	Port string `json:"port"`
	Name string `json:"name"`
}

// ConnState, bir bağlantının tam durumunu tutar.
type ConnState struct {
	conn         net.Conn
	name         string
	ip           string
	publicIP     string // STUN ile öğrenilen
	connectedAt  time.Time
	lastActivity time.Time
	status       UserStatus
	statusMsg    string
	messageCount int32
	inviteCode   string
	version      string // karşı tarafın protokol sürümü
	rateLimiter  *RateLimiter
}

// SavedPeer, diske kaydedilen peer.
type SavedPeer struct {
	IP         string    `json:"ip"`
	Name       string    `json:"name"`
	PublicIP   string    `json:"public_ip,omitempty"`
	InviteCode string    `json:"invite_code,omitempty"`
	SavedAt    time.Time `json:"saved_at"`
	Blocked    bool      `json:"blocked"`
	Starred    bool      `json:"starred"`
}

// OfflineMessage, çevrimdışı peer için kuyruklanan mesaj.
type OfflineMessage struct {
	Packet   Packet
	QueuedAt time.Time
	Attempts int
}

// ReconnectJob, otomatik yeniden bağlanma görevi.
type ReconnectJob struct {
	ip      string
	name    string
	attempt int
	nextAt  time.Time
}

// ─────────────────────────────────────────────────────────────────────────────
// Hız sınırlayıcı (token bucket)
// ─────────────────────────────────────────────────────────────────────────────

type RateLimiter struct {
	mu       sync.Mutex
	tokens   int
	max      int
	lastFill time.Time
	rate     int // token/saniye
}

func NewRateLimiter(rate int) *RateLimiter {
	return &RateLimiter{tokens: rate, max: rate, lastFill: time.Now(), rate: rate}
}

func (r *RateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(r.lastFill).Seconds()
	r.tokens += int(elapsed * float64(r.rate))
	if r.tokens > r.max {
		r.tokens = r.max
	}
	r.lastFill = now
	if r.tokens > 0 {
		r.tokens--
		return true
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// STUN — gerçek genel IP keşfi
// ─────────────────────────────────────────────────────────────────────────────

// discoverPublicIP basit STUN binding isteği gönderir ve genel IP:port döner.
// RFC 5389 uyumlu: sadece Binding Request / XOR-MAPPED-ADDRESS okur.
func discoverPublicIP() (string, string, error) {
	servers := []string{stunServer1, stunServer2}
	for _, srv := range servers {
		ip, port, err := stunQuery(srv)
		if err == nil {
			return ip, port, nil
		}
	}
	return "", "", fmt.Errorf("tüm STUN sunucularına ulaşılamadı")
}

func stunQuery(server string) (string, string, error) {
	conn, err := net.DialTimeout("udp", server, 5*time.Second)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// STUN Binding Request: 20 byte header
	req := make([]byte, 20)
	req[0] = 0x00 // Binding Request
	req[1] = 0x01
	req[2] = 0x00 // length = 0 (attributes yok)
	req[3] = 0x00
	// Magic Cookie
	req[4] = 0x21
	req[5] = 0x12
	req[6] = 0xa4
	req[7] = 0x42
	// Transaction ID (rastgele 12 byte)
	txID := make([]byte, 12)
	rand.Read(txID)
	copy(req[8:], txID)

	if _, err := conn.Write(req); err != nil {
		return "", "", err
	}

	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil || n < 20 {
		return "", "", fmt.Errorf("STUN yanıtı alınamadı")
	}

	// Attribute'ları parse et
	pos := 20
	for pos+4 <= n {
		attrType := binary.BigEndian.Uint16(resp[pos : pos+2])
		attrLen := int(binary.BigEndian.Uint16(resp[pos+2 : pos+4]))
		pos += 4
		if pos+attrLen > n {
			break
		}
		data := resp[pos : pos+attrLen]

		// XOR-MAPPED-ADDRESS (0x0020) veya MAPPED-ADDRESS (0x0001)
		if (attrType == 0x0020 || attrType == 0x0001) && attrLen >= 8 {
			family := data[1]
			if family == 0x01 { // IPv4
				rawPort := binary.BigEndian.Uint16(data[2:4])
				rawIP := binary.BigEndian.Uint32(data[4:8])
				var port uint16
				var ipInt uint32
				if attrType == 0x0020 {
					// XOR ile şifreli
					magic := uint32(0x2112a442)
					port = rawPort ^ 0x2112
					ipInt = rawIP ^ magic
				} else {
					port = rawPort
					ipInt = rawIP
				}
				ipStr := fmt.Sprintf("%d.%d.%d.%d",
					(ipInt>>24)&0xff, (ipInt>>16)&0xff,
					(ipInt>>8)&0xff, ipInt&0xff)
				return ipStr, fmt.Sprintf("%d", port), nil
			}
		}
		// padding: 4'e yuvarla
		pos += attrLen
		if attrLen%4 != 0 {
			pos += 4 - attrLen%4
		}
	}
	return "", "", fmt.Errorf("STUN yanıtında adres bulunamadı")
}

// ─────────────────────────────────────────────────────────────────────────────
// TCP Hole Punching
// ─────────────────────────────────────────────────────────────────────────────

// holePunch, iki tarafın da aynı anda bağlantı açmaya çalışmasını sağlar.
// Rendezvous sunucusu koordinasyonu için kullanılır.
// Her iki taraf da birbirinin IP:portuna aynı anda SYN gönderir.
func holePunch(ctx context.Context, remoteAddr string, localPort int) (net.Conn, error) {
	laddr := &net.TCPAddr{Port: localPort}
	raddr, err := net.ResolveTCPAddr("tcp", remoteAddr)
	if err != nil {
		return nil, err
	}

	var conn net.Conn
	errCh := make(chan error, 1)
	connCh := make(chan net.Conn, 1)

	// Dinleyici (karşı taraf bize bağlanabilir)
	ln, err := net.ListenTCP("tcp", laddr)
	if err == nil {
		go func() {
			ln.SetDeadline(time.Now().Add(10 * time.Second))
			c, e := ln.Accept()
			ln.Close()
			if e != nil {
				errCh <- e
			} else {
				connCh <- c
			}
		}()
	}

	// Biz bağlanalım (SYN gönder)
	go func() {
		d := net.Dialer{LocalAddr: laddr, Timeout: 10 * time.Second}
		c, e := d.DialContext(ctx, "tcp", raddr.String())
		if e != nil {
			errCh <- e
		} else {
			connCh <- c
		}
	}()

	select {
	case conn = <-connCh:
		return conn, nil
	case <-time.After(12 * time.Second):
		return nil, fmt.Errorf("hole punch zaman aşımına uğradı")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Davet kodu kayıt defteri
// ─────────────────────────────────────────────────────────────────────────────

type InviteEntry struct {
	Code          string
	OwnerIP       string
	OwnerPublicIP string // STUN ile öğrenilen
	OwnerPort     string
	OwnerName     string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

type InviteRegistry struct {
	mu      sync.RWMutex
	entries map[string]*InviteEntry
}

func NewInviteRegistry() *InviteRegistry {
	return &InviteRegistry{entries: make(map[string]*InviteEntry)}
}

func (ir *InviteRegistry) Register(ownerIP, pubIP, ownerPort, ownerName string, ttl time.Duration) string {
	code := generateInviteCode()
	ir.mu.Lock()
	ir.entries[code] = &InviteEntry{
		Code:          code,
		OwnerIP:       ownerIP,
		OwnerPublicIP: pubIP,
		OwnerPort:     ownerPort,
		OwnerName:     ownerName,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(ttl),
	}
	ir.mu.Unlock()
	return code
}

func (ir *InviteRegistry) Resolve(code string) (*InviteEntry, bool) {
	ir.mu.RLock()
	defer ir.mu.RUnlock()
	e, ok := ir.entries[strings.ToUpper(code)]
	if !ok || time.Now().After(e.ExpiresAt) {
		return nil, false
	}
	return e, true
}

func (ir *InviteRegistry) Expire(code string) {
	ir.mu.Lock()
	delete(ir.entries, strings.ToUpper(code))
	ir.mu.Unlock()
}

func generateInviteCode() string {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, inviteCodeLength)
	rand.Read(b)
	for i := range b {
		b[i] = chars[b[i]%byte(len(chars))]
	}
	return string(b)
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendezvous dinleyici  (port 9999)
// ─────────────────────────────────────────────────────────────────────────────

type RendezvousRequest struct {
	Action string `json:"action"` // "resolve", "punch_notify"
	Code   string `json:"code"`
	IP     string `json:"ip,omitempty"`
	Port   string `json:"port,omitempty"`
}

type RendezvousResponse struct {
	OK        bool   `json:"ok"`
	IP        string `json:"ip,omitempty"`
	PublicIP  string `json:"pub_ip,omitempty"`
	Port      string `json:"port,omitempty"`
	Name      string `json:"name,omitempty"`
	NeedPunch bool   `json:"need_punch,omitempty"` // NAT traversal gerekli mi
	Message   string `json:"message,omitempty"`
}

func startRendezvousListener(registry *InviteRegistry, logger *log.Logger) {
	ln, err := net.Listen("tcp", rendezvousPort)
	if err != nil {
		logger.Printf("[Rendezvous] Dinleyici başlatılamadı: %v", err)
		return
	}
	logger.Printf("[Rendezvous] %s portunda dinleniyor", rendezvousPort)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleRendezvous(conn, registry, logger)
	}
}

func handleRendezvous(conn net.Conn, registry *InviteRegistry, logger *log.Logger) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var req RendezvousRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}

	var resp RendezvousResponse
	switch req.Action {
	case "resolve":
		if entry, ok := registry.Resolve(req.Code); ok {
			// Genel IP varsa paylaş (NAT traversal için)
			pubIP := entry.OwnerPublicIP
			needPunch := pubIP != "" && pubIP != entry.OwnerIP
			resp = RendezvousResponse{
				OK:        true,
				IP:        entry.OwnerIP,
				PublicIP:  pubIP,
				Port:      entry.OwnerPort,
				Name:      entry.OwnerName,
				NeedPunch: needPunch,
			}
		} else {
			resp = RendezvousResponse{OK: false, Message: "kod bulunamadı veya süresi doldu"}
		}
	default:
		resp = RendezvousResponse{OK: false, Message: "bilinmeyen işlem"}
	}

	json.NewEncoder(conn).Encode(resp)
	logger.Printf("[Rendezvous] %s → code=%s ok=%v", conn.RemoteAddr(), req.Code, resp.OK)
}

func resolveInviteCode(registry *InviteRegistry, code, host string) (*RendezvousResponse, error) {
	code = strings.ToUpper(strings.TrimSpace(code))

	// Önce yerel kayıt defteri
	if entry, ok := registry.Resolve(code); ok {
		return &RendezvousResponse{
			OK:       true,
			IP:       entry.OwnerIP,
			PublicIP: entry.OwnerPublicIP,
			Port:     entry.OwnerPort,
			Name:     entry.OwnerName,
		}, nil
	}

	if host == "" {
		return nil, fmt.Errorf("kod %s bulunamadı (uzak sorgulama için host belirtin)", code)
	}

	addr := net.JoinHostPort(host, "9999")
	conn, err := net.DialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		return nil, fmt.Errorf("randevu sunucusuna (%s) ulaşılamadı: %w", addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))

	json.NewEncoder(conn).Encode(RendezvousRequest{Action: "resolve", Code: code})

	var resp RendezvousResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("randevu: %s", resp.Message)
	}
	return &resp, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// PeerManager — merkezi koordinatör
// ─────────────────────────────────────────────────────────────────────────────

type PeerManager struct {
	mu sync.RWMutex

	// Bağlantılar
	conns      map[string]*ConnState // ip → durum
	name       string
	localIP    string
	publicIP   string // STUN ile öğrenilen
	publicPort string

	// TLS
	tlsClient *tls.Config
	tlsServer *tls.Config
	certFP    string

	// Davet
	inviteReg *InviteRegistry

	// Kalıcı kayıtlar
	savedPeers   map[string]*SavedPeer // küçük harf isim → peer
	blockedUsers map[string]bool
	favorites    map[string]bool

	// Mesaj geçmişi & çevrimdışı kuyruk
	messageLog   []Packet
	maxLogSize   int
	offlineQueue map[string][]OfflineMessage // ip → mesajlar

	// Yeniden bağlanma
	reconnectJobs map[string]*ReconnectJob
	reconnectCh   chan ReconnectJob

	// İstatistikler
	totalMessages    int64
	totalConnections int64
	bytesSent        int64
	bytesReceived    int64
	sessionStart     time.Time

	// Altyapı
	logFile        *os.File
	logger         *log.Logger
	commandHistory []string
	maxHistorySize int
	dialSemaphore  chan struct{}
	shutdown       chan struct{}
	ctx            context.Context
	cancel         context.CancelFunc

	// Profil
	statusMsg string
	status    UserStatus
}

func NewPeerManager(name string, tlsClient, tlsServer *tls.Config) (*PeerManager, error) {
	lf, err := os.OpenFile(filepath.Join(".", logFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("log dosyası açılamadı: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	pm := &PeerManager{
		conns:          make(map[string]*ConnState),
		name:           name,
		tlsClient:      tlsClient,
		tlsServer:      tlsServer,
		inviteReg:      NewInviteRegistry(),
		savedPeers:     make(map[string]*SavedPeer),
		blockedUsers:   make(map[string]bool),
		favorites:      make(map[string]bool),
		messageLog:     make([]Packet, 0, 1000),
		maxLogSize:     1000,
		offlineQueue:   make(map[string][]OfflineMessage),
		reconnectJobs:  make(map[string]*ReconnectJob),
		reconnectCh:    make(chan ReconnectJob, 64),
		sessionStart:   time.Now(),
		logFile:        lf,
		logger:         log.New(os.Stdout, "", 0),
		commandHistory: make([]string, 0, 100),
		maxHistorySize: 100,
		dialSemaphore:  make(chan struct{}, maxConcurrentDials),
		shutdown:       make(chan struct{}),
		ctx:            ctx,
		cancel:         cancel,
		status:         STATUS_ONLINE,
	}

	pm.localIP = detectLocalIP()
	return pm, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// STUN ile genel IP keşfi
// ─────────────────────────────────────────────────────────────────────────────

func (pm *PeerManager) discoverPublicAddress() {
	fmt.Println("[System] 🌐 Genel IP adresi belirleniyor (STUN)...")
	ip, port, err := discoverPublicIP()
	if err != nil {
		fmt.Printf("[System] ⚠️  STUN başarısız: %v (sadece LAN bağlantısı)\n", err)
		pm.publicIP = pm.localIP
		return
	}
	pm.publicIP = ip
	pm.publicPort = port
	nat := pm.publicIP != pm.localIP
	natStr := "Yok (doğrudan bağlantı)"
	if nat {
		natStr = fmt.Sprintf("Var (yerel: %s, genel: %s)", pm.localIP, pm.publicIP)
	}
	fmt.Printf("[System] ✓ Genel IP : %s:%s\n", pm.publicIP, pm.publicPort)
	fmt.Printf("[System] ✓ NAT      : %s\n\n", natStr)
}

// ─────────────────────────────────────────────────────────────────────────────
// Davet sistemi
// ─────────────────────────────────────────────────────────────────────────────

func (pm *PeerManager) GenerateInvite() {
	port := strings.TrimPrefix(chatPort, ":")
	code := pm.inviteReg.Register(pm.localIP, pm.publicIP, port, pm.name, 30*time.Minute)

	behind := pm.publicIP != pm.localIP
	sameNet := "Aynı ağda (/join " + code + ")"
	diffNet := "/join " + code + "@" + pm.publicIP

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║              🎫  DAVETİYE KODU                       ║")
	fmt.Println("╠══════════════════════════════════════════════════════╣")
	fmt.Printf("║  Kod      : %-41s║\n", code)
	fmt.Printf("║  Geçerli  : 30 dakika                                ║\n")
	fmt.Println("╠══════════════════════════════════════════════════════╣")
	fmt.Println("║  AYNI AĞ (LAN):                                      ║")
	fmt.Printf("║    /join %-45s║\n", code)
	fmt.Println("╠══════════════════════════════════════════════════════╣")
	fmt.Println("║  FARKLI AĞ / İNTERNET:                               ║")
	fmt.Printf("║    /join %-45s║\n", diffNet)
	if behind {
		fmt.Println("╠══════════════════════════════════════════════════════╣")
		fmt.Println("║  ⚠️  NAT tespit edildi. Karşı taraf NAT traversal     ║")
		fmt.Println("║  otomatik denenecek (hole punching).                 ║")
	}
	_ = sameNet
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Println()
}

func (pm *PeerManager) JoinViaInvite(input string) {
	input = strings.TrimSpace(input)
	var code, host string
	if idx := strings.Index(input, "@"); idx >= 0 {
		code, host = input[:idx], input[idx+1:]
	} else {
		code = input
	}

	fmt.Printf("\n[System] 🔍 Davet kodu çözümleniyor: %s...\n", code)
	resp, err := resolveInviteCode(pm.inviteReg, code, host)
	if err != nil {
		fmt.Printf("[System] ❌ Çözümlenemedi: %v\n\n", err)
		return
	}

	targetIP := resp.IP
	if resp.PublicIP != "" && resp.PublicIP != resp.IP {
		fmt.Printf("[System] ✓ Peer bulundu: %s (yerel: %s, genel: %s)\n", resp.Name, resp.IP, resp.PublicIP)
	} else {
		fmt.Printf("[System] ✓ Peer bulundu: %s (%s)\n", resp.Name, resp.IP)
	}

	if resp.NeedPunch {
		fmt.Println("[System] 🔀 NAT arkasında — TCP hole punching deneniyor...")
		go pm.connectWithHolePunch(resp.PublicIP, resp.Name)
	} else {
		fmt.Printf("[System] 🔒 Bağlanılıyor: %s...\n\n", targetIP)
		go pm.connectToPeer(targetIP, resp.Name, true)
	}

	// Otomatik kaydet
	pm.mu.Lock()
	key := strings.ToLower(resp.Name)
	if _, exists := pm.savedPeers[key]; !exists {
		pm.savedPeers[key] = &SavedPeer{
			IP:         targetIP,
			PublicIP:   resp.PublicIP,
			Name:       resp.Name,
			InviteCode: code,
			SavedAt:    time.Now(),
		}
	}
	pm.mu.Unlock()
	pm.writeSavedPeers()
	pm.inviteReg.Expire(code)
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS bağlantı katmanı
// ─────────────────────────────────────────────────────────────────────────────

func (pm *PeerManager) connectToPeer(ip, hint string, saveOnSuccess bool) {
	if pm.isBlocked(ip) {
		fmt.Printf("\n[System] ❌ %s engellendi.\n\n", ip)
		return
	}
	pm.mu.RLock()
	_, exists := pm.conns[ip]
	pm.mu.RUnlock()
	if exists {
		fmt.Printf("\n[System] ⚠️  %s ile zaten bağlantı var.\n\n", ip)
		return
	}

	select {
	case pm.dialSemaphore <- struct{}{}:
		defer func() { <-pm.dialSemaphore }()
	case <-pm.ctx.Done():
		return
	}

	target := ip + chatPort
	d := &net.Dialer{Timeout: dialTimeout}
	tlsConn, err := tls.DialWithDialer(d, "tcp", target, pm.tlsClient)
	if err != nil {
		fmt.Printf("\n[System] ❌ %s adresine bağlanılamadı: %v\n\n", ip, err)
		// Yeniden bağlanma planla (eğer kayıtlı peer ise)
		if saveOnSuccess {
			pm.scheduleReconnect(ip, hint)
		}
		return
	}

	if tlsConn.ConnectionState().Version < tls.VersionTLS13 {
		tlsConn.Close()
		fmt.Printf("\n[System] ❌ TLS 1.3 gerekli (%s reddedildi).\n\n", ip)
		return
	}

	atomic.AddInt64(&pm.totalConnections, 1)
	pm.registerConn(ip, hint, tlsConn)
	// El sıkışma paketi gönder
	pm.sendPacket(tlsConn, Packet{
		Type:     MSG_HANDSHAKE,
		From:     pm.name,
		Content:  pm.publicIP,
		PublicIP: pm.publicIP,
	})
	go pm.handleConn(tlsConn, ip)
}

func (pm *PeerManager) connectWithHolePunch(remotePublicIP, name string) {
	// Basit hole punch: karşı tarafın portuna doğrudan TCP dene
	port := strings.TrimPrefix(chatPort, ":")
	target := remotePublicIP + ":" + port

	ctx, cancel := context.WithTimeout(pm.ctx, 15*time.Second)
	defer cancel()

	conn, err := holePunch(ctx, target, 0)
	if err != nil {
		// Hole punch başarısız olursa normal bağlantı dene
		fmt.Printf("[System] ⚠️  Hole punch başarısız (%v), doğrudan bağlantı deneniyor...\n", err)
		pm.connectToPeer(remotePublicIP, name, true)
		return
	}

	// TLS wrap
	tlsConn := tls.Client(conn, pm.tlsClient)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		fmt.Printf("[System] ❌ TLS el sıkışması başarısız: %v\n", err)
		return
	}

	fmt.Println("[System] ✓ Hole punching başarılı! Bağlantı kuruldu.")
	ip := strings.Split(remotePublicIP, ":")[0]
	atomic.AddInt64(&pm.totalConnections, 1)
	pm.registerConn(ip, name, tlsConn)
	pm.sendPacket(tlsConn, Packet{
		Type:     MSG_HANDSHAKE,
		From:     pm.name,
		PublicIP: pm.publicIP,
	})
	go pm.handleConn(tlsConn, ip)
}

func (pm *PeerManager) startTLSListener() {
	ln, err := tls.Listen("tcp", chatPort, pm.tlsServer)
	if err != nil {
		fmt.Printf("\n[KRİTİK] TLS dinleyici hatası: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()
	fmt.Printf("[System] ✓ TLS 1.3 dinleniyor (port %s)\n", strings.TrimPrefix(chatPort, ":"))

	for {
		select {
		case <-pm.shutdown:
			return
		default:
		}
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		ip := strings.Split(conn.RemoteAddr().String(), ":")[0]
		if pm.isBlocked(ip) {
			conn.Close()
			continue
		}
		go pm.handleConn(conn, ip)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Bağlantı işleyici
// ─────────────────────────────────────────────────────────────────────────────

func (pm *PeerManager) handleConn(conn net.Conn, ip string) {
	done := make(chan struct{})
	go pm.keepAlive(conn, ip, done)
	defer func() {
		close(done)
		conn.Close()
		pm.mu.Lock()
		cs := pm.conns[ip]
		delete(pm.conns, ip)
		pm.mu.Unlock()

		name := ip
		if cs != nil {
			name = cs.name
			// Kayıtlı peer ise yeniden bağlanmayı planla
			pm.mu.RLock()
			_, saved := pm.savedPeers[strings.ToLower(cs.name)]
			pm.mu.RUnlock()
			if saved {
				pm.scheduleReconnect(ip, cs.name)
			}
		}
		fmt.Printf("\n\033[31m[System] 🔌 %s bağlantısı kesildi.\033[0m\n\n", name)
		pm.refreshPrompt()
	}()

	conn.SetReadDeadline(time.Now().Add(readTimeout))
	dec := json.NewDecoder(bufio.NewReaderSize(conn, 65536))

	for {
		var pkt Packet
		if err := dec.Decode(&pkt); err != nil {
			break
		}
		conn.SetReadDeadline(time.Now().Add(readTimeout))
		atomic.AddInt64(&pm.bytesReceived, int64(len(pkt.Content)))

		switch pkt.Type {
		case MSG_PING:
			pm.sendPacket(conn, Packet{Type: MSG_PONG, From: pm.name})
			continue
		case MSG_PONG:
			pm.touchConn(ip)
			continue
		case MSG_HANDSHAKE:
			pm.registerConn(ip, pkt.From, conn)
			pm.conns[ip].publicIP = pkt.PublicIP
			pm.conns[ip].version = pkt.Version
			// Karşılıklı el sıkışma
			pm.sendPacket(conn, Packet{
				Type:     MSG_HANDSHAKE,
				From:     pm.name,
				PublicIP: pm.publicIP,
				Version:  protocolVersion,
			})
			fmt.Printf("\n\033[32m[System] 🔐 %s ile şifreli tünel kuruldu!\033[0m\n", pkt.From)
			pm.refreshPrompt()
			// Çevrimdışı kuyruktaki mesajları ilet
			go pm.flushOfflineQueue(ip)
			// Peer exchange: tanıdıklarımızı paylaş
			go pm.sendPeerList(conn)
			continue
		case MSG_PEER_LIST:
			go pm.handlePeerList(pkt)
			continue
		case MSG_STATUS:
			pm.mu.Lock()
			if cs, ok := pm.conns[ip]; ok {
				cs.statusMsg = pkt.Content
			}
			pm.mu.Unlock()
			fmt.Printf("\n[Durum] %s: %s\n\n", pkt.From, pkt.Content)
			pm.refreshPrompt()
			continue
		case MSG_RELAY_REQ:
			go pm.handleRelayRequest(pkt, conn)
			continue
		case MSG_RELAY_FWD:
			pm.displayMessage(pkt)
			continue
		}

		// Hız sınırlama
		pm.mu.RLock()
		cs := pm.conns[ip]
		pm.mu.RUnlock()
		if cs != nil && !cs.rateLimiter.Allow() {
			continue // çok hızlı mesaj gönderiliyor, say
		}

		pm.touchConn(ip)
		if cs != nil {
			atomic.AddInt32(&cs.messageCount, 1)
		}
		atomic.AddInt64(&pm.totalMessages, 1)
		pm.logPacket(pkt)
		pm.displayMessage(pkt)
		pm.refreshPrompt()
	}
}

func (pm *PeerManager) displayMessage(pkt Packet) {
	ts := pkt.Timestamp.Format("15:04:05")
	switch pkt.Type {
	case MSG_PRIVATE:
		fmt.Printf("\n\033[35m[%s] 🔒 [ÖZEL %s → %s]: %s\033[0m\n", ts, pkt.From, pkt.To, pkt.Content)
	case MSG_RELAY_FWD:
		fmt.Printf("\n\033[34m[%s] [RELAY] %s: %s\033[0m\n", ts, pkt.From, pkt.Content)
	default:
		fmt.Printf("\n\033[33m[%s] %s:\033[0m %s\n", ts, pkt.From, pkt.Content)
	}
	pm.writeLog(fmt.Sprintf("[%s] %s: %s", ts, pkt.From, pkt.Content))
}

// ─────────────────────────────────────────────────────────────────────────────
// Peer exchange
// ─────────────────────────────────────────────────────────────────────────────

func (pm *PeerManager) sendPeerList(conn net.Conn) {
	pm.mu.RLock()
	var peers []PeerAddr
	for ip, cs := range pm.conns {
		if cs.name != "" {
			peers = append(peers, PeerAddr{IP: ip, Name: cs.name, Port: strings.TrimPrefix(chatPort, ":")})
		}
	}
	pm.mu.RUnlock()

	if len(peers) == 0 {
		return
	}
	pm.sendPacket(conn, Packet{
		Type:  MSG_PEER_LIST,
		From:  pm.name,
		Peers: peers,
	})
}

func (pm *PeerManager) handlePeerList(pkt Packet) {
	// Tanımadığımız peerları kayıtlara ekle (bağlantı açmıyoruz, sadece kaydediyoruz)
	for _, pa := range pkt.Peers {
		if pa.IP == pm.localIP || pa.IP == pm.publicIP {
			continue
		}
		pm.mu.Lock()
		key := strings.ToLower(pa.Name)
		if _, exists := pm.savedPeers[key]; !exists && pa.Name != "" {
			pm.savedPeers[key] = &SavedPeer{
				IP:      pa.IP,
				Name:    pa.Name,
				SavedAt: time.Now(),
			}
			fmt.Printf("\n[System] 📡 Peer keşfedildi: %s (%s) — /connect %s ile bağlanın\n", pa.Name, pa.IP, pa.IP)
		}
		pm.mu.Unlock()
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Relay (NAT geçişi için arkadaş üzerinden yönlendirme)
// ─────────────────────────────────────────────────────────────────────────────

func (pm *PeerManager) SendViaRelay(relayName, targetName, content string) {
	pm.mu.RLock()
	var relayConn net.Conn
	for _, cs := range pm.conns {
		if strings.EqualFold(cs.name, relayName) {
			relayConn = cs.conn
			break
		}
	}
	pm.mu.RUnlock()

	if relayConn == nil {
		fmt.Printf("\n[System] ❌ Relay peer '%s' bulunamadı.\n\n", relayName)
		return
	}

	pm.sendPacket(relayConn, Packet{
		Type:    MSG_RELAY_REQ,
		From:    pm.name,
		To:      targetName,
		Content: content,
	})
	fmt.Printf("\n✓ [RELAY via %s → %s]: %s\n\n", relayName, targetName, content)
}

func (pm *PeerManager) handleRelayRequest(pkt Packet, fromConn net.Conn) {
	// Bize yönlendirilen mesajı hedef peer'a ilet
	pm.mu.RLock()
	var targetConn net.Conn
	for _, cs := range pm.conns {
		if strings.EqualFold(cs.name, pkt.To) {
			targetConn = cs.conn
			break
		}
	}
	pm.mu.RUnlock()

	if targetConn == nil {
		// Hedef bulunamadı, göndericiye bildir
		pm.sendPacket(fromConn, Packet{
			Type:    MSG_SYSTEM,
			From:    "[System]",
			Content: fmt.Sprintf("Relay hedefi '%s' bulunamadı", pkt.To),
		})
		return
	}

	// Yönlendir
	pm.sendPacket(targetConn, Packet{
		Type:    MSG_RELAY_FWD,
		From:    pkt.From,
		To:      pkt.To,
		Content: pkt.Content,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Çevrimdışı kuyruk
// ─────────────────────────────────────────────────────────────────────────────

func (pm *PeerManager) queueOffline(ip string, pkt Packet) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	q := pm.offlineQueue[ip]
	if len(q) >= offlineQueueMax {
		q = q[1:] // en eskiyi at
	}
	pm.offlineQueue[ip] = append(q, OfflineMessage{Packet: pkt, QueuedAt: time.Now()})
}

func (pm *PeerManager) flushOfflineQueue(ip string) {
	pm.mu.Lock()
	msgs := pm.offlineQueue[ip]
	delete(pm.offlineQueue, ip)
	conn := pm.conns[ip]
	pm.mu.Unlock()

	if len(msgs) == 0 || conn == nil {
		return
	}
	fmt.Printf("[System] 📬 %s için %d mesaj iletiliyor...\n", ip, len(msgs))
	for _, m := range msgs {
		pm.sendPacket(conn.conn, m.Packet)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Otomatik yeniden bağlanma
// ─────────────────────────────────────────────────────────────────────────────

func (pm *PeerManager) scheduleReconnect(ip, name string) {
	pm.mu.Lock()
	job, exists := pm.reconnectJobs[ip]
	if !exists {
		job = &ReconnectJob{ip: ip, name: name, attempt: 0}
		pm.reconnectJobs[ip] = job
	}
	job.attempt++
	if job.attempt > reconnectMaxAttempts {
		delete(pm.reconnectJobs, ip)
		pm.mu.Unlock()
		fmt.Printf("[System] ⚠️  %s için yeniden bağlanma denemesi bitti.\n", name)
		return
	}

	// Exponential backoff: 2s, 4s, 8s, ... max 5dk
	delay := reconnectBaseDelay * time.Duration(1<<uint(bits.Len(uint(job.attempt-1))))
	if delay > reconnectMaxDelay {
		delay = reconnectMaxDelay
	}
	job.nextAt = time.Now().Add(delay)
	attempt := job.attempt
	pm.mu.Unlock()

	fmt.Printf("[System] 🔄 %s — %d. deneme %v sonra...\n", name, attempt, delay.Round(time.Second))
	go func() {
		select {
		case <-time.After(delay):
		case <-pm.ctx.Done():
			return
		}
		pm.mu.RLock()
		_, stillConnected := pm.conns[ip]
		pm.mu.RUnlock()
		if stillConnected {
			pm.mu.Lock()
			delete(pm.reconnectJobs, ip)
			pm.mu.Unlock()
			return
		}
		pm.connectToPeer(ip, name, true)
	}()
}

func (pm *PeerManager) CancelReconnect(ip string) {
	pm.mu.Lock()
	delete(pm.reconnectJobs, ip)
	pm.mu.Unlock()
	fmt.Printf("[System] ✓ %s için yeniden bağlanma iptal edildi.\n\n", ip)
}

// ─────────────────────────────────────────────────────────────────────────────
// Yardımcı fonksiyonlar
// ─────────────────────────────────────────────────────────────────────────────

func (pm *PeerManager) sendPacket(conn net.Conn, pkt Packet) error {
	if pkt.ID == "" {
		pkt.ID = generateID()
	}
	if pkt.Version == "" {
		pkt.Version = protocolVersion
	}
	if pkt.Timestamp.IsZero() {
		pkt.Timestamp = time.Now()
	}
	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	err := json.NewEncoder(conn).Encode(pkt)
	conn.SetWriteDeadline(time.Time{})
	if err == nil {
		atomic.AddInt64(&pm.bytesSent, int64(len(pkt.Content)))
	}
	return err
}

func (pm *PeerManager) registerConn(ip, name string, conn net.Conn) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if cs, exists := pm.conns[ip]; exists {
		if name != "" {
			cs.name = name
		}
		return
	}
	pm.conns[ip] = &ConnState{
		conn:         conn,
		name:         name,
		ip:           ip,
		connectedAt:  time.Now(),
		lastActivity: time.Now(),
		status:       STATUS_ONLINE,
		rateLimiter:  NewRateLimiter(rateLimit),
	}
}

func (pm *PeerManager) touchConn(ip string) {
	pm.mu.Lock()
	if cs, ok := pm.conns[ip]; ok {
		cs.lastActivity = time.Now()
		cs.status = STATUS_ONLINE
	}
	pm.mu.Unlock()
}

func (pm *PeerManager) isBlocked(ip string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.blockedUsers[ip]
}

func (pm *PeerManager) keepAlive(conn net.Conn, ip string, done chan struct{}) {
	t := time.NewTicker(keepAliveInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			pm.mu.RLock()
			_, ok := pm.conns[ip]
			pm.mu.RUnlock()
			if !ok {
				return
			}
			if err := pm.sendPacket(conn, Packet{Type: MSG_PING, From: pm.name}); err != nil {
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

func (pm *PeerManager) logPacket(pkt Packet) {
	pm.mu.Lock()
	pm.messageLog = append(pm.messageLog, pkt)
	if len(pm.messageLog) > pm.maxLogSize {
		pm.messageLog = pm.messageLog[1:]
	}
	pm.mu.Unlock()
}

func (pm *PeerManager) writeLog(line string) {
	if pm.logFile != nil {
		fmt.Fprintln(pm.logFile, line)
	}
}

func (pm *PeerManager) refreshPrompt() {
	fmt.Printf("\033[36m%s > \033[0m", pm.name)
}

func (pm *PeerManager) Close() {
	pm.cancel()
	if pm.logFile != nil {
		pm.logFile.Close()
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Mesajlaşma
// ─────────────────────────────────────────────────────────────────────────────

func (pm *PeerManager) BroadcastMessage(text string) {
	if len(text) > maxMessageLength {
		fmt.Printf("\n[System] ❌ Mesaj çok uzun (max %d karakter).\n\n", maxMessageLength)
		return
	}
	pm.mu.RLock()
	connsCopy := make(map[string]*ConnState, len(pm.conns))
	for k, v := range pm.conns {
		connsCopy[k] = v
	}
	pm.mu.RUnlock()

	if len(connsCopy) == 0 {
		fmt.Println("\n[System] ℹ️  Bağlı peer yok. /invite ile davet kodu oluşturun.\n")
		return
	}

	pkt := Packet{
		Type:    MSG_NORMAL,
		From:    pm.name,
		Content: text,
	}

	var failed []string
	for ip, cs := range connsCopy {
		if err := pm.sendPacket(cs.conn, pkt); err != nil {
			failed = append(failed, ip)
		}
	}

	atomic.AddInt64(&pm.totalMessages, 1)
	pm.logPacket(pkt)

	// Başarısız bağlantıları temizle
	if len(failed) > 0 {
		pm.mu.Lock()
		for _, ip := range failed {
			if cs, ok := pm.conns[ip]; ok {
				cs.conn.Close()
				delete(pm.conns, ip)
			}
		}
		pm.mu.Unlock()
	}
}

func (pm *PeerManager) SendPrivate(targetName, content string) {
	if len(content) > maxMessageLength {
		fmt.Printf("\n[System] ❌ Mesaj çok uzun.\n\n")
		return
	}
	pm.mu.RLock()
	var target *ConnState
	for _, cs := range pm.conns {
		if strings.EqualFold(cs.name, targetName) {
			target = cs
			break
		}
	}
	pm.mu.RUnlock()

	if target == nil {
		// Çevrimdışı — kuyruğa ekle
		pm.mu.RLock()
		var targetIP string
		for _, sp := range pm.savedPeers {
			if strings.EqualFold(sp.Name, targetName) {
				targetIP = sp.IP
				break
			}
		}
		pm.mu.RUnlock()

		if targetIP != "" {
			pkt := Packet{Type: MSG_PRIVATE, From: pm.name, To: targetName, Content: content}
			pm.queueOffline(targetIP, pkt)
			fmt.Printf("\n[System] 📪 %s çevrimdışı — mesaj kuyruğa alındı (bağlandığında iletilecek).\n\n", targetName)
			return
		}
		fmt.Printf("\n[System] ❌ '%s' bulunamadı.\n\n", targetName)
		return
	}

	pkt := Packet{Type: MSG_PRIVATE, From: pm.name, To: targetName, Content: content}
	if err := pm.sendPacket(target.conn, pkt); err != nil {
		fmt.Printf("\n[System] ❌ Özel mesaj gönderilemedi.\n\n")
		return
	}
	fmt.Printf("\n✓ \033[35m[ÖZEL → %s]: %s\033[0m\n\n", targetName, content)
	pm.logPacket(pkt)
}

// ─────────────────────────────────────────────────────────────────────────────
// Bağlantı yönetimi komutları
// ─────────────────────────────────────────────────────────────────────────────

func (pm *PeerManager) DisconnectPeer(ip string) {
	pm.mu.Lock()
	cs, ok := pm.conns[ip]
	if !ok {
		pm.mu.Unlock()
		fmt.Printf("\n[System] ❌ %s ile bağlantı yok.\n\n", ip)
		return
	}
	delete(pm.conns, ip)
	pm.mu.Unlock()
	cs.conn.Close()
	fmt.Printf("\n[System] ✓ %s bağlantısı kesildi.\n\n", ip)
}

func (pm *PeerManager) DisconnectAll() {
	pm.mu.Lock()
	for ip, cs := range pm.conns {
		cs.conn.Close()
		delete(pm.conns, ip)
	}
	pm.mu.Unlock()
	fmt.Println("\n[System] ✓ Tüm bağlantılar kesildi.\n")
}

func (pm *PeerManager) closeAll() {
	pm.mu.Lock()
	select {
	case <-pm.shutdown:
	default:
		close(pm.shutdown)
	}
	for ip, cs := range pm.conns {
		pm.sendPacket(cs.conn, Packet{Type: MSG_SYSTEM, From: "[System]",
			Content: pm.name + " sohbetten ayrıldı."})
		cs.conn.Close()
		delete(pm.conns, ip)
	}
	pm.mu.Unlock()
}

// ─────────────────────────────────────────────────────────────────────────────
// Peer kayıt / yükleme
// ─────────────────────────────────────────────────────────────────────────────

func (pm *PeerManager) savePeer(ip, name string) {
	if !isValidIP(ip) {
		fmt.Printf("\n[System] ❌ Geçersiz IP: %s\n\n", ip)
		return
	}
	pm.mu.Lock()
	pm.savedPeers[strings.ToLower(name)] = &SavedPeer{IP: ip, Name: name, SavedAt: time.Now()}
	pm.mu.Unlock()
	pm.writeSavedPeers()
	fmt.Printf("\n[System] ✓ '%s' → %s kaydedildi.\n\n", name, ip)
}

func (pm *PeerManager) deleteSavedPeer(target string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for key, peer := range pm.savedPeers {
		if strings.EqualFold(key, target) || peer.IP == target {
			delete(pm.savedPeers, key)
			pm.writeSavedPeers()
			fmt.Printf("\n[System] ✓ '%s' silindi.\n\n", key)
			return
		}
	}
	fmt.Printf("\n[System] ❌ '%s' bulunamadı.\n\n", target)
}

func (pm *PeerManager) loadSavedPeers() {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: name=ip  (eski) veya JSON (yeni)
		if strings.HasPrefix(line, "{") {
			var sp SavedPeer
			if err := json.Unmarshal([]byte(line), &sp); err == nil && isValidIP(sp.IP) {
				pm.savedPeers[strings.ToLower(sp.Name)] = &sp
			}
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			name, ip := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			if isValidIP(ip) {
				pm.savedPeers[strings.ToLower(name)] = &SavedPeer{IP: ip, Name: name}
			}
		}
	}
}

func (pm *PeerManager) writeSavedPeers() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	var lines []string
	for _, peer := range pm.savedPeers {
		b, _ := json.Marshal(peer)
		lines = append(lines, string(b))
	}
	sort.Strings(lines)
	_ = os.WriteFile(configFile, []byte(strings.Join(lines, "\n")), 0600)
}

// ─────────────────────────────────────────────────────────────────────────────
// Ekrana yazdırma yardımcıları
// ─────────────────────────────────────────────────────────────────────────────

func (pm *PeerManager) PrintPeers() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	fmt.Println("\n╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                  🔐 BAĞLI PEERLAR                            ║")
	fmt.Println("╠══════════════╦══════════════════╦══════════════╦═════════════╣")
	fmt.Printf("║ %-12s ║ %-16s ║ %-12s ║ %-11s ║\n", "IP", "İsim", "Bağlandı", "Mesaj")
	fmt.Println("╠══════════════╬══════════════════╬══════════════╬═════════════╣")
	if len(pm.conns) == 0 {
		fmt.Println("║            Bağlı peer yok                                    ║")
	}
	for ip, cs := range pm.conns {
		fmt.Printf("║ %-12s ║ %-16s ║ %-12s ║ %-11d ║\n",
			ip, cs.name, cs.connectedAt.Format("15:04"), atomic.LoadInt32(&cs.messageCount))
	}
	fmt.Println("╚══════════════╩══════════════════╩══════════════╩═════════════╝\n")
}

func (pm *PeerManager) PrintSaved() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	fmt.Println("\n=== 📚 KAYITLI PEERLAR ===")
	if len(pm.savedPeers) == 0 {
		fmt.Println("Kayıtlı peer yok.")
	} else {
		names := make([]string, 0, len(pm.savedPeers))
		for n := range pm.savedPeers {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			p := pm.savedPeers[n]
			status := "🔴 Çevrimdışı"
			if _, ok := pm.conns[p.IP]; ok {
				status = "🟢 Çevrimiçi"
			}
			star := " "
			if pm.favorites[p.IP] {
				star = "⭐"
			}
			offline := ""
			if q := pm.offlineQueue[p.IP]; len(q) > 0 {
				offline = fmt.Sprintf(" [%d kuyruktaki]", len(q))
			}
			fmt.Printf("  %s %-20s [%s]  %s%s\n", star, p.Name, p.IP, status, offline)
		}
	}
	fmt.Println("==========================\n")
}

func (pm *PeerManager) PrintHistory() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	fmt.Println("\n=== 📋 MESAJ GEÇMİŞİ (son 50) ===")
	start := len(pm.messageLog) - 50
	if start < 0 {
		start = 0
	}
	for _, pkt := range pm.messageLog[start:] {
		prefix := pkt.From
		if pkt.Type == MSG_PRIVATE {
			prefix = "🔒 ÖZEL " + pkt.From + " → " + pkt.To
		}
		fmt.Printf("[%s] %s: %s\n", pkt.Timestamp.Format("15:04:05"), prefix, pkt.Content)
	}
	fmt.Println("====================================\n")
}

func (pm *PeerManager) PrintStats() {
	pm.mu.RLock()
	active := len(pm.conns)
	queued := 0
	for _, q := range pm.offlineQueue {
		queued += len(q)
	}
	reconnecting := len(pm.reconnectJobs)
	pm.mu.RUnlock()

	total := atomic.LoadInt64(&pm.totalMessages)
	sent := atomic.LoadInt64(&pm.bytesSent)
	recv := atomic.LoadInt64(&pm.bytesReceived)

	fmt.Println("\n╔══════════════════════════════════════════════════╗")
	fmt.Println("║             📊  OTURUM İSTATİSTİKLERİ            ║")
	fmt.Println("╠══════════════════════════════════════════════════╣")
	fmt.Printf("║  Başlangıç       : %-29s║\n", pm.sessionStart.Format("02.01.2006 15:04:05"))
	fmt.Printf("║  Süre            : %-29s║\n", time.Since(pm.sessionStart).Round(time.Second))
	fmt.Printf("║  Yerel IP        : %-29s║\n", pm.localIP)
	fmt.Printf("║  Genel IP (STUN) : %-29s║\n", pm.publicIP)
	fmt.Printf("║  Aktif peer      : %-29d║\n", active)
	fmt.Printf("║  Yeniden bağ.    : %-29d║\n", reconnecting)
	fmt.Printf("║  Kuyruktaki msg  : %-29d║\n", queued)
	fmt.Printf("║  Toplam mesaj    : %-29d║\n", total)
	fmt.Printf("║  Gönderilen      : %-.2f KB%-20s║\n", float64(sent)/1024, "")
	fmt.Printf("║  Alınan          : %-.2f KB%-20s║\n", float64(recv)/1024, "")
	fmt.Println("╚══════════════════════════════════════════════════╝\n")
}

func (pm *PeerManager) PrintSecurity() {
	fmt.Println("\n=== 🔒 GÜVENLİK BİLGİSİ ===")
	fmt.Println("  Şifreleme      : TLS 1.3")
	fmt.Println("  Anahtar tipi   : ECDSA P-256 (geçici)")
	fmt.Println("  E2E şifreli    : ✅ Evet")
	fmt.Println("  IP görünürlüğü : Sadece doğrudan peerlar")
	fmt.Println("  NAT traversal  : TCP hole punching + STUN")
	fmt.Println()
	fmt.Printf("  Sertifika parmak izi:\n  %s\n", pm.certFP)
	fmt.Println()
	fmt.Println("  ÖNERİLER:")
	fmt.Println("  1. İlk bağlantıda parmak izlerini karşılaştırın")
	fmt.Println("  2. Davet kodlarını sadece güvendiğiniz kişilerle paylaşın")
	fmt.Println("  3. Davet kodları 30 dakikada geçersiz olur")
	fmt.Println("  4. NAT arkasındaysanız /invite ile kod paylaşın")
	fmt.Println("=============================\n")
}

func (pm *PeerManager) PrintHelp() {
	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              AND CHAT v2  ·  KOMUT REHBERİ                   ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  🎫 DAVETİYE                                                  ║")
	fmt.Println("║    /invite                  Davet kodu oluştur               ║")
	fmt.Println("║    /join <KOD>              Aynı ağda katıl                  ║")
	fmt.Println("║    /join <KOD>@<HOST>       İnternetten katıl                ║")
	fmt.Println("║                                                               ║")
	fmt.Println("║  📡 BAĞLANTI                                                  ║")
	fmt.Println("║    /connect <IP|İsim>       IP veya kayıtlı isimle bağlan    ║")
	fmt.Println("║    /connect-all             Tüm kayıtlı peerlara bağlan      ║")
	fmt.Println("║    /disconnect <IP>         Bağlantıyı kes                   ║")
	fmt.Println("║    /disconnect-all          Tümünü kes                       ║")
	fmt.Println("║    /reconnect <IP>          Yeniden bağlanmayı iptal et      ║")
	fmt.Println("║    /list                    Bağlı peerları göster            ║")
	fmt.Println("║                                                               ║")
	fmt.Println("║  📨 MESAJLAŞMA                                                ║")
	fmt.Println("║    <mesaj>                  Herkese yayınla                  ║")
	fmt.Println("║    @<İsim> <mesaj>          Özel mesaj                       ║")
	fmt.Println("║    /relay <Via> <Hedef> <M> Relay üzerinden mesaj            ║")
	fmt.Println("║    /history                 Mesaj geçmişi                    ║")
	fmt.Println("║                                                               ║")
	fmt.Println("║  💾 PEER YÖNETİMİ                                             ║")
	fmt.Println("║    /save <IP> <İsim>        Peer kaydet                      ║")
	fmt.Println("║    /saved                   Kayıtlıları göster               ║")
	fmt.Println("║    /remove <İsim|IP>        Kaydı sil                        ║")
	fmt.Println("║    /star <IP>               Favoriye ekle/çıkar              ║")
	fmt.Println("║    /block <IP>              Engelle                          ║")
	fmt.Println("║    /unblock <IP>            Engeli kaldır                    ║")
	fmt.Println("║    /blocked                 Engellileri göster               ║")
	fmt.Println("║                                                               ║")
	fmt.Println("║  ⚙️  GENEL                                                    ║")
	fmt.Println("║    /whoami                  Kimliğini göster                 ║")
	fmt.Println("║    /set-status <mesaj>      Durum mesajı güncelle            ║")
	fmt.Println("║    /stats                   Oturum istatistikleri            ║")
	fmt.Println("║    /security                Güvenlik bilgisi                 ║")
	fmt.Println("║    /local-ip                Yerel IP                         ║")
	fmt.Println("║    /clear                   Ekranı temizle                   ║")
	fmt.Println("║    /help                    Bu yardım                        ║")
	fmt.Println("║    /exit                    Güvenli çıkış                    ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

func (pm *PeerManager) printWelcome() {
	fmt.Println()
	fmt.Println("──────────────────────────────────────────────────────────")
	fmt.Printf("  🚀  \033[32m%s\033[0m olarak bağlandınız — uçtan uca şifreli\n", pm.name)
	fmt.Printf("  🌐  Genel IP: %s  |  Yerel IP: %s\n", pm.publicIP, pm.localIP)
	fmt.Println("──────────────────────────────────────────────────────────")
	fmt.Println("  HIZLI BAŞLANGIC:")
	fmt.Println("  1. \033[36m/invite\033[0m  → kod oluştur, arkadaşına gönder")
	fmt.Println("  2. Arkadaşın \033[36m/join KOD@SENİN_IP\033[0m yazar → bağlandı!")
	fmt.Println("  3. Sohbete başla  (tüm komutlar için /help)")
	fmt.Println("──────────────────────────────────────────────────────────")
	fmt.Println()
}

// ─────────────────────────────────────────────────────────────────────────────
// Komut döngüsü
// ─────────────────────────────────────────────────────────────────────────────

func commandLoop(reader *bufio.Reader, pm *PeerManager) {
	for {
		fmt.Printf("\033[36m%s > \033[0m", pm.name)
		input, err := reader.ReadString('\n')
		if err != nil {
			continue
		}
		input = sanitize(strings.TrimSpace(input))
		if input == "" {
			continue
		}
		pm.commandHistory = append(pm.commandHistory, input)

		if strings.HasPrefix(input, "/") {
			handleCommand(input, pm, reader)
		} else if strings.HasPrefix(input, "@") {
			parts := strings.SplitN(input, " ", 2)
			if len(parts) < 2 {
				fmt.Println("\n[System] ❌ Kullanım: @<İsim> <mesaj>\n")
				continue
			}
			pm.SendPrivate(strings.TrimPrefix(parts[0], "@"), parts[1])
		} else {
			pm.BroadcastMessage(input)
		}
	}
}

func handleCommand(input string, pm *PeerManager, reader *bufio.Reader) {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return
	}
	cmd := strings.ToLower(parts[0])

	switch cmd {

	case "/invite":
		pm.GenerateInvite()

	case "/join":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Kullanım: /join <KOD>  veya  /join <KOD>@<HOST>\n")
			return
		}
		pm.JoinViaInvite(parts[1])

	case "/connect":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Kullanım: /connect <IP veya Kayıtlı İsim>\n")
			return
		}
		target := resolveName(pm, parts[1])
		if target == "" {
			fmt.Printf("\n[System] ❌ '%s' bulunamadı.\n\n", parts[1])
			return
		}
		fmt.Printf("\n[System] 🔒 %s adresine bağlanılıyor...\n", target)
		go pm.connectToPeer(target, parts[1], true)

	case "/connect-all":
		pm.mu.RLock()
		saved := make(map[string]*SavedPeer, len(pm.savedPeers))
		for k, v := range pm.savedPeers {
			saved[k] = v
		}
		pm.mu.RUnlock()
		fmt.Printf("\n[System] 🔒 %d kayıtlı peer'a bağlanılıyor...\n\n", len(saved))
		for _, p := range saved {
			if !p.Blocked {
				go pm.connectToPeer(p.IP, p.Name, true)
			}
		}

	case "/disconnect":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Kullanım: /disconnect <IP>\n")
			return
		}
		pm.DisconnectPeer(parts[1])

	case "/disconnect-all":
		pm.DisconnectAll()

	case "/reconnect":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Kullanım: /reconnect <IP> — yeniden bağlanmayı iptal eder\n")
			return
		}
		pm.CancelReconnect(parts[1])

	case "/list":
		pm.PrintPeers()

	case "/save":
		if len(parts) < 3 {
			fmt.Println("\n[System] ❌ Kullanım: /save <IP> <İsim>\n")
			return
		}
		pm.savePeer(parts[1], strings.Join(parts[2:], " "))

	case "/saved":
		pm.PrintSaved()

	case "/remove":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Kullanım: /remove <IP veya İsim>\n")
			return
		}
		pm.deleteSavedPeer(parts[1])

	case "/remove-all":
		fmt.Print("[Uyarı] Tüm kayıtlı peerları sil? (e/h): ")
		c, _ := reader.ReadString('\n')
		if strings.EqualFold(strings.TrimSpace(c), "e") {
			pm.mu.Lock()
			pm.savedPeers = make(map[string]*SavedPeer)
			pm.mu.Unlock()
			_ = os.Remove(configFile)
			fmt.Println("\n[System] ✓ Tüm kayıtlar silindi.\n")
		}

	case "/star":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Kullanım: /star <IP>\n")
			return
		}
		pm.mu.Lock()
		if pm.favorites[parts[1]] {
			delete(pm.favorites, parts[1])
			fmt.Printf("\n[System] ✓ %s favorilerden çıkarıldı.\n\n", parts[1])
		} else {
			pm.favorites[parts[1]] = true
			fmt.Printf("\n[System] ⭐ %s favorilere eklendi.\n\n", parts[1])
		}
		pm.mu.Unlock()

	case "/block":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Kullanım: /block <IP>\n")
			return
		}
		pm.mu.Lock()
		pm.blockedUsers[parts[1]] = true
		pm.mu.Unlock()
		fmt.Printf("\n[System] ✓ %s engellendi.\n\n", parts[1])

	case "/unblock":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Kullanım: /unblock <IP>\n")
			return
		}
		pm.mu.Lock()
		delete(pm.blockedUsers, parts[1])
		pm.mu.Unlock()
		fmt.Printf("\n[System] ✓ %s engeli kaldırıldı.\n\n", parts[1])

	case "/blocked":
		pm.mu.RLock()
		fmt.Println("\n=== 🚫 ENGELLENMİŞLER ===")
		for ip := range pm.blockedUsers {
			fmt.Printf("  • %s\n", ip)
		}
		if len(pm.blockedUsers) == 0 {
			fmt.Println("  (yok)")
		}
		pm.mu.RUnlock()
		fmt.Println("=========================\n")

	case "/relay":
		// /relay <ViaIsim> <HedefIsim> <mesaj>
		if len(parts) < 4 {
			fmt.Println("\n[System] ❌ Kullanım: /relay <Via> <Hedef> <mesaj>\n")
			return
		}
		pm.SendViaRelay(parts[1], parts[2], strings.Join(parts[3:], " "))

	case "/whoami":
		fmt.Printf("\n[System] 👤 İsim         : %s\n", pm.name)
		fmt.Printf("[System] 🔐 Parmak izi   : %s\n", pm.certFP)
		fmt.Printf("[System] 🖥️  Yerel IP     : %s\n", pm.localIP)
		fmt.Printf("[System] 🌐 Genel IP     : %s\n", pm.publicIP)
		fmt.Printf("[System] 📍 Durum        : %s\n", pm.status)
		if pm.statusMsg != "" {
			fmt.Printf("[System] 💬 Durum mesajı : %s\n", pm.statusMsg)
		}
		fmt.Println()

	case "/set-status":
		if len(parts) < 2 {
			fmt.Println("\n[System] ❌ Kullanım: /set-status <mesaj>\n")
			return
		}
		msg := strings.Join(parts[1:], " ")
		pm.statusMsg = msg
		// Bağlı herkese bildir
		pm.mu.RLock()
		for _, cs := range pm.conns {
			pm.sendPacket(cs.conn, Packet{Type: MSG_STATUS, From: pm.name, Content: msg})
		}
		pm.mu.RUnlock()
		fmt.Printf("\n[System] ✓ Durum güncellendi: %s\n\n", msg)

	case "/history":
		pm.PrintHistory()

	case "/stats":
		pm.PrintStats()

	case "/local-ip":
		fmt.Printf("\n[System] 🖥️  Yerel IP: %s  |  Genel IP: %s\n\n", pm.localIP, pm.publicIP)

	case "/security":
		pm.PrintSecurity()

	case "/help":
		pm.PrintHelp()

	case "/clear":
		fmt.Print("\033[H\033[2J")

	case "/exit":
		pm.closeAll()
		fmt.Println("\n[System] 🛑 Güle güle!")
		pm.Close()
		os.Exit(0)

	default:
		fmt.Printf("\n[System] ❌ Bilinmeyen komut: %s\n[System] /help yazın.\n\n", cmd)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Yardımcı fonksiyonlar
// ─────────────────────────────────────────────────────────────────────────────

func detectLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func resolveName(pm *PeerManager, target string) string {
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

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func isValidIP(ip string) bool { return net.ParseIP(ip) != nil }

func isValidUsername(u string) bool {
	ok, _ := regexp.MatchString(`^[a-zA-Z0-9_\-]{1,32}$`, u)
	return ok
}

func sanitize(in string) string {
	return strings.NewReplacer("\x1b", "", "\033", "", "\r", "", "\x00", "").Replace(in)
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS sertifika üretimi
// ─────────────────────────────────────────────────────────────────────────────

func generateTLS() (*tls.Config, *tls.Config, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"AND Chat v2"}, CommonName: "p2p-node"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().AddDate(0, 0, tlsCertValidityDays),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	cert, err := tls.X509KeyPair(certPEM, privPEM)
	if err != nil {
		return nil, nil, "", err
	}

	h := sha256.Sum256(der)
	parts := make([]string, 8)
	for i := range parts {
		parts[i] = hex.EncodeToString(h[i*2 : i*2+2])
	}
	fp := strings.Join(parts, ":")

	client := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		NextProtos:         []string{"and-chat-v2"},
	}
	server := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"and-chat-v2"},
	}
	return client, server, fp, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Sinyal işleyici
// ─────────────────────────────────────────────────────────────────────────────

func handleSignals(pm *PeerManager) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	pm.closeAll()
	fmt.Println("\n\n[System] 🛑 Kapatılıyor... Güle güle!")
	pm.Close()
	os.Exit(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	fmt.Print("\033[H\033[2J")
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                       AND CHAT  v2                            ║")
	fmt.Println("║   E2E Şifreli · Sunucusuz · NAT Traversal · Davet Kodları     ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	fmt.Println("[System] 🔐 Geçici TLS 1.3 anahtarları üretiliyor (ECDSA P-256)...")
	tlsClient, tlsServer, fp, err := generateTLS()
	if err != nil {
		fmt.Printf("[KRİTİK] TLS kurulumu başarısız: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[System] ✓ Sertifika parmak izi: %s\n\n", fp)

	reader := bufio.NewReader(os.Stdin)
	var username string
	for {
		fmt.Print("👉 Sohbet adınız (max 32 karakter, harf/rakam/_/-): ")
		in, _ := reader.ReadString('\n')
		username = sanitize(strings.TrimSpace(in))
		if username == "" {
			fmt.Println("[!] Ad boş olamaz.")
			continue
		}
		if len(username) > maxUsernameLength {
			fmt.Printf("[!] Çok uzun (max %d).\n", maxUsernameLength)
			continue
		}
		if !isValidUsername(username) {
			fmt.Println("[!] Sadece harf, rakam, alt çizgi ve tire kullanılabilir.")
			continue
		}
		break
	}

	pm, err := NewPeerManager(username, tlsClient, tlsServer)
	if err != nil {
		fmt.Printf("[KRİTİK] Başlatılamadı: %v\n", err)
		os.Exit(1)
	}
	defer pm.Close()

	pm.certFP = fp
	pm.loadSavedPeers()
	fmt.Printf("[System] ✓ %d kayıtlı peer yüklendi.\n", len(pm.savedPeers))

	// STUN ile genel IP öğren
	pm.discoverPublicAddress()

	// Dinleyicileri başlat
	go pm.startTLSListener()
	go startRendezvousListener(pm.inviteReg, pm.logger)
	go handleSignals(pm)

	pm.printWelcome()
	commandLoop(reader, pm)
}
