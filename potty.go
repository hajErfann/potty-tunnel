package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"gopkg.in/yaml.v3"
)

const version = "1.0.0"

// ============================================================================
// Configuration Structures
// ============================================================================

type Config struct {
	Mode        string          `yaml:"mode"`         // server or client
	Listen      string          `yaml:"listen"`       // server listen address
	Transport   string          `yaml:"transport"`    // tcpmux, kcpmux, wsmux, wssmux
	PSK         string          `yaml:"psk"`          // pre-shared key
	Profile     string          `yaml:"profile"`      // balanced|aggressive|latency|cpu-efficient
	Verbose     bool            `yaml:"verbose"`      // verbose logging
	CertFile    string          `yaml:"cert_file"`    // TLS cert for wssmux
	KeyFile     string          `yaml:"key_file"`     // TLS key for wssmux
	MaxSessions int             `yaml:"max_sessions"` // max sessions (0=unlimited)
	Heartbeat   int             `yaml:"heartbeat"`    // heartbeat interval
	Mappings    []PortMapping   `yaml:"maps"`         // port mappings
	Paths       []PathConfig    `yaml:"paths"`        // multi-path for client
	SMUX        SMUXConfig      `yaml:"smux"`         // SMUX settings
	KCP         KCPConfig       `yaml:"kcp"`          // KCP settings
	Advanced    AdvancedConfig  `yaml:"advanced"`     // advanced settings
}

type PathConfig struct {
	Transport      string `yaml:"transport"`
	Addr           string `yaml:"addr"`
	ConnectionPool int    `yaml:"connection_pool"`
	AggressivePool bool   `yaml:"aggressive_pool"`
	RetryInterval  int    `yaml:"retry_interval"`
	DialTimeout    int    `yaml:"dial_timeout"`
}

type PortMapping struct {
	Type   string `yaml:"type"`   // tcp or udp
	Bind   string `yaml:"bind"`   // bind address
	Target string `yaml:"target"` // target address
}

type SMUXConfig struct {
	KeepAlive int `yaml:"keepalive"`
	MaxRecv   int `yaml:"max_recv"`
	MaxStream int `yaml:"max_stream"`
	FrameSize int `yaml:"frame_size"`
	Version   int `yaml:"version"`
}

type KCPConfig struct {
	NoDelay  int `yaml:"nodelay"`
	Interval int `yaml:"interval"`
	Resend   int `yaml:"resend"`
	NC       int `yaml:"nc"`
	SndWnd   int `yaml:"sndwnd"`
	RcvWnd   int `yaml:"rcvwnd"`
	MTU      int `yaml:"mtu"`
}

type AdvancedConfig struct {
	// TCP Settings
	TCPNoDelay      bool `yaml:"tcp_nodelay"`
	TCPKeepAlive    int  `yaml:"tcp_keepalive"`
	TCPReadBuffer   int  `yaml:"tcp_read_buffer"`
	TCPWriteBuffer  int  `yaml:"tcp_write_buffer"`

	// WebSocket Settings
	WebSocketReadBuffer  int  `yaml:"websocket_read_buffer"`
	WebSocketWriteBuffer int  `yaml:"websocket_write_buffer"`
	WebSocketCompression bool `yaml:"websocket_compression"`

	// Connection Management
	CleanupInterval    int `yaml:"cleanup_interval"`
	SessionTimeout     int `yaml:"session_timeout"`
	ConnectionTimeout  int `yaml:"connection_timeout"`
	StreamTimeout      int `yaml:"stream_timeout"`
	MaxConnections     int `yaml:"max_connections"`

	// UDP Flow Management
	MaxUDPFlows    int `yaml:"max_udp_flows"`
	UDPFlowTimeout int `yaml:"udp_flow_timeout"`

	// Buffer Pool Sizes
	BufferPoolSize      int `yaml:"buffer_pool_size"`
	LargeBufferPoolSize int `yaml:"large_buffer_pool_size"`
	UDPFramePoolSize    int `yaml:"udp_frame_pool_size"`
	UDPDataSliceSize    int `yaml:"udp_data_slice_size"`
}

// Apply profile defaults
func (c *Config) applyProfile() {
	profiles := map[string]map[string]interface{}{
		"balanced": {
			"smux_keepalive": 8, "smux_recv": 8388608, "smux_stream": 8388608,
			"kcp_nodelay": 1, "kcp_interval": 10, "kcp_sndwnd": 768, "kcp_rcvwnd": 768,
		},
		"aggressive": {
			"smux_keepalive": 5, "smux_recv": 16777216, "smux_stream": 16777216,
			"kcp_nodelay": 1, "kcp_interval": 8, "kcp_sndwnd": 1024, "kcp_rcvwnd": 1024,
		},
		"latency": {
			"smux_keepalive": 3, "smux_recv": 4194304, "smux_stream": 4194304,
			"kcp_nodelay": 1, "kcp_interval": 8, "kcp_sndwnd": 768, "kcp_rcvwnd": 768,
		},
		"cpu-efficient": {
			"smux_keepalive": 10, "smux_recv": 8388608, "smux_stream": 8388608,
			"kcp_nodelay": 0, "kcp_interval": 20, "kcp_sndwnd": 512, "kcp_rcvwnd": 512,
		},
	}

	if p, ok := profiles[c.Profile]; ok {
		if c.SMUX.KeepAlive == 0 {
			c.SMUX.KeepAlive = p["smux_keepalive"].(int)
			c.SMUX.MaxRecv = p["smux_recv"].(int)
			c.SMUX.MaxStream = p["smux_stream"].(int)
		}
		if c.KCP.NoDelay == 0 && c.KCP.SndWnd == 0 {
			c.KCP.NoDelay = p["kcp_nodelay"].(int)
			c.KCP.Interval = p["kcp_interval"].(int)
			c.KCP.Resend = 2
			c.KCP.NC = 1
			c.KCP.SndWnd = p["kcp_sndwnd"].(int)
			c.KCP.RcvWnd = p["kcp_rcvwnd"].(int)
			c.KCP.MTU = 1350
		}
	}

	// Apply defaults
	if c.SMUX.FrameSize == 0 {
		c.SMUX.FrameSize = 32768
	}
	if c.SMUX.Version == 0 {
		c.SMUX.Version = 2
	}
	if c.Heartbeat == 0 {
		c.Heartbeat = 10
	}
	if c.Advanced.TCPKeepAlive == 0 {
		c.Advanced.TCPKeepAlive = 15
	}
	if c.Advanced.TCPReadBuffer == 0 {
		c.Advanced.TCPReadBuffer = 4194304
	}
	if c.Advanced.TCPWriteBuffer == 0 {
		c.Advanced.TCPWriteBuffer = 4194304
	}
	if c.Advanced.WebSocketReadBuffer == 0 {
		c.Advanced.WebSocketReadBuffer = 262144
	}
	if c.Advanced.WebSocketWriteBuffer == 0 {
		c.Advanced.WebSocketWriteBuffer = 262144
	}
	if c.Advanced.MaxConnections == 0 {
		c.Advanced.MaxConnections = 2000
	}
	if c.Advanced.MaxUDPFlows == 0 {
		c.Advanced.MaxUDPFlows = 1000
	}
	if c.Advanced.UDPFlowTimeout == 0 {
		c.Advanced.UDPFlowTimeout = 300
	}
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	config.applyProfile()
	return &config, nil
}

func generateDefaultConfig(path string, mode string) error {
	config := &Config{
		Mode:      mode,
		Transport: "tcpmux",
		PSK:       "change_me_please",
		Profile:   "balanced",
		Verbose:   false,
		Heartbeat: 10,
		SMUX: SMUXConfig{
			KeepAlive: 8,
			MaxRecv:   8388608,
			MaxStream: 8388608,
			FrameSize: 32768,
			Version:   2,
		},
		KCP: KCPConfig{
			NoDelay: 1, Interval: 10, Resend: 2, NC: 1,
			SndWnd: 768, RcvWnd: 768, MTU: 1350,
		},
		Advanced: AdvancedConfig{
			TCPNoDelay:           true,
			TCPKeepAlive:         15,
			TCPReadBuffer:        4194304,
			TCPWriteBuffer:       4194304,
			WebSocketReadBuffer:  262144,
			WebSocketWriteBuffer: 262144,
			CleanupInterval:      3,
			SessionTimeout:       30,
			ConnectionTimeout:    60,
			StreamTimeout:        120,
			MaxConnections:       2000,
			MaxUDPFlows:          1000,
			UDPFlowTimeout:       300,
		},
	}

	if mode == "server" {
		config.Listen = "0.0.0.0:4000"
		config.Mappings = []PortMapping{
			{Type: "tcp", Bind: "0.0.0.0:2222", Target: "127.0.0.1:22"},
		}
	} else {
		config.Paths = []PathConfig{
			{
				Transport:      "tcpmux",
				Addr:           "YOUR_SERVER_IP:4000",
				ConnectionPool: 2,
				RetryInterval:  3,
				DialTimeout:    10,
			},
		}
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// ============================================================================
// Transport Layer
// ============================================================================

type Transport interface {
	Listen(config *Config) (net.Listener, error)
	Dial(addr string, config *Config) (net.Conn, error)
}

// TCP Transport
type TCPTransport struct{}

func (t *TCPTransport) Listen(config *Config) (net.Listener, error) {
	return net.Listen("tcp", config.Listen)
}

func (t *TCPTransport) Dial(addr string, config *Config) (net.Conn, error) {
	timeout := time.Duration(config.Advanced.ConnectionTimeout) * time.Second
	return net.DialTimeout("tcp", addr, timeout)
}

// KCP Transport
type KCPTransport struct{}

func (t *KCPTransport) Listen(config *Config) (net.Listener, error) {
	key := generateKey(config.PSK)
	block, _ := kcp.NewAESBlockCrypt(key)
	listener, err := kcp.ListenWithOptions(config.Listen, block, 10, 3)
	if err != nil {
		return nil, err
	}
	listener.SetReadBuffer(4194304)
	listener.SetWriteBuffer(4194304)
	listener.SetDSCP(46)
	return &KCPListener{listener: listener, config: config}, nil
}

func (t *KCPTransport) Dial(addr string, config *Config) (net.Conn, error) {
	key := generateKey(config.PSK)
	block, _ := kcp.NewAESBlockCrypt(key)
	conn, err := kcp.DialWithOptions(addr, block, 10, 3)
	if err != nil {
		return nil, err
	}
	configureKCP(conn, &config.KCP)
	return conn, nil
}

type KCPListener struct {
	listener *kcp.Listener
	config   *Config
}

func (l *KCPListener) Accept() (net.Conn, error) {
	conn, err := l.listener.AcceptKCP()
	if err != nil {
		return nil, err
	}
	configureKCP(conn, &l.config.KCP)
	return conn, nil
}

func (l *KCPListener) Close() error {
	return l.listener.Close()
}

func (l *KCPListener) Addr() net.Addr {
	return l.listener.Addr()
}

func configureKCP(conn *kcp.UDPSession, kc *KCPConfig) {
	conn.SetStreamMode(true)
	conn.SetWriteDelay(false)
	conn.SetNoDelay(kc.NoDelay, kc.Interval, kc.Resend, kc.NC)
	conn.SetWindowSize(kc.SndWnd, kc.RcvWnd)
	conn.SetMtu(kc.MTU)
	conn.SetACKNoDelay(false)
	conn.SetReadBuffer(4194304)
	conn.SetWriteBuffer(4194304)
}

// WebSocket Transport
type WSTransport struct {
	secure bool
}

func (t *WSTransport) Listen(config *Config) (net.Listener, error) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:    config.Advanced.WebSocketReadBuffer,
		WriteBufferSize:   config.Advanced.WebSocketWriteBuffer,
		EnableCompression: config.Advanced.WebSocketCompression,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	listener := &WSListener{
		upgrader: upgrader,
		connChan: make(chan net.Conn, 100),
		config:   config,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		listener.connChan <- &wsConn{Conn: conn}
	})

	server := &http.Server{
		Addr:    config.Listen,
		Handler: mux,
	}

	if t.secure {
		// Load TLS config
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS cert: %v", err)
		}
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		go server.ListenAndServeTLS("", "")
	} else {
		go server.ListenAndServe()
	}

	listener.server = server
	return listener, nil
}

func (t *WSTransport) Dial(addr string, config *Config) (net.Conn, error) {
	scheme := "ws"
	if t.secure {
		scheme = "wss"
	}

	url := fmt.Sprintf("%s://%s/", scheme, addr)
	dialer := websocket.Dialer{
		ReadBufferSize:    config.Advanced.WebSocketReadBuffer,
		WriteBufferSize:   config.Advanced.WebSocketWriteBuffer,
		EnableCompression: config.Advanced.WebSocketCompression,
		HandshakeTimeout:  time.Duration(config.Advanced.ConnectionTimeout) * time.Second,
	}

	if t.secure {
		dialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, // In production, verify properly
		}
	}

	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		return nil, err
	}

	return &wsConn{Conn: conn}, nil
}

type WSListener struct {
	upgrader websocket.Upgrader
	connChan chan net.Conn
	server   *http.Server
	config   *Config
}

func (l *WSListener) Accept() (net.Conn, error) {
	conn, ok := <-l.connChan
	if !ok {
		return nil, fmt.Errorf("listener closed")
	}
	return conn, nil
}

func (l *WSListener) Close() error {
	close(l.connChan)
	return l.server.Close()
}

func (l *WSListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

type wsConn struct {
	*websocket.Conn
	readBuf []byte
}

func (c *wsConn) Read(b []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	_, data, err := c.Conn.ReadMessage()
	if err != nil {
		return 0, err
	}

	n := copy(b, data)
	if n < len(data) {
		c.readBuf = data[n:]
	}
	return n, nil
}

func (c *wsConn) Write(b []byte) (int, error) {
	err := c.Conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(t)
}

// ============================================================================
// Session Manager
// ============================================================================

type SessionManager struct {
	sessions  []*SessionWrapper
	mu        sync.RWMutex
	smuxConf  *smux.Config
	config    *Config
}

type SessionWrapper struct {
	session     *smux.Session
	conn        net.Conn
	activeCount int32
	createdAt   time.Time
}

func NewSessionManager(config *Config) *SessionManager {
	smuxConf := smux.DefaultConfig()
	smuxConf.Version = config.SMUX.Version
	smuxConf.KeepAliveInterval = time.Duration(config.SMUX.KeepAlive) * time.Second
	smuxConf.KeepAliveTimeout = time.Duration(config.SMUX.KeepAlive*3) * time.Second
	smuxConf.MaxFrameSize = config.SMUX.FrameSize
	smuxConf.MaxReceiveBuffer = config.SMUX.MaxRecv
	smuxConf.MaxStreamBuffer = config.SMUX.MaxStream

	return &SessionManager{
		sessions: make([]*SessionWrapper, 0),
		smuxConf: smuxConf,
		config:   config,
	}
}

func (m *SessionManager) AddSession(conn net.Conn, isServer bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var sess *smux.Session
	var err error

	if isServer {
		sess, err = smux.Server(conn, m.smuxConf)
	} else {
		sess, err = smux.Client(conn, m.smuxConf)
	}

	if err != nil {
		return err
	}

	wrapper := &SessionWrapper{
		session:     sess,
		conn:        conn,
		activeCount: 0,
		createdAt:   time.Now(),
	}

	m.sessions = append(m.sessions, wrapper)

	if m.config.Verbose {
		log.Printf("✓ Session added (total: %d)", len(m.sessions))
	}

	return nil
}

func (m *SessionManager) GetLeastLoaded() (*SessionWrapper, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.sessions) == 0 {
		return nil, fmt.Errorf("no sessions available")
	}

	var best *SessionWrapper
	minLoad := int32(1<<31 - 1)

	for _, w := range m.sessions {
		if w.session.IsClosed() {
			continue
		}
		load := atomic.LoadInt32(&w.activeCount)
		if load < minLoad {
			minLoad = load
			best = w
		}
	}

	if best == nil {
		return nil, fmt.Errorf("no available sessions")
	}

	return best, nil
}

func (m *SessionManager) OpenStream() (*smux.Stream, error) {
	wrapper, err := m.GetLeastLoaded()
	if err != nil {
		return nil, err
	}

	stream, err := wrapper.session.OpenStream()
	if err != nil {
		return nil, err
	}

	atomic.AddInt32(&wrapper.activeCount, 1)
	go func() {
		<-stream.GetDieCh()
		atomic.AddInt32(&wrapper.activeCount, -1)
	}()

	return stream, nil
}

func (m *SessionManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, w := range m.sessions {
		w.session.Close()
		w.conn.Close()
	}
	m.sessions = nil
	return nil
}

// ============================================================================
// UDP Flow Manager
// ============================================================================

type UDPFlowManager struct {
	flows   map[string]*UDPFlow
	mu      sync.RWMutex
	timeout time.Duration
}

type UDPFlow struct {
	conn      *net.UDPConn
	stream    *smux.Stream
	lastSeen  time.Time
	closeOnce sync.Once
}

func NewUDPFlowManager(timeout int) *UDPFlowManager {
	return &UDPFlowManager{
		flows:   make(map[string]*UDPFlow),
		timeout: time.Duration(timeout) * time.Second,
	}
}

func (m *UDPFlowManager) GetOrCreate(key string, conn *net.UDPConn, stream *smux.Stream) *UDPFlow {
	m.mu.Lock()
	defer m.mu.Unlock()

	if flow, ok := m.flows[key]; ok {
		flow.lastSeen = time.Now()
		return flow
	}

	flow := &UDPFlow{
		conn:     conn,
		stream:   stream,
		lastSeen: time.Now(),
	}
	m.flows[key] = flow
	return flow
}

func (m *UDPFlowManager) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for key, flow := range m.flows {
		if now.Sub(flow.lastSeen) > m.timeout {
			flow.closeOnce.Do(func() {
				flow.conn.Close()
				flow.stream.Close()
			})
			delete(m.flows, key)
		}
	}
}

// ============================================================================
// Server Implementation
// ============================================================================

type Server struct {
	config    *Config
	transport Transport
	manager   *SessionManager
	udpMgr    *UDPFlowManager
}

func NewServer(config *Config) *Server {
	var transport Transport

	switch config.Transport {
	case "kcpmux":
		transport = &KCPTransport{}
	case "wsmux":
		transport = &WSTransport{secure: false}
	case "wssmux":
		transport = &WSTransport{secure: true}
	default:
		transport = &TCPTransport{}
	}

	return &Server{
		config:    config,
		transport: transport,
		manager:   NewSessionManager(config),
		udpMgr:    NewUDPFlowManager(config.Advanced.UDPFlowTimeout),
	}
}

func (s *Server) Start() error {
	listener, err := s.transport.Listen(s.config)
	if err != nil {
		return err
	}
	defer listener.Close()

	s.printBanner()

	// Start port mappings
	for _, mapping := range s.config.Mappings {
		go s.startMapping(mapping)
	}

	// Cleanup routine
	go s.cleanupRoutine()

	// Accept client connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("❌ Accept error: %v", err)
			continue
		}

		if s.config.Verbose {
			log.Printf("🔗 New connection from %s", conn.RemoteAddr())
		}

		go s.handleClient(conn)
	}
}

func (s *Server) printBanner() {
	log.Printf("🚽 Potty Server v%s", version)
	log.Printf("📡 Transport: %s", s.config.Transport)
	log.Printf("🔊 Listening: %s", s.config.Listen)
	log.Printf("🔐 PSK: %s", maskPSK(s.config.PSK))
	log.Printf("💚 Profile: %s", s.config.Profile)
	log.Printf("⚙️  SMUX: keepalive=%ds buffer=%dMB frame=%dKB",
		s.config.SMUX.KeepAlive,
		s.config.SMUX.MaxRecv/1048576,
		s.config.SMUX.FrameSize/1024)

	if s.config.Transport == "kcpmux" {
		log.Printf("⚙️  KCP: nodelay=%d interval=%dms window=%d/%d mtu=%d",
			s.config.KCP.NoDelay, s.config.KCP.Interval,
			s.config.KCP.SndWnd, s.config.KCP.RcvWnd, s.config.KCP.MTU)
	}

	log.Printf("🔧 Advanced: tcp_buf=%dMB ws_buf=%dKB max_conn=%d",
		s.config.Advanced.TCPReadBuffer/1048576,
		s.config.Advanced.WebSocketReadBuffer/1024,
		s.config.Advanced.MaxConnections)
}

func (s *Server) cleanupRoutine() {
	ticker := time.NewTicker(time.Duration(s.config.Advanced.CleanupInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.udpMgr.Cleanup()
	}
}

func (s *Server) handleClient(conn net.Conn) {
	if err := s.manager.AddSession(conn, true); err != nil {
		log.Printf("❌ Failed to add session: %v", err)
		conn.Close()
		return
	}

	// Heartbeat
	ticker := time.NewTicker(time.Duration(s.config.Heartbeat) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Keep connection alive
		conn.SetDeadline(time.Now().Add(time.Duration(s.config.Advanced.SessionTimeout) * time.Second))
	}
}

func (s *Server) startMapping(mapping PortMapping) {
	if mapping.Type == "tcp" {
		s.startTCPMapping(mapping)
	} else if mapping.Type == "udp" {
		s.startUDPMapping(mapping)
	}
}

func (s *Server) startTCPMapping(mapping PortMapping) {
	listener, err := net.Listen("tcp", mapping.Bind)
	if err != nil {
		log.Printf("❌ Failed to bind %s: %v", mapping.Bind, err)
		return
	}
	defer listener.Close()

	log.Printf("↔️  TCP: %s -> %s", mapping.Bind, mapping.Target)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go s.handleTCPForward(conn, mapping)
	}
}

func (s *Server) startUDPMapping(mapping PortMapping) {
	addr, err := net.ResolveUDPAddr("udp", mapping.Bind)
	if err != nil {
		log.Printf("❌ Failed to resolve UDP addr %s: %v", mapping.Bind, err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("❌ Failed to bind UDP %s: %v", mapping.Bind, err)
		return
	}
	defer conn.Close()

	log.Printf("↔️  UDP: %s -> %s", mapping.Bind, mapping.Target)

	buf := make([]byte, 65536)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		go s.handleUDPForward(conn, clientAddr, buf[:n], mapping)
	}
}

func (s *Server) handleTCPForward(conn net.Conn, mapping PortMapping) {
	defer conn.Close()

	stream, err := s.manager.OpenStream()
	if err != nil {
		if s.config.Verbose {
			log.Printf("❌ Failed to open stream: %v", err)
		}
		return
	}
	defer stream.Close()

	// Send target + type
	header := []byte(fmt.Sprintf("tcp:%s", mapping.Target))
	headerLen := make([]byte, 2)
	binary.BigEndian.PutUint16(headerLen, uint16(len(header)))

	if _, err := stream.Write(headerLen); err != nil {
		return
	}
	if _, err := stream.Write(header); err != nil {
		return
	}

	if s.config.Verbose {
		log.Printf("→ TCP forward to %s", mapping.Target)
	}

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(stream, conn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(conn, stream)
	}()

	wg.Wait()
}

func (s *Server) handleUDPForward(conn *net.UDPConn, clientAddr *net.UDPAddr, data []byte, mapping PortMapping) {
	stream, err := s.manager.OpenStream()
	if err != nil {
		return
	}
	defer stream.Close()

	// Send header
	header := []byte(fmt.Sprintf("udp:%s", mapping.Target))
	headerLen := make([]byte, 2)
	binary.BigEndian.PutUint16(headerLen, uint16(len(header)))

	stream.Write(headerLen)
	stream.Write(header)

	// Send UDP data
	dataLen := make([]byte, 4)
	binary.BigEndian.PutUint32(dataLen, uint32(len(data)))
	stream.Write(dataLen)
	stream.Write(data)

	// Read response
	respLen := make([]byte, 4)
	if _, err := io.ReadFull(stream, respLen); err != nil {
		return
	}

	respSize := binary.BigEndian.Uint32(respLen)
	respData := make([]byte, respSize)
	if _, err := io.ReadFull(stream, respData); err != nil {
		return
	}

	conn.WriteToUDP(respData, clientAddr)
}

// ============================================================================
// Client Implementation
// ============================================================================

type Client struct {
	config  *Config
	manager *SessionManager
}

func NewClient(config *Config) *Client {
	return &Client{
		config:  config,
		manager: NewSessionManager(config),
	}
}

func (c *Client) Start() error {
	c.printBanner()

	// Connect to all paths
	for _, path := range c.config.Paths {
		for i := 0; i < path.ConnectionPool; i++ {
			go c.connectPath(path, i)
		}
	}

	// Reconnection loop
	go c.reconnectLoop()

	// Handle streams
	return c.handleStreams()
}

func (c *Client) printBanner() {
	log.Printf("🚽 Potty Client v%s", version)
	log.Printf("🔐 PSK: %s", maskPSK(c.config.PSK))
	log.Printf("💚 Profile: %s", c.config.Profile)

	for i, path := range c.config.Paths {
		log.Printf("🔌 Path %d: %s (%s) pool=%d",
			i+1, path.Addr, path.Transport, path.ConnectionPool)
	}

	log.Printf("⚙️  SMUX: keepalive=%ds buffer=%dMB",
		c.config.SMUX.KeepAlive,
		c.config.SMUX.MaxRecv/1048576)
}

func (c *Client) connectPath(path PathConfig, id int) {
	var transport Transport

	switch path.Transport {
	case "kcpmux":
		transport = &KCPTransport{}
	case "wsmux":
		transport = &WSTransport{secure: false}
	case "wssmux":
		transport = &WSTransport{secure: true}
	default:
		transport = &TCPTransport{}
	}

	for {
		conn, err := transport.Dial(path.Addr, c.config)
		if err != nil {
			if c.config.Verbose {
				log.Printf("❌ Path %s [%d] failed: %v", path.Addr, id, err)
			}
			time.Sleep(time.Duration(path.RetryInterval) * time.Second)
			continue
		}

		if err := c.manager.AddSession(conn, false); err != nil {
			conn.Close()
			time.Sleep(time.Duration(path.RetryInterval) * time.Second)
			continue
		}

		log.Printf("✓ Path %s [%d] connected", path.Addr, id)

		// Heartbeat
		ticker := time.NewTicker(time.Duration(c.config.Heartbeat) * time.Second)
		for range ticker.C {
			if _, err := conn.Write([]byte{0}); err != nil {
				ticker.Stop()
				break
			}
		}

		time.Sleep(time.Duration(path.RetryInterval) * time.Second)
	}
}

func (c *Client) reconnectLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Check session count
		c.manager.mu.RLock()
		count := len(c.manager.sessions)
		c.manager.mu.RUnlock()

		if c.config.Verbose && count == 0 {
			log.Printf("⚠️  No active sessions")
		}
	}
}

func (c *Client) handleStreams() error {
	for {
		c.manager.mu.RLock()
		sessions := make([]*SessionWrapper, len(c.manager.sessions))
		copy(sessions, c.manager.sessions)
		c.manager.mu.RUnlock()

		for _, wrapper := range sessions {
			if wrapper.session.IsClosed() {
				continue
			}

			stream, err := wrapper.session.AcceptStream()
			if err != nil {
				continue
			}

			atomic.AddInt32(&wrapper.activeCount, 1)
			go func(s *smux.Stream) {
				defer func() {
					atomic.AddInt32(&wrapper.activeCount, -1)
					s.Close()
				}()
				c.handleStream(s)
			}(stream)
		}

		time.Sleep(50 * time.Millisecond)
	}
}

func (c *Client) handleStream(stream *smux.Stream) {
	// Read header
	headerLen := make([]byte, 2)
	if _, err := io.ReadFull(stream, headerLen); err != nil {
		return
	}

	length := binary.BigEndian.Uint16(headerLen)
	header := make([]byte, length)
	if _, err := io.ReadFull(stream, header); err != nil {
		return
	}

	parts := string(header)

	if len(parts) < 4 {
		return
	}

	connType := parts[:3]
	target := parts[4:]

	if connType == "tcp" {
		c.handleTCPStream(stream, target)
	} else if connType == "udp" {
		c.handleUDPStream(stream, target)
	}
}

func (c *Client) handleTCPStream(stream *smux.Stream, target string) {
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		if c.config.Verbose {
			log.Printf("❌ Failed to connect to %s: %v", target, err)
		}
		return
	}
	defer conn.Close()

	if c.config.Verbose {
		log.Printf("← TCP connect to %s", target)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(conn, stream)
	}()

	go func() {
		defer wg.Done()
		io.Copy(stream, conn)
	}()

	wg.Wait()
}

func (c *Client) handleUDPStream(stream *smux.Stream, target string) {
	// Read UDP data
	dataLen := make([]byte, 4)
	if _, err := io.ReadFull(stream, dataLen); err != nil {
		return
	}

	size := binary.BigEndian.Uint32(dataLen)
	data := make([]byte, size)
	if _, err := io.ReadFull(stream, data); err != nil {
		return
	}

	// Send to target
	conn, err := net.Dial("udp", target)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.Write(data)

	// Read response
	buf := make([]byte, 65536)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	// Send response back
	respLen := make([]byte, 4)
	binary.BigEndian.PutUint32(respLen, uint32(n))
	stream.Write(respLen)
	stream.Write(buf[:n])
}

// ============================================================================
// Utilities
// ============================================================================

func generateKey(psk string) []byte {
	hash := sha256.Sum256([]byte(psk))
	return hash[:]
}

func maskPSK(psk string) string {
	if len(psk) <= 8 {
		return "****"
	}
	return psk[:4] + "****" + psk[len(psk)-4:]
}

// ============================================================================
// Main
// ============================================================================

func main() {
	configFile := flag.String("config", "", "Config file path")
	generateConfig := flag.String("generate-config", "", "Generate config (server|client)")
	showVersion := flag.Bool("version", false, "Show version")

	flag.Parse()

	if *showVersion {
		fmt.Printf("Potty v%s\n", version)
		return
	}

	if *generateConfig != "" {
		filename := fmt.Sprintf("potty-%s.yaml", *generateConfig)
		if err := generateDefaultConfig(filename, *generateConfig); err != nil {
			log.Fatal(err)
		}
		log.Printf("✓ Generated: %s", filename)
		return
	}

	if *configFile == "" {
		fmt.Println("Potty - Reverse Tunnel v" + version)
		fmt.Println("\nUsage:")
		fmt.Println("  potty -config <file.yaml>")
		fmt.Println("  potty -generate-config server")
		fmt.Println("  potty -generate-config client")
		os.Exit(1)
	}

	config, err := loadConfig(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	if config.PSK == "change_me_please" {
		log.Fatal("⚠️  Change PSK in config!")
	}

	switch config.Mode {
	case "server":
		server := NewServer(config)
		if err := server.Start(); err != nil {
			log.Fatal(err)
		}
	case "client":
		client := NewClient(config)
		if err := client.Start(); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("Invalid mode")
	}
}