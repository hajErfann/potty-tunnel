#!/bin/bash

# Potty Installer v1.1.0
# Interactive installation and configuration tool

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Installation directories
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/potty"
SYSTEMD_DIR="/etc/systemd/system"

# GitHub repo
GITHUB_REPO="https://github.com/hajErfann/potty-tunnel"
BINARY_NAME="potty-linux-amd64"
DOWNLOAD_URL="$GITHUB_REPO/releases/latest/download/$BINARY_NAME"

# Banner
show_banner() {
    clear
    echo -e "${PURPLE}"
    echo "  ____       _   _         "
    echo " |  _ \ ___ | |_| |_ _   _ "
    echo " | |_) / _ \| __| __| | | |"
    echo " |  __/ (_) | |_| |_| |_| |"
    echo " |_|   \___/ \__|\__|\__, |"
    echo "                     |___/ "
    echo -e "${CYAN}    Reverse Tunnel Installer v1.1.0${NC}"
    echo ""
}

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}❌ This script must be run as root${NC}"
        exit 1
    fi
}

# Install dependencies
install_dependencies() {
    echo -e "${YELLOW}📦 Installing dependencies...${NC}"
    if command -v apt &>/dev/null; then
        apt update -qq
        apt install -y wget curl tar git > /dev/null 2>&1 || { echo -e "${RED}Failed to install dependencies${NC}"; exit 1; }
    elif command -v yum &>/dev/null; then
        yum install -y wget curl tar git > /dev/null 2>&1 || { echo -e "${RED}Failed to install dependencies${NC}"; exit 1; }
    else
        echo -e "${RED}❌ Unsupported package manager${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Dependencies installed${NC}"
}

# Download binary
download_binary() {
    echo -e "${YELLOW}⬇️  Downloading Potty binary...${NC}"
    mkdir -p "$INSTALL_DIR"
    if wget -q --show-progress "$DOWNLOAD_URL" -O "$INSTALL_DIR/potty"; then
        chmod +x "$INSTALL_DIR/potty"
        echo -e "${GREEN}✓ Potty downloaded${NC}"
    else
        echo -e "${YELLOW}⚠️  Binary not available, compiling from source${NC}"
        compile_from_source
    fi
}

# Compile from source
compile_from_source() {
    echo -e "${YELLOW}🔨 Compiling Potty from source...${NC}"

    # Install Go if not installed
    if ! command -v go &>/dev/null; then
        echo -e "${YELLOW}📦 Installing Go...${NC}"
        wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
        export PATH=$PATH:/usr/local/go/bin
        rm go1.21.5.linux-amd64.tar.gz
    fi

    # Clone and build
    TEMP_DIR=$(mktemp -d)
    git clone "$GITHUB_REPO" "$TEMP_DIR/potty-tunnel" > /dev/null 2>&1
    cd "$TEMP_DIR/potty-tunnel"
    go mod download > /dev/null 2>&1
    go build -o potty -ldflags="-s -w" potty

    # Copy binary
    cp potty "$INSTALL_DIR/potty"
    chmod +x "$INSTALL_DIR/potty"

    # Cleanup
    cd /
    rm -rf "$TEMP_DIR"

    echo -e "${GREEN}✓ Potty compiled and installed${NC}"
}

# Create systemd service
create_systemd_service() {
    local MODE=$1
    local SERVICE_FILE="$SYSTEMD_DIR/potty-${MODE}.service"

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Potty Reverse Tunnel ${MODE^}
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$CONFIG_DIR
ExecStart=$INSTALL_DIR/potty -config $CONFIG_DIR/${MODE}.yaml
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo -e "${GREEN}✓ Systemd service created${NC}"
}

# ---------------------------
# Server Installation
# ---------------------------
install_server() {
    show_banner
    mkdir -p "$CONFIG_DIR"

    echo -e "${YELLOW}📝 Server Configuration${NC}"

    # Transport type
    echo "Select Transport Type:"
    echo "1) TCP (tcpmux)"
    echo "2) KCP (kcpmux)"
    echo "3) WebSocket (wsmux)"
    echo "4) WebSocket Secure (wssmux)"
    read -p "Choice [1-4]: " transport_choice
    case $transport_choice in
        1) TRANSPORT="tcpmux" ;;
        2) TRANSPORT="kcpmux" ;;
        3) TRANSPORT="wsmux" ;;
        4) TRANSPORT="wssmux" ;;
        *) TRANSPORT="tcpmux" ;;
    esac

    # Listen port
    read -p "Listen Port [4000]: " LISTEN_PORT
    LISTEN_PORT=${LISTEN_PORT:-4000}

    # PSK
    while true; do
        read -sp "Enter PSK (Pre-Shared Key): " PSK
        echo ""
        if [ -z "$PSK" ]; then
            echo "PSK cannot be empty!"
        else
            break
        fi
    done

    # Profile
    echo "Select Performance Profile:"
    echo "1) balanced"
    echo "2) aggressive"
    echo "3) latency"
    echo "4) cpu-efficient"
    read -p "Choice [1-4]: " profile_choice
    case $profile_choice in
        1) PROFILE="balanced" ;;
        2) PROFILE="aggressive" ;;
        3) PROFILE="latency" ;;
        4) PROFILE="cpu-efficient" ;;
        *) PROFILE="balanced" ;;
    esac

    # TLS
    CERT_FILE=""
    KEY_FILE=""
    if [ "$TRANSPORT" == "wssmux" ]; then
        read -p "Certificate file path: " CERT_FILE
        read -p "Private key file path: " KEY_FILE
        if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
            echo "⚠️  Certificate files not found, you can add them later"
            CERT_FILE=""
            KEY_FILE=""
        fi
    fi

    # Port mappings
    MAPPINGS=""
    COUNT=0
    while true; do
        echo "Add Port Mapping #$((COUNT+1))"
        read -p "Protocol (tcp/udp) [tcp]: " PROTO
        PROTO=${PROTO:-tcp}
        read -p "Bind address (e.g., 0.0.0.0:2222): " BIND
        read -p "Target address (e.g., 127.0.0.1:22): " TARGET
        if [ $COUNT -eq 0 ]; then
            MAPPINGS="  - type: \"$PROTO\"\n    bind: \"$BIND\"\n    target: \"$TARGET\""
        else
            MAPPINGS="$MAPPINGS\n  - type: \"$PROTO\"\n    bind: \"$BIND\"\n    target: \"$TARGET\""
        fi
        COUNT=$((COUNT+1))
        read -p "Add another mapping? [y/N]: " MORE
        [[ ! $MORE =~ ^[Yy]$ ]] && break
    done

    # Verbose
    read -p "Enable verbose logging? [y/N]: " VERBOSE
    [[ $VERBOSE =~ ^[Yy]$ ]] && VERBOSE="true" || VERBOSE="false"

    # Write config
    CONFIG_FILE="$CONFIG_DIR/server.yaml"
    cat > "$CONFIG_FILE" << EOF
mode: "server"
listen: "0.0.0.0:${LISTEN_PORT}"
transport: "${TRANSPORT}"
psk: "${PSK}"
profile: "${PROFILE}"
verbose: ${VERBOSE}

EOF
    [[ -n "$CERT_FILE" ]] && echo -e "cert_file: \"$CERT_FILE\"\nkey_file: \"$KEY_FILE\"\n" >> "$CONFIG_FILE"
    echo -e "maps:\n$MAPPINGS\n" >> "$CONFIG_FILE"

    # SMUX, KCP, Advanced, heartbeat
    cat >> "$CONFIG_FILE" << 'EOF'
smux:
  keepalive: 8
  max_recv: 8388608
  max_stream: 8388608
  frame_size: 32768
  version: 2

kcp:
  nodelay: 1
  interval: 10
  resend: 2
  nc: 1
  sndwnd: 768
  rcvwnd: 768
  mtu: 1350

advanced:
  tcp_nodelay: true
  tcp_keepalive: 15
  tcp_read_buffer: 4194304
  tcp_write_buffer: 4194304
  websocket_read_buffer: 262144
  websocket_write_buffer: 262144
  websocket_compression: false
  cleanup_interval: 3
  session_timeout: 30
  connection_timeout: 60
  stream_timeout: 120
  max_connections: 2000
  max_udp_flows: 1000
  udp_flow_timeout: 300

max_sessions: 0
heartbeat: 10
EOF

    create_systemd_service "server"
    echo "Server installation complete!"
    read -p "Press Enter to return to menu..."
    main_menu
}

# ---------------------------
# Client Installation
# ---------------------------
install_client() {
    show_banner
    mkdir -p "$CONFIG_DIR"

    echo "📝 Client Configuration"
    while true; do
        read -sp "Enter PSK (must match server): " PSK
        echo ""
        [ -n "$PSK" ] && break
    done

    echo "Select Performance Profile:"
    echo "1) balanced"
    echo "2) aggressive"
    echo "3) latency"
    echo "4) cpu-efficient"
    read -p "Choice [1-4]: " profile_choice
    case $profile_choice in
        1) PROFILE="balanced" ;;
        2) PROFILE="aggressive" ;;
        3) PROFILE="latency" ;;
        4) PROFILE="cpu-efficient" ;;
        *) PROFILE="balanced" ;;
    esac

    PATHS=""
    COUNT=0
    while true; do
        echo "Add Connection Path #$((COUNT+1))"
        echo "1) TCP (tcpmux)"
        echo "2) KCP (kcpmux)"
        echo "3) WebSocket (wsmux)"
        echo "4) WebSocket Secure (wssmux)"
        read -p "Choice [1-4]: " transport_choice
        case $transport_choice in
            1) T="tcpmux" ;;
            2) T="kcpmux" ;;
            3) T="wsmux" ;;
            4) T="wssmux" ;;
            *) T="tcpmux" ;;
        esac
        read -p "Server address (e.g., 1.2.3.4:4000): " ADDR
        read -p "Connection pool size [2]: " POOL
        POOL=${POOL:-2}

        [[ $COUNT -eq 0 ]] && PATHS="  - transport: \"$T\"\n    addr: \"$ADDR\"\n    connection_pool: $POOL\n    aggressive_pool: false\n    retry_interval: 3\n    dial_timeout: 10" || PATHS="$PATHS\n  - transport: \"$T\"\n    addr: \"$ADDR\"\n    connection_pool: $POOL\n    aggressive_pool: false\n    retry_interval: 3\n    dial_timeout: 10"
        COUNT=$((COUNT+1))
        read -p "Add another path? [y/N]: " MORE
        [[ ! $MORE =~ ^[Yy]$ ]] && break
    done

    read -p "Enable verbose logging? [y/N]: " VERBOSE
    [[ $VERBOSE =~ ^[Yy]$ ]] && VERBOSE="true" || VERBOSE="false"

    CONFIG_FILE="$CONFIG_DIR/client.yaml"
    cat > "$CONFIG_FILE" << EOF
mode: "client"
psk: "${PSK}"
profile: "${PROFILE}"
verbose: ${VERBOSE}

paths:
$PATHS

smux:
  keepalive: 8
  max_recv: 8388608
  max_stream: 8388608
  frame_size: 32768
  version: 2

kcp:
  nodelay: 1
  interval: 10
  resend: 2
  nc: 1
  sndwnd: 768
  rcvwnd: 768
  mtu: 1350

advanced:
  tcp_nodelay: true
  tcp_keepalive: 15
  tcp_read_buffer: 4194304
  tcp_write_buffer: 4194304
  websocket_read_buffer: 262144
  websocket_write_buffer: 262144
  websocket_compression: false
  cleanup_interval: 3
  session_timeout: 30
  connection_timeout: 60
  stream_timeout: 120
  max_connections: 2000
  max_udp_flows: 1000
  udp_flow_timeout: 300

heartbeat: 10
EOF

    create_systemd_service "client"
    echo "Client installation complete!"
    read -p "Press Enter to return to menu..."
    main_menu
}

# ---------------------------
# Config management
# ---------------------------
manage_configs() {
    show_banner
    echo "1) View Server Config"
    echo "2) View Client Config"
    echo "3) Edit Server Config"
    echo "4) Edit Client Config"
    echo "5) Delete Server Config"
    echo "6) Delete Client Config"
    echo "0) Back to Main Menu"
    read -p "Select option: " choice
    case $choice in
        1) [ -f "$CONFIG_DIR/server.yaml" ] && cat "$CONFIG_DIR/server.yaml" || echo "Server config not found"; read -p "Enter to continue..."; manage_configs ;;
        2) [ -f "$CONFIG_DIR/client.yaml" ] && cat "$CONFIG_DIR/client.yaml" || echo "Client config not found"; read -p "Enter to continue..."; manage_configs ;;
        3) [ -f "$CONFIG_DIR/server.yaml" ] && ${EDITOR:-nano} "$CONFIG_DIR/server.yaml" || echo "Server config not found"; manage_configs ;;
        4) [ -f "$CONFIG_DIR/client.yaml" ] && ${EDITOR:-nano} "$CONFIG_DIR/client.yaml" || echo "Client config not found"; manage_configs ;;
        5) read -p "Delete server config? [y/N]: " c; [[ $c =~ ^[Yy]$ ]] && rm -f "$CONFIG_DIR/server.yaml"; manage_configs ;;
        6) read -p "Delete client config? [y/N]: " c; [[ $c =~ ^[Yy]$ ]] && rm -f "$CONFIG_DIR/client.yaml"; manage_configs ;;
        0) main_menu ;;
        *) manage_configs ;;
    esac
}

# ---------------------------
# Service management
# ---------------------------
manage_services() {
    show_banner
    echo "1) Start Server"
    echo "2) Start Client"
    echo "3) Stop Server"
    echo "4) Stop Client"
    echo "5) Restart Server"
    echo "6) Restart Client"
    echo "7) Status Server"
    echo "8) Status Client"
    echo "9) Enable Server Auto-start"
    echo "10) Enable Client Auto-start"
    echo "11) Disable Server Auto-start"
    echo "12) Disable Client Auto-start"
    echo "13) View Server Logs"
    echo "14) View Client Logs"
    echo "0) Back to Main Menu"
    read -p "Select option: " choice
    case $choice in
        1) systemctl start potty-server ;;
        2) systemctl start potty-client ;;
        3) systemctl stop potty-server ;;
        4) systemctl stop potty-client ;;
        5) systemctl restart potty-server ;;
        6) systemctl restart potty-client ;;
        7) systemctl status potty-server ;;
        8) systemctl status potty-client ;;
        9) systemctl enable potty-server ;;
        10) systemctl enable potty-client ;;
        11) systemctl disable potty-server ;;
        12) systemctl disable potty-client ;;
        13) journalctl -u potty-server -f ;;
        14) journalctl -u potty-client -f ;;
        0) main_menu ;;
    esac
    [ $choice -ne 0 ] && [ $choice -lt 13 ] && read -p "Press Enter to continue..."
    manage_services
}

# ---------------------------
# Uninstall
# ---------------------------
uninstall_potty() {
    show_banner
    echo "⚠️ This will remove Potty binary, configs, and systemd services"
    read -p "Are you sure? [y/N]: " c
    [[ $c =~ ^[Yy]$ ]] || main_menu

    systemctl stop potty-server 2>/dev/null
    systemctl stop potty-client 2>/dev/null
    systemctl disable potty-server 2>/dev/null
    systemctl disable potty-client 2>/dev/null

# Remove files
rm -f "$INSTALL_DIR/potty"
rm -rf "$CONFIG_DIR"
rm -f "$SYSTEMD_DIR/potty-server.service"
rm -f "$SYSTEMD_DIR/potty-client.service"

systemctl daemon-reload

echo -e "${GREEN}✓ Potty uninstalled successfully${NC}"
exit 0
}

# ---------------------------
# Main Menu
# ---------------------------
main_menu() {
    show_banner
    echo "1) Install Potty Server"
    echo "2) Install Potty Client"
    echo "3) Manage Configurations"
    echo "4) Manage Services"
    echo "5) Uninstall Potty"
    echo "0) Exit"
    read -p "Select option: " choice
    case $choice in
        1) install_server ;;
        2) install_client ;;
        3) manage_configs ;;
        4) manage_services ;;
        5) uninstall_potty ;;
        0) exit 0 ;;
        *) echo "Invalid option"; sleep 2; main_menu ;;
    esac
}

# ---------------------------
# Execution
# ---------------------------
check_root
show_banner
install_dependencies

# Check binary
if [ ! -f "$INSTALL_DIR/potty" ]; then
    echo "Potty not found. Installing..."
    download_binary
fi

main_menu
