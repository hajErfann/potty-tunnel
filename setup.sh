#!/bin/bash

# Potty Installer v1.0.0
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

# Installation directory
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/potty"
SYSTEMD_DIR="/etc/systemd/system"

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
    echo -e "${CYAN}    Reverse Tunnel Installer v1.0.0${NC}"
    echo ""
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}❌ This script must be run as root${NC}"
        exit 1
    fi
}

# Install dependencies
install_dependencies() {
    echo -e "${YELLOW}📦 Installing dependencies...${NC}"

    if command -v apt &> /dev/null; then
        apt update -qq
        apt install -y wget curl tar git > /dev/null 2>&1
    elif command -v yum &> /dev/null; then
        yum install -y wget curl tar git > /dev/null 2>&1
    else
        echo -e "${RED}❌ Unsupported package manager${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓ Dependencies installed${NC}"
}

# Download Potty binary
download_binary() {
    echo -e "${YELLOW}⬇️  Downloading Potty...${NC}"

    # GitHub repository
    GITHUB_REPO="https://github.com/hajErfann/potty-tunnel"
    DOWNLOAD_URL="$GITHUB_REPO/releases/latest/download/potty-linux-amd64"

    if wget -q --show-progress "$DOWNLOAD_URL" -O "$INSTALL_DIR/potty" 2>/dev/null; then
        chmod +x "$INSTALL_DIR/potty"
        echo -e "${GREEN}✓ Potty downloaded${NC}"
    else
        echo -e "${YELLOW}⚠️  Binary not available, will compile from source${NC}"
        compile_from_source
    fi
}

# Compile from source
compile_from_source() {
    echo -e "${YELLOW}🔨 Compiling Potty from source...${NC}"

    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        echo -e "${YELLOW}📦 Installing Go...${NC}"
        wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
        tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        rm go1.21.5.linux-amd64.tar.gz
    fi

    # Clone and compile
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"

    echo -e "${YELLOW}📥 Cloning repository...${NC}"
    git clone https://github.com/hajErfann/potty-tunnel.git
    cd potty-tunnel

    echo -e "${YELLOW}📦 Downloading dependencies...${NC}"
    go mod download

    echo -e "${YELLOW}🔨 Building...${NC}"
    go build -o potty -ldflags="-s -w" potty.go

    # Copy to install directory
    cp potty "$INSTALL_DIR/potty"
    chmod +x "$INSTALL_DIR/potty"

    # Cleanup
    cd /
    rm -rf "$TEMP_DIR"

    echo -e "${GREEN}✓ Potty compiled and installed${NC}"
}

# Main menu
main_menu() {
    show_banner
    echo -e "${WHITE}╔════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║          POTTY INSTALLER MENU          ║${NC}"
    echo -e "${WHITE}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}1)${NC} Install Potty Server"
    echo -e "${CYAN}2)${NC} Install Potty Client"
    echo -e "${CYAN}3)${NC} Manage Configurations"
    echo -e "${CYAN}4)${NC} Manage Services"
    echo -e "${CYAN}5)${NC} Uninstall Potty"
    echo -e "${CYAN}0)${NC} Exit"
    echo ""
    read -p "$(echo -e ${YELLOW}Select option: ${NC})" choice

    case $choice in
        1) install_server ;;
        2) install_client ;;
        3) manage_configs ;;
        4) manage_services ;;
        5) uninstall_potty ;;
        0) exit 0 ;;
        *) echo -e "${RED}Invalid option${NC}" && sleep 2 && main_menu ;;
    esac
}

# Install Server
install_server() {
    show_banner
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}       POTTY SERVER INSTALLATION${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # Create config directory
    mkdir -p "$CONFIG_DIR"

    # Get configuration
    echo -e "${YELLOW}📝 Server Configuration${NC}"
    echo ""

    # Transport type
    echo -e "${CYAN}Select Transport Type:${NC}"
    echo "1) TCP (tcpmux) - Reliable, standard"
    echo "2) KCP (kcpmux) - Fast, low latency"
    echo "3) WebSocket (wsmux) - Firewall bypass"
    echo "4) WebSocket Secure (wssmux) - Secure + Firewall bypass"
    read -p "Choice [1-4]: " transport_choice

    case $transport_choice in
        1) TRANSPORT="tcpmux" ;;
        2) TRANSPORT="kcpmux" ;;
        3) TRANSPORT="wsmux" ;;
        4) TRANSPORT="wssmux" ;;
        *) TRANSPORT="tcpmux" ;;
    esac

    # Listen port
    read -p "$(echo -e ${CYAN}Listen Port [4000]: ${NC})" LISTEN_PORT
    LISTEN_PORT=${LISTEN_PORT:-4000}

    # PSK
    while true; do
        read -sp "$(echo -e ${CYAN}Enter PSK (Pre-Shared Key): ${NC})" PSK
        echo ""
        if [ -z "$PSK" ]; then
            echo -e "${RED}PSK cannot be empty!${NC}"
        else
            break
        fi
    done

    # Profile
    echo ""
    echo -e "${CYAN}Select Performance Profile:${NC}"
    echo "1) balanced - General use"
    echo "2) aggressive - Maximum speed"
    echo "3) latency - Gaming/Real-time"
    echo "4) cpu-efficient - Low CPU usage"
    read -p "Choice [1-4]: " profile_choice

    case $profile_choice in
        1) PROFILE="balanced" ;;
        2) PROFILE="aggressive" ;;
        3) PROFILE="latency" ;;
        4) PROFILE="cpu-efficient" ;;
        *) PROFILE="balanced" ;;
    esac

    # TLS Certificate (for WSS)
    CERT_FILE=""
    KEY_FILE=""
    if [ "$TRANSPORT" == "wssmux" ]; then
        echo ""
        echo -e "${YELLOW}⚠️  WSS requires TLS certificate${NC}"
        read -p "$(echo -e ${CYAN}Certificate file path: ${NC})" CERT_FILE
        read -p "$(echo -e ${CYAN}Private key file path: ${NC})" KEY_FILE

        if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
            echo -e "${YELLOW}⚠️  Certificate files not found. You can add them later.${NC}"
        fi
    fi

    # Port mappings
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}       PORT MAPPINGS${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    MAPPINGS=""
    MAPPING_COUNT=0

    while true; do
        echo ""
        echo -e "${YELLOW}Add Port Mapping #$((MAPPING_COUNT+1))${NC}"

        # Protocol
        read -p "Protocol (tcp/udp) [tcp]: " PROTOCOL
        PROTOCOL=${PROTOCOL:-tcp}

        # Bind port
        read -p "Bind address (e.g., 0.0.0.0:2222): " BIND_ADDR
        if [ -z "$BIND_ADDR" ]; then
            echo -e "${RED}Bind address required${NC}"
            continue
        fi

        # Target
        read -p "Target address (e.g., 127.0.0.1:22): " TARGET_ADDR
        if [ -z "$TARGET_ADDR" ]; then
            echo -e "${RED}Target address required${NC}"
            continue
        fi

        # Add to mappings
        if [ $MAPPING_COUNT -eq 0 ]; then
            MAPPINGS="  - type: \"${PROTOCOL}\"
    bind: \"${BIND_ADDR}\"
    target: \"${TARGET_ADDR}\""
        else
            MAPPINGS="${MAPPINGS}
  - type: \"${PROTOCOL}\"
    bind: \"${BIND_ADDR}\"
    target: \"${TARGET_ADDR}\""
        fi

        MAPPING_COUNT=$((MAPPING_COUNT+1))

        read -p "$(echo -e ${CYAN}Add another mapping? [y/N]: ${NC})" add_more
        if [[ ! $add_more =~ ^[Yy]$ ]]; then
            break
        fi
    done

    # Verbose logging
    echo ""
    read -p "$(echo -e ${CYAN}Enable verbose logging? [y/N]: ${NC})" VERBOSE
    if [[ $VERBOSE =~ ^[Yy]$ ]]; then
        VERBOSE="true"
    else
        VERBOSE="false"
    fi

    # Generate config file
    CONFIG_FILE="$CONFIG_DIR/server.yaml"

    cat > "$CONFIG_FILE" << EOF
# Potty Server Configuration
# Generated by installer on $(date)

mode: "server"
listen: "0.0.0.0:${LISTEN_PORT}"
transport: "${TRANSPORT}"
psk: "${PSK}"
profile: "${PROFILE}"
verbose: ${VERBOSE}

EOF

    # Add TLS config if WSS
    if [ "$TRANSPORT" == "wssmux" ] && [ -n "$CERT_FILE" ]; then
        cat >> "$CONFIG_FILE" << EOF
# TLS Certificate
cert_file: "${CERT_FILE}"
key_file: "${KEY_FILE}"

EOF
    fi

    # Add port mappings
    cat >> "$CONFIG_FILE" << EOF
# Port Mappings
maps:
${MAPPINGS}

# SMUX Settings (auto-configured by profile)
smux:
  keepalive: 8
  max_recv: 8388608
  max_stream: 8388608
  frame_size: 32768
  version: 2

# KCP Settings (used with kcpmux)
kcp:
  nodelay: 1
  interval: 10
  resend: 2
  nc: 1
  sndwnd: 768
  rcvwnd: 768
  mtu: 1350

# Advanced Settings
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

    echo ""
    echo -e "${GREEN}✓ Configuration saved to: ${CONFIG_FILE}${NC}"

    # Create systemd service
    create_systemd_service "server"

    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✓ Server installation complete!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${CYAN}To start the server:${NC}"
    echo -e "  ${WHITE}systemctl start potty-server${NC}"
    echo ""
    echo -e "${CYAN}To enable auto-start:${NC}"
    echo -e "  ${WHITE}systemctl enable potty-server${NC}"
    echo ""
    echo -e "${CYAN}To check status:${NC}"
    echo -e "  ${WHITE}systemctl status potty-server${NC}"
    echo ""

    read -p "Press Enter to return to menu..."
    main_menu
}

# Install Client
install_client() {
    show_banner
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}       POTTY CLIENT INSTALLATION${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    mkdir -p "$CONFIG_DIR"

    echo -e "${YELLOW}📝 Client Configuration${NC}"
    echo ""

    # PSK
    while true; do
        read -sp "$(echo -e ${CYAN}Enter PSK (must match server): ${NC})" PSK
        echo ""
        if [ -z "$PSK" ]; then
            echo -e "${RED}PSK cannot be empty!${NC}"
        else
            break
        fi
    done

    # Profile
    echo ""
    echo -e "${CYAN}Select Performance Profile:${NC}"
    echo "1) balanced - General use"
    echo "2) aggressive - Maximum speed"
    echo "3) latency - Gaming/Real-time"
    echo "4) cpu-efficient - Low CPU usage"
    read -p "Choice [1-4]: " profile_choice

    case $profile_choice in
        1) PROFILE="balanced" ;;
        2) PROFILE="aggressive" ;;
        3) PROFILE="latency" ;;
        4) PROFILE="cpu-efficient" ;;
        *) PROFILE="balanced" ;;
    esac

    # Connection paths
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}       CONNECTION PATHS${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    PATHS=""
    PATH_COUNT=0

    while true; do
        echo ""
        echo -e "${YELLOW}Add Connection Path #$((PATH_COUNT+1))${NC}"

        # Transport
        echo -e "${CYAN}Select Transport:${NC}"
        echo "1) TCP (tcpmux)"
        echo "2) KCP (kcpmux)"
        echo "3) WebSocket (wsmux)"
        echo "4) WebSocket Secure (wssmux)"
        read -p "Choice [1-4]: " transport_choice

        case $transport_choice in
            1) PATH_TRANSPORT="tcpmux" ;;
            2) PATH_TRANSPORT="kcpmux" ;;
            3) PATH_TRANSPORT="wsmux" ;;
            4) PATH_TRANSPORT="wssmux" ;;
            *) PATH_TRANSPORT="tcpmux" ;;
        esac

        # Server address
        read -p "Server address (e.g., 1.2.3.4:4000): " SERVER_ADDR
        if [ -z "$SERVER_ADDR" ]; then
            echo -e "${RED}Server address required${NC}"
            continue
        fi

        # Connection pool
        read -p "Connection pool size [2]: " POOL_SIZE
        POOL_SIZE=${POOL_SIZE:-2}

        # Add to paths
        if [ $PATH_COUNT -eq 0 ]; then
            PATHS="  - transport: \"${PATH_TRANSPORT}\"
    addr: \"${SERVER_ADDR}\"
    connection_pool: ${POOL_SIZE}
    aggressive_pool: false
    retry_interval: 3
    dial_timeout: 10"
        else
            PATHS="${PATHS}
  - transport: \"${PATH_TRANSPORT}\"
    addr: \"${SERVER_ADDR}\"
    connection_pool: ${POOL_SIZE}
    aggressive_pool: false
    retry_interval: 3
    dial_timeout: 10"
        fi

        PATH_COUNT=$((PATH_COUNT+1))

        read -p "$(echo -e ${CYAN}Add another path? [y/N]: ${NC})" add_more
        if [[ ! $add_more =~ ^[Yy]$ ]]; then
            break
        fi
    done

    # Verbose
    echo ""
    read -p "$(echo -e ${CYAN}Enable verbose logging? [y/N]: ${NC})" VERBOSE
    if [[ $VERBOSE =~ ^[Yy]$ ]]; then
        VERBOSE="true"
    else
        VERBOSE="false"
    fi

    # Generate config
    CONFIG_FILE="$CONFIG_DIR/client.yaml"

    cat > "$CONFIG_FILE" << EOF
# Potty Client Configuration
# Generated by installer on $(date)

mode: "client"
psk: "${PSK}"
profile: "${PROFILE}"
verbose: ${VERBOSE}

# Connection Paths
paths:
${PATHS}

# SMUX Settings
smux:
  keepalive: 8
  max_recv: 8388608
  max_stream: 8388608
  frame_size: 32768
  version: 2

# KCP Settings
kcp:
  nodelay: 1
  interval: 10
  resend: 2
  nc: 1
  sndwnd: 768
  rcvwnd: 768
  mtu: 1350

# Advanced Settings
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

    echo ""
    echo -e "${GREEN}✓ Configuration saved to: ${CONFIG_FILE}${NC}"

    # Create systemd service
    create_systemd_service "client"

    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✓ Client installation complete!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${CYAN}To start the client:${NC}"
    echo -e "  ${WHITE}systemctl start potty-client${NC}"
    echo ""
    echo -e "${CYAN}To enable auto-start:${NC}"
    echo -e "  ${WHITE}systemctl enable potty-client${NC}"
    echo ""
    echo -e "${CYAN}To check status:${NC}"
    echo -e "  ${WHITE}systemctl status potty-client${NC}"
    echo ""

    read -p "Press Enter to return to menu..."
    main_menu
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

# Manage configs
manage_configs() {
    show_banner
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}       CONFIGURATION MANAGEMENT${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "1) View Server Config"
    echo "2) View Client Config"
    echo "3) Edit Server Config"
    echo "4) Edit Client Config"
    echo "5) Delete Server Config"
    echo "6) Delete Client Config"
    echo "0) Back to Main Menu"
    echo ""
    read -p "$(echo -e ${YELLOW}Select option: ${NC})" choice

    case $choice in
        1)
            if [ -f "$CONFIG_DIR/server.yaml" ]; then
                cat "$CONFIG_DIR/server.yaml"
            else
                echo -e "${RED}Server config not found${NC}"
            fi
            read -p "Press Enter to continue..."
            manage_configs
            ;;
        2)
            if [ -f "$CONFIG_DIR/client.yaml" ]; then
                cat "$CONFIG_DIR/client.yaml"
            else
                echo -e "${RED}Client config not found${NC}"
            fi
            read -p "Press Enter to continue..."
            manage_configs
            ;;
        3)
            if [ -f "$CONFIG_DIR/server.yaml" ]; then
                ${EDITOR:-nano} "$CONFIG_DIR/server.yaml"
            else
                echo -e "${RED}Server config not found${NC}"
                read -p "Press Enter to continue..."
            fi
            manage_configs
            ;;
        4)
            if [ -f "$CONFIG_DIR/client.yaml" ]; then
                ${EDITOR:-nano} "$CONFIG_DIR/client.yaml"
            else
                echo -e "${RED}Client config not found${NC}"
                read -p "Press Enter to continue..."
            fi
            manage_configs
            ;;
        5)
            read -p "$(echo -e ${RED}Delete server config? [y/N]: ${NC})" confirm
            if [[ $confirm =~ ^[Yy]$ ]]; then
                rm -f "$CONFIG_DIR/server.yaml"
                echo -e "${GREEN}✓ Server config deleted${NC}"
            fi
            read -p "Press Enter to continue..."
            manage_configs
            ;;
        6)
            read -p "$(echo -e ${RED}Delete client config? [y/N]: ${NC})" confirm
            if [[ $confirm =~ ^[Yy]$ ]]; then
                rm -f "$CONFIG_DIR/client.yaml"
                echo -e "${GREEN}✓ Client config deleted${NC}"
            fi
            read -p "Press Enter to continue..."
            manage_configs
            ;;
        0) main_menu ;;
        *) manage_configs ;;
    esac
}

# Manage services
manage_services() {
    show_banner
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}       SERVICE MANAGEMENT${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
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
    echo ""
    read -p "$(echo -e ${YELLOW}Select option: ${NC})" choice

    case $choice in
        1) systemctl start potty-server && echo -e "${GREEN}✓ Server started${NC}" ;;
        2) systemctl start potty-client && echo -e "${GREEN}✓ Client started${NC}" ;;
        3) systemctl stop potty-server && echo -e "${GREEN}✓ Server stopped${NC}" ;;
        4) systemctl stop potty-client && echo -e "${GREEN}✓ Client stopped${NC}" ;;
        5) systemctl restart potty-server && echo -e "${GREEN}✓ Server restarted${NC}" ;;
        6) systemctl restart potty-client && echo -e "${GREEN}✓ Client restarted${NC}" ;;
        7) systemctl status potty-server ;;
        8) systemctl status potty-client ;;
        9) systemctl enable potty-server && echo -e "${GREEN}✓ Server auto-start enabled${NC}" ;;
        10) systemctl enable potty-client && echo -e "${GREEN}✓ Client auto-start enabled${NC}" ;;
        11) systemctl disable potty-server && echo -e "${GREEN}✓ Server auto-start disabled${NC}" ;;
        12) systemctl disable potty-client && echo -e "${GREEN}✓ Client auto-start disabled${NC}" ;;
        13) journalctl -u potty-server -f ;;
        14) journalctl -u potty-client -f ;;
        0) main_menu ;;
    esac

    if [ $choice -ne 0 ] && [ $choice -ne 13 ] && [ $choice -ne 14 ]; then
        read -p "Press Enter to continue..."
    fi

    manage_services
}

# Uninstall
uninstall_potty() {
    show_banner
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}       UNINSTALL POTTY${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${YELLOW}⚠️  This will remove:${NC}"
    echo "  - Potty binary"
    echo "  - All configurations"
    echo "  - Systemd services"
    echo ""
    read -p "$(echo -e ${RED}Are you sure? [y/N]: ${NC})" confirm

    if [[ $confirm =~ ^[Yy]$ ]]; then
        # Stop services
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

        echo ""
        echo -e "${GREEN}✓ Potty uninstalled successfully${NC}"
        echo ""
        exit 0
    else
        main_menu
    fi
}

# Main execution
check_root
show_banner
install_dependencies

# Check if potty is already installed
if [ ! -f "$INSTALL_DIR/potty" ]; then
    echo -e "${YELLOW}Potty not found. Installing...${NC}"
    download_binary
fi

main_menu