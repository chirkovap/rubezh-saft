#!/bin/bash
#
# XDPGuard Installation Script
#
# Automatically installs and configures XDPGuard with:
# - Dependency installation
# - XDP program compilation
# - Configuration setup
# - Systemd service installation
#
# Usage:
#   sudo ./scripts/install.sh         # Fresh install
#   sudo ./scripts/install.sh update  # Update existing installation
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0;m' # No Color

echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}  XDPGuard Installation Script${NC}"
echo -e "${GREEN}=====================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}ERROR: Please run as root (use sudo)${NC}"
    exit 1
fi

# Detect installation mode
MODE="${1:-install}"
if [ "$MODE" = "update" ]; then
    echo -e "${YELLOW}Mode: UPDATE (preserving config)${NC}"
    UPDATE_MODE=true
else
    echo -e "${YELLOW}Mode: FRESH INSTALL${NC}"
    UPDATE_MODE=false
fi

echo ""

# Step 1: Install dependencies
echo -e "${GREEN}[1/8] Installing dependencies...${NC}"
apt-get update -qq
apt-get install -y -qq \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    build-essential \
    python3 \
    python3-pip \
    python3-yaml \
    python3-flask \
    iproute2 \
    bpftool \
    git \
    curl > /dev/null 2>&1

echo -e "${GREEN}✓ Dependencies installed${NC}"

# Step 2: Detect network interface
echo -e "${GREEN}[2/8] Detecting network interface...${NC}"
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -z "$INTERFACE" ]; then
    INTERFACE="eth0"  # Fallback
    echo -e "${YELLOW}⚠ Could not detect interface, using $INTERFACE${NC}"
else
    echo -e "${GREEN}✓ Detected interface: $INTERFACE${NC}"
fi

# Step 3: Compile XDP program
echo -e "${GREEN}[3/8] Compiling XDP program...${NC}"

if [ ! -f "bpf/xdp_filter.c" ]; then
    echo -e "${RED}ERROR: bpf/xdp_filter.c not found. Are you in the xdpguard directory?${NC}"
    exit 1
fi

mkdir -p build

clang -O2 -g -target bpf \
    -D__BPF_TRACING__ \
    -I/usr/include/$(uname -m)-linux-gnu \
    -c bpf/xdp_filter.c \
    -o build/xdp_filter.o

if [ ! -f "build/xdp_filter.o" ]; then
    echo -e "${RED}ERROR: XDP compilation failed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ XDP program compiled successfully${NC}"

# Step 4: Install files
echo -e "${GREEN}[4/8] Installing files...${NC}"

# Create directories
mkdir -p /opt/xdpguard
mkdir -p /usr/lib/xdpguard
mkdir -p /etc/xdpguard
mkdir -p /var/log

# Copy Python files
cp -r python /opt/xdpguard/
cp -r web /opt/xdpguard/
cp daemon.py /opt/xdpguard/
cp cli.py /opt/xdpguard/

# Copy compiled XDP program
cp build/xdp_filter.o /usr/lib/xdpguard/

echo -e "${GREEN}✓ Files installed to /opt/xdpguard${NC}"

# Step 5: Configure
echo -e "${GREEN}[5/8] Configuring...${NC}"

if [ "$UPDATE_MODE" = true ] && [ -f "/etc/xdpguard/config.yaml" ]; then
    echo -e "${YELLOW}⚠ Config exists, preserving /etc/xdpguard/config.yaml${NC}"
    # Still update interface if it changed
    sed -i "s/interface:.*/interface: $INTERFACE/" /etc/xdpguard/config.yaml
else
    # Fresh install - copy config and customize
    if [ -f "config/config.yaml" ]; then
        cp config/config.yaml /etc/xdpguard/config.yaml
    else
        echo -e "${RED}ERROR: config/config.yaml not found${NC}"
        exit 1
    fi
    
    # Set detected interface
    sed -i "s/interface:.*/interface: $INTERFACE/" /etc/xdpguard/config.yaml
    
    echo -e "${GREEN}✓ Config installed to /etc/xdpguard/config.yaml${NC}"
fi

# Step 6: Install systemd service
echo -e "${GREEN}[6/8] Installing systemd service...${NC}"

cat > /etc/systemd/system/xdpguard.service << 'EOF'
[Unit]
Description=XDPGuard DDoS Protection System
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/xdpguard
ExecStart=/usr/bin/python3 /opt/xdpguard/daemon.py
Restart=on-failure
RestartSec=10s

# Logging
StandardOutput=journal
StandardError=journal

# Security
NoNewPrivileges=false
PrivateTmp=true

# Resource limits
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo -e "${GREEN}✓ Systemd service installed${NC}"

# Step 7: Set permissions
echo -e "${GREEN}[7/8] Setting permissions...${NC}"
chown -R root:root /opt/xdpguard
chmod +x /opt/xdpguard/daemon.py
chmod +x /opt/xdpguard/cli.py
chmod 644 /etc/xdpguard/config.yaml
echo -e "${GREEN}✓ Permissions set${NC}"

# Step 8: Enable and start service
echo -e "${GREEN}[8/8] Starting service...${NC}"

if [ "$UPDATE_MODE" = true ]; then
    echo -e "${YELLOW}Restarting xdpguard service...${NC}"
    systemctl restart xdpguard
else
    systemctl enable xdpguard
    systemctl start xdpguard
fi

# Wait a moment for service to start
sleep 2

# Check service status
if systemctl is-active --quiet xdpguard; then
    echo -e "${GREEN}✓ XDPGuard service is running${NC}"
else
    echo -e "${RED}⚠ Service started but may have issues. Check: journalctl -u xdpguard -n 50${NC}"
fi

echo ""
echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}=====================================${NC}"
echo ""
echo -e "${YELLOW}Quick Start:${NC}"
echo -e "  - Web UI: http://$(hostname -I | awk '{print $1}'):8080"
echo -e "  - Status: systemctl status xdpguard"
echo -e "  - Logs: journalctl -u xdpguard -f"
echo -e "  - Config: /etc/xdpguard/config.yaml"
echo ""
echo -e "${YELLOW}Important:${NC}"
echo -e "  1. Configure rate limits in /etc/xdpguard/config.yaml"
echo -e "  2. Add your management IPs to whitelist_ips"
echo -e "  3. Restart service: systemctl restart xdpguard"
echo ""
echo -e "${GREEN}Happy protecting! 🛡️${NC}"
