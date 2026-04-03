#!/bin/bash
#
# САФТ "Рубеж" Installation Script
#
# Automatically installs and configures SAFT Rubezh with:
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
echo -e "${GREEN}  САФТ Рубеж Installation Script${NC}"
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
echo "This may take a few minutes..."

# Update package list quietly
apt-get update -qq 2>&1 | grep -v "^Get:" | grep -v "^Fetched" || true

# Install packages one by one with progress
PACKAGES="clang llvm libbpf-dev linux-headers-$(uname -r) build-essential python3 python3-pip python3-yaml python3-flask iproute2 bpftool git curl"

for pkg in $PACKAGES; do
    echo -n "  Installing $pkg... "
    if dpkg -l | grep -q "^ii  $pkg"; then
        echo "[already installed]"
    else
        apt-get install -y -qq $pkg > /dev/null 2>&1 && echo "[done]" || echo "[failed]"
    fi
done

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
    echo -e "${RED}ERROR: bpf/xdp_filter.c not found. Are you in the rubezh-saft directory?${NC}"
    exit 1
fi

mkdir -p build

echo "  Running clang compiler..."
# Fixed compilation flags - no 32-bit stubs needed
clang -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    -D__BPF_TRACING__ \
    -I/usr/include/x86_64-linux-gnu \
    -c bpf/xdp_filter.c \
    -o build/xdp_filter.o 2>&1 | head -20

if [ ! -f "build/xdp_filter.o" ]; then
    echo -e "${RED}ERROR: XDP compilation failed${NC}"
    echo -e "${YELLOW}Try installing: sudo apt-get install gcc-multilib${NC}"
    exit 1
fi

echo -e "${GREEN}✓ XDP program compiled successfully${NC}"

# Step 4: Install files
echo -e "${GREEN}[4/8] Installing files...${NC}"

# Create directories
mkdir -p /opt/rubezh-saft
mkdir -p /usr/lib/rubezh-saft
mkdir -p /etc/rubezh-saft
mkdir -p /var/log

echo "  Copying Python files..."
cp -r python /opt/rubezh-saft/
cp -r web /opt/rubezh-saft/
cp daemon.py /opt/rubezh-saft/
cp cli.py /opt/rubezh-saft/

echo "  Copying XDP program..."
cp build/xdp_filter.o /usr/lib/rubezh-saft/

echo -e "${GREEN}✓ Files installed to /opt/rubezh-saft${NC}"

# Step 5: Configure
echo -e "${GREEN}[5/8] Configuring...${NC}"

if [ "$UPDATE_MODE" = true ] && [ -f "/etc/rubezh-saft/config.yaml" ]; then
    echo -e "${YELLOW}⚠ Config exists, preserving /etc/rubezh-saft/config.yaml${NC}"
    # Still update interface if it changed
    sed -i "s/interface:.*/interface: $INTERFACE/" /etc/rubezh-saft/config.yaml
else
    # Fresh install - copy config and customize
    if [ -f "config/config.yaml" ]; then
        cp config/config.yaml /etc/rubezh-saft/config.yaml
    else
        echo -e "${RED}ERROR: config/config.yaml not found${NC}"
        exit 1
    fi

    # Set detected interface
    sed -i "s/interface:.*/interface: $INTERFACE/" /etc/rubezh-saft/config.yaml

    # Generate unique cryptographic secrets so every fresh installation has
    # distinct credentials.  python3 is guaranteed present at this point
    # (installed in Step 1).
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    API_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

    # Replace the placeholder values written by the template config.
    sed -i "s/secret_key:.*/secret_key: $SECRET_KEY/" /etc/rubezh-saft/config.yaml
    sed -i "s/api_key:.*/api_key: \"$API_KEY\"/" /etc/rubezh-saft/config.yaml

    echo -e "${GREEN}✓ Config installed to /etc/rubezh-saft/config.yaml${NC}"
    echo -e "${YELLOW}  Generated secret_key and api_key — save the API key for CLI access:${NC}"
    echo -e "  api_key: $API_KEY"
fi

# Step 6: Install systemd service
echo -e "${GREEN}[6/8] Installing systemd service...${NC}"

cat > /etc/systemd/system/rubezh-saft.service << 'EOF'
[Unit]
Description=САФТ Рубеж — Система Анализа и Фильтрации Трафика
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/rubezh-saft
ExecStart=/usr/bin/python3 /opt/rubezh-saft/daemon.py
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
chown -R root:root /opt/rubezh-saft
chmod +x /opt/rubezh-saft/daemon.py
chmod +x /opt/rubezh-saft/cli.py
chmod 644 /etc/rubezh-saft/config.yaml
echo -e "${GREEN}✓ Permissions set${NC}"

# Step 8: Enable and start service
echo -e "${GREEN}[8/8] Starting service...${NC}"

if [ "$UPDATE_MODE" = true ]; then
    echo -e "${YELLOW}Restarting rubezh-saft service...${NC}"
    systemctl restart rubezh-saft
else
    systemctl enable rubezh-saft
    systemctl start rubezh-saft
fi

# Wait for service to start
echo "  Waiting for service to initialize..."
sleep 5

# Check service status
if systemctl is-active --quiet rubezh-saft; then
    echo -e "${GREEN}✓ САФТ Рубеж service is running${NC}"
else
    echo -e "${RED}⚠ Service started but may have issues. Check: journalctl -u rubezh-saft -n 50${NC}"
fi

echo ""
echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}=====================================${NC}"
echo ""
echo -e "${YELLOW}Quick Start:${NC}"
echo -e "  - Web UI: http://$(hostname -I | awk '{print $1}'):8080"
echo -e "  - Status: systemctl status rubezh-saft"
echo -e "  - Logs: journalctl -u rubezh-saft -f"
echo -e "  - Config: /etc/rubezh-saft/config.yaml"
echo ""
echo -e "${YELLOW}Verify ConfigSync is working:${NC}"
echo -e "  sudo journalctl -u rubezh-saft -n 50 | grep -i 'config\|sync'"
echo ""
echo -e "${YELLOW}Important:${NC}"
echo -e "  1. Add your management IPs to whitelist_ips in config"
echo -e "  2. Adjust rate limits if needed (default: 1000 SYN/sec)"
echo -e "  3. Restart after config changes: systemctl restart rubezh-saft"
echo ""
echo -e "${GREEN}Happy protecting! 🛡️${NC}"
