# XDPGuard - High-Performance DDoS Protection

🛡️ **XDP/eBPF-based DDoS protection system for Linux** with real-time configuration and web dashboard.

## ✨ Key Features

- **🚀 Ultra-fast packet filtering** at kernel level using XDP/eBPF
- **⚙️ Runtime configuration** - change rate limits without recompiling!
- **📊 Web Dashboard** with real-time statistics (Russian/English, Dark theme)
- **📈 Three monitoring tabs**: Dashboard, Event Logs, Packet Logs
- **🤖 Automatic attack detection** and IP blocking
- **✅ Whitelist support** to protect trusted IPs
- **📦 One-command installation** with automatic dependency management

## 🔥 What's New v2.0

✅ **Runtime config sync** - XDP limits update from config.yaml automatically  
✅ **ConfigSync module** - applies settings to BPF maps without recompilation  
✅ **Makefile** - automatic XDP compilation with dependency checking  
✅ **install.sh** - one-command installation script  
✅ **Optimized defaults** - 1000 SYN/sec (was 30) to prevent blocking legitimate traffic  

## 💻 Quick Start

### One-Command Installation

```bash
# Clone repository
git clone https://github.com/chirkovap/xdpguard.git
cd xdpguard

# Run installer (automatically installs dependencies, compiles XDP, sets up service)
sudo ./install.sh

# Start service
sudo systemctl start xdpguard
sudo systemctl enable xdpguard  # Auto-start on boot

# Access web interface
# Open browser: http://YOUR_IP:8080
```

That's it! 🎉 The system is now protecting your server.

## 🔧 Manual Installation

If you prefer manual control:

### 1. Install Dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip clang llvm gcc make \
    libbpf-dev linux-headers-$(uname -r) bpftool iproute2

pip3 install flask pyyaml scapy
```

### 2. Compile XDP Program

```bash
make              # Compile XDP program
sudo make install # Install to /usr/lib/xdpguard/
```

### 3. Configure

```bash
# Copy config
sudo mkdir -p /etc/xdpguard
sudo cp config/config.yaml /etc/xdpguard/

# Edit config (set your network interface!)
sudo nano /etc/xdpguard/config.yaml
```

### 4. Install Service

```bash
# Copy files
sudo mkdir -p /opt/xdpguard
sudo cp -r python web daemon.py /opt/xdpguard/

# Create systemd service
sudo nano /etc/systemd/system/xdpguard.service
```

Paste:
```ini
[Unit]
Description=XDPGuard DDoS Protection Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/xdpguard
ExecStart=/usr/bin/python3 /opt/xdpguard/daemon.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
# Start service
sudo systemctl daemon-reload
sudo systemctl start xdpguard
sudo systemctl enable xdpguard
```

## ⚙️ Configuration

### Important: Runtime Configuration

**XDPGuard v2.0+ supports runtime configuration!** You can change rate limits in `config.yaml` and they will be applied automatically when the service starts.

### Key Settings in `/etc/xdpguard/config.yaml`:

```yaml
network:
  interface: ens33        # Change to your interface (ip link show)
  xdp_mode: xdpgeneric   # xdpgeneric, xdpdrv, or xdpoffload

protection:
  enabled: true
  syn_rate: 1000         # SYN packets/sec per IP (default: 1000)
  syn_burst: 2000        # Burst allowance
  conn_rate: 1000        # Connections/sec
  udp_rate: 500          # UDP packets/sec
  icmp_rate: 100         # ICMP packets/sec

whitelist_ips:
  - 127.0.0.1           # Localhost
  - 192.168.0.0/16      # Private networks
  - 10.0.0.0/8
  # Add your management IPs here!

logging:
  enable_packet_logging: true  # Show packets in web UI
  max_packets: 10000

web:
  host: 0.0.0.0         # Web interface host
  port: 8080            # Web interface port
```

### ⚠️ Important: Whitelist Your IPs!

Always add your management IPs to the whitelist to prevent locking yourself out:

```yaml
whitelist_ips:
  - 127.0.0.1
  - 192.168.146.0/24    # Your subnet
  - YOUR_PUBLIC_IP      # Your management IP
```

### After Config Changes

```bash
# Just restart the service - config is auto-synced!
sudo systemctl restart xdpguard

# Check logs to verify config sync
sudo journalctl -u xdpguard --since "10 seconds ago" | grep "Синхронизация"
```

You should see:
```
Синхронизация конфигурации с XDP...
✓ SYN rate limit: 1000
✓ UDP rate limit: 500
✓ ICMP rate limit: 100
✓ Конфигурация успешно синхронизирована с XDP
```

## 🔍 Monitoring

### Web Dashboard

Access: `http://YOUR_IP:8080`

**Three tabs:**
1. **📊 Dashboard** - Real-time statistics, drop rate, throughput
2. **📝 Event Logs** - Attack events, blocks, system events
3. **📦 Packet Logs** - Individual packet captures with details

### Command Line

```bash
# View logs
sudo journalctl -u xdpguard -f

# Check statistics via API
curl http://localhost:8080/api/status
curl http://localhost:8080/api/packets?limit=10
curl http://localhost:8080/api/events?limit=20

# Check XDP is loaded
sudo ip link show YOUR_INTERFACE | grep xdp

# View BPF maps
sudo bpftool map dump name stats_map
sudo bpftool map dump name blacklist
sudo bpftool map dump name config_map
```

## 🧪 Testing

### Generate Test Traffic

```bash
# From another machine, test with hping3
sudo hping3 -S -p 80 --flood YOUR_SERVER_IP

# Or simple ping flood
ping -f YOUR_SERVER_IP
```

### Manual IP Blocking

```bash
# Block IP via API
curl -X POST http://localhost:8080/api/block \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "reason": "test"}'

# Unblock IP
curl -X POST http://localhost:8080/api/unblock \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100"}'

# View blocked IPs
curl http://localhost:8080/api/blacklist
```

## 🛠️ Troubleshooting

### SSH/Web Becomes Unreachable After XDP Load

**Problem:** Rate limits are too aggressive and block legitimate traffic.

**Solution:**
```bash
# 1. Disable XDP immediately (from console or SSH if still accessible)
sudo ip link set dev YOUR_INTERFACE xdp off

# 2. Add your IPs to whitelist
sudo nano /etc/xdpguard/config.yaml
# Add your management subnet:
whitelist_ips:
  - 192.168.146.0/24

# 3. Restart service (config will auto-sync)
sudo systemctl restart xdpguard
```

### Config Changes Not Applied

**Check if config sync worked:**
```bash
sudo journalctl -u xdpguard --since "1 minute ago" | grep -i sync
```

You should see:
- "Синхронизация конфигурации с XDP..."
- "✓ SYN rate limit: 1000" (your value)
- "✓ Конфигурация успешно синхронизирована"

### XDP Won't Load

```bash
# Check if XDP file exists
ls -lh /usr/lib/xdpguard/xdp_filter.o

# If not, recompile:
cd /opt/xdpguard  # or your clone directory
sudo make clean
sudo make
sudo make install

# Restart service
sudo systemctl restart xdpguard
```

### High Drop Rate (>50%)

**Symptoms:** Dashboard shows >50% packets dropped, SSH lags.

**Cause:** Rate limits too low for your traffic.

**Fix:**
```bash
sudo nano /etc/xdpguard/config.yaml
# Increase limits:
protection:
  syn_rate: 2000      # Increase
  conn_rate: 2000
  udp_rate: 1000
  
# Add your subnet to whitelist
whitelist_ips:
  - YOUR_SUBNET/24

sudo systemctl restart xdpguard
```

## 📚 Architecture

### How It Works

1. **XDP Program (bpf/xdp_filter.c)** - Runs at NIC driver level, filters packets in kernel
2. **ConfigSync (python/config_sync.py)** - Syncs config.yaml to BPF maps via bpftool
3. **XDPManager (python/xdpmanager.py)** - Manages XDP lifecycle, statistics, blocking
4. **Web Dashboard (web/)** - Flask-based UI for monitoring
5. **Daemon (daemon.py)** - Main service orchestrator

### Config Flow

```
config.yaml → ConfigSync → BPF config_map → XDP program
     ↑                                           ↓
     User edits                         Packet filtering (kernel)
```

**Key Benefit:** No recompilation needed! Just edit config.yaml and restart service.

## 📝 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | System statistics |
| `/api/events` | GET | Event logs |
| `/api/packets` | GET | Packet logs |
| `/api/packets/stats` | GET | Packet statistics |
| `/api/blacklist` | GET | Blocked IPs |
| `/api/block` | POST | Block IP |
| `/api/unblock` | POST | Unblock IP |

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 📜 License

GPL-3.0 License - See LICENSE file

## 📧 Contact

For issues and questions, please use GitHub Issues.

---

**Made with ❤️ by chirkovap**
