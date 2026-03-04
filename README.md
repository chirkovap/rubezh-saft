# XDPGuard

**High-performance DDoS protection system using XDP/eBPF** 🛡️

XDPGuard provides kernel-level packet filtering with **dynamic configuration** - change rate limits without recompiling!

## ✨ Features

- 🚀 **Ultra-fast**: XDP processes packets at NIC driver level
- ⚙️ **Dynamic Config**: Change rate limits in real-time via `config.yaml`
- 🎯 **Protocol-specific**: Separate limits for TCP SYN, UDP, ICMP
- 🔒 **Whitelist/Blacklist**: IP-based access control
- 📊 **Real-time Stats**: Live packet statistics and monitoring
- 🌎 **Web UI**: Beautiful dashboard with dark theme (RU/EN)
- 📦 **Packet Logging**: Detailed capture logs (like ELK/Splunk)
- 🔔 **Event System**: SIEM-style attack detection and logging

## 📦 Quick Start

### Installation (Automatic)

```bash
# Clone repository
git clone https://github.com/chirkovap/xdpguard.git
cd xdpguard

# Run automated install (compiles XDP, installs everything)
sudo ./scripts/install.sh

# Access web UI
firefox http://$(hostname -I | awk '{print $1}'):8080
```

**That's it!** 🎉 XDPGuard is now protecting your system.

### Update Existing Installation

```bash
cd xdpguard
git pull origin main

# Update without losing config
sudo ./scripts/install.sh update
```

## ⚙️ Configuration

### How It Works

🔑 **Key Innovation**: XDPGuard uses BPF maps for configuration storage. When you edit `/etc/xdpguard/config.yaml` and restart, Python automatically syncs values to XDP kernel maps - **no recompilation needed**!

### Configure Rate Limits

Edit `/etc/xdpguard/config.yaml`:

```yaml
protection:
  enabled: true
  
  # Packets per second per IP
  syn_rate: 1000      # TCP SYN packets
  udp_rate: 500       # UDP packets  
  icmp_rate: 100      # ICMP packets
  
  # Burst allowance
  syn_burst: 2000
  udp_burst: 1000
  icmp_burst: 200
```

**Apply changes:**

```bash
sudo systemctl restart xdpguard

# Verify sync
sudo journalctl -u xdpguard -n 20 | grep -i "config"
# Should show: ✓ Rate limits synced to XDP successfully
```

### Whitelist Management

**IMPORTANT**: Add your management IPs to avoid lockout!

```yaml
whitelist_ips:
  - 127.0.0.1           # Localhost
  - 192.168.0.0/16      # Local network
  - 10.0.0.0/8          # VPN network
  - YOUR.IP.HERE        # <-- Add your IP!
```

Whitelist is automatically synced to XDP on restart.

### Network Interface

Auto-detected during install, but verify:

```yaml
network:
  interface: ens33    # Change if needed
  xdp_mode: xdpgeneric
```

Find your interface: `ip link show`

## 🔧 Management

### Service Control

```bash
# Status
sudo systemctl status xdpguard

# Start/Stop
sudo systemctl start xdpguard
sudo systemctl stop xdpguard

# Restart (applies config changes)
sudo systemctl restart xdpguard

# Logs
sudo journalctl -u xdpguard -f
```

### CLI Commands

```bash
cd /opt/xdpguard

# Get statistics
sudo python3 cli.py stats

# Block IP
sudo python3 cli.py block 1.2.3.4

# Unblock IP
sudo python3 cli.py unblock 1.2.3.4

# List blocked IPs
sudo python3 cli.py list
```

### Web API

```bash
# Get status
curl http://localhost:8080/api/status

# Get events
curl http://localhost:8080/api/events?limit=20

# Get packet logs
curl http://localhost:8080/api/packets?limit=100

# Block IP
curl -X POST http://localhost:8080/api/block \
  -H "Content-Type: application/json" \
  -d '{"ip": "1.2.3.4", "reason": "malicious"}'
```

## 📊 Web Dashboard

### Features

- **Dashboard**: Real-time statistics, throughput, drop rate
- **Events Log**: Attack detection, blocks, system events
- **Packet Log**: Detailed packet capture with filtering
- **Themes**: Light/Dark mode toggle
- **Languages**: English/Russian

### Screenshots

Access at: `http://<your-server-ip>:8080`

- 📊 Drop rate indicator
- 🟢 Packets passed/dropped
- 🚫 Blocked IPs list
- ⚡ Quick actions (block, unblock, reload)

## 🛠️ Architecture

```
┌───────────────────┐
│  Network Packets  │
└───────┬───────────┘
        │
        │ NIC Driver
        │
        │
   ┌────┴─────────────┐
   │  XDP/eBPF Filter  │  <-- Kernel space (C)
   │  - Whitelist      │
   │  - Blacklist      │
   │  - Rate Limits    │
   │  - Stats          │
   └─────┬────────────┘
        │
        │ BPF Maps (shared memory)
        │
   ┌────┴─────────────┐
   │  Python Manager   │  <-- Userspace
   │  - ConfigSync     │
   │  - EventLogger    │
   │  - PacketCapture  │
   │  - Web UI         │
   └──────────────────┘
```

**Key Components:**

1. **XDP Filter** (`bpf/xdp_filter.c`): C program running in kernel
2. **ConfigSync** (`python/config_sync.py`): Syncs YAML to BPF maps
3. **XDPManager** (`python/xdpmanager.py`): Manages XDP lifecycle
4. **Web Dashboard** (`web/app.py`): Flask-based UI

## 🐛 Troubleshooting

### SSH/Web UI Becomes Unreachable

**Cause**: Rate limits too aggressive, blocking legitimate traffic.

**Fix**:

```bash
# Emergency: Disable XDP from console
sudo ip link set dev ens33 xdp off

# Edit config
sudo nano /etc/xdpguard/config.yaml
# Increase: syn_rate: 1000, udp_rate: 500

# Add your IP to whitelist
# whitelist_ips:
#   - YOUR.IP.HERE

# Restart
sudo systemctl restart xdpguard
```

### Config Changes Not Applied

**Verify sync**:

```bash
sudo journalctl -u xdpguard -n 30 | grep -i sync
```

Should show:
```
✓ Rate limits synced to XDP successfully
✓ Config verification passed
```

If not:
```bash
# Reinstall to fix BPF maps
cd xdpguard
sudo ./scripts/install.sh update
```

### PacketCapture Not Working

```bash
# Check logs
sudo journalctl -u xdpguard -n 50 | grep -i packet

# Should see:
# PacketCapture инициализирован
# ✓ Захват пакетов запущен

# Enable in config if disabled
# logging:
#   enable_packet_logging: true
```

### High Drop Rate (>50%)

**Check**:

```bash
curl http://localhost:8080/api/status
```

If `packets_dropped / packets_total > 0.5`:

1. **Increase rate limits** in config
2. **Add legit IPs to whitelist**
3. **Check for actual attack**: `curl http://localhost:8080/api/events`

## 📚 FAQ

**Q: Does config.yaml really work without recompiling?**  
A: Yes! Since commit `919041d`, Python syncs config to BPF maps dynamically.

**Q: Why is my VM slow after enabling XDPGuard?**  
A: Use `xdpgeneric` mode (default). Native `xdpdrv` requires driver support.

**Q: Can I use this in production?**  
A: Yes, but test rate limits first! Start with high values (1000+) and adjust down.

**Q: How to add entire subnet to whitelist?**  
A: Use CIDR notation: `192.168.0.0/24` or `10.0.0.0/8`

**Q: Does it protect against all DDoS attacks?**  
A: It mitigates volumetric attacks (SYN flood, UDP flood, ICMP flood). Application-layer attacks (HTTP flood) need additional protection.

## 📝 System Requirements

- **OS**: Ubuntu 20.04+, Debian 11+, or similar
- **Kernel**: 5.4+ with XDP support
- **RAM**: 512MB minimum, 1GB recommended
- **Disk**: 100MB for installation
- **Root access** required

## 👥 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push: `git push origin feature/amazing`
5. Open Pull Request

## 📜 License

GPL-3.0 License - See [LICENSE](LICENSE) file

## 👏 Credits

- **eBPF/XDP**: Linux kernel BPF subsystem
- **libbpf**: BPF library
- **Flask**: Web framework
- **Plotly**: Charts (if enabled)

## 📧 Support

- **Issues**: [GitHub Issues](https://github.com/chirkovap/xdpguard/issues)
- **Docs**: This README + code comments
- **Community**: Check [Discussions](https://github.com/chirkovap/xdpguard/discussions)

---

**Made with ❤️ and eBPF**
