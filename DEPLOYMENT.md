# FALCON-X Deployment Guide

## Overview

This guide covers deployment of FALCON-X on both the current demonstration platform (x86_64 laptop) and the target platform (Raspberry Pi 4 ARM64).

## Platform Requirements

### Current Platform (x86_64 Laptop)
- Intel Pentium or compatible
- 4 GB RAM minimum
- 500 GB HDD minimum
- Minimal Debian/Ubuntu Linux
- systemd
- nftables
- Python 3.8+
- Network interface for monitoring

### Target Platform (Raspberry Pi 4 ARM64)
- Raspberry Pi 4 (4GB+ RAM recommended)
- ARM64 Linux (Raspberry Pi OS or similar)
- systemd
- nftables
- Python 3.8+
- Network interface for monitoring

## System Preparation

### Base System Installation

#### x86_64 Laptop
```bash
# Install minimal Debian/Ubuntu
sudo apt-get update
sudo apt-get upgrade -y

# Install essential packages
sudo apt-get install -y python3 python3-pip nftables systemd
```

#### Raspberry Pi 4
```bash
# Install Raspberry Pi OS Lite (ARM64)
sudo apt-get update
sudo apt-get upgrade -y

# Install essential packages
sudo apt-get install -y python3 python3-pip nftables systemd
```

## FALCON-X Installation

### 1. Copy Files

```bash
# Create installation directory
sudo mkdir -p /opt/falconx

# Copy FALCON-X files
sudo cp -r . /opt/falconx/

# Set ownership
sudo chown -R root:root /opt/falconx
```

### 2. Install Python Dependencies

```bash
cd /opt/falconx
sudo pip3 install -r requirements.txt
```

### 3. Make Scripts Executable

```bash
sudo chmod +x /opt/falconx/bin/falconx-detect
sudo chmod +x /opt/falconx/bin/falconx-menu
sudo chmod +x /opt/falconx/tests/lab/generate_traffic.py
```

### 4. Install systemd Services

```bash
# Copy service files
sudo cp /opt/falconx/systemd/falconx-engine.service /etc/systemd/system/
sudo cp /opt/falconx/systemd/falconx-menu.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable engine service (starts at boot)
sudo systemctl enable falconx-engine.service

# Enable menu service
sudo systemctl enable falconx-menu.service
```

### 5. Create Log Directory

```bash
sudo mkdir -p /var/log
sudo touch /var/log/falconx-engine.log
sudo chown root:root /var/log/falconx-engine.log
```

### 6. Configure Network Interface

Edit the engine service to use your network interface:

```bash
sudo nano /etc/systemd/system/falconx-engine.service
```

Change `ExecStart` line to use your interface:
```
ExecStart=/opt/falconx/bin/falconx-detect start eth0
```

Replace `eth0` with your actual interface name (e.g., `wlan0`, `enp3s0`).

```bash
# Reload systemd after changes
sudo systemctl daemon-reload
```

## Configuration

### Engine Configuration

The engine can be configured by modifying `/opt/falconx/falconx/main.py`:

- Interface selection
- Queue sizes
- Detection thresholds
- Learning window duration

### Enforcement Mode

Default mode is **LOG-ONLY**. To enable active enforcement:

Edit `/opt/falconx/falconx/enforcement.py`:
```python
self.enforcement = EnforcementManager(mode='active')
```

**WARNING**: Active enforcement will block traffic. Use with caution.

### Dashboard Configuration

Edit `/opt/falconx/dashboard/app.py` to change dashboard settings:
- Host binding
- Port number
- Debug mode

## Starting the System

### Manual Start

```bash
# Start detection engine
sudo /opt/falconx/bin/falconx-detect start eth0

# Start dashboard (optional)
python3 /opt/falconx/dashboard/app.py --host 0.0.0.0 --port 8080
```

### Automatic Start (systemd)

```bash
# Start engine service
sudo systemctl start falconx-engine.service

# Check status
sudo systemctl status falconx-engine.service

# View logs
sudo journalctl -u falconx-engine.service -f
```

## Verification

### Check Engine Status

```bash
/opt/falconx/bin/falconx-detect status
```

### Run Safe Test

```bash
/opt/falconx/bin/falconx-detect test
```

### Launch Menu

```bash
/opt/falconx/bin/falconx-menu
```

### Access Dashboard

Open browser to: http://localhost:8080

## Network Configuration

### Monitor Interface

The engine needs to monitor network traffic. Configure your network to route traffic through the FALCON-X system:

**Option 1: Bridge Mode**
- Configure network bridge
- Place FALCON-X between network and internet

**Option 2: SPAN Port**
- Configure switch SPAN port
- Mirror traffic to FALCON-X monitoring interface

**Option 3: Host-based**
- Monitor local traffic only
- Suitable for single host protection

## Platform-Specific Notes

### x86_64 Laptop
- Full functionality available
- Use for development and testing
- All features operational

### Raspberry Pi 4
- Resource constraints apply
- Reduce queue sizes if needed
- Monitor memory usage
- Consider SD card wear for logging

## Troubleshooting

### Engine Won't Start

```bash
# Check logs
sudo journalctl -u falconx-engine.service -n 50

# Check interface
ip link show

# Check permissions
ls -la /opt/falconx/bin/
```

### No Packets Captured

```bash
# Check interface is up
ip link show eth0

# Check promiscuous mode
sudo ip link set eth0 promisc on

# Check permissions
sudo /opt/falconx/bin/falconx-detect status
```

### Dashboard Not Accessible

```bash
# Check if running
ps aux | grep dashboard

# Check port
netstat -tlnp | grep 8080

# Check firewall
sudo nft list ruleset
```

### High Memory Usage

Reduce queue sizes in `falconx/capture.py`:
```python
self.queue: queue.Queue[Packet] = queue.Queue(maxsize=500)  # Reduce from 1000
```

## Security Considerations

### Default Security
- LOG-ONLY enforcement mode
- No automatic blocking
- nftables only (no iptables)
- Isolated privileged operations

### Hardening
- Enable firewall rules
- Restrict dashboard access
- Use HTTPS for dashboard
- Regular updates
- Monitor logs

### AI Security
- AI is optional
- No shell access for AI
- No direct firewall control
- AI cannot become root of trust

## Backup and Recovery

### Configuration Backup

```bash
# Backup configuration
sudo tar -czf falconx-config-backup.tar.gz /opt/falconx/config/
```

### Incident Logs

```bash
# Backup incident logs
sudo cp /var/log/falconx-engine.log ./falconx-logs-backup.log
```

### System Recovery

```bash
# Restore from backup
sudo tar -xzf falconx-config-backup.tar.gz -C /
```

## Updates

### Update FALCON-X

```bash
# Stop services
sudo systemctl stop falconx-engine.service

# Backup current version
sudo cp -r /opt/falconx /opt/falconx.backup

# Copy new version
sudo cp -r . /opt/falconx/

# Restart services
sudo systemctl start falconx-engine.service
```

## Uninstallation

```bash
# Stop services
sudo systemctl stop falconx-engine.service
sudo systemctl disable falconx-engine.service
sudo systemctl stop falconx-menu.service
sudo systemctl disable falconx-menu.service

# Remove files
sudo rm -rf /opt/falconx
sudo rm /etc/systemd/system/falconx-engine.service
sudo rm /etc/systemd/system/falconx-menu.service

# Reload systemd
sudo systemctl daemon-reload
```

## Support

For deployment issues:
1. Check logs: `sudo journalctl -u falconx-engine.service -f`
2. Run tests: `cd /opt/falconx && pytest tests/`
3. Check documentation: README.md, ARCHITECTURE.md, TESTING.md
