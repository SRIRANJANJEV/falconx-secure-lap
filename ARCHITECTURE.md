# FALCON-X Architecture

## Overview

FALCON-X is a modular network security appliance with a layered detection pipeline designed for resource-constrained environments.

## Detection Pipeline

```
NETWORK PACKET
    ↓
SCAPY CAPTURE
    ↓
FEATURE EXTRACTION
    ↓
BASELINE
    ↓
RULE DETECTION
    ↓
STATISTICAL ANOMALY
    ↓
OPTIONAL ML
    ↓
RISK SCORE
    ↓
INCIDENT
    ↓
DASHBOARD
    ↓
OPTIONAL NFTABLES ENFORCEMENT
```

## Components

### Core Engine

#### `capture.py`
- Threaded packet capture using Scapy
- Bounded queue for packet buffering
- Graceful error handling
- Non-blocking operation

#### `features.py`
- Packet feature extraction
- Flow feature aggregation
- Protocol-specific features (TCP, UDP, ICMP, DNS)
- Flow key generation
- Automatic flow cleanup

#### `baseline.py`
- Normal network behavior learning
- Per-device baseline profiling
- Rate-based baselines (packet, byte, SYN, ICMP, DNS)
- Configurable learning window
- Anomaly detection against baseline

#### `rules.py`
- Lightweight rule-based detection
- SYN rate spike detection
- ICMP burst detection
- DNS burst detection
- Port scan detection
- Sliding window detection

#### `anomaly.py`
- Statistical anomaly detection
- Mean and standard deviation analysis
- 3-sigma anomaly detection
- Bounded history window
- Graceful degradation with insufficient data

#### `ml_interface.py`
- Optional ML/AI integration
- Placeholder for future ML models
- Graceful degradation when unavailable
- Status tracking (LEARNING, ACTIVE, UNAVAILABLE)

#### `risk.py`
- Risk score calculation
- Severity-weighted scoring
- Risk level classification (critical, high, medium, low)
- Detection type aggregation

#### `incidents.py`
- Incident creation and tracking
- Bounded incident history
- Automatic old incident cleanup
- Incident metadata preservation

#### `enforcement.py`
- nftables-based firewall enforcement
- LOG-ONLY mode (default)
- ACTIVE mode (requires explicit enable)
- IP blocking/unblocking
- Firewall status monitoring

#### `state.py`
- System state management
- Engine status tracking (RUNNING, STOPPED, FAILED)
- Protection state tracking (PROTECTED, DEGRADED, UNPROTECTED)
- ML/AI status tracking
- Firewall status tracking
- Packet/incident counting

#### `main.py`
- Main engine orchestrator
- Thread coordination
- Processing loop
- Statistics reporting
- Signal handling

### User Interface

#### `bin/falconx-detect`
- Detection engine CLI
- Commands: start, stop, status, test, incidents, interface
- Root privilege handling
- PID file management
- Log file management

#### `bin/falconx-menu`
- Terminal-based boot menu
- System status display
- Engine control
- Network interface viewing
- Incident viewing
- Firewall status
- AI status
- Test execution

### Dashboard

#### `dashboard/app.py`
- Flask web server
- REST API endpoints
- System state integration
- Static file serving

#### `dashboard/templates/index.html`
- Web dashboard UI
- Real-time status display
- Auto-refresh functionality
- Status color coding

### Testing

#### `tests/lab/generate_traffic.py`
- Synthetic traffic generator
- Safety checks (localhost/private IPs only)
- Multiple traffic modes
- Configurable packet counts

#### `tests/test_*.py`
- Unit tests for each component
- Feature extraction tests
- Rule detection tests
- Baseline learning tests
- Risk scoring tests
- Incident management tests
- State management tests
- Anomaly detection tests
- ML interface tests
- Traffic generator safety tests

### System Integration

#### `systemd/falconx-engine.service`
- Automatic engine startup
- Network dependency
- Failure recovery
- Security hardening

#### `systemd/falconx-menu.service`
- Menu availability
- Engine dependency
- One-shot service

## Design Principles

### Resource Constraints
- Bounded queues (max 1000 packets)
- Bounded incident history (max 100 incidents)
- Bounded flow tables (300 second timeout)
- Bounded statistics windows (100 samples)

### Graceful Degradation
- AI optional - pipeline works without it
- ML unavailable - rule detection continues
- Feature extraction fails - packet dropped, engine continues
- Statistics insufficient - baseline detection skipped

### Security
- Default LOG-ONLY enforcement
- Explicit switch for ACTIVE enforcement
- nftables only (no iptables)
- Isolated privileged operations
- No root trust in AI

### Performance
- Threaded architecture
- Non-blocking operations
- Efficient data structures
- Minimal memory footprint

## Data Flow

1. **Packet Capture**: Scapy captures packets from network interface
2. **Feature Extraction**: Packet features extracted and flow features updated
3. **Baseline Update**: Features added to baseline during learning phase
4. **Rule Detection**: Real-time rule evaluation on each packet
5. **Window Processing**: Periodic statistical analysis and baseline comparison
6. **Risk Scoring**: Combined detections scored for risk assessment
7. **Incident Creation**: High-risk events create incidents
8. **State Update**: System state updated with current metrics
9. **Dashboard Update**: Status exposed via API
10. **Enforcement**: Optional blocking based on incidents

## Configuration

### Engine Configuration
- Interface selection
- Queue sizes
- Detection thresholds
- Learning window duration
- Enforcement mode

### System Configuration
- systemd service configuration
- Log file locations
- PID file locations
- Dashboard port/host

## Dependencies

### Python
- scapy >= 2.5.0
- flask >= 2.3.0

### System
- nftables
- systemd
- Python 3

## Platform Considerations

### x86_64 (Current)
- Full functionality available
- Development and testing platform
- Demonstrates prototype capability

### Raspberry Pi 4 ARM64 (Target)
- Optimized for resource constraints
- Lower power consumption
- Embedded deployment
- Same codebase, different hardware

## Future Enhancements

### ML Models
- Actual ML model integration
- Model training pipeline
- Model versioning

### Dashboard
- Real-time graphs
- Historical data
- Alert configuration
- User authentication

### Enforcement
- More sophisticated blocking rules
- Rate limiting
- Traffic shaping

### Detection
- Additional rule types
- Protocol-specific detection
- Behavioral profiling
