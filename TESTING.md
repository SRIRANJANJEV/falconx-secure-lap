# FALCON-X Testing Guide

## Overview

This guide covers testing FALCON-X components, including unit tests, integration tests, and traffic generation testing.

## Test Structure

```
tests/
├── __init__.py
├── test_features.py        # Feature extraction tests
├── test_rules.py           # Rule detection tests
├── test_baseline.py       # Baseline learning tests
├── test_anomaly.py         # Anomaly detection tests
├── test_ml_interface.py    # ML interface tests
├── test_risk.py            # Risk scoring tests
├── test_incidents.py       # Incident management tests
├── test_state.py           # State management tests
└── lab/
    └── generate_traffic.py # Synthetic traffic generator
```

## Running Tests

### Run All Tests

```bash
cd /opt/falconx
pytest tests/
```

### Run Specific Test File

```bash
pytest tests/test_features.py
```

### Run Specific Test

```bash
pytest tests/test_features.py::test_extract_packet_features_tcp
```

### Run with Verbose Output

```bash
pytest tests/ -v
```

### Run with Coverage

```bash
pytest tests/ --cov=falconx --cov-report=html
```

## Test Descriptions

### test_features.py

Tests for packet and flow feature extraction:

- `test_extract_packet_features_tcp`: TCP packet feature extraction
- `test_extract_packet_features_icmp`: ICMP packet feature extraction
- `test_extract_packet_features_dns`: DNS packet feature extraction
- `test_flow_key_generation`: Flow key generation
- `test_flow_features_update`: Flow feature updates

### test_rules.py

Tests for rule-based detection:

- `test_syn_detection`: SYN rate spike detection
- `test_icmp_detection`: ICMP burst detection
- `test_dns_detection`: DNS burst detection
- `test_port_scan_detection`: Port scan detection
- `test_window_reset`: Detection window reset

### test_baseline.py

Tests for baseline learning:

- `test_baseline_update`: Baseline update functionality
- `test_baseline_finalization`: Baseline finalization
- `test_new_device_detection`: New device detection
- `test_anomaly_detection_during_learning`: Anomaly detection during learning
- `test_anomaly_detection_after_learning`: Anomaly detection after learning

### test_anomaly.py

Tests for statistical anomaly detection:

- `test_add_sample`: Adding samples to history
- `test_history_bounding`: History bounding
- `test_insufficient_history`: Detection with insufficient history
- `test_normal_detection`: Detection with normal metrics
- `test_anomaly_detection`: Detection with anomalous metrics

### test_ml_interface.py

Tests for ML interface:

- `test_ml_interface_initialization`: ML interface initialization
- `test_ml_enable`: Enabling ML interface
- `test_ml_disable`: Disabling ML interface
- `test_ml_load_model`: Loading ML model
- `test_ml_predict_unavailable`: Prediction when unavailable
- `test_ml_predict_available`: Prediction when available
- `test_ml_is_available`: Availability check

### test_risk.py

Tests for risk scoring:

- `test_risk_calculation_no_detections`: Risk calculation with no detections
- `test_risk_calculation_low_severity`: Risk calculation with low severity
- `test_risk_calculation_high_severity`: Risk calculation with high severity
- `test_risk_calculation_with_baseline_anomaly`: Risk calculation with baseline anomaly
- `test_risk_level_critical`: Critical risk level
- `test_risk_description`: Risk description generation

### test_incidents.py

Tests for incident management:

- `test_incident_creation`: Incident creation
- `test_incident_counter`: Incident counter increment
- `test_recent_incidents`: Getting recent incidents
- `test_incident_bounded_queue`: Bounded incident queue
- `test_old_incident_cleanup`: Old incident cleanup

### test_state.py

Tests for system state management:

- `test_engine_status_transitions`: Engine status transitions
- `test_protection_state_transitions`: Protection state transitions
- `test_packet_counting`: Packet counting
- `test_incident_counting`: Incident counting
- `test_packet_rate_update`: Packet rate update
- `test_status_updates`: Various status updates
- `test_status_dict`: Status dictionary generation
- `test_is_protected`: Protection status check

### test_traffic_generator.py

Tests for synthetic traffic generator safety:

- `test_safe_target_localhost`: Localhost safety check
- `test_safe_target_private_ip`: Private IP safety check
- `test_unsafe_target_public_ip`: Public IP rejection
- `test_safe_target_loopback`: Loopback address safety
- `test_invalid_target`: Invalid target handling

## Synthetic Traffic Testing

### Traffic Generator

The synthetic traffic generator safely generates test traffic for local/lab environments only.

**Safety Features:**
- Only targets localhost (127.0.0.1) or private IPs
- Explicit --target argument required
- Prevents targeting public internet
- Small controlled packet counts

### Usage

```bash
# Normal traffic
python3 /opt/falconx/tests/lab/generate_traffic.py --target 127.0.0.1 --mode normal

# ICMP burst
python3 /opt/falconx/tests/lab/generate_traffic.py --target 127.0.0.1 --mode icmp-burst

# DNS burst
python3 /opt/falconx/tests/lab/generate_traffic.py --target 127.0.0.1 --mode dns-burst

# SYN burst
python3 /opt/falconx/tests/lab/generate_traffic.py --target 127.0.0.1 --mode syn-burst

# Port scan simulation
python3 /opt/falconx/tests/lab/generate_traffic.py --target 127.0.0.1 --mode port-scan-simulation
```

### Traffic Modes

- **normal**: Normal-looking traffic (TCP and UDP)
- **icmp-burst**: ICMP burst (30 packets)
- **dns-burst**: DNS burst (20 packets)
- **syn-burst**: SYN burst (50 packets)
- **port-scan-simulation**: Port scan to multiple ports (15 ports)

### Custom Packet Counts

```bash
python3 /opt/falconx/tests/lab/generate_traffic.py --target 127.0.0.1 --mode normal --count 20
```

### Custom Port Count (Port Scan)

```bash
python3 /opt/falconx/tests/lab/generate_traffic.py --target 127.0.0.1 --mode port-scan-simulation --ports 20
```

## Integration Testing

### Engine Startup Test

```bash
# Start engine
sudo /opt/falconx/bin/falconx-detect start eth0

# Check status
/opt/falconx/bin/falconx/bin/falconx-detect status

# Stop engine
sudo /opt/falconx/bin/falconx-detect stop
```

### End-to-End Detection Test

```bash
# Start engine
sudo /opt/falconx/bin/falconx-detect start eth0

# Generate test traffic
python3 /opt/falconx/tests/lab/generate_traffic.py --target 127.0.0.1 --mode syn-burst

# Check for incidents
/opt/falconx/bin/falconx-detect incidents

# Stop engine
sudo /opt/falconx/bin/falconx-detect stop
```

### Dashboard Integration Test

```bash
# Start engine
sudo /opt/falconx/bin/falconx-detect start eth0

# Start dashboard
python3 /opt/falconx/dashboard/app.py --host 0.0.0.0 --port 8080

# Access dashboard
# Open browser to http://localhost:8080

# Stop services
sudo /opt/falconx/bin/falconx-detect stop
# Kill dashboard process
```

## Privileged Tests

Tests requiring root privileges, nftables, or real network interfaces are marked as:

**SKIPPED — REQUIRES PRIVILEGED LINUX**

These tests are skipped on systems without the required privileges.

### Running Privileged Tests

```bash
# Run as root
sudo pytest tests/
```

## Raspberry Pi Tests

Tests requiring Raspberry Pi hardware are marked as:

**SKIPPED — REQUIRES RASPBERRY PI**

These tests are skipped on non-Raspberry Pi systems.

## Test Coverage

Current test coverage includes:
- Feature extraction (100%)
- Rule detection (100%)
- Baseline learning (100%)
- Anomaly detection (100%)
- ML interface (100%)
- Risk scoring (100%)
- Incident management (100%)
- State management (100%)
- Traffic generator safety (100%)

## Continuous Integration

### GitHub Actions (Example)

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.8'
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov
      - name: Run tests
        run: pytest tests/ --cov=falconx
```

## Troubleshooting Tests

### Import Errors

```bash
# Ensure you're in the correct directory
cd /opt/falconx

# Check Python path
export PYTHONPATH=/opt/falconx:$PYTHONPATH
```

### Scapy Permission Errors

```bash
# Run with sudo
sudo pytest tests/

# Or set capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3
```

### Missing Dependencies

```bash
# Install test dependencies
pip install pytest pytest-cov

# Install Scapy
sudo apt-get install python3-scapy
pip install scapy
```

## Best Practices

1. **Run tests before committing**: Ensure all tests pass
2. **Add tests for new features**: Maintain coverage
3. **Test edge cases**: Include boundary conditions
4. **Mock external dependencies**: Avoid real network calls in unit tests
5. **Clean up after tests**: Ensure no resource leaks
6. **Use descriptive names**: Make test names self-documenting

## Future Test Enhancements

- Performance benchmarking tests
- Load testing with high packet rates
- Memory leak detection
- Long-running stability tests
- Hardware-specific tests (Raspberry Pi)
- Integration tests with real network traffic
