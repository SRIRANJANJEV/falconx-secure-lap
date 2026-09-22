#!/usr/bin/env python3
"""
FALCON-X Dashboard
Simple web dashboard for monitoring detection engine status
"""

import json
import logging
import os
import sys
import time
import psutil
from flask import Flask, render_template, jsonify
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from falconx.state import SystemState, EngineStatus, ProtectionState

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.template_folder = 'templates'
app.static_folder = 'static'

# State file for engine communication
STATE_FILE = '/var/run/falconx-state.json'
INCIDENTS_FILE = '/var/run/falconx-incidents.json'


def read_engine_state():
    """Read engine state from state file"""
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error reading state file: {e}")

    # Return default state if file doesn't exist
    return {
        'engine_status': 'STOPPED',
        'protection_state': 'UNPROTECTED',
        'uptime': 0,
        'packet_count': 0,
        'incident_count': 0,
        'current_packet_rate': 0.0,
        'ml_status': 'UNAVAILABLE',
        'ai_status': 'UNAVAILABLE',
        'firewall_status': 'INACTIVE',
        'interface': 'unknown',
        'start_time': None
    }


def read_incidents():
    """Read incidents from incidents file"""
    try:
        if os.path.exists(INCIDENTS_FILE):
            with open(INCIDENTS_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error reading incidents file: {e}")

    return {'incidents': [], 'count': 0}


def get_system_metrics():
    """Get system metrics (CPU, RAM, Disk)"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        return {
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'memory_available_gb': memory.available / (1024**3),
            'disk_percent': disk.percent,
            'disk_available_gb': disk.free / (1024**3)
        }
    except Exception as e:
        logger.error(f"Error getting system metrics: {e}")
        return {
            'cpu_percent': 0,
            'memory_percent': 0,
            'memory_available_gb': 0,
            'disk_percent': 0,
            'disk_available_gb': 0
        }


def calculate_protection_state(engine_state):
    """Calculate protection state based on engine status"""
    engine_status = engine_state.get('engine_status', 'STOPPED')
    ml_status = engine_state.get('ml_status', 'UNAVAILABLE')
    firewall_status = engine_state.get('firewall_status', 'INACTIVE')

    if engine_status == 'STOPPED' or engine_status == 'FAILED':
        return 'UNPROTECTED'
    elif ml_status == 'UNAVAILABLE' or firewall_status == 'INACTIVE':
        return 'DEGRADED'
    else:
        return 'PROTECTED'


@app.route('/')
def index():
    """Dashboard home page"""
    return render_template('index.html')


@app.route('/api/status')
def api_status():
    """API endpoint for system status"""
    engine_state = read_engine_state()
    system_metrics = get_system_metrics()

    # Calculate uptime
    uptime = 0
    if engine_state.get('start_time'):
        uptime = time.time() - engine_state['start_time']

    # Calculate protection state
    protection_state = calculate_protection_state(engine_state)

    # Build complete status
    status = {
        'engine_status': engine_state.get('engine_status', 'STOPPED'),
        'protection_state': protection_state,
        'uptime': uptime,
        'packet_count': engine_state.get('packet_count', 0),
        'incident_count': engine_state.get('incident_count', 0),
        'current_packet_rate': engine_state.get('current_packet_rate', 0.0),
        'ml_status': engine_state.get('ml_status', 'UNAVAILABLE'),
        'ai_status': engine_state.get('ai_status', 'UNAVAILABLE'),
        'firewall_status': engine_state.get('firewall_status', 'INACTIVE'),
        'interface': engine_state.get('interface', 'unknown'),
        'risk_score': 'UNKNOWN',  # Would come from engine
        'threat_count': engine_state.get('incident_count', 0),
        'cpu_percent': system_metrics['cpu_percent'],
        'memory_percent': system_metrics['memory_percent'],
        'memory_available_gb': system_metrics['memory_available_gb'],
        'disk_percent': system_metrics['disk_percent'],
        'disk_available_gb': system_metrics['disk_available_gb']
    }

    return jsonify(status)


@app.route('/api/incidents')
def api_incidents():
    """API endpoint for incidents"""
    incidents_data = read_incidents()
    return jsonify(incidents_data)


def run_dashboard(host='0.0.0.0', port=8080):
    """Run the dashboard server"""
    logger.info(f"Starting dashboard on {host}:{port}")
    app.run(host=host, port=port, debug=False)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='FALCON-X Dashboard')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind to')

    args = parser.parse_args()
    run_dashboard(host=args.host, port=args.port)
