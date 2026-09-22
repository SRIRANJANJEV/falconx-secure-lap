"""
FALCON-X Detection Engine Main Module
Orchestrates the complete detection pipeline
"""

import logging
import time
import threading
import signal
import sys
from typing import Optional

from .capture import PacketCapture
from .features import FeatureExtractor
from .baseline import BaselineLearner
from .rules import RuleDetector
from .anomaly import AnomalyDetector
from .ml_interface import MLInterface
from .risk import RiskScorer
from .incidents import IncidentManager
from .enforcement import EnforcementManager
from .state import SystemState

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DetectionEngine:
    """Main detection engine orchestrator"""

    def __init__(self, interface: str = None):
        self.interface = interface
        self.running = False

        # Initialize components
        self.capture = PacketCapture(interface)
        self.interface = self.capture.interface  # Use the actual interface (may be auto-detected)
        self.feature_extractor = FeatureExtractor()
        self.baseline = BaselineLearner()
        self.rule_detector = RuleDetector()
        self.anomaly_detector = AnomalyDetector()
        self.ml_interface = MLInterface()
        self.risk_scorer = RiskScorer()
        self.incident_manager = IncidentManager()
        self.enforcement = EnforcementManager(mode='LOG_ONLY')
        self.state = SystemState()
        self.state.set_interface(self.interface)

        # Statistics
        self.stats_interval = 5.0
        self.last_stats_time = time.time()

    def start(self):
        """Start the detection engine"""
        logger.info("Starting FALCON-X Detection Engine")
        self.running = True
        self.state.set_engine_running()

        # Try to enable ML
        if self.ml_interface.enable():
            logger.info("ML detection enabled")
            # Try to load existing model
            self.ml_interface.load_model()
        else:
            logger.info("ML detection unavailable")

        # Start packet capture
        self.capture.start()

        # Start processing thread
        self.process_thread = threading.Thread(target=self._process_loop, daemon=True)
        self.process_thread.start()

        # Start stats thread
        self.stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
        self.stats_thread.start()

        logger.info("Detection engine started")

    def stop(self):
        """Stop the detection engine"""
        logger.info("Stopping detection engine")
        self.running = False
        self.capture.stop()
        self.state.set_engine_stopped()
        self.state.remove_state_file()
        self.incident_manager.remove_incidents_file()
        logger.info("Detection engine stopped")

    def _process_loop(self):
        """Main packet processing loop"""
        while self.running:
            try:
                # Get packet from capture
                packet = self.capture.get_packet(timeout=1.0)
                if packet is None:
                    continue

                # Extract features
                features = self.feature_extractor.extract_packet_features(packet)
                self.feature_extractor.update_flow_features(features)

                # Update baseline
                self.baseline.update(features)

                # Add sample to ML training data
                self.ml_interface.add_training_sample(features)

                # Finalize baseline after learning period
                if self.baseline.is_learning and time.time() - self.baseline.start_time > 300:
                    self.baseline.finalize_baseline()

                # Run rule detection
                detections = self.rule_detector.detect(features)

                # Check for window expiration
                if self.rule_detector.check_window_expiration():
                    # Get current metrics
                    current_metrics = self.rule_detector.get_current_metrics()

                    # Add to anomaly detector history
                    self.anomaly_detector.add_sample(current_metrics)

                    # Run anomaly detection
                    anomaly_result = self.anomaly_detector.detect(current_metrics)

                    # Check baseline
                    baseline_result = self.baseline.check_anomaly(current_metrics)

                    # Combine detections
                    all_detections = detections.copy()
                    if anomaly_result.get('anomalies'):
                        all_detections.extend(anomaly_result['anomalies'])

                    # Calculate risk
                    risk_result = self.risk_scorer.calculate_risk(all_detections, baseline_result)

                    # Create incident if risk is significant
                    if risk_result['score'] >= 20 and all_detections:
                        incident = self.incident_manager.create_incident(
                            all_detections, risk_result, features
                        )
                        self.state.increment_incident_count()

                    # Reset detection window
                    self.rule_detector.reset_window()

                # Update state
                self.state.increment_packet_count()
                self.state.update_packet_rate(self.capture.get_queue_size())

            except Exception as e:
                logger.error(f"Error in processing loop: {e}")
                continue

    def _stats_loop(self):
        """Statistics reporting loop"""
        while self.running:
            time.sleep(self.stats_interval)

            try:
                # Calculate packet rate
                elapsed = time.time() - self.last_stats_time
                if elapsed > 0:
                    rate = self.state.packet_count / elapsed
                    self.state.update_packet_rate(rate)
                    self.last_stats_time = time.time()

                # Clear old incidents
                self.incident_manager.clear_old_incidents()

                # Update ML status
                self.state.set_ml_status(self.ml_interface.get_status())

                # Try to train ML model if enough data collected
                if self.ml_interface.enabled and not self.ml_interface.model_loaded:
                    progress = self.ml_interface.get_training_progress()
                    if progress['ready_to_train']:
                        logger.info("Attempting to train ML model...")
                        if self.ml_interface.train_model():
                            logger.info("ML model trained successfully")
                        else:
                            logger.info("ML model training failed, will retry")

                # Update firewall status
                fw_status = self.enforcement.get_firewall_status()
                self.state.set_firewall_status('ACTIVE' if fw_status['active'] else 'INACTIVE')

                # Save state and incidents for dashboard
                self.state.save_state()
                self.incident_manager.save_incidents()

                # Log status
                logger.info(f"Status: {self.state.get_status_dict()}")

            except Exception as e:
                logger.error(f"Error in stats loop: {e}")

    def get_status(self):
        """Get engine status"""
        return self.state.get_status_dict()

    def get_incidents(self, count: int = 10):
        """Get recent incidents"""
        return self.incident_manager.get_recent_incidents(count)


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='FALCON-X Detection Engine')
    parser.add_argument('--interface', default='eth0', help='Network interface')
    parser.add_argument('--log-level', default='INFO', help='Log level')

    args = parser.parse_args()

    # Set log level
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))

    # Create and start engine
    engine = DetectionEngine(interface=args.interface)

    # Signal handlers
    def signal_handler(sig, frame):
        logger.info("Received shutdown signal")
        engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        engine.start()
        while engine.running:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt")
        engine.stop()


if __name__ == '__main__':
    main()
