"""
ML/AI interface module
Optional ML detection with graceful degradation using Isolation Forest
"""

import logging
import pickle
import os
from typing import Dict, Any, Optional, List
from collections import deque

logger = logging.getLogger(__name__)

# Try to import sklearn, but don't fail if not available
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not available, ML features will be disabled")


class MLInterface:
    """Interface for optional ML/AI detection using Isolation Forest"""

    def __init__(self, model_path: str = '/var/lib/falconx/ml_model.pkl'):
        self.model_path = model_path
        self.enabled = False
        self.model_loaded = False
        self.status = 'UNAVAILABLE'
        self.model = None
        self.training_data = deque(maxlen=1000)  # Store training samples
        self.min_samples_for_training = 100
        self.isolation_forest = None

        # Check if sklearn is available
        if not SKLEARN_AVAILABLE:
            self.status = 'UNAVAILABLE'
            logger.info("ML unavailable: scikit-learn not installed")
        else:
            self.status = 'LEARNING'
            logger.info("ML available, ready for training")

    def enable(self):
        """Enable ML detection"""
        if not SKLEARN_AVAILABLE:
            logger.warning("Cannot enable ML: scikit-learn not available")
            return False

        self.enabled = True
        self.status = 'LEARNING'
        logger.info("ML interface enabled")
        return True

    def disable(self):
        """Disable ML detection"""
        self.enabled = False
        self.status = 'UNAVAILABLE'
        logger.info("ML interface disabled")

    def add_training_sample(self, features: Dict[str, Any]):
        """Add a sample to training data"""
        if not self.enabled:
            return

        # Extract numerical features for training
        numerical_features = self._extract_numerical_features(features)
        if numerical_features:
            self.training_data.append(numerical_features)

    def _extract_numerical_features(self, features: Dict[str, Any]) -> Optional[List[float]]:
        """Extract numerical features from packet features"""
        try:
            return [
                float(features.get('size', 0)),
                float(1 if features.get('is_syn', False) else 0),
                float(1 if features.get('is_icmp', False) else 0),
                float(1 if features.get('is_dns', False) else 0),
                float(features.get('src_port', 0) if features.get('src_port') else 0),
                float(features.get('dst_port', 0) if features.get('dst_port') else 0)
            ]
        except (ValueError, TypeError):
            return None

    def train_model(self) -> bool:
        """Train Isolation Forest model if enough data is available"""
        if not SKLEARN_AVAILABLE or not self.enabled:
            return False

        if len(self.training_data) < self.min_samples_for_training:
            logger.info(f"Insufficient training data: {len(self.training_data)}/{self.min_samples_for_training}")
            return False

        try:
            # Convert deque to list
            training_samples = list(self.training_data)

            # Train Isolation Forest
            self.isolation_forest = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42
            )
            self.isolation_forest.fit(training_samples)

            self.model_loaded = True
            self.status = 'ACTIVE'
            logger.info("ML model trained successfully")

            # Save model
            self._save_model()

            return True
        except Exception as e:
            logger.error(f"Error training ML model: {e}")
            return False

    def _save_model(self):
        """Save trained model to disk"""
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.isolation_forest, f)
            logger.info(f"ML model saved to {self.model_path}")
        except Exception as e:
            logger.error(f"Error saving ML model: {e}")

    def load_model(self, model_path: Optional[str] = None) -> bool:
        """Load ML model from disk"""
        if not SKLEARN_AVAILABLE:
            return False

        path = model_path or self.model_path

        try:
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    self.isolation_forest = pickle.load(f)
                self.model_loaded = True
                self.status = 'ACTIVE'
                logger.info(f"ML model loaded from {path}")
                return True
            else:
                logger.info(f"No pre-trained model found at {path}")
                return False
        except Exception as e:
            logger.error(f"Error loading ML model: {e}")
            return False

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Run ML prediction on features"""
        if not SKLEARN_AVAILABLE:
            return {
                'is_threat': False,
                'confidence': 0.0,
                'reason': 'ML not available (scikit-learn not installed)'
            }

        if not self.enabled or not self.model_loaded:
            return {
                'is_threat': False,
                'confidence': 0.0,
                'reason': 'ML not ready'
            }

        try:
            numerical_features = self._extract_numerical_features(features)
            if not numerical_features:
                return {
                    'is_threat': False,
                    'confidence': 0.0,
                    'reason': 'Invalid features'
                }

            # Reshape for single sample prediction
            import numpy as np
            sample = np.array(numerical_features).reshape(1, -1)

            # Predict
            prediction = self.isolation_forest.predict(sample)[0]
            score = self.isolation_forest.score_samples(sample)[0]

            # Isolation Forest returns -1 for anomalies, 1 for normal
            is_threat = prediction == -1
            confidence = abs(score)

            return {
                'is_threat': is_threat,
                'confidence': float(confidence),
                'reason': 'Isolation Forest prediction'
            }
        except Exception as e:
            logger.error(f"Error in ML prediction: {e}")
            return {
                'is_threat': False,
                'confidence': 0.0,
                'reason': f'Prediction error: {e}'
            }

    def get_status(self) -> str:
        """Get ML status"""
        if not SKLEARN_AVAILABLE:
            return 'UNAVAILABLE'
        return self.status

    def is_available(self) -> bool:
        """Check if ML is available"""
        return SKLEARN_AVAILABLE and self.enabled and self.model_loaded

    def get_training_progress(self) -> Dict[str, Any]:
        """Get training progress information"""
        return {
            'samples_collected': len(self.training_data),
            'samples_required': self.min_samples_for_training,
            'ready_to_train': len(self.training_data) >= self.min_samples_for_training,
            'model_loaded': self.model_loaded
        }
