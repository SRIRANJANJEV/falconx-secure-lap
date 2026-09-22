"""
Test ML interface
"""

import pytest
from falconx.ml_interface import MLInterface, SKLEARN_AVAILABLE


def test_ml_interface_initialization():
    """Test ML interface initialization"""
    ml = MLInterface()

    assert ml.enabled == False
    assert ml.model_loaded == False

    if SKLEARN_AVAILABLE:
        assert ml.status == 'LEARNING'
    else:
        assert ml.status == 'UNAVAILABLE'


def test_ml_enable():
    """Test enabling ML interface"""
    ml = MLInterface()

    if not SKLEARN_AVAILABLE:
        # Skip if sklearn not available
        result = ml.enable()
        assert result == False
        return

    result = ml.enable()
    assert result == True
    assert ml.enabled == True
    assert ml.status == 'LEARNING'


def test_ml_disable():
    """Test disabling ML interface"""
    ml = MLInterface()

    if not SKLEARN_AVAILABLE:
        # Disable should work even without sklearn
        ml.disable()
        assert ml.enabled == False
        assert ml.status == 'UNAVAILABLE'
        return

    ml.enable()
    ml.disable()

    assert ml.enabled == False
    assert ml.status == 'UNAVAILABLE'


def test_ml_add_training_sample():
    """Test adding training samples"""
    ml = MLInterface()

    if not SKLEARN_AVAILABLE:
        # Should not add samples if sklearn not available
        ml.enable()
        ml.add_training_sample({'size': 100, 'is_syn': False})
        assert len(ml.training_data) == 0
        return

    ml.enable()
    ml.add_training_sample({'size': 100, 'is_syn': False, 'is_icmp': False, 'is_dns': False, 'src_port': 12345, 'dst_port': 80})

    assert len(ml.training_data) == 1


def test_ml_load_model():
    """Test loading ML model"""
    ml = MLInterface()

    if not SKLEARN_AVAILABLE:
        # Should fail if sklearn not available
        result = ml.load_model()
        assert result == False
        return

    ml.enable()

    # Try to load non-existent model
    result = ml.load_model('/nonexistent/path.pkl')
    assert result == False


def test_ml_predict_unavailable():
    """Test ML prediction when unavailable"""
    ml = MLInterface()

    features = {'test': 'data'}
    result = ml.predict(features)

    assert result['is_threat'] == False
    assert result['confidence'] == 0.0

    if SKLEARN_AVAILABLE:
        assert 'not ready' in result['reason']
    else:
        assert 'not available' in result['reason']


def test_ml_training_progress():
    """Test training progress information"""
    ml = MLInterface()

    progress = ml.get_training_progress()

    assert 'samples_collected' in progress
    assert 'samples_required' in progress
    assert 'ready_to_train' in progress
    assert 'model_loaded' in progress

    assert progress['samples_collected'] == 0
    assert progress['samples_required'] == 100
    assert progress['ready_to_train'] == False
    assert progress['model_loaded'] == False


def test_ml_is_available():
    """Test ML availability check"""
    ml = MLInterface()

    # Should not be available initially
    assert ml.is_available() == False

    if SKLEARN_AVAILABLE:
        ml.enable()
        # Still not available until model is loaded
        assert ml.is_available() == False
    else:
        # Should never be available without sklearn
        assert ml.is_available() == False
