"""Tests for Attack Classifier."""
import pytest
import numpy as np


class TestTrainingData:
    def test_generate_balanced_data(self):
        from agents.classifier_agent.training_data import generate_training_data
        X, y = generate_training_data(num_samples=700, seed=42)
        assert X.shape[0] == 700
        assert X.shape[1] == 8
        assert len(np.unique(y)) == 7  # 7 classes

    def test_deterministic_generation(self):
        from agents.classifier_agent.training_data import generate_training_data
        X1, y1 = generate_training_data(num_samples=100, seed=42)
        X2, y2 = generate_training_data(num_samples=100, seed=42)
        np.testing.assert_array_equal(X1, X2)
        np.testing.assert_array_equal(y1, y2)

    def test_features_in_range(self):
        from agents.classifier_agent.training_data import generate_training_data
        X, _ = generate_training_data(num_samples=500)
        assert X.min() >= 0.0
        assert X.max() <= 1.0


class TestClassifierModel:
    def test_model_creation(self):
        try:
            from agents.classifier_agent.model import AttackClassifierMLP
            model = AttackClassifierMLP()
            assert model is not None
        except ImportError:
            pytest.skip("PyTorch not available")

    def test_model_predict(self):
        try:
            from agents.classifier_agent.model import AttackClassifierMLP
            model = AttackClassifierMLP()
            model.train_on_synthetic_data(num_samples=500, epochs=10)
            cls, conf = model.predict([0.8, 0.7, 0.3, 0.4, 1.0, 0.0, 1.0, 0.5])
            assert 0 <= cls < 7
            assert 0.0 <= conf <= 1.0
        except ImportError:
            pytest.skip("PyTorch not available")
