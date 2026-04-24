"""
Attack Classifier MLP - Lightweight PyTorch model for attack classification.
CPU-only, trained on synthetic data during initialization.
"""
from __future__ import annotations
import logging
import numpy as np
from typing import Any

logger = logging.getLogger(__name__)

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


NUM_FEATURES = 8
NUM_CLASSES = 7  # phishing, credential_theft, http_exploitation, ransomware, lateral_movement, insider_threat, reconnaissance


class AttackClassifierMLP:
    """Lightweight 3-layer MLP for attack type classification."""

    def __init__(self):
        self._model = None
        if TORCH_AVAILABLE:
            self._model = self._build_model()

    def _build_model(self):
        return nn.Sequential(
            nn.Linear(NUM_FEATURES, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(16, NUM_CLASSES),
            nn.Softmax(dim=-1),
        )

    def train_on_synthetic_data(self, num_samples: int = 2000, epochs: int = 50) -> None:
        if not TORCH_AVAILABLE or not self._model:
            logger.warning("PyTorch not available, skipping training")
            return

        from agents.classifier_agent.training_data import generate_training_data
        X, y = generate_training_data(num_samples)
        X_tensor = torch.FloatTensor(X)
        y_tensor = torch.LongTensor(y)

        optimizer = torch.optim.Adam(self._model.parameters(), lr=0.001)
        criterion = nn.CrossEntropyLoss()

        self._model.train()
        for epoch in range(epochs):
            optimizer.zero_grad()
            outputs = self._model(X_tensor)
            loss = criterion(outputs, y_tensor)
            loss.backward()
            optimizer.step()
            if (epoch + 1) % 25 == 0:
                logger.info("Epoch %d/%d, Loss: %.4f", epoch + 1, epochs, loss.item())

        self._model.eval()
        with torch.no_grad():
            preds = self._model(X_tensor).argmax(dim=1)
            accuracy = (preds == y_tensor).float().mean().item()
            logger.info("Training accuracy: %.2f%%", accuracy * 100)

    def predict(self, features: list[float]) -> tuple[int, float]:
        if not TORCH_AVAILABLE or not self._model:
            return 0, 0.5

        self._model.eval()
        with torch.no_grad():
            x = torch.FloatTensor([features])
            probs = self._model(x)[0]
            predicted_class = probs.argmax().item()
            confidence = probs[predicted_class].item()
        return predicted_class, confidence
