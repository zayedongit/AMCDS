"""
Training Data Generator - Creates synthetic labeled data for the attack classifier.
"""
from __future__ import annotations
import numpy as np
import random


def generate_training_data(num_samples: int = 2000, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """
    Generate balanced synthetic training data for attack classification.

    Features: [severity, confidence, evidence_count, action_count,
               has_source_ip, has_user_id, has_target_ip, alert_type_hash]

    Classes: 0=phishing, 1=credential_theft, 2=http_exploitation,
             3=ransomware, 4=lateral_movement, 5=insider_threat, 6=reconnaissance
    """
    rng = random.Random(seed)
    np_rng = np.random.RandomState(seed)

    samples_per_class = num_samples // 7
    X, y = [], []

    # Class 0: Phishing - medium severity, email-related, has user_id
    for _ in range(samples_per_class):
        X.append([
            rng.uniform(0.5, 0.8),   # severity
            rng.uniform(0.6, 0.9),   # confidence
            rng.uniform(0.1, 0.3),   # evidence
            rng.uniform(0.2, 0.4),   # actions
            rng.uniform(0.3, 0.6),   # has_source_ip
            1.0,                      # has_user_id
            0.0,                      # has_target_ip
            rng.uniform(0.1, 0.3),   # alert_type_hash
        ])
        y.append(0)

    # Class 1: Credential theft - high severity, IP-focused
    for _ in range(samples_per_class):
        X.append([
            rng.uniform(0.6, 1.0),
            rng.uniform(0.5, 0.95),
            rng.uniform(0.2, 0.5),
            rng.uniform(0.3, 0.6),
            1.0,
            rng.uniform(0.5, 1.0),
            rng.uniform(0.0, 0.3),
            rng.uniform(0.3, 0.5),
        ])
        y.append(1)

    # Class 2: HTTP exploitation - critical severity, has target_ip
    for _ in range(samples_per_class):
        X.append([
            rng.uniform(0.75, 1.0),
            rng.uniform(0.7, 0.95),
            rng.uniform(0.1, 0.4),
            rng.uniform(0.3, 0.5),
            1.0,
            rng.uniform(0.0, 0.3),
            1.0,
            rng.uniform(0.5, 0.7),
        ])
        y.append(2)

    # Class 3: Ransomware - critical severity, endpoint-focused
    for _ in range(samples_per_class):
        X.append([
            rng.uniform(0.9, 1.0),
            rng.uniform(0.8, 0.99),
            rng.uniform(0.3, 0.6),
            rng.uniform(0.4, 0.8),
            rng.uniform(0.0, 0.3),
            rng.uniform(0.0, 0.5),
            rng.uniform(0.0, 0.3),
            rng.uniform(0.7, 0.9),
        ])
        y.append(3)

    # Class 4: Lateral movement - high severity
    for _ in range(samples_per_class):
        X.append([
            rng.uniform(0.6, 0.9),
            rng.uniform(0.6, 0.9),
            rng.uniform(0.2, 0.5),
            rng.uniform(0.2, 0.5),
            1.0,
            rng.uniform(0.3, 0.8),
            1.0,
            rng.uniform(0.4, 0.6),
        ])
        y.append(4)

    # Class 5: Insider threat - medium severity, user-focused
    for _ in range(samples_per_class):
        X.append([
            rng.uniform(0.4, 0.7),
            rng.uniform(0.5, 0.8),
            rng.uniform(0.1, 0.4),
            rng.uniform(0.1, 0.3),
            rng.uniform(0.3, 0.7),
            1.0,
            rng.uniform(0.0, 0.3),
            rng.uniform(0.6, 0.8),
        ])
        y.append(5)

    # Class 6: Reconnaissance - low severity, network-focused
    for _ in range(samples_per_class):
        X.append([
            rng.uniform(0.3, 0.6),
            rng.uniform(0.5, 0.85),
            rng.uniform(0.3, 0.8),
            rng.uniform(0.1, 0.3),
            1.0,
            rng.uniform(0.0, 0.2),
            1.0,
            rng.uniform(0.0, 0.2),
        ])
        y.append(6)

    # Add noise
    X_arr = np.array(X, dtype=np.float32)
    X_arr += np_rng.normal(0, 0.05, X_arr.shape).astype(np.float32)
    X_arr = np.clip(X_arr, 0.0, 1.0)

    # Shuffle
    indices = np_rng.permutation(len(X_arr))
    return X_arr[indices], np.array(y)[indices]
