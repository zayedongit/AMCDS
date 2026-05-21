import joblib
import os
import numpy as np
from feature_extractor import URLFeatureExtractor

class URLThreatDetector:
    """
    A local class to detect malicious URLs without needing a web server.
    Can be imported directly into other Python applications.
    """
    def __init__(self, model_dir=None):
        if model_dir is None:
            # Default to the directory where this script is located
            model_dir = os.path.dirname(__file__)
            
        model_path = os.path.join(model_dir, 'model.pkl')
        
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found at {model_path}. Please train the model first.")
            
        # Load the pre-trained model and feature names
        model_data = joblib.load(model_path)
        self.model = model_data['model']
        self.feature_names = model_data['feature_names']
        
        # Initialize the feature extractor
        self.extractor = URLFeatureExtractor()

    def predict(self, url: str):
        """
        Predicts if a URL is malicious.
        Returns: (is_malicious: bool, confidence: float, top_features: list)
        """
        # Extract features from the URL
        features_dict = self.extractor.extract(url)
        
        # Order features exactly as the model expects
        feature_array = [features_dict[k] for k in self.feature_names]
        X = np.array([feature_array])
        
        # Make prediction
        prediction = self.model.predict(X)[0]
        probability = self.model.predict_proba(X)[0]
        
        # Calculate feature importance for explainability
        importances = self.model.feature_importances_
        top_indices = np.argsort(importances)[::-1][:3]
        top_features = [{"feature": self.feature_names[i], "value": float(feature_array[i])} for i in top_indices]
        
        is_malicious = bool(prediction == 1)
        confidence = float(max(probability))
        
        return is_malicious, confidence, top_features

# Example usage if someone runs this file directly
if __name__ == "__main__":
    detector = URLThreatDetector()
    test_url = "http://secure-login.paypal-update.com/login.php?session=abcdef"
    is_malicious, conf, top_feats = detector.predict(test_url)
    
    print(f"URL: {test_url}")
    print(f"Malicious: {is_malicious} (Confidence: {conf:.2f})")
    print(f"Top flags: {top_feats}")
