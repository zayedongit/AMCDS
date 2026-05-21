import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from feature_extractor import URLFeatureExtractor
import os
import sys

def map_label(label_type):
    # 'benign' -> 0, anything else ('phishing', 'defacement', 'malware') -> 1
    return 0 if str(label_type).strip().lower() == 'benign' else 1

def main():
    data_path = '/Users/sahinaparween/Desktop/AMCDS/malicious_phish.csv'
    
    if not os.path.exists(data_path):
        print(f"Dataset not found at {data_path}")
        sys.exit(1)
        
    print("Loading dataset...")
    # Load a sample to keep training fast for the prototype (e.g., 50k rows)
    # The full dataset is over 600k rows.
    try:
        df = pd.read_csv(data_path).sample(n=50000, random_state=42)
    except ValueError:
        # If dataset is smaller than 50k
        df = pd.read_csv(data_path)
        
    print(f"Loaded {len(df)} rows.")
    
    # Map labels to 0/1
    df['label'] = df['type'].apply(map_label)
    
    print("Extracting features (this might take a minute)...")
    extractor = URLFeatureExtractor()
    feature_names = extractor.get_feature_names()
    
    # Apply extractor to each URL
    features_list = []
    for idx, url in enumerate(df['url']):
        try:
            features = extractor.extract_array(str(url))
        except Exception:
            # Fallback for completely malformed URLs
            features = [0] * len(feature_names)
        features_list.append(features)
        
        if (idx + 1) % 10000 == 0:
            print(f"Processed {idx + 1} URLs...")
            
    X = np.array(features_list)
    y = df['label'].values
    
    # Train-test split
    print("Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Train model
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    
    # Evaluate
    print("Evaluating model...")
    y_pred = model.predict(X_test)
    print("\nAccuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign (0)', 'Malicious (1)']))
    
    # Save model and feature names
    model_data = {
        'model': model,
        'feature_names': feature_names
    }
    
    model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
    print(f"Saving model to {model_path}...")
    joblib.dump(model_data, model_path)
    print("Done!")

if __name__ == '__main__':
    main()
