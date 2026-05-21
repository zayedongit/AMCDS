from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import os
import numpy as np
from feature_extractor import URLFeatureExtractor
import uvicorn

app = FastAPI(title="HTTPS Threat Detector API", 
              description="A simple ML-based API to detect malicious URLs.")

class URLRequest(BaseModel):
    url: str

# Global variables for the model and extractor
model = None
feature_names = None
extractor = URLFeatureExtractor()

@app.on_event("startup")
def load_model():
    global model, feature_names
    model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
    if os.path.exists(model_path):
        model_data = joblib.load(model_path)
        model = model_data['model']
        feature_names = model_data['feature_names']
        print("Model loaded successfully.")
    else:
        print(f"Warning: Model not found at {model_path}. Please run train.py first.")

@app.post("/predict")
def predict(request: URLRequest):
    if model is None:
        raise HTTPException(status_code=503, detail="Model is not loaded. Train the model first.")
        
    try:
        # Extract features
        features_dict = extractor.extract(request.url)
        
        # Ensure features are in the same order as trained
        feature_array = [features_dict[k] for k in feature_names]
        X = np.array([feature_array])
        
        # Predict
        prediction = model.predict(X)[0]
        probability = model.predict_proba(X)[0]
        
        # Get feature importance for explainability
        importances = model.feature_importances_
        # Sort top 3 contributing features
        top_indices = np.argsort(importances)[::-1][:3]
        top_features = [{"feature": feature_names[i], "importance": float(importances[i]), "value": float(feature_array[i])} for i in top_indices]
        
        return {
            "url": request.url,
            "prediction": "malicious" if prediction == 1 else "benign",
            "confidence": float(max(probability)),
            "top_contributing_features": top_features
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health_check():
    return {"status": "ok", "model_loaded": model is not None}

if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
