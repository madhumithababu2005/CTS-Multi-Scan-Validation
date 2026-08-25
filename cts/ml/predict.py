import os
import sys
import json
import joblib
import numpy as np

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def extract_features(finding, replay_info):
    """
    Extract features from a finding and its replay result for ML prediction.
    Returns a feature vector that matches the expected input for the Random Forest model (29 features).
    """
    features = []
    
    url = finding.get("url", "")
    rule = finding.get("rule", "")
    evidence = replay_info.get("reason", "")
    replay_verdict = replay_info.get("verdict", "inconclusive")
    
    # Feature 1: Replay verdict (encoded)
    verdict_map = {"reproduced": 1, "not_reproduced": 0, "inconclusive": 0.5}
    features.append(verdict_map.get(replay_verdict, 0.5))
    
    # Feature 2: URL length
    features.append(len(url))
    
    # Feature 3: Rule name length
    features.append(len(rule))
    
    # Feature 4: Evidence length
    features.append(len(evidence))
    
    # Feature 5: URL path depth (number of /)
    features.append(url.count("/"))
    
    # Feature 6: Has query parameters
    features.append(1.0 if "?" in url else 0.0)
    
    # Feature 7: Has file extension
    features.append(1.0 if "." in url.split("/")[-1] else 0.0)
    
    # Feature 8: Port number (if present in URL)
    features.append(1.0 if ":5000" in url or ":3000" in url or ":8080" in url else 0.0)
    
    # Feature 9: Is localhost
    features.append(1.0 if "localhost" in url or "127.0.0.1" in url else 0.0)
    
    # Feature 10: Is HTTPS
    features.append(1.0 if url.startswith("https://") else 0.0)
    
    # Feature 11-15: Rule category one-hot encoding
    rule_lower = rule.lower()
    features.append(1.0 if "header" in rule_lower else 0.0)  # Header-related
    features.append(1.0 if "csp" in rule_lower else 0.0)     # CSP-specific
    features.append(1.0 if "disclosure" in rule_lower or "leak" in rule_lower else 0.0)  # Info disclosure
    features.append(1.0 if "misconfiguration" in rule_lower else 0.0)  # Misconfiguration
    features.append(1.0 if "browsing" in rule_lower or "directory" in rule_lower else 0.0)  # Directory-related
    
    # Feature 16-20: Evidence keyword one-hot encoding
    evidence_lower = evidence.lower()
    features.append(1.0 if "missing" in evidence_lower else 0.0)
    features.append(1.0 if "present" in evidence_lower or "found" in evidence_lower else 0.0)
    features.append(1.0 if "error" in evidence_lower or "failed" in evidence_lower else 0.0)
    features.append(1.0 if "header" in evidence_lower else 0.0)
    features.append(1.0 if "enabled" in evidence_lower else 0.0)
    
    # Feature 21-25: URL pattern features
    features.append(1.0 if "/uploads/" in url else 0.0)
    features.append(1.0 if "/ftp/" in url else 0.0)
    features.append(1.0 if "/api/" in url else 0.0)
    features.append(1.0 if "/admin/" in url else 0.0)
    features.append(1.0 if ".bak" in url or ".backup" in url else 0.0)
    
    # Feature 26-29: Additional features
    features.append(1.0 if "timestamp" in rule_lower else 0.0)
    features.append(1.0 if "clickjacking" in rule_lower else 0.0)
    features.append(1.0 if "content-type" in rule_lower else 0.0)
    features.append(1.0 if "server" in rule_lower and "leak" in rule_lower else 0.0)
    
    return np.array([features])

def load_model(model_path):
    """Load the trained Random Forest model."""
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found: {model_path}")
    
    model = joblib.load(model_path)
    return model

def predict_classification(model, features):
    """
    Make prediction using the loaded model.
    Returns (prediction, confidence) tuple.
    """
    # Get prediction
    prediction = model.predict(features)[0]
    
    # Get prediction probabilities
    probabilities = model.predict_proba(features)[0]
    
    # Map numeric prediction to classification
    class_map = {0: "false_positive", 1: "true_positive", 2: "inconclusive"}
    ml_prediction = class_map.get(prediction, "inconclusive")
    
    # Get confidence (max probability)
    ml_confidence = float(max(probabilities))
    
    return ml_prediction, ml_confidence

def run_ml_classification(findings, replay_results, model_path):
    """
    Run ML classification on all findings.
    Returns a dictionary mapping finding IDs to (ml_prediction, ml_confidence) tuples.
    """
    # Load model
    model = load_model(model_path)
    
    # Map replay results by ID
    replay_map = {r["id"]: r for r in replay_results}
    
    ml_results = {}
    
    for finding in findings:
        fid = finding["id"]
        replay_info = replay_map.get(fid)
        
        if not replay_info:
            print(f"Warning: No replay result for finding ID {fid}, skipping ML prediction")
            ml_results[fid] = (None, None)
            continue
        
        try:
            # Extract features
            features = extract_features(finding, replay_info)
            
            # Make prediction
            ml_prediction, ml_confidence = predict_classification(model, features)
            
            ml_results[fid] = (ml_prediction, ml_confidence)
            
        except Exception as e:
            print(f"Error predicting for finding ID {fid}: {e}")
            ml_results[fid] = (None, None)
    
    return ml_results

if __name__ == "__main__":
    # Test the module
    print("ML Prediction Module - Ready")
    print("This module should be imported and used by classify.py")
