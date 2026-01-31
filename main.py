import base64
import os
import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import numpy as np
from features import extract_url_features

# Get VirusTotal API key from environment variable
VT_API_KEY = os.getenv("VT_API_KEY")
app = FastAPI(title="Phishcheck")

# Load model with error handling
try:
    model = joblib.load("phishing_model.pkl")
except FileNotFoundError:
    raise FileNotFoundError(
        "phishing_model.pkl not found. Please run train.py first to generate the model.")
except Exception as e:
    raise Exception(f"Error loading model: {str(e)}")


class URLRequest(BaseModel):
    url: str


def check_virustotal(url):
    """
    Checks VirusTotal to see if other security vendors have flagged this URL.
    """
    # Safety check: If no key is set, skip this step
    if not VT_API_KEY:
        return {"status": "SKIPPED", "message": "No VirusTotal API Key configured"}

    # Encoding the URL to Base64 (Required by VirusTotal API)
    # VT requires the ID to be base64 encoded without trailing '='
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    headers = {
        "x-apikey": VT_API_KEY
    }

    # Asking VirusTotal: "Do you know this URL?"
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=5
        )

        if response.status_code == 200:
            data = response.json()
            try:
                stats = data['data']['attributes']['last_analysis_stats']
                return {
                    "malicious_votes": stats.get('malicious', 0),
                    "harmless_votes": stats.get('harmless', 0),
                    "status": "FOUND",
                    "permalink": data['data']['links'].get('self', '')
                }
            except KeyError as e:
                return {"status": "ERROR", "message": f"Unexpected API response format: {str(e)}"}
        elif response.status_code == 404:
            return {"status": "NOT_FOUND", "message": "URL not in VirusTotal database"}
        else:
            return {"status": "ERROR", "code": response.status_code}

    except Exception as e:
        return {"status": "CONNECTION_ERROR", "details": str(e)}


@app.get("/")
def home():
    return {"status": "Phishcheck (Hybrid + Threat Intel) is Online"}


@app.post("/scan")
def scan(request: URLRequest):
    """
    Scans a URL for phishing indicators using AI model and VirusTotal.
    """
    try:
        # Validate URL format
        if not request.url or not request.url.startswith(('http://', 'https://')):
            raise HTTPException(
                status_code=400, detail="Invalid URL format. URL must start with http:// or https://")

        # --- AI Analysis (Local Model) ---
        features_list = extract_url_features(request.url, fetch_html=True)
        
        # Validate feature extraction returned correct number of features
        if len(features_list) != 13:
            raise HTTPException(
                status_code=500, detail=f"Feature extraction returned {len(features_list)} features, expected 13")

        features = np.array(features_list).reshape(1, -1)

        prediction = model.predict(features)[0]
        confidence = model.predict_proba(features)[0][1]

        # --- Threat Intel (VirusTotal Cloud) ---
        vt_result = check_virustotal(request.url)

        # --- Return Combined Report ---
        return {
            "url": request.url,
            "ai_analysis": {
                "phishing_detected": bool(prediction),
                "confidence_score": f"{confidence:.2%}",
                "risk_level": "CRITICAL" if confidence > 0.8 else "STABLE",
                "scanned_features": {
                    "url_length": features_list[0],
                    "password_field": bool(features_list[10]),
                    "iframe_present": bool(features_list[11])
                }
            },
            "threat_intel": vt_result
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing URL: {str(e)}")
