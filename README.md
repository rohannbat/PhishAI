# AI-Phish 🛡️

A hybrid phishing URL detection system that combines machine learning with threat intelligence to identify malicious URLs. The system uses a Random Forest classifier trained on URL and HTML features, enhanced with VirusTotal API integration for real-time threat intelligence.

## Features

- 🤖 **Machine Learning Detection**: Random Forest classifier trained on 13 features extracted from URLs and HTML content
- 🔍 **Hybrid Analysis**: Combines local AI analysis with cloud-based threat intelligence (VirusTotal)
- ⚡ **Fast API**: RESTful API built with FastAPI for easy integration
- 🐳 **Docker Support**: Containerized application for easy deployment
- 📊 **Comprehensive Features**: Analyzes both lexical URL patterns and HTML content characteristics

## How It Works

The system extracts 13 features from URLs:

### URL Features (9 features)
- URL length
- Hostname length
- Special character count
- Shannon entropy (randomness measure)
- Digit count
- HTTPS usage
- Suspicious TLD detection (.xyz, .top, .tk)
- IP address presence
- WWW prefix

### HTML Features (4 features)
- Number of input fields
- Password field presence
- Iframe presence
- Title length

These features are fed into a Random Forest classifier that predicts whether a URL is phishing or legitimate.

## Installation

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd AI-Phish
```

2. Install dependencies:
```bash
pip install -r requirments.txt
```

**Note**: There are two requirements files in the repository. Use `requirments.txt` which contains all necessary dependencies.

3. Train the model (optional - a pre-trained model may be included):
```bash
python train.py
```

This will generate `phishing_model.pkl` in the project directory.

## Usage

### Running the API Server

Start the FastAPI server:

```bash
uvicorn main:app --reload
```

The API will be available at `http://localhost:8000`

### API Endpoints

#### Health Check
```bash
GET /
```
Returns the API status.

#### Scan URL
```bash
POST /scan
Content-Type: application/json

{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "ai_analysis": {
    "phishing_detected": false,
    "confidence_score": "15.23%",
    "risk_level": "STABLE",
    "scanned_features": {
      "url_length": 19,
      "password_field": false,
      "iframe_present": false
    }
  },
  "threat_intel": {
    "status": "FOUND",
    "malicious_votes": 0,
    "harmless_votes": 45,
    "permalink": "https://www.virustotal.com/..."
  }
}
```

### Example Usage with cURL

```bash
curl -X POST "http://localhost:8000/scan" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}'
```

### Example Usage with Python

```python
import requests

response = requests.post(
    "http://localhost:8000/scan",
    json={"url": "https://example.com"}
)
print(response.json())
```

## VirusTotal Integration

The system integrates with VirusTotal API for additional threat intelligence. To enable this feature:

1. Get a VirusTotal API key from [virustotal.com](https://www.virustotal.com/)
2. Set it as an environment variable:
```bash
export VT_API_KEY="your_api_key_here"
```

Or modify `main.py` to use your API key directly (not recommended for production).

If no API key is configured, the system will skip VirusTotal checks and still provide AI-based analysis.

## Training the Model

The model is trained on synthetic data that simulates both legitimate and phishing URLs. To retrain:

```bash
python train.py
```

The training script:
- Generates synthetic legitimate URLs from known safe domains
- Creates phishing URL patterns based on common attack vectors
- Extracts features from all URLs
- Trains a Random Forest classifier
- Evaluates performance and saves the model to `phishing_model.pkl`

**Note**: The training uses simulated HTML features for efficiency. In production, the system fetches real HTML content for analysis.

## Docker Deployment

### Build the Docker Image

```bash
docker build -t ai-phish .
```

### Run the Container

```bash
docker run -p 8000:8000 -e VT_API_KEY="your_api_key" ai-phish
```

The API will be available at `http://localhost:8000`

**Note**: The Dockerfile automatically trains the model during the build process if `phishing_model.pkl` doesn't exist.

## Project Structure

```
AI-Phish/
├── main.py              # FastAPI application and API endpoints
├── train.py             # Model training script
├── features.py          # Feature extraction functions
├── phishing_model.pkl   # Trained Random Forest model (generated)
├── requirements.txt     # Dependencies (incomplete)
├── requirments.txt      # Dependencies (complete - use this)
├── Dockerfile           # Docker configuration
└── README.md            # This file
```

## Dependencies

- `fastapi` - Web framework for building the API
- `uvicorn` - ASGI server
- `scikit-learn` - Machine learning library (Random Forest)
- `pandas` - Data manipulation
- `numpy` - Numerical computing
- `joblib` - Model serialization
- `requests` - HTTP library for fetching URLs and VirusTotal API
- `beautifulsoup4` - HTML parsing
- `python-multipart` - Form data parsing

## Model Performance

The Random Forest classifier is trained with:
- 100 estimators
- 80/20 train/test split
- Random state for reproducibility

Check the training output for accuracy metrics and classification reports.

## Security Considerations

⚠️ **Important Notes**:
- This is a detection tool, not a guarantee. Always use multiple security layers
- The model is trained on synthetic data - real-world performance may vary
- VirusTotal API has rate limits - consider caching results for production use
- Never expose API keys in version control

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

## Acknowledgments

- VirusTotal for threat intelligence API
- scikit-learn for machine learning capabilities
- FastAPI for the excellent web framework

