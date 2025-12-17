# ML Service - Smart Contract Security Auditor

A Flask-based machine learning service for smart contract vulnerability detection.

## Tech Stack

- **Python** 3.10+
- **Flask** 3.0.0
- **Flask-CORS** 4.0.0
- **Gunicorn** 21.2.0
- **NumPy**
- **Scikit-learn**
- **Joblib**

## Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

## Installation

```bash
# Navigate to ML service directory
cd ml-service

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
.\venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Commands

| Command | Description |
|---------|-------------|
| `python app.py` | Start development server |
| `flask run` | Start with Flask CLI |
| `gunicorn app:app` | Start production server |
| `gunicorn -w 4 -b 0.0.0.0:5000 app:app` | Production with 4 workers |
| `pip install -r requirements.txt` | Install dependencies |
| `pip freeze > requirements.txt` | Update requirements file |

## Running the Application

### Development Mode

```bash
# Activate virtual environment first
.\venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

# Run the application
python app.py
```

The service will start on `http://localhost:5000`.

### Production Mode

```bash
# Using Gunicorn (recommended for production)
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

Options:
- `-w 4`: Number of worker processes
- `-b 0.0.0.0:5000`: Bind address and port

## Project Structure

```
ml-service/
├── app.py                 # Main Flask application
│   ├── Data Classes       # Vulnerability, AnalysisMetrics, AnalysisResponse
│   ├── Vulnerability      # Pattern definitions (reentrancy, overflow, etc.)
│   │   Patterns
│   ├── Analysis Engine    # Contract parsing and analysis logic
│   ├── Risk Scoring       # Risk calculation algorithms
│   └── API Routes         # REST endpoints
├── requirements.txt       # Python dependencies
└── venv/                  # Virtual environment (created locally)
```

## API Endpoints

### Health Check
```
GET /health
```
Returns service health status.

**Response:**
```json
{
  "status": "healthy",
  "service": "ml-vulnerability-detector",
  "timestamp": "2025-12-17T10:30:00Z"
}
```

### Analyze Contract
```
POST /analyze
```
Analyzes a Solidity smart contract for vulnerabilities.

**Request Body:**
```json
{
  "contract_code": "// Solidity code here...",
  "contract_name": "MyContract.sol"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Analysis completed",
  "contract_name": "MyContract.sol",
  "vulnerabilities": [
    {
      "id": "vuln-001",
      "name": "Reentrancy Vulnerability",
      "description": "External call made before state changes",
      "severity": "CRITICAL",
      "category": "REENTRANCY",
      "line_number": 42,
      "code_snippet": "msg.sender.call{value: amount}(\"\")",
      "recommendation": "Use checks-effects-interactions pattern",
      "confidence": 0.95,
      "cwe_id": "CWE-841",
      "swc_id": "SWC-107"
    }
  ],
  "metrics": {
    "overall_risk_score": 85.5,
    "total_vulnerabilities": 5,
    "severity_count": {
      "CRITICAL": 1,
      "HIGH": 2,
      "MEDIUM": 1,
      "LOW": 1
    },
    "category_count": {
      "REENTRANCY": 1,
      "ARITHMETIC": 2,
      "ACCESS_CONTROL": 2
    },
    "model_confidence": 0.92
  },
  "processing_time_ms": 150
}
```

## Vulnerability Detection

The service detects the following vulnerability categories:

| Category | Severity | SWC ID | Description |
|----------|----------|--------|-------------|
| Reentrancy | CRITICAL | SWC-107 | External calls before state changes |
| Integer Overflow | HIGH | SWC-101 | Arithmetic without overflow protection |
| Unchecked Call | HIGH | SWC-104 | External call return value not checked |
| Access Control | HIGH | SWC-105 | Missing or weak access controls |
| Tx.Origin | MEDIUM | SWC-115 | Using tx.origin for authorization |
| Timestamp Dependency | LOW | SWC-116 | Reliance on block.timestamp |
| Gas Limit | LOW | SWC-128 | Potential DoS via gas limits |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_ENV` | Environment mode | `development` |
| `FLASK_DEBUG` | Enable debug mode | `True` |
| `PORT` | Server port | `5000` |
| `HOST` | Server host | `0.0.0.0` |

## Integration

The ML service is called by the Java backend service for advanced vulnerability detection. Ensure this service is running before starting full system analysis.

**Default Endpoint:** `http://localhost:5000/analyze`

## Features

- **Rule-based Detection**: Pattern matching for known vulnerabilities
- **ML-enhanced Analysis**: Machine learning models for complex detection
- **Risk Scoring**: Calculate overall contract risk scores
- **Confidence Metrics**: Provide confidence levels for detections
- **SWC/CWE Mapping**: Link vulnerabilities to standard classifications
