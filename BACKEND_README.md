# Zerava Security Scanner - Backend

A comprehensive security scanning backend built with Flask that performs automated security assessments of web applications.

## 🚀 Features

- **HTTPS/TLS Analysis**: Validates HTTPS availability, redirects, and certificate configuration
- **SSL/TLS Security**: Checks for weak protocols (SSLv2, SSLv3, TLS 1.0/1.1) and certificate expiration
- **Security Headers**: Validates 7+ critical security headers and their configurations
- **Port Scanning**: Identifies exposed services on 20+ common ports
- **OWASP Top 10**: Tests for SQL injection, XSS, information disclosure, and more
- **Automated Scoring**: Calculates security scores (0-100) with diminishing returns algorithm
- **Background Jobs**: Asynchronous scan execution with progress tracking
- **RESTful API**: Complete REST API for scan management

## 📋 Requirements

- Python 3.8+
- pip (Python package manager)

## 🛠️ Installation

### 1. Clone or Download the Project

```bash
cd Zerava-backend
```

### 2. Create Virtual Environment (Recommended)

```bash
python -m venv venv

# On Linux/Mac:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt --break-system-packages
```

### 4. Verify Installation

```bash
python -c "import flask; import requests; print('Dependencies OK')"
```

## ⚙️ Configuration

Configuration is managed in `config.py`. Key settings:

```python
# Environment Variables (optional)
FLASK_ENV=development          # development, production, testing
FLASK_DEBUG=True              # Enable debug mode
FLASK_HOST=0.0.0.0            # Host to bind to
FLASK_PORT=5000               # Port to run on

# CORS Settings
CORS_ORIGINS=http://localhost:3000,http://localhost:5173

# Scanning Settings
MAX_CONCURRENT_SCANS=5        # Max parallel scans
SCAN_TIMEOUT=300              # Scan timeout in seconds
SCANNING_ENABLED=True         # Enable/disable scanning

# Security
SECRET_KEY=your-secret-key    # Change in production!
```

## 🚀 Running the Application

### Development Mode

```bash
python run.py
```

The server will start at `http://localhost:5000`

### Production Mode

```bash
# Set environment variables
export FLASK_ENV=production
export FLASK_DEBUG=False
export SECRET_KEY=your-secure-random-key

# Run with gunicorn (recommended for production)
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 'app:create_app()'
```

## 📡 API Endpoints

### Scan Management

#### Create a New Scan
```http
POST /api/scans
Content-Type: application/json

{
  "target": "https://example.com",
  "scan_type": "full"
}

Response: 201 Created
{
  "scan_id": "scan-abc123",
  "status": "pending",
  "message": "Scan started"
}
```

**Scan Types:**
- `full` - Comprehensive scan (HTTPS, SSL/TLS, headers, ports, OWASP)
- `quick` - Fast scan (HTTPS, headers only)
- `api` - API-focused scan (HTTPS, SSL/TLS, headers, OWASP)
- `headers` - Headers only

#### Get Scan Results
```http
GET /api/scans/{scan_id}

Response: 200 OK
{
  "id": "scan-abc123",
  "target": "example.com",
  "type": "full",
  "status": "completed",
  "score": 78,
  "summary": {
    "totalFindings": 25,
    "critical": 2,
    "high": 5,
    "medium": 8,
    "low": 10
  },
  "findings": [...],
  "date": "2026-02-01T10:30:00Z"
}
```

#### List All Scans
```http
GET /api/scans?status=completed

Response: 200 OK
{
  "scans": [...],
  "total": 10
}
```

#### Get Scan Findings
```http
GET /api/scans/{scan_id}/findings?severity=critical

Response: 200 OK
{
  "scan_id": "scan-abc123",
  "findings": [...],
  "total": 25,
  "filtered": 2
}
```

#### Cancel/Delete Scan
```http
DELETE /api/scans/{scan_id}

Response: 200 OK
{
  "message": "Scan cancelled",
  "scan_id": "scan-abc123"
}
```

### Status & Health

#### Health Check
```http
GET /api/status/health

Response: 200 OK
{
  "status": "healthy",
  "timestamp": "2026-02-01T12:00:00Z",
  "version": "1.0.0"
}
```

#### Queue Status
```http
GET /api/status/queue

Response: 200 OK
{
  "queue_stats": {
    "total_jobs": 10,
    "pending": 2,
    "running": 3,
    "completed": 5
  }
}
```

#### System Metrics
```http
GET /api/status/metrics

Response: 200 OK
{
  "total_scans": 100,
  "scans_today": 25,
  "average_scan_time_seconds": 45.2
}
```

## 🧪 Testing

### Test with cURL

```bash
# Create a scan
curl -X POST http://localhost:5000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "scan_type": "quick"}'

# Get scan results
curl http://localhost:5000/api/scans/scan-abc123

# Health check
curl http://localhost:5000/api/status/health
```

### Test with Python

```python
import requests

# Create scan
response = requests.post('http://localhost:5000/api/scans', json={
    'target': 'https://example.com',
    'scan_type': 'full'
})
scan_id = response.json()['scan_id']

# Get results
import time
time.sleep(30)  # Wait for scan to complete
results = requests.get(f'http://localhost:5000/api/scans/{scan_id}')
print(results.json())
```

## 📁 Project Structure

```
Zerava-backend/
├── app/
│   ├── __init__.py              # Flask app factory
│   ├── models/                  # Data models
│   │   ├── scan.py              # Scan model
│   │   ├── finding.py           # Finding model
│   │   └── report.py            # Report model
│   ├── scanners/                # Security scanners
│   │   ├── https_checker.py     # HTTPS/redirect checker
│   │   ├── ssl_tls_checker.py   # SSL/TLS checker
│   │   ├── security_headers.py  # Headers checker
│   │   ├── open_ports.py        # Port scanner
│   │   └── owasp_top10.py       # OWASP checker
│   ├── scoring/                 # Scoring system
│   │   └── score_calculator.py  # Score calculation
│   ├── utils/                   # Utilities
│   │   └── job_queue.py         # Background jobs
│   └── routes/                  # API routes
│       ├── scan_routes.py       # Scan endpoints
│       └── status_routes.py     # Status endpoints
├── config.py                    # Configuration
├── run.py                       # Application entry point
└── requirements.txt             # Dependencies
```

## 🔧 Troubleshooting

### Port Already in Use
```bash
# Find process using port 5000
lsof -i :5000

# Kill the process
kill -9 <PID>

# Or use a different port
export FLASK_PORT=8000
python run.py
```

### CORS Issues
Ensure your frontend URL is in `CORS_ORIGINS`:
```python
CORS_ORIGINS = 'http://localhost:3000,http://localhost:5173'
```

### Scan Timeouts
Increase timeout in `config.py`:
```python
SCAN_TIMEOUT = 600  # 10 minutes
HTTP_REQUEST_TIMEOUT = 20
```

### SSL Certificate Errors
For development/testing, some scanners use `verify=False`. For production:
```python
HTTP_VERIFY_SSL = True
```

## 🔒 Security Considerations

### For Production:

1. **Change Secret Key**
   ```python
   SECRET_KEY = os.urandom(32).hex()
   ```

2. **Enable Rate Limiting**
   ```python
   RATE_LIMIT_ENABLED = True
   RATE_LIMIT_PER_HOUR = 10
   ```

3. **Use HTTPS**
   - Deploy behind reverse proxy (Nginx)
   - Use SSL certificates

4. **Database Storage**
   - Current implementation uses in-memory storage
   - For production, integrate with PostgreSQL/MongoDB

5. **Authentication**
   - Add API key or JWT authentication
   - Implement user management

## 📊 Scoring System

The scoring algorithm:
- Starts with base score of 100
- Deducts points based on finding severity:
  - Critical: 40 points
  - High: 20 points
  - Medium: 10 points
  - Low: 5 points
- Uses diminishing returns (logarithmic scale)
- Maximum deductions per severity level

**Score Ratings:**
- 95-100: A+ (Excellent)
- 90-94: A (Very Good)
- 80-89: B (Good)
- 70-79: C (Acceptable)
- 60-69: D (Poor)
- 0-59: F (Critical Issues)

## 🐛 Known Limitations

1. **In-Memory Storage**: Scans are lost on restart
2. **No Persistence**: No database integration yet
3. **Basic Auth**: No authentication/authorization
4. **Port Scanning**: Limited to 20 common ports
5. **OWASP Checks**: Basic vulnerability detection only

## 🛣️ Roadmap

- [ ] Database integration (PostgreSQL/MongoDB)
- [ ] User authentication and API keys
- [ ] Scheduled/recurring scans
- [ ] Email notifications
- [ ] Export reports (PDF, JSON, HTML)
- [ ] Advanced vulnerability scanning
- [ ] Integration with CVE databases
- [ ] Web dashboard

## 📝 License

This project is part of the Zerava security scanning platform.

## 🤝 Contributing

For questions or issues, please contact the development team.

---

**Happy Scanning! 🔒**
