# Smart Contract Security Auditor

A full-stack application for automated security analysis and vulnerability detection in Solidity smart contracts.

[![Frontend](https://img.shields.io/badge/Frontend-React%2019-61DAFB?logo=react)](frontend-ui/)
[![Backend](https://img.shields.io/badge/Backend-Spring%20Boot%204-6DB33F?logo=spring)](backend-java-service/)
[![ML Service](https://img.shields.io/badge/ML-Python%20Flask-3776AB?logo=python)](ml-service/)

## 🏗️ Architecture

```
┌─────────────────┐     ┌─────────────────────┐     ┌─────────────────┐
│                 │     │                     │     │                 │
│  React Frontend │────▶│  Spring Boot API    │────▶│  ML Service     │
│  (Port 3000)    │     │  (Port 8080)        │     │  (Port 5000)    │
│                 │     │                     │     │                 │
└─────────────────┘     └──────────┬──────────┘     └─────────────────┘
                                   │
                                   ▼
                        ┌─────────────────────┐
                        │    PostgreSQL DB    │
                        │  (Neon/AWS/Azure)   │
                        └─────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- **Node.js** 18+ (for frontend)
- **Java** 25 JDK (for backend)
- **Python** 3.10+ (for ML service)
- **PostgreSQL** database (local or cloud)

### 1. Clone the Repository

```bash
git clone https://github.com/oyerishi/smart-contract-auditor.git
cd smart-contract-auditor
```

### 2. Start ML Service

```bash
cd ml-service
python -m venv venv
.\venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
python app.py
```

### 3. Start Backend Service

```bash
cd backend-java-service

# Set database environment variables
$env:DB_URL = "jdbc:postgresql://localhost:5432/auditor_db"
$env:DB_USERNAME = "postgres"
$env:DB_PASSWORD = "your_password"

# Build and run
mvn clean package -DskipTests
java -jar target/smart-contract-auditor.jar
```

### 4. Start Frontend

```bash
cd frontend-ui
npm install
npm start
```

Open http://localhost:3000 in your browser.

---

## 📁 Project Structure

```
smart-contract-auditor/
├── frontend-ui/                 # React Frontend Application
│   ├── src/
│   │   ├── components/          # Reusable UI components
│   │   │   ├── common/          # Buttons, inputs, modals
│   │   │   ├── dashboard/       # Dashboard widgets
│   │   │   ├── editor/          # Monaco code editor
│   │   │   └── upload/          # File upload components
│   │   ├── pages/               # Page components
│   │   │   ├── Home.tsx         # Landing page
│   │   │   ├── Login.tsx        # Authentication
│   │   │   ├── Register.tsx     # User registration
│   │   │   ├── Dashboard.tsx    # Main dashboard
│   │   │   └── ScanReport.tsx   # Vulnerability reports
│   │   ├── services/            # API integration
│   │   ├── context/             # React Context (Auth, Scan)
│   │   ├── hooks/               # Custom hooks
│   │   └── utils/               # Helper functions
│   ├── public/                  # Static assets
│   └── package.json
│
├── backend-java-service/        # Spring Boot Backend
│   ├── src/main/java/com/security/auditor/
│   │   ├── controller/          # REST API endpoints
│   │   ├── service/             # Business logic
│   │   ├── repository/          # Data access layer
│   │   ├── model/               # JPA entities & DTOs
│   │   ├── analysis/            # Static analysis engine
│   │   ├── config/              # Spring configuration
│   │   ├── security/            # JWT authentication
│   │   └── exception/           # Error handling
│   ├── src/main/resources/      # Configuration files
│   └── pom.xml
│
├── ml-service/                  # Python ML Service
│   ├── app.py                   # Flask application
│   └── requirements.txt         # Python dependencies
│
├── test-contracts/              # Sample Solidity contracts
└── README.md                    # This file
```

---

## 🔧 Services Overview

### Frontend (React)

| Technology | Version |
|------------|---------|
| React | 19.2.0 |
| TypeScript | 4.9.5 |
| Redux Toolkit | 2.11.0 |
| React Router | 7.9.6 |
| Monaco Editor | 4.7.0 |
| Tailwind CSS | Latest |

**Commands:**
```bash
cd frontend-ui
npm install          # Install dependencies
npm start            # Development server (port 3000)
npm run build        # Production build
npm test             # Run tests
```

### Backend (Java Spring Boot)

| Technology | Version |
|------------|---------|
| Java | 25 |
| Spring Boot | 4.0.0 |
| Spring Security | Latest |
| PostgreSQL | Latest |
| JWT (jjwt) | 0.12.6 |

**Commands:**
```bash
cd backend-java-service
mvn clean package -DskipTests    # Build JAR
mvn spring-boot:run              # Run with Maven
.\run.ps1                        # Run with local .env
.\run-with-cloud-db.ps1          # Run with cloud DB
```

### ML Service (Python Flask)

| Technology | Version |
|------------|---------|
| Python | 3.10+ |
| Flask | 3.0.0 |
| Scikit-learn | Latest |
| Gunicorn | 21.2.0 |

**Commands:**
```bash
cd ml-service
pip install -r requirements.txt  # Install dependencies
python app.py                    # Development server (port 5000)
gunicorn -w 4 app:app           # Production server
```

---

## 🌐 Deployment

### Option 1: GitHub Pages (Frontend Only) + External Backend

#### Deploy Frontend to GitHub Pages

1. **Update API URL** in `frontend-ui/src/config/api.config.ts`:
   ```typescript
   export const API_BASE_URL = 'https://your-backend-url.com/api';
   ```

2. **Add homepage** to `frontend-ui/package.json`:
   ```json
   {
     "homepage": "https://oyerishi.github.io/smart-contract-auditor"
   }
   ```

3. **Install gh-pages**:
   ```bash
   cd frontend-ui
   npm install gh-pages --save-dev
   ```

4. **Add deploy scripts** to `package.json`:
   ```json
   {
     "scripts": {
       "predeploy": "npm run build",
       "deploy": "gh-pages -d build"
     }
   }
   ```

5. **Deploy**:
   ```bash
   npm run deploy
   ```

6. **Enable GitHub Pages** in repository Settings → Pages → Source: `gh-pages` branch

### Option 2: Backend Hosting Options

Since GitHub Pages only hosts static files, you'll need to host the backend elsewhere:

| Platform | Free Tier | Best For |
|----------|-----------|----------|
| **[Railway](https://railway.app)** | $5 credit/month | Java + PostgreSQL |
| **[Render](https://render.com)** | 750 hours/month | Java + PostgreSQL |
| **[Fly.io](https://fly.io)** | 3 shared VMs | Docker containers |
| **[Heroku](https://heroku.com)** | Eco dynos ($5/mo) | Easy deployment |
| **[AWS Free Tier](https://aws.amazon.com)** | 12 months free | Full control |

#### Deploy Backend to Railway (Recommended)

1. Create account at [railway.app](https://railway.app)
2. Connect your GitHub repository
3. Add PostgreSQL database
4. Set environment variables:
   - `DB_URL`
   - `DB_USERNAME`
   - `DB_PASSWORD`
   - `JWT_SECRET`
5. Deploy automatically from `main` branch

#### Deploy ML Service to Render

1. Create account at [render.com](https://render.com)
2. Create new Web Service
3. Connect GitHub repository
4. Set:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`
5. Deploy

### Option 3: Docker Deployment (All Services)

Create a `docker-compose.yml` for easy deployment:

```yaml
version: '3.8'
services:
  frontend:
    build: ./frontend-ui
    ports:
      - "3000:80"
    depends_on:
      - backend

  backend:
    build: ./backend-java-service
    ports:
      - "8080:8080"
    environment:
      - DB_URL=${DB_URL}
      - DB_USERNAME=${DB_USERNAME}
      - DB_PASSWORD=${DB_PASSWORD}
    depends_on:
      - ml-service

  ml-service:
    build: ./ml-service
    ports:
      - "5000:5000"
```

---

## 📊 Repository Structure Recommendation

### ✅ Recommended: Single Monorepo

Keep all three services in **one repository** because:

- ✅ Easier to manage versioning and releases
- ✅ Single source of truth
- ✅ Simplified CI/CD pipeline
- ✅ Easier for contributors to understand the full system
- ✅ Coordinated deployments

### Alternative: Separate Repos

Only consider separate repos if:
- Different teams manage each service independently
- Services have vastly different release cycles
- You want to open-source only parts of the project

---

## 🔐 Environment Variables

### Backend Service
| Variable | Description | Required |
|----------|-------------|----------|
| `DB_URL` | PostgreSQL JDBC URL | Yes |
| `DB_USERNAME` | Database username | Yes |
| `DB_PASSWORD` | Database password | Yes |
| `JWT_SECRET` | Secret key for JWT tokens | Yes |
| `ML_SERVICE_URL` | ML service endpoint | No (default: http://localhost:5000) |

### Frontend
| Variable | Description | Required |
|----------|-------------|----------|
| `REACT_APP_API_URL` | Backend API URL | Yes |

---

## 🛡️ Vulnerability Detection

The system detects these smart contract vulnerabilities:

| Vulnerability | Severity | SWC ID |
|--------------|----------|--------|
| Reentrancy | 🔴 CRITICAL | SWC-107 |
| Integer Overflow/Underflow | 🟠 HIGH | SWC-101 |
| Unchecked External Call | 🟠 HIGH | SWC-104 |
| Access Control Issues | 🟠 HIGH | SWC-105 |
| Tx.Origin Authentication | 🟡 MEDIUM | SWC-115 |
| Timestamp Dependency | 🟢 LOW | SWC-116 |
| DoS with Gas Limit | 🟢 LOW | SWC-128 |

---

## 📝 API Documentation

### Authentication
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/register` | POST | Register new user |
| `/api/auth/login` | POST | Login and get JWT |

### Contracts
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/contracts/upload` | POST | Upload contract |
| `/api/contracts` | GET | List contracts |
| `/api/contracts/{id}` | GET | Get contract details |

### Scans
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scans` | POST | Start new scan |
| `/api/scans` | GET | List scans |
| `/api/scans/{id}` | GET | Get scan results |
| `/api/scans/{id}/report` | GET | Download PDF report |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📞 Support

- Create an [Issue](https://github.com/oyerishi/smart-contract-auditor/issues) for bug reports
- Start a [Discussion](https://github.com/oyerishi/smart-contract-auditor/discussions) for questions

---

<p align="center">
  Made with ❤️ for the blockchain security community
</p>
