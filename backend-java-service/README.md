# Backend Java Service - Smart Contract Security Auditor

A Spring Boot backend service for smart contract static analysis and security auditing.

## Tech Stack

- **Java** 25
- **Spring Boot** 4.0.0
- **Spring Security** with JWT authentication
- **Spring Data JPA** with PostgreSQL
- **HikariCP** connection pooling
- **Maven** build tool

## Prerequisites

- Java 25 (JDK)
- Maven 3.8+
- PostgreSQL database (local or cloud)

## Installation

```bash
# Navigate to backend directory
cd backend-java-service

# Build the project
mvn clean package -DskipTests

# Or build with tests
mvn clean package
```

## Commands

| Command | Description |
|---------|-------------|
| `mvn clean package` | Build JAR with tests |
| `mvn clean package -DskipTests` | Build JAR without tests |
| `mvn spring-boot:run` | Run directly with Maven |
| `mvn test` | Run unit tests |
| `java -jar target/smart-contract-auditor.jar` | Run the built JAR |
| `.\run.ps1` | Run with local environment variables |
| `.\run-with-cloud-db.ps1` | Run with cloud database configuration |

## Running the Application

### Option 1: Using PowerShell Scripts

**With Local Database:**
```powershell
# Create a .env file with your database credentials first
.\run.ps1
```

**With Cloud Database:**
```powershell
# Edit run-with-cloud-db.ps1 to configure your cloud database
.\run-with-cloud-db.ps1
```

### Option 2: Using Maven

```bash
# Set environment variables first
$env:DB_URL = "jdbc:postgresql://localhost:5432/auditor_db"
$env:DB_USERNAME = "postgres"
$env:DB_PASSWORD = "postgres"

# Run the application
mvn spring-boot:run
```

### Option 3: Using JAR

```bash
# Build first
mvn clean package -DskipTests

# Set environment variables and run
java -jar target/smart-contract-auditor.jar
```

## Database Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_URL` | JDBC connection URL | `jdbc:postgresql://localhost:5432/auditor_db` |
| `DB_USERNAME` | Database username | `postgres` |
| `DB_PASSWORD` | Database password | `postgres` |

### Cloud Database Examples

**Neon DB:**
```
jdbc:postgresql://ep-xxx.us-east-2.aws.neon.tech:5432/neondb?sslmode=require
```

**AWS RDS:**
```
jdbc:postgresql://mydb.123456789.us-east-1.rds.amazonaws.com:5432/auditor_db?ssl=true&sslmode=require
```

**Azure Database:**
```
jdbc:postgresql://myserver.postgres.database.azure.com:5432/auditor_db?ssl=true&sslmode=require
```

## Project Structure

```
backend-java-service/
├── src/
│   ├── main/
│   │   ├── java/com/security/auditor/
│   │   │   ├── AuditorApplication.java    # Main application entry point
│   │   │   ├── analysis/                  # Static analysis engine
│   │   │   ├── config/                    # Spring configuration classes
│   │   │   ├── controller/                # REST API controllers
│   │   │   ├── exception/                 # Custom exception handlers
│   │   │   ├── health/                    # Health check endpoints
│   │   │   ├── model/                     # JPA entities and DTOs
│   │   │   ├── repository/                # Data access layer
│   │   │   ├── service/                   # Business logic layer
│   │   │   └── util/                      # Utility classes
│   │   └── resources/
│   │       ├── application.properties     # Main configuration
│   │       ├── application-dev.properties # Development profile
│   │       ├── application-prod.properties# Production profile
│   │       └── logback-spring.xml         # Logging configuration
│   └── test/
│       ├── java/                          # Unit and integration tests
│       └── resources/
│           └── application-test.properties# Test configuration
├── target/                                # Build output
│   └── smart-contract-auditor.jar         # Compiled JAR
├── uploads/
│   └── contracts/                         # Uploaded contract files
├── logs/                                  # Application logs
├── pom.xml                                # Maven configuration
├── run.ps1                                # Local run script
└── run-with-cloud-db.ps1                  # Cloud database run script
```

## API Endpoints

The service runs on `http://localhost:8080/api` by default.

### Authentication
- `POST /auth/register` - Register new user
- `POST /auth/login` - Login and get JWT token

### Contracts
- `POST /contracts/upload` - Upload contract for analysis
- `GET /contracts` - List user's contracts
- `GET /contracts/{id}` - Get contract details

### Scans
- `POST /scans` - Start a new scan
- `GET /scans` - List user's scans
- `GET /scans/{id}` - Get scan results
- `GET /scans/{id}/report` - Get detailed report

### Health
- `GET /actuator/health` - Health check endpoint

## Features

- **JWT Authentication**: Secure API access with token-based auth
- **Static Analysis**: Analyze Solidity contracts for vulnerabilities
- **ML Integration**: Connect to ML service for advanced detection
- **File Management**: Secure contract file upload and storage
- **PDF Reports**: Generate downloadable vulnerability reports
- **API Documentation**: SpringDoc OpenAPI integration

## Logging

Logs are written to `logs/application.log` with the following configuration:
- Max file size: 10MB
- Max history: 10 files
- Log levels: DEBUG for app, INFO for frameworks
