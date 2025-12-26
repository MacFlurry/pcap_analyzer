# Technology Stack - PCAP Analyzer

## Core
- **Language:** Python 3.10+
- **Web Framework:** FastAPI (ASGI) with Uvicorn server, Nginx reverse proxy (production)
- **Analysis Engine:** Hybrid dpkt + Scapy (dpkt for fast initial parsing, Scapy for deep inspection) with PacketMetadata lazy evaluation (3-5x speedup)
- **Additional Tools:** tshark (Wireshark CLI) for PCAP validation

## Database & Data
- **Database:** PostgreSQL (Production, multi-tenant) and SQLite (Development/Testing)
- **ORM:** SQLAlchemy
- **Migrations:** Alembic

## Frontend
- **Languages:** HTML5, CSS3, Vanilla JavaScript
- **Visualizations:** Plotly.js (interactive timeline, protocol distribution, heatmaps)
- **Templating:** Jinja2

## Security
- **Authentication:** Hybrid JWT (Authorization Headers + HttpOnly Cookies)
- **Two-Factor Authentication (2FA):** pyotp for TOTP generation and verification, qrcode for QR code generation
- **Password Hashing:** Passlib (bcrypt/Argon2id) with zxcvbn strength validation
- **CSRF Protection:** fastapi-csrf-protect library
- **Input Validation:**
    - Magic number file validation
    - Decompression bomb protection (decompression_monitor.py)
    - Path traversal prevention
- **Data Privacy:** PII sanitization (error_sanitizer.py)

## Infrastructure & DevOps
- **Containerization:** Docker (multi-stage builds)
- **Orchestration:** Kubernetes with Helm charts
- **Certificate Management:** cert-manager (Let's Encrypt automation)
- **Local Development:** Docker Compose
- **Web Server:** Uvicorn (ASGI) with Nginx reverse proxy

## Quality Assurance
- **Testing:** pytest with Hypothesis, Testcontainers (PostgreSQL integration), and Playwright (E2E testing)
- **Coverage:** coverage.py
- **Linting & Formatting:** Black, isort, Flake8
- **CI/CD:** GitHub Actions, pre-commit hooks
