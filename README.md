# Container Security Analyzer 🛡️

A professional, modular static analysis tool built with Python Flask to detect vulnerabilities, misconfigurations, and security anti-patterns in container configuration files.

**Important:** This application performs *static analysis only*. It does not execute containers or perform active penetration testing.

## Features

- **Multi-Format Support:** Analyzes `Dockerfile`, `docker-compose.yml`, Kubernetes manifests (`.yaml`), and `.env` files.
- **Rule Engine:** Modular analyzers with specific rules for secrets detection, privilege escalation, network exposure, and supply-chain risks.
- **Modern Dashboard:** Cyber-security themed dark UI with glassmorphism effects, drag-and-drop upload, and animated charts.
- **Scoring System:** Calculates a security score (0-100) and assigns a grade (A-F) based on finding severity.
- **Reporting:** Export detailed, self-contained HTML reports.
- **Privacy:** In-memory history only (no database required).

## Architecture

- **Backend:** Python 3.12, Flask, Werkzeug
- **Frontend:** HTML5, Bootstrap 5, Vanilla JS, Chart.js, FontAwesome
- **Deployment:** Ready for Azure App Service Linux (includes `Procfile`, `startup.sh`, and GitHub Actions workflow).

## Installation

1. **Clone the repository** (or download the files).
2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
4. **Environment Variables:**
   Rename `.env.example` to `.env` and configure your settings.

## Usage

Run the application locally:
```bash
flask run
```
Or with Gunicorn:
```bash
gunicorn app:app --bind=0.0.0.0:8000
```

Navigate to `http://127.0.0.1:5000` (or 8000) in your browser. Drag and drop your configuration files into the drop zone and click "Start Analysis".

## Rule Categories

- **Privilege Escalation:** Detects `privileged: true`, `USER root`, `hostPID`, etc.
- **Network Security:** Detects `hostNetwork`, dangerous exposed ports (22, 2375, 3389).
- **Secrets Management:** Regex-based detection for hardcoded API keys, tokens, and passwords in `ENV`, `ARG`, `.env` files, and ConfigMaps.
- **Supply Chain:** Detects unpinned image tags (`latest`), unofficial base images, and unsafe remote script execution (`curl | bash`).
- **Resource Constraints:** Flags missing memory/CPU limits.

## Deployment to Azure App Service

This repository includes a GitHub Actions workflow `.github/workflows/azure-deploy.yml`.

1. Create a Web App in Azure App Service (Linux, Python 3.12).
2. Download the Publish Profile from the Azure Portal.
3. In your GitHub repository, go to **Settings > Secrets and variables > Actions**.
4. Add a repository secret named `AZURE_WEBAPP_PUBLISH_PROFILE` and paste the publish profile XML content.
5. Push to the `main` branch to trigger deployment.
