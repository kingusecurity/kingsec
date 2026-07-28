# KingSec v1.1.0 Installation Guide

Author: Abdul Mannan  
Contact: kingusecurity@gmail.com  
GitHub: https://github.com/kingusecurity/kingsec

---

## System Requirements

### Minimum Requirements

- CPU: 2 cores, 2.0 GHz or higher
- RAM: 4 GB
- Disk: 10 GB free space
- Python: 3.11 or higher
- Docker: 24.0 or higher (for Docker-based installation)
- Network: Outbound access for container image downloads

### Recommended Requirements

- CPU: 4 cores, 2.5 GHz or higher
- RAM: 8 GB (16 GB if running all scanners concurrently)
- Disk: 50 GB SSD
- Python: 3.12
- Docker: 26.0 or higher with Docker Compose v2

### Supported Operating Systems

- Ubuntu 22.04 / 24.04 LTS
- Debian 12
- RHEL 9 / Rocky Linux 9
- macOS 14 (Sonoma) or newer
- Windows 10 / 11 (Professional or Enterprise)
- Windows Server 2022

---

## Docker Installation (Recommended)

Docker-based deployment is the recommended method for running KingSec. It provides isolation, consistent environments, and simplified dependency management.

### Step 1: Install Docker

**Ubuntu / Debian**

    sudo apt update
    sudo apt install -y docker.io docker-compose-v2
    sudo systemctl enable --now docker

**RHEL / Rocky Linux**

    sudo dnf install -y docker docker-compose-plugin
    sudo systemctl enable --now docker

**macOS**

Download and install Docker Desktop from https://docs.docker.com/desktop/setup/install/mac-install/

**Windows**

Download and install Docker Desktop from https://docs.docker.com/desktop/setup/install/windows-install/

Ensure WSL 2 backend is enabled during installation.

### Step 2: Pull the KingSec Image

    docker pull kingusecurity/kingsec:1.1.0

### Step 3: Create a Data Directory

    mkdir -p /opt/kingsec/data
    mkdir -p /opt/kingsec/logs
    mkdir -p /opt/kingsec/reports

On Windows (PowerShell):

    New-Item -ItemType Directory -Path "C:\ProgramData\KingSec\data" -Force
    New-Item -ItemType Directory -Path "C:\ProgramData\KingSec\logs" -Force
    New-Item -ItemType Directory -Path "C:\ProgramData\KingSec\reports" -Force

### Step 4: Run the Container

    docker run -d \
      --name kingsec \
      --restart unless-stopped \
      -p 127.0.0.1:8765:8765 \
      -v /opt/kingsec/data:/app/data \
      -v /opt/kingsec/logs:/app/logs \
      -v /opt/kingsec/reports:/app/reports \
      kingusecurity/kingsec:1.1.0

On Windows (PowerShell):

    docker run -d `
      --name kingsec `
      --restart unless-stopped `
      -p 127.0.0.1:8765:8765 `
      -v "C:\ProgramData\KingSec\data:/app/data" `
      -v "C:\ProgramData\KingSec\logs:/app/logs" `
      -v "C:\ProgramData\KingSec\reports:/app/reports" `
      kingusecurity/kingsec:1.1.0

### Step 5: Verify the Container is Running

    docker ps --filter name=kingsec

Expected output shows the kingsec container with status "Up" and port 8765 mapped.

---

## Docker Compose Installation

### Step 1: Create the Compose Directory

    mkdir -p /opt/kingsec
    cd /opt/kingsec

### Step 2: Create docker-compose.yml

Create a file named docker-compose.yml with the following content:

    version: "3.9"
    services:
      kingsec:
        image: kingusecurity/kingsec:1.1.0
        container_name: kingsec
        restart: unless-stopped
        ports:
          - "127.0.0.1:8765:8765"
        volumes:
          - ./data:/app/data
          - ./logs:/app/logs
          - ./reports:/app/reports
        environment:
          - KINGSEC_SECRET_KEY=<generate-a-random-secret-key>
          - KINGSEC_JWT_SECRET=<generate-a-jwt-secret>
          - KINGSEC_LOG_LEVEL=info
        healthcheck:
          test: ["CMD", "curl", "-f", "http://localhost:8765/api/health"]
          interval: 30s
          timeout: 10s
          retries: 3

### Step 3: Start the Service

    docker compose up -d

### Step 4: Verify the Deployment

    docker compose ps

---

## Direct pip Installation

Use this method for development, air-gapped environments, or when Docker is not available.

### Step 1: Create a Virtual Environment

    python3 -m venv /opt/kingsec/venv
    source /opt/kingsec/venv/bin/activate

On Windows (PowerShell):

    python -m venv C:\ProgramData\KingSec\venv
    C:\ProgramData\KingSec\venv\Scripts\Activate.ps1

### Step 2: Install KingSec

    pip install kingsec==1.1.0

### Step 3: Prepare the Data Directories

    mkdir -p /opt/kingsec/data
    mkdir -p /opt/kingsec/logs
    mkdir -p /opt/kingsec/reports

### Step 4: Initialize the Database

    kingsec db init --version 1.1.0

### Step 5: Start KingSec

    kingsec start --host 127.0.0.1 --port 8765

The service runs in the foreground. Use a process manager (systemd, supervisord) for production.

### systemd Service File (Linux)

Create /etc/systemd/system/kingsec.service:

    [Unit]
    Description=KingSec ASM and VM Platform
    After=network.target

    [Service]
    Type=simple
    User=kingsec
    WorkingDirectory=/opt/kingsec
    Environment="PATH=/opt/kingsec/venv/bin"
    Environment="KINGSEC_SECRET_KEY=<secret>"
    Environment="KINGSEC_JWT_SECRET=<jwt-secret>"
    ExecStart=/opt/kingsec/venv/bin/kingsec start --host 127.0.0.1 --port 8765
    Restart=on-failure
    RestartSec=10

    [Install]
    WantedBy=multi-user.target

Enable and start:

    sudo systemctl daemon-reload
    sudo systemctl enable --now kingsec

---

## Windows-Specific Notes

### Path Configuration

Ensure Python 3.11+ is added to your system PATH during installation. Verify with:

    python --version
    pip --version

### Chocolatey Installation

    choco install python --version 3.12
    choco install docker-desktop

### Scoop Installation

    scoop bucket add extras
    scoop install python
    scoop install docker

### Windows Firewall

If you bind to 0.0.0.0 (not recommended for production), create a firewall rule:

    New-NetFirewallRule -DisplayName "KingSec API" -Direction Inbound -Protocol TCP -LocalPort 8765 -Action Allow

### Docker Desktop on Windows

- Use WSL 2 backend for best performance
- Mount volumes from wsl$ paths for faster I/O
- Example volume mount: \\\\wsl$\\docker-desktop-data\\data\\kingsec

### Running Without Docker

- Use PowerShell as Administrator
- Activate the virtual environment before running kingsec commands
- Windows paths may use either backslashes or forward slashes for volume mounts

---

## Linux / macOS Specific Notes

### Linux

- Create a dedicated system user: sudo useradd -r -s /bin/false kingsec
- Grant the kingsec user ownership: sudo chown -R kingsec:kingsec /opt/kingsec
- SELinux: On RHEL-based systems, ensure container_t context for Docker volumes
- AppArmor: No additional configuration required on Ubuntu/Debian

### macOS

- Docker Desktop for Mac does not require manual volume permission changes
- For pip installation, use Homebrew Python: brew install python@3.12
- Launch on login: Add kingsec start command to LaunchAgents

---

## Scanner Dependency Installation

KingSec uses pluggable scanners. Install them according to your assessment needs.

| Scanner     | Installation Command (Linux/macOS)                  | Installation Command (Windows)                   |
|-------------|------------------------------------------------------|--------------------------------------------------|
| Nmap        | sudo apt install nmap                                | choco install nmap                               |
| Nuclei      | go install github.com/projectdiscovery/nuclei/v3/... | scoop install nuclei                             |
| Nikto       | sudo apt install nikto                               | choco install nikto                              |
| FFUF        | go install github.com/ffuf/ffuf/v2@latest            | scoop install ffuf                               |
| Gobuster    | go install github.com/OJ/gobuster/v3@latest          | scoop install gobuster                           |
| Trivy       | sudo apt install trivy                               | choco install trivy                              |
| Semgrep     | pip install semgrep                                  | pip install semgrep                              |
| Amass       | go install github.com/owasp-amass/amass/v4/...@master| scoop install amass                              |
| ZAP         | docker pull ghcr.io/zaproxy/zaproxy:stable           | docker pull ghcr.io/zaproxy/zaproxy:stable       |

**Note:** After installing scanners, restart KingSec to register the new tool paths.

---

## Database Migration

### Automatic Migration

KingSec runs database migrations automatically on startup. No manual action is required for standard upgrades.

### Manual Migration

If automatic migration is disabled, run:

    kingsec db migrate --version 1.1.0

### Rollback

To revert to a previous version:

    kingsec db rollback --version 1.0.0

**Warning:** Rollback may cause data loss. Always back up before rolling back.

### Backup Before Migration

    kingsec db backup --output /opt/kingsec/backups/pre-migration-1.1.0.sqlite

---

## First-Run Setup

### Step 1: Access the Web Interface

Open a browser and navigate to http://127.0.0.1:8765

### Step 2: Create the First Admin Account

- The registration page prompts for username, email, and password
- The first registered user is automatically granted the ADMIN role
- Subsequent registrations default to VIEWER until promoted

### Step 3: Configure JWT and Encryption Secrets

For production, set the following environment variables before first run:

- KINGSEC_SECRET_KEY: A random 64-character string
- KINGSEC_JWT_SECRET: A random 64-character string
- KINGSEC_JWT_ALGORITHM: HS256 (default)
- KINGSEC_JWT_EXPIRY_MINUTES: 60 (default)

Generate secrets with:

    python -c "import secrets; print(secrets.token_hex(32))"

### Step 4: Verify Scanner Connectivity

Navigate to Settings > Scanner Health in the web interface to verify all installed scanners are detected.

---

## Verification Steps

After installation, confirm KingSec is operational:

### Health Check Endpoint

    curl http://127.0.0.1:8765/api/health

Expected response:

    {"status": "healthy", "version": "1.1.0", "uptime": "<seconds>"}

### Version Check

    curl http://127.0.0.1:8765/api/version

Expected response:

    {"version": "1.1.0", "build": "release"}

### Docker Logs

    docker logs kingsec --tail 50

Look for the line: "KingSec v1.1.0 started successfully on 127.0.0.1:8765"

### Web Interface

Navigate to http://127.0.0.1:8765. The login page loads without errors. Browser console shows no 4xx or 5xx errors.

---

## Troubleshooting Common Install Issues

### Port 8765 Already in Use

Stop the process occupying the port or change the bind port:

    docker run -d -p 127.0.0.1:18765:8765 kingusecurity/kingsec:1.1.0

### Permission Denied on Volume Mounts

Ensure the data directory is writable by the container user (UID 1000):

    sudo chown -R 1000:1000 /opt/kingsec/data

### Docker: Command Not Found

Install Docker and add your user to the docker group:

    sudo usermod -aG docker $USER
    newgrp docker

### pip Install Fails

- Upgrade pip: pip install --upgrade pip
- Ensure Python 3.11+ is active: python --version
- On Windows, use a virtual environment to avoid permission issues

### Database Migration Fails

- Check write permissions on the data directory
- Run kingsec db check for integrity verification
- Restore from backup: kingsec db restore --input <backup-file>

### Scanners Not Detected

- Verify the scanner is installed: which nmap (Linux/macOS) or where nmap (Windows)
- Restart KingSec after installing new scanners
- Check the logs: docker logs kingsec

### Web Interface Shows Blank Page

- Clear browser cache and hard reload (Ctrl+F5)
- Check browser console for JavaScript errors
- Ensure the API server is reachable at port 8765
