# KingSec v1.1.0 — Download & Install

---

## System Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| OS | Linux x86_64 or arm64 | Linux x86_64 or arm64 |
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8 GB |
| Disk | 10 GB free | 20 GB+ |
| Docker (optional) | Docker Engine 20.10+ | Docker Engine 24.0+ |
| Python (pip install) | Python 3.9 – 3.12 | Python 3.11 |
| Network | Localhost only (default) | Localhost only |

> **Note:** Windows and macOS are not officially supported at this time, but the Docker image may work on these platforms via Docker Desktop.

---

## Docker Install (Recommended)

**Step 1 — Pull the image**

```bash
docker pull kingusecurity/kingsec:1.1.0
```

**Step 2 — Create a data directory (optional but recommended)**

```bash
mkdir -p ~/kingsec-data
```

**Step 3 — Run the container**

```bash
docker run -d \
  --name kingsec \
  -p 127.0.0.1:8765:8765 \
  -v ~/kingsec-data:/data \
  kingusecurity/kingsec:1.1.0
```

**Step 4 — Open the web interface**

Navigate to `http://127.0.0.1:8765` in your browser.

**Persistent storage:** The `-v` mount ensures your assessments, findings, and configuration survive container restarts and upgrades.

**Upgrading:**

```bash
docker stop kingsec
docker rm kingsec
docker pull kingusecurity/kingsec:1.1.0
docker run -d \
  --name kingsec \
  -p 127.0.0.1:8765:8765 \
  -v ~/kingsec-data:/data \
  kingusecurity/kingsec:1.1.0
```

---

## pip Install (Native)

**Step 1 — Install via pip**

```bash
pip install kingsec==1.1.0
```

**Step 2 — Run KingSec**

```bash
kingsec serve
```

By default, the server starts on `127.0.0.1:8765`.

**Optional — Specify data directory:**

```bash
kingsec serve --data-dir /path/to/data
```

**Upgrading:**

```bash
pip install --upgrade kingsec==1.1.0
```

---

## Verifying the Installation

Open `http://127.0.0.1:8765` in a browser. You should see the KingSec login page.

**Default credentials (change immediately):**

- Username: `admin`
- Password: `kingsec-admin`

---

## Post-Install Steps

1. **Change the default admin password** — Settings > Users > Admin
2. **Enable MFA** — Settings > Authentication > MFA
3. **Configure AI (optional)** — Settings > AI Providers > Add Key
4. **Run your first assessment** — Assessments > New Assessment > Quick Host Scan
5. **Create user accounts** — Settings > Users > Add User (if RBAC is needed)

---

## Documentation

- **GitHub repository:** https://github.com/kingusecurity/kingsec
- **Issue tracker:** https://github.com/kingusecurity/kingsec/issues
- **Documentation:** See the `docs/` directory in the repository
- **Release notes:** https://github.com/kingusecurity/kingsec/releases

---

## Support

- **Email:** kingusecurity@gmail.com
- **GitHub Issues:** Bug reports and feature requests
- **Response time:** Typically within 48 hours for email inquiries

---

**Version:** 1.1.0  
**Author:** Abdul Mannan  
**Contact:** kingusecurity@gmail.com  
**GitHub:** https://github.com/kingusecurity/kingsec
