# Troubleshooting Guide

**Version:** 1.1.0  
**Last Updated:** 2026-07-27

## Installation Issues

### Docker container exits immediately
1. Check logs: `docker logs kingsec`
2. Verify `.env` file has `KINGSEC_JWT__SECRET_KEY` set
3. Ensure ports are available: `netstat -an | findstr 8765`
4. Run with interactive mode to see errors: `docker run -it --rm kingsec:1.1.0`

### "alembic upgrade head" fails
1. Ensure database URL is correct in `.env` or environment
2. SQLite: verify data directory exists and is writable
3. PostgreSQL: check connection string, credentials, and network access
4. Run with verbose output: `alembic upgrade head --verbose`

### Permission denied when running Docker
- Linux: add user to docker group: `sudo usermod -aG docker $USER`
- Windows: run PowerShell as Administrator
- macOS: ensure Docker Desktop has sufficient permissions

### Scanner binary not found
1. Verify binary is installed: `nmap --version`
2. Check PATH: `echo $PATH` (Linux/macOS), `echo %PATH%` (Windows)
3. Restart KingSec to trigger scanner re-discovery
4. Check Scanner Health in the UI or GET /api/v1/scanners/health

## Runtime Issues

### API returns 401 Unauthorized
1. Token may be expired — log in again
2. Ensure Authorization header format: `Bearer <token>` (note the space)
3. Check that the server is running: `curl http://127.0.0.1:8765/api/v1/settings/healthz`

### API returns 429 Too Many Requests
Rate limit exceeded. Wait for the rate limit window to reset (see X-RateLimit-Reset header). Rate limits apply per IP address.

### Assessment stuck on "pending" status
1. Check Scanner Health — if no scanners are usable, the assessment will not start
2. Verify target is reachable from the KingSec host
3. Check server logs for error messages
4. Cancel and recreate the assessment

### Report generation fails
1. Ensure the assessment has completed (status is "completed")
2. Check disk space — report generation requires free disk space
3. For PDF reports, verify WeasyPrint's native dependencies are installed
   (this is the most common cause — WeasyPrint is a Python package, but PDF
   rendering also needs system-level GTK libraries that `pip install` does
   not provide):
   - **Windows:** install the GTK3 runtime from
     https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases
     (download and run the latest `.exe`), then restart your terminal (and
     KingSec) so the updated `PATH` takes effect.
   - **Linux (Debian/Ubuntu):** `sudo apt install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0`
   - **macOS:** `brew install pango`
   - If the server log shows "WeasyPrint could not import some external
     libraries", the above has not yet taken effect — this confirms the
     diagnosis. See https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation
     for the authoritative, OS-specific instructions.
   - The Docker image already includes these libraries — this issue only
     affects direct (non-Docker) installs.

### Frontend shows blank page
1. Check browser console for JavaScript errors (F12)
2. Clear browser cache and reload
3. Verify API server is running and accessible from the browser
4. Check that the frontend was built (dist/ directory exists)

## Database Issues

### "No script_location key found" in Alembic
- Run Alembic commands from the project root directory
- If installed via pip, use `kingsec-migrate` instead of `alembic`

### SQLite foreign key errors
KingSec enables `PRAGMA foreign_keys=ON` automatically. This is expected behavior.

### Migration history shows unexpected versions
Verify migrations are applied in order: `alembic history --verbose`

## Scanner Issues

### Nuclei shows "templates not found"
Run `nuclei -update-templates` to download the template database. This is a required asset.

### Trivy shows "database not initialized"
Run `trivy image --download-db-only` to download the vulnerability database.

### Nmap requires root privileges
- Linux: use `sudo` or set capabilities: `sudo setcap cap_net_raw+ep /usr/bin/nmap`
- Windows: run terminal as Administrator

### ZAP requires Java
OWASP ZAP requires Java Runtime Environment. Install Java 11 or later.

## Connectivity Issues

### Cannot reach the API from another machine
The server binds to 127.0.0.1 by default. Configure `KINGSEC_SERVER__HOST=0.0.0.0` in `.env` to allow external connections. Use a reverse proxy (nginx, Caddy) in production.

### CORS errors in frontend
The API includes CORS middleware. Ensure the frontend origin is allowed in `KINGSEC_CORS__ALLOW_ORIGINS`.

## Performance Issues

### Assessments are very slow
1. Check target responsiveness (ping, port scan)
2. Reduce scanner count by using a more specific profile
3. Ensure sufficient system resources (CPU, RAM, disk I/O)
4. Check for competing processes

### UI is slow
1. Reduce the number of open tabs
2. Check browser memory usage
3. Verify API server responsiveness

## Error Messages

| Error | Likely Cause | Solution |
|-------|--------------|----------|
| "Database schema version mismatch" | Migrations not applied | Run `alembic upgrade head` |
| "Invalid token" | Token expired or malformed | Log in again |
| "Permission denied" | Insufficient role | Request ADMIN role from administrator |
| "Assessment not found" | Invalid assessment ID | Verify the assessment ID |
| "Scanner not usable" | Scanner binary missing | Install the required scanner |
| "Target unreachable" | Network connectivity issue | Verify target is accessible |
| "Report not found" | Report not yet generated | Complete the assessment first |
