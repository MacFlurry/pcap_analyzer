# Troubleshooting Guide

**Version**: 5.0
**Date**: 2025-12-21
**Status**: Production Ready ✅

---

## Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [Database Connection Issues](#database-connection-issues)
3. [Authentication & Authorization](#authentication--authorization)
4. [Docker Compose Issues](#docker-compose-issues)
5. [Kubernetes Issues](#kubernetes-issues)
6. [Performance Problems](#performance-problems)
7. [File Upload Issues](#file-upload-issues)
8. [Network & Connectivity](#network--connectivity)
9. [Log Analysis](#log-analysis)
10. [Known Issues](#known-issues)

---

## Quick Diagnostics

### Health Check

**Verify application is running**:

```bash
# Docker Compose
curl http://localhost:8000/api/health

# Kubernetes
kubectl port-forward -n pcap-analyzer svc/pcap-analyzer 8000:8000
curl http://localhost:8000/api/health

# Expected response
{
  "status": "ok",
  "database": "connected",
  "version": "5.0.0"
}
```

**If health check fails**:
- ❌ **No response**: Application not running → Check container/pod logs
- ❌ **"database": "disconnected"**: Database connection issue → See [Database Connection Issues](#database-connection-issues)
- ❌ **HTTP 500**: Application error → Check logs for stack trace

---

### Check Logs

**Docker Compose**:
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f app
docker-compose logs -f postgres

# Last 100 lines
docker-compose logs --tail=100 app
```

**Kubernetes**:
```bash
# Application logs
kubectl logs -n pcap-analyzer deployment/pcap-analyzer -f

# Previous crashed pod
kubectl logs -n pcap-analyzer deployment/pcap-analyzer --previous

# All pods
kubectl logs -n pcap-analyzer -l app=pcap-analyzer --all-containers=true
```

---

### Common Log Patterns

**Look for these patterns**:

```bash
# CRITICAL errors (application crash)
grep "CRITICAL" logs/app.log

# Database connection errors
grep "connection refused\|Connection pool exhausted" logs/app.log

# Authentication failures
grep "Failed login attempt\|Invalid token" logs/app.log

# Rate limiting
grep "Rate limit exceeded" logs/app.log
```

---

## Database Connection Issues

### Issue: "password authentication failed for user pcap"

**Symptoms**:
```
FATAL:  password authentication failed for user "pcap"
```

**Diagnosis**:
```bash
# Check DATABASE_URL password
echo $DATABASE_URL

# Docker Compose: Check .env file
cat .env | grep POSTGRES_PASSWORD

# Kubernetes: Check secret
kubectl get secret pcap-secrets -n pcap-analyzer -o jsonpath='{.data.postgres-password}' | base64 -d
```

**Solutions**:

**Option 1: Reset PostgreSQL password**
```bash
# Docker Compose
docker exec -it pcap_postgres psql -U postgres
ALTER USER pcap WITH PASSWORD 'new_password';
\q

# Update .env
nano .env  # Set POSTGRES_PASSWORD=new_password

# Restart
docker-compose restart app
```

**Option 2: Fix DATABASE_URL**
```bash
# Ensure password matches
export DATABASE_URL="postgresql://pcap:correct_password@postgres:5432/pcap_analyzer"
```

---

### Issue: "FATAL: database pcap_analyzer does not exist"

**Symptoms**:
```
FATAL:  database "pcap_analyzer" does not exist
```

**Diagnosis**:
```bash
# List databases
docker exec -it pcap_postgres psql -U postgres -c "\l"

# Or Kubernetes
kubectl exec -n pcap-analyzer postgres-0 -- psql -U postgres -c "\l"
```

**Solution**:
```bash
# Create database
docker exec -it pcap_postgres psql -U postgres
CREATE DATABASE pcap_analyzer OWNER pcap;
GRANT ALL PRIVILEGES ON DATABASE pcap_analyzer TO pcap;
\q

# Run migrations
docker-compose exec app alembic upgrade head
```

---

### Issue: "connection refused (port 5432)"

**Symptoms**:
```
could not connect to server: Connection refused
    Is the server running on host "postgres" and accepting TCP/IP connections on port 5432?
```

**Diagnosis**:
```bash
# Check if PostgreSQL is running
docker ps | grep postgres

# Or Kubernetes
kubectl get pods -n pcap-analyzer -l app=postgres

# Check PostgreSQL logs
docker-compose logs postgres
```

**Solutions**:

**Option 1: PostgreSQL not started**
```bash
# Docker Compose
docker-compose up -d postgres

# Wait for PostgreSQL to be ready
docker exec -it pcap_postgres pg_isready -U pcap
```

**Option 2: Wrong host/port**
```bash
# Docker Compose: host should be "postgres" (service name)
DATABASE_URL="postgresql://pcap:password@postgres:5432/pcap_analyzer"

# Kubernetes: use service DNS
DATABASE_URL="postgresql://pcap:password@postgres.pcap-analyzer.svc.cluster.local:5432/pcap_analyzer"

# Local PostgreSQL: use localhost
DATABASE_URL="postgresql://pcap:password@localhost:5432/pcap_analyzer"
```

**Option 3: Port conflict**
```bash
# Check if port 5432 is in use
lsof -i :5432

# Use different port
POSTGRES_PORT=15432 docker-compose up -d
```

---

### Issue: "Connection pool exhausted"

**Symptoms**:
```
ERROR    [database] Connection pool exhausted (10/10)
```

**Diagnosis**:
```bash
# Check active connections
docker exec -it pcap_postgres psql -U postgres -d pcap_analyzer
SELECT count(*) FROM pg_stat_activity WHERE datname='pcap_analyzer';
\q
```

**Solutions**:

**Option 1: Increase pool size**
```bash
# .env
DATABASE_MAX_SIZE=20

# Restart
docker-compose restart app
```

**Option 2: Increase PostgreSQL max_connections**
```bash
# Check current limit
docker exec -it pcap_postgres psql -U postgres -c "SHOW max_connections;"

# Increase limit
docker exec -it pcap_postgres psql -U postgres
ALTER SYSTEM SET max_connections = 200;
SELECT pg_reload_conf();
\q

# Restart PostgreSQL
docker-compose restart postgres
```

**Option 3: Find connection leaks**
```bash
# Check for long-running connections
docker exec -it pcap_postgres psql -U postgres -d pcap_analyzer
SELECT pid, now() - pg_stat_activity.query_start AS duration, query
FROM pg_stat_activity
WHERE state != 'idle'
ORDER BY duration DESC;
\q

# Kill long-running connection (if stuck)
# SELECT pg_terminate_backend(12345);  -- Replace with actual PID
```

---

### Issue: "SSL connection has been closed unexpectedly"

**Symptoms**:
```
SSL error: decryption failed or bad record mac
SSL connection has been closed unexpectedly
```

**Diagnosis**:
```bash
# Check DATABASE_SSL_MODE
echo $DATABASE_SSL_MODE

# Check PostgreSQL SSL configuration
docker exec -it pcap_postgres psql -U postgres -c "SHOW ssl;"
```

**Solutions**:

**Option 1: Disable SSL (development only)**
```bash
# .env
DATABASE_SSL_MODE=disable

# Restart
docker-compose restart app
```

**Option 2: Enable SSL in PostgreSQL**
```bash
# postgresql.conf
ssl = on
ssl_cert_file = '/path/to/server.crt'
ssl_key_file = '/path/to/server.key'

# Restart PostgreSQL
docker-compose restart postgres
```

**Option 3: Use correct SSL mode**
```bash
# Cloud PostgreSQL (AWS RDS, GCP Cloud SQL)
DATABASE_SSL_MODE=require  # Or verify-full

# Local PostgreSQL without SSL
DATABASE_SSL_MODE=disable
```

---

## Authentication & Authorization

### Issue: "SECRET_KEY environment variable is required in production"

**Symptoms**:
```
ValueError: SECRET_KEY environment variable is required in production
```

**Diagnosis**:
```bash
# Check ENVIRONMENT mode
echo $ENVIRONMENT

# Check SECRET_KEY set
echo ${SECRET_KEY:-NOT_SET}
```

**Solution**:
```bash
# Generate SECRET_KEY
export SECRET_KEY=$(openssl rand -hex 32)

# Add to .env
echo "SECRET_KEY=$SECRET_KEY" >> .env

# Or Kubernetes: create secret
kubectl create secret generic pcap-secrets \
  --from-literal=secret-key="$(openssl rand -hex 32)" \
  -n pcap-analyzer

# Restart
docker-compose restart app
```

---

### Issue: "Incorrect username or password"

**Symptoms**:
```
HTTP 401 Unauthorized
{"detail": "Incorrect username or password"}
```

**Diagnosis**:
```bash
# Check user exists
curl -X GET http://localhost:8000/api/users \
  -H "Authorization: Bearer <admin_token>"

# Or direct database query
docker exec -it pcap_postgres psql -U pcap -d pcap_analyzer
SELECT username, is_approved, is_active FROM users WHERE username='alice';
\q
```

**Common Causes**:

1. **User not approved** (is_approved=false)
   ```bash
   # Admin approves user
   curl -X PUT http://localhost:8000/api/admin/users/<user_id>/approve \
     -H "Authorization: Bearer <admin_token>"
   ```

2. **User blocked** (is_active=false)
   ```bash
   # Admin unblocks user
   curl -X PUT http://localhost:8000/api/admin/users/<user_id>/unblock \
     -H "Authorization: Bearer <admin_token>"
   ```

3. **Wrong password**
   ```bash
   # Reset password (user must do this themselves via /api/users/me)
   curl -X PUT http://localhost:8000/api/users/me \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{
       "current_password": "old_password",
       "new_password": "NewPassword123!"
     }'
   ```

4. **Admin brise-glace password** (check logs)
   ```bash
   docker-compose logs app | grep "ADMIN BRISE-GLACE"
   ```

---

### Issue: "Token expired" or "Invalid token"

**Symptoms**:
```
HTTP 401 Unauthorized
{"detail": "Could not validate credentials"}
```

**Diagnosis**:
```bash
# Check token expiration (JWT tokens expire after 30 minutes)
# Decode token (use jwt.io or jwt-cli)
echo "eyJ..." | jwt decode -

# Check SECRET_KEY hasn't changed
echo $SECRET_KEY
```

**Solution**:
```bash
# Re-login to get new token
curl -X POST http://localhost:8000/api/token \
  -d "username=alice&password=SecurePassword123!"
```

---

### Issue: "Rate limit exceeded"

**Symptoms**:
```
HTTP 429 Too Many Requests
{"detail": "Rate limit exceeded. Please wait 5 seconds."}
```

**Diagnosis**:
```bash
# Check failed login attempts
docker-compose logs app | grep "Failed login attempt"

# Example: Failed login attempt for user alice (attempt 7/7)
```

**Solution**:
```bash
# Wait for lockout to expire (1s, 2s, or 5s depending on attempts)
sleep 5

# Then retry login
curl -X POST http://localhost:8000/api/token \
  -d "username=alice&password=CORRECT_PASSWORD"
```

**Prevention**:
- Use correct password
- Avoid brute force attacks
- Consider implementing CAPTCHA after 3 failed attempts (roadmap)

---

### Issue: "Forbidden: Insufficient permissions"

**Symptoms**:
```
HTTP 403 Forbidden
{"detail": "Forbidden"}
```

**Common Causes**:

1. **Admin endpoint accessed by regular user**
   ```bash
   # Check user role
   curl -X GET http://localhost:8000/api/users/me \
     -H "Authorization: Bearer <token>"

   # Expected: {"role": "admin"} for admin endpoints
   ```

2. **CSRF token missing**
   ```bash
   # Get CSRF token
   CSRF_TOKEN=$(curl -s -X GET http://localhost:8000/api/csrf/token \
     -H "Authorization: Bearer <token>" | jq -r '.csrf_token')

   # Include in request
   curl -X POST http://localhost:8000/api/upload \
     -H "Authorization: Bearer <token>" \
     -H "X-CSRF-Token: $CSRF_TOKEN" \
     -F "file=@capture.pcap"
   ```

3. **Accessing another user's resource**
   ```bash
   # Regular users can only access their own tasks
   # Admin users can access all tasks
   ```

---

## Docker Compose Issues

### Issue: "Port already in use"

**Symptoms**:
```
ERROR: for postgres  Cannot start service postgres: driver failed programming external connectivity on endpoint pcap_postgres: Bind for 0.0.0.0:5432 failed: port is already allocated
```

**Diagnosis**:
```bash
# Find process using port
lsof -i :5432

# Or on Linux
sudo netstat -tlnp | grep 5432
```

**Solutions**:

**Option 1: Stop conflicting service**
```bash
# Stop local PostgreSQL
sudo systemctl stop postgresql

# Or kill process
kill <PID>
```

**Option 2: Use different port**
```bash
# .env
POSTGRES_PORT=15432
APP_PORT=9000

# Restart
docker-compose down
docker-compose up -d
```

---

### Issue: "docker-compose: command not found"

**Symptoms**:
```
bash: docker-compose: command not found
```

**Diagnosis**:
```bash
# Check Docker Compose version
docker compose version  # New syntax (Docker Compose V2)
docker-compose version  # Old syntax (Docker Compose V1)
```

**Solution**:

**Option 1: Use new syntax** (recommended)
```bash
# Replace docker-compose with docker compose
docker compose up -d
docker compose logs -f
```

**Option 2: Install Docker Compose V1**
```bash
# Linux
sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# macOS (via Homebrew)
brew install docker-compose
```

---

### Issue: "No such file or directory: .env"

**Symptoms**:
```
WARNING: The POSTGRES_PASSWORD variable is not set. Defaulting to a blank string.
```

**Diagnosis**:
```bash
# Check .env file exists
ls -la .env
```

**Solution**:
```bash
# Create .env from example
cp .env.example .env

# Edit .env
nano .env

# Add required variables
POSTGRES_PASSWORD=$(openssl rand -base64 32)
SECRET_KEY=$(openssl rand -hex 32)
CSRF_SECRET_KEY=$(openssl rand -hex 32)

# Restart
docker-compose down
docker-compose up -d
```

---

### Issue: "Volume permission denied"

**Symptoms**:
```
ERROR: for postgres  Cannot start service postgres: failed to mkdir /var/lib/postgresql/data: Permission denied
```

**Diagnosis**:
```bash
# Check volume ownership
docker volume inspect pcap_analyzer_postgres_data

# Check directory permissions
docker exec -it pcap_postgres ls -la /var/lib/postgresql
```

**Solutions**:

**Option 1: Fix permissions**
```bash
# Stop containers
docker-compose down

# Remove volume
docker volume rm pcap_analyzer_postgres_data

# Recreate with correct permissions
docker-compose up -d
```

**Option 2: Use named volume with correct UID**
```yaml
# docker-compose.yml
services:
  postgres:
    user: "999:999"  # PostgreSQL UID/GID
    volumes:
      - postgres_data:/var/lib/postgresql/data
```

---

## Kubernetes Issues

### Issue: "ImagePullBackOff"

**Symptoms**:
```
kubectl get pods -n pcap-analyzer
NAME                             READY   STATUS             RESTARTS   AGE
pcap-analyzer-5d4f8b9c7d-abcde   0/1     ImagePullBackOff   0          2m
```

**Diagnosis**:
```bash
# Check pod events
kubectl describe pod pcap-analyzer-5d4f8b9c7d-abcde -n pcap-analyzer

# Common errors:
# - "pull access denied" (private registry auth required)
# - "manifest unknown" (image tag doesn't exist)
# - "image not found" (wrong image name)
```

**Solutions**:

**Option 1: Build and load image** (kind)
```bash
# Build image locally
docker build -t pcap-analyzer:latest .

# Load into kind cluster
kind load docker-image pcap-analyzer:latest --name pcap-analyzer

# Verify image loaded
docker exec -it pcap-analyzer-control-plane crictl images | grep pcap-analyzer
```

**Option 2: Use imagePullPolicy: IfNotPresent**
```yaml
# values.yaml or deployment.yaml
spec:
  containers:
  - name: app
    image: pcap-analyzer:latest
    imagePullPolicy: IfNotPresent  # Don't pull if image exists locally
```

**Option 3: Fix image registry** (production)
```bash
# Push to registry
docker tag pcap-analyzer:latest myregistry.com/pcap-analyzer:v5.0.0
docker push myregistry.com/pcap-analyzer:v5.0.0

# Update Helm values
helm upgrade pcap-analyzer ./helm-chart/pcap-analyzer \
  --set image.repository=myregistry.com/pcap-analyzer \
  --set image.tag=v5.0.0
```

---

### Issue: "CrashLoopBackOff"

**Symptoms**:
```
kubectl get pods -n pcap-analyzer
NAME                             READY   STATUS             RESTARTS   AGE
pcap-analyzer-5d4f8b9c7d-abcde   0/1     CrashLoopBackOff   5          5m
```

**Diagnosis**:
```bash
# Check pod logs
kubectl logs -n pcap-analyzer pcap-analyzer-5d4f8b9c7d-abcde

# Check previous crashed pod logs
kubectl logs -n pcap-analyzer pcap-analyzer-5d4f8b9c7d-abcde --previous

# Check events
kubectl describe pod pcap-analyzer-5d4f8b9c7d-abcde -n pcap-analyzer
```

**Common Causes**:

1. **Missing SECRET_KEY**
   ```bash
   # Check secret exists
   kubectl get secret pcap-secrets -n pcap-analyzer

   # Create secret
   kubectl create secret generic pcap-secrets \
     --from-literal=secret-key="$(openssl rand -hex 32)" \
     --from-literal=csrf-secret-key="$(openssl rand -hex 32)" \
     -n pcap-analyzer
   ```

2. **Database connection failure**
   ```bash
   # Check PostgreSQL is running
   kubectl get pods -n pcap-analyzer -l app=postgres

   # Check DATABASE_URL is correct
   kubectl get deployment pcap-analyzer -n pcap-analyzer -o yaml | grep DATABASE_URL
   ```

3. **Liveness probe failing**
   ```bash
   # Check liveness probe configuration
   kubectl get deployment pcap-analyzer -n pcap-analyzer -o yaml | grep -A 5 livenessProbe

   # Disable temporarily for debugging
   kubectl patch deployment pcap-analyzer -n pcap-analyzer \
     -p '{"spec":{"template":{"spec":{"containers":[{"name":"app","livenessProbe":null}]}}}}'
   ```

---

### Issue: "Ingress not working"

**Symptoms**:
```
curl http://pcap.local
curl: (7) Failed to connect to pcap.local port 80: Connection refused
```

**Diagnosis**:
```bash
# Check Ingress exists
kubectl get ingress -n pcap-analyzer

# Check Ingress controller installed
kubectl get pods -n ingress-nginx

# Check /etc/hosts entry
cat /etc/hosts | grep pcap.local
```

**Solutions**:

**Option 1: Install Ingress controller**
```bash
# Install nginx Ingress controller (kind)
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml

# Wait for ready
kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=90s
```

**Option 2: Add /etc/hosts entry**
```bash
# Add entry
echo "127.0.0.1 pcap.local" | sudo tee -a /etc/hosts

# Verify
ping pcap.local
```

**Option 3: Use NodePort instead**
```bash
# Disable Ingress, use NodePort
helm upgrade pcap-analyzer ./helm-chart/pcap-analyzer \
  --set ingress.enabled=false \
  --set service.type=NodePort \
  --set service.nodePort=30080

# Access via http://localhost:8000 (if kind-config.yaml maps ports)
```

---

### Issue: "PersistentVolumeClaim pending"

**Symptoms**:
```
kubectl get pvc -n pcap-analyzer
NAME           STATUS    VOLUME   CAPACITY   ACCESS MODES   STORAGECLASS   AGE
data-pvc       Pending                                                     5m
```

**Diagnosis**:
```bash
# Check PVC events
kubectl describe pvc data-pvc -n pcap-analyzer

# Common error: "no persistent volumes available"
```

**Solutions**:

**Option 1: Create StorageClass** (kind/local)
```bash
# kind uses local-path provisioner by default
kubectl get storageclass

# If missing, install
kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/master/deploy/local-path-storage.yaml

# Set as default
kubectl patch storageclass local-path -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
```

**Option 2: Use emptyDir** (development only)
```yaml
# values.yaml
persistence:
  enabled: false

# Uses emptyDir (data lost on pod restart)
```

---

## Performance Problems

### Issue: Slow query performance

**Symptoms**:
- Slow page loads (>5 seconds)
- High database CPU usage
- Slow API responses

**Diagnosis**:
```bash
# Enable slow query logging
docker exec -it pcap_postgres psql -U postgres
ALTER SYSTEM SET log_min_duration_statement = 1000;  # Log queries >1s
SELECT pg_reload_conf();
\q

# Check slow queries
docker-compose logs postgres | grep "duration:"

# Example: LOG:  duration: 2345.678 ms  statement: SELECT * FROM tasks
```

**Solutions**:

**Option 1: Add missing indexes**
```sql
-- Check missing indexes
docker exec -it pcap_postgres psql -U pcap -d pcap_analyzer

-- Analyze query
EXPLAIN ANALYZE SELECT * FROM tasks WHERE owner_id='abc-123';

-- If "Seq Scan" appears, add index
CREATE INDEX idx_tasks_owner_id ON tasks(owner_id);

-- Reanalyze
ANALYZE tasks;
\q
```

**Option 2: Increase PostgreSQL memory**
```bash
# postgresql.conf
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 4MB

# Restart PostgreSQL
docker-compose restart postgres
```

**Option 3: Increase connection pool**
```bash
# .env
DATABASE_MIN_SIZE=5
DATABASE_MAX_SIZE=20

# Restart app
docker-compose restart app
```

---

### Issue: High memory usage

**Symptoms**:
- Application killed by OOM (Out of Memory)
- Kubernetes: pod evicted
- Docker: container restart

**Diagnosis**:
```bash
# Check memory usage
docker stats pcap_analyzer

# Kubernetes
kubectl top pod -n pcap-analyzer

# Check logs for OOM killer
dmesg | grep -i "out of memory"
```

**Solutions**:

**Option 1: Reduce MAX_UPLOAD_SIZE_MB**
```bash
# .env
MAX_UPLOAD_SIZE_MB=100  # Reduce from 500

# Restart
docker-compose restart app
```

**Option 2: Increase container memory limit**
```yaml
# docker-compose.yml
services:
  app:
    mem_limit: 2g  # Increase from 1g

# Kubernetes
resources:
  limits:
    memory: 2Gi  # Increase from 1Gi
```

**Option 3: Fix memory leaks** (if any)
```bash
# Profile application memory
docker exec -it pcap_analyzer python -m memory_profiler app/main.py

# Check for unclosed connections
# All database queries use 'async with' context managers (no leaks)
```

---

## File Upload Issues

### Issue: "File too large"

**Symptoms**:
```
HTTP 413 Request Entity Too Large
{"detail": "File too large. Maximum size is 500 MB."}
```

**Solution**:
```bash
# Increase upload size limit
# .env
MAX_UPLOAD_SIZE_MB=1000

# Restart
docker-compose restart app
```

**Note**: Larger files require more memory/CPU for processing.

---

### Issue: "Invalid file type"

**Symptoms**:
```
HTTP 400 Bad Request
{"detail": "Invalid file type. Must be .pcap or .pcapng"}
```

**Diagnosis**:
```bash
# Check file extension
file capture.pcap

# Check magic number
hexdump -C capture.pcap | head -n 1

# Expected:
# PCAP: d4 c3 b2 a1 (little-endian) or a1 b2 c3 d4 (big-endian)
# PCAPNG: 0a 0d 0d 0a
```

**Solutions**:

**Option 1: Rename file**
```bash
# If file is valid PCAP but wrong extension
mv capture.cap capture.pcap
```

**Option 2: Convert format**
```bash
# Convert PcapNG to PCAP
tshark -F pcap -r capture.pcapng -w capture.pcap

# Or editcap
editcap -F pcap capture.pcapng capture.pcap
```

---

### Issue: "Decompression bomb detected"

**Symptoms**:
```
HTTP 400 Bad Request
{"detail": "Decompression bomb detected (ratio: 150:1)"}
```

**Explanation**: File expands >100x when decompressed (security protection)

**Solution**:

**Option 1: Accept risk and disable check** (not recommended)
```python
# app/utils/decompression_monitor.py
MAX_EXPANSION_RATIO = 200  # Increase from 100
```

**Option 2: Use uncompressed PCAP**
```bash
# Decompress manually
gunzip capture.pcap.gz

# Upload uncompressed file
curl -X POST http://localhost:8000/api/upload \
  -H "Authorization: Bearer <token>" \
  -F "file=@capture.pcap"
```

---

## Network & Connectivity

### Issue: "Connection timeout"

**Symptoms**:
```
curl: (28) Connection timed out after 30000 milliseconds
```

**Diagnosis**:
```bash
# Check network connectivity
ping pcap.example.com

# Check DNS resolution
nslookup pcap.example.com

# Check port is open
telnet pcap.example.com 80
```

**Solutions**:

**Option 1: Check firewall**
```bash
# Allow port 8000
sudo ufw allow 8000/tcp

# Or iptables
sudo iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
```

**Option 2: Check reverse proxy**
```bash
# Check nginx is running
sudo systemctl status nginx

# Check nginx config
sudo nginx -t

# Restart nginx
sudo systemctl restart nginx
```

---

## Log Analysis

### Enable Debug Logging

**Temporary** (current session):
```bash
# Docker Compose
docker-compose exec app bash -c "export LOG_LEVEL=DEBUG && uvicorn app.main:app --reload"

# Kubernetes
kubectl set env deployment/pcap-analyzer LOG_LEVEL=DEBUG -n pcap-analyzer
```

**Permanent**:
```bash
# .env
LOG_LEVEL=DEBUG

# Restart
docker-compose restart app
```

**Remember**: Set back to `INFO` or `WARNING` in production (DEBUG logs are verbose)

---

### Grep Useful Patterns

```bash
# Failed database queries
docker-compose logs app | grep -i "database error\|query failed"

# Authentication failures
docker-compose logs app | grep "Failed login attempt\|Invalid token"

# Rate limiting
docker-compose logs app | grep "Rate limit exceeded"

# Admin actions (audit trail)
docker-compose logs app | grep "AUDIT:"

# Errors only
docker-compose logs app | grep -E "ERROR|CRITICAL"

# Slow requests (>1s)
docker-compose logs app | grep "duration:" | awk '$4 > 1000'
```

---

## Known Issues

### Issue: SQLite "database is locked"

**Symptoms** (v4.x only, fixed in v5.0 with PostgreSQL):
```
sqlite3.OperationalError: database is locked
```

**Solution**: Migrate to PostgreSQL (see [Migration Guide](MIGRATION_GUIDE_v5.0.md))

---

### Issue: Windows Docker Compose volume permissions

**Symptoms**:
```
PermissionError: [Errno 13] Permission denied: '/data/pcap_analyzer.db'
```

**Workaround**:
```yaml
# docker-compose.yml (Windows only)
services:
  app:
    volumes:
      - /c/Users/YourName/pcap_data:/data  # Use absolute Windows path
```

---

### Issue: macOS Docker DNS resolution slow

**Symptoms**: Slow DNS lookups (5-10 seconds)

**Workaround**:
```bash
# Use Google DNS
# /etc/resolv.conf (inside container)
nameserver 8.8.8.8
nameserver 8.8.4.4
```

---

## Getting Help

### Before Opening an Issue

1. **Check this troubleshooting guide** ✅
2. **Search existing issues**: https://github.com/MacFlurry/pcap_analyzer/issues
3. **Run health check**: `curl http://localhost:8000/api/health`
4. **Collect logs**:
   ```bash
   docker-compose logs app > logs.txt
   docker-compose logs postgres >> logs.txt
   ```

### Opening a GitHub Issue

**Template**:

```markdown
**Environment**:
- Version: 5.0.0
- Deployment: Docker Compose / Kubernetes / CLI
- OS: Ubuntu 22.04 / macOS 13 / Windows 11
- Database: PostgreSQL 15 / SQLite

**Symptoms**:
[Describe what's happening]

**Logs**:
```
[Paste relevant logs here]
```

**Steps to Reproduce**:
1. ...
2. ...
3. ...

**Expected Behavior**:
[What should happen]

**Actual Behavior**:
[What actually happens]
```

**Submit**: https://github.com/MacFlurry/pcap_analyzer/issues/new

---

## Related Documentation

- [PostgreSQL Deployment Guide](POSTGRESQL_DEPLOYMENT.md)
- [Migration Guide v5.0](MIGRATION_GUIDE_v5.0.md)
- [Environment Variables Reference](ENVIRONMENT_VARIABLES.md)
- [Security Best Practices](SECURITY_BEST_PRACTICES.md)

---

**Last Updated**: 2025-12-21
**Version**: 5.0.0
**Status**: Production Ready ✅
