# HNG Stage 3: Anomaly Detection Engine

A real-time HTTP traffic anomaly detection daemon built alongside Nextcloud. It watches all incoming Nginx access logs, learns what normal traffic looks like, and automatically blocks suspicious IPs using iptables when traffic deviates significantly from the baseline.

---

## Live Deployment

| Resource | URL |
|----------|-----|
| **Server IP (Nextcloud)** | http://92.5.80.18 |
| **Metrics Dashboard** | http://detector-gideonbature.duckdns.org |
| **GitHub Repository** | https://github.com/GideonBature/hng-stage3 |

---

## Language Choice

**Python** was chosen for the following reasons:

- The standard library provides everything needed for this task: `collections.deque` for the sliding windows, `threading` for concurrent components, `subprocess` for iptables management, and `statistics` for baseline computation.
- Flask makes the live dashboard trivial to implement without introducing heavy dependencies.
- Python's readability makes the detection and baseline logic easy to follow, comment, and audit — which matters for a security tool.
- The entire daemon runs in under 5MB of memory, which is acceptable for a Python process of this kind.

---

## How the Sliding Window Works

The sliding window is the core data structure that tracks request rates in real time. Two windows are maintained: one per IP and one globally.

Each window is a `collections.deque` of timestamps. Every incoming log entry appends the current timestamp to the relevant IP's deque and to the global deque:

```python
self._ip_windows[source_ip].append(now)
self._global_window.append(now)
```

Every second, the evaluator evicts timestamps older than 60 seconds from the left of each deque:

```python
def _evict_old(self, window: deque, cutoff: float):
    while window and window[0] < cutoff:
        window.popleft()
```

After eviction, the current rate is simply the count of remaining entries divided by the window size:

```python
ip_rate = len(window) / self.window_seconds  # window_seconds = 60
```

This gives an exact per-second rate for any IP over the last 60 seconds without any approximation. The deque structure is ideal here because eviction from the left is O(1), making the window efficient even under high traffic.

---

## How the Baseline Works

The baseline answers the question: what does normal traffic look like right now?

**Structure:**

- Per-second request count buckets are stored in a dictionary: `{floor(timestamp): count}`
- These buckets cover a rolling 30-minute window
- Every 60 seconds, expired buckets (older than 30 minutes) are evicted and mean and stddev are recomputed from the remaining values

**Per-hour slots:**

The baseline also maintains per-hour slots. Each clock hour gets its own `{mean, stddev, samples}` record. When the current hour has accumulated enough samples (≥ 10), its slot is preferred over the global rolling window. This means the baseline adapts to time-of-day traffic patterns rather than mixing morning and afternoon traffic together.

**Floor values:**

To prevent false positives during very low traffic periods, a minimum floor is enforced:

```yaml
min_rps_floor: 1.0    # minimum effective mean
```

If the computed mean falls below 1.0 req/s, the floor value is used instead. This stops the detector from treating any request as anomalous during quiet periods.

**Recalculation interval:** every 60 seconds  
**Window size:** 30 minutes (1800 seconds)  
**Minimum samples before baseline is valid:** 10

---

## Detection Logic

An IP or global traffic rate is flagged as anomalous if either condition fires first:

```
z-score = (current_rate - baseline_mean) / baseline_stddev

Anomaly if: z-score > 3.0
         OR current_rate > 5.0 * baseline_mean
```

The z-score measures how many standard deviations the current rate is above normal. A z-score above 3.0 means the rate is statistically very unlikely to occur under normal conditions.

The 5x multiplier catches sudden spikes even when the stddev is very large (which happens when traffic is naturally bursty).

**Error surge detection:** If an IP's 4xx/5xx error rate exceeds 3x the baseline error rate, its detection thresholds are automatically tightened by 50%, making it easier to ban IPs that are probing or scanning.

---

## How iptables Blocking Works

When an IP is flagged as anomalous, the blocker inserts a DROP rule at the top of the INPUT chain:

```python
subprocess.run(
    ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
    check=True,
)
```

`-I INPUT` inserts at position 1, so the DROP rule is evaluated before any ACCEPT rules. All packets from the banned IP are silently dropped at the kernel level before they reach Nginx or Nextcloud.

**Auto-unban backoff schedule:**

| Offense | Ban Duration |
|---------|-------------|
| 1st | 10 minutes |
| 2nd | 30 minutes |
| 3rd | 2 hours |
| 4th+ | Permanent |

On unban, the rule is removed:

```python
subprocess.run(
    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
)
```

A Slack notification is sent on every ban and every unban.

---

## Setup Instructions (Fresh VPS to Running Stack)

### Prerequisites

- Ubuntu 22.04 or 24.04 VPS (minimum 2 vCPU, 2GB RAM)
- Docker and Docker Compose installed
- A domain or subdomain pointing to your server IP
- A Slack incoming webhook URL

### Step 1: Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
docker --version
```

### Step 2: Open required ports

```bash
sudo iptables -I INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 8080 -j ACCEPT
sudo apt install iptables-persistent -y
sudo netfilter-persistent save
```

Also open ports 80 and 8080 in your cloud provider's security list / firewall dashboard.

### Step 3: Clone the repository

```bash
git clone https://github.com/GideonBature/hng-stage3.git
cd hng-stage3
```

### Step 4: Configure environment

```bash
cp .env.example .env
nano .env
```

Fill in your values:

```env
# Slack incoming webhook URL
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Public IP of this VPS (used as a Nextcloud trusted domain)
SERVER_IP=your.server.ip.address

# Public domain that points to this server and serves the detector dashboard
DASHBOARD_DOMAIN=your.dashboard.domain

# Docker bridge gateway IP that nginx uses to reach the detector on the host network.
# Find it with: docker network inspect <network> | grep Gateway
DOCKER_GATEWAY_IP=172.17.0.1
```

> **Note:** `.env` is git-ignored. Never commit real secrets. If a webhook URL is
> ever exposed publicly, revoke it in Slack and create a new one.

### Step 5: Configure the detector

```bash
nano detector/config.yaml
```

The Slack webhook is read from the `SLACK_WEBHOOK_URL` environment variable via
the placeholder in `config.yaml`, so you do not normally need to edit this file:

```yaml
slack:
  webhook_url: "${SLACK_WEBHOOK_URL}"
```

The nginx config is generated at container startup from
`nginx/nginx.conf.template` using `envsubst`, substituting `${DASHBOARD_DOMAIN}`
and `${DOCKER_GATEWAY_IP}` from your `.env` file. You should not need to edit
`nginx.conf.template` unless you are changing the routing itself.

### Step 6: Bring the stack up

```bash
docker compose up -d --build
```

### Step 7: Verify everything is running

```bash
# Check all containers
docker compose ps

# Check Nginx is writing JSON logs
docker compose exec nginx tail -5 /var/log/nginx/hng-access.log

# Check detector is tailing the log
docker compose logs detector | head -20

# Check the named volume exists
docker volume ls | grep HNG-nginx-logs

# Check dashboard is accessible
curl -I http://your-dashboard-domain.duckdns.org

# Check Nextcloud is accessible by IP
curl -I http://your.server.ip
```

### What a successful startup looks like

```
NAME        STATUS
detector    Up (healthy)
nextcloud   Up
nginx       Up (healthy)
```

Detector logs should show:

```
[INFO] main: HNG Anomaly Detection Daemon starting
[INFO] monitor: LogMonitor waiting for log file
[INFO] monitor: Opened log file: /var/log/nginx/hng-access.log
[INFO] monitor: LogMonitor started tailing log
[INFO] main: All components started. Entering main evaluation loop.
```

---

## Repository Structure

```
detector/
  main.py          # Entry point, wires all components together
  monitor.py       # Tails and parses Nginx JSON access log
  baseline.py      # Rolling baseline tracker with per-hour slots
  detector.py      # Z-score anomaly detection logic
  blocker.py       # iptables ban/unban management
  unbanner.py      # Background thread for auto-unban backoff
  notifier.py      # Slack alert sender
  dashboard.py     # Flask live metrics web UI
  config.yaml      # All thresholds and configuration
  requirements.txt # Python dependencies
  Dockerfile       # Container definition
nginx/
  nginx.conf.template  # Template rendered at startup via envsubst
docs/
  architecture.png
screenshots/
README.md
FIXES.md
.env.example
```

---

## Architecture

```
Internet
    |
    v
Nginx (port 80)
    |--- Nextcloud (port 80, internal)     <- accessible by IP
    |--- Detector Dashboard (port 8080)    <- accessible by subdomain
    |
    | writes JSON logs to HNG-nginx-logs volume
    v
/var/log/nginx/hng-access.log
    |
    | tailed line by line
    v
monitor.py --> baseline.py (rolling 30min window)
           --> detector.py (z-score evaluation every 1s)
                   |
                   | anomaly detected
                   v
             blocker.py (iptables DROP)
             notifier.py (Slack alert)
             audit.py (structured log)
                   |
                   | after ban duration
                   v
             unbanner.py (iptables remove + Slack unban alert)
```

---

## Blog Post

Read the full write-up: [Building a Real-Time DDoS Detection Engine from Scratch — HNG DevOps Stage 3](https://dev.to/gideonbature/building-a-real-time-ddos-detection-engine-from-scratch-hng-devops-stage-3-2k5i)