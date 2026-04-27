"""
dashboard.py - Live metrics web dashboard served via Flask.
Refreshes every 3 seconds. Shows banned IPs, global req/s, top 10 IPs,
CPU/memory, effective mean/stddev, and uptime.
"""

import time
import logging
import threading
import psutil
from flask import Flask, jsonify, render_template_string
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

START_TIME = time.time()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="refresh" content="3">
  <title>HNG Anomaly Detector Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Courier New', monospace;
      background: #0d1117;
      color: #c9d1d9;
      padding: 20px;
    }
    h1 { color: #58a6ff; margin-bottom: 6px; font-size: 22px; }
    .subtitle { color: #8b949e; font-size: 13px; margin-bottom: 20px; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 16px;
      margin-bottom: 20px;
    }
    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 16px;
    }
    .card h2 {
      font-size: 13px;
      color: #8b949e;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 10px;
    }
    .metric {
      font-size: 28px;
      font-weight: bold;
      color: #58a6ff;
    }
    .metric.warn { color: #f85149; }
    .metric.ok { color: #3fb950; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th {
      text-align: left;
      color: #8b949e;
      padding: 4px 8px;
      border-bottom: 1px solid #30363d;
    }
    td {
      padding: 6px 8px;
      border-bottom: 1px solid #21262d;
    }
    .banned { color: #f85149; }
    .ts { color: #8b949e; font-size: 12px; text-align: right; margin-top: 16px; }
  </style>
</head>
<body>
  <h1>HNG Anomaly Detection Engine</h1>
  <div class="subtitle">Auto-refreshes every 3 seconds &bull; {{ uptime }}</div>

  <div class="grid">
    <div class="card">
      <h2>Global Traffic</h2>
      <div class="metric {{ 'warn' if global_rps > baseline_mean * 3 else 'ok' }}">
        {{ "%.2f"|format(global_rps) }} req/s
      </div>
    </div>
    <div class="card">
      <h2>Baseline</h2>
      <div style="font-size:14px; line-height:1.8;">
        Mean: <strong>{{ "%.3f"|format(baseline_mean) }}</strong> req/s<br>
        Stddev: <strong>{{ "%.3f"|format(baseline_stddev) }}</strong><br>
        Error mean: <strong>{{ "%.3f"|format(error_mean) }}</strong>
      </div>
    </div>
    <div class="card">
      <h2>System</h2>
      <div style="font-size:14px; line-height:1.8;">
        CPU: <strong>{{ cpu_pct }}%</strong><br>
        Memory: <strong>{{ mem_pct }}%</strong> ({{ mem_used }} / {{ mem_total }})<br>
        Banned IPs: <strong class="{{ 'warn' if banned_count > 0 else 'ok' }}">
          {{ banned_count }}
        </strong>
      </div>
    </div>
  </div>

  <div class="card" style="margin-bottom:16px;">
    <h2>Currently Banned IPs</h2>
    {% if banned_ips %}
    <table>
      <tr><th>IP</th><th>Banned At</th><th>Duration</th><th>Unban At</th><th>Offenses</th><th>Condition</th></tr>
      {% for b in banned_ips %}
      <tr>
        <td class="banned">{{ b.ip }}</td>
        <td>{{ b.banned_at }}</td>
        <td>{{ b.duration }}</td>
        <td>{{ b.unban_at }}</td>
        <td>{{ b.offense_count }}</td>
        <td style="font-size:11px;">{{ b.condition[:60] }}</td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
    <div style="color:#3fb950; padding: 8px 0;">No IPs currently banned.</div>
    {% endif %}
  </div>

  <div class="card">
    <h2>Top 10 Source IPs (last 60s)</h2>
    {% if top_ips %}
    <table>
      <tr><th>IP</th><th>Requests</th></tr>
      {% for ip, count in top_ips %}
      <tr>
        <td>{{ ip }}</td>
        <td>{{ count }}</td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
    <div style="color:#8b949e; padding: 8px 0;">No traffic recorded yet.</div>
    {% endif %}
  </div>

  <div class="ts">Last updated: {{ now_ts }}</div>
</body>
</html>
"""


class Dashboard:
    def __init__(self, config: dict, baseline, detector, blocker):
        self._config = config
        self._baseline = baseline
        self._detector = detector
        self._blocker = blocker
        self._host = config["dashboard"]["host"]
        self._port = config["dashboard"]["port"]
        self._app = Flask(__name__)
        self._setup_routes()

    def _uptime_str(self) -> str:
        secs = int(time.time() - START_TIME)
        h, rem = divmod(secs, 3600)
        m, s = divmod(rem, 60)
        return f"Uptime: {h}h {m}m {s}s"

    def _setup_routes(self):
        app = self._app

        @app.route("/")
        def index():
            mean, stddev = self._baseline.get_global_stats()
            err_mean, _ = self._baseline.get_error_stats()
            global_rps = self._detector.get_global_rate()
            top_ips = self._baseline.get_top_ips(10)

            banned_raw = self._blocker.get_banned()
            banned_ips = []
            for ip, rec in banned_raw.items():
                banned_ips.append({
                    "ip": ip,
                    "banned_at": datetime.fromtimestamp(
                        rec.banned_at, tz=timezone.utc
                    ).strftime("%H:%M:%S UTC"),
                    "duration": "permanent" if rec.duration == -1
                                else f"{rec.duration}s",
                    "unban_at": "never" if rec.duration == -1
                                else datetime.fromtimestamp(
                                    rec.unban_at, tz=timezone.utc
                                ).strftime("%H:%M:%S UTC"),
                    "offense_count": rec.offense_count,
                    "condition": rec.condition,
                })

            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            mem_used = f"{mem.used // 1024 // 1024}MB"
            mem_total = f"{mem.total // 1024 // 1024}MB"

            return render_template_string(
                HTML_TEMPLATE,
                global_rps=global_rps,
                baseline_mean=mean,
                baseline_stddev=stddev,
                error_mean=err_mean,
                banned_ips=banned_ips,
                banned_count=len(banned_ips),
                top_ips=top_ips,
                cpu_pct=f"{cpu:.1f}",
                mem_pct=f"{mem.percent:.1f}",
                mem_used=mem_used,
                mem_total=mem_total,
                uptime=self._uptime_str(),
                now_ts=datetime.now(timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                ),
            )

        @app.route("/api/metrics")
        def metrics():
            mean, stddev = self._baseline.get_global_stats()
            err_mean, _ = self._baseline.get_error_stats()
            banned = self._blocker.get_banned()
            mem = psutil.virtual_memory()
            return jsonify({
                "global_rps": self._detector.get_global_rate(),
                "baseline_mean": mean,
                "baseline_stddev": stddev,
                "error_mean": err_mean,
                "banned_count": len(banned),
                "banned_ips": list(banned.keys()),
                "top_ips": self._baseline.get_top_ips(10),
                "cpu_pct": psutil.cpu_percent(interval=None),
                "mem_pct": mem.percent,
                "uptime_seconds": int(time.time() - START_TIME),
            })

    def run(self):
        logger.info(f"Dashboard starting on {self._host}:{self._port}")
        self._app.run(
            host=self._host,
            port=self._port,
            debug=False,
            use_reloader=False,
        )

    def start_background(self):
        t = threading.Thread(
            target=self.run, daemon=True, name="dashboard"
        )
        t.start()
