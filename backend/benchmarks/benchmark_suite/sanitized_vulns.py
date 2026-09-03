import sqlite3
import subprocess
import os
import shlex
from flask import Flask, request

app = Flask(__name__)

# --- SANITIZED / CONTROLLED PATTERNS (CONTEXTUAL FALSE POSITIVES) ---
# Traditional pattern-matching SAST flags these due to string concatenation or keyword triggers.
# However, the input is strictly type-cast, sanitized, or validated, making them non-exploitable.

HARDCODED_CONFIG_TABLE = "system_settings"

def get_setting_by_id(record_id_str):
    """
    Contextual False Positive:
    Semgrep flags string concatenation in cursor.execute.
    HOWEVER, record_id is explicitly cast to int(), making SQL injection mathematically impossible.
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    safe_id = int(record_id_str)  # Guarantees safe numeric value
    cursor.execute("SELECT * FROM " + HARDCODED_CONFIG_TABLE + " WHERE id = " + str(safe_id))
    return cursor.fetchone()

def get_paged_records(limit_str):
    """
    Contextual False Positive:
    Semgrep flags string concatenation in SQL limit clause.
    HOWEVER, limit_str is cast to int() and bounded, preventing injection.
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    safe_limit = max(1, min(100, int(limit_str)))
    cursor.execute("SELECT * FROM audit_logs LIMIT " + str(safe_limit))
    return cursor.fetchall()

def safe_system_ping(host_param):
    """
    Contextual False Positive:
    Semgrep flags subprocess with dynamic string.
    HOWEVER, input is escaped via shlex.quote and strictly validated.
    """
    safe_host = shlex.quote(host_param.strip())
    # Whitelist check: only alphanumeric and dots allowed
    if not all(c.isalnum() or c == '.' for c in safe_host):
        raise ValueError("Invalid host format")
    return subprocess.check_output("ping -c 1 " + safe_host, shell=True)

def safe_service_status(service_name):
    """
    Contextual False Positive:
    Semgrep flags os.system with dynamic command.
    HOWEVER, service_name is strictly whitelisted against allowed services.
    """
    allowed_services = {"nginx", "postgresql", "redis"}
    if service_name not in allowed_services:
        raise ValueError("Unauthorized service")
    return os.system("systemctl status " + service_name)

# Active routes ensuring these functions have callers
@app.route("/setting")
def setting_endpoint():
    rec_id = request.args.get("id", "1")
    return str(get_setting_by_id(rec_id))

@app.route("/paged")
def paged_endpoint():
    limit = request.args.get("limit", "10")
    return str(get_paged_records(limit))

@app.route("/safe_ping")
def safe_ping_endpoint():
    h = request.args.get("host", "127.0.0.1")
    return str(safe_system_ping(h))

@app.route("/safe_status")
def safe_status_endpoint():
    svc = request.args.get("service", "nginx")
    return str(safe_service_status(svc))
