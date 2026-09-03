import sqlite3
import subprocess
import os
from flask import Flask, request

app = Flask(__name__)

# --- ACTIVE & REACHABLE VULNERABILITIES (TRUE POSITIVES) ---
# All functions below are actively invoked from exposed Flask routes with raw user input.

def execute_user_query(user_input):
    """Reachable SQL Injection: Called directly by /search route."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = '" + user_input + "'")
    return cursor.fetchall()

def execute_user_lookup(account_name):
    """Reachable SQL Injection (% format): Called directly by /lookup route."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM accounts WHERE name = '%s'" % account_name)
    return cursor.fetchall()

def run_diagnostic_ping(host):
    """Reachable Command Injection: Called directly by /diagnostics route."""
    cmd = "ping -c 1 " + host
    return subprocess.check_output(cmd, shell=True)

def run_system_maintenance(service_name):
    """Reachable Command Injection: Called directly by /restart route."""
    return os.system("systemctl restart " + service_name)

def dynamic_calculate(expression):
    """Reachable Code Injection: Called directly by /eval route."""
    return eval(expression)

# --- ENTRYPOINTS ENSURING HIGH REACHABILITY IN AST ---

@app.route("/search")
def search_route():
    q = request.args.get("q", "")
    return str(execute_user_query(q))

@app.route("/lookup")
def lookup_route():
    name = request.args.get("name", "")
    return str(execute_user_lookup(name))

@app.route("/diagnostics")
def ping_route():
    ip = request.args.get("ip", "")
    return str(run_diagnostic_ping(ip))

@app.route("/restart")
def restart_route():
    svc = request.args.get("service", "")
    return str(run_system_maintenance(svc))

@app.route("/eval")
def eval_route():
    expr = request.args.get("expr", "")
    return str(dynamic_calculate(expr))
