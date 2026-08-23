import sqlite3
import subprocess
from flask import Flask, request

app = Flask(__name__)

def execute_query(query):
    # Vulnerable: directly executing unsanitized query (SQL Injection)
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = '" + query + "'")
    return cursor.fetchall()

@app.route("/search")
def search():
    user_input = request.args.get('q')
    # Reachable vulnerability
    results = execute_query(user_input)
    return str(results)

@app.route("/ping")
def ping():
    ip = request.args.get('ip')
    # Vulnerable: OS Command Injection
    # Not called from anywhere else in the code, so reachability score will be lower
    output = subprocess.check_output("ping -c 1 " + ip, shell=True)
    return output
