import sqlite3
import subprocess
import os

# --- UNREACHABLE / DEAD CODE VULNERABILITIES (FALSE POSITIVES BY UNREACHABILITY) ---
# None of these functions are ever imported, called, or referenced anywhere in the repository.
# Traditional pattern-matching SAST (Semgrep) flags all of them indiscriminately.
# Tree-sitter reachability analysis detects 0 callers, downgrading risk score to 35 (< 40 threshold).

def obsolete_legacy_query_v1(input_data):
    """Dead Code: Uncalled legacy database helper with raw SQL format."""
    conn = sqlite3.connect("archive.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM legacy_logs WHERE details = '" + input_data + "'")
    return cursor.fetchall()

def obsolete_legacy_query_v2(table_filter):
    """Dead Code: Deprecated query function with string format."""
    conn = sqlite3.connect("archive.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_trail WHERE tag = '%s'" % table_filter)
    return cursor.fetchall()

def abandoned_backup_utility(db_path):
    """Dead Code: Unused maintenance function with command injection pattern."""
    command = "tar -czf backup.tar.gz " + db_path
    return subprocess.check_output(command, shell=True)

def dead_popen_runner(debug_command):
    """Dead Code: Orphaned subprocess popen with shell=True."""
    return subprocess.Popen("bash " + debug_command, shell=True)

def discontinued_system_sync(server_node):
    """Dead Code: Unused maintenance task with os.system."""
    return os.system("rsync -avz /data/ " + server_node)

def unreferenced_math_evaluator(raw_formula):
    """Dead Code: Discontinued experimental formula parser."""
    return eval(raw_formula)

def dead_admin_archive_dump(table_name):
    """Dead Code: Uncalled reporting dump function."""
    conn = sqlite3.connect("archive.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM '" + table_name + "'")
    return cursor.fetchall()

def orphaned_diagnostic_check(interface_name):
    """Dead Code: Abandoned network health check."""
    return subprocess.run("ifconfig " + interface_name, shell=True)
