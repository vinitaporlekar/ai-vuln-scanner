# FILE: backend/app/scanner.py
# This file contains the rules that detect vulnerabilities.
# Think of it as a "rulebook" — each rule looks for one type of danger.

import re
# 're' = Regular Expressions. A way to search for PATTERNS in text.
# Instead of searching for exact words, you can search for patterns like
# "any line that contains password = followed by quotes"


def scan_code(code: str, filename: str) -> dict:
    """
    Takes in code as text, checks every line against our rules,
    and returns a report of everything it found.
    
    Parameters:
        code: the actual source code as a string
        filename: name of the file (used in the report)
    
    Returns:
        A dictionary with the scan results
    """
    
    vulnerabilities = []  # We'll collect all findings here
    lines = code.split("\n")  # Split code into individual lines
    
    # Go through every line, one by one
    for line_num, line in enumerate(lines, start=1):
        # enumerate gives us both the line number AND the line text
        # start=1 means line numbers begin at 1, not 0
        
        stripped = line.strip()  # Remove spaces from both ends
        
        # Skip empty lines and comments — nothing dangerous there
        if not stripped or stripped.startswith("#"):
            continue  # 'continue' = skip to the next line
        
        # ===== RULE 1: Hardcoded Secrets =====
        # Catches: password = "admin123", api_key = "sk-abc..."
        # Why dangerous: anyone who reads your code sees your passwords
        secret_patterns = [
            r'(?:password|passwd|pwd)\s*=\s*["\']',
            r'(?:api_key|apikey|api_secret)\s*=\s*["\']',
            r'(?:secret_key|secret)\s*=\s*["\']',
            r'(?:token|auth_token|access_token)\s*=\s*["\']',
        ]
        # What those patterns mean:
        # (?:password|passwd) = match "password" OR "passwd"
        # \s* = any amount of spaces
        # = = a literal equals sign
        # ["\'] = followed by a quote mark
        
        for pattern in secret_patterns:
            if re.search(pattern, stripped, re.IGNORECASE):
                vulnerabilities.append({
                    "rule": "Hardcoded Secret",
                    "severity": "CRITICAL",
                    "line": line_num,
                    "code": stripped,
                    "message": "Never put passwords or API keys directly in code. "
                              "Use environment variables instead.",
                    "fix": "Use: os.environ.get('PASSWORD') or a .env file"
                })
                break  # One match per line is enough
        
        # ===== RULE 2: SQL Injection =====
        # Catches: query = "SELECT * FROM users WHERE id=" + user_id
        # Why dangerous: hackers can inject their own SQL commands
        sql_patterns = [
            r'(?:execute|cursor\.execute)\s*\(\s*["\'].*\+',
            r'(?:SELECT|INSERT|UPDATE|DELETE).*\+\s*\w',
            r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE)',
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, stripped, re.IGNORECASE):
                vulnerabilities.append({
                    "rule": "SQL Injection Risk",
                    "severity": "CRITICAL",
                    "line": line_num,
                    "code": stripped,
                    "message": "Building SQL queries with string concatenation "
                              "allows hackers to inject malicious SQL.",
                    "fix": "Use parameterized queries: cursor.execute('SELECT * "
                          "FROM users WHERE id = %s', (user_id,))"
                })
                break
        
        # ===== RULE 3: Dangerous Functions =====
        # Catches: eval(user_input), exec(), os.system()
        # Why dangerous: these run arbitrary code — a hacker's dream
        dangerous_funcs = {
            r'\beval\s*\(': {
                "name": "eval()",
                "message": "eval() executes any string as code. If a user "
                          "controls the input, they can run anything.",
                "fix": "Use ast.literal_eval() for safe parsing, or "
                      "avoid eval entirely."
            },
            r'\bexec\s*\(': {
                "name": "exec()",
                "message": "exec() runs arbitrary Python code. Extremely "
                          "dangerous with any external input.",
                "fix": "Find an alternative approach that doesn't require "
                      "executing dynamic code."
            },
            r'os\.system\s*\(': {
                "name": "os.system()",
                "message": "os.system() runs shell commands. Vulnerable to "
                          "command injection attacks.",
                "fix": "Use subprocess.run() with a list of arguments instead."
            },
        }
        
        for pattern, info in dangerous_funcs.items():
            if re.search(pattern, stripped):
                vulnerabilities.append({
                    "rule": f"Dangerous Function: {info['name']}",
                    "severity": "HIGH",
                    "line": line_num,
                    "code": stripped,
                    "message": info["message"],
                    "fix": info["fix"]
                })
        
        # ===== RULE 4: Insecure Imports =====
        # Catches: import pickle, import subprocess
        # Why dangerous: these modules have known security risks
        insecure_imports = {
            "pickle": "pickle can execute arbitrary code when loading data. "
                     "Use json instead.",
            "subprocess": "subprocess runs system commands. Ensure inputs "
                         "are sanitized.",
            "marshal": "marshal can execute code during deserialization.",
        }
        
        if stripped.startswith("import ") or "from " in stripped:
            for module, warning in insecure_imports.items():
                if module in stripped:
                    vulnerabilities.append({
                        "rule": f"Insecure Import: {module}",
                        "severity": "MEDIUM",
                        "line": line_num,
                        "code": stripped,
                        "message": warning,
                        "fix": f"Consider if {module} is truly needed. "
                              f"Look for safer alternatives."
                    })
        
        # ===== RULE 5: Debug Leftovers =====
        # Catches: print(), TODO, FIXME, HACK
        # Why dangerous: not a hack risk, but shows unfinished/sloppy code
        debug_patterns = [
            (r'\bprint\s*\(', "print() statement found — remove before production."),
            (r'#\s*TODO', "TODO comment — unfinished work."),
            (r'#\s*FIXME', "FIXME comment — known bug not fixed."),
            (r'#\s*HACK', "HACK comment — fragile workaround."),
        ]
        
        for pattern, msg in debug_patterns:
            if re.search(pattern, stripped, re.IGNORECASE):
                vulnerabilities.append({
                    "rule": "Debug/TODO Leftover",
                    "severity": "LOW",
                    "line": line_num,
                    "code": stripped,
                    "message": msg,
                    "fix": "Clean up before deploying to production."
                })
    
    # ===== BUILD THE FINAL REPORT =====
    # Count vulnerabilities by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulnerabilities:
        severity_counts[v["severity"]] += 1
    
    # Calculate a risk score (0-100)
    # Critical = 25 points each, High = 15, Medium = 5, Low = 1
    risk_score = min(100, 
        severity_counts["CRITICAL"] * 25 +
        severity_counts["HIGH"] * 15 +
        severity_counts["MEDIUM"] * 5 +
        severity_counts["LOW"] * 1
    )
    
    return {
        "filename": filename,
        "total_lines": len(lines),
        "vulnerabilities_found": len(vulnerabilities),
        "risk_score": risk_score,
        "severity_counts": severity_counts,
        "vulnerabilities": vulnerabilities
    }