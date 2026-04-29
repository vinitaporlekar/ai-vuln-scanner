# FILE: backend/app/cve_data.py
# A collection of real-world vulnerability patterns.
# Each entry describes a known type of security flaw.
# ChromaDB will store these as embeddings so we can
# search them by MEANING, not just keywords.

CVE_DATABASE = [
    {
        "id": "CVE-2019-1010083",
        "title": "Python eval() Code Injection",
        "description": "Use of eval() with untrusted input allows "
                      "remote attackers to execute arbitrary Python code. "
                      "The eval function interprets a string as code, "
                      "meaning any user-supplied input passed to eval "
                      "can run system commands, read files, or delete data.",
        "severity": "CRITICAL",
        "fix": "Replace eval() with ast.literal_eval() for safe parsing "
              "of Python literals. For JSON data, use json.loads(). "
              "Never pass user input to eval().",
        "category": "code_injection"
    },
    {
        "id": "CVE-2021-44228",
        "title": "Remote Code Execution via exec()",
        "description": "The exec() function executes dynamically generated "
                      "Python code. When combined with user input, attackers "
                      "can inject malicious code that runs with full "
                      "application privileges. Similar to eval but can "
                      "execute multiple statements.",
        "severity": "CRITICAL",
        "fix": "Remove exec() calls entirely. Use structured alternatives "
              "like dictionaries for dynamic dispatch, or importlib for "
              "dynamic module loading.",
        "category": "code_injection"
    },
    {
        "id": "CVE-2020-13091",
        "title": "SQL Injection via String Concatenation",
        "description": "Building SQL queries by concatenating user input "
                      "directly into query strings allows SQL injection. "
                      "Attackers can modify queries to bypass authentication, "
                      "extract sensitive data, or delete entire databases. "
                      "This affects any code using string formatting or "
                      "concatenation with SQL statements.",
        "severity": "CRITICAL",
        "fix": "Use parameterized queries with placeholders: "
              "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)). "
              "Use an ORM like SQLAlchemy for automatic protection.",
        "category": "sql_injection"
    },
    {
        "id": "CVE-2022-21449",
        "title": "Hardcoded Credentials in Source Code",
        "description": "Storing passwords, API keys, tokens, or secrets "
                      "directly in source code exposes them to anyone with "
                      "repository access. If code is pushed to a public "
                      "repository, credentials are immediately compromised. "
                      "Automated bots scan GitHub for exposed secrets.",
        "severity": "CRITICAL",
        "fix": "Store secrets in environment variables using os.environ.get(). "
              "Use a .env file with python-dotenv for local development. "
              "Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) "
              "in production.",
        "category": "hardcoded_secrets"
    },
    {
        "id": "CVE-2020-1747",
        "title": "Arbitrary Code Execution via pickle",
        "description": "Python's pickle module can execute arbitrary code "
                      "during deserialization. Loading a pickle file from "
                      "an untrusted source allows attackers to run any "
                      "Python code. The unpickling process can be exploited "
                      "to import modules and execute system commands.",
        "severity": "HIGH",
        "fix": "Use json for data serialization instead of pickle. "
              "If pickle is required, only load from trusted sources "
              "and implement signature verification.",
        "category": "deserialization"
    },
    {
        "id": "CVE-2019-14322",
        "title": "OS Command Injection via os.system()",
        "description": "Using os.system() to run shell commands with "
                      "user-supplied input allows command injection. "
                      "Attackers can chain commands using semicolons or "
                      "pipe operators to execute arbitrary system commands "
                      "with the application's permissions.",
        "severity": "HIGH",
        "fix": "Use subprocess.run() with a list of arguments instead of "
              "a shell string. Set shell=False (the default). Validate "
              "and sanitize all inputs before passing to any system call.",
        "category": "command_injection"
    },
    {
        "id": "CVE-2021-3177",
        "title": "Subprocess Shell Injection",
        "description": "Using subprocess with shell=True and user input "
                      "allows shell injection attacks. The shell interprets "
                      "special characters, letting attackers inject additional "
                      "commands. Even subprocess.run can be dangerous when "
                      "shell=True is set.",
        "severity": "HIGH",
        "fix": "Always use subprocess.run() with a list of arguments "
              "and shell=False. Example: subprocess.run(['ls', '-la']) "
              "instead of subprocess.run('ls -la', shell=True).",
        "category": "command_injection"
    },
    {
        "id": "CVE-2023-36053",
        "title": "Cross-Site Scripting via Template Injection",
        "description": "Inserting user input directly into HTML templates "
                      "without escaping allows cross-site scripting (XSS). "
                      "Attackers can inject JavaScript that steals cookies, "
                      "redirects users, or modifies page content. Affects "
                      "any web application rendering user content.",
        "severity": "HIGH",
        "fix": "Always escape user input before rendering in HTML. "
              "Use template engines with auto-escaping enabled. "
              "Implement Content Security Policy (CSP) headers.",
        "category": "xss"
    },
    {
        "id": "CVE-2022-42969",
        "title": "Insecure Deserialization via marshal",
        "description": "Python's marshal module can execute code during "
                      "deserialization, similar to pickle. Loading marshal "
                      "data from untrusted sources leads to arbitrary code "
                      "execution. Marshal is intended for internal use only.",
        "severity": "MEDIUM",
        "fix": "Use json or msgpack for data serialization. "
              "Never use marshal with untrusted data. "
              "Marshal is meant for Python internal use only.",
        "category": "deserialization"
    },
    {
        "id": "CVE-2020-28493",
        "title": "Debug Information Exposure",
        "description": "Leaving print statements, debug logs, or verbose "
                      "error messages in production code exposes internal "
                      "application details. Attackers use this information "
                      "to understand application structure and find attack "
                      "vectors. Stack traces reveal file paths and logic.",
        "severity": "LOW",
        "fix": "Remove all print() statements before deployment. "
              "Use a proper logging framework with configurable levels. "
              "Set DEBUG=False in production environments.",
        "category": "info_exposure"
    },
]