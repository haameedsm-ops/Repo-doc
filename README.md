# 🩺 Repo Doctor

> **A developer-focused repository health scanner that diagnoses code quality, security, dependencies, Git health, and project structure.**

Repo Doctor is a Python-based developer tool designed to inspect a software repository and provide a quick, practical health report.

Instead of manually checking files, dependencies, security issues, and Git history, Repo Doctor brings the important signals together into one terminal-based diagnosis.

---

## ✨ What Repo Doctor Checks

### 🧬 Project DNA
Analyzes the repository structure and identifies the programming languages being used.

- Source file count
- Lines of code
- Programming language distribution

### 🔐 Security Scan
Looks for obvious security risks such as hardcoded secrets.

- API keys
- Tokens
- Password-like values
- Other suspicious secret patterns

### 🧹 Code Quality
Detects maintainability problems that can make a project harder to work with.

Currently checks for:

- Large files
- TODO / FIXME markers
- Long Python functions
- Long JavaScript functions
- Python complexity
- JavaScript complexity

Each finding includes:

- Severity
- File location
- Function name when applicable
- Explanation
- Recommendation
- Priority

### 📦 Dependency Analysis
Analyzes supported dependency manifests.

Currently supported:

- `requirements.txt`
- `package.json`

Repo Doctor can:

- Detect direct dependencies
- Identify package versions
- Check known vulnerabilities
- Check dependency freshness
- Report outdated packages

Vulnerability intelligence is powered by the **OSV vulnerability database**.

### 📜 Git Health
Analyzes the repository's Git history.

Reports:

- Whether the repository is a Git repository
- Number of commits
- Number of contributors
- Number of branches
- Latest commit
- Latest commit author

### 🩺 Repository Health Score

Repo Doctor generates separate health scores for:

- 🔐 Security
- 🧹 Code Quality
- 📚 Documentation
- 🩺 Overall Repository Health

The final diagnosis provides a simple interpretation of the score.

---

## 🖥️ Example

```text
🩺 REPO DOCTOR
========================================
Source files: 27
Lines of code: 4567

🧬 PROJECT DNA
----------------------------------------
JavaScript         15 files
CSS                3 files
HTML               1 files

🔐 SECURITY SCAN
----------------------------------------
✅ No obvious hardcoded secrets detected.

🧹 CODE QUALITY
----------------------------------------
⚠️ Quality issues found: 8

[MEDIUM] Large File → src/App.css
    3310 lines

[HIGH] High JavaScript Complexity → src/components/LabConsole.jsx
    Estimated complexity: 28

📦 DEPENDENCY ANALYSIS
----------------------------------------
📄 package.json
Direct dependencies: 12
    ✅ No known vulnerabilities found

📊 Dependency Summary
----------------------------------------
Dependencies analyzed: 12
Vulnerable packages: 0
Total vulnerabilities: 0

📜 GIT HEALTH
----------------------------------------
Git repository: YES
Commits:        5
Contributors:   1
Branches:       1

🩺 REPOSITORY HEALTH
========================================
Overall Health      92/100
🔐 Security         100/100
🧹 Code Quality     75/100
📚 Documentation    100/100

🩺 DIAGNOSIS
----------------------------------------
🟢 Excellent repository health.

🏗️ Project Structure

Repo-doc/
│
├── main.py
│
├── scanner/
│   ├── __init__.py
│   ├── dependencies.py
│   ├── files.py
│   ├── git_analysis.py
│   ├── health.py
│   ├── quality.py
│   ├── security.py
│   └── vulnerabilities.py
│
├── README.md
└── requirements.txt
⚙️ Requirements
Python 3.10+
Git
Internet connection for vulnerability and dependency freshness checks

Install Python dependencies:

pip install -r requirements.txt
🚀 Usage

Run Repo Doctor:

python main.py

Enter the path of the repository you want to analyze:

Enter repository path: C:\Users\YourName\Desktop\my-project

Repo Doctor will scan the repository and generate the health report.

🔎 Supported Analysis
Category	Supported
Repository scanning	✅
Language detection	✅
Lines of code	✅
Secret detection	✅
Large file detection	✅
TODO/FIXME detection	✅
Python function analysis	✅
JavaScript function analysis	✅
Python complexity	✅
JavaScript complexity	✅
requirements.txt	✅
package.json	✅
Vulnerability scanning	✅
Dependency freshness	✅
Git analysis	✅
Health scoring	✅
🛡️ Design Philosophy

Repo Doctor is intended to be a developer assistant, not a replacement for professional security auditing or static-analysis platforms.

The goal is to provide developers with:

A fast first diagnosis of their repository before deeper review.

It focuses on practical findings that developers can understand and act on immediately.

🧠 Technology Stack
Python
pathlib
ast
re
json
requests
Git
OSV vulnerability database
🔮 Future Roadmap

Planned improvements include:

 Deeper JavaScript/TypeScript AST analysis
 Safer automatic refactoring suggestions
 Duplicate code detection
 Dead code detection
 Test coverage analysis
 License compliance checks
 Lockfile analysis
 CI/CD integration
 HTML report generation
 JSON report export
 Interactive web dashboard
 Repository comparison over time
 AI-assisted diagnosis and remediation
🎯 Why This Project?

Modern repositories can contain thousands of lines of code, dozens of dependencies, security risks, and maintainability problems.

Repo Doctor aims to make the first health check simple:

Scan → Diagnose → Explain → Improve
👨‍💻 Author

Haameed

Computer Science Engineering Student
Interested in software development, cybersecurity, developer tools, and emerging technologies.

📄 License

This project is intended for learning, experimentation, and developer tooling.

Add an appropriate open-source license before distributing the project publicly.