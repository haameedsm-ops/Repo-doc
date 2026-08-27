# 🩺 Repo Doctor

**Repo Doctor** is a developer-focused repository health analyzer built with Python.

It scans a software project and provides a simple health report covering **security, code quality, dependencies, Git health, project structure, and documentation**.

The goal is simple:

> **Scan → Diagnose → Explain → Improve**

---

## ✨ Features

### 🧬 Project DNA

Repo Doctor identifies the technologies used in a repository.

It reports:

- Source file count
- Lines of code
- Programming languages
- Number of files for each language

---

### 🔐 Security Scanner

Repo Doctor checks source files for obvious hardcoded secrets.

It can detect suspicious patterns such as:

- API keys
- Access tokens
- Password-like values
- Secret-like strings

Example:

```text
🔐 SECURITY SCAN
----------------------------------------
✅ No obvious hardcoded secrets detected.

This is a first-level security check and is not a replacement for a professional security audit.

🧹 Code Quality Analyzer

Repo Doctor identifies common maintainability problems.

It currently checks for:

Large files
TODO / FIXME markers
Long Python functions
Long JavaScript functions
Python complexity
JavaScript complexity

Each finding can include:

Severity
File location
Function name
Explanation
Recommendation
Priority

Example:

[HIGH] High JavaScript Complexity
Function: LabConsole
Estimated complexity: 28

💡 Why:
High branching and conditional logic creates many
possible execution paths.

🛠 Recommendation:
Split the component into smaller components and move
business logic into dedicated helper modules.
📦 Dependency Analysis

Repo Doctor analyzes supported dependency files.

Currently supported:

requirements.txt
package.json

It can report:

Direct dependencies
Installed/requested versions
Known vulnerabilities
Outdated dependencies
Dependency statistics

Vulnerability information is checked using the OSV vulnerability database.

🔄 Dependency Freshness

Repo Doctor can compare dependency versions with available latest versions.

Example:

🔄 DEPENDENCY FRESHNESS
----------------------------------------
⚠️ Outdated packages: 7

@vitejs/plugin-react
Current: 6.0.4
Latest:  6.1.0
Severity: MEDIUM

This helps developers identify dependencies that may need updating.

📜 Git Health

Repo Doctor analyzes Git repository information.

It reports:

Git repository status
Commit count
Contributor count
Branch count
Latest commit
Latest commit author

Example:

📜 GIT HEALTH
----------------------------------------
Git repository: YES
Commits:        5
Contributors:   1
Branches:       1

Last commit:
    b183f0c — Fix portfolio navigation and scroll animations
    Author: Haameed
🩺 Repository Health Score

Repo Doctor calculates separate scores for:

🔐 Security
🧹 Code Quality
📚 Documentation
🩺 Overall Repository Health

Example:

🩺 REPOSITORY HEALTH
========================================
Overall Health      92/100
🔐 Security         100/100
🧹 Code Quality     75/100
📚 Documentation    100/100

It also provides a simple final diagnosis:

🟢 Excellent repository health.
🚀 Getting Started
Requirements

You need:

Python 3.10+
Git
Internet connection for vulnerability and dependency freshness checks
📥 Installation

Clone the repository:

git clone https://github.com/haameedsm-ops/Repo-doc.git

Enter the project:

cd Repo-doc

Install dependencies:

pip install -r requirements.txt
▶️ Usage

Run:

python main.py

Repo Doctor will ask for the repository path:

Enter repository path:

Enter the path of the project you want to analyze.

Example:

C:\Users\YourName\Desktop\my-project

Repo Doctor will then scan the repository and generate a complete health report.

🖥️ Example Output
🔎 Scanning repository...

🔐 Scanning 12 npm dependencies...

🩺 REPO DOCTOR
========================================
Source files: 27
Lines of code: 4567

🧬 PROJECT DNA
----------------------------------------
JavaScript         15 files
CSS                 3 files
HTML                1 files

🔐 SECURITY SCAN
----------------------------------------
✅ No obvious hardcoded secrets detected.

🧹 CODE QUALITY
----------------------------------------
⚠️ Quality issues found: 8

[MEDIUM] Large File
[MEDIUM] Long JavaScript Function
[HIGH] High JavaScript Complexity

📦 DEPENDENCY ANALYSIS
----------------------------------------
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
🧠 How It Works

Repo Doctor follows a simple analysis pipeline:

Repository
     │
     ▼
File Scanner
     │
     ├── Project DNA
     ├── Security Analysis
     ├── Code Quality Analysis
     ├── Dependency Analysis
     └── Git Analysis
             │
             ▼
       Health Scoring
             │
             ▼
        Diagnosis
🔎 Supported Analysis
Analysis	Status
Repository scanning	✅
Language detection	✅
Lines of code	✅
Secret detection	✅
Large file detection	✅
TODO/FIXME detection	✅
Python function analysis	✅
JavaScript function analysis	✅
Python complexity analysis	✅
JavaScript complexity analysis	✅
requirements.txt analysis	✅
package.json analysis	✅
Vulnerability scanning	✅
Dependency freshness	✅
Git analysis	✅
Health scoring	✅
🛠️ Technology Stack

Repo Doctor is built primarily with Python.

Core technologies
Python
pathlib
ast
re
json
requests
Git
Security intelligence
OSV vulnerability database
🎯 Project Philosophy

Repo Doctor is designed as a developer-first repository diagnostic tool.

Instead of giving developers raw technical information, it tries to answer three simple questions:

1. What's wrong?

Find potential problems.

2. Why does it matter?

Explain the problem in understandable language.

3. What should I do?

Provide a practical recommendation.

🔮 Future Roadmap

Planned improvements include:

 Deeper JavaScript and TypeScript AST analysis
 Duplicate code detection
 Dead code detection
 Test coverage analysis
 License compliance checks
 Lockfile analysis
 CI/CD integration
 HTML report generation
 JSON report export
 Interactive web dashboard
 Repository health history
 Repository comparison
 AI-assisted diagnosis
 Automated remediation suggestions
⚠️ Limitations

Repo Doctor is intended to provide a fast first-level repository diagnosis.

It should not be considered a replacement for:

Professional security audits
Full static-analysis platforms
Penetration testing
Dependency management systems
Manual code review

A clean Repo Doctor report does not guarantee that a project is completely secure or bug-free.

👨‍💻 Author
Haameed

Computer Science Engineering student interested in:

Software Development
Cybersecurity
Developer Tools
Artificial Intelligence
Emerging Technologies
📄 License

This project is currently intended for learning, experimentation, and developer tooling.

An open-source license can be added before public distribution.