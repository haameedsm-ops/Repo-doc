# 🩺 Repo Doctor

**Repo Doctor** is a Python-based repository health analyzer that scans software projects and gives developers a clear diagnosis of their codebase.

It brings together **security analysis, code quality checks, dependency analysis, dependency freshness, Git health, project structure, and repository health scoring** in one tool.

> **Scan → Diagnose → Explain → Improve**

---

## ✨ Features

### 🧬 Project DNA

Analyzes the structure and technology stack of a repository.

* Source file count
* Lines of code
* Programming language detection
* Language-wise file statistics

### 🔐 Security Scanner

Scans source files for obvious hardcoded secrets and suspicious credentials.

Checks for patterns related to:

* API keys
* Access tokens
* Passwords
* Secret-like values

Example:

```text
🔐 SECURITY SCAN
----------------------------------------
✅ No obvious hardcoded secrets detected.
```

> Repo Doctor provides a first-level security check and is not intended to replace a professional security audit.

### 🧹 Code Quality Analyzer

Identifies common maintainability problems in source code.

Currently analyzes:

* Large files
* TODO / FIXME markers
* Long Python functions
* Long JavaScript functions
* Python complexity
* JavaScript complexity

Quality findings include useful information such as:

* Severity
* File location
* Function name
* Explanation
* Recommendation
* Priority

Example:

```text
[HIGH] High JavaScript Complexity
Function: LabConsole
Estimated complexity: 28

Why:
High branching and conditional logic creates many
possible execution paths.

Recommendation:
Split the component into smaller components and move
business logic into dedicated helper modules.
```

### 📦 Dependency Analysis

Analyzes supported dependency manifests.

Currently supported:

* `requirements.txt`
* `package.json`

It can identify:

* Direct dependencies
* Dependency versions
* Known vulnerabilities
* Dependency statistics

Vulnerability information is checked using the **OSV vulnerability database**.

### 🔄 Dependency Freshness

Checks whether dependencies are behind their available latest versions.

Example:

```text
🔄 DEPENDENCY FRESHNESS
----------------------------------------
⚠️ Outdated packages: 7

@vitejs/plugin-react
Current: 6.0.4
Latest:  6.1.0
Severity: MEDIUM
```

This helps developers identify packages that may need updating.

### 📜 Git Health

Analyzes the Git history of the target repository.

Reports:

* Git repository status
* Commit count
* Contributor count
* Branch count
* Latest commit
* Latest commit author

Example:

```text
📜 GIT HEALTH
----------------------------------------
Git repository: YES
Commits:        5
Contributors:   1
Branches:       1
```

### 🩺 Repository Health Score

Repo Doctor calculates individual scores for:

* 🔐 Security
* 🧹 Code Quality
* 📚 Documentation
* 🩺 Overall Repository Health

It also provides a simple diagnosis based on the final score.

Example:

```text
🩺 REPOSITORY HEALTH
========================================
Overall Health      92/100
🔐 Security         100/100
🧹 Code Quality     75/100
📚 Documentation    100/100

🩺 DIAGNOSIS
----------------------------------------
🟢 Excellent repository health.
```

---

## 🚀 Getting Started

### Requirements

* Python 3.10+
* Git
* Internet connection for vulnerability and dependency freshness checks

### Installation

Clone the repository:

```bash
git clone https://github.com/haameedsm-ops/Repo-doc.git
```

Enter the project directory:

```bash
cd Repo-doc
```

Install the required Python packages:

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

Run Repo Doctor:

```bash
python main.py
```

The program will ask for the repository you want to analyze:

```text
Enter repository path:
```

Example:

```text
C:\Users\YourName\Desktop\my-project
```

Repo Doctor will scan the target repository and generate a health report.

---

## 🔎 Analysis Pipeline

```text
                Target Repository
                       │
                       ▼
                Repository Scanner
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   Project DNA     Security       Code Quality
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   Dependencies    Git Health    Documentation
        │
        ▼
  Vulnerability &
  Freshness Checks
        │
        ▼
   Health Scoring
        │
        ▼
     Diagnosis
```

---

## 🏗️ Project Structure

```text
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
```

---

## 📊 Supported Analysis

| Analysis                       | Status |
| ------------------------------ | ------ |
| Repository scanning            | ✅      |
| Language detection             | ✅      |
| Lines of code                  | ✅      |
| Secret detection               | ✅      |
| Large file detection           | ✅      |
| TODO/FIXME detection           | ✅      |
| Python function analysis       | ✅      |
| JavaScript function analysis   | ✅      |
| Python complexity analysis     | ✅      |
| JavaScript complexity analysis | ✅      |
| `requirements.txt` analysis    | ✅      |
| `package.json` analysis        | ✅      |
| Vulnerability scanning         | ✅      |
| Dependency freshness           | ✅      |
| Git analysis                   | ✅      |
| Health scoring                 | ✅      |

---

## 🛠️ Technology Stack

Repo Doctor is primarily built with Python.

### Core Technologies

* Python
* `pathlib`
* `ast`
* `re`
* `json`
* `requests`
* Git

### Vulnerability Intelligence

* OSV vulnerability database

---

## 🧠 Design Philosophy

Repo Doctor is designed to be a **developer-first diagnostic tool**.

Instead of simply reporting technical problems, it aims to answer three questions:

### 1. What is wrong?

Identify potential problems in the repository.

### 2. Why does it matter?

Explain the impact in simple language.

### 3. What should I do?

Provide a practical recommendation for improvement.

---

## 🎯 Project Goal

Modern software repositories can contain thousands of lines of code, numerous dependencies, security risks, and maintainability problems.

Repo Doctor aims to make the initial health check simple and actionable.

```text
Scan
  ↓
Detect
  ↓
Explain
  ↓
Score
  ↓
Improve
```

---

## 🔮 Roadmap

Planned improvements include:

* [ ] Deeper JavaScript and TypeScript AST analysis
* [ ] Duplicate code detection
* [ ] Dead code detection
* [ ] Test coverage analysis
* [ ] License compliance checks
* [ ] Lockfile analysis
* [ ] CI/CD integration
* [ ] HTML report generation
* [ ] JSON report export
* [ ] Interactive web dashboard
* [ ] Repository health history
* [ ] Repository comparison
* [ ] AI-assisted diagnosis
* [ ] Automated remediation suggestions

---

## ⚠️ Limitations

Repo Doctor is intended to provide a **fast first-level repository diagnosis**.

It is not a replacement for:

* Professional security audits
* Penetration testing
* Full static-analysis platforms
* Manual code review
* Dedicated dependency management systems

A clean Repo Doctor report does not guarantee that a repository is completely secure or bug-free.

---

## 👨‍💻 Author

**Haameed**

Computer Science Engineering Student

Interested in:

* Software Development
* Cybersecurity
* Developer Tools
* Artificial Intelligence
* Emerging Technologies

---

## 📄 License

This project is currently intended for learning, experimentation, and developer tooling.

An appropriate open-source license can be added before public distribution.
