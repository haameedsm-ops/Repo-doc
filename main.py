from time import perf_counter
from pathlib import Path

from scanner.vulnerabilities import (
    check_vulnerabilities_batch
)

from scanner.git_analysis import (
    analyze_git_repository
)

from scanner.dependencies import (
    find_dependency_files,
    parse_requirements,
    parse_package_json
)

from scanner.health import (
    calculate_security_score,
    calculate_quality_score,
    calculate_documentation_score,
    calculate_overall_score,
    generate_diagnosis,
    print_diagnosis,
    print_quality_breakdown
)

from scanner.quality import (
    analyze_quality
)

from scanner.files import (
    scan_files,
    detect_languages,
    count_lines
)

from scanner.security import (
    scan_for_secrets
)

from scanner.config import (
    load_config
)


# ============================================================
# TIMING HELPER
# ============================================================

def run_stage(name, function, *args):
    """
    Run a scanner stage and report execution time.
    """

    start = perf_counter()

    result = function(*args)

    elapsed = perf_counter() - start

    print(
        f"   ⏱ {name}: {elapsed:.2f}s"
    )

    return result


# ============================================================
# REPOSITORY INPUT
# ============================================================

repo_path = input(
    "Enter repository path: "
).strip()

if not repo_path:

    print(
        "❌ Repository path cannot be empty."
    )

    exit()


repo = Path(repo_path)

if not repo.exists():

    print(
        "❌ Repository path does not exist."
    )

    exit()


if not repo.is_dir():

    print(
        "❌ Repository path must be a directory."
    )

    exit()


config = load_config(
    repo_path
)

print(
    "\n🔎 Scanning repository...\n"
)

total_start = perf_counter()


# ============================================================
# GIT ANALYSIS
# ============================================================

print(
    "🔧 Analyzing Git..."
)

git_info = run_stage(
    "Git analysis",
    analyze_git_repository,
    repo_path
)


# ============================================================
# BASIC REPOSITORY SCAN
# ============================================================

print(
    "\n📁 Scanning source files..."
)

files = run_stage(
    "File scanning",
    scan_files,
    repo_path
)

languages = run_stage(
    "Language detection",
    detect_languages,
    files
)

lines = run_stage(
    "Line counting",
    count_lines,
    files
)


# ============================================================
# SECURITY SCAN
# ============================================================

print(
    "\n🔐 Running security scan..."
)

security_findings = run_stage(
    "Secret scanning",
    scan_for_secrets,
    files
)


# ============================================================
# CODE QUALITY SCAN
# ============================================================

print(
    "\n🧹 Running code quality scan..."
)

quality_findings = run_stage(
    "Quality analysis",
    analyze_quality,
    files,
    config
)


# ============================================================
# DEPENDENCY SCAN
# ============================================================

print(
    "\n📦 Discovering dependencies..."
)

dependency_files = run_stage(
    "Dependency discovery",
    find_dependency_files,
    repo_path
)

dependency_findings = []

dependency_results = []

dependency_groups = {
    "PyPI": [],
    "npm": []
}


# ============================================================
# COLLECT DIRECT DEPENDENCIES
# ============================================================

for file in dependency_files:

    filename = file.name.lower()

    # --------------------------------------------------------
    # PYTHON
    # --------------------------------------------------------

    if filename == "requirements.txt":

        dependencies = parse_requirements(
            file
        )

        for dependency in dependencies:

            # IMPORTANT:
            # Store complete manifest path
            # instead of only "requirements.txt"

            dependency["_file"] = str(
                file.resolve()
            )

            dependency_groups[
                "PyPI"
            ].append(
                dependency
            )

    # --------------------------------------------------------
    # NODE.JS
    # --------------------------------------------------------

    elif filename == "package.json":

        dependencies = parse_package_json(
            file
        )

        for dependency in dependencies:

            # IMPORTANT:
            # Store complete manifest path
            # instead of only "package.json"

            dependency["_file"] = str(
                file.resolve()
            )

            dependency_groups[
                "npm"
            ].append(
                dependency
            )


# ============================================================
# REMOVE DUPLICATE DEPENDENCIES
# ============================================================

for ecosystem in dependency_groups:

    unique_dependencies = []

    seen_dependencies = set()

    for dependency in dependency_groups[
        ecosystem
    ]:

        key = (
            dependency.get("name"),
            dependency.get("version")
        )

        if key in seen_dependencies:
            continue

        seen_dependencies.add(
            key
        )

        unique_dependencies.append(
            dependency
        )

    dependency_groups[
        ecosystem
    ] = unique_dependencies


# ============================================================
# VULNERABILITY SCAN
# ============================================================

python_vulnerabilities = {}

npm_vulnerabilities = {}


# ------------------------------------------------------------
# PYTHON VULNERABILITIES
# ------------------------------------------------------------

if dependency_groups["PyPI"]:

    print(
        f"\n🔐 Scanning "
        f"{len(dependency_groups['PyPI'])} "
        f"Python dependencies..."
    )

    python_vulnerabilities = run_stage(
        "Python vulnerability scan",
        check_vulnerabilities_batch,
        dependency_groups["PyPI"],
        "PyPI"
    )


# ------------------------------------------------------------
# NPM VULNERABILITIES
# ------------------------------------------------------------

if dependency_groups["npm"]:

    print(
        f"\n🔐 Scanning "
        f"{len(dependency_groups['npm'])} "
        f"npm dependencies..."
    )

    npm_vulnerabilities = run_stage(
        "npm vulnerability scan",
        check_vulnerabilities_batch,
        dependency_groups["npm"],
        "npm"
    )


# ============================================================
# BUILD DEPENDENCY RESULTS
# ============================================================

for ecosystem, dependencies in dependency_groups.items():

    if ecosystem == "PyPI":

        vulnerability_map = (
            python_vulnerabilities
        )

    else:

        vulnerability_map = (
            npm_vulnerabilities
        )

    for dependency in dependencies:

        name = dependency[
            "name"
        ]

        version = dependency[
            "version"
        ]

        vulnerabilities = (
            vulnerability_map.get(
                (name, version),
                []
            )
        )

        dependency_results.append({

            "file": dependency["_file"],

            "name": name,

            "version": version,

            "ecosystem": ecosystem,

            "vulnerabilities": vulnerabilities

        })

        # ----------------------------------------------------
        # Vulnerability finding
        # ----------------------------------------------------

        if vulnerabilities:

            dependency_findings.append({

                "type":
                    "Vulnerable Dependency",

                "package":
                    name,

                "version":
                    version,

                "count":
                    len(vulnerabilities),

                "severity":
                    "HIGH",

                "confidence":
                    100

            })


# ============================================================
# COMBINE SECURITY FINDINGS
# ============================================================

all_security_findings = (
    security_findings
    +
    dependency_findings
)


# ============================================================
# HEALTH CALCULATION
# ============================================================

security_score = calculate_security_score(
    all_security_findings
)

quality_result = calculate_quality_score(
    quality_findings
)

quality_score = quality_result["score"]
quality_breakdown = quality_result["breakdown"]

documentation_score = calculate_documentation_score(
    files
)

overall_score = calculate_overall_score(
    security_score,
    quality_score,
    documentation_score
)


# ============================================================
# REPO DOCTOR HEADER
# ============================================================

print("\n")

print(
    "🩺 REPO DOCTOR"
)

print(
    "=" * 40
)

print(
    f"Source files: {len(files)}"
)

print(
    f"Lines of code: {lines}"
)

# ============================================================
# REPO DOCTOR CONFIGURATION
# ============================================================

print(
    "\n⚙️ REPO DOCTOR CONFIG"
)

print(
    "-" * 40
)

config_file = repo / ".repo-doctor.json"

if config_file.exists():
    print(
        "Configuration: .repo-doctor.json"
    )
else:
    print(
        "Configuration: Default thresholds"
    )

thresholds = config.get(
    "thresholds",
    {}
)

print(
    f"Python threshold:     "
    f"{thresholds.get('python', 500)}"
)

print(
    f"JavaScript threshold: "
    f"{thresholds.get('javascript', 800)}"
)

print(
    f"CSS threshold:        "
    f"{thresholds.get('css', 1200)}"
)

print(
    f"HTML threshold:       "
    f"{thresholds.get('html', 1000)}"
)

# ============================================================
# PROJECT DNA
# ============================================================

print(
    "\n🧬 PROJECT DNA"
)

print(
    "-" * 40
)

if languages:

    for language, count in sorted(
        languages.items(),
        key=lambda item: item[1],
        reverse=True
    ):

        print(
            f"{language:<18} "
            f"{count} files"
        )

else:

    print(
        "No recognized programming languages found."
    )


# ============================================================
# SECURITY SCAN
# ============================================================

print(
    "\n🔐 SECURITY SCAN"
)

print(
    "-" * 40
)

if security_findings:

    print(
        f"⚠️ Potential secrets found: "
        f"{len(security_findings)}"
    )

    for finding in security_findings:

        location = finding[
            "file"
        ]

        if "line" in finding:

            location += (
                f" (line {finding['line']})"
            )

        print(
            f"[{finding['severity']}] "
            f"{finding['type']} → "
            f"{location} "
            f"| Confidence: "
            f"{finding['confidence']}%"
        )

else:

    print(
        "✅ No obvious hardcoded secrets detected."
    )


# ============================================================
# CODE QUALITY
# ============================================================

print(
    "\n🧹 CODE QUALITY"
)

print(
    "-" * 40
)

if quality_findings:

    print(
        f"⚠️ Quality issues found: "
        f"{len(quality_findings)}"
    )

    for finding in quality_findings:

        location = finding[
            "file"
        ]

        if "line" in finding:

            location += (
                f" (line {finding['line']})"
            )

        print(
            f"\n[{finding['severity']}] "
            f"{finding['type']} → "
            f"{location}"
        )

        if "function" in finding:

            print(
                f"    Function: "
                f"{finding['function']}"
            )

        # ----------------------------------------------------
        # Duplicate/similar code
        # ----------------------------------------------------

        if "file_2" in finding:

            print(
                f"    Compared with: "
                f"{finding['file_2']}"
            )

        # ----------------------------------------------------
        # Details
        # ----------------------------------------------------

        if "details" in finding:

            print(
                f"    {finding['details']}"
            )

        # ----------------------------------------------------
        # Why
        # ----------------------------------------------------

        if "why" in finding:

            print(
                f"    💡 Why: "
                f"{finding['why']}"
            )

        # ----------------------------------------------------
        # Recommendation
        # ----------------------------------------------------

        if "recommendation" in finding:

            print(
                f"    🛠 Recommendation: "
                f"{finding['recommendation']}"
            )

        # ----------------------------------------------------
        # Priority
        # ----------------------------------------------------

        if "priority" in finding:

            print(
                f"    📌 Priority: "
                f"{finding['priority']}"
            )

else:

    print(
        "✅ No basic quality issues detected."
    )


# ============================================================
# DEPENDENCY ANALYSIS
# ============================================================

print(
    "\n📦 DEPENDENCY ANALYSIS"
)

print(
    "-" * 40
)

if not dependency_files:

    print(
        "No dependency manifest detected."
    )

else:

    # --------------------------------------------------------
    # Display every physical dependency manifest
    # separately.
    # --------------------------------------------------------

    for file in dependency_files:

        filename = file.name.lower()

        if filename not in {
            "requirements.txt",
            "package.json"
        }:
            continue

        # ----------------------------------------------------
        # Match using absolute path
        # ----------------------------------------------------

        file_path = str(
            file.resolve()
        )

        file_results = [

            result

            for result in dependency_results

            if result["file"] == file_path

        ]

        # ----------------------------------------------------
        # Display relative manifest path
        # ----------------------------------------------------

        try:

            display_path = file.relative_to(
                repo
            )

        except ValueError:

            display_path = file

        print(
            f"\n📄 {display_path}"
        )

        print(
            f"Direct dependencies: "
            f"{len(file_results)}"
        )

        # ----------------------------------------------------
        # Vulnerable packages
        # ----------------------------------------------------

        vulnerable_results = [

            result

            for result in file_results

            if result["vulnerabilities"]

        ]

        # ----------------------------------------------------
        # Unspecified versions
        # ----------------------------------------------------

        unspecified_results = [

            result

            for result in file_results

            if result["version"]
            == "unspecified"

        ]

        # ----------------------------------------------------
        # Display vulnerabilities
        # ----------------------------------------------------

        if vulnerable_results:

            print(
                f"🚨 Vulnerable packages: "
                f"{len(vulnerable_results)}"
            )

            for result in vulnerable_results:

                print(
                    f"\n  {result['name']} "
                    f"{result['version']}"
                )

                print(
                    f"    🚨 "
                    f"{len(result['vulnerabilities'])} "
                    f"known vulnerability(s)"
                )

                for vuln in result[
                    "vulnerabilities"
                ]:

                    print(
                        f"    ID: "
                        f"{vuln.get('id', 'Unknown')}"
                    )

        else:

            print(
                "  ✅ No known vulnerabilities found"
            )

        # ----------------------------------------------------
        # Display unspecified versions
        # ----------------------------------------------------

        if unspecified_results:

            print(
                f"  ⚠️ Versions not specified: "
                f"{len(unspecified_results)}"
            )


# ============================================================
# DEPENDENCY SUMMARY
# ============================================================

print(
    "\n📊 Dependency Summary"
)

print(
    "-" * 30
)

total_dependencies = len(
    dependency_results
)

vulnerable_packages = sum(

    1

    for result in dependency_results

    if result["vulnerabilities"]

)

total_vulnerabilities = sum(

    len(result["vulnerabilities"])

    for result in dependency_results

)

print(
    f"Dependencies analyzed: "
    f"{total_dependencies}"
)

print(
    f"Vulnerable packages: "
    f"{vulnerable_packages}"
)

print(
    f"Total vulnerabilities: "
    f"{total_vulnerabilities}"
)


# ============================================================
# GIT HEALTH
# ============================================================

print(
    "\n📜 GIT HEALTH"
)

print(
    "-" * 40
)

if git_info["is_git"]:

    print(
        "Git repository: YES"
    )

    print(
        f"Commits:        "
        f"{git_info['commits']}"
    )

    print(
        f"Contributors:   "
        f"{git_info['contributors']}"
    )

    print(
        f"Branches:       "
        f"{git_info['branches']}"
    )

    last_commit = (
        git_info["last_commit"]
    )

    if last_commit:

        print(
            "\nLast commit:"
        )

        print(
            f"    {last_commit['hash']} "
            f"— {last_commit['message']}"
        )

        print(
            f"    Author: "
            f"{last_commit['author']}"
        )

else:

    print(
        "⚠️ Not a Git repository."
    )


# ============================================================
# REPOSITORY HEALTH
# ============================================================

print(
    "\n🩺 REPOSITORY HEALTH"
)

print(
    "=" * 40
)

print(
    f"Overall Health      "
    f"{overall_score}/100"
)

print(
    f"🔐 Security         "
    f"{security_score}/100"
)

print(
    f"🧹 Code Quality     "
    f"{quality_score}/100"
)

print(
    f"📚 Documentation    "
    f"{documentation_score}/100"
)

print_quality_breakdown(
    quality_score,
    quality_findings
)


# ============================================================
# SMART DIAGNOSIS
# ============================================================

diagnosis = generate_diagnosis(
    security_findings,
    quality_findings,
    dependency_results
)

print_diagnosis(
    diagnosis
)

# ============================================================
# PERFORMANCE SUMMARY
# ============================================================

total_elapsed = (
    perf_counter()
    - total_start
)

print(
    "\n⚡ SCAN PERFORMANCE"
)

print(
    "-" * 40
)

print(
    f"Total scan time: "
    f"{total_elapsed:.2f}s"
)