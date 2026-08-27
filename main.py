from scanner.vulnerabilities import (
    check_vulnerabilities_batch
)

from scanner.git_analysis import (
    analyze_git_repository
)

from scanner.dependencies import (
    find_dependency_files,
    parse_requirements,
    parse_package_json,
    check_outdated_dependencies
)

from scanner.health import (
    calculate_security_score,
    calculate_quality_score,
    calculate_documentation_score,
    calculate_overall_score
)

from scanner.quality import (
    check_large_files,
    check_todos,
    check_long_functions,
    analyze_python_complexity
)

from scanner.files import (
    scan_files,
    detect_languages,
    count_lines
)

from scanner.security import (
    scan_for_secrets
)


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


print(
    "\n🔎 Scanning repository...\n"
)


# ============================================================
# GIT ANALYSIS
# ============================================================

git_info = analyze_git_repository(
    repo_path
)


# ============================================================
# BASIC REPOSITORY SCAN
# ============================================================

files = scan_files(
    repo_path
)

languages = detect_languages(
    files
)

lines = count_lines(
    files
)


# ============================================================
# SECURITY SCAN
# ============================================================

security_findings = (
    scan_for_secrets(files)
)


# ============================================================
# CODE QUALITY
# ============================================================

quality_findings = []


quality_findings.extend(
    check_large_files(files)
)

quality_findings.extend(
    check_todos(files)
)

quality_findings.extend(
    check_long_functions(files)
)

quality_findings.extend(
    analyze_python_complexity(files)
)


# ============================================================
# DEPENDENCIES
# ============================================================

dependency_files = (
    find_dependency_files(
        repo_path
    )
)


dependency_findings = []

dependency_results = []

outdated_results = []


dependency_groups = {

    "PyPI": [],

    "npm": []

}


# ============================================================
# COLLECT DEPENDENCIES
# ============================================================

for file in dependency_files:

    filename = file.name.lower()


    # --------------------------------------------------------
    # PYTHON
    # --------------------------------------------------------

    if filename == "requirements.txt":

        dependencies = (
            parse_requirements(file)
        )


        for dependency in dependencies:

            dependency["_file"] = (
                file.name
            )

            dependency_groups[
                "PyPI"
            ].append(
                dependency
            )


    # --------------------------------------------------------
    # NODE
    # --------------------------------------------------------

    elif filename == "package.json":

        dependencies = (
            parse_package_json(file)
        )


        for dependency in dependencies:

            dependency["_file"] = (
                file.name
            )

            dependency_groups[
                "npm"
            ].append(
                dependency
            )


# ============================================================
# VULNERABILITY SCAN
# ============================================================

python_vulnerabilities = {}

npm_vulnerabilities = {}


if dependency_groups["PyPI"]:

    print(
        f"🔐 Scanning "
        f"{len(dependency_groups['PyPI'])} "
        f"Python dependencies..."
    )


    python_vulnerabilities = (
        check_vulnerabilities_batch(
            dependency_groups["PyPI"],
            ecosystem="PyPI"
        )
    )


if dependency_groups["npm"]:

    print(
        f"🔐 Scanning "
        f"{len(dependency_groups['npm'])} "
        f"npm dependencies..."
    )


    npm_vulnerabilities = (
        check_vulnerabilities_batch(
            dependency_groups["npm"],
            ecosystem="npm"
        )
    )


# ============================================================
# OUTDATED DEPENDENCY SCAN
# ============================================================

print(
    "\n📦 Checking dependency versions..."
)


for ecosystem, dependencies in (
    dependency_groups.items()
):

    if not dependencies:
        continue


    print(
        f"   Checking {ecosystem}..."
    )


    results = (
        check_outdated_dependencies(
            dependencies,
            ecosystem
        )
    )


    for result in results:

        result["ecosystem"] = (
            ecosystem
        )


        outdated_results.append(
            result
        )


# ============================================================
# BUILD DEPENDENCY RESULTS
# ============================================================

for ecosystem, dependencies in (
    dependency_groups.items()
):

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

            "file":
                dependency["_file"],

            "name":
                name,

            "version":
                version,

            "ecosystem":
                ecosystem,

            "vulnerabilities":
                vulnerabilities

        })


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
    + dependency_findings
)


# ============================================================
# HEALTH
# ============================================================

security_score = (
    calculate_security_score(
        all_security_findings
    )
)


quality_score = (
    calculate_quality_score(
        quality_findings
    )
)


documentation_score = (
    calculate_documentation_score(
        files
    )
)


overall_score = (
    calculate_overall_score(
        security_score,
        quality_score,
        documentation_score
    )
)


# ============================================================
# HEADER
# ============================================================

print("\n")

print(
    "🩺 REPO DOCTOR"
)

print("=" * 40)


print(
    f"Source files: {len(files)}"
)

print(
    f"Lines of code: {lines}"
)


# ============================================================
# PROJECT DNA
# ============================================================

print(
    "\n🧬 PROJECT DNA"
)

print("-" * 40)


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
        "No recognized programming "
        "languages found."
    )


# ============================================================
# SECURITY
# ============================================================

print(
    "\n🔐 SECURITY SCAN"
)

print("-" * 40)


if security_findings:

    print(
        f"⚠️ Potential secrets found: "
        f"{len(security_findings)}"
    )


    for finding in security_findings:

        print(

            f"[{finding['severity']}] "

            f"{finding['type']} → "

            f"{finding['file']} "

            f"(line {finding['line']}) "

            f"| Confidence: "

            f"{finding['confidence']}%"

        )

else:

    print(
        "✅ No obvious hardcoded "
        "secrets detected."
    )


# ============================================================
# CODE QUALITY
# ============================================================

print(
    "\n🧹 CODE QUALITY"
)

print("-" * 40)


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
                f" (line "
                f"{finding['line']})"
            )


        print(

            f"[{finding['severity']}] "

            f"{finding['type']} → "

            f"{location}"

        )


        if "function" in finding:

            print(

                f"    Function: "

                f"{finding['function']}"

            )


        print(
            f"    {finding['details']}"
        )


else:

    print(
        "✅ No basic quality "
        "issues detected."
    )


# ============================================================
# DEPENDENCY ANALYSIS
# ============================================================

print(
    "\n📦 DEPENDENCY ANALYSIS"
)

print("-" * 40)


if not dependency_files:

    print(
        "No dependency manifest detected."
    )

else:

    manifest_files = []


    for file in dependency_files:

        if file.name.lower() in {

            "requirements.txt",

            "package.json"

        }:

            if file not in manifest_files:

                manifest_files.append(
                    file
                )


    for file in manifest_files:

        file_results = [

            result

            for result in dependency_results

            if result["file"]
            == file.name

        ]


        print(
            f"\n📄 {file.name}"
        )


        print(
            f"Direct dependencies: "
            f"{len(file_results)}"
        )


        vulnerable_results = [

            result

            for result in file_results

            if result["vulnerabilities"]

        ]


        if vulnerable_results:

            print(
                f"🚨 Vulnerable packages: "
                f"{len(vulnerable_results)}"
            )


            for result in vulnerable_results:

                print(

                    f"  {result['name']} "

                    f"{result['version']}"

                )


                print(

                    f"    🚨 "

                    f"{len(result['vulnerabilities'])} "

                    f"known vulnerability(s)"

                )


        else:

            print(
                "  ✅ No known "
                "vulnerabilities found"
            )


# ============================================================
# OUTDATED DEPENDENCIES
# ============================================================

print(
    "\n🔄 DEPENDENCY FRESHNESS"
)

print("-" * 40)


if outdated_results:

    print(
        f"⚠️ Outdated packages: "
        f"{len(outdated_results)}"
    )


    for result in outdated_results:

        print(

            f"\n  {result['name']}"

        )


        print(

            f"    Current: "
            f"{result['current']}"

        )


        print(

            f"    Latest:  "
            f"{result['latest']}"

        )


        print(

            f"    Severity: "
            f"{result['severity']}"

        )

else:

    print(
        "✅ All checked dependencies "
        "are up to date."
    )


# ============================================================
# DEPENDENCY SUMMARY
# ============================================================

print(
    "\n📊 Dependency Summary"
)

print("-" * 30)


total_dependencies = len(
    dependency_results
)


vulnerable_packages = sum(

    1

    for result in dependency_results

    if result["vulnerabilities"]

)


total_vulnerabilities = sum(

    len(
        result["vulnerabilities"]
    )

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


print(

    f"Outdated packages: "
    f"{len(outdated_results)}"

)


# ============================================================
# GIT HEALTH
# ============================================================

print(
    "\n📜 GIT HEALTH"
)

print("-" * 40)


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

print("=" * 40)


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


# ============================================================
# FINAL DIAGNOSIS
# ============================================================

print(
    "\n🩺 DIAGNOSIS"
)

print("-" * 40)


if overall_score >= 90:

    print(
        "🟢 Excellent repository health."
    )

elif overall_score >= 75:

    print(
        "🟡 Good repository health."
    )

elif overall_score >= 50:

    print(
        "🟠 Repository needs attention."
    )

else:

    print(
        "🔴 Critical repository health "
        "issues detected."
    )