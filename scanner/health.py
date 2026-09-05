
# ============================================================
# SECURITY SCORE
# ============================================================

def calculate_security_score(findings):
    """
    Calculate security health score out of 100.

    Rules:
    - Each unique secret: -15 points, max -60
    - First unique vulnerable package: -12
    - Each additional unique vulnerable package: -8
    - Each additional vulnerability on a vulnerable package: -2
    - Same package/version in multiple manifests is counted once.
    - Dependencies with zero vulnerabilities are ignored.
    """

    score = 100

    secret_count = 0

    # Unique vulnerable package/version combinations
    vulnerable_packages = set()

    # Maximum vulnerability count for each package/version
    vulnerability_counts = {}

    for finding in findings:

        finding_type = finding.get("type", "")

        # ----------------------------------------------------
        # SECRETS
        # ----------------------------------------------------

        if finding_type in {
            "API Key",
            "Password",
            "Token"
        }:
            secret_count += 1

        # ----------------------------------------------------
        # VULNERABLE DEPENDENCY
        # ----------------------------------------------------

        elif finding_type == "Vulnerable Dependency":

            package_name = finding.get("package")

            version = finding.get(
                "version",
                "unspecified"
            )

            if not package_name:
                continue

            try:
                vulnerability_count = int(
                    finding.get("count", 0)
                )
            except (TypeError, ValueError):
                vulnerability_count = 0

            if vulnerability_count <= 0:
                continue

            package_key = (
                package_name,
                version
            )

            vulnerable_packages.add(
                package_key
            )

            previous_count = vulnerability_counts.get(
                package_key,
                0
            )

            vulnerability_counts[
                package_key
            ] = max(
                previous_count,
                vulnerability_count
            )

    # --------------------------------------------------------
    # COUNTS
    # --------------------------------------------------------

    vulnerable_package_count = len(
        vulnerable_packages
    )

    total_vulnerabilities = sum(
        vulnerability_counts.values()
    )

    # --------------------------------------------------------
    # SECRET PENALTY
    # --------------------------------------------------------

    score -= min(
        secret_count * 15,
        60
    )

    # --------------------------------------------------------
    # VULNERABLE PACKAGE PENALTY
    # --------------------------------------------------------

    if vulnerable_package_count > 0:

        package_penalty = (
            12
            + (
                vulnerable_package_count - 1
            ) * 8
        )

        score -= min(
            package_penalty,
            40
        )

    # --------------------------------------------------------
    # ADDITIONAL VULNERABILITY PENALTY
    # --------------------------------------------------------

    additional_vulnerabilities = (
        total_vulnerabilities
        - vulnerable_package_count
    )

    if additional_vulnerabilities > 0:

        score -= min(
            additional_vulnerabilities * 2,
            20
        )

    return max(
        round(score),
        0
    )

# ============================================================
# CODE QUALITY SCORE
# ============================================================

# ============================================================
# CODE QUALITY SCORE
# ============================================================

def calculate_quality_score(quality_findings):
    """
    Calculate code quality score and provide a breakdown.

    Starts at 100 and deducts points based on issue severity
    and issue type.

    Quality deductions are capped at 50 points so that a
    repository with many findings does not immediately receive
    an unusably low score.
    """

    score = 100

    breakdown = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    # --------------------------------------------------------
    # Base deductions by severity
    # --------------------------------------------------------

    severity_deductions = {
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 2
    }

    # --------------------------------------------------------
    # Calculate deductions
    # --------------------------------------------------------

    total_deduction = 0

    for finding in quality_findings:

        severity = finding.get(
            "severity",
            "LOW"
        ).upper()

        if severity not in severity_deductions:
            severity = "LOW"

        finding_type = finding.get(
            "type",
            "Quality issue"
        )

        deduction = severity_deductions[severity]

        # ----------------------------------------------------
        # Large files get slightly different weighting.
        # ----------------------------------------------------

        if finding_type == "Large File":

            large_file_deductions = {
                "HIGH": 6,
                "MEDIUM": 4,
                "LOW": 2
            }

            deduction = large_file_deductions.get(
                severity,
                2
            )

        total_deduction += deduction
        breakdown[severity] += deduction

    # --------------------------------------------------------
    # Cap total quality deductions.
    # --------------------------------------------------------

    MAX_QUALITY_DEDUCTION = 50

    total_deduction = min(
        total_deduction,
        MAX_QUALITY_DEDUCTION
    )

    score -= total_deduction

    # Never allow score below 50.
    score = max(
        score,
        50
    )

    return {
        "score": score,
        "breakdown": breakdown,
        "total_deduction": total_deduction
    }

# ============================================================
# DOCUMENTATION SCORE
# ============================================================

def calculate_documentation_score(files):
    """
    Score repository documentation based on README presence.
    """

    readme_names = {
        "readme.md",
        "readme.txt",
        "readme"
    }

    has_readme = any(
        file.name.lower() in readme_names
        for file in files
    )

    return 100 if has_readme else 30


# ============================================================
# OVERALL SCORE
# ============================================================

def calculate_overall_score(
    security_score,
    quality_score,
    documentation_score
):
    """
    Calculate the overall repository health score.
    """

    return round(
        security_score * 0.5
        + quality_score * 0.3
        + documentation_score * 0.2
    )

# ============================================================
# PRIORITIZED DIAGNOSIS
# ============================================================
# ============================================================
# PRIORITIZED DIAGNOSIS
# ============================================================

def generate_diagnosis(
    security_findings,
    quality_findings,
    dependency_results,
):
    """
    Generate a prioritized repository diagnosis.

    Security, quality, and dependency issues are grouped
    by severity.

    Vulnerable dependencies are grouped by unique
    package name + version, even when the same dependency
    appears in multiple manifest files.
    """

    diagnosis = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": []
    }

    # ========================================================
    # SECURITY FINDINGS
    # ========================================================

    for finding in security_findings:

        severity = str(
            finding.get(
                "severity",
                "LOW"
            )
        ).upper()

        if severity not in diagnosis:
            severity = "LOW"

        diagnosis[severity].append({

            "category": "Security",

            "type": finding.get(
                "type",
                "Security issue"
            ),

            "file": finding.get(
                "file"
            ),

            "details": finding.get(
                "details",
                ""
            )

        })

    # ========================================================
    # QUALITY FINDINGS
    # ========================================================

    for finding in quality_findings:

        severity = str(
            finding.get(
                "severity",
                "LOW"
            )
        ).upper()

        if severity not in diagnosis:
            severity = "LOW"

        diagnosis[severity].append({

            "category": "Code Quality",

            "type": finding.get(
                "type",
                "Quality issue"
            ),

            "file": finding.get(
                "file"
            ),

            "details": finding.get(
                "details",
                ""
            )

        })

    # ========================================================
    # DEPENDENCY FINDINGS
    # ========================================================

    severity_rank = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    # --------------------------------------------------------
    # Group the same package/version across manifests
    #
    # Example:
    #
    # build.gradle -> spring-core 6.1.0
    # pom.xml      -> spring-core 6.1.0
    #
    # These become ONE diagnosis entry.
    # --------------------------------------------------------

    grouped_dependencies = {}

    for result in dependency_results:

        # ----------------------------------------------------
        # Extract package information
        # ----------------------------------------------------

        name = result.get("name")
        version = result.get("version")

        vulnerabilities = result.get(
            "vulnerabilities",
            []
        )

        # ----------------------------------------------------
        # Ignore non-vulnerable / malformed entries
        # ----------------------------------------------------

        if not name:
            continue

        if not version:
            version = "unspecified"

        if not isinstance(
            vulnerabilities,
            list
        ):
            vulnerabilities = []

        if not vulnerabilities:
            continue

        # ----------------------------------------------------
        # Unique package key
        # ----------------------------------------------------

        package_key = (
            name,
            version
        )

        if package_key not in grouped_dependencies:

            grouped_dependencies[package_key] = {

                "name": name,

                "version": version,

                "vulnerabilities": [],

                "files": []

            }

        grouped = grouped_dependencies[
            package_key
        ]

        # ----------------------------------------------------
        # Collect vulnerabilities without duplicates
        # ----------------------------------------------------

        existing_ids = {
            vulnerability.get("id")
            for vulnerability
            in grouped["vulnerabilities"]
            if isinstance(
                vulnerability,
                dict
            )
        }

        for vulnerability in vulnerabilities:

            if not isinstance(
                vulnerability,
                dict
            ):
                continue

            vulnerability_id = vulnerability.get(
                "id"
            )

            if vulnerability_id not in existing_ids:

                grouped["vulnerabilities"].append(
                    vulnerability
                )

                if vulnerability_id:
                    existing_ids.add(
                        vulnerability_id
                    )

        # ----------------------------------------------------
        # Collect manifest file
        # ----------------------------------------------------

        dependency_file = result.get(
            "file"
        )

        if dependency_file:

            if dependency_file not in grouped["files"]:

                grouped["files"].append(
                    dependency_file
                )

    # ========================================================
    # CREATE DIAGNOSIS FOR UNIQUE PACKAGES
    # ========================================================

    for package_data in grouped_dependencies.values():

        name = package_data["name"]

        version = package_data["version"]

        vulnerabilities = package_data[
            "vulnerabilities"
        ]

        files = package_data[
            "files"
        ]

        if not vulnerabilities:
            continue

        # ----------------------------------------------------
        # Determine highest vulnerability severity
        # ----------------------------------------------------

        package_severity = "HIGH"

        for vulnerability in vulnerabilities:

            if not isinstance(
                vulnerability,
                dict
            ):
                continue

            vulnerability_severity = str(
                vulnerability.get(
                    "severity",
                    "HIGH"
                )
            ).upper()

            if vulnerability_severity not in severity_rank:

                vulnerability_severity = "HIGH"

            if (
                severity_rank[
                    vulnerability_severity
                ]
                > severity_rank[
                    package_severity
                ]
            ):

                package_severity = (
                    vulnerability_severity
                )

        # ----------------------------------------------------
        # Collect vulnerability IDs
        # ----------------------------------------------------

        vulnerability_ids = []

        for vulnerability in vulnerabilities:

            if not isinstance(
                vulnerability,
                dict
            ):
                continue

            vulnerability_id = vulnerability.get(
                "id"
            )

            if (
                vulnerability_id
                and vulnerability_id
                not in vulnerability_ids
            ):

                vulnerability_ids.append(
                    vulnerability_id
                )

        # ----------------------------------------------------
        # Format manifest names
        # ----------------------------------------------------

        manifest_names = []

        for file_path in files:

            if not file_path:
                continue

            file_name = str(
                file_path
            ).replace(
                "\\",
                "/"
            ).split(
                "/"
            )[-1]

            if file_name not in manifest_names:

                manifest_names.append(
                    file_name
                )

        # ----------------------------------------------------
        # Build details message
        # ----------------------------------------------------

        vulnerability_count = len(
            vulnerabilities
        )

        details = (
            f"{name} "
            f"{version} "
            f"has "
            f"{vulnerability_count} "
            f"known vulnerabilit"
            f"{'y' if vulnerability_count == 1 else 'ies'}"
        )

        if manifest_names:

            details += (
                " | Declared in: "
                + ", ".join(
                    manifest_names
                )
            )

        # ----------------------------------------------------
        # Add ONE diagnosis entry
        # ----------------------------------------------------

        diagnosis[
            package_severity
        ].append({

            "category":
                "Dependency Security",

            "type":
                "Vulnerable Dependency",

            "package":
                name,

            "version":
                version,

            "vulnerability_count":
                vulnerability_count,

            "ids":
                vulnerability_ids,

            "files":
                manifest_names,

            "details":
                details

        })

    return diagnosis

# ============================================================
# PRINT PRIORITIZED DIAGNOSIS
# ============================================================

def print_diagnosis(diagnosis):
    """
    Print repository issues in priority order.
    """

    print(
        "\n🩺 DIAGNOSIS"
    )

    print(
        "=" * 40
    )

    severity_icons = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢"
    }

    total_issues = sum(
        len(items)
        for items in diagnosis.values()
    )

    if total_issues == 0:

        print(
            "✅ No major repository issues detected."
        )

        return

    for severity in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW"
    ]:

        findings = diagnosis.get(
            severity,
            []
        )

        if not findings:
            continue

        print(
            f"\n{severity_icons[severity]} "
            f"{severity}"
        )

        print(
            "-" * 40
        )

        # ----------------------------------------------------
        # Group similar findings
        # ----------------------------------------------------

        grouped = {}

        for finding in findings:

            key = (
                finding.get("category"),
                finding.get("type")
            )

            grouped.setdefault(
                key,
                []
            ).append(
                finding
            )

        # ----------------------------------------------------
        # Print groups
        # ----------------------------------------------------

        for (
            category,
            finding_type
        ), items in grouped.items():

            # Dependency packages
            if finding_type == "Vulnerable Dependency":

                print(
                    f"   {finding_type}: "
                    f"{len(items)} package(s)"
                )

                for item in items[:5]:

                    package = item.get(
                        "package",
                        "Unknown"
                    )

                    version = item.get(
                        "version",
                        ""
                    )

                    count = item.get(
                        "vulnerability_count",
                        0
                    )

                    print(
                        f"      • "
                        f"{package} "
                        f"{version} — "
                        f"{count} "
                        f"vulnerabilit"
                        f"{'y' if count == 1 else 'ies'}"
                    )

                if len(items) > 5:

                    print(
                        f"      • ... and "
                        f"{len(items) - 5} "
                        f"more package(s)"
                    )

                continue

            # ------------------------------------------------
            # Normal findings
            # ------------------------------------------------

            print(
                f"   {finding_type}: "
                f"{len(items)} issue(s)"
            )

            for item in items[:5]:

                if item.get("file"):

                    print(
                        f"      • "
                        f"{item['file']}"
                    )

                if item.get("details"):

                    print(
                        f"        "
                        f"{item['details']}"
                    )

            if len(items) > 5:

                print(
                    f"      • ... and "
                    f"{len(items) - 5} more"
                )

    # ========================================================
    # RECOMMENDED ACTIONS
    # ========================================================

    print(
        "\n📌 RECOMMENDED ACTIONS"
    )

    print(
        "-" * 40
    )

    actions = []

    if diagnosis["CRITICAL"]:

        actions.append(
            "Immediately address critical security vulnerabilities."
        )

    if any(
        item["category"] == "Dependency Security"
        for item in diagnosis["HIGH"]
    ):

        actions.append(
            "Update vulnerable dependencies and review their advisories."
        )

    if any(
        "Complexity" in item["type"]
        for severity in [
            "CRITICAL",
            "HIGH",
            "MEDIUM"
        ]
        for item in diagnosis[severity]
    ):

        actions.append(
            "Refactor highly complex functions into smaller focused functions."
        )

    if any(
        item["type"] == "Large File"
        for severity in diagnosis
        for item in diagnosis[severity]
    ):

        actions.append(
            "Split oversized source files into smaller focused modules."
        )

    if any(
        item["type"] == "Duplicate Code"
        for severity in diagnosis
        for item in diagnosis[severity]
    ):

        actions.append(
            "Extract duplicated logic into reusable components or utilities."
        )

    if not actions:

        actions.append(
            "Continue monitoring repository health and maintain existing standards."
        )

    for index, action in enumerate(
        actions,
        start=1
    ):

        print(
            f"{index}. {action}"
        )

def print_quality_breakdown(
    quality_score,
    quality_findings
):
    """
    Print an explainable code quality score
    with deductions for each finding.
    """

    print(
        "\n🧹 QUALITY SCORE BREAKDOWN"
    )

    print(
        "-" * 40
    )

    print(
        "Starting score: 100/100"
    )

    print()

    if not quality_findings:

        print(
            "✅ No quality deductions."
        )

        print(
            "Final score: 100/100"
        )

        return

    # --------------------------------------------------------
    # Deduction rules
    # --------------------------------------------------------

    severity_deductions = {
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 2
    }

    large_file_deductions = {
        "HIGH": 6,
        "MEDIUM": 4,
        "LOW": 2
    }

    MAX_QUALITY_DEDUCTION = 50

    raw_deduction = 0

    icons = {
        "HIGH": "🔴",
        "MEDIUM": "🟡",
        "LOW": "🟢"
    }

    print(
        "Deductions:"
    )

    # --------------------------------------------------------
    # Print each finding
    # --------------------------------------------------------

    for finding in quality_findings:

        severity = finding.get(
            "severity",
            "LOW"
        ).upper()

        if severity not in severity_deductions:
            severity = "LOW"

        finding_type = finding.get(
            "type",
            "Quality issue"
        )

        # Large File has its own weighting.
        if finding_type == "Large File":

            deduction = large_file_deductions.get(
                severity,
                2
            )

        else:

            deduction = severity_deductions.get(
                severity,
                2
            )

        raw_deduction += deduction

        icon = icons.get(
            severity,
            "🟢"
        )

        print(
            f"  {icon} "
            f"{finding_type:<25} "
            f"-{deduction}"
        )

    # --------------------------------------------------------
    # Apply maximum deduction
    # --------------------------------------------------------

    total_deduction = min(
        raw_deduction,
        MAX_QUALITY_DEDUCTION
    )

    print()

    if raw_deduction > MAX_QUALITY_DEDUCTION:

        print(
            f"Raw deductions: "
            f"-{raw_deduction}"
        )

        print(
            f"Maximum deduction: "
            f"-{MAX_QUALITY_DEDUCTION}"
        )

    print(
        f"Total deductions: "
        f"-{total_deduction}"
    )

    print(
        f"Final score: "
        f"{quality_score}/100"
    )