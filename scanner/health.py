
# ============================================================
# SECURITY SCORE
# ============================================================

def calculate_security_score(findings):
    """
    Calculate a practical security health score out of 100.

    Security scoring considers:
    - Hardcoded secrets
    - Vulnerable packages
    - Number of vulnerabilities

    Vulnerabilities belonging to the same package are not
    treated as separate vulnerable packages.
    """

    score = 100

    secret_count = 0
    vulnerable_packages = 0
    total_vulnerabilities = 0

    for finding in findings:

        finding_type = finding.get(
            "type",
            ""
        )

        # ----------------------------------------------------
        # Secrets
        # ----------------------------------------------------

        if finding_type in {
            "API Key",
            "Password",
            "Token"
        }:

            secret_count += 1

        # ----------------------------------------------------
        # Vulnerable dependencies
        # ----------------------------------------------------

        elif finding_type == "Vulnerable Dependency":

            vulnerable_packages += 1

            try:

                count = int(
                    finding.get(
                        "count",
                        1
                    )
                )

            except (
                TypeError,
                ValueError
            ):

                count = 1

            total_vulnerabilities += count

    # --------------------------------------------------------
    # Secret penalty
    # --------------------------------------------------------

    score -= min(
        secret_count * 15,
        60
    )

    # --------------------------------------------------------
    # Vulnerable package penalty
    #
    # First vulnerable package = 12
    # Additional packages = 8 each
    # Maximum = 40
    # --------------------------------------------------------

    if vulnerable_packages:

        package_penalty = (
            12
            + max(
                vulnerable_packages - 1,
                0
            ) * 8
        )

        score -= min(
            package_penalty,
            40
        )

    # --------------------------------------------------------
    # Additional vulnerability penalty
    #
    # We already penalized the package itself.
    # Only additional vulnerabilities create a smaller
    # extra penalty.
    # --------------------------------------------------------

    if total_vulnerabilities > vulnerable_packages:

        additional_vulnerabilities = (
            total_vulnerabilities
            - vulnerable_packages
        )

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

    Each vulnerable dependency is represented using its
    actual package name, version, vulnerability count,
    and vulnerability IDs.
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

        if not isinstance(vulnerabilities, list):
            vulnerabilities = []

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
                severity_rank[vulnerability_severity]
                > severity_rank[package_severity]
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

            if vulnerability_id:
                vulnerability_ids.append(
                    vulnerability_id
                )

        # ----------------------------------------------------
        # Create ONE diagnosis entry per package
        # ----------------------------------------------------

        diagnosis[package_severity].append({

            "category":
                "Dependency Security",

            "type":
                "Vulnerable Dependency",

            "package":
                name,

            "version":
                version,

            "vulnerability_count":
                len(vulnerabilities),

            "ids":
                vulnerability_ids,

            "details":
                (
                    f"{name} "
                    f"{version} "
                    f"has "
                    f"{len(vulnerabilities)} "
                    f"known vulnerabilit"
                    f"{'y' if len(vulnerabilities) == 1 else 'ies'}"
                )

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