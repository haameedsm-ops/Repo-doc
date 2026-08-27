# ============================================================
# SECURITY SCORE
# ============================================================

def calculate_security_score(findings):
    """Calculate a practical security health score out of 100."""

    score = 100

    secret_count = 0
    vulnerable_packages = 0

    for finding in findings:
        finding_type = finding.get("type", "")

        if finding_type in {"API Key", "Password", "Token"}:
            secret_count += 1

        elif finding_type == "Vulnerable Dependency":
            vulnerable_packages += 1

    # Hardcoded secrets are serious.
    score -= min(secret_count * 15, 60)

    # Known vulnerable dependencies are also serious.
    score -= min(vulnerable_packages * 12, 40)

    return max(round(score), 0)


# ============================================================
# CODE QUALITY SCORE
# ============================================================

def calculate_quality_score(findings):
    """Calculate code quality without over-penalising normal React code."""

    score = 100

    # Different findings have different practical impact.
    penalties = {
        "Large File": 3,
        "Long Function": 4,
        "Long JavaScript Function": 4,
        "Moderate Complexity": 4,
        "Moderate JavaScript Complexity": 4,
        "High Complexity": 8,
        "High JavaScript Complexity": 8,
        "JavaScript Security Pattern": 12,
        "TODO/FIXME": 1,
    }

    for finding in findings:
        finding_type = finding.get("type", "")
        severity = finding.get("severity", "LOW")

        deduction = penalties.get(finding_type)

        # Fallback for future finding types.
        if deduction is None:
            if severity == "HIGH":
                deduction = 8
            elif severity == "MEDIUM":
                deduction = 4
            else:
                deduction = 1

        score -= deduction

    return max(round(score), 0)


# ============================================================
# DOCUMENTATION SCORE
# ============================================================

def calculate_documentation_score(files):
    """Score repository documentation based on README presence."""

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
    """Calculate the overall repository health score."""

    return round(
        security_score * 0.5
        + quality_score * 0.3
        + documentation_score * 0.2
    )