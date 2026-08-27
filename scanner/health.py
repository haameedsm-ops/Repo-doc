def calculate_security_score(findings):

    score = 100

    secret_count = 0
    vulnerable_packages = 0

    for finding in findings:

        finding_type = finding.get("type", "")

        # --------------------------------
        # Hardcoded secrets
        # --------------------------------

        if finding_type in {
            "API Key",
            "Password",
            "Token"
        }:

            secret_count += 1

        # --------------------------------
        # Vulnerable dependencies
        # --------------------------------

        elif finding_type == "Vulnerable Dependency":

            vulnerable_packages += 1

    # --------------------------------
    # Secret penalties
    # --------------------------------

    score -= min(
        secret_count * 12,
        45
    )

    # --------------------------------
    # Dependency penalties
    # --------------------------------

    score -= min(
        vulnerable_packages * 10,
        35
    )

    return max(round(score), 0)

def calculate_quality_score(findings):
    score = 100

    for finding in findings:

        severity = finding["severity"]

        if severity == "HIGH":
            deduction = 15

        elif severity == "MEDIUM":
            deduction = 8

        else:
            deduction = 3

        score -= deduction

    return round(max(score, 0))


def calculate_documentation_score(files):

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


def calculate_overall_score(
    security_score,
    quality_score,
    documentation_score
):

    return round(
        security_score * 0.5
        + quality_score * 0.3
        + documentation_score * 0.2
    )