import re
from pathlib import Path


# ============================================================
# SECRET PATTERNS
# ============================================================

SECRET_PATTERNS = {
    "API Key": r'''(?i)\b(api[_-]?key)\b\s*[:=]\s*["']([^"']+)["']''',

    "Secret Key": r'''(?i)\b(secret[_-]?key)\b\s*[:=]\s*["']([^"']+)["']''',

    "Password": r'''(?i)\b(password|passwd|pwd)\b\s*[:=]\s*["']([^"']+)["']''',

    "Token": r'''(?i)\b(token|auth[_-]?token)\b\s*[:=]\s*["']([^"']+)["']''',
}


# ============================================================
# FILE CATEGORIES
# ============================================================

TEST_PARTS = {
    "test",
    "tests",
    "__tests__",
    "__test__",
}

GENERATED_PARTS = {
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    "generated",
}

CONFIG_NAMES = {
    "vite.config.js",
    "vite.config.ts",
    "webpack.config.js",
    "webpack.config.ts",
    "jest.config.js",
    "jest.config.ts",
    "eslint.config.js",
    "eslint.config.mjs",
    "prettier.config.js",
    "prettier.config.cjs",
    "tailwind.config.js",
    "tailwind.config.ts",
}


# ============================================================
# PLACEHOLDERS
# ============================================================

PLACEHOLDERS = {
    "example",
    "test",
    "demo",
    "dummy",
    "fake",
    "sample",
    "changeme",
    "placeholder",
    "null",
    "none",
    "undefined",
    "your_api_key",
    "your-api-key",
    "your_password",
    "your-password",
    "your_secret",
    "your-secret",
    "your_token",
    "your-token",
    "test-token",
    "test_token",
    "demo-token",
    "demo_token",
    "example-token",
    "example_token",
    "dummy-token",
    "dummy_token",
    "xxxxxxxx",
    "xxxx",
}


# ============================================================
# FILE CLASSIFICATION
# ============================================================

def get_file_category(file: Path) -> str:
    """Classify a file as source, test, generated or config."""

    parts = {
        part.lower()
        for part in file.parts
    }

    name = file.name.lower()

    # Generated files should never produce secret findings.
    if parts.intersection(GENERATED_PARTS):
        return "generated"

    # Test directories.
    if parts.intersection(TEST_PARTS):
        return "test"

    # Test filename conventions.
    if (
        ".test." in name
        or ".spec." in name
        or name.endswith("_test.py")
    ):
        return "test"

    # Configuration files.
    if name in CONFIG_NAMES:
        return "config"

    return "source"


# ============================================================
# PLACEHOLDER DETECTION
# ============================================================

def is_placeholder(value: str) -> bool:
    """Determine whether a detected value looks like a placeholder."""

    value_lower = value.lower().strip()

    if value_lower in PLACEHOLDERS:
        return True

    # Common placeholder patterns.
    placeholder_patterns = [
        r"^your[-_].*$",
        r"^example[-_].*$",
        r"^test[-_].*$",
        r"^demo[-_].*$",
        r"^dummy[-_].*$",
        r"^fake[-_].*$",
        r"^sample[-_].*$",
        r"^placeholder[-_].*$",
        r"^x{4,}$",
        r"^0{4,}$",
    ]

    return any(
        re.match(pattern, value_lower)
        for pattern in placeholder_patterns
    )


# ============================================================
# CONFIDENCE
# ============================================================

def calculate_confidence(secret_type, value):
    """Calculate how likely the detected value is a real secret."""

    # Obvious placeholders.
    if is_placeholder(value):
        return 15

    # Very short values are less suspicious.
    if len(value) < 8:
        return 20

    score = 50

    # Longer values are more suspicious.
    if len(value) >= 16:
        score += 15

    if len(value) >= 32:
        score += 10

    # Mixed character types increase suspicion.
    if re.search(r"[A-Z]", value):
        score += 5

    if re.search(r"[a-z]", value):
        score += 5

    if re.search(r"\d", value):
        score += 10

    if re.search(r"[^A-Za-z0-9]", value):
        score += 5

    # Structured secret types deserve additional attention.
    if secret_type in {
        "API Key",
        "Secret Key",
        "Token",
    }:
        score += 5

    return min(score, 100)


# ============================================================
# SEVERITY
# ============================================================

def get_severity(
    confidence,
    file_category="source",
):
    """Determine severity using confidence and file context."""

    # Test files are intentionally treated less severely.
    if file_category == "test":
        if confidence >= 80:
            return "MEDIUM"

        if confidence >= 50:
            return "LOW"

        return "LOW"

    if confidence >= 80:
        return "HIGH"

    if confidence >= 50:
        return "MEDIUM"

    return "LOW"


# ============================================================
# FALSE-POSITIVE DETECTION
# ============================================================

def is_false_positive(content, match):
    """
    Detect common cases where a secret-like assignment is
    actually user input or interactive password collection.
    """

    line_start = (
        content.rfind(
            "\n",
            0,
            match.start(),
        )
        + 1
    )

    line_end = content.find(
        "\n",
        match.end(),
    )

    if line_end == -1:
        line_end = len(content)

    line = content[
        line_start:line_end
    ].lower()

    suspicious_inputs = [
        "input(",
        "getpass(",
        "prompt(",
        "askpassword(",
    ]

    for pattern in suspicious_inputs:
        if pattern in line:
            return True

    return False


# ============================================================
# SECRET FINDING DEDUPLICATION
# ============================================================

def _finding_key(finding):
    """Create a stable key for a security finding."""

    return (
        finding.get("type"),
        finding.get("file"),
        finding.get("line"),
        finding.get("confidence"),
    )


def remove_duplicate_findings(findings):
    """Remove duplicate security findings."""

    unique = []
    seen = set()

    for finding in findings:
        key = _finding_key(finding)

        if key in seen:
            continue

        seen.add(key)
        unique.append(finding)

    return unique


# ============================================================
# SECRET SCANNER
# ============================================================

def scan_for_secrets(files):
    """Scan source files for possible hardcoded secrets."""

    findings = []

    for file in files:
        category = get_file_category(file)

        # Never scan generated output.
        if category == "generated":
            continue

        try:
            content = file.read_text(
                encoding="utf-8",
                errors="ignore",
            )
        except (
            PermissionError,
            OSError,
        ):
            continue

        for secret_type, pattern in SECRET_PATTERNS.items():

            try:
                matches = re.finditer(
                    pattern,
                    content,
                )
            except re.error:
                # Never allow one invalid pattern to crash
                # the entire repository scan.
                continue

            for match in matches:

                if is_false_positive(
                    content,
                    match,
                ):
                    continue

                # Group 2 is always the actual secret value.
                value = match.group(2)

                placeholder = is_placeholder(value)

                confidence = calculate_confidence(
                    secret_type,
                    value,
                )

                # ------------------------------------------------
                # Ignore obvious placeholders.
                # ------------------------------------------------
                if placeholder:
                    continue

                # ------------------------------------------------
                # Ignore very low-confidence test values.
                #
                # Example:
                # token = "abc"
                #
                # These are usually test data rather than
                # actual credentials.
                # ------------------------------------------------
                if category == "test" and confidence < 50:
                    continue

                severity = get_severity(
                    confidence,
                    category,
                )

                line_number = (
                    content[:match.start()]
                    .count("\n")
                    + 1
                )

                # ------------------------------------------------
                # Explanation
                # ------------------------------------------------

                if category == "test":
                    why = (
                        "This secret-like value appears inside "
                        "a test file. It may be intentionally fake "
                        "test data, but it should still be verified."
                    )

                    recommendation = (
                        "Verify that this is not a real credential. "
                        "Use clearly fake test values and never commit "
                        "production secrets to test files."
                    )

                else:
                    why = (
                        "Hardcoded credentials can be exposed through "
                        "source control, logs, deployments or leaked "
                        "repositories."
                    )

                    recommendation = (
                        "Move the credential to environment variables "
                        "or a secure secret manager and rotate it if "
                        "it has already been committed."
                    )

                findings.append({
                    "type": secret_type,
                    "file": str(file),
                    "line": line_number,
                    "severity": severity,
                    "priority": severity,
                    "confidence": confidence,
                    "file_category": category,
                    "placeholder": False,
                    "details": (
                        f"Possible {secret_type.lower()} detected "
                        f"(confidence: {confidence}%)."
                    ),
                    "why": why,
                    "recommendation": recommendation,
                })

    return remove_duplicate_findings(findings)