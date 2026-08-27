import re


SECRET_PATTERNS = {
    "API Key": r'(?i)\b(api[_-]?key)\b\s*[:=]\s*["\']([^"\']+)["\']',
    "Secret Key": r'(?i)\b(secret[_-]?key)\b\s*[:=]\s*["\']([^"\']+)["\']',
    "Password": r'(?i)\b(password|passwd|pwd)\b\s*[:=]\s*["\']([^"\']+)["\'](?!\s*\))',
    "Token": r'(?i)\b(token|auth[_-]?token)\b\s*[:=]\s*["\']([^"\']+)["\']',
}


PLACEHOLDERS = {
    "example",
    "test",
    "demo",
    "changeme",
    "your_api_key",
    "your_password",
    "your_secret",
    "placeholder",
    "null",
    "none",
}


def calculate_confidence(secret_type, value):

    value_lower = value.lower().strip()

    # Obvious placeholder
    if value_lower in PLACEHOLDERS:
        return 15

    # Very short values are less suspicious
    if len(value) < 8:
        return 20

    score = 50

    # Longer values are more suspicious
    if len(value) >= 16:
        score += 15

    # Mixed character types increase suspicion
    if re.search(r"[A-Z]", value):
        score += 5

    if re.search(r"[a-z]", value):
        score += 5

    if re.search(r"\d", value):
        score += 10

    if re.search(r"[^A-Za-z0-9]", value):
        score += 5

    # Passwords and tokens are particularly interesting
    if secret_type in {"API Key", "Secret Key", "Token"}:
        score += 5

    return min(score, 100)


def get_severity(confidence):

    if confidence >= 80:
        return "HIGH"

    if confidence >= 50:
        return "MEDIUM"

    return "LOW"

def is_false_positive(content, match):

    line_start = content.rfind("\n", 0, match.start()) + 1
    line_end = content.find("\n", match.end())

    if line_end == -1:
        line_end = len(content)

    line = content[line_start:line_end].lower()

    suspicious_inputs = [
        "input(",
        "getpass(",
        "prompt(",
        "askpassword("
    ]

    for pattern in suspicious_inputs:
        if pattern in line:
            return True

    return False


def scan_for_secrets(files):

    findings = []

    for file in files:

        try:
            content = file.read_text(
                encoding="utf-8",
                errors="ignore"
            )

        except (PermissionError, OSError):
            continue

        for secret_type, pattern in SECRET_PATTERNS.items():

            matches = re.finditer(pattern, content)

            for match in matches:

                if is_false_positive(content, match):
                   continue

                value = match.group(2)

                confidence = calculate_confidence(
                    secret_type,
                    value
                )

                severity = get_severity(confidence)

                line_number = (
                    content[:match.start()]
                    .count("\n") + 1
                )

                findings.append({
                    "type": secret_type,
                    "file": str(file),
                    "line": line_number,
                    "severity": severity,
                    "confidence": confidence
                })

    return findings