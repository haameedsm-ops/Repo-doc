import ast
import re


# ============================================================
# QUALITY THRESHOLDS
# ============================================================

MAX_SOURCE_FILE_LINES = 500
MAX_CSS_LINES = 5000
MAX_JS_LINES = 500
MAX_FUNCTION_LINES = 50
MAX_JS_FUNCTION_LINES = 50


# ============================================================
# FILE TYPES
# ============================================================

SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".java", ".cpp", ".c", ".h", ".hpp",
    ".go", ".rs", ".php", ".kt",
}

CSS_EXTENSIONS = {".css", ".scss", ".sass", ".less"}
JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}


# ============================================================
# FILE READER
# ============================================================

def read_file(file):
    try:
        return file.read_text(encoding="utf-8", errors="ignore")
    except (PermissionError, OSError):
        return ""


# ============================================================
# LARGE FILE DETECTION
# ============================================================

def check_large_files(files):
    findings = []

    for file in files:
        extension = file.suffix.lower()

        if extension not in SOURCE_EXTENSIONS | CSS_EXTENSIONS:
            continue

        content = read_file(file)
        if not content:
            continue

        line_count = len(content.splitlines())

        if extension in CSS_EXTENSIONS:
            if line_count > MAX_CSS_LINES:
                findings.append({
                    "type": "Large Stylesheet",
                    "file": str(file),
                    "details": f"{line_count} lines",
                    "severity": "LOW",
                })
        else:
            threshold = MAX_JS_LINES if extension in JS_EXTENSIONS else MAX_SOURCE_FILE_LINES

            if line_count > threshold:
                findings.append({
                    "type": "Large Source File",
                    "file": str(file),
                    "details": f"{line_count} lines",
                    "severity": "MEDIUM",
                })

    return findings


# ============================================================
# TODO / FIXME DETECTION
# ============================================================

def check_todos(files):
    findings = []

    for file in files:
        extension = file.suffix.lower()
        if extension not in SOURCE_EXTENSIONS | CSS_EXTENSIONS:
            continue

        content = read_file(file)
        if not content:
            continue

        for line_number, line in enumerate(content.splitlines(), start=1):
            upper_line = line.upper()

            if "TODO" in upper_line or "FIXME" in upper_line:
                findings.append({
                    "type": "TODO/FIXME",
                    "file": str(file),
                    "line": line_number,
                    "details": line.strip(),
                    "severity": "LOW",
                })

    return findings


# ============================================================
# PYTHON LONG FUNCTION DETECTION
# ============================================================

def check_python_long_functions(file):
    findings = []
    content = read_file(file)

    if not content:
        return findings

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        if not hasattr(node, "end_lineno"):
            continue

        length = node.end_lineno - node.lineno + 1

        if length > MAX_FUNCTION_LINES:
            findings.append({
                "type": "Long Function",
                "file": str(file),
                "function": node.name,
                "line": node.lineno,
                "details": f"{length} lines",
                "severity": "MEDIUM",
            })

    return findings


# ============================================================
# JAVASCRIPT HELPERS
# ============================================================

def strip_js_strings_and_comments(content):
    """Reduce false positives while preserving line structure."""
    pattern = re.compile(
        r"//[^\n]*|/\*[\s\S]*?\*/|(?:'[^'\\]*(?:\\.[^'\\]*)*'|\"[^\"\\]*(?:\\.[^\"\\]*)*\"|`[^`\\]*(?:\\.[^`\\]*)*`)",
        re.MULTILINE,
    )
    return pattern.sub(lambda match: "\n" * match.group(0).count("\n"), content)


def find_matching_brace(text, opening_index):
    depth = 0
    in_string = None
    escape = False

    for index in range(opening_index, len(text)):
        char = text[index]

        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == in_string:
                in_string = None
            continue

        if char in "'\"`":
            in_string = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index

    return None


def estimate_js_complexity(function_text):
    """Approximate cyclomatic complexity for JavaScript/TypeScript."""
    cleaned = strip_js_strings_and_comments(function_text)
    complexity = 1

    complexity += len(re.findall(r"\bif\s*\(", cleaned))
    complexity += len(re.findall(r"\belse\s+if\b", cleaned))
    complexity += len(re.findall(r"\bfor\s*\(", cleaned))
    complexity += len(re.findall(r"\bwhile\s*\(", cleaned))
    complexity += len(re.findall(r"\bcatch\s*\(", cleaned))
    complexity += len(re.findall(r"\bswitch\s*\(", cleaned))
    complexity += len(re.findall(r"\bcase\s+", cleaned))
    complexity += len(re.findall(r"\?\s*[^.?]", cleaned))
    complexity += len(re.findall(r"&&|\|\|", cleaned))

    return complexity


def check_js_functions(file):
    findings = []
    content = read_file(file)

    if not content:
        return findings

    cleaned = strip_js_strings_and_comments(content)

    # Named functions, arrow functions, and React components.
    patterns = [
        re.compile(r"\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{"),
        re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{"),
    ]

    lines = content.splitlines()

    for pattern in patterns:
        for match in pattern.finditer(cleaned):
            opening = cleaned.find("{", match.start(), match.end())
            if opening == -1:
                continue

            closing = find_matching_brace(cleaned, opening)
            if closing is None:
                continue

            start_line = cleaned.count("\n", 0, match.start()) + 1
            end_line = cleaned.count("\n", 0, closing) + 1
            length = end_line - start_line + 1

            if length <= MAX_JS_FUNCTION_LINES:
                continue

            name = match.group(1)
            findings.append({
                "type": "Long JavaScript Function",
                "file": str(file),
                "function": name,
                "line": start_line,
                "details": f"{length} lines",
                "severity": "MEDIUM",
            })

    return findings


# ============================================================
# LONG FUNCTION DETECTION
# ============================================================

def check_long_functions(files):
    findings = []

    for file in files:
        extension = file.suffix.lower()

        if extension == ".py":
            findings.extend(check_python_long_functions(file))
        elif extension in JS_EXTENSIONS:
            findings.extend(check_js_functions(file))

    return findings


# ============================================================
# PYTHON COMPLEXITY
# ============================================================

def calculate_function_complexity(function_node):
    complexity = 1

    for node in ast.walk(function_node):
        if isinstance(node, (
            ast.If, ast.For, ast.While, ast.AsyncFor,
            ast.ExceptHandler, ast.With, ast.AsyncWith, ast.Assert
        )):
            complexity += 1
        elif isinstance(node, ast.BoolOp):
            complexity += len(node.values) - 1
        elif isinstance(node, ast.IfExp):
            complexity += 1

    return complexity


def analyze_python_complexity(files):
    findings = []

    for file in files:
        if file.suffix.lower() != ".py":
            continue

        content = read_file(file)
        if not content:
            continue

        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            complexity = calculate_function_complexity(node)

            if complexity >= 10:
                findings.append({
                    "type": "High Complexity",
                    "file": str(file),
                    "function": node.name,
                    "line": node.lineno,
                    "details": f"Complexity: {complexity}",
                    "severity": "HIGH",
                })
            elif complexity >= 6:
                findings.append({
                    "type": "Moderate Complexity",
                    "file": str(file),
                    "function": node.name,
                    "line": node.lineno,
                    "details": f"Complexity: {complexity}",
                    "severity": "MEDIUM",
                })

    return findings


# ============================================================
# JAVASCRIPT COMPLEXITY
# ============================================================

def analyze_javascript_complexity(files):
    findings = []

    for file in files:
        if file.suffix.lower() not in JS_EXTENSIONS:
            continue

        content = read_file(file)
        if not content:
            continue

        cleaned = strip_js_strings_and_comments(content)

        patterns = [
            re.compile(r"\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{"),
            re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{"),
        ]

        for pattern in patterns:
            for match in pattern.finditer(cleaned):
                opening = cleaned.find("{", match.start(), match.end())
                if opening == -1:
                    continue

                closing = find_matching_brace(cleaned, opening)
                if closing is None:
                    continue

                function_text = cleaned[match.start():closing + 1]
                complexity = estimate_js_complexity(function_text)
                line = cleaned.count("\n", 0, match.start()) + 1

                if complexity >= 20:
                    severity = "HIGH"
                    finding_type = "High JavaScript Complexity"
                elif complexity >= 10:
                    severity = "MEDIUM"
                    finding_type = "Moderate JavaScript Complexity"
                else:
                    continue

                findings.append({
                    "type": finding_type,
                    "file": str(file),
                    "function": match.group(1),
                    "line": line,
                    "details": f"Estimated complexity: {complexity}",
                    "severity": severity,
                })

    return findings
