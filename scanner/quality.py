import ast
import re


MAX_FILE_LINES = 300
MAX_FUNCTION_LINES = 50
MAX_JS_FUNCTION_LINES = 80

JS_EXTENSIONS = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx"
}


# ============================================================
# FILE READER
# ============================================================

def read_file(file):
    try:
        return file.read_text(
            encoding="utf-8",
            errors="ignore"
        )
    except (PermissionError, OSError):
        return ""


# ============================================================
# LARGE FILE CHECK
# ============================================================

def check_large_files(files):

    findings = []

    binary_extensions = {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".bmp",
        ".mp4",
        ".mp3",
        ".woff",
        ".woff2",
        ".ttf",
        ".zip",
        ".pdf"
    }

    for file in files:

        if file.suffix.lower() in binary_extensions:
            continue

        content = read_file(file)

        if not content:
            continue

        line_count = len(content.splitlines())

        if line_count > MAX_FILE_LINES:

            findings.append({
                "type": "Large File",
                "file": str(file),
                "details": f"{line_count} lines",
                "severity": "MEDIUM",

                "why": (
                    "Large files are harder to navigate, "
                    "maintain and review."
                ),

                "recommendation": (
                    "Split the file into smaller, "
                    "focused modules or components."
                ),

                "priority": "MEDIUM"
            })

    return findings


# ============================================================
# TODO / FIXME CHECK
# ============================================================

def check_todos(files):

    findings = []

    for file in files:

        content = read_file(file)

        if not content:
            continue

        for line_number, line in enumerate(
            content.splitlines(),
            start=1
        ):

            if (
                "TODO" in line.upper()
                or "FIXME" in line.upper()
            ):

                findings.append({
                    "type": "TODO/FIXME",
                    "file": str(file),
                    "line": line_number,
                    "details": line.strip(),
                    "severity": "LOW",

                    "why": (
                        "TODO/FIXME markers usually indicate "
                        "unfinished or deferred work."
                    ),

                    "recommendation": (
                        "Resolve the task, convert it into "
                        "a tracked issue, or remove the marker."
                    ),

                    "priority": "LOW"
                })

    return findings


# ============================================================
# PYTHON LONG FUNCTIONS
# ============================================================

def check_long_functions(files):

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

            if isinstance(
                node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef
                )
            ):

                start = node.lineno

                end = getattr(
                    node,
                    "end_lineno",
                    start
                )

                length = end - start + 1

                if length > MAX_FUNCTION_LINES:

                    findings.append({
                        "type": "Long Function",
                        "file": str(file),
                        "function": node.name,
                        "line": start,
                        "details": f"{length} lines",
                        "severity": "MEDIUM",

                        "why": (
                            "Long functions often handle "
                            "multiple responsibilities."
                        ),

                        "recommendation": (
                            "Break the function into smaller "
                            "single-purpose helper functions."
                        ),

                        "priority": "MEDIUM"
                    })

    return findings


# ============================================================
# PYTHON COMPLEXITY
# ============================================================

def calculate_function_complexity(function_node):

    complexity = 1

    for node in ast.walk(function_node):

        if isinstance(
            node,
            (
                ast.If,
                ast.For,
                ast.While,
                ast.AsyncFor,
                ast.ExceptHandler,
                ast.With,
                ast.AsyncWith
            )
        ):

            complexity += 1

        elif isinstance(node, ast.BoolOp):

            complexity += len(node.values) - 1

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

            if isinstance(
                node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef
                )
            ):

                complexity = calculate_function_complexity(
                    node
                )

                if complexity >= 10:

                    findings.append({
                        "type": "High Complexity",
                        "file": str(file),
                        "function": node.name,
                        "line": node.lineno,
                        "details": (
                            f"Complexity: {complexity}"
                        ),
                        "severity": "HIGH",

                        "why": (
                            "Many decision paths make the "
                            "function harder to test and maintain."
                        ),

                        "recommendation": (
                            "Split complex logic into smaller "
                            "functions and simplify conditions."
                        ),

                        "priority": "HIGH"
                    })

                elif complexity >= 6:

                    findings.append({
                        "type": "Moderate Complexity",
                        "file": str(file),
                        "function": node.name,
                        "line": node.lineno,
                        "details": (
                            f"Complexity: {complexity}"
                        ),
                        "severity": "MEDIUM",

                        "why": (
                            "The function contains several "
                            "decision paths."
                        ),

                        "recommendation": (
                            "Consider extracting conditional "
                            "logic into helper functions."
                        ),

                        "priority": "MEDIUM"
                    })

    return findings


# ============================================================
# JAVASCRIPT FUNCTION DETECTION
# ============================================================

def _find_js_functions(content):

    functions = []

    patterns = [

        # function name() {}
        re.compile(
            r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\("
        ),

        # const name = (...) =>
        re.compile(
            r"\b(?:const|let|var)\s+"
            r"([A-Za-z_$][\w$]*)\s*="
            r"\s*(?:async\s*)?"
            r"(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"
        )
    ]

    for pattern in patterns:

        for match in pattern.finditer(content):

            name = match.group(1)

            line = (
                content[:match.start()].count("\n")
                + 1
            )

            functions.append({
                "name": name,
                "line": line
            })

    unique = {}

    for function in functions:

        key = (
            function["name"],
            function["line"]
        )

        unique[key] = function

    return sorted(
        unique.values(),
        key=lambda item: item["line"]
    )


# ============================================================
# JAVASCRIPT FUNCTION LENGTH
# ============================================================

def check_long_javascript_functions(files):

    findings = []

    for file in files:

        if file.suffix.lower() not in JS_EXTENSIONS:
            continue

        content = read_file(file)

        if not content:
            continue

        lines = content.splitlines()

        functions = _find_js_functions(content)

        for index, function in enumerate(functions):

            start_line = function["line"]

            if index + 1 < len(functions):

                next_start = functions[index + 1]["line"]

                length = next_start - start_line

            else:

                length = (
                    len(lines)
                    - start_line
                    + 1
                )

            if length > MAX_JS_FUNCTION_LINES:

                findings.append({
                    "type": "Long JavaScript Function",
                    "file": str(file),
                    "function": function["name"],
                    "line": start_line,
                    "details": f"{length} lines",
                    "severity": "MEDIUM",

                    "why": (
                        "Large JavaScript functions often "
                        "contain multiple responsibilities."
                    ),

                    "recommendation": (
                        "Extract reusable logic into smaller "
                        "helper functions or components."
                    ),

                    "priority": "MEDIUM"
                })

    return findings


# ============================================================
# JAVASCRIPT COMPLEXITY
# ============================================================

def calculate_javascript_complexity(content):

    complexity = 1

    complexity += len(
        re.findall(
            r"\bif\s*\(",
            content
        )
    )

    complexity += len(
        re.findall(
            r"\belse\s+if\s*\(",
            content
        )
    )

    complexity += len(
        re.findall(
            r"\bfor\s*\(",
            content
        )
    )

    complexity += len(
        re.findall(
            r"\bwhile\s*\(",
            content
        )
    )

    complexity += len(
        re.findall(
            r"\bswitch\s*\(",
            content
        )
    )

    complexity += len(
        re.findall(
            r"\?",
            content
        )
    )

    complexity += len(
        re.findall(
            r"&&|\|\|",
            content
        )
    )

    return complexity


def analyze_javascript_quality(files):

    findings = []

    for file in files:

        if file.suffix.lower() not in JS_EXTENSIONS:
            continue

        content = read_file(file)

        if not content:
            continue

        # ----------------------------------------------------
        # Function length
        # ----------------------------------------------------

        findings.extend(
            check_long_javascript_functions(
                [file]
            )
        )

        # ----------------------------------------------------
        # Complexity
        # ----------------------------------------------------

        complexity = calculate_javascript_complexity(
            content
        )

        functions = _find_js_functions(content)

        function_name = (
            functions[0]["name"]
            if functions
            else "Module"
        )

        function_line = (
            functions[0]["line"]
            if functions
            else 1
        )

        if complexity >= 20:

            findings.append({
                "type": "High JavaScript Complexity",
                "file": str(file),
                "function": function_name,
                "line": function_line,
                "details": (
                    f"Estimated complexity: "
                    f"{complexity}"
                ),
                "severity": "HIGH",

                "why": (
                    "High branching and conditional logic "
                    "creates many possible execution paths."
                ),

                "recommendation": (
                    "Split the component into smaller "
                    "components and move business logic "
                    "into dedicated helper modules."
                ),

                "priority": "HIGH"
            })

        elif complexity >= 10:

            findings.append({
                "type": "Moderate JavaScript Complexity",
                "file": str(file),
                "function": function_name,
                "line": function_line,
                "details": (
                    f"Estimated complexity: "
                    f"{complexity}"
                ),
                "severity": "MEDIUM",

                "why": (
                    "The file contains several conditional "
                    "execution paths."
                ),

                "recommendation": (
                    "Consider simplifying conditions or "
                    "extracting complex logic."
                ),

                "priority": "MEDIUM"
            })

    return findings