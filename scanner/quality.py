import ast
from pathlib import Path


# ============================================================
# QUALITY THRESHOLDS
# ============================================================

MAX_SOURCE_FILE_LINES = 500
MAX_CSS_LINES = 5000
MAX_JS_LINES = 500
MAX_FUNCTION_LINES = 50


# ============================================================
# FILE TYPES
# ============================================================

SOURCE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".cpp",
    ".c",
    ".h",
    ".hpp",
    ".go",
    ".rs",
    ".php",
    ".kt",
}

CSS_EXTENSIONS = {
    ".css",
    ".scss",
    ".sass",
    ".less",
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

    except (
        PermissionError,
        OSError
    ):

        return ""


# ============================================================
# LARGE FILE DETECTION
# ============================================================

def check_large_files(files):

    findings = []

    for file in files:

        extension = file.suffix.lower()

        # ----------------------------------------------------
        # Ignore non-source/binary files
        # ----------------------------------------------------

        if extension not in SOURCE_EXTENSIONS | CSS_EXTENSIONS:
            continue

        content = read_file(file)

        if not content:
            continue

        line_count = len(
            content.splitlines()
        )

        # ----------------------------------------------------
        # CSS gets a larger threshold
        # ----------------------------------------------------

        if extension in CSS_EXTENSIONS:

            if line_count > MAX_CSS_LINES:

                findings.append({

                    "type": "Large Stylesheet",

                    "file": str(file),

                    "details":
                        f"{line_count} lines",

                    "severity": "LOW"

                })

        # ----------------------------------------------------
        # Source code
        # ----------------------------------------------------

        else:

            threshold = MAX_SOURCE_FILE_LINES

            if extension in {
                ".js",
                ".jsx",
                ".ts",
                ".tsx"
            }:

                threshold = MAX_JS_LINES


            if line_count > threshold:

                findings.append({

                    "type": "Large Source File",

                    "file": str(file),

                    "details":
                        f"{line_count} lines",

                    "severity": "MEDIUM"

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

        for line_number, line in enumerate(
            content.splitlines(),
            start=1
        ):

            upper_line = line.upper()

            if (
                "TODO" in upper_line
                or "FIXME" in upper_line
            ):

                findings.append({

                    "type": "TODO/FIXME",

                    "file": str(file),

                    "line": line_number,

                    "details": line.strip(),

                    "severity": "LOW"

                })

    return findings


# ============================================================
# LONG FUNCTION DETECTION
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


        lines = content.splitlines()


        for node in ast.walk(tree):

            if not isinstance(
                node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef
                )
            ):

                continue


            if not hasattr(
                node,
                "end_lineno"
            ):

                continue


            length = (
                node.end_lineno
                - node.lineno
                + 1
            )


            if length > MAX_FUNCTION_LINES:

                findings.append({

                    "type": "Long Function",

                    "file": str(file),

                    "function": node.name,

                    "line": node.lineno,

                    "details":
                        f"{length} lines",

                    "severity": "MEDIUM"

                })

    return findings


# ============================================================
# FUNCTION COMPLEXITY
# ============================================================

def calculate_function_complexity(
    function_node
):

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
                ast.AsyncWith,
                ast.Assert
            )
        ):

            complexity += 1


        elif isinstance(
            node,
            ast.BoolOp
        ):

            complexity += (
                len(node.values) - 1
            )


        elif isinstance(
            node,
            ast.IfExp
        ):

            complexity += 1


    return complexity


# ============================================================
# PYTHON COMPLEXITY ANALYSIS
# ============================================================

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

            if not isinstance(
                node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef
                )
            ):

                continue


            complexity = (
                calculate_function_complexity(node)
            )


            if complexity >= 10:

                findings.append({

                    "type": "High Complexity",

                    "file": str(file),

                    "function": node.name,

                    "line": node.lineno,

                    "details":
                        f"Complexity: {complexity}",

                    "severity": "HIGH"

                })


            elif complexity >= 6:

                findings.append({

                    "type": "Moderate Complexity",

                    "file": str(file),

                    "function": node.name,

                    "line": node.lineno,

                    "details":
                        f"Complexity: {complexity}",

                    "severity": "MEDIUM"

                })

    return findings