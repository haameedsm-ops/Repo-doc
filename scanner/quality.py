import ast
import re

from tree_sitter import Parser
import tree_sitter_javascript


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
# TREE-SITTER JAVASCRIPT PARSER
# ============================================================

def _create_javascript_parser():

    parser = Parser()

    parser.language = (
        tree_sitter_javascript.language()
    )

    return parser


# ============================================================
# TREE-SITTER FUNCTION DETECTION
# ============================================================

def _find_tree_sitter_functions(content):

    parser = _create_javascript_parser()

    source = content.encode(
        "utf-8",
        errors="ignore"
    )

    tree = parser.parse(source)

    functions = []

    function_node_types = {
        "function_declaration",
        "function",
        "arrow_function",
        "method_definition"
    }

    def walk(node):

        if node.type in function_node_types:

            functions.append(node)

        for child in node.children:

            walk(child)

    walk(tree.root_node)

    return tree, functions


# ============================================================
# TREE-SITTER FUNCTION NAME
# ============================================================

def _get_function_name(node, source):

    parent = node.parent

    # --------------------------------------------------------
    # Named function declaration
    # --------------------------------------------------------

    if node.type == "function_declaration":

        name_node = node.child_by_field_name(
            "name"
        )

        if name_node:

            return source[
                name_node.start_byte:
                name_node.end_byte
            ].decode(
                "utf-8",
                errors="ignore"
            )


    # --------------------------------------------------------
    # Arrow function / assigned function
    # --------------------------------------------------------

    if parent:

        if parent.type in {
            "variable_declarator",
            "pair"
        }:

            name_node = parent.child_by_field_name(
                "name"
            )

            if name_node:

                return source[
                    name_node.start_byte:
                    name_node.end_byte
                ].decode(
                    "utf-8",
                    errors="ignore"
                )


    # --------------------------------------------------------
    # Method definition
    # --------------------------------------------------------

    if node.type == "method_definition":

        name_node = node.child_by_field_name(
            "name"
        )

        if name_node:

            return source[
                name_node.start_byte:
                name_node.end_byte
            ].decode(
                "utf-8",
                errors="ignore"
            )


    return "Anonymous Function"


# ============================================================
# TREE-SITTER COMPLEXITY
# ============================================================

def calculate_tree_sitter_complexity(node):

    complexity = 1

    decision_nodes = {
        "if_statement",
        "for_statement",
        "for_in_statement",
        "while_statement",
        "do_statement",
        "switch_case",
        "catch_clause",
        "ternary_expression"
    }

    logical_nodes = {
        "&&",
        "||",
        "??"
    }

    def walk(current):

        nonlocal complexity

        if current is not node:

            if current.type in decision_nodes:

                complexity += 1

            elif current.type in logical_nodes:

                complexity += 1

        for child in current.children:

            walk(child)

    walk(node)

    return complexity


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

        source = content.encode(
            "utf-8",
            errors="ignore"
        )

        try:

            tree, functions = (
                _find_tree_sitter_functions(
                    content
                )
            )

        except Exception:

            continue

        for node in functions:

            start_line = node.start_point[0] + 1

            end_line = node.end_point[0] + 1

            length = (
                end_line
                - start_line
                + 1
            )

            if length > MAX_JS_FUNCTION_LINES:

                name = _get_function_name(
                    node,
                    source
                )

                findings.append({
                    "type": "Long JavaScript Function",
                    "file": str(file),
                    "function": name,
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
# JAVASCRIPT COMPLEXITY ANALYSIS
# ============================================================

def analyze_javascript_quality(files):

    findings = []

    for file in files:

        if file.suffix.lower() not in JS_EXTENSIONS:
            continue

        content = read_file(file)

        if not content:
            continue

        source = content.encode(
            "utf-8",
            errors="ignore"
        )

        try:

            tree, functions = (
                _find_tree_sitter_functions(
                    content
                )
            )

        except Exception:

            continue

        # ----------------------------------------------------
        # Function-level analysis
        # ----------------------------------------------------

        for node in functions:

            name = _get_function_name(
                node,
                source
            )

            start_line = node.start_point[0] + 1

            end_line = node.end_point[0] + 1

            length = (
                end_line
                - start_line
                + 1
            )

            # ------------------------------------------------
            # Function length
            # ------------------------------------------------

            if length > MAX_JS_FUNCTION_LINES:

                findings.append({
                    "type": "Long JavaScript Function",
                    "file": str(file),
                    "function": name,
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

            # ------------------------------------------------
            # Complexity
            # ------------------------------------------------

            complexity = (
                calculate_tree_sitter_complexity(
                    node
                )
            )

            if complexity >= 20:

                findings.append({
                    "type": "High JavaScript Complexity",
                    "file": str(file),
                    "function": name,
                    "line": start_line,
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
                        "Split the function into smaller "
                        "functions, simplify conditions, and "
                        "move business logic into dedicated "
                        "helper modules."
                    ),
                    "priority": "HIGH"
                })

            elif complexity >= 10:

                findings.append({
                    "type": "Moderate JavaScript Complexity",
                    "file": str(file),
                    "function": name,
                    "line": start_line,
                    "details": (
                        f"Estimated complexity: "
                        f"{complexity}"
                    ),
                    "severity": "MEDIUM",
                    "why": (
                        "The function contains several "
                        "conditional execution paths."
                    ),
                    "recommendation": (
                        "Consider simplifying conditions or "
                        "extracting complex logic into helper "
                        "functions."
                    ),
                    "priority": "MEDIUM"
                })

    return findings