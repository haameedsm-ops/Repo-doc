from __future__ import annotations

import ast
import re
from collections import Counter
from pathlib import Path
from typing import Any


# ============================================================
# DEFAULT CONFIGURATION
# ============================================================

LARGE_FILE_THRESHOLDS = {
    ".py": 500,
    ".js": 800,
    ".jsx": 800,
    ".ts": 800,
    ".tsx": 800,
    ".css": 1200,
    ".scss": 1200,
    ".sass": 1200,
    ".less": 1200,
    ".html": 1000,
    ".htm": 1000,
}

DEFAULT_MAX_FILE_LINES = 1000

LONG_FUNCTION_LINES = 80

PYTHON_COMPLEXITY_THRESHOLD = 10
JAVASCRIPT_COMPLEXITY_THRESHOLD = 10

DUPLICATE_MIN_LINES = 8
DUPLICATE_SIMILARITY = 0.85


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
    "vite.config.mjs",
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
# LANGUAGE HELPERS
# ============================================================

def _get_file_type(file: Path) -> str:
    """Return a human-readable file type."""

    extension = file.suffix.lower()

    mapping = {
        ".py": "Python",
        ".js": "JavaScript",
        ".jsx": "JavaScript",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
        ".css": "CSS",
        ".scss": "SCSS",
        ".sass": "Sass",
        ".less": "LESS",
        ".html": "HTML",
        ".htm": "HTML",
    }

    return mapping.get(
        extension,
        extension.lstrip(".").upper() or "Unknown",
    )


def _get_file_line_threshold(
    file: Path,
    config: dict[str, Any] | None = None,
) -> int:
    """
    Return the configured line threshold for a file.

    Priority:

    1. Repository .repo-doctor.json threshold
    2. Extension-specific default
    3. Global default
    """

    suffix = file.suffix.lower()

    # --------------------------------------------------------
    # Repository configuration
    # --------------------------------------------------------

    if config:
        thresholds = config.get("thresholds", {})

        if isinstance(thresholds, dict):
            language = _get_file_type(file)

            language_key = {
                "Python": "python",
                "JavaScript": "javascript",
                "TypeScript": "javascript",
                "CSS": "css",
                "SCSS": "css",
                "Sass": "css",
                "LESS": "css",
                "HTML": "html",
            }.get(language)

            if language_key:
                custom_threshold = thresholds.get(language_key)

                if (
                    isinstance(custom_threshold, int)
                    and not isinstance(custom_threshold, bool)
                    and custom_threshold > 0
                ):
                    return custom_threshold

    # --------------------------------------------------------
    # Extension defaults
    # --------------------------------------------------------

    return LARGE_FILE_THRESHOLDS.get(
        suffix,
        DEFAULT_MAX_FILE_LINES,
    )


def _get_file_category(file: Path) -> str:
    """
    Classify a source file.

    Categories:

        source
        test
        generated
        config
    """

    parts = {
        part.lower()
        for part in file.parts
    }

    name = file.name.lower()

    # --------------------------------------------------------
    # Test files
    # --------------------------------------------------------

    if parts.intersection(TEST_PARTS):
        return "test"

    if (
        ".test." in name
        or ".spec." in name
        or name.endswith("_test.py")
        or name.startswith("test_")
    ):
        return "test"

    # --------------------------------------------------------
    # Generated files
    # --------------------------------------------------------

    if parts.intersection(GENERATED_PARTS):
        return "generated"

    # --------------------------------------------------------
    # Configuration files
    # --------------------------------------------------------

    if name in CONFIG_NAMES:
        return "config"

    return "source"


# ============================================================
# SEVERITY
# ============================================================

def _get_large_file_severity(
    line_count: int,
    threshold: int,
) -> str:
    """Calculate severity based on file size."""

    if threshold <= 0:
        return "HIGH"

    ratio = line_count / threshold

    if ratio >= 3:
        return "HIGH"

    if ratio >= 1.75:
        return "MEDIUM"

    return "LOW"


# ============================================================
# SAFE FILE READING
# ============================================================

def _read_file(file: Path) -> str:
    """Read a source file safely."""

    try:
        return file.read_text(
            encoding="utf-8",
            errors="ignore",
        )
    except (OSError, UnicodeError):
        return ""


def _line_count(text: str) -> int:
    """Count source lines."""

    if not text:
        return 0

    return len(text.splitlines())


# ============================================================
# LARGE FILE DETECTION
# ============================================================

def check_large_files(
    files: list[Path],
    config: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Detect files exceeding language-specific thresholds.

    Generated files are ignored.
    """

    findings = []

    for file in files:

        category = _get_file_category(file)

        if category == "generated":
            continue

        text = _read_file(file)

        if not text:
            continue

        lines = _line_count(text)

        threshold = _get_file_line_threshold(
            file,
            config,
        )

        if lines <= threshold:
            continue

        over_percentage = (
            (lines - threshold)
            / threshold
            * 100
        )

        severity = _get_large_file_severity(
            lines,
            threshold,
        )

        file_type = _get_file_type(file)

        findings.append({
            "type": "Large File",
            "file": str(file),
            "severity": severity,
            "priority": severity,
            "confidence": 100,
            "lines": lines,
            "threshold": threshold,
            "over_percentage": round(
                over_percentage,
                1,
            ),
            "details": (
                f"Type: {file_type} | "
                f"Lines: {lines} | "
                f"Threshold: {threshold} | "
                f"Over threshold: "
                f"{over_percentage:.1f}%"
            ),
            "why": (
                f"This {file_type} file contains "
                f"{lines} lines, exceeding the "
                f"recommended {threshold}-line "
                f"threshold. Large files are harder "
                f"to navigate, maintain, test and review."
            ),
            "recommendation": (
                "Consider splitting this file into "
                "smaller focused modules or components."
            ),
        })

    return findings


# ============================================================
# PYTHON AST HELPERS
# ============================================================

def _parse_python(
    file: Path,
    text: str,
) -> ast.AST | None:
    """Parse Python safely."""

    try:
        return ast.parse(
            text,
            filename=str(file),
        )
    except (
        SyntaxError,
        ValueError,
        TypeError,
    ):
        return None


def _python_imports(
    tree: ast.AST,
) -> list[tuple[str, int]]:
    """Collect imported symbols and line numbers."""

    imports = []

    for node in ast.walk(tree):

        if isinstance(node, ast.Import):

            for alias in node.names:

                name = (
                    alias.asname
                    or alias.name.split(".")[0]
                )

                imports.append(
                    (
                        name,
                        node.lineno,
                    )
                )

        elif isinstance(node, ast.ImportFrom):

            for alias in node.names:

                if alias.name == "*":
                    continue

                name = (
                    alias.asname
                    or alias.name
                )

                imports.append(
                    (
                        name,
                        node.lineno,
                    )
                )

    return imports


def _python_unused_imports(
    tree: ast.AST,
) -> list[tuple[str, int]]:
    """Find Python imports that are never referenced."""

    imports = _python_imports(tree)

    if not imports:
        return []

    used_names = set()

    for node in ast.walk(tree):

        if isinstance(node, ast.Name):
            used_names.add(node.id)

    unused = []

    for name, line in imports:

        if name not in used_names:
            unused.append(
                (
                    name,
                    line,
                )
            )

    return unused


# ============================================================
# PYTHON COMPLEXITY
# ============================================================

def _calculate_python_complexity(
    node: ast.AST,
) -> int:
    """
    Approximate cyclomatic complexity.
    """

    complexity = 1

    for child in ast.walk(node):

        if isinstance(
            child,
            (
                ast.If,
                ast.For,
                ast.AsyncFor,
                ast.While,
                ast.IfExp,
                ast.ExceptHandler,
                ast.With,
                ast.AsyncWith,
                ast.Assert,
            ),
        ):
            complexity += 1

        elif isinstance(child, ast.BoolOp):

            complexity += max(
                0,
                len(child.values) - 1,
            )

        elif isinstance(child, ast.comprehension):

            complexity += 1

    return complexity


def analyze_python_complexity(
    file: Path,
    text: str,
) -> list[dict[str, Any]]:
    """Analyze Python function complexity."""

    tree = _parse_python(
        file,
        text,
    )

    if tree is None:
        return []

    findings = []

    for node in ast.walk(tree):

        if not isinstance(
            node,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
            ),
        ):
            continue

        complexity = _calculate_python_complexity(
            node
        )

        if complexity <= PYTHON_COMPLEXITY_THRESHOLD:
            continue

        severity = (
            "HIGH"
            if complexity >= 20
            else "MEDIUM"
        )

        findings.append({
            "type": "High Python Complexity",
            "file": str(file),
            "line": node.lineno,
            "function": node.name,
            "complexity": complexity,
            "threshold": PYTHON_COMPLEXITY_THRESHOLD,
            "severity": severity,
            "priority": severity,
            "confidence": 95,
            "details": (
                f"Cyclomatic complexity: "
                f"{complexity} "
                f"(threshold: "
                f"{PYTHON_COMPLEXITY_THRESHOLD})"
            ),
            "why": (
                "Highly complex functions are harder "
                "to understand, test and maintain."
            ),
            "recommendation": (
                "Split the function into smaller "
                "focused functions and reduce "
                "nested branching."
            ),
        })

    return findings


# ============================================================
# LONG PYTHON FUNCTIONS
# ============================================================

def _python_function_length(
    node: ast.AST,
) -> int:
    """Return approximate source length."""

    start_line = getattr(
        node,
        "lineno",
        1,
    )

    end_line = getattr(
        node,
        "end_lineno",
        start_line,
    )

    return max(
        1,
        end_line - start_line + 1,
    )


def check_python_long_functions(
    file: Path,
    text: str,
) -> list[dict[str, Any]]:
    """Detect unusually long Python functions."""

    tree = _parse_python(
        file,
        text,
    )

    if tree is None:
        return []

    findings = []

    for node in ast.walk(tree):

        if not isinstance(
            node,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
            ),
        ):
            continue

        length = _python_function_length(node)

        if length <= LONG_FUNCTION_LINES:
            continue

        severity = (
            "HIGH"
            if length >= LONG_FUNCTION_LINES * 2
            else "MEDIUM"
        )

        findings.append({
            "type": "Long Function",
            "file": str(file),
            "line": node.lineno,
            "function": node.name,
            "lines": length,
            "threshold": LONG_FUNCTION_LINES,
            "severity": severity,
            "priority": severity,
            "confidence": 100,
            "details": (
                f"Function length: {length} lines "
                f"(threshold: {LONG_FUNCTION_LINES})"
            ),
            "why": (
                "Long functions are harder to "
                "understand, test and maintain."
            ),
            "recommendation": (
                "Break this function into smaller "
                "single-purpose functions."
            ),
        })

    return findings


# ============================================================
# JAVASCRIPT IMPORT DETECTION
# ============================================================

JS_IMPORT_PATTERN = re.compile(
    r"""
    ^\s*
    import
    \s+
    (?:
        (?P<default>[A-Za-z_$][\w$]*)
        (?:\s*,\s*)?
    )?
    (?:
        \{
            (?P<named>[^}]+)
        \}
    )?
    (?:\s+from\s+)?
    ["'][^"']+["']
    \s*;?
    """,
    re.MULTILINE | re.VERBOSE,
)


def _extract_js_imports(
    text: str,
) -> list[tuple[str, int]]:
    """Extract imported identifiers."""

    imports = []

    for match in JS_IMPORT_PATTERN.finditer(text):

        line = (
            text.count(
                "\n",
                0,
                match.start(),
            )
            + 1
        )

        default_name = match.group("default")

        if default_name:
            imports.append(
                (
                    default_name,
                    line,
                )
            )

        named = match.group("named")

        if named:

            for item in named.split(","):

                item = item.strip()

                if not item:
                    continue

                parts = re.split(
                    r"\s+as\s+",
                    item,
                    maxsplit=1,
                )

                identifier = parts[-1].strip()

                identifier = re.sub(
                    r"^\s*type\s+",
                    "",
                    identifier,
                )

                if re.match(
                    r"^[A-Za-z_$][\w$]*$",
                    identifier,
                ):
                    imports.append(
                        (
                            identifier,
                            line,
                        )
                    )

    return imports


# ============================================================
# JAVASCRIPT TOKEN USAGE
# ============================================================

JS_IDENTIFIER_PATTERN = re.compile(
    r"\b[A-Za-z_$][\w$]*\b"
)


def _strip_js_comments_and_strings(
    text: str,
) -> str:
    """
    Remove JavaScript comments and string contents.

    This is intentionally lightweight rather than a full
    JavaScript parser.
    """

    pattern = re.compile(
        r"""
        //.*?$ |
        /\*.*?\*/ |
        "(?:\\.|[^"\\])*" |
        '(?:\\.|[^'\\])*' |
        `(?:\\.|[^`\\])*`
        """,
        re.MULTILINE | re.DOTALL | re.VERBOSE,
    )

    return pattern.sub(
        " ",
        text,
    )


# ============================================================
# JAVASCRIPT UNUSED IMPORTS
# ============================================================

def analyze_javascript_unused_imports(
    file: Path,
    text: str,
) -> list[dict[str, Any]]:
    """Detect unused JavaScript/TypeScript imports."""

    imports = _extract_js_imports(text)

    if not imports:
        return []

    cleaned = _strip_js_comments_and_strings(text)

    cleaned = JS_IMPORT_PATTERN.sub(
        " ",
        cleaned,
    )

    identifiers = Counter(
        JS_IDENTIFIER_PATTERN.findall(
            cleaned
        )
    )

    findings = []

    has_jsx = bool(
        re.search(
            r"<[A-Za-z][^>]*>",
            text,
        )
    )

    for name, line in imports:

        # React may not appear explicitly in modern JSX.
        if name == "React" and has_jsx:
            continue

        if identifiers[name] > 0:
            continue

        findings.append({
            "type": "Unused JavaScript Import",
            "file": str(file),
            "line": line,
            "severity": "LOW",
            "priority": "LOW",
            "confidence": 90,
            "details": (
                f"Unused import: {name}"
            ),
            "why": (
                "This imported symbol does not appear "
                "to be referenced in the file."
            ),
            "recommendation": (
                "Remove the unused import to reduce "
                "bundle clutter and improve "
                "maintainability."
            ),
        })

    return findings


# ============================================================
# JAVASCRIPT COMPLEXITY
# ============================================================

JS_BRANCH_PATTERNS = {
    "if": r"\bif\s*\(",
    "for": r"\bfor\s*\(",
    "while": r"\bwhile\s*\(",
    "catch": r"\bcatch\s*\(",
    "switch": r"\bswitch\s*\(",
    "case": r"\bcase\s+",
    "ternary": r"\?(?![?.])",
    "nullish": r"\?\?",
    "and": r"&&",
    "or": r"\|\|",
}


def _javascript_complexity(
    text: str,
) -> int:
    """Approximate cyclomatic complexity."""

    cleaned = _strip_js_comments_and_strings(
        text
    )

    complexity = 1

    for pattern in JS_BRANCH_PATTERNS.values():

        complexity += len(
            re.findall(
                pattern,
                cleaned,
            )
        )

    return complexity


def _find_matching_brace(
    text: str,
    opening_brace: int,
) -> int | None:
    """
    Find the closing brace matching an opening brace.

    This intentionally handles balanced braces and is not
    intended to replace a complete JavaScript parser.
    """

    depth = 0

    for index in range(
        opening_brace,
        len(text),
    ):

        char = text[index]

        if char == "{":
            depth += 1

        elif char == "}":

            depth -= 1

            if depth == 0:
                return index + 1

    return None


def _extract_javascript_functions(
    text: str,
) -> list[tuple[str, int, str]]:
    """
    Extract common JavaScript/TypeScript function-like blocks.

    Returns:

        (function_name, starting_line, function_body)
    """

    functions = []

    patterns = [

        # ----------------------------------------------------
        # function foo(...) {
        # ----------------------------------------------------

        re.compile(
            r"\bfunction\s+"
            r"([A-Za-z_$][\w$]*)"
            r"\s*\([^)]*\)\s*\{",
            re.MULTILINE,
        ),

        # ----------------------------------------------------
        # async function foo(...) {
        # ----------------------------------------------------

        re.compile(
            r"\basync\s+function\s+"
            r"([A-Za-z_$][\w$]*)"
            r"\s*\([^)]*\)\s*\{",
            re.MULTILINE,
        ),

        # ----------------------------------------------------
        # const foo = (...) => {
        # ----------------------------------------------------

        re.compile(
            r"\b(?:const|let|var)\s+"
            r"([A-Za-z_$][\w$]*)"
            r"\s*=\s*"
            r"(?:async\s*)?"
            r"(?:\([^)]*\)|[A-Za-z_$][\w$]*)"
            r"\s*=>\s*\{",
            re.MULTILINE,
        ),

        # ----------------------------------------------------
        # method(...) {
        # ----------------------------------------------------

        re.compile(
            r"^\s*(?:async\s+)?"
            r"([A-Za-z_$][\w$]*)"
            r"\s*\([^)]*\)\s*\{",
            re.MULTILINE,
        ),
    ]

    seen = set()

    for pattern in patterns:

        for match in pattern.finditer(text):

            name = match.group(1)

            start = match.start()

            line = (
                text.count(
                    "\n",
                    0,
                    start,
                )
                + 1
            )

            key = (
                name,
                line,
            )

            if key in seen:
                continue

            seen.add(key)

            opening_brace = text.find(
                "{",
                match.start(),
            )

            if opening_brace == -1:
                continue

            end = _find_matching_brace(
                text,
                opening_brace,
            )

            if end is None:
                continue

            body = text[
                start:end
            ]

            functions.append(
                (
                    name,
                    line,
                    body,
                )
            )

    return functions


def analyze_javascript_complexity(
    file: Path,
    text: str,
) -> list[dict[str, Any]]:
    """
    Analyze JavaScript/TypeScript complexity per function.
    """

    functions = _extract_javascript_functions(
        text
    )

    if not functions:
        return []

    findings = []

    for name, line, body in functions:

        complexity = _javascript_complexity(
            body
        )

        if complexity <= JAVASCRIPT_COMPLEXITY_THRESHOLD:
            continue

        # ----------------------------------------------------
        # Severity
        # ----------------------------------------------------

        if complexity >= 20:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        # ----------------------------------------------------
        # Finding
        # ----------------------------------------------------

        findings.append({
            "type": "High JavaScript Complexity",
            "file": str(file),
            "line": line,
            "function": name,
            "complexity": complexity,
            "threshold": JAVASCRIPT_COMPLEXITY_THRESHOLD,
            "severity": severity,
            "priority": severity,
            "confidence": 80,
            "details": (
                f"Function '{name}' estimated "
                f"complexity: {complexity} "
                f"(threshold: "
                f"{JAVASCRIPT_COMPLEXITY_THRESHOLD})"
            ),
            "why": (
                "Highly complex functions are harder "
                "to understand, test and maintain."
            ),
            "recommendation": (
                "Split this function into smaller "
                "focused functions and reduce "
                "nested conditions."
            ),
        })

    return findings


# ============================================================
# TODO / FIXME
# ============================================================

TODO_PATTERN = re.compile(
    r"\b(TODO|FIXME|XXX|HACK)\b",
    re.IGNORECASE,
)


def check_todos(
    file: Path,
    text: str,
) -> list[dict[str, Any]]:
    """Detect TODO/FIXME-style markers."""

    findings = []

    for match in TODO_PATTERN.finditer(text):

        line = (
            text.count(
                "\n",
                0,
                match.start(),
            )
            + 1
        )

        marker = match.group(1).upper()

        findings.append({
            "type": f"{marker} Marker",
            "file": str(file),
            "line": line,
            "severity": "LOW",
            "priority": "LOW",
            "confidence": 100,
            "details": (
                f"Found {marker} marker."
            ),
            "why": (
                "Unresolved TODO/FIXME markers can "
                "indicate unfinished work or "
                "technical debt."
            ),
            "recommendation": (
                "Review the marker and either complete "
                "the work or convert it into a "
                "tracked issue."
            ),
        })

    return findings


# ============================================================
# NORMALIZATION FOR DUPLICATE DETECTION
# ============================================================

def _normalize_code_line(
    line: str,
) -> str:
    """Normalize a source line."""

    # Remove JavaScript comments.
    line = re.sub(
        r"//.*$",
        "",
        line,
    )

    # Remove Python comments.
    line = re.sub(
        r"#.*$",
        "",
        line,
    )

    # Normalize whitespace.
    line = re.sub(
        r"\s+",
        " ",
        line,
    )

    return line.strip()


def _code_blocks(
    file: Path,
    text: str,
) -> list[tuple[list[str], int]]:
    """
    Create normalized sliding blocks.

    Blank/comment-only lines are ignored.
    """

    lines = [
        _normalize_code_line(line)
        for line in text.splitlines()
    ]

    lines = [
        line
        for line in lines
        if line
    ]

    blocks = []

    if len(lines) < DUPLICATE_MIN_LINES:
        return blocks

    for index in range(
        len(lines) - DUPLICATE_MIN_LINES + 1
    ):

        block = lines[
            index:
            index + DUPLICATE_MIN_LINES
        ]

        blocks.append(
            (
                block,
                index + 1,
            )
        )

    return blocks


# ============================================================
# DUPLICATE CODE HELPERS
# ============================================================

def _similarity(
    a: list[str],
    b: list[str],
) -> float:
    """Calculate simple line-based similarity."""

    if len(a) != len(b):
        return 0.0

    if not a:
        return 0.0

    matches = sum(
        1
        for left, right in zip(a, b)
        if left == right
    )

    return matches / len(a)


def _extend_duplicate_block(
    first: list[str],
    second: list[str],
) -> int:
    """
    Determine the longest matching block length.

    The initial match is DUPLICATE_MIN_LINES long.
    This extends it while the following lines match.
    """

    length = min(
        len(first),
        len(second),
    )

    matched = 0

    for index in range(length):

        if first[index] != second[index]:
            break

        matched += 1

    return matched


# ============================================================
# DUPLICATE CODE
# ============================================================

def check_duplicate_code(
    files: list[Path],
) -> list[dict[str, Any]]:
    """
    Detect repeated blocks across source files.

    IMPORTANT:

    The old implementation could report the same duplicated
    region many times because every sliding 8-line window
    created another finding.

    This implementation:

    1. Finds candidate matching blocks.
    2. Groups results by file pair.
    3. Keeps only the strongest match for each pair.
    4. Prevents duplicate reports for the same region.
    """

    blocks_by_file = {}

    # --------------------------------------------------------
    # Collect blocks
    # --------------------------------------------------------

    for file in files:

        category = _get_file_category(file)

        if category == "generated":
            continue

        text = _read_file(file)

        if not text:
            continue

        blocks = _code_blocks(
            file,
            text,
        )

        if blocks:
            blocks_by_file[file] = blocks

    # --------------------------------------------------------
    # Compare files
    # --------------------------------------------------------

    findings = []

    file_list = list(
        blocks_by_file.keys()
    )

    # One finding per meaningful file pair.
    best_matches = {}

    for i in range(
        len(file_list)
    ):

        file_a = file_list[i]

        for j in range(
            i + 1,
            len(file_list),
        ):

            file_b = file_list[j]

            best_match = None

            blocks_a = blocks_by_file[file_a]
            blocks_b = blocks_by_file[file_b]

            for block_a, line_a in blocks_a:

                # ------------------------------------------------
                # Use first few normalized lines as a cheap
                # candidate signature.
                # ------------------------------------------------

                signature_a = tuple(
                    block_a[:3]
                )

                for block_b, line_b in blocks_b:

                    if signature_a != tuple(
                        block_b[:3]
                    ):
                        continue

                    similarity = _similarity(
                        block_a,
                        block_b,
                    )

                    if similarity < DUPLICATE_SIMILARITY:
                        continue

                    matched_lines = _extend_duplicate_block(
                        block_a,
                        block_b,
                    )

                    candidate = (
                        matched_lines,
                        similarity,
                        line_a,
                        line_b,
                    )

                    if (
                        best_match is None
                        or candidate[0] > best_match[0]
                        or (
                            candidate[0] == best_match[0]
                            and candidate[1] > best_match[1]
                        )
                    ):
                        best_match = candidate

            if best_match is None:
                continue

            matched_lines, similarity, line_a, line_b = (
                best_match
            )

            best_matches[
                (
                    str(file_a),
                    str(file_b),
                )
            ] = (
                matched_lines,
                similarity,
                line_a,
                line_b,
            )

    # --------------------------------------------------------
    # Create findings
    # --------------------------------------------------------

    for (
        file_a,
        file_b,
    ), (
        matched_lines,
        similarity,
        line_a,
        line_b,
    ) in best_matches.items():

        findings.append({
            "type": "Duplicate Code",
            "file": file_a,
            "line": line_a,
            "file_2": file_b,
            "line_2": line_b,
            "severity": "LOW",
            "priority": "LOW",
            "confidence": int(
                similarity * 100
            ),
            "duplicate_lines": matched_lines,
            "similarity": round(
                similarity,
                3,
            ),
            "details": (
                f"Repeated {matched_lines}-line "
                f"code block with "
                f"{similarity * 100:.0f}% similarity."
            ),
            "why": (
                "Duplicated code increases "
                "maintenance cost and can cause "
                "fixes to be applied in one location "
                "but missed in another."
            ),
            "recommendation": (
                "Consider extracting shared logic "
                "into a reusable function, component "
                "or module."
            ),
        })

    return findings


# ============================================================
# FINDING DEDUPLICATION
# ============================================================

def _finding_key(
    finding: dict[str, Any],
) -> tuple:
    """Create a stable identity for a finding."""

    return (
        finding.get("type"),
        finding.get("file"),
        finding.get("line"),
        finding.get("function"),
        finding.get("details"),
        finding.get("file_2"),
        finding.get("line_2"),
    )


def remove_duplicate_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Remove exact duplicate findings."""

    unique = []

    seen = set()

    for finding in findings:

        key = _finding_key(
            finding
        )

        if key in seen:
            continue

        seen.add(key)

        unique.append(
            finding
        )

    return unique


# ============================================================
# TEST-FILE ADJUSTMENT
# ============================================================

def _adjust_test_finding(
    finding: dict[str, Any],
) -> dict[str, Any]:
    """Add context when a finding belongs to a test file."""

    path = Path(
        finding.get(
            "file",
            "",
        )
    )

    if _get_file_category(path) != "test":
        return finding

    adjusted = dict(finding)

    adjusted["test_file"] = True

    return adjusted


# ============================================================
# MAIN QUALITY ANALYZER
# ============================================================

def analyze_quality(
    files: list[Path],
    config: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Run the complete Repo Doctor quality analysis.

    Public API:

        analyze_quality(files, config)
    """

    findings = []

    # --------------------------------------------------------
    # Large files
    # --------------------------------------------------------

    findings.extend(
        check_large_files(
            files,
            config,
        )
    )

    # --------------------------------------------------------
    # Per-file analysis
    # --------------------------------------------------------

    for file in files:

        extension = file.suffix.lower()

        category = _get_file_category(
            file
        )

        if category == "generated":
            continue

        text = _read_file(file)

        if not text:
            continue

        # ----------------------------------------------------
        # TODO / FIXME
        # ----------------------------------------------------

        findings.extend(
            check_todos(
                file,
                text,
            )
        )

        # ----------------------------------------------------
        # Python
        # ----------------------------------------------------

        if extension == ".py":

            tree = _parse_python(
                file,
                text,
            )

            if tree is not None:

                for name, line in _python_unused_imports(
                    tree
                ):

                    findings.append({
                        "type": "Unused Python Import",
                        "file": str(file),
                        "line": line,
                        "severity": "LOW",
                        "priority": "LOW",
                        "confidence": 95,
                        "details": (
                            f"Unused import: {name}"
                        ),
                        "why": (
                            "This imported symbol does not "
                            "appear to be referenced in "
                            "the file."
                        ),
                        "recommendation": (
                            "Remove the unused import to "
                            "reduce clutter and improve "
                            "maintainability."
                        ),
                    })

            findings.extend(
                analyze_python_complexity(
                    file,
                    text,
                )
            )

            findings.extend(
                check_python_long_functions(
                    file,
                    text,
                )
            )

        # ----------------------------------------------------
        # JavaScript / TypeScript
        # ----------------------------------------------------

        elif extension in {
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
        }:

            findings.extend(
                analyze_javascript_unused_imports(
                    file,
                    text,
                )
            )

            findings.extend(
                analyze_javascript_complexity(
                    file,
                    text,
                )
            )

    # --------------------------------------------------------
    # Duplicate code
    # --------------------------------------------------------

    findings.extend(
        check_duplicate_code(
            files
        )
    )

    # --------------------------------------------------------
    # Context adjustments
    # --------------------------------------------------------

    findings = [
        _adjust_test_finding(
            finding
        )
        for finding in findings
    ]

    # --------------------------------------------------------
    # Remove exact duplicates
    # --------------------------------------------------------

    findings = remove_duplicate_findings(
        findings
    )

    # --------------------------------------------------------
    # Stable ordering
    # --------------------------------------------------------

    severity_order = {
        "HIGH": 0,
        "MEDIUM": 1,
        "LOW": 2,
        "INFO": 3,
    }

    findings.sort(
        key=lambda finding: (
            severity_order.get(
                finding.get(
                    "severity",
                    "LOW",
                ),
                9,
            ),
            finding.get(
                "file",
                "",
            ),
            finding.get(
                "line",
                0,
            ),
            finding.get(
                "type",
                "",
            ),
        )
    )

    return findings


# ============================================================
# BACKWARD-COMPATIBILITY ALIAS
# ============================================================

def analyze_javascript_quality(
    files: list[Path],
) -> list[dict[str, Any]]:
    """
    Backward-compatible JavaScript quality API.

    Older main.py versions can still call this directly.
    """

    findings = []

    for file in files:

        if file.suffix.lower() not in {
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
        }:
            continue

        text = _read_file(file)

        if not text:
            continue

        findings.extend(
            analyze_javascript_unused_imports(
                file,
                text,
            )
        )

        findings.extend(
            analyze_javascript_complexity(
                file,
                text,
            )
        )

    return remove_duplicate_findings(
        findings
    )