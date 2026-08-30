
import ast
import re
import hashlib

from tree_sitter import Parser
import tree_sitter_javascript


# ============================================================
# DEFAULT SETTINGS
# ============================================================

DEFAULT_MAX_FILE_LINES = 1000

MAX_FUNCTION_LINES = 50
MAX_JS_FUNCTION_LINES = 80

JS_EXTENSIONS = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx"
}


# ============================================================
# LARGE FILE THRESHOLDS
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


# ============================================================
# DUPLICATE CODE SETTINGS
# ============================================================

DUPLICATE_MIN_LINES = 8
DUPLICATE_CHUNK_LINES = 8

# Maximum source lines considered for duplicate detection
# Large files are still checked for large-file warnings.
DUPLICATE_MAX_FILE_LINES = 5000

# Maximum chunks generated from one file.
# This prevents huge repositories from exploding in memory/time.
DUPLICATE_MAX_CHUNKS_PER_FILE = 600

# Step between chunks.
# Using 1 creates many overlapping chunks.
# Using 4 is much faster while still finding meaningful duplication.
DUPLICATE_CHUNK_STEP = 4

DUPLICATE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".css",
    ".scss",
    ".sass",
    ".less",
    ".html",
    ".htm"
}


# ============================================================
# UNUSED CODE SETTINGS
# ============================================================

UNUSED_CODE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx"
}


# ============================================================
# BINARY FILES
# ============================================================

BINARY_EXTENSIONS = {
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
    ".pdf",
    ".exe",
    ".dll",
    ".so",
    ".bin"
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
# FILE TYPE
# ============================================================

def _get_file_type(file):

    extension = file.suffix.lower()

    file_types = {
        ".py": "Python",
        ".js": "JavaScript",
        ".jsx": "JavaScript JSX",
        ".ts": "TypeScript",
        ".tsx": "TypeScript JSX",
        ".css": "CSS",
        ".scss": "SCSS",
        ".sass": "Sass",
        ".less": "Less",
        ".html": "HTML",
        ".htm": "HTML",
    }

    return file_types.get(
        extension,
        extension.lstrip(".").upper() or "Unknown"
    )


# ============================================================
# LARGE FILE THRESHOLD
# ============================================================

def _get_file_line_threshold(
    file,
    config=None
):

    if config is None:
        config = {}

    thresholds = config.get(
        "large_file_thresholds",
        {}
    )

    extension = file.suffix.lower()

    # Config has priority
    if extension in thresholds:
        return thresholds[extension]

    # Built-in language-specific threshold
    if extension in LARGE_FILE_THRESHOLDS:
        return LARGE_FILE_THRESHOLDS[extension]

    return DEFAULT_MAX_FILE_LINES


# ============================================================
# LARGE FILE SEVERITY
# ============================================================

def _get_large_file_severity(
    line_count,
    threshold
):

    if threshold <= 0:
        return "HIGH"

    ratio = line_count / threshold

    if ratio >= 4:
        return "HIGH"

    if ratio >= 2:
        return "MEDIUM"

    return "LOW"


# ============================================================
# LARGE FILE CHECK
# ============================================================

def check_large_files(
    files,
    config=None
):

    findings = []

    if config is None:
        config = {}

    for file in files:

        if file.suffix.lower() in BINARY_EXTENSIONS:
            continue

        content = read_file(file)

        if not content:
            continue

        line_count = len(
            content.splitlines()
        )

        threshold = _get_file_line_threshold(
            file,
            config
        )

        if threshold <= 0:
            continue

        if line_count <= threshold:
            continue

        file_type = _get_file_type(file)

        percentage_over = (
            (line_count - threshold)
            / threshold
            * 100
        )

        severity = _get_large_file_severity(
            line_count,
            threshold
        )

        if severity == "HIGH":

            recommendation = (
                f"This {file_type} file is extremely "
                "large. Split it into smaller focused "
                "modules, components, or stylesheets."
            )

        elif severity == "MEDIUM":

            recommendation = (
                f"Consider splitting this {file_type} "
                "file into smaller focused modules "
                "or components."
            )

        else:

            recommendation = (
                f"Consider gradually splitting this "
                f"{file_type} file into smaller "
                "focused sections."
            )

        findings.append({

            "type": "Large File",

            "file": str(file),

            "details": (
                f"Type: {file_type} | "
                f"Lines: {line_count} | "
                f"Threshold: {threshold} | "
                f"Over threshold: "
                f"{percentage_over:.1f}%"
            ),

            "severity": severity,

            "why": (
                f"This {file_type} file contains "
                f"{line_count} lines, exceeding the "
                f"recommended {threshold}-line "
                "threshold. Large files are harder "
                "to navigate, maintain, test and "
                "review."
            ),

            "recommendation": recommendation,

            "priority": severity

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

                    "severity": "LOW",

                    "why": (
                        "TODO/FIXME markers usually "
                        "indicate unfinished or "
                        "deferred work."
                    ),

                    "recommendation": (
                        "Resolve the task, convert it "
                        "into a tracked issue, or remove "
                        "the marker."
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

                length = (
                    end
                    - start
                    + 1
                )

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
                ast.AsyncWith
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

                complexity = (
                    calculate_function_complexity(
                        node
                    )
                )

                if complexity >= 10:

                    findings.append({

                        "type": "High Complexity",

                        "file": str(file),

                        "function": node.name,

                        "line": node.lineno,

                        "details": (
                            f"Complexity: "
                            f"{complexity}"
                        ),

                        "severity": "HIGH",

                        "why": (
                            "Many decision paths make "
                            "the function harder to "
                            "test and maintain."
                        ),

                        "recommendation": (
                            "Split complex logic into "
                            "smaller functions and "
                            "simplify conditions."
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
                            f"Complexity: "
                            f"{complexity}"
                        ),

                        "severity": "MEDIUM",

                        "why": (
                            "The function contains "
                            "several decision paths."
                        ),

                        "recommendation": (
                            "Consider extracting "
                            "conditional logic into "
                            "helper functions."
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

def _find_tree_sitter_functions(
    content
):

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

def _get_function_name(
    node,
    source
):

    parent = node.parent

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

    if parent:

        if parent.type in {
            "variable_declarator",
            "pair"
        }:

            name_node = (
                parent.child_by_field_name(
                    "name"
                )
            )

            if name_node:

                return source[
                    name_node.start_byte:
                    name_node.end_byte
                ].decode(
                    "utf-8",
                    errors="ignore"
                )

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

def calculate_tree_sitter_complexity(
    node
):

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
# JAVASCRIPT QUALITY ANALYSIS
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

        for node in functions:

            name = _get_function_name(
                node,
                source
            )

            start_line = (
                node.start_point[0] + 1
            )

            end_line = (
                node.end_point[0] + 1
            )

            length = (
                end_line
                - start_line
                + 1
            )

            complexity = (
                calculate_tree_sitter_complexity(
                    node
                )
            )

            # ------------------------------------------------
            # COMBINED LONG + COMPLEX
            # ------------------------------------------------

            if (
                length > MAX_JS_FUNCTION_LINES
                and complexity >= 20
            ):

                findings.append({

                    "type":
                        "Complex & Long JavaScript Function",

                    "file":
                        str(file),

                    "function":
                        name,

                    "line":
                        start_line,

                    "details": (
                        f"Length: {length} lines | "
                        f"Estimated complexity: "
                        f"{complexity}"
                    ),

                    "severity":
                        "HIGH",

                    "why": (
                        "This JavaScript function is "
                        "both unusually long and "
                        "highly complex, making it "
                        "harder to test, understand "
                        "and maintain."
                    ),

                    "recommendation": (
                        "Split the function into smaller "
                        "single-purpose functions, "
                        "simplify conditional logic, "
                        "and move reusable business "
                        "logic into dedicated modules."
                    ),

                    "priority":
                        "HIGH"

                })

                continue

            # ------------------------------------------------
            # LONG FUNCTION
            # ------------------------------------------------

            if length > MAX_JS_FUNCTION_LINES:

                findings.append({

                    "type":
                        "Long JavaScript Function",

                    "file":
                        str(file),

                    "function":
                        name,

                    "line":
                        start_line,

                    "details":
                        f"{length} lines",

                    "severity":
                        "MEDIUM",

                    "why": (
                        "Large JavaScript functions "
                        "often contain multiple "
                        "responsibilities."
                    ),

                    "recommendation": (
                        "Extract reusable logic into "
                        "smaller helper functions or "
                        "components."
                    ),

                    "priority":
                        "MEDIUM"

                })

            # ------------------------------------------------
            # HIGH COMPLEXITY
            # ------------------------------------------------

            if complexity >= 20:

                findings.append({

                    "type":
                        "High JavaScript Complexity",

                    "file":
                        str(file),

                    "function":
                        name,

                    "line":
                        start_line,

                    "details": (
                        "Estimated complexity: "
                        f"{complexity}"
                    ),

                    "severity":
                        "HIGH",

                    "why": (
                        "High branching and "
                        "conditional logic creates "
                        "many possible execution paths."
                    ),

                    "recommendation": (
                        "Split the function into smaller "
                        "functions, simplify conditions, "
                        "and move business logic into "
                        "dedicated helper modules."
                    ),

                    "priority":
                        "HIGH"

                })

            elif complexity >= 10:

                findings.append({

                    "type":
                        "Moderate JavaScript Complexity",

                    "file":
                        str(file),

                    "function":
                        name,

                    "line":
                        start_line,

                    "details": (
                        "Estimated complexity: "
                        f"{complexity}"
                    ),

                    "severity":
                        "MEDIUM",

                    "why": (
                        "The function contains several "
                        "conditional execution paths."
                    ),

                    "recommendation": (
                        "Consider simplifying conditions "
                        "or extracting complex logic into "
                        "helper functions."
                    ),

                    "priority":
                        "MEDIUM"

                })

    return findings


# ============================================================
# NORMALIZE CODE LINE
# ============================================================

def _normalize_code_line(line):

    line = line.strip()

    if not line:
        return ""

    # Python comments
    if line.startswith("#"):
        return ""

    # JavaScript comments
    if line.startswith("//"):
        return ""

    # CSS / HTML comment-only lines
    if (
        line.startswith("/*")
        and line.endswith("*/")
    ):
        return ""

    # Remove inline comments approximately
    line = re.sub(
        r"\s+(#|//).*$",
        "",
        line
    )

    # Normalize whitespace
    line = re.sub(
        r"\s+",
        " ",
        line
    )

    return line.strip()


# ============================================================
# NORMALIZE CODE
# ============================================================

def _normalize_code(content):

    normalized_lines = []

    for line in content.splitlines():

        normalized = _normalize_code_line(
            line
        )

        if normalized:

            normalized_lines.append(
                normalized
            )

    return normalized_lines


# ============================================================
# CREATE CODE CHUNKS
# ============================================================

def _create_code_chunks(lines):

    chunks = []

    if len(lines) < DUPLICATE_MIN_LINES:
        return chunks

    chunk_size = DUPLICATE_CHUNK_LINES

    # --------------------------------------------------------
    # Limit how much work is done on huge files
    # --------------------------------------------------------

    max_start = (
        len(lines)
        - chunk_size
        + 1
    )

    step = DUPLICATE_CHUNK_STEP

    positions = range(
        0,
        max_start,
        step
    )

    for start in positions:

        if len(chunks) >= DUPLICATE_MAX_CHUNKS_PER_FILE:
            break

        chunk = lines[
            start:
            start + chunk_size
        ]

        if len(chunk) < chunk_size:
            continue

        chunks.append(
            (
                start,
                chunk
            )
        )

    return chunks


# ============================================================
# HASH CHUNK
# ============================================================

def _hash_chunk(chunk):

    normalized = "\n".join(chunk)

    return hashlib.sha256(
        normalized.encode(
            "utf-8",
            errors="ignore"
        )
    ).hexdigest()


# ============================================================
# DUPLICATE SEVERITY
# ============================================================

def _duplicate_severity(
    line_count,
    similarity
):

    if (
        similarity >= 95
        and line_count >= 20
    ):
        return "HIGH"

    if (
        similarity >= 85
        and line_count >= 12
    ):
        return "MEDIUM"

    return "LOW"


# ============================================================
# DUPLICATE CODE DETECTION
# ============================================================

def check_duplicate_code(files):

    findings = []

    chunk_index = {}

    # --------------------------------------------------------
    # BUILD CHUNK INDEX
    # --------------------------------------------------------

    for file in files:

        extension = file.suffix.lower()

        if extension not in DUPLICATE_EXTENSIONS:
            continue

        if extension in BINARY_EXTENSIONS:
            continue

        content = read_file(file)

        if not content:
            continue

        normalized_lines = _normalize_code(
            content
        )

        if len(normalized_lines) < DUPLICATE_MIN_LINES:
            continue

        # ----------------------------------------------------
        # Important performance protection
        # ----------------------------------------------------

        if len(normalized_lines) > DUPLICATE_MAX_FILE_LINES:

            # Sample the beginning, middle and end
            # instead of processing the entire file.
            third = DUPLICATE_MAX_FILE_LINES // 3

            normalized_lines = (
                normalized_lines[:third]
                +
                normalized_lines[
                    len(normalized_lines) // 2 - third // 2:
                    len(normalized_lines) // 2 + third // 2
                ]
                +
                normalized_lines[-third:]
            )

        chunks = _create_code_chunks(
            normalized_lines
        )

        for start, chunk in chunks:

            chunk_hash = _hash_chunk(
                chunk
            )

            chunk_index.setdefault(
                chunk_hash,
                []
            ).append({

                "file": file,

                "start": start,

                "lines": chunk

            })

    # --------------------------------------------------------
    # FIND DUPLICATE CHUNKS
    # --------------------------------------------------------

    reported_pairs = set()

    for chunk_hash, matches in chunk_index.items():

        if len(matches) < 2:
            continue

        # ----------------------------------------------------
        # Limit comparisons for extremely repeated chunks
        # ----------------------------------------------------

        if len(matches) > 20:
            matches = matches[:20]

        for i in range(
            len(matches)
        ):

            for j in range(
                i + 1,
                len(matches)
            ):

                first = matches[i]
                second = matches[j]

                first_file = str(
                    first["file"]
                )

                second_file = str(
                    second["file"]
                )

                # Same file is ignored
                if first_file == second_file:
                    continue

                pair = tuple(
                    sorted([
                        (
                            first_file,
                            first["start"]
                        ),
                        (
                            second_file,
                            second["start"]
                        )
                    ])
                )

                if pair in reported_pairs:
                    continue

                reported_pairs.add(pair)

                similarity = 100.0

                line_count = (
                    DUPLICATE_CHUNK_LINES
                )

                severity = _duplicate_severity(
                    line_count,
                    similarity
                )

                first_start = (
                    first["start"] + 1
                )

                first_end = (
                    first_start
                    + line_count
                    - 1
                )

                second_start = (
                    second["start"] + 1
                )

                second_end = (
                    second_start
                    + line_count
                    - 1
                )

                findings.append({

                    "type":
                        "Duplicate Code",

                    "file":
                        first_file,

                    "file_2":
                        second_file,

                    "line":
                        first_start,

                    "line_2":
                        second_start,

                    "details": (
                        "Similarity: 100% | "
                        f"Lines: {line_count} | "
                        f"Range 1: "
                        f"{first_start}-{first_end} | "
                        f"Range 2: "
                        f"{second_start}-{second_end}"
                    ),

                    "severity":
                        severity,

                    "why": (
                        "Very similar code appears "
                        "in multiple files. Duplicated "
                        "logic increases maintenance "
                        "cost and can cause inconsistent "
                        "bug fixes."
                    ),

                    "recommendation": (
                        "Extract the shared logic into "
                        "a reusable function, component, "
                        "utility, or shared stylesheet."
                    ),

                    "priority":
                        severity

                })

    return findings


# ============================================================
# PYTHON UNUSED IMPORT DETECTION
# ============================================================

def check_unused_python_imports(files):

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

        used_names = set()
        imported_nodes = []

        for node in ast.walk(tree):

            if isinstance(
                node,
                ast.Name
            ):

                used_names.add(
                    node.id
                )

            elif isinstance(
                node,
                (
                    ast.Import,
                    ast.ImportFrom
                )
            ):

                imported_nodes.append(node)

        for node in imported_nodes:

            for alias in node.names:

                if alias.name == "*":
                    continue

                if alias.asname:
                    imported_name = alias.asname

                else:
                    imported_name = (
                        alias.name.split(".")[0]
                    )

                if imported_name in used_names:
                    continue

                findings.append({

                    "type":
                        "Unused Python Import",

                    "file":
                        str(file),

                    "line":
                        node.lineno,

                    "details": (
                        f"Unused import: "
                        f"{alias.name}"
                    ),

                    "severity":
                        "LOW",

                    "why": (
                        "This imported module or "
                        "symbol does not appear to "
                        "be used in the file."
                    ),

                    "recommendation": (
                        "Remove the unused import to "
                        "reduce clutter and improve "
                        "code maintainability."
                    ),

                    "priority":
                        "LOW"

                })

    return findings


# ============================================================
# JAVASCRIPT / TYPESCRIPT UNUSED IMPORT DETECTION
# ============================================================

def check_unused_javascript_imports(files):

    findings = []

    for file in files:

        if file.suffix.lower() not in JS_EXTENSIONS:
            continue

        content = read_file(file)

        if not content:
            continue

        # ----------------------------------------------------
        # Find imports directly from the original source.
        # ----------------------------------------------------

        import_pattern = re.compile(
            r"""^\s*import\s+(.+?)\s+from\s+['"][^'"]+['"]\s*;?\s*$""",
            re.MULTILINE
        )

        imports = []

        for match in import_pattern.finditer(
            content
        ):

            imported_part = (
                match.group(1).strip()
            )

            line_number = (
                content[:match.start()]
                .count("\n")
                + 1
            )

            imports.append({

                "names": imported_part,

                "line": line_number

            })

        # ----------------------------------------------------
        # Remove import declarations before checking usage.
        # ----------------------------------------------------

        usage_content = re.sub(
            r"^\s*import\s+.*$",
            "",
            content,
            flags=re.MULTILINE
        )

        # Remove comments approximately
        usage_content = re.sub(
            r"//.*",
            "",
            usage_content
        )

        usage_content = re.sub(
            r"/\*.*?\*/",
            "",
            usage_content,
            flags=re.DOTALL
        )

        # ----------------------------------------------------
        # Check imported names
        # ----------------------------------------------------

        for item in imports:

            imported_part = item["names"]

            line_number = item["line"]

            names = []

            # Default import
            if (
                not imported_part.startswith("{")
                and not imported_part.startswith("*")
            ):

                default_match = re.match(
                    r"([A-Za-z_$][\w$]*)",
                    imported_part
                )

                if default_match:

                    names.append(
                        default_match.group(1)
                    )

            # Namespace import
            namespace_match = re.search(
                r"\*\s+as\s+([A-Za-z_$][\w$]*)",
                imported_part
            )

            if namespace_match:

                names.append(
                    namespace_match.group(1)
                )

            # Named imports
            named_match = re.search(
                r"\{(.*?)\}",
                imported_part,
                flags=re.DOTALL
            )

            if named_match:

                named_content = (
                    named_match.group(1)
                )

                for item_name in named_content.split(","):

                    item_name = item_name.strip()

                    if not item_name:
                        continue

                    if " as " in item_name:

                        local_name = (
                            item_name.split(
                                " as ",
                                1
                            )[1].strip()
                        )

                    else:

                        local_name = item_name

                    if re.match(
                        r"^[A-Za-z_$][\w$]*$",
                        local_name
                    ):

                        names.append(
                            local_name
                        )

            for name in names:

                occurrences = len(
                    re.findall(
                        rf"\b{re.escape(name)}\b",
                        usage_content
                    )
                )

                if occurrences > 0:
                    continue

                findings.append({

                    "type":
                        "Unused JavaScript Import",

                    "file":
                        str(file),

                    "line":
                        line_number,

                    "details": (
                        f"Unused import: {name}"
                    ),

                    "severity":
                        "LOW",

                    "why": (
                        "This imported symbol does "
                        "not appear to be referenced "
                        "in the file."
                    ),

                    "recommendation": (
                        "Remove the unused import to "
                        "reduce bundle clutter and "
                        "improve maintainability."
                    ),

                    "priority":
                        "LOW"

                })

    return findings


# ============================================================
# SMART UNUSED IMPORT ANALYSIS
# ============================================================

def check_unused_imports(files):

    findings = []

    findings.extend(
        check_unused_python_imports(
            files
        )
    )

    findings.extend(
        check_unused_javascript_imports(
            files
        )
    )

    return findings


# ============================================================
# QUALITY FINDING DEDUPLICATION
# ============================================================

def deduplicate_quality_findings(
    findings
):

    unique_findings = []

    seen = set()

    for finding in findings:

        key = (

            finding.get(
                "type",
                ""
            ),

            finding.get(
                "file",
                ""
            ),

            finding.get(
                "line",
                0
            ),

            finding.get(
                "function",
                ""
            ),

            finding.get(
                "file_2",
                ""
            ),

            finding.get(
                "line_2",
                0
            )

        )

        if key in seen:
            continue

        seen.add(key)

        unique_findings.append(
            finding
        )

    return unique_findings


# ============================================================
# SMART QUALITY ANALYSIS
# ============================================================

def analyze_quality(
    files,
    config=None
):

    findings = []

    # --------------------------------------------------------
    # 1. Large files
    # --------------------------------------------------------

    findings.extend(
        check_large_files(
            files,
            config
        )
    )

    # --------------------------------------------------------
    # 2. TODO / FIXME
    # --------------------------------------------------------

    findings.extend(
        check_todos(
            files
        )
    )

    # --------------------------------------------------------
    # 3. Python long functions
    # --------------------------------------------------------

    findings.extend(
        check_long_functions(
            files
        )
    )

    # --------------------------------------------------------
    # 4. Python complexity
    # --------------------------------------------------------

    findings.extend(
        analyze_python_complexity(
            files
        )
    )

    # --------------------------------------------------------
    # 5. JavaScript / TypeScript quality
    # --------------------------------------------------------

    findings.extend(
        analyze_javascript_quality(
            files
        )
    )

    # --------------------------------------------------------
    # 6. Duplicate code
    # --------------------------------------------------------

    findings.extend(
        check_duplicate_code(
            files
        )
    )

    # --------------------------------------------------------
    # 7. Unused imports
    # --------------------------------------------------------

    findings.extend(
        check_unused_imports(
            files
        )
    )

    # --------------------------------------------------------
    # Remove duplicates
    # --------------------------------------------------------

    return deduplicate_quality_findings(
        findings
    )
