
from pathlib import Path


# ============================================================
# SUPPORTED LANGUAGES
# ============================================================

LANGUAGES = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".jsx": "JavaScript",
    ".java": "Java",
    ".cpp": "C++",
    ".c": "C",
    ".h": "C/C++ Header",
    ".html": "HTML",
    ".css": "CSS",
    ".kt": "Kotlin",
    ".go": "Go",
    ".rs": "Rust",
    ".php": "PHP",
}


# ============================================================
# IGNORED DIRECTORIES
# ============================================================

IGNORED_DIRECTORIES = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    "target",
    ".idea",
    ".vscode",
}


# ============================================================
# IGNORED FILES
# ============================================================

IGNORED_FILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}


# ============================================================
# SOURCE EXTENSIONS
# ============================================================

TEXT_EXTENSIONS = set(LANGUAGES.keys())


# ============================================================
# FILE SCANNER
# ============================================================

def scan_files(repo_path):
    """
    Scan a repository and return files that Repo Doctor can
    safely analyze.

    The scanner intentionally keeps all non-ignored files
    instead of restricting the repository to known programming
    language extensions. This allows documentation and project
    configuration files to remain available to other scanners.
    """

    repo = Path(repo_path)

    if not repo.exists():
        raise FileNotFoundError(
            "Repository path does not exist."
        )

    if not repo.is_dir():
        raise NotADirectoryError(
            "Repository path must be a directory."
        )

    files = []

    for file in repo.rglob("*"):

        if not file.is_file():
            continue

        # ----------------------------------------------------
        # Ignore unnecessary directories
        # ----------------------------------------------------

        if any(
            part in IGNORED_DIRECTORIES
            for part in file.parts
        ):
            continue

        # ----------------------------------------------------
        # Ignore dependency lockfiles
        # ----------------------------------------------------

        if file.name in IGNORED_FILES:
            continue

        files.append(file)

    return files


# ============================================================
# LANGUAGE DETECTION
# ============================================================

def detect_languages(files):
    """Detect programming languages from file extensions."""

    languages = {}

    for file in files:

        extension = file.suffix.lower()

        if extension not in LANGUAGES:
            continue

        language = LANGUAGES[extension]

        languages[language] = (
            languages.get(language, 0) + 1
        )

    return languages


# ============================================================
# LINE COUNT
# ============================================================

def count_lines(files):
    """
    Count lines only in recognized source files.

    Documentation, images, configuration files and other
    non-source files are not included in the LOC total.
    """

    total_lines = 0

    for file in files:

        extension = file.suffix.lower()

        if extension not in TEXT_EXTENSIONS:
            continue

        try:

            with open(
                file,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as f:

                total_lines += sum(
                    1
                    for _ in f
                )

        except (
            PermissionError,
            OSError
        ):
            continue

    return total_lines
