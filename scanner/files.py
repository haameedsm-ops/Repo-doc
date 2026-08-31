
from pathlib import Path
import os


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
    ".github",
    "node_modules",
    "venv",
    ".venv",
    "env",
    ".env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".gradle",
    ".idea",
    ".vscode",
    ".next",
    ".nuxt",
    ".cache",
    "dist",
    "build",
    "target",
    "out",
    "coverage",
    "vendor",
    "Pods",
}


# ============================================================
# IGNORED FILES
# ============================================================

IGNORED_FILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.lock",
    "Cargo.lock",
    "Gemfile.lock",
}


# ============================================================
# SOURCE EXTENSIONS
# ============================================================

TEXT_EXTENSIONS = set(LANGUAGES.keys())


# ============================================================
# MAX SOURCE FILE SIZE
# ============================================================

MAX_SOURCE_FILE_SIZE_MB = 10

MAX_SOURCE_FILE_SIZE = (
    MAX_SOURCE_FILE_SIZE_MB * 1024 * 1024
)


# ============================================================
# FILE SCANNER
# ============================================================

def scan_files(repo_path):
    """
    Scan a repository efficiently.

    Only supported source files are returned.

    Important:
    - Ignored directories are skipped before recursion.
    - Dependency/build/cache directories are never traversed.
    - Only supported source extensions are collected.
    - Files larger than MAX_SOURCE_FILE_SIZE are skipped.
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

    # --------------------------------------------------------
    # Recursive directory scanner
    # --------------------------------------------------------

    def scan_directory(directory):
        try:
            entries = os.scandir(directory)
        except (
            PermissionError,
            OSError
        ):
            return

        with entries:
            for entry in entries:

                try:

                    # ------------------------------------------------
                    # Directory
                    # ------------------------------------------------

                    if entry.is_dir(
                        follow_symlinks=False
                    ):

                        if entry.name in IGNORED_DIRECTORIES:
                            continue

                        scan_directory(
                            entry.path
                        )

                        continue

                    # ------------------------------------------------
                    # Ignore non-files
                    # ------------------------------------------------

                    if not entry.is_file(
                        follow_symlinks=False
                    ):
                        continue

                    # ------------------------------------------------
                    # Ignore dependency lockfiles
                    # ------------------------------------------------

                    if entry.name in IGNORED_FILES:
                        continue

                    # ------------------------------------------------
                    # Only supported source files
                    # ------------------------------------------------

                    extension = Path(
                        entry.name
                    ).suffix.lower()

                    if extension not in TEXT_EXTENSIONS:
                        continue

                    # ------------------------------------------------
                    # Skip extremely large files
                    # ------------------------------------------------

                    try:

                        if (
                            entry.stat(
                                follow_symlinks=False
                            ).st_size
                            > MAX_SOURCE_FILE_SIZE
                        ):
                            continue

                    except (
                        PermissionError,
                        OSError
                    ):
                        continue

                    files.append(
                        Path(entry.path)
                    )

                except (
                    PermissionError,
                    OSError
                ):
                    continue

    scan_directory(
        str(repo)
    )

    return files


# ============================================================
# LANGUAGE DETECTION
# ============================================================

def detect_languages(files):
    """
    Detect programming languages from file extensions.
    """

    languages = {}

    for file in files:

        extension = file.suffix.lower()

        if extension not in LANGUAGES:
            continue

        language = LANGUAGES[
            extension
        ]

        languages[language] = (
            languages.get(
                language,
                0
            )
            + 1
        )

    return languages


# ============================================================
# LINE COUNT
# ============================================================

def count_lines(files):
    """
    Count lines only in recognized source files.
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
