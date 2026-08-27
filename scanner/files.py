from pathlib import Path


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


IGNORED_FILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}


TEXT_EXTENSIONS = set(LANGUAGES.keys())


def scan_files(repo_path):

    repo = Path(repo_path)

    if not repo.exists():

        raise FileNotFoundError(
            "Repository path does not exist."
        )

    files = []

    for file in repo.rglob("*"):

        if not file.is_file():
            continue

        # Ignore unnecessary directories
        if any(
            part in IGNORED_DIRECTORIES
            for part in file.parts
        ):
            continue

        # Ignore lockfiles from source analysis
        if file.name in IGNORED_FILES:
            continue

        files.append(file)

    return files


def detect_languages(files):

    languages = {}

    for file in files:

        extension = file.suffix.lower()

        if extension in LANGUAGES:

            language = LANGUAGES[extension]

            languages[language] = (
                languages.get(language, 0) + 1
            )

    return languages


def count_lines(files):

    total_lines = 0

    for file in files:

        # Only count recognized source files
        if file.suffix.lower() not in TEXT_EXTENSIONS:
            continue

        try:

            with open(
                file,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as f:

                total_lines += sum(
                    1 for _ in f
                )

        except (
            PermissionError,
            OSError
        ):

            continue

    return total_lines