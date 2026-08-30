from pathlib import Path

import re
import json
import requests


# ============================================================
# DEPENDENCY FILES
# ============================================================

DEPENDENCY_FILES = {
    "requirements.txt": "Python",
    "package.json": "Node.js",
    "pom.xml": "Java",
    "build.gradle": "Java",
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
# FIND DEPENDENCY FILES
# ============================================================

def find_dependency_files(repo_path):
    """
    Find dependency manifests efficiently.

    Each physical dependency file is returned only once.
    Generated/vendor directories are skipped.
    """

    repo = Path(repo_path)

    if not repo.exists() or not repo.is_dir():
        return []

    found = []
    seen = set()

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
        # Only inspect known dependency files
        # ----------------------------------------------------

        filename = file.name.lower()

        if filename not in DEPENDENCY_FILES:
            continue

        # ----------------------------------------------------
        # Prevent duplicate paths
        # ----------------------------------------------------

        try:
            resolved = file.resolve()
        except OSError:
            resolved = file.absolute()

        if resolved in seen:
            continue

        seen.add(resolved)
        found.append(file)

    return found


# ============================================================
# PYTHON REQUIREMENTS PARSER
# ============================================================

def parse_requirements(file):
    """
    Parse dependencies from requirements.txt.
    """

    dependencies = []

    try:
        content = file.read_text(
            encoding="utf-8",
            errors="ignore"
        )

    except (
        PermissionError,
        OSError
    ):
        return dependencies

    for line in content.splitlines():

        line = line.strip()

        # Empty line
        if not line:
            continue

        # Comment
        if line.startswith("#"):
            continue

        # Options such as:
        # -r requirements-dev.txt
        # --index-url ...
        if line.startswith("-"):
            continue

        # ----------------------------------------------------
        # Package with version
        # ----------------------------------------------------

        match = re.match(
            r"^([A-Za-z0-9_.-]+)\s*"
            r"(?:==|>=|<=|~=|>|<)\s*"
            r"([A-Za-z0-9.*+-]+)",
            line
        )

        if match:

            dependencies.append({
                "name": match.group(1),
                "version": match.group(2)
            })

        else:

            # ------------------------------------------------
            # Package without version
            # ------------------------------------------------

            package_match = re.match(
                r"^([A-Za-z0-9_.-]+)",
                line
            )

            if package_match:

                dependencies.append({
                    "name": package_match.group(1),
                    "version": "unspecified"
                })

    return dependencies


# ============================================================
# NODE PACKAGE.JSON
# ============================================================

def parse_package_json(file):
    """
    Parse dependencies from package.json.

    Reads:
    - dependencies
    - devDependencies
    - optionalDependencies
    - peerDependencies
    """

    dependencies = []

    try:

        content = file.read_text(
            encoding="utf-8",
            errors="ignore"
        )

        data = json.loads(content)

    except (
        OSError,
        json.JSONDecodeError
    ):
        return dependencies

    sections = [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies"
    ]

    seen = set()

    for section in sections:

        packages = data.get(
            section,
            {}
        )

        if not isinstance(
            packages,
            dict
        ):
            continue

        for name, version in packages.items():

            if name in seen:
                continue

            seen.add(name)

            dependencies.append({
                "name": name,
                "version": clean_npm_version(version)
            })

    return dependencies


# ============================================================
# CLEAN NPM VERSION
# ============================================================

def clean_npm_version(version):
    """
    Convert npm version expressions into a usable
    semantic version.

    Examples:

    ^5.3.1       -> 5.3.1
    ~4.19.2      -> 4.19.2
    >=9.0.1      -> 9.0.1
    9.0.1        -> 9.0.1
    latest       -> unspecified
    """

    if not isinstance(
        version,
        str
    ):
        return "unspecified"

    version = version.strip()

    match = re.search(
        r"\d+\.\d+\.\d+"
        r"(?:[-+][A-Za-z0-9.-]+)?",
        version
    )

    if match:
        return match.group(0)

    return "unspecified"


# ============================================================
# GENERIC PARSER
# ============================================================

def parse_dependency_file(file):

    filename = file.name.lower()

    if filename == "requirements.txt":
        return parse_requirements(file)

    if filename == "package.json":
        return parse_package_json(file)

    return []


# ============================================================
# VERSION PARSER
# ============================================================

def parse_version(version):
    """
    Convert semantic version into:

    (major, minor, patch)

    Example:

    5.3.1 -> (5, 3, 1)
    """

    if not version:
        return None

    match = re.search(
        r"(\d+)\.(\d+)\.(\d+)",
        version
    )

    if not match:
        return None

    return tuple(
        int(value)
        for value in match.groups()
    )


# ============================================================
# CHECK NPM LATEST VERSION
# ============================================================

def get_latest_npm_version(package):

    try:

        url = (
            "https://registry.npmjs.org/"
            + package
            + "/latest"
        )

        response = requests.get(
            url,
            timeout=5
        )

        if response.status_code != 200:
            return None

        data = response.json()

        return data.get("version")

    except (
        requests.RequestException,
        ValueError
    ):
        return None


# ============================================================
# CHECK PYPI LATEST VERSION
# ============================================================

def get_latest_pypi_version(package):

    try:

        url = (
            "https://pypi.org/pypi/"
            + package
            + "/json"
        )

        response = requests.get(
            url,
            timeout=5
        )

        if response.status_code != 200:
            return None

        data = response.json()

        return (
            data
            .get("info", {})
            .get("version")
        )

    except (
        requests.RequestException,
        ValueError
    ):
        return None


# ============================================================
# OUTDATED DEPENDENCY CHECK
# ============================================================

def check_outdated_dependencies(
    dependencies,
    ecosystem
):
    """
    Check whether dependencies are behind the latest
    published version.

    This function is currently optional and can be used
    later for dependency health recommendations.
    """

    results = []

    for dependency in dependencies:

        name = dependency.get(
            "name"
        )

        current = dependency.get(
            "version"
        )

        if (
            not name
            or not current
            or current == "unspecified"
        ):
            continue

        # ----------------------------------------------------
        # Get latest version
        # ----------------------------------------------------

        if ecosystem == "npm":

            latest = get_latest_npm_version(
                name
            )

        elif ecosystem == "PyPI":

            latest = get_latest_pypi_version(
                name
            )

        else:

            latest = None

        if not latest:
            continue

        # ----------------------------------------------------
        # Parse versions
        # ----------------------------------------------------

        current_version = parse_version(
            current
        )

        latest_version = parse_version(
            latest
        )

        if not (
            current_version
            and latest_version
        ):
            continue

        # ----------------------------------------------------
        # Compare versions
        # ----------------------------------------------------

        if latest_version > current_version:

            major_difference = (
                latest_version[0]
                > current_version[0]
            )

            minor_difference = (
                latest_version[1]
                > current_version[1]
            )

            if major_difference:

                severity = "HIGH"

            elif minor_difference:

                severity = "MEDIUM"

            else:

                severity = "LOW"

            results.append({

                "name": name,

                "current": current,

                "latest": latest,

                "severity": severity

            })

    return results