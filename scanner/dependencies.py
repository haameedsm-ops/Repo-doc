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
# FIND DEPENDENCY FILES
# ============================================================

def find_dependency_files(repo_path):

    repo = Path(repo_path)

    if not repo.exists():
        return []

    found = []

    for file in repo.rglob("*"):

        if not file.is_file():
            continue

        if any(
            part in IGNORED_DIRECTORIES
            for part in file.parts
        ):
            continue

        if file.name.lower() in DEPENDENCY_FILES:

            found.append(file)

    return found


# ============================================================
# PYTHON REQUIREMENTS PARSER
# ============================================================

def parse_requirements(file):

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

        if not line:
            continue

        if line.startswith("#"):
            continue

        if line.startswith("-"):
            continue


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

            package_match = re.match(
                r"^([A-Za-z0-9_.-]+)",
                line
            )

            if package_match:

                dependencies.append({

                    "name":
                        package_match.group(1),

                    "version":
                        "unspecified"

                })


    return dependencies


# ============================================================
# NODE PACKAGE.JSON
# ============================================================

def parse_package_json(file):

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

                "version":
                    clean_npm_version(version)

            })


    return dependencies


# ============================================================
# CLEAN NPM VERSION
# ============================================================

def clean_npm_version(version):

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


        current_version = parse_version(
            current
        )

        latest_version = parse_version(
            latest
        )


        if (
            current_version
            and latest_version
            and latest_version > current_version
        ):

            major_difference = (
                latest_version[0]
                > current_version[0]
            )


            if major_difference:

                severity = "HIGH"

            elif (
                latest_version[1]
                > current_version[1]
            ):

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