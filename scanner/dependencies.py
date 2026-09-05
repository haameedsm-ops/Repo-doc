from pathlib import Path
import os
import re
import json
import requests
import xml.etree.ElementTree as ET

from concurrent.futures import ThreadPoolExecutor, as_completed


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
# NETWORK SETTINGS
# ============================================================

NETWORK_TIMEOUT = 3

SESSION = requests.Session()

SESSION.headers.update({
    "User-Agent": "Repo-Doctor/1.0"
})


# ============================================================
# FIND DEPENDENCY FILES
# ============================================================

def find_dependency_files(repo_path):
    """
    Find dependency manifests efficiently.

    Ignored directories are pruned during traversal so
    Repo Doctor does not waste time scanning node_modules,
    .git, build output, virtual environments, etc.
    """

    repo = Path(repo_path)

    if not repo.exists() or not repo.is_dir():
        return []

    found = []
    seen = set()

    for current_root, directories, files in os.walk(repo):

        # ----------------------------------------------------
        # Prune ignored directories BEFORE entering them
        # ----------------------------------------------------

        directories[:] = [
            directory
            for directory in directories
            if directory.lower() not in IGNORED_DIRECTORIES
        ]

        current_path = Path(current_root)

        for filename in files:

            if filename.lower() not in DEPENDENCY_FILES:
                continue

            file = current_path / filename

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

    except (PermissionError, OSError):

        return dependencies

    for line in content.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        # Ignore pip options
        if line.startswith("-"):
            continue

        # Remove inline comments
        line = line.split("#", 1)[0].strip()

        # Package with version
        match = re.match(
            r"^([A-Za-z0-9_.-]+)\s*"
            r"(?:==|>=|<=|~=|>|<)\s*"
            r"([A-Za-z0-9.*+!-]+)",
            line
        )

        if match:

            dependencies.append({
                "name": match.group(1),
                "version": match.group(2)
            })

            continue

        # Package without version
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

        if not isinstance(packages, dict):
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
# MAVEN POM.XML
# ============================================================

# ============================================================
# MAVEN POM.XML
# ============================================================

def parse_pom_xml(file):
    """
    Parse Maven pom.xml dependencies.

    Supports Maven POM files with or without XML namespaces.

    Example:

        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>6.1.0</version>
        </dependency>

    Becomes:

        {
            "name": "org.springframework:spring-core",
            "version": "6.1.0"
        }
    """

    dependencies = []

    try:
        tree = ET.parse(file)
        root = tree.getroot()

    except (
        ET.ParseError,
        OSError
    ):
        return dependencies

    # --------------------------------------------------------
    # Helper to get XML tag name without namespace
    # --------------------------------------------------------

    def clean_tag(tag):
        return tag.split("}")[-1]

    # --------------------------------------------------------
    # Helper to get child text
    # --------------------------------------------------------

    def get_child_text(parent, child_name):

        for child in parent:

            if clean_tag(child.tag) == child_name:

                if child.text:
                    return child.text.strip()

                return ""

        return ""

    # --------------------------------------------------------
    # Find every <dependency> element
    # --------------------------------------------------------

    for dependency in root.iter():

        if clean_tag(dependency.tag) != "dependency":
            continue

        group = get_child_text(
            dependency,
            "groupId"
        )

        artifact = get_child_text(
            dependency,
            "artifactId"
        )

        version = get_child_text(
            dependency,
            "version"
        )

        # ----------------------------------------------------
        # Skip incomplete dependencies
        # ----------------------------------------------------

        if not group or not artifact:
            continue

        # ----------------------------------------------------
        # Maven properties such as:
        #
        # ${spring.version}
        #
        # cannot currently be resolved.
        # ----------------------------------------------------

        if not version:

            version = "unspecified"

        elif (
            version.startswith("${")
            and version.endswith("}")
        ):

            version = "unspecified"

        dependencies.append({
            "name": f"{group}:{artifact}",
            "version": version
        })

    return dependencies

# ============================================================
# GRADLE BUILD.GRADLE
# ============================================================

def parse_build_gradle(file):
    """
    Parse dependencies from build.gradle.

    Supports common Gradle dependency formats:

        implementation 'group:artifact:version'

        implementation "group:artifact:version"

        implementation('group:artifact:version')

        implementation("group:artifact:version")

        api 'group:artifact:version'

        testImplementation 'group:artifact:version'

        runtimeOnly 'group:artifact:version'

    Example:

        implementation 'org.springframework:spring-core:6.1.0'

    Becomes:

        {
            "name": "org.springframework:spring-core",
            "version": "6.1.0"
        }
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

    # --------------------------------------------------------
    # Remove comments
    # --------------------------------------------------------

    content = re.sub(
        r"//.*",
        "",
        content
    )

    content = re.sub(
        r"/\*.*?\*/",
        "",
        content,
        flags=re.DOTALL
    )

    # --------------------------------------------------------
    # Match:
    #
    # implementation 'group:artifact:version'
    # implementation "group:artifact:version"
    #
    # api(...)
    # testImplementation(...)
    # runtimeOnly(...)
    # compileOnly(...)
    # annotationProcessor(...)
    # --------------------------------------------------------

    pattern = re.compile(
        r"""
        \b
        (?:implementation
        |api
        |compileOnly
        |runtimeOnly
        |testImplementation
        |testCompileOnly
        |testRuntimeOnly
        |annotationProcessor)
        \s*
        \(?
        \s*
        ['"]
        ([A-Za-z0-9_.-]+)
        :
        ([A-Za-z0-9_.-]+)
        :
        ([A-Za-z0-9_.${}-]+)
        ['"]
        \)?
        """,
        re.VERBOSE
    )

    seen = set()

    for match in pattern.finditer(content):

        group = match.group(1)
        artifact = match.group(2)
        version = match.group(3)

        name = f"{group}:{artifact}"

        # ----------------------------------------------------
        # Gradle variables such as:
        #
        # implementation "org.foo:bar:$barVersion"
        #
        # cannot be resolved yet.
        # ----------------------------------------------------

        if (
            version.startswith("${")
            or version.startswith("$")
        ):
            version = "unspecified"

        if name in seen:
            continue

        seen.add(name)

        dependencies.append({
            "name": name,
            "version": version
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
        ^5.3.1  -> 5.3.1
        ~4.19.2 -> 4.19.2
        >=9.0.1 -> 9.0.1
        9.0.1   -> 9.0.1
        latest  -> unspecified
    """

    if not isinstance(version, str):
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

# ============================================================
# GENERIC PARSER
# ============================================================

def parse_dependency_file(file):
    """
    Parse a supported dependency manifest.
    """

    filename = file.name.lower()

    if filename == "requirements.txt":
        return parse_requirements(file)

    if filename == "package.json":
        return parse_package_json(file)

    if filename == "pom.xml":
        return parse_pom_xml(file)

    if filename == "build.gradle":
        return parse_build_gradle(file)

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
    """
    Get the latest published npm version.
    """

    try:

        url = (
            "https://registry.npmjs.org/"
            + package
            + "/latest"
        )

        response = SESSION.get(
            url,
            timeout=NETWORK_TIMEOUT
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
    """
    Get the latest published PyPI version.
    """

    try:

        url = (
            "https://pypi.org/pypi/"
            + package
            + "/json"
        )

        response = SESSION.get(
            url,
            timeout=NETWORK_TIMEOUT
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
# CHECK JAVA DEPENDENCY AGAINST OSV
# ============================================================

def check_java_dependency_vulnerability(
    name,
    version
):
    """
    Check a Maven/Gradle dependency against OSV.

    name format:

        groupId:artifactId

    Example:

        org.springframework:spring-core
    """

    if (
        not name
        or not version
        or version == "unspecified"
    ):
        return []

    try:
        url = "https://api.osv.dev/v1/query"

        payload = {
            "version": version,
            "package": {
                "name": name,
                "ecosystem": "Maven"
            }
        }

        response = SESSION.post(
            url,
            json=payload,
            timeout=NETWORK_TIMEOUT
        )

        if response.status_code != 200:
            return []

        data = response.json()

        return data.get(
            "vulns",
            []
        )

    except (
        requests.RequestException,
        ValueError
    ):
        return []
    
# ============================================================
# CHECK ONE DEPENDENCY
# ============================================================

def _check_single_dependency(
    dependency,
    ecosystem
):
    """
    Check one dependency against the latest published version.
    """

    name = dependency.get("name")
    current = dependency.get("version")

    if (
        not name
        or not current
        or current == "unspecified"
    ):
        return None

    if ecosystem == "npm":

        latest = get_latest_npm_version(
            name
        )

    elif ecosystem == "PyPI":

        latest = get_latest_pypi_version(
            name
        )

    else:

        return None

    if not latest:
        return None

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
        return None

    if latest_version <= current_version:
        return None

    current_major = current_version[0]
    current_minor = current_version[1]

    latest_major = latest_version[0]
    latest_minor = latest_version[1]

    if latest_major > current_major:

        severity = "HIGH"

    elif latest_minor > current_minor:

        severity = "MEDIUM"

    else:

        severity = "LOW"

    return {
        "name": name,
        "current": current,
        "latest": latest,
        "severity": severity
    }


# ============================================================
# OUTDATED DEPENDENCY CHECK
# ============================================================

def check_outdated_dependencies(
    dependencies,
    ecosystem
):
    """
    Check dependencies for newer published versions.

    Network requests are performed concurrently.
    """

    results = []

    if not dependencies:
        return results

    checkable = [

        dependency

        for dependency in dependencies

        if (
            dependency.get("name")
            and dependency.get("version")
            and dependency.get("version") != "unspecified"
        )
    ]

    if not checkable:
        return results

    max_workers = min(
        8,
        len(checkable)
    )

    with ThreadPoolExecutor(
        max_workers=max_workers
    ) as executor:

        futures = [

            executor.submit(
                _check_single_dependency,
                dependency,
                ecosystem
            )

            for dependency in checkable
        ]

        for future in as_completed(futures):

            try:

                result = future.result()

                if result:
                    results.append(result)

            except Exception:

                continue

    return results