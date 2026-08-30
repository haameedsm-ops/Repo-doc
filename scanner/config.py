from pathlib import Path


# ============================================================
# DEFAULT LARGE FILE THRESHOLDS
# ============================================================

DEFAULT_LARGE_FILE_THRESHOLDS = {
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


# ============================================================
# CONFIGURATION LOADER
# ============================================================

def load_config(repository_path):
    """
    Load Repo Doctor configuration.

    If .repo-doctor.toml does not exist, default
    thresholds are automatically used.
    """

    config_path = (
        Path(repository_path)
        / ".repo-doctor.toml"
    )

    default_config = {
        "large_file_thresholds":
            DEFAULT_LARGE_FILE_THRESHOLDS.copy()
    }

    if not config_path.exists():
        return default_config

    try:

        import tomllib

    except ModuleNotFoundError:

        try:
            import tomli as tomllib
        except ModuleNotFoundError:
            return default_config

    try:

        with config_path.open(
            "rb"
        ) as config_file:

            data = tomllib.load(
                config_file
            )

    except (OSError, ValueError, TypeError):

        return default_config

    quality_config = data.get(
        "quality",
        {}
    )

    configured = quality_config.get(
        "large_files",
        {}
    )

    thresholds = (
        DEFAULT_LARGE_FILE_THRESHOLDS.copy()
    )

    extension_mapping = {
        "python": [".py"],
        "javascript": [".js", ".jsx"],
        "typescript": [".ts", ".tsx"],
        "css": [".css"],
        "scss": [".scss"],
        "sass": [".sass"],
        "less": [".less"],
        "html": [".html", ".htm"],
    }

    for file_type, extensions in (
        extension_mapping.items()
    ):

        if file_type not in configured:
            continue

        value = configured[file_type]

        if not isinstance(value, int):
            continue

        if value <= 0:
            continue

        for extension in extensions:

            thresholds[extension] = value

    return {
        "large_file_thresholds": thresholds
    }