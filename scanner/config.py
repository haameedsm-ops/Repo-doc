from pathlib import Path
import json


# ============================================================
# DEFAULT CONFIGURATION
# ============================================================

DEFAULT_CONFIG = {
    "thresholds": {
        "python": 500,
        "javascript": 800,
        "css": 1200,
        "html": 1000,
    }
}


# ============================================================
# LOAD REPOSITORY CONFIGURATION
# ============================================================

def load_config(repo_path):
    """
    Load Repo Doctor configuration from the repository.

    If .repo-doctor.json does not exist or is invalid,
    safely fall back to default configuration.
    """

    config = DEFAULT_CONFIG.copy()

    config_file = Path(repo_path) / ".repo-doctor.json"

    if not config_file.is_file():
        return config

    try:
        with config_file.open(
            "r",
            encoding="utf-8"
        ) as file:
            user_config = json.load(file)

    except (
        OSError,
        json.JSONDecodeError
    ):
        return config

    if not isinstance(user_config, dict):
        return config

    user_thresholds = user_config.get(
        "thresholds",
        {}
    )

    if not isinstance(user_thresholds, dict):
        return config

    # --------------------------------------------------------
    # Validate individual thresholds
    # --------------------------------------------------------

    for language in [
        "python",
        "javascript",
        "css",
        "html"
    ]:

        value = user_thresholds.get(language)

        if isinstance(value, int) and value > 0:

            config["thresholds"][language] = value

    return config