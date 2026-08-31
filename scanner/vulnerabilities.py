from pathlib import Path
import json
import time

import requests


OSV_BATCH_API = "https://api.osv.dev/v1/querybatch"

BATCH_SIZE = 100

# Cache vulnerability results for 24 hours
CACHE_TTL = 60 * 60 * 24

CACHE_FILE = (
    Path(__file__).resolve().parent
    / ".osv_cache.json"
)


# ============================================================
# CACHE HELPERS
# ============================================================

def load_cache():
    """
    Load cached OSV vulnerability results.
    """

    if not CACHE_FILE.exists():
        return {}

    try:
        data = json.loads(
            CACHE_FILE.read_text(
                encoding="utf-8"
            )
        )

        if not isinstance(data, dict):
            return {}

        return data

    except (
        OSError,
        json.JSONDecodeError
    ):
        return {}


def save_cache(cache):
    """
    Save OSV vulnerability results locally.
    """

    try:
        CACHE_FILE.write_text(
            json.dumps(
                cache,
                indent=2
            ),
            encoding="utf-8"
        )

    except OSError:
        pass


def cache_key(name, version, ecosystem):
    """
    Generate a unique cache key.
    """

    return (
        f"{ecosystem}:"
        f"{name}:"
        f"{version}"
    )


# ============================================================
# BATCH VULNERABILITY SCAN
# ============================================================

def check_vulnerabilities_batch(
    dependencies,
    ecosystem="PyPI"
):
    """
    Scan multiple dependencies using the OSV batch API.

    Uses a local 24-hour cache to avoid repeatedly
    querying the same package/version.

    Returns:

        {
            (package_name, version):
                [vulnerability, ...]
        }
    """

    results = {}

    if not dependencies:
        return results


    # ---------------------------------------------------------
    # Load cache
    # ---------------------------------------------------------

    cache = load_cache()

    now = time.time()


    # ---------------------------------------------------------
    # Prepare valid unique dependencies
    # ---------------------------------------------------------

    unique_packages = []

    seen = set()

    for dependency in dependencies:

        name = dependency.get(
            "name"
        )

        version = dependency.get(
            "version"
        )

        if not name:
            continue

        if (
            not version
            or version == "unspecified"
        ):
            continue

        key = (
            name,
            version
        )

        if key in seen:
            continue

        seen.add(key)

        results[key] = []

        unique_packages.append({
            "name": name,
            "version": version
        })


    if not unique_packages:
        return results


    # ---------------------------------------------------------
    # Check local cache
    # ---------------------------------------------------------

    packages_to_scan = []

    for package in unique_packages:

        name = package["name"]
        version = package["version"]

        key = cache_key(
            name,
            version,
            ecosystem
        )

        cached = cache.get(key)

        if not cached:
            packages_to_scan.append(
                package
            )
            continue


        cached_time = cached.get(
            "timestamp",
            0
        )

        # -----------------------------------------------------
        # Cache still valid
        # -----------------------------------------------------

        if (
            now - cached_time
            < CACHE_TTL
        ):

            results[
                (name, version)
            ] = cached.get(
                "vulnerabilities",
                []
            )

        else:

            # Cache expired
            packages_to_scan.append(
                package
            )


    # ---------------------------------------------------------
    # Everything was cached
    # ---------------------------------------------------------

    if not packages_to_scan:

        return results


    # ---------------------------------------------------------
    # Batch requests
    # ---------------------------------------------------------

    for start in range(
        0,
        len(packages_to_scan),
        BATCH_SIZE
    ):

        batch = packages_to_scan[
            start:start + BATCH_SIZE
        ]

        queries = []

        for package in batch:

            queries.append({

                "package": {
                    "name":
                        package["name"],

                    "ecosystem":
                        ecosystem
                },

                "version":
                    package["version"]

            })


        payload = {
            "queries": queries
        }


        try:

            response = requests.post(

                OSV_BATCH_API,

                json=payload,

                timeout=10
            )


            if response.status_code != 200:

                print(
                    f"⚠️ OSV API returned "
                    f"HTTP {response.status_code}"
                )

                continue


            data = response.json()

            batch_results = data.get(
                "results",
                []
            )


            # -------------------------------------------------
            # Match results
            # -------------------------------------------------

            for package, result in zip(
                batch,
                batch_results
            ):

                vulnerabilities = (
                    result.get(
                        "vulns",
                        []
                    )
                )

                name = package[
                    "name"
                ]

                version = package[
                    "version"
                ]

                key = (
                    name,
                    version
                )

                results[key] = (
                    vulnerabilities
                )


                # -------------------------------------------------
                # Save to cache
                # -------------------------------------------------

                cache_key_value = cache_key(
                    name,
                    version,
                    ecosystem
                )

                cache[
                    cache_key_value
                ] = {

                    "timestamp":
                        now,

                    "vulnerabilities":
                        vulnerabilities

                }


        except (
            requests.RequestException,
            ValueError
        ):

            print(
                "⚠️ OSV vulnerability "
                "scan failed."
            )

            continue


    # ---------------------------------------------------------
    # Save cache
    # ---------------------------------------------------------

    save_cache(cache)


    return results