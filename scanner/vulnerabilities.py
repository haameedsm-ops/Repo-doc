import requests


OSV_BATCH_API = "https://api.osv.dev/v1/querybatch"

BATCH_SIZE = 100


def check_vulnerabilities_batch(dependencies, ecosystem="PyPI"):
    """
    Scan multiple dependencies using the OSV batch API.

    Returns:
        {
            (package_name, version): [vulnerability, ...]
        }
    """

    results = {}

    if not dependencies:
        return results

    # ---------------------------------------------------------
    # Prepare valid dependencies
    # ---------------------------------------------------------

    packages = []

    for dependency in dependencies:

        name = dependency.get("name")
        version = dependency.get("version")

        if not name:
            continue

        if not version or version == "unspecified":
            continue

        packages.append({
            "name": name,
            "version": version
        })

        results[(name, version)] = []


    if not packages:
        return results


    # ---------------------------------------------------------
    # Remove duplicate packages
    # ---------------------------------------------------------

    unique_packages = []

    seen = set()

    for package in packages:

        key = (
            package["name"],
            package["version"]
        )

        if key in seen:
            continue

        seen.add(key)

        unique_packages.append(package)


    # ---------------------------------------------------------
    # Batch requests
    # ---------------------------------------------------------

    for start in range(
        0,
        len(unique_packages),
        BATCH_SIZE
    ):

        batch = unique_packages[
            start:start + BATCH_SIZE
        ]

        queries = []

        for package in batch:

            queries.append({

                "package": {
                    "name": package["name"],
                    "ecosystem": ecosystem
                },

                "version": package["version"]

            })


        payload = {
            "queries": queries
        }


        try:

            response = requests.post(
                OSV_BATCH_API,
                json=payload,
                timeout=15
            )


            if response.status_code != 200:
                continue


            data = response.json()

            batch_results = data.get(
                "results",
                []
            )


            # -------------------------------------------------
            # Match results back to packages
            # -------------------------------------------------

            for package, result in zip(
                batch,
                batch_results
            ):

                vulnerabilities = result.get(
                    "vulns",
                    []
                )

                key = (
                    package["name"],
                    package["version"]
                )

                results[key] = vulnerabilities


        except (
            requests.RequestException,
            ValueError
        ):

            continue


    return results