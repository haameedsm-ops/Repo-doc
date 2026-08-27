from pathlib import Path
import subprocess


def run_git_command(repo_path, command):

    try:

        result = subprocess.run(
            ["git"] + command,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return None

        return result.stdout.strip()

    except (
        subprocess.SubprocessError,
        FileNotFoundError
    ):

        return None


def is_git_repository(repo_path):

    result = run_git_command(
        repo_path,
        ["rev-parse", "--is-inside-work-tree"]
    )

    return result == "true"


def get_commit_count(repo_path):

    result = run_git_command(
        repo_path,
        ["rev-list", "--count", "HEAD"]
    )

    if result is None:
        return 0

    try:
        return int(result)

    except ValueError:
        return 0


def get_branch_count(repo_path):

    result = run_git_command(
        repo_path,
        ["branch", "--format=%(refname:short)"]
    )

    if not result:
        return 0

    return len(result.splitlines())


def get_contributor_count(repo_path):

    result = run_git_command(
        repo_path,
        ["shortlog", "-sne", "HEAD"]
    )

    if not result:
        return 0

    return len(result.splitlines())


def get_last_commit(repo_path):

    result = run_git_command(
        repo_path,
        [
            "log",
            "-1",
            "--pretty=format:%h|%an|%s"
        ]
    )

    if not result:
        return None

    parts = result.split("|", 2)

    if len(parts) != 3:
        return None

    return {
        "hash": parts[0],
        "author": parts[1],
        "message": parts[2]
    }


def analyze_git_repository(repo_path):

    if not is_git_repository(repo_path):

        return {
            "is_git": False
        }

    return {
        "is_git": True,
        "commits": get_commit_count(repo_path),
        "branches": get_branch_count(repo_path),
        "contributors": get_contributor_count(repo_path),
        "last_commit": get_last_commit(repo_path)
    }