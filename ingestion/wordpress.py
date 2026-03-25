from __future__ import annotations

"""
WordPress plugin ingestion via plugins.svn.wordpress.org.

Sources:
  - WordPress.org Plugin API for recently updated plugins + metadata
  - SVN for version-to-version diffs (no full download needed!)

SVN advantage: `svn diff -r OLD:NEW` gives us the diff directly.
No need to download two full archives like PyPI/npm.
"""

import re
import subprocess
from datetime import datetime
from typing import Tuple

import httpx

from storage.models import Package, ReleaseEvent

WP_API_URL = "https://api.wordpress.org/plugins/info/1.2/"
WP_SVN_URL = "https://plugins.svn.wordpress.org/{slug}"
WP_PLUGIN_API = (
    "https://api.wordpress.org/plugins/info/1.2/"
    "?action=plugin_information&request[slug]={slug}"
)
WP_UPDATED_API = (
    "https://api.wordpress.org/plugins/info/1.2/"
    "?action=query_plugins&request[browse]=updated&request[per_page]={count}"
)


def fetch_recent_releases(count: int = 50) -> list:
    """Fetch recently updated WordPress plugins."""
    events = []
    try:
        resp = httpx.get(
            WP_UPDATED_API.format(count=count),
            timeout=15, follow_redirects=True,
        )
        resp.raise_for_status()
        data = resp.json()

        for p in data.get("plugins", []):
            slug = p.get("slug", "")
            version = p.get("version", "")
            last_updated = p.get("last_updated", "")

            if slug and version:
                events.append(ReleaseEvent(
                    package_name=slug,
                    ecosystem="wordpress",
                    version=version,
                    timestamp=last_updated or datetime.utcnow().isoformat(),
                ))
    except Exception as e:
        print(f"[wordpress] API fetch error: {e}")

    return events


def fetch_package_info(slug: str) -> Package | None:
    """Fetch plugin metadata from WordPress.org API."""
    try:
        resp = httpx.get(
            WP_PLUGIN_API.format(slug=slug),
            timeout=15, follow_redirects=True,
        )
        resp.raise_for_status()
        data = resp.json()

        # active_installs is the key metric for WordPress plugins
        downloads = data.get("active_installs", 0)
        if downloads == 0:
            downloads = data.get("downloaded", 0)

        # WordPress plugins don't have explicit dependencies
        # but "requires_plugins" was added recently
        deps = data.get("requires_plugins", []) or []

        return Package(
            name=slug,
            ecosystem="wordpress",
            latest_version=data.get("version", ""),
            downloads=downloads,
            direct_deps=deps,
            updated_at=datetime.utcnow().isoformat(),
        )
    except Exception as e:
        print(f"[wordpress] Info fetch error for {slug}: {e}")
        return None


def get_previous_version(slug: str, current_version: str) -> str:
    """Get the previous version from SVN tags."""
    try:
        result = subprocess.run(
            ["svn", "list", f"{WP_SVN_URL.format(slug=slug)}/tags/"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return ""

        versions = []
        for line in result.stdout.splitlines():
            v = line.strip().rstrip("/")
            if v and v != current_version:
                versions.append(v)

        if not versions:
            return ""

        # Sort by version (simple string sort works for most WP plugins)
        versions.sort()

        # Find the one just before current
        # Try to find current in list and return predecessor
        if current_version in versions:
            idx = versions.index(current_version)
            return versions[idx - 1] if idx > 0 else ""

        # Return last one before current alphabetically
        prev = [v for v in versions if v < current_version]
        return prev[-1] if prev else versions[-1]

    except Exception:
        return ""


# ---------------------------------------------------------------------------
# SVN-based diff — the key advantage over PyPI/npm
# ---------------------------------------------------------------------------

def svn_diff(slug: str, old_version: str, new_version: str,
             timeout: int = 60) -> str:
    """
    Get diff between two versions directly from SVN.
    No download needed — SVN computes the diff server-side.

    Returns unified diff string.
    """
    old_url = f"{WP_SVN_URL.format(slug=slug)}/tags/{old_version}"
    new_url = f"{WP_SVN_URL.format(slug=slug)}/tags/{new_version}"

    try:
        result = subprocess.run(
            ["svn", "diff", "--old", old_url, "--new", new_url],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout
        # Fallback: diff trunk revisions
        return _svn_diff_by_revision(slug, timeout)
    except subprocess.TimeoutExpired:
        print(f"[wordpress] SVN diff timeout for {slug}")
        return ""
    except Exception as e:
        print(f"[wordpress] SVN diff error for {slug}: {e}")
        return ""


def _svn_diff_by_revision(slug: str, timeout: int = 60) -> str:
    """Fallback: diff between last two SVN revisions."""
    try:
        # Get last 2 revisions
        log_result = subprocess.run(
            ["svn", "log", "-l", "2", "-q",
             f"{WP_SVN_URL.format(slug=slug)}/trunk/"],
            capture_output=True, text=True, timeout=15,
        )
        revisions = re.findall(r'r(\d+)', log_result.stdout)
        if len(revisions) < 2:
            return ""

        new_rev, old_rev = revisions[0], revisions[1]
        result = subprocess.run(
            ["svn", "diff", "-r", f"{old_rev}:{new_rev}",
             f"{WP_SVN_URL.format(slug=slug)}/trunk/"],
            capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout if result.returncode == 0 else ""
    except Exception:
        return ""


def parse_svn_diff(diff_text: str) -> Tuple[list, list, list, dict]:
    """
    Parse SVN unified diff into structured data.

    Returns:
        (added_files, removed_files, modified_files, file_diffs)
        where file_diffs = {filepath: [added_lines]}
    """
    added_files = []
    removed_files = []
    modified_files = []
    file_diffs = {}  # filepath → list of (line_num, line_text)

    current_file = None
    line_num = 0

    for line in diff_text.splitlines():
        # New file header
        if line.startswith("Index: "):
            current_file = line[7:].strip()
            file_diffs[current_file] = []

        # Track added/removed/modified
        elif line.startswith("--- ") and current_file:
            if "(nonexistent)" in line or "(revision 0)" in line:
                if current_file not in added_files:
                    added_files.append(current_file)
            elif current_file not in modified_files and current_file not in added_files:
                modified_files.append(current_file)

        elif line.startswith("+++ ") and current_file:
            if "(nonexistent)" in line or "(revision 0)" in line:
                if current_file not in removed_files:
                    removed_files.append(current_file)

        # Hunk header — track line numbers
        elif line.startswith("@@ ") and current_file:
            m = re.search(r'\+(\d+)', line)
            if m:
                line_num = int(m.group(1))

        # Added line (only these matter for security analysis)
        elif line.startswith("+") and not line.startswith("+++") and current_file:
            file_diffs.setdefault(current_file, []).append(
                (line_num, line[1:])  # strip the leading +
            )
            line_num += 1

        elif not line.startswith("-"):
            line_num += 1

    return added_files, removed_files, modified_files, file_diffs
