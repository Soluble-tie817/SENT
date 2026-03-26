from __future__ import annotations

"""
SBOM import — load your dependency tree and boost those packages.

Reads requirements.txt, Pipfile.lock, poetry.lock, package.json,
or a plain list of package names. Resolves transitive dependencies
via PyPI/npm APIs. Marks all packages in your tree with a high
synthetic download count so they always pass the scoring threshold.

Usage:
    python3 cli.py sbom requirements.txt
    python3 cli.py watch --sbom requirements.txt -t 8 -i 30
"""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Set, Tuple

import httpx

from graph.dependency_graph import graph

# Packages in your SBOM get this synthetic weight.
# High enough to always pass any reasonable threshold.
SBOM_BOOST = 1_000_000_000  # 1 billion


def parse_requirements(filepath: str) -> List[Tuple[str, str]]:
    """
    Parse a dependency file. Returns list of (name, ecosystem).

    Supports:
      - requirements.txt / constraints.txt (pip)
      - package.json (npm)
      - plain text (one package name per line)
    """
    path = Path(filepath)
    if not path.exists():
        print(f"[sbom] File not found: {filepath}")
        return []

    text = path.read_text()
    name = path.name.lower()

    if name == "package.json":
        return _parse_package_json(text)
    else:
        return _parse_requirements_txt(text)


def _parse_requirements_txt(text: str) -> List[Tuple[str, str]]:
    """Parse pip requirements format."""
    packages = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip version specifiers, extras, environment markers
        name = re.split(r'[><=!~;\s\[]', line)[0].strip()
        if name:
            packages.append((name.lower(), "pypi"))
    return packages


def _parse_package_json(text: str) -> List[Tuple[str, str]]:
    """Parse npm package.json."""
    import json
    try:
        data = json.loads(text)
        packages = []
        for section in ("dependencies", "devDependencies"):
            for name in data.get(section, {}):
                packages.append((name, "npm"))
        return packages
    except Exception:
        return []


def _resolve_pypi_deps(name: str) -> Tuple[str, List[str], int]:
    """Fetch deps and downloads for a PyPI package."""
    try:
        r = httpx.get(f"https://pypi.org/pypi/{name}/json", timeout=10, follow_redirects=True)
        if r.status_code != 200:
            return (name, [], 0)
        data = r.json()
        info = data.get("info", {})

        deps = []
        for req in (info.get("requires_dist") or []):
            dep = re.split(r'[><=!;\s\[]', req)[0].strip().lower()
            if dep:
                deps.append(dep)

        # Try pypistats
        downloads = 0
        try:
            sr = httpx.get(f"https://pypistats.org/api/packages/{name}/recent",
                           timeout=5, follow_redirects=True)
            if sr.status_code == 200:
                downloads = sr.json().get("data", {}).get("last_month", 0)
        except Exception:
            pass

        return (name, deps, max(downloads, 0))
    except Exception:
        return (name, [], 0)


def _resolve_npm_deps(name: str) -> Tuple[str, List[str], int]:
    """Fetch deps for an npm package."""
    try:
        r = httpx.get(f"https://registry.npmjs.org/{name}", timeout=10, follow_redirects=True)
        if r.status_code != 200:
            return (name, [], 0)
        data = r.json()
        latest = data.get("dist-tags", {}).get("latest", "")
        info = data.get("versions", {}).get(latest, {})
        deps = list((info.get("dependencies") or {}).keys())
        return (name, deps, 0)
    except Exception:
        return (name, [], 0)


def import_sbom(
    filepath: str,
    resolve_transitive: bool = True,
    workers: int = 15,
    verbose: bool = True,
) -> Set[str]:
    """
    Import an SBOM file into the dependency graph.

    1. Parse the file for direct dependencies
    2. Resolve transitive deps via PyPI/npm APIs
    3. Add all to the graph with boosted weight
    4. Return set of all package names tracked

    Returns set of "ecosystem/name" strings for all tracked packages.
    """
    direct = parse_requirements(filepath)
    if not direct:
        print("[sbom] No packages found in file")
        return set()

    if verbose:
        print(f"[sbom] Parsed {len(direct)} direct dependencies from {filepath}")

    # Resolve all deps
    all_packages: Set[str] = set()
    to_resolve: List[Tuple[str, str]] = list(direct)
    resolved: Set[str] = set()

    depth = 0
    max_depth = 3 if resolve_transitive else 1

    while to_resolve and depth < max_depth:
        depth += 1
        batch = [(n, e) for n, e in to_resolve if f"{e}/{n}" not in resolved]
        if not batch:
            break

        if verbose:
            print(f"[sbom] Resolving depth {depth}: {len(batch)} packages...")

        next_round = []

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {}
            for name, eco in batch:
                if eco == "pypi":
                    futures[pool.submit(_resolve_pypi_deps, name)] = (name, eco)
                elif eco == "npm":
                    futures[pool.submit(_resolve_npm_deps, name)] = (name, eco)

            for future in as_completed(futures):
                name, eco = futures[future]
                try:
                    pkg_name, deps, downloads = future.result()
                    node = f"{eco}/{pkg_name}"
                    resolved.add(node)
                    all_packages.add(node)

                    # Add to graph with boosted weight
                    graph.add_package(pkg_name, eco, deps, max(downloads, SBOM_BOOST))

                    # Queue transitive deps for next round
                    for dep in deps:
                        dep_node = f"{eco}/{dep}"
                        if dep_node not in resolved:
                            next_round.append((dep, eco))
                            all_packages.add(dep_node)
                except Exception:
                    pass

        to_resolve = next_round

    if verbose:
        print(f"[sbom] Tracking {len(all_packages)} packages (direct + transitive)")
        print(f"[sbom] All boosted to cascade weight >= {SBOM_BOOST:,}")

    # Recompute cascade weights
    graph._cascade_dirty = True
    graph._ensure_cascade()

    # Save graph
    graph.save_to_db()

    if verbose:
        # Show top boosted
        top = [p for p in graph.top_by_cascade(20)
               if f"{p['ecosystem']}/{p['name']}" in all_packages][:10]
        if top:
            print(f"\n[sbom] Your top packages by cascade weight:")
            for i, p in enumerate(top, 1):
                print(f"  {i:2d}. {p['ecosystem']}/{p['name']}"
                      f"  cascade={p['cascade_weight']:>15,}")

    return all_packages
