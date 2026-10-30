"""Weighted URL path selection for the legitimate-load generator."""
import random
from urllib.parse import urlsplit, urlunsplit


def parse_paths(spec: str) -> tuple[list[str], list[float]]:
    """"/:6,/work:3,/health" -> (["/", "/work", "/health"], [6.0, 3.0, 1.0]); a missing weight is 1."""
    paths, weights = [], []
    for item in spec.split(","):
        path, _, weight = item.strip().partition(":")
        paths.append(path or "/")
        weights.append(float(weight) if weight else 1.0)
    return paths, weights


def pick_url(target_url: str, paths: list[str], weights: list[float]) -> str:
    """The target's origin with one of the weighted paths, so legitimate users browse a mix of endpoints."""
    parts = urlsplit(target_url)
    return urlunsplit((parts.scheme, parts.netloc, random.choices(paths, weights)[0], "", ""))
