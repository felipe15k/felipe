"""Utility functions for logging, helpers, and constants."""

import logging
import os
import re
import sys
from pathlib import Path

# Constants
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# High-value keywords for endpoint classification
HIGH_VALUE_KEYWORDS = [
    "admin", "root", "superuser", "config", "secret", "backup",
    "db", "database", "token", "key", "password", "internal",
]

# Noise markers in URLs
NOISE_MARKERS = [
    '.css', '.js', '.png', '.jpg', '.svg', '/static/', '/assets/', 'cdn', 'analytics'
]

# Telemetry path markers
TELEMETRY_PATH_MARKERS = [
    "/track", "/telemetry", "/beacon", "/metrics", "/pixel", "/collect",
    "/analytics", "/event", "/log", "/ping", "/heartbeat", "/sampling",
]

# Documentation page markers
DOC_PAGE_MARKERS = [
    "developer.", "developers.", "docs.", "api-docs", "apidocs",
    "/swagger", "/redoc", "/openapi", "readme.io",
]

# Build-time markers (webpack, vite, rollup runtime)
BUILD_RUNTIME_MARKERS = [
    "__webpack_require__",
    "__vite_ssr_import_meta__",
    "import.meta",
    "__ROLLUP_",
    "__DEV__",
]

# Known placeholder secrets
KNOWN_PLACEHOLDER_SECRETS = {
    "akiaiosfodnn7example",
    "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",
    "aizasyabcdefghijklmnopqrstuvwxyz1234567",
    "ghp_000000000000000000000000000000000",
    "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "eyjhbgcioijiuzi1niisinr5cci6ikpxvcj9.eyjzdwiioiixmjm0ntY3odkwiiwibmftzsi6ikpvag4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "your_api_key_here",
    "your-api-key-here",
    "changeme",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "0000000000000000000000000000000000000000",
}

# Regex patterns for heuristics
CONSTANT_NAME_PATTERN = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+){2,}$")
CAMEL_CASE_IDENTIFIER_PATTERN = re.compile(r"^[a-z][a-zA-Z]*[A-Z][a-zA-Z]*$")
LOOKS_LIKE_PATH_PATTERN = re.compile(r"^/[\w\-.]+(?:/[\w\-.:{}]*)+/?$")
VERSION_TOKEN_PATTERN = re.compile(r"\d+\.\d+(?:\.\d+){0,2}")


def setup_logging(output_dir: str, verbose: bool) -> logging.Logger:
    """Configure logging for the application.
    
    Args:
        output_dir: Output directory for log files
        verbose: Enable DEBUG level logging
        
    Returns:
        Configured logger instance
    """
    os.makedirs(output_dir, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(message)s"

    logger = logging.getLogger("recon_pro")
    logger.setLevel(level)
    logger.handlers.clear()

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter(fmt, "%H:%M:%S"))
    ch.setLevel(level)
    logger.addHandler(ch)

    # File handler
    fh = logging.FileHandler(os.path.join(output_dir, "recon.log"))
    fh.setFormatter(logging.Formatter(fmt))
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)

    return logger


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string.
    
    Higher entropy indicates more randomness (typical for tokens/secrets).
    
    Args:
        s: Input string
        
    Returns:
        Shannon entropy value (0.0 - 8.0)
    """
    import math
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def decode_jwt_header(token: str) -> dict or None:
    """Decode JWT header and return parsed object if valid.
    
    Args:
        token: JWT token string
        
    Returns:
        Decoded header dict or None if invalid
    """
    import base64
    import json
    
    parts = token.split(".")
    if len(parts) < 2:
        return None
    
    header = parts[0]
    padded = header + "=" * (-len(header) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded)
        obj = json.loads(decoded)
        return obj if ("alg" in obj or "typ" in obj) else None
    except Exception:
        return None


def looks_like_jwt(token: str) -> bool:
    """Check if token looks like a valid JWT.
    
    Args:
        token: Token string to check
        
    Returns:
        True if token appears to be a valid JWT
    """
    return decode_jwt_header(token) is not None


def extract_context(data: str, match_start: int, match_end: int, context_chars: int = 120) -> str:
    """Extract surrounding context from data around a match.
    
    Args:
        data: Full data string
        match_start: Start position of match
        match_end: End position of match
        context_chars: Characters to include on each side
        
    Returns:
        Context string with match highlighted
    """
    start = max(0, match_start - context_chars)
    end = min(len(data), match_end + context_chars)
    context = data[start:end]
    
    # Add markers
    if start > 0:
        context = "..." + context
    if end < len(data):
        context = context + "..."
    
    return context


def is_likely_build_artifact(data: str, match_pos: int, window_size: int = 200) -> bool:
    """Check if match is likely a build-time artifact (webpack, vite, rollup).
    
    Args:
        data: Full data string
        match_pos: Position of match
        window_size: Characters to inspect around match
        
    Returns:
        True if likely a build artifact
    """
    start = max(0, match_pos - window_size)
    end = min(len(data), match_pos + window_size)
    window = data[start:end].lower()
    
    return any(marker.lower() in window for marker in BUILD_RUNTIME_MARKERS)


def sanitize_folder_name(name: str) -> str:
    """Transform a domain/identifier into a safe folder name.
    
    Args:
        name: Name to sanitize
        
    Returns:
        Safe folder name
    """
    name = name.strip().lower()
    name = re.sub(r"^https?://", "", name)
    name = name.rstrip("/")
    name = re.sub(r"[^a-z0-9._-]", "_", name)
    return name or "recon_run"


def is_test_file(path: str) -> bool:
    """Check if path indicates a test file.
    
    Args:
        path: File path
        
    Returns:
        True if likely a test file
    """
    path_lower = path.lower()
    test_indicators = ['.test.', '.spec.', '__tests__', 'fixtures/', 'mock', 'stub']
    return any(indicator in path_lower for indicator in test_indicators)
