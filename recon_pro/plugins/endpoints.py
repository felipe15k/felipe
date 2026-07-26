"""Endpoint extraction and analysis module."""

import logging
import re
from typing import List, Dict, Optional

from ..utils import (
    HIGH_VALUE_KEYWORDS,
    NOISE_MARKERS,
    TELEMETRY_PATH_MARKERS,
    DOC_PAGE_MARKERS,
    extract_context,
)


# API endpoint patterns
API_PATTERNS = [
    r'["\'](\/api\/v\d+\/[^"\'
]+)["\']',
    r'["\'](\/graphql[^"\'
]*)["\']',
    r'["\'](\/rest\/[^"\'
]+)["\']',
    r'["\'](\/internal\/[^"\'
]+)["\']',
    r'["\'](\/admin\/[^"\'
]+)["\']',
    r'["\'](\/manage\/[^"\'
]+)["\']',
    r'["\'](\/auth\/[^"\'
]+)["\']',
    r'["\'](\/api\/[^"\'
]+)["\']',
    r'["\']((wss?:\/\/)[^"\'
]+)["\']',
]

# Storage bucket patterns
STORAGE_BUCKET_PATTERNS = {
    "AWS S3": r"([a-z0-9.\-]+\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com|s3\.amazonaws\.com/[a-z0-9.\-]+)",
    "Google Cloud Storage": r"storage\.googleapis\.com/[a-z0-9._\-]+",
    "Azure Blob Storage": r"[a-z0-9]+\.blob\.core\.windows\.net(?:/[a-z0-9._\-]+)?",
}

# Known third-party library signatures
KNOWN_LIBRARY_SIGNATURES = {
    "Blockscout (block explorer)": [
        "smart-contracts/verification",
        "optimism/output-roots",
        "validators/zilliqa",
        "tokens/bridged",
        "internal-transactions",
    ],
    "Stripe API/Elements": [
        "/v1/payment_intents",
        "/v1/setup_intents",
        "/v1/sources",
        "/v1/tokens",
        "/v1/payment_methods",
    ],
    "Auth0": [
        "/oauth/token",
        "/userinfo",
        "/.well-known/jwks.json",
        "/dbconnections/",
        "/passwordless/",
    ],
    "Algolia": [
        "/1/indexes/",
        "/1/keys",
        "/1/clusters",
    ],
    "Segment Analytics": [
        "/v1/batch",
        "/v1/identify",
        "/v1/track",
        "/v1/page",
        "/v1/alias",
    ],
}

MIN_LIBRARY_SIGNATURE_MATCHES = 3
VENDORED_LIBRARY_ENDPOINT_THRESHOLD = 15


class EndpointExtractor:
    """Extracts and classifies API endpoints from JavaScript."""

    def __init__(self, logger: logging.Logger):
        """Initialize EndpointExtractor.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger
        self.patterns = API_PATTERNS
        self.storage_patterns = STORAGE_BUCKET_PATTERNS

    def extract(
        self, data: str, from_doc_page: bool = False, source_label: Optional[str] = None
    ) -> List[Dict]:
        """Extract endpoints from JavaScript data.
        
        Args:
            data: JavaScript code to analyze
            from_doc_page: Whether data is from a documentation page
            source_label: Label for source (e.g., source map file)
            
        Returns:
            List of discovered endpoints
        """
        found = []
        seen = set()

        for pattern in self.patterns:
            for m in re.findall(pattern, data):
                endpoint = m.strip() if isinstance(m, str) else m[0].strip()
                
                # Skip noise
                if any(x in endpoint.lower() for x in NOISE_MARKERS):
                    continue
                if endpoint in seen:
                    continue
                seen.add(endpoint)

                severity = self._classify_endpoint(endpoint)
                entry = {
                    "path": endpoint,
                    "severity": severity,
                    "status": "UNKNOWN",
                    "context": extract_context(data, data.find(endpoint), data.find(endpoint) + len(endpoint)),
                }
                
                if source_label:
                    entry["source_file"] = source_label

                # Check for telemetry
                if any(marker in endpoint.lower() for marker in TELEMETRY_PATH_MARKERS):
                    downgrade = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "MEDIUM"}
                    if severity != downgrade.get(severity):
                        entry["severity"] = severity = downgrade.get(severity)
                    entry["likely_telemetry"] = True

                # Check for documentation pages
                if from_doc_page:
                    downgrade = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "MEDIUM"}
                    entry["severity"] = downgrade.get(severity, "MEDIUM")
                    entry["note"] = "Found in documentation page"

                found.append(entry)

        return found

    def extract_storage_buckets(self, data: str, logger: logging.Logger = None) -> List[Dict]:
        """Extract cloud storage bucket references.
        
        Args:
            data: JavaScript code to analyze
            logger: Logger instance
            
        Returns:
            List of discovered storage buckets
        """
        found = []
        seen = set()
        
        for provider, pattern in self.storage_patterns.items():
            for match in re.finditer(pattern, data, re.IGNORECASE):
                bucket = match.group(0).strip().rstrip("/\"'")
                if bucket not in seen:
                    seen.add(bucket)
                    found.append({"provider": provider, "value": bucket})
        
        if found and logger:
            logger.debug(f"{len(found)} storage bucket reference(s) found")
        
        return found

    def _classify_endpoint(self, endpoint: str) -> str:
        """Classify endpoint severity.
        
        Args:
            endpoint: Endpoint path
            
        Returns:
            Severity level: CRITICAL, HIGH, or MEDIUM
        """
        ep_lower = endpoint.lower()
        
        # Check for high-value keywords
        if any(kw in ep_lower for kw in HIGH_VALUE_KEYWORDS):
            return "CRITICAL"
        
        # Check for API patterns
        if "/api/" in ep_lower or "/graphql" in ep_lower:
            return "HIGH"
        
        return "MEDIUM"

    def flag_vendored_libraries(self, endpoints: List[Dict]) -> Optional[str]:
        """Detect if endpoints are from a known third-party library.
        
        Args:
            endpoints: List of endpoint entries
            
        Returns:
            Name of detected library or None
        """
        paths = [e["path"] for e in endpoints]
        joined = " ".join(p.lower() for p in paths)
        
        best_name, best_count = None, 0
        for lib_name, markers in KNOWN_LIBRARY_SIGNATURES.items():
            count = sum(1 for m in markers if m.lower() in joined)
            if count > best_count:
                best_name, best_count = lib_name, count
        
        if best_count >= MIN_LIBRARY_SIGNATURE_MATCHES:
            for e in endpoints:
                e["vendored_library"] = best_name
            return best_name
        
        # Check for volume-based vendoring
        non_medium = [e for e in endpoints if e["severity"] in ("CRITICAL", "HIGH")]
        if len(non_medium) > VENDORED_LIBRARY_ENDPOINT_THRESHOLD:
            for e in endpoints:
                e["likely_vendored_library"] = True
            return True
        
        return None

    def is_likely_doc_page(self, url: str) -> bool:
        """Check if URL indicates a documentation page.
        
        Args:
            url: URL to check
            
        Returns:
            True if likely a documentation page
        """
        u_lower = url.lower()
        return any(marker in u_lower for marker in DOC_PAGE_MARKERS)
