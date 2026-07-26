"""Exposure detection module (.env, .git, CORS, GraphQL introspection)."""

import json
import logging
import uuid
from typing import List, Dict, Optional
from urllib.parse import urljoin

import requests


# Well-known sensitive files
WELL_KNOWN_SENSITIVE_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.production",
    "/.env.local",
    "/.aws/credentials",
    "/config.json.bak",
    "/wp-config.php.bak",
    "/docker-compose.yml",
    "/.DS_Store",
    "/backup.sql",
    "/.vscode/sftp.json",
]

# Content markers to confirm file authenticity
SENSITIVE_PATH_CONTENT_MARKERS = {
    "/.git/HEAD": ["ref:"],
    "/.git/config": ["[core]", "[remote"],
    "/.env": ["="],
    "/.env.production": ["="],
    "/.env.local": ["="],
    "/.aws/credentials": ["aws_access_key_id"],
    "/docker-compose.yml": ["version:", "services:"],
    "/.vscode/sftp.json": ['"host"'],
}

# GraphQL introspection query
GRAPHQL_INTROSPECTION_QUERY = json.dumps(
    {
        "query": """{
            __schema {
                types {
                    name
                    kind
                    fields {
                        name
                        type {
                            name
                        }
                    }
                }
            }
        }"""
    }
)


class ExposureDetector:
    """Detects common security exposures (CORS, .env, .git, GraphQL)."""

    def __init__(self, logger: logging.Logger, timeout: int = 8):
        """Initialize ExposureDetector.
        
        Args:
            logger: Logger instance
            timeout: Request timeout in seconds
        """
        self.logger = logger
        self.timeout = timeout

    def _response_signature(self, resp: requests.Response) -> tuple:
        """Create a response signature for catch-all detection.
        
        Args:
            resp: Response object
            
        Returns:
            Tuple of (status_code, content_type, body_length)
        """
        body_len = len(resp.content) if resp.content else 0
        content_type = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
        return (resp.status_code, content_type, body_len)

    def check_well_known_exposures(
        self, session: requests.Session, base_url: str
    ) -> List[Dict]:
        """Check for well-known sensitive files.
        
        Args:
            session: Requests session
            base_url: Base URL to check
            
        Returns:
            List of exposed files found
        """
        # Get baseline response
        canary_path = f"/__recon_canary_{uuid.uuid4().hex[:12]}.txt"
        try:
            baseline_resp = session.get(urljoin(base_url, canary_path), timeout=self.timeout)
            baseline_sig = self._response_signature(baseline_resp)
        except requests.RequestException as e:
            self.logger.debug(f"Failed to get baseline 404 for {base_url}: {e}")
            return []

        found = []
        for path in WELL_KNOWN_SENSITIVE_PATHS:
            try:
                full = urljoin(base_url, path)
                resp = session.get(full, timeout=self.timeout)
                
                if resp.status_code != 200:
                    continue
                
                # Skip catch-all responses
                if self._response_signature(resp) == baseline_sig:
                    continue
                
                # Skip HTML fallback
                content_type = resp.headers.get("Content-Type", "").lower()
                if "text/html" in content_type:
                    continue
                
                # Check content markers
                body = resp.text[:2000]
                markers = SENSITIVE_PATH_CONTENT_MARKERS.get(path)
                if markers and not any(m in body for m in markers):
                    continue
                
                found.append({
                    "path": path,
                    "url": full,
                    "content_type": content_type,
                })
                self.logger.warning(f"[EXPOSED FILE] {full}")
                
            except requests.RequestException as e:
                self.logger.debug(f"Failed to check {path} on {base_url}: {e}")
        
        return found

    def check_cors_misconfiguration(
        self, session: requests.Session, base_url: str
    ) -> Optional[Dict]:
        """Check for CORS misconfigurations.
        
        Args:
            session: Requests session
            base_url: Base URL to check
            
        Returns:
            CORS issue dict or None
        """
        probe_origin = "https://recon-cors-probe.invalid"
        
        try:
            resp = session.get(
                base_url, timeout=self.timeout, headers={"Origin": probe_origin}
            )
        except requests.RequestException as e:
            self.logger.debug(f"Failed CORS check for {base_url}: {e}")
            return None

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == probe_origin and acac == "true":
            self.logger.warning(
                f"[CORS MISCONFIG] {base_url}: reflects arbitrary Origin with credentials"
            )
            return {
                "url": base_url,
                "severity": "CRITICAL",
                "detail": "Access-Control-Allow-Origin reflects any Origin + credentials enabled",
            }
        
        if acao == "*":
            return {
                "url": base_url,
                "severity": "MEDIUM",
                "detail": "Access-Control-Allow-Origin: * (without credentials)",
            }
        
        return None

    def check_graphql_introspection(
        self, session: requests.Session, base_url: str, graphql_endpoints: List[str]
    ) -> List[Dict]:
        """Check if GraphQL introspection is enabled.
        
        Args:
            session: Requests session
            base_url: Base URL
            graphql_endpoints: List of potential GraphQL endpoints
            
        Returns:
            List of findings
        """
        findings = []
        
        for endpoint in graphql_endpoints:
            url = urljoin(base_url, endpoint)
            try:
                resp = session.post(
                    url,
                    data=GRAPHQL_INTROSPECTION_QUERY,
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout,
                )
                
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "data" in data and "__schema" in data["data"]:
                            self.logger.warning(
                                f"[GRAPHQL INTROSPECTION] {url}: schema introspection enabled"
                            )
                            findings.append({
                                "endpoint": endpoint,
                                "url": url,
                                "severity": "HIGH",
                                "detail": "GraphQL introspection enabled - schema is accessible",
                            })
                    except json.JSONDecodeError:
                        pass
                        
            except requests.RequestException as e:
                self.logger.debug(f"Failed GraphQL check on {url}: {e}")
        
        return findings
