"""Core analyzer module for coordinating analysis."""

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
from urllib.parse import urljoin

import requests

from ..core.fetcher import Fetcher
from ..plugins.secrets import SecretExtractor, SecretValidator
from ..plugins.endpoints import EndpointExtractor
from ..plugins.exposures import ExposureDetector


class Analyzer:
    """Coordinates the analysis of JavaScript files."""

    def __init__(self, args, logger: logging.Logger):
        """Initialize Analyzer.
        
        Args:
            args: Parsed arguments
            logger: Logger instance
        """
        self.args = args
        self.logger = logger
        self.fetcher = Fetcher(
            args.output_dir,
            timeout=args.timeout,
            retries=args.retries,
            delay=args.delay,
        )
        self.secret_extractor = SecretExtractor(logger)
        self.secret_validator = SecretValidator(args.timeout)
        self.endpoint_extractor = EndpointExtractor(logger)
        self.exposure_detector = ExposureDetector(logger, args.timeout)

    def analyze_file(
        self, session: requests.Session, url: str
    ) -> Optional[Dict]:
        """Analyze a single JavaScript file.
        
        Args:
            session: Requests session
            url: URL of JavaScript file
            
        Returns:
            Analysis result dict or None
        """
        # Fetch file
        result = self.fetcher.process_js(url, self.logger)
        if result is None:
            return None
        
        data, file_hash = result

        findings = {
            "url": url,
            "file_hash": file_hash,
            "secrets": [],
            "endpoints": [],
            "storage_buckets": [],
            "high_value": [],
        }

        # Extract secrets
        findings["secrets"] = self.secret_extractor.extract(data, file_path=url)

        # Extract storage buckets
        findings["storage_buckets"] = self.endpoint_extractor.extract_storage_buckets(data, self.logger)

        # Extract endpoints
        from_doc_page = self.endpoint_extractor.is_likely_doc_page(url)
        endpoints = self.endpoint_extractor.extract(data, from_doc_page)
        
        # Flag vendored libraries
        self.endpoint_extractor.flag_vendored_libraries(endpoints)
        
        # Verify endpoints if requested
        for entry in endpoints:
            if self.args.verify_endpoints and "source_file" not in entry:
                is_noise = (
                    entry.get("likely_vendored_library")
                    or entry.get("vendored_library")
                    or entry.get("likely_telemetry")
                )
                should_verify = (
                    entry["severity"] in ("CRITICAL", "HIGH")
                    and not is_noise
                ) or self.args.verify_all
                
                if should_verify:
                    status = self._verify_endpoint(session, url, entry["path"])
                    entry["status"] = status if status else "FAILED"
                    
                    # Skip dead endpoints
                    if status in (None, 404, "SPA_FALLBACK"):
                        continue
            
            findings["endpoints"].append(entry)
            if entry["severity"] == "CRITICAL":
                findings["high_value"].append(entry["path"])
        
        return findings if (findings["secrets"] or findings["endpoints"] or findings["storage_buckets"]) else None

    def _verify_endpoint(
        self, session: requests.Session, base_url: str, endpoint: str
    ) -> Optional[str]:
        """Verify endpoint exists via HEAD request.
        
        Args:
            session: Requests session
            base_url: Base URL
            endpoint: Endpoint path
            
        Returns:
            HTTP status code, "SPA_FALLBACK", or None
        """
        try:
            full = urljoin(base_url, endpoint)
            resp = session.head(full, timeout=self.args.timeout, allow_redirects=True)
            status = resp.status_code
            content_type = resp.headers.get("Content-Type", "").lower()
            
            # Detect SPA fallback
            looks_like_api = "/api/" in endpoint or "/graphql" in endpoint
            if status == 200 and "text/html" in content_type and looks_like_api:
                return "SPA_FALLBACK"
            
            return status
        except requests.RequestException:
            return None
