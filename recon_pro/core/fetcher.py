"""Core fetcher module for downloading and caching JavaScript files."""

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

import requests


class Fetcher:
    """Handles JavaScript file downloading with retry, cache, and deduplication."""

    def __init__(self, output_dir: str, timeout: int = 8, retries: int = 2, delay: float = 0.0):
        """Initialize Fetcher.
        
        Args:
            output_dir: Directory for temporary files and cache
            timeout: Request timeout in seconds
            retries: Number of retry attempts
            delay: Delay between requests in seconds
        """
        self.output_dir = output_dir
        self.timeout = timeout
        self.retries = retries
        self.delay = delay
        self.temp_dir = os.path.join(output_dir, "temp_js_files")
        self.hash_cache_path = os.path.join(output_dir, "hash_cache.json")
        self.hash_cache = self._load_hash_cache()
        
        os.makedirs(self.temp_dir, exist_ok=True)

    def _load_hash_cache(self) -> dict:
        """Load hash cache from disk."""
        if os.path.exists(self.hash_cache_path):
            try:
                with open(self.hash_cache_path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def save_hash_cache(self, logger: logging.Logger) -> None:
        """Save hash cache to disk.
        
        Args:
            logger: Logger instance
        """
        try:
            with open(self.hash_cache_path, "w") as f:
                json.dump(self.hash_cache, f, indent=2)
        except OSError as e:
            logger.warning(f"Failed to save hash cache: {e}")

    def fetch_with_retry(
        self, url: str, logger: logging.Logger
    ) -> Optional[str]:
        """Fetch URL with retry logic and exponential backoff.
        
        Args:
            url: URL to fetch
            logger: Logger instance
            
        Returns:
            Response text or None on failure
        """
        last_exc = None
        for attempt in range(1, self.retries + 2):
            try:
                if self.delay:
                    time.sleep(self.delay)
                
                resp = requests.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    return resp.text
                elif resp.status_code == 429:
                    # Rate limited - exponential backoff
                    wait_time = min(2 ** attempt, 60)
                    logger.debug(f"Rate limited on {url}, waiting {wait_time}s")
                    time.sleep(wait_time)
                    continue
                elif resp.status_code in (401, 403):
                    # Access denied
                    logger.debug(f"Access denied: {url} (HTTP {resp.status_code})")
                    return None
                else:
                    logger.debug(f"HTTP {resp.status_code}: {url}")
                    return None
                    
            except requests.RequestException as e:
                last_exc = e
                logger.debug(f"Attempt {attempt} failed for {url}: {e}")
                time.sleep(min(2 ** attempt, 10))
        
        logger.debug(f"Gave up on {url} after {self.retries + 1} attempts ({last_exc})")
        return None

    def process_js(
        self, url: str, logger: logging.Logger
    ) -> Optional[tuple[str, str]]:
        """Download and process JavaScript file.
        
        Implements deduplication by content hash and temporary file storage.
        
        Args:
            url: URL to fetch
            logger: Logger instance
            
        Returns:
            Tuple of (content, file_hash) or None on failure
        """
        data = self.fetch_with_retry(url, logger)
        if data is None or len(data) < 100:
            return None

        # Dedup by content hash
        file_hash = hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()
        
        if file_hash in self.hash_cache:
            logger.info(
                f"Duplicate by hash, skipping: {url} "
                f"(already processed as {self.hash_cache[file_hash]})"
            )
            return None
        
        # Store in cache
        self.hash_cache[file_hash] = url
        
        # Save to disk
        try:
            filepath = os.path.join(self.temp_dir, f"{file_hash}.js")
            with open(filepath, "w", encoding="utf-8", errors="ignore") as f:
                f.write(data)
        except OSError as e:
            logger.warning(f"Failed to save local copy of {url}: {e}")
        
        return data, file_hash
