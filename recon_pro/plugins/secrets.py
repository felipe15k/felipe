"""Secret extraction and validation module."""

import json
import logging
import re
from typing import List, Dict, Optional

import requests

from ..utils import (
    shannon_entropy,
    decode_jwt_header,
    CAMEL_CASE_IDENTIFIER_PATTERN,
    CONSTANT_NAME_PATTERN,
    LOOKS_LIKE_PATH_PATTERN,
    KNOWN_PLACEHOLDER_SECRETS,
    is_test_file,
    is_likely_build_artifact,
    extract_context,
)


# Secret patterns with high precision
SECRET_PATTERNS = {
    "AWS Access Key": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token": r"ghp_[A-Za-z0-9]{36}",
    "GitHub Token (outros escopos)": r"gh[oprsu]_[A-Za-z0-9]{36}",
    "GitHub Fine-grained PAT": r"github_pat_[A-Za-z0-9_]{22,}",
    "Generic JWT": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "Private Key": r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z-]{10,48}",
    "Stripe Live Secret Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Live Publishable Key": r"pk_live_[0-9a-zA-Z]{24,}",
    "SendGrid API Key": r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twilio Account SID": r"AC[a-f0-9]{32}",
    "npm Access Token": r"npm_[A-Za-z0-9]{36}",
    "Azure Storage Connection String": r"DefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{20,}",
    "Azure Client Secret": r"(?i)client_secret\s*[:=]\s*['\"][A-Za-z0-9_.\-~]{34,40}['\"]",
    "Firebase/GCP Service Account": r'"type":\s*"service_account"',
    "Heroku API Key": r"(?i)heroku[a-z0-9_\-]{0,20}\s*[:=]\s*['\"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"]",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Discord Webhook": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+",
    "OpenAI API Key": r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
    "Anthropic API Key": r"sk-ant-(?:api03-)?[A-Za-z0-9_\-]{90,}",
    "Database Connection String": r"(?i)(postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[A-Za-z0-9_.\-]+:[^@\s'\"]{4,}@[A-Za-z0-9_.\-]+(?::\d+)?/[A-Za-z0-9_.\-]*",
    "Generic Bearer Token": r"(?i)bearer\s+[A-Za-z0-9_\-.=]{20,}",
    "Generic Secret Assignment": r"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"]([A-Za-z0-9_\-/+=]{16,})['\"]  ",
}

# Secret types exempt from entropy filtering
ENTROPY_EXEMPT_TYPES = {
    "Private Key",
    "Discord Webhook",
    "Database Connection String",
    "Azure Storage Connection String",
    "Firebase/GCP Service Account",
    "Heroku API Key",
}

# Entropy thresholds by secret type
ENTROPY_THRESHOLDS = {
    "AWS Secret Key": 4.0,
    "Google API Key": 3.9,
    "Generic JWT": 4.2,
    "Generic Secret Assignment": 3.7,
    "Slack Token": 3.5,
    "Stripe Live Secret Key": 3.5,
    "Stripe Live Publishable Key": 3.5,
    "SendGrid API Key": 3.8,
    "Twilio API Key": 3.3,
    "Twilio Account SID": 3.0,
    "npm Access Token": 3.8,
    "GitHub Token (outros escopos)": 3.8,
    "GitHub Fine-grained PAT": 3.8,
    "Azure Client Secret": 3.9,
    "Mailgun API Key": 3.7,
    "Generic Bearer Token": 3.8,
}

# Secret types that are client-side public by design
PUBLIC_BY_DESIGN_SECRET_TYPES = {
    "Google API Key",
    "Stripe Live Publishable Key",
    "Twilio Account SID",
}

MIN_ENTROPY = 3.5


class SecretExtractor:
    """Extracts secrets from JavaScript with advanced filtering."""

    def __init__(self, logger: logging.Logger):
        """Initialize SecretExtractor.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger
        self.patterns = SECRET_PATTERNS
        self.entropy_thresholds = ENTROPY_THRESHOLDS

    def extract(
        self, data: str, source_label: Optional[str] = None, file_path: Optional[str] = None
    ) -> List[Dict]:
        """Extract secrets from data with comprehensive filtering.
        
        Args:
            data: JavaScript code to analyze
            source_label: Label for source (e.g., source map file)
            file_path: File path for test file detection
            
        Returns:
            List of discovered secrets
        """
        # Skip if test file
        if file_path and is_test_file(file_path):
            return []
        
        found = []
        
        for name, pattern in self.patterns.items():
            for match in re.finditer(pattern, data):
                # Extract value
                if name == "Generic Secret Assignment":
                    clean = match.group(2) if match.lastindex >= 2 else match.group(0)
                else:
                    clean = match.group(0)
                
                clean = clean.strip()
                
                # Basic length check
                if len(clean) <= 5:
                    continue
                
                # Check placeholder
                if clean.lower() in KNOWN_PLACEHOLDER_SECRETS:
                    self.logger.debug(f"Skipped placeholder ({name}): {clean[:30]}...")
                    continue
                
                # Check build artifact
                if is_likely_build_artifact(data, match.start()):
                    self.logger.debug(f"Skipped build artifact ({name}): {clean[:30]}...")
                    continue
                
                # JWT validation
                jwt_header = None
                if name == "Generic JWT":
                    jwt_header = decode_jwt_header(clean)
                    if jwt_header is None:
                        continue
                elif name not in ENTROPY_EXEMPT_TYPES:
                    threshold = self.entropy_thresholds.get(name, MIN_ENTROPY)
                    if shannon_entropy(clean) < threshold:
                        self.logger.debug(
                            f"Skipped low entropy ({name}, threshold={threshold}): {clean[:20]}..."
                        )
                        continue
                
                # Heuristic filters for Generic Secret Assignment
                if name == "Generic Secret Assignment":
                    if CONSTANT_NAME_PATTERN.match(clean):
                        self.logger.debug(f"Skipped constant name: {clean[:40]}")
                        continue
                    if CAMEL_CASE_IDENTIFIER_PATTERN.match(clean):
                        self.logger.debug(f"Skipped camelCase identifier: {clean[:40]}")
                        continue
                    if LOOKS_LIKE_PATH_PATTERN.match(clean):
                        self.logger.debug(f"Skipped path pattern: {clean[:40]}")
                        continue
                
                # Create entry
                entry = {
                    "type": name,
                    "value": clean,
                    "confidence": "HIGH",
                    "context": extract_context(data, match.start(), match.end()),
                }
                
                if source_label:
                    entry["source_file"] = source_label
                
                # JWT notes
                if jwt_header is not None:
                    alg = str(jwt_header.get("alg", "")).lower()
                    if alg == "none":
                        entry["note"] = "JWT with alg:none vulnerability"
                    elif alg in ("hs256", "hs384", "hs512"):
                        entry["note"] = f"JWT signed with {alg.upper()} (symmetric key)"
                
                # Public by design
                if name in PUBLIC_BY_DESIGN_SECRET_TYPES:
                    entry["confidence"] = "INFO"
                    entry["note"] = "Public by design - verify provider restrictions"
                
                found.append(entry)
        
        # Dedup by value
        return self._dedup_by_value(found)

    def _dedup_by_value(self, items: List[Dict]) -> List[Dict]:
        """Deduplicate by secret value, keeping most specific type.
        
        Args:
            items: List of secret entries
            
        Returns:
            Deduplicated list
        """
        by_value = {}
        for item in items:
            key = item["value"].lower()
            existing = by_value.get(key)
            # Keep specific types over Generic Secret Assignment
            if existing is None or existing["type"] == "Generic Secret Assignment":
                by_value[key] = item
        return list(by_value.values())


class SecretValidator:
    """Validates secrets against provider APIs."""

    def __init__(self, timeout: int = 8):
        """Initialize SecretValidator.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout

    def validate_github(self, token: str) -> Optional[bool]:
        """Validate GitHub token.
        
        Args:
            token: GitHub token to validate
            
        Returns:
            True if valid, False if invalid, None if inconclusive
        """
        try:
            r = requests.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {token}"},
                timeout=self.timeout,
            )
            if r.status_code == 200:
                return True
            if r.status_code == 401:
                return False
            return None
        except requests.RequestException:
            return None

    def validate_slack(self, token: str) -> Optional[bool]:
        """Validate Slack token.
        
        Args:
            token: Slack token to validate
            
        Returns:
            True if valid, False if invalid, None if inconclusive
        """
        try:
            r = requests.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {token}"},
                timeout=self.timeout,
            )
            return bool(r.json().get("ok"))
        except Exception:
            return None

    def validate_stripe(self, token: str) -> Optional[bool]:
        """Validate Stripe API key.
        
        Args:
            token: Stripe secret key
            
        Returns:
            True if valid, False if invalid, None if inconclusive
        """
        try:
            r = requests.get(
                "https://api.stripe.com/v1/charges?limit=1",
                auth=(token, ""),
                timeout=self.timeout,
            )
            if r.status_code == 200:
                return True
            if r.status_code == 401:
                return False
            return None
        except requests.RequestException:
            return None

    def validate_sendgrid(self, token: str) -> Optional[bool]:
        """Validate SendGrid API key.
        
        Args:
            token: SendGrid API key
            
        Returns:
            True if valid, False if invalid, None if inconclusive
        """
        try:
            r = requests.get(
                "https://api.sendgrid.com/v3/scopes",
                headers={"Authorization": f"Bearer {token}"},
                timeout=self.timeout,
            )
            if r.status_code == 200:
                return True
            if r.status_code == 401:
                return False
            return None
        except requests.RequestException:
            return None

    def validate_npm(self, token: str) -> Optional[bool]:
        """Validate npm access token.
        
        Args:
            token: npm token
            
        Returns:
            True if valid, False if invalid, None if inconclusive
        """
        try:
            r = requests.get(
                "https://registry.npmjs.org/-/npm/v1/user",
                headers={"Authorization": f"Bearer {token}"},
                timeout=self.timeout,
            )
            if r.status_code == 200:
                return True
            if r.status_code in (401, 403):
                return False
            return None
        except requests.RequestException:
            return None

    def validate_aws(self, access_key: str, secret_key: str) -> Optional[bool]:
        """Validate AWS credentials.
        
        Args:
            access_key: AWS access key
            secret_key: AWS secret key
            
        Returns:
            True if valid, False if invalid, None if inconclusive
        """
        try:
            import boto3
            from botocore.exceptions import ClientError
            
            client = boto3.client(
                "sts",
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name="us-east-1",
            )
            client.get_caller_identity()
            return True
        except ClientError:
            return False
        except Exception:
            return None

    def validate_twilio(self, account_sid: str, auth_token: str) -> Optional[bool]:
        """Validate Twilio credentials.
        
        Args:
            account_sid: Twilio Account SID
            auth_token: Twilio Auth Token
            
        Returns:
            True if valid, False if invalid, None if inconclusive
        """
        try:
            r = requests.get(
                f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}.json",
                auth=(account_sid, auth_token),
                timeout=self.timeout,
            )
            if r.status_code == 200:
                return True
            if r.status_code == 401:
                return False
            return None
        except requests.RequestException:
            return None
