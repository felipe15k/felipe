"""Main scanner orchestration module."""

import logging
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Optional
from urllib.parse import urlparse

import requests

from ..core.analyzer import Analyzer
from ..core.fetcher import Fetcher
from ..plugins.exposures import ExposureDetector
from ..utils import sanitize_folder_name


class ReconScanner:
    """Main orchestrator for the reconnaissance scanning process."""

    HISTORY_DIRNAME = ".recon_history"

    def __init__(self, args, logger: logging.Logger):
        """Initialize ReconScanner.
        
        Args:
            args: Parsed command-line arguments
            logger: Logger instance
        """
        self.args = args
        self.logger = logger
        self.run_dir, self.run_name = self._resolve_run_dir()
        self.args.output_dir = self.run_dir
        self.logger.info(f"Run directory: {self.run_dir}")

    def _resolve_run_dir(self) -> tuple:
        """Resolve the run directory and handle cleanup of old runs.
        
        Returns:
            Tuple of (run_dir, run_name)
        """
        base_dir = self.args.output_dir
        
        # Determine run name
        if self.args.u:
            raw = self.args.u
            domain = raw if not raw.startswith("http") else urlparse(raw).netloc
            run_name = sanitize_folder_name(domain)
        else:
            run_name = sanitize_folder_name(
                Path(self.args.l).stem
            )

        os.makedirs(base_dir, exist_ok=True)

        # Cleanup old runs
        if not self.args.keep_old:
            for entry in os.listdir(base_dir):
                if entry == self.HISTORY_DIRNAME:
                    continue
                entry_path = os.path.join(base_dir, entry)
                if entry == run_name or not os.path.isdir(entry_path):
                    continue
                try:
                    shutil.rmtree(entry_path)
                    self.logger.info(f"Removed old run directory: {entry_path}")
                except OSError as e:
                    self.logger.warning(f"Failed to remove old run: {e}")

        run_dir = os.path.join(base_dir, run_name)
        if os.path.isdir(run_dir):
            try:
                shutil.rmtree(run_dir)
                self.logger.info(f"Cleaned up existing run directory: {run_dir}")
            except OSError as e:
                self.logger.warning(f"Failed to clean run directory: {e}")

        os.makedirs(run_dir, exist_ok=True)
        return run_dir, run_name

    def run(self) -> int:
        """Execute the scanning process.
        
        Returns:
            Exit code
        """
        try:
            # Load domains
            domains = self._load_domains()
            if not domains:
                self.logger.error("No valid domains found")
                return 1

            self.logger.info(f"Target domains: {domains}")

            # Initialize session
            session = requests.Session()
            session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            })

            # Discover assets
            all_targets = self._discover_assets(domains)
            if not all_targets:
                self.logger.error("No targets discovered")
                return 1

            self.logger.info(f"Discovered {len(all_targets)} target(s)")

            # Check exposures
            exposure_findings = {"exposed_files": [], "cors_issues": [], "graphql_issues": []}
            if not self.args.skip_exposure_checks:
                exposure_findings = self._check_exposures(session, all_targets)

            # Get JS URLs
            js_urls = self._get_js_urls(all_targets)
            if not js_urls:
                self.logger.warning("No JavaScript files found")
                return 1

            self.logger.info(f"Found {len(js_urls)} JavaScript file(s)")

            # Analyze JavaScript
            analyzer = Analyzer(self.args, self.logger)
            results = self._analyze_js_files(session, analyzer, js_urls)

            # Post-processing
            if self.args.validate_secrets:
                results = self._validate_secrets(results, analyzer.secret_validator)

            results = self._deduplicate_global_secrets(results)

            # Save reports
            self._save_reports(results, exposure_findings)

            # Print summary
            self._print_summary(results, exposure_findings)

            return 0

        except Exception as e:
            self.logger.error(f"Fatal error: {e}", exc_info=True)
            return 1

    def _load_domains(self) -> List[str]:
        """Load target domains.
        
        Returns:
            List of domain strings
        """
        if self.args.u:
            raw = self.args.u
            domain = raw if not raw.startswith("http") else urlparse(raw).netloc
            return [domain]

        if not os.path.isfile(self.args.l):
            self.logger.error(f"Domain file not found: {self.args.l}")
            return []

        with open(self.args.l) as f:
            domains = [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]
        return domains

    def _discover_assets(self, domains: List[str]) -> List[str]:
        """Discover subdomains and targets.
        
        Args:
            domains: List of domains
            
        Returns:
            List of target URLs
        """
        all_targets = set()
        
        for domain in domains:
            all_targets.add(f"https://{domain}")
            
            # Try subfinder if available
            if shutil.which("subfinder"):
                try:
                    result = subprocess.run(
                        ["subfinder", "-d", domain, "-silent"],
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    subs = [s.strip() for s in result.stdout.splitlines() if s.strip()]
                    for sub in subs:
                        all_targets.add(f"https://{sub}")
                    self.logger.info(f"subfinder found {len(subs)} subdomains for {domain}")
                except Exception as e:
                    self.logger.debug(f"subfinder failed: {e}")
            else:
                self.logger.warning("subfinder not found, using only root domain")
        
        return list(all_targets)

    def _get_js_urls(self, targets: List[str]) -> List[str]:
        """Collect JavaScript file URLs.
        
        Args:
            targets: List of target URLs
            
        Returns:
            List of JavaScript URLs
        """
        all_js = set()
        hosts = [t.replace("https://", "").replace("http://", "") for t in targets]
        hosts_stdin = "\n".join(hosts)

        # Try gau
        if shutil.which("gau"):
            try:
                result = subprocess.run(
                    ["gau"],
                    input=hosts_stdin,
                    capture_output=True,
                    text=True,
                    timeout=self.args.tool_timeout,
                )
                urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                all_js.update(u for u in urls if u.endswith((".js", ".json")))
                self.logger.info(f"gau found {len(urls)} URL(s)")
            except Exception as e:
                self.logger.debug(f"gau failed: {e}")

        # Try waybackurls
        if shutil.which("waybackurls"):
            try:
                result = subprocess.run(
                    ["waybackurls"],
                    input=hosts_stdin,
                    capture_output=True,
                    text=True,
                    timeout=self.args.tool_timeout,
                )
                urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                all_js.update(u for u in urls if u.endswith((".js", ".json")))
                self.logger.info(f"waybackurls found {len(urls)} URL(s)")
            except Exception as e:
                self.logger.debug(f"waybackurls failed: {e}")

        # Try katana
        if shutil.which("katana"):
            try:
                targets_file = os.path.join(self.args.output_dir, "katana_targets.txt")
                with open(targets_file, "w") as f:
                    f.write("\n".join(targets))
                
                result = subprocess.run(
                    [
                        "katana",
                        "-list",
                        targets_file,
                        "-d",
                        "2",
                        "-silent",
                        "-ef",
                        "woff,css,png,jpg,svg,map",
                        "-c",
                        str(self.args.katana_concurrency),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=self.args.tool_timeout,
                )
                urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                all_js.update(u for u in urls if u.endswith((".js", ".json")))
                self.logger.info(f"katana found {len(urls)} URL(s)")
            except Exception as e:
                self.logger.debug(f"katana failed: {e}")
        
        # Normalize URLs
        all_js = {
            u if u.startswith(("http://", "https://")) else f"https://{u}"
            for u in all_js
        }
        
        self.logger.info(f"Total unique JS files: {len(all_js)}")
        return list(all_js)

    def _check_exposures(
        self, session: requests.Session, targets: List[str]
    ) -> Dict:
        """Check for common security exposures.
        
        Args:
            session: Requests session
            targets: List of target URLs
            
        Returns:
            Dictionary of findings
        """
        findings = {"exposed_files": [], "cors_issues": [], "graphql_issues": []}
        detector = ExposureDetector(self.logger, self.args.timeout)
        
        self.logger.info(f"Checking exposures on {len(targets)} target(s)...")
        
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = {
                executor.submit(
                    self._check_one_target_exposure, detector, session, target
                ): target
                for target in targets
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        findings["exposed_files"].extend(result[0])
                        if result[1]:
                            findings["cors_issues"].append(result[1])
                        findings["graphql_issues"].extend(result[2])
                except Exception as e:
                    self.logger.debug(f"Exposure check failed: {e}")
        
        return findings

    def _check_one_target_exposure(
        self, detector: ExposureDetector, session: requests.Session, target: str
    ) -> tuple:
        """Check one target for exposures.
        
        Args:
            detector: ExposureDetector instance
            session: Requests session
            target: Target URL
            
        Returns:
            Tuple of (exposed_files, cors_issue, graphql_issues)
        """
        exposed = detector.check_well_known_exposures(session, target)
        cors = detector.check_cors_misconfiguration(session, target)
        graphql = detector.check_graphql_introspection(session, target, ["/graphql"])
        
        for e in exposed:
            e["target"] = target
        
        return exposed, cors, graphql

    def _analyze_js_files(
        self,
        session: requests.Session,
        analyzer: Analyzer,
        js_urls: List[str],
    ) -> List[Dict]:
        """Analyze JavaScript files.
        
        Args:
            session: Requests session
            analyzer: Analyzer instance
            js_urls: List of JS URLs
            
        Returns:
            List of analysis results
        """
        results = []
        self.logger.info(f"Analyzing {len(js_urls)} file(s) with {self.args.threads} thread(s)...")
        
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = {
                executor.submit(analyzer.analyze_file, session, url): url
                for url in js_urls
            }
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 10 == 0 or completed == len(futures):
                    self.logger.info(f"Progress: {completed}/{len(futures)} files analyzed")
                
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        self.logger.info(f"FOUND: {result['url']}")
                        if result["high_value"]:
                            self.logger.warning(f"  [CRITICAL] {result['high_value']}")
                        if result["secrets"]:
                            self.logger.warning(f"  [SECRET] {len(result['secrets'])} secret(s)")
                except Exception as e:
                    self.logger.error(f"Analysis error: {e}")
        
        return results

    def _validate_secrets(
        self, results: List[Dict], validator
    ) -> List[Dict]:
        """Validate secrets against provider APIs.
        
        Args:
            results: Analysis results
            validator: SecretValidator instance
            
        Returns:
            Results with validated secrets
        """
        self.logger.info("Validating secrets...")
        
        unique_targets = {}
        for res in results:
            for s in res.get("secrets", []):
                if s.get("confidence") != "HIGH":
                    continue
                
                stype = s["type"]
                if stype == "GitHub Token":
                    key = (stype, s["value"])
                    unique_targets[key] = lambda v=s["value"]: validator.validate_github(v)
                elif stype == "Slack Token":
                    key = (stype, s["value"])
                    unique_targets[key] = lambda v=s["value"]: validator.validate_slack(v)
        
        outcomes = {}
        for (stype, value), validate_fn in unique_targets.items():
            outcome = validate_fn()
            outcomes[(stype, value)] = outcome
            if outcome is True:
                self.logger.warning(f"  [CONFIRMED] {stype}: {value[:20]}... is VALID")
            elif outcome is False:
                self.logger.info(f"  [INVALID] {stype}: {value[:20]}... not valid")
        
        # Apply outcomes
        for res in results:
            for s in res.get("secrets", []):
                key = (s.get("type"), s.get("value"))
                if key in outcomes:
                    outcome = outcomes[key]
                    if outcome is True:
                        s["confidence"] = "CONFIRMED"
                        s["note"] = "Validated against provider API - still valid"
                    elif outcome is False:
                        s["confidence"] = "INVALID"
                        s["note"] = "Validated against provider API - no longer valid"
        
        return results

    def _deduplicate_global_secrets(self, results: List[Dict], threshold: int = 5) -> List[Dict]:
        """Deduplicate secrets that appear in many files (likely build artifacts).
        
        Args:
            results: Analysis results
            threshold: Minimum file count to mark as LOW confidence
            
        Returns:
            Results with deduplicated secrets
        """
        value_files = {}
        for res in results:
            for s in res.get("secrets", []):
                value_files.setdefault(s["value"], set()).add(res["url"])
        
        downgraded = 0
        for res in results:
            for s in res.get("secrets", []):
                n_files = len(value_files[s["value"]])
                if s.get("confidence", "HIGH") == "HIGH" and n_files >= threshold:
                    s["confidence"] = "LOW"
                    s["note"] = f"Same value in {n_files} files - likely build constant"
                    downgraded += 1
        
        if downgraded:
            self.logger.info(
                f"Deduplicated {downgraded} secret(s) appearing in multiple files"
            )
        
        return results

    def _save_reports(self, results: List[Dict], exposure_findings: Dict) -> None:
        """Save analysis reports.
        
        Args:
            results: Analysis results
            exposure_findings: Exposure findings
        """
        import json
        
        os.makedirs(self.args.output_dir, exist_ok=True)
        
        # Main report
        report_path = os.path.join(self.args.output_dir, "intelligence_report.json")
        with open(report_path, "w") as f:
            json.dump(results, f, indent=2)
        self.logger.info(f"Report saved: {report_path}")
        
        # Exposure findings
        if exposure_findings["exposed_files"] or exposure_findings["cors_issues"]:
            exposure_path = os.path.join(self.args.output_dir, "exposure_findings.json")
            with open(exposure_path, "w") as f:
                json.dump(exposure_findings, f, indent=2)
            self.logger.warning(
                f"{len(exposure_findings['exposed_files'])} exposed file(s), "
                f"{len(exposure_findings['cors_issues'])} CORS issue(s) found"
            )

    def _print_summary(self, results: List[Dict], exposure_findings: Dict) -> None:
        """Print execution summary.
        
        Args:
            results: Analysis results
            exposure_findings: Exposure findings
        """
        total_secrets = 0
        total_endpoints = 0
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
        secret_types = {}
        
        for res in results:
            total_secrets += len(res.get("secrets", []))
            total_endpoints += len(res.get("endpoints", []))
            
            for s in res.get("secrets", []):
                secret_types[s["type"]] = secret_types.get(s["type"], 0) + 1
            
            for e in res.get("endpoints", []):
                severity = e.get("severity", "MEDIUM")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        self.logger.info("=" * 50)
        self.logger.info("EXECUTION SUMMARY")
        self.logger.info("=" * 50)
        self.logger.info(f"Files analyzed: {len(results)}")
        self.logger.info(f"Total secrets found: {total_secrets}")
        for stype, count in sorted(secret_types.items(), key=lambda x: -x[1]):
            self.logger.info(f"  {stype}: {count}")
        self.logger.info(f"Total endpoints found: {total_endpoints}")
        for sev in ("CRITICAL", "HIGH", "MEDIUM"):
            if severity_counts[sev]:
                self.logger.info(f"  {sev}: {severity_counts[sev]}")
        
        if exposure_findings["exposed_files"]:
            self.logger.warning(f"Exposed files: {len(exposure_findings['exposed_files'])}")
        if exposure_findings["cors_issues"]:
            self.logger.warning(f"CORS issues: {len(exposure_findings['cors_issues'])}")
        
        self.logger.info("=" * 50)
