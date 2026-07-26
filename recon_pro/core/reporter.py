"""Report generation and formatting module."""

import json
import logging
from typing import List, Dict
from datetime import datetime


class ReportGenerator:
    """Generates reports in various formats (JSON, SARIF, HTML)."""

    def __init__(self, logger: logging.Logger):
        """Initialize ReportGenerator.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger

    def generate_json(
        self, results: List[Dict], output_path: str
    ) -> None:
        """Generate JSON report.
        
        Args:
            results: Analysis results
            output_path: Path to save report
        """
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        self.logger.info(f"JSON report saved: {output_path}")

    def generate_sarif(
        self, results: List[Dict], output_path: str
    ) -> None:
        """Generate SARIF report for GitHub/DefectDojo integration.
        
        Args:
            results: Analysis results
            output_path: Path to save report
        """
        runs = [{
            "tool": {
                "driver": {
                    "name": "Recon Pro",
                    "version": "2.0.0",
                    "informationUri": "https://github.com/felipe15k/felipe",
                }
            },
            "results": self._convert_to_sarif_results(results),
        }]
        
        sarif = {
            "version": "2.1.0",
            "runs": runs,
        }
        
        with open(output_path, "w") as f:
            json.dump(sarif, f, indent=2)
        self.logger.info(f"SARIF report saved: {output_path}")

    def _convert_to_sarif_results(self, results: List[Dict]) -> List[Dict]:
        """Convert analysis results to SARIF format.
        
        Args:
            results: Analysis results
            
        Returns:
            List of SARIF result objects
        """
        sarif_results = []
        
        for res in results:
            # Secrets
            for secret in res.get("secrets", []):
                sarif_results.append({
                    "ruleId": f"SEC-{secret['type'].replace(' ', '-').upper()}",
                    "level": self._severity_to_sarif_level(secret.get("confidence", "HIGH")),
                    "message": {
                        "text": f"Found {secret['type']}: {secret['value'][:20]}..."
                    },
                    "locations": [{
                        "physicalLocation": {
                            "address": {
                                "uri": res["url"],
                            },
                        },
                    }],
                })
            
            # Endpoints
            for endpoint in res.get("endpoints", []):
                sarif_results.append({
                    "ruleId": f"API-{endpoint.get('severity', 'MEDIUM').upper()}",
                    "level": self._severity_to_sarif_level(endpoint.get("severity", "MEDIUM")),
                    "message": {
                        "text": f"Found endpoint: {endpoint['path']}"
                    },
                    "locations": [{
                        "physicalLocation": {
                            "address": {
                                "uri": res["url"],
                            },
                        },
                    }],
                })
        
        return sarif_results

    def _severity_to_sarif_level(self, severity: str) -> str:
        """Convert severity to SARIF level.
        
        Args:
            severity: Severity string
            
        Returns:
            SARIF level
        """
        mapping = {
            "CRITICAL": "error",
            "HIGH": "warning",
            "MEDIUM": "note",
            "INFO": "note",
            "CONFIRMED": "error",
            "INVALID": "none",
        }
        return mapping.get(severity, "warning")

    def generate_html(
        self, results: List[Dict], output_path: str
    ) -> None:
        """Generate HTML report (future implementation).
        
        Args:
            results: Analysis results
            output_path: Path to save report
        """
        html = self._build_html(results)
        with open(output_path, "w") as f:
            f.write(html)
        self.logger.info(f"HTML report saved: {output_path}")

    def _build_html(self, results: List[Dict]) -> str:
        """Build HTML report.
        
        Args:
            results: Analysis results
            
        Returns:
            HTML string
        """
        total_secrets = sum(len(r.get("secrets", [])) for r in results)
        total_endpoints = sum(len(r.get("endpoints", [])) for r in results)
        
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Recon Pro Report</title>
    <style>
        body {{ font-family: Arial; margin: 20px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f0f0f0; padding: 10px; margin: 20px 0; }}
        .critical {{ color: #d9534f; }}
        .high {{ color: #f0ad4e; }}
    </style>
</head>
<body>
    <h1>Recon Pro Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Generated: {datetime.now().isoformat()}</p>
        <p>Files analyzed: {len(results)}</p>
        <p><strong class="critical">Secrets found: {total_secrets}</strong></p>
        <p><strong class="high">Endpoints found: {total_endpoints}</strong></p>
    </div>
</body>
</html>
        """
