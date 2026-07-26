"""Recon Pro: Passive JavaScript reconnaissance for bug bounty.

A comprehensive tool for discovering secrets, API endpoints, and other
sensitive data in JavaScript bundles through static analysis.
"""

__version__ = "2.0.0"
__author__ = "Felipe"
__license__ = "MIT"

from .cli import main

__all__ = ["main"]
