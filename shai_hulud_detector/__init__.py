"""
Shai-Hulud NPM Supply Chain Attack Detector
A Python package for detecting indicators of compromise from the September 2025 npm attack.
"""

__version__ = "2.0.0"
__author__ = "Shai-Hulud Detection Team"

from .main import ShaiHuludDetector, main

__all__ = ["ShaiHuludDetector", "main"]