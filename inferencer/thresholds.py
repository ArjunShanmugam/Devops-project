"""
inferencer/thresholds.py
Configurable thresholds for the policy inferencer per Architecture.md §9.2.1
"""
import os

MIN_REQUEST_COUNT = int(os.environ.get("MIN_REQUEST_COUNT", 5))
MAX_STALENESS_WINDOWS = int(os.environ.get("MAX_STALENESS_WINDOWS", 3))
