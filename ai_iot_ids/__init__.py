"""
AI-Driven IoT Intrusion Detection System

A multi-layered security solution designed to monitor and protect IoT/ICS networks
through hybrid detection combining signature-based rules with machine learning-based
anomaly detection.
"""

__version__ = "0.1.0"
__author__ = "AI-IoT-IDS Team"
__description__ = "AI-driven Intrusion Detection System for IoT networks"

# Core modules
from . import models
from . import interfaces
from . import utils

__all__ = [
    "models",
    "interfaces", 
    "utils",
]