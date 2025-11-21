"""
Modules package for Web Security Scanner
Contains technology detection and vulnerability testers
"""

from .technology_detector import TechnologyDetector
from .web_mapper import WebMapper

__all__ = ['TechnologyDetector', 'WebMapper']
