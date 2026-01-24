"""
Detectors Package

This module imports all detector classes, triggering their registration
with the DetectorRegistry. This ensures all detectors are available
when ScoringService requests them.

To add a new detector:
1. Create a new file in this directory (e.g., urgency.py)
2. Add @DetectorRegistry.register decorator to your class
3. Add an import line below

That's it! ScoringService will automatically pick it up.
"""

# Import all detectors to trigger their @DetectorRegistry.register decorators
from app.detectors.brand_protection import BrandProtectionDetector
from app.detectors.links import MaliciousLinkDetector
from app.detectors.header_analysis import HeaderAnalysisDetector
from app.detectors.attachments import HarmfulAttachmentDetector

# Re-export for convenience
__all__ = [
    'BrandProtectionDetector',
    'MaliciousLinkDetector', 
    'HeaderAnalysisDetector',
    'HarmfulAttachmentDetector',
]
