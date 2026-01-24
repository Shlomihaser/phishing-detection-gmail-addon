class RiskThresholds:
    """Named constants for risk scoring - avoid magic numbers."""

    CRITICAL_IMPACT = 80.0  # Score that triggers critical override
    DANGEROUS_LEVEL = 70.0  # >= this score = DANGEROUS
    SUSPICIOUS_LEVEL = 30.0  # >= this score = SUSPICIOUS, < DANGEROUS

    # Weighting
    DETECTOR_WEIGHT = 0.6  # 60% weight for heuristic detectors
    ML_WEIGHT = 0.4  # 40% weight for ML model

    # ML Override thresholds
    ML_HIGH_CONFIDENCE = 0.85  # 85% ML confidence triggers boost
    ML_BOOST_MINIMUM = 50.0  # Minimum score when ML is confident


class AttachmentScores:
    """Scores for attachment-related risks."""

    MALICIOUS_FILE = 100.0  # Known dangerous file type
    HIDDEN_EXECUTABLE = 100.0  # MIME exec but ext is not
    DOUBLE_EXTENSION = 100.0  # .txt.exe
    MIME_MISMATCH = 75.0  # Content spoofing
    UNNAMED_SUSPICIOUS = 30.0  # Unnamed non-image file
    MISSING_EXTENSION = 25.0  # No extension provided


class LinkScores:
    """Scores for link-related risks."""
    IP_ADDRESS = 40.0  # Direct IP usage
    LINK_MASKING = 50.0  # Text != Href
    URL_SHORTENER = 25.0  # bit.ly, etc.
    SUSPICIOUS_TLD = 20.0  # .xyz, .top, etc.
