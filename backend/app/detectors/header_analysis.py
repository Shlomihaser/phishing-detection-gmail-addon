from typing import Optional

from app.detectors.base import BaseDetector
from app.detectors.registry import DetectorRegistry
from app.models.domain import Email
from app.models.risk import DetectorResult
from app.utils.url_parser import extract_domain
from app.constants.allowed_hosts import MAILING_SERVICE_DOMAINS


@DetectorRegistry.register
class HeaderAnalysisDetector(BaseDetector):
    def evaluate(self, email: Email) -> Optional[DetectorResult]:
        reasons = []
        max_score = 0.0

        # --- 1. Authentication Checks (SPF/DKIM/DMARC) ---
        if email.auth_results:
            spf = email.auth_results.spf
            dkim = email.auth_results.dkim
            dmarc = email.auth_results.dmarc
            
            # Check if ALL auth headers are missing
            if not spf and not dkim and not dmarc:
                reasons.append("No authentication headers present (SPF/DKIM/DMARC missing)")
                max_score = max(max_score, 40.0)
            else:
                # SPF Check
                if spf:
                    if spf == 'fail':
                        reasons.append("SPF authentication failed")
                        max_score = max(max_score, 100.0)
                    elif spf in ('softfail', 'neutral'):
                        reasons.append(f"SPF result is weak ({spf})")
                        max_score = max(max_score, 40.0)
                
                # DKIM Check
                if dkim:
                    if dkim == 'fail':
                        reasons.append("DKIM signature invalid")
                        max_score = max(max_score, 100.0)
                    elif dkim in ('neutral', 'policy'):
                        reasons.append(f"DKIM result is weak ({dkim})")
                        max_score = max(max_score, 30.0)
                
                # DMARC Check (Most Authoritative)
                if dmarc:
                    if dmarc == 'fail':
                        reasons.append("DMARC policy failed (domain owner rejects this email)")
                        max_score = max(max_score, 100.0)
                    elif dmarc in ('none', 'quarantine'):
                        reasons.append(f"DMARC policy is {dmarc}")
                        max_score = max(max_score, 25.0)

        # --- 2. Reply-To Mismatch ---
        if email.reply_to and email.sender_email:
            sender_ext = extract_domain(email.sender_email)
            reply_ext = extract_domain(email.reply_to)
            
            sender_domain = sender_ext.registered_domain.lower() if sender_ext.registered_domain else ""
            reply_domain = reply_ext.registered_domain.lower() if reply_ext.registered_domain else ""
            
            if sender_domain and reply_domain and sender_domain != reply_domain:
                # Check if reply domain is a known mailing service (whitelist)
                if reply_domain not in MAILING_SERVICE_DOMAINS:
                    reasons.append(f"Reply-To domain mismatch (From: {sender_domain}, Reply-To: {reply_domain})")
                    max_score = max(max_score, 60.0)

        # --- 3. Return-Path Mismatch ---
        if email.return_path and email.sender_email:
            sender_ext = extract_domain(email.sender_email)
            return_ext = extract_domain(email.return_path)
            
            sender_domain = sender_ext.registered_domain.lower() if sender_ext.registered_domain else ""
            return_domain = return_ext.registered_domain.lower() if return_ext.registered_domain else ""
            
            if sender_domain and return_domain and sender_domain != return_domain:
                # Check if return-path is a known mailing service
                if return_domain not in MAILING_SERVICE_DOMAINS:
                    reasons.append(f"Return-Path mismatch (From: {sender_domain}, Envelope: {return_domain})")
                    max_score = max(max_score, 30.0)

        if not reasons:
            return None
            
        return DetectorResult(
            detector_name="Header analysis",
            score_impact=max_score,
            description="Authentication/Identity issues: " + "; ".join(reasons)
        )
