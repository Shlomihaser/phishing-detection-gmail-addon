from typing import Optional
import os
import magic
from app.models.domain import Email
from app.models.risk import DetectorResult
from app.detectors.base import BaseDetector
from app.detectors.registry import DetectorRegistry
from app.constants.file_defs import FILE_DEFINITIONS


@DetectorRegistry.register
class HarmfulAttachmentDetector(BaseDetector):
    def evaluate(self, email: Email) -> Optional[DetectorResult]:
        flagged_attachments = {}
        max_risk_score = 0.0
       
        for index, attachment in enumerate(email.attachments):
            reasons = []
            
            # --- Step 1: Detect actual content type using magic ---
            detected_mime = 'application/octet-stream'  # Default fallback
            if attachment.content_header:
                try:
                    detected_mime = magic.from_buffer(attachment.content_header, mime=True)
                except Exception:
                    pass  # Keep default if magic fails
            
            # --- Step 2: Extract filename and extension ---
            ext = ""
            fake_ext = ""
            file_def = None
            
            if attachment.filename:
                filename = attachment.filename.lower()
                name, ext_with_dot = os.path.splitext(filename)
                ext = ext_with_dot.lstrip('.') if ext_with_dot else ""
                fake_ext = name.split('.')[-1] if '.' in name else ""
                file_def = FILE_DEFINITIONS.get(ext)
            
            # --- Step 3: Check for hidden executable (Priority 1 - Catches worst offenders) ---
            is_executable = (detected_mime == 'application/x-dosexec' or 
                           detected_mime == 'application/x-msdownload')
            
            if is_executable:
                if ext not in ('exe', 'msi'):
                    reasons.append(f"hidden executable content detected ({detected_mime})")
                    max_risk_score = max(max_risk_score, 100.0)

            if attachment.filename:
                # --- Named Attachment Checks ---
                
                # Check 1: Is it explicitly Dangerous?
                if file_def and file_def['type'] == 'DANGEROUS':
                    reasons.append(f"malicious file type ({ext})")
                    max_risk_score = max(max_risk_score, 100.0)

                # Check 2: Missing Extension
                if not ext:
                    reasons.append("missing file extension")
                    max_risk_score = max(max_risk_score, 25.0)

                # Check 3: Double Extension Trick
                fake_def = FILE_DEFINITIONS.get(fake_ext)
                if fake_def and fake_def['type'] == 'SAFE':
                    if not file_def or file_def['type'] != 'SAFE':
                        reasons.append(f"deceptive double extension (.{fake_ext}.{ext})")
                        max_risk_score = max(max_risk_score, 100.0)
                
                # Check 4: Content Spoofing (MIME Mismatch)
                if file_def and file_def.get('mime'):
                    expected_mime = file_def['mime']
                    is_valid = (detected_mime == expected_mime)
                    
                    # Loosen Logic: Allow legitimate mismatches
                    # 1. Office files are effectively zips
                    if not is_valid and 'openxml' in expected_mime and detected_mime == 'application/zip':
                        is_valid = True
                    # 2. Text-based files (CSV, XML, Code) often read as text/plain
                    if not is_valid and 'text/plain' in detected_mime and expected_mime in ['text/csv', 'application/json', 'text/xml']:
                        is_valid = True
                    # 3. Code files (py, js) are text
                    if not is_valid and 'text/plain' in detected_mime and ext in ['py', 'js', 'java', 'html', 'css']:
                        is_valid = True

                    if not is_valid:
                        # If we expected Safe but got Executable -> 100
                        if is_executable:
                            max_risk_score = max(max_risk_score, 100.0)
                        # Minor mismatch (e.g. png vs jpg) -> 25 (Warning)
                        elif 'image' in expected_mime and 'image' in detected_mime:
                            pass  # Allow jpg/png mixups
                        else:
                            reasons.append(f"file content ({detected_mime}) does not match extension (expected {expected_mime})")
                            max_risk_score = max(max_risk_score, 75.0)

            else:
                # --- Unnamed Attachment Checks ---
                # Logic Update: Only flag if it's NOT an image/text (likely inline signature)
                if not detected_mime.startswith(('image/', 'text/')):
                    reasons.append("unnamed suspicious attachment")
                    max_risk_score = max(max_risk_score, 30.0)
                else:
                    # Ignore safe unnamed images (logos/sig)
                    continue

            if reasons:
                # Ensure we have a filename key even for unnamed high-risk files
                key_name = attachment.filename or f"unnamed_attachment_{index}"
                flagged_attachments[key_name] = reasons
        
        if not flagged_attachments:
            return None
        
        issue_details = []
        for fname, issues in flagged_attachments.items():
            issue_details.append(f"{fname}: {', '.join(issues)}")

        return DetectorResult(
            detector_name="Harmful Attachment Detector",
            score_impact=max_risk_score,
            description="Suspicious attachments detected: " + "; ".join(issue_details)
        )
