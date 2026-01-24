# Unified File Security Definitions
# Format: 'ext': {'type': 'SAFE'|'DANGEROUS', 'mime': 'expected_mime', 'alt': ['allowed', 'alternatives']}

FILE_DEFINITIONS = {
    # Dangerous Scripts & Executables (Block by Name)
    "exe": {"type": "DANGEROUS", "mime": "application/x-dosexec"},
    "scr": {"type": "DANGEROUS", "mime": None},
    "vbs": {"type": "DANGEROUS", "mime": "text/plain"},
    "js": {"type": "DANGEROUS", "mime": "text/plain"},
    "bat": {"type": "DANGEROUS", "mime": "text/plain"},
    "cmd": {"type": "DANGEROUS", "mime": "text/plain"},
    "ps1": {"type": "DANGEROUS", "mime": "text/plain"},
    "jar": {"type": "DANGEROUS", "mime": "application/java-archive"},
    "msi": {"type": "DANGEROUS", "mime": "application/x-msi"},
    # Safe Documents (Verify by Content)
    # 'alt' = alternative MIME types that magic might detect (false positive prevention)
    "pdf": {
        "type": "SAFE",
        "mime": "application/pdf",
        "alt": ["text/plain", "application/octet-stream"],
    },
    "png": {"type": "SAFE", "mime": "image/png", "alt": ["image/jpeg", "image/gif"]},
    "jpg": {"type": "SAFE", "mime": "image/jpeg", "alt": ["image/png"]},
    "jpeg": {"type": "SAFE", "mime": "image/jpeg", "alt": ["image/png"]},
    "gif": {"type": "SAFE", "mime": "image/gif", "alt": ["image/png"]},
    "zip": {"type": "SAFE", "mime": "application/zip"},
    "doc": {
        "type": "SAFE",
        "mime": "application/msword",
        "alt": ["application/octet-stream"],
    },
    "xls": {
        "type": "SAFE",
        "mime": "application/vnd.ms-excel",
        "alt": ["application/octet-stream"],
    },
    "csv": {"type": "SAFE", "mime": "text/plain"},
    "ppt": {
        "type": "SAFE",
        "mime": "application/vnd.ms-powerpoint",
        "alt": ["application/octet-stream"],
    },
    "docx": {
        "type": "SAFE",
        "mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "alt": ["application/zip"],
    },
    "xlsx": {
        "type": "SAFE",
        "mime": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "alt": ["application/zip"],
    },
    "pptx": {
        "type": "SAFE",
        "mime": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "alt": ["application/zip"],
    },
    "txt": {"type": "SAFE", "mime": "text/plain"},
    # Code files (detected as text/plain, which is fine)
    "py": {"type": "SAFE", "mime": "text/plain"},
    "html": {"type": "SAFE", "mime": "text/html", "alt": ["text/plain"]},
    "css": {"type": "SAFE", "mime": "text/css", "alt": ["text/plain"]},
    "json": {"type": "SAFE", "mime": "application/json", "alt": ["text/plain"]},
    "xml": {"type": "SAFE", "mime": "text/xml", "alt": ["text/plain"]},
}
