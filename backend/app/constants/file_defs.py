from enum import Enum


class FileType(str, Enum):
    SAFE = "SAFE"
    DANGEROUS = "DANGEROUS"


FILE_DEFINITIONS = {
    # Dangerous Scripts & Executables (Block by Name)
    "exe": {"type": FileType.DANGEROUS, "mime": "application/x-dosexec"},
    "scr": {"type": FileType.DANGEROUS, "mime": None},
    "vbs": {"type": FileType.DANGEROUS, "mime": "text/plain"},
    "js": {"type": FileType.DANGEROUS, "mime": "text/plain"},
    "bat": {"type": FileType.DANGEROUS, "mime": "text/plain"},
    "cmd": {"type": FileType.DANGEROUS, "mime": "text/plain"},
    "ps1": {"type": FileType.DANGEROUS, "mime": "text/plain"},
    "jar": {"type": FileType.DANGEROUS, "mime": "application/java-archive"},
    "msi": {"type": FileType.DANGEROUS, "mime": "application/x-msi"},
    # Safe Documents (Verify by Content)
    # 'alt' = alternative MIME types that magic might detect (false positive prevention)
    "pdf": {
        "type": FileType.SAFE,
        "mime": "application/pdf",
        "alt": ["text/plain", "application/octet-stream"],
    },
    "png": {
        "type": FileType.SAFE,
        "mime": "image/png",
        "alt": ["image/jpeg", "image/gif"],
    },
    "jpg": {"type": FileType.SAFE, "mime": "image/jpeg", "alt": ["image/png"]},
    "jpeg": {"type": FileType.SAFE, "mime": "image/jpeg", "alt": ["image/png"]},
    "gif": {"type": FileType.SAFE, "mime": "image/gif", "alt": ["image/png"]},
    "zip": {"type": FileType.SAFE, "mime": "application/zip"},
    "doc": {
        "type": FileType.SAFE,
        "mime": "application/msword",
        "alt": ["application/octet-stream"],
    },
    "xls": {
        "type": FileType.SAFE,
        "mime": "application/vnd.ms-excel",
        "alt": ["application/octet-stream"],
    },
    "csv": {"type": FileType.SAFE, "mime": "text/plain"},
    "ppt": {
        "type": FileType.SAFE,
        "mime": "application/vnd.ms-powerpoint",
        "alt": ["application/octet-stream"],
    },
    "docx": {
        "type": FileType.SAFE,
        "mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "alt": ["application/zip"],
    },
    "xlsx": {
        "type": FileType.SAFE,
        "mime": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "alt": ["application/zip"],
    },
    "pptx": {
        "type": FileType.SAFE,
        "mime": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "alt": ["application/zip"],
    },
    "txt": {"type": FileType.SAFE, "mime": "text/plain"},
    # Code files (detected as text/plain, which is fine)
    "py": {"type": FileType.SAFE, "mime": "text/plain"},
    "html": {"type": FileType.SAFE, "mime": "text/html", "alt": ["text/plain"]},
    "css": {"type": FileType.SAFE, "mime": "text/css", "alt": ["text/plain"]},
    "json": {
        "type": FileType.SAFE,
        "mime": "application/json",
        "alt": ["text/plain"],
    },
    "xml": {"type": FileType.SAFE, "mime": "text/xml", "alt": ["text/plain"]},
}
