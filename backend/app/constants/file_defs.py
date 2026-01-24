# Unified File Security Definitions
# Format: 'ext': {'type': 'SAFE'|'DANGEROUS', 'mime': 'mime/type'}

FILE_DEFINITIONS = {
    # Dangerous Scripts & Executables (Block by Name)
    'exe': {'type': 'DANGEROUS', 'mime': 'application/x-dosexec'},
    'scr': {'type': 'DANGEROUS', 'mime': None},
    'vbs': {'type': 'DANGEROUS', 'mime': 'text/plain'}, 
    'js':  {'type': 'DANGEROUS', 'mime': 'text/plain'},
    'bat': {'type': 'DANGEROUS', 'mime': 'text/plain'},
    'cmd': {'type': 'DANGEROUS', 'mime': 'text/plain'},
    'ps1': {'type': 'DANGEROUS', 'mime': 'text/plain'},
    'jar': {'type': 'DANGEROUS', 'mime': 'application/java-archive'},
    'msi': {'type': 'DANGEROUS', 'mime': 'application/x-msi'}, 
    
    # Safe Documents (Verify by Content)
    'pdf':  {'type': 'SAFE', 'mime': 'application/pdf'},
    'png':  {'type': 'SAFE', 'mime': 'image/png'},
    'jpg':  {'type': 'SAFE', 'mime': 'image/jpeg'},
    'jpeg': {'type': 'SAFE', 'mime': 'image/jpeg'},
    'gif':  {'type': 'SAFE', 'mime': 'image/gif'},
    'zip':  {'type': 'SAFE', 'mime': 'application/zip'},
    'doc':  {'type': 'SAFE', 'mime': 'application/msword'},
    'xls':  {'type': 'SAFE', 'mime': 'application/vnd.ms-excel'},
    'csv':  {'type': 'SAFE', 'mime': 'text/plain'}, 
    'ppt':  {'type': 'SAFE', 'mime': 'application/vnd.ms-powerpoint'},
    'docx': {'type': 'SAFE', 'mime': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'}, 
    'xlsx': {'type': 'SAFE', 'mime': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}, 
    'pptx': {'type': 'SAFE', 'mime': 'application/vnd.openxmlformats-officedocument.presentationml.presentation'},
    'txt':  {'type': 'SAFE', 'mime': 'text/plain'} 
}
