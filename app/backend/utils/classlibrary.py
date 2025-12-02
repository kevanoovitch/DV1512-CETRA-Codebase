
from dataclasses import dataclass, asdict

class FileFormat:
    def __init__(self):
        filePath = None
        ID = None

class ApiResult:
    def __init__(self):
        self.findings = []
        self.permissions = []
        self.file_hash=None
        self.extension_id=None
        self.file_format = FileFormat()

class Finding:
    def __init__(self, tag, type, category, score, family=None):
        self.tag = tag
        self.type = type
        self.category = category
        self.score = score
        self.family = family