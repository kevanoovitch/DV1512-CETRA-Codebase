
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
        self.behavior = None 
        self.file_format = FileFormat()
        self.extensionData= {}

class Finding:
    def __init__(self, tag, type, category, score=-1, family=None, api=None):
        self.tag = tag
        self.type = type
        self.category = category
        self.score = score
        self.family = family
        self.api = api
        
    
    def __repr__(self):
        return f"TAG: {self.tag} TYPE: {self.type} cat: {self.category} score: {self.score} family {self.family} api {self.api} \n"

    def to_dict(self):
        return {
            "tag": self.tag,
            "type": self.type,
            "category": self.category,
            "score": self.score,
            "family": self.family,
            "api" : self.api
        } 