"""Data models for Intrascan"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum


class Severity(Enum):
    """Template severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Parse severity from string"""
        try:
            return cls(value.lower())
        except ValueError:
            return cls.UNKNOWN


class MatcherType(Enum):
    """Types of matchers"""
    STATUS = "status"
    WORD = "word"
    REGEX = "regex"
    DSL = "dsl"
    BINARY = "binary"
    SIZE = "size"

    @classmethod
    def from_string(cls, value: str) -> "MatcherType":
        """Parse matcher type from string"""
        mapping = {
            "status": cls.STATUS,
            "word": cls.WORD,
            "words": cls.WORD,
            "regex": cls.REGEX,
            "dsl": cls.DSL,
            "binary": cls.BINARY,
            "size": cls.SIZE,
        }
        return mapping.get(value.lower(), cls.WORD)


class ExtractorType(Enum):
    """Types of extractors"""
    REGEX = "regex"
    KVAL = "kval"
    JSON = "json"
    XPATH = "xpath"
    DSL = "dsl"

    @classmethod
    def from_string(cls, value: str) -> "ExtractorType":
        """Parse extractor type from string"""
        mapping = {
            "regex": cls.REGEX,
            "kval": cls.KVAL,
            "json": cls.JSON,
            "xpath": cls.XPATH,
            "dsl": cls.DSL,
        }
        return mapping.get(value.lower(), cls.REGEX)


@dataclass
class TemplateInfo:
    """Template info section"""
    name: str
    author: str = ""
    severity: Severity = Severity.UNKNOWN
    description: str = ""
    tags: List[str] = field(default_factory=list)
    reference: List[str] = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: dict) -> "TemplateInfo":
        """Parse from YAML dict"""
        severity = Severity.from_string(data.get("severity", "unknown"))
        tags = data.get("tags", "")
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        
        reference = data.get("reference", [])
        if isinstance(reference, str):
            reference = [reference]
            
        return cls(
            name=data.get("name", "Unknown"),
            author=data.get("author", ""),
            severity=severity,
            description=data.get("description", ""),
            tags=tags,
            reference=reference,
        )


@dataclass
class Matcher:
    """Matcher definition"""
    type: MatcherType
    part: str = "body"              # body, header, all, status_code
    condition: str = "or"           # and/or (within matcher values)
    negative: bool = False
    case_insensitive: bool = False
    name: str = ""
    
    # Type-specific values
    status: List[int] = field(default_factory=list)
    words: List[str] = field(default_factory=list)
    regex: List[str] = field(default_factory=list)
    dsl: List[str] = field(default_factory=list)
    binary: List[str] = field(default_factory=list)
    size: List[int] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "Matcher":
        """Parse from YAML dict"""
        matcher_type = MatcherType.from_string(data.get("type", "word"))
        
        return cls(
            type=matcher_type,
            part=data.get("part", "body"),
            condition=data.get("condition", "or"),
            negative=data.get("negative", False),
            case_insensitive=data.get("case-insensitive", False),
            name=data.get("name", ""),
            status=data.get("status", []),
            words=data.get("words", []),
            regex=data.get("regex", []),
            dsl=data.get("dsl", []),
            binary=data.get("binary", []),
            size=data.get("size", []),
        )


@dataclass
class Extractor:
    """Extractor definition"""
    type: ExtractorType
    name: str = ""
    part: str = "body"
    internal: bool = False
    case_insensitive: bool = False
    
    # Type-specific fields
    regex: List[str] = field(default_factory=list)
    group: int = 0
    kval: List[str] = field(default_factory=list)
    json: List[str] = field(default_factory=list)
    xpath: List[str] = field(default_factory=list)
    dsl: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "Extractor":
        """Parse from YAML dict"""
        extractor_type = ExtractorType.from_string(data.get("type", "regex"))
        
        return cls(
            type=extractor_type,
            name=data.get("name", ""),
            part=data.get("part", "body"),
            internal=data.get("internal", False),
            case_insensitive=data.get("case-insensitive", False),
            regex=data.get("regex", []),
            group=data.get("group", 0),
            kval=data.get("kval", []),
            json=data.get("json", []),
            xpath=data.get("xpath", []),
            dsl=data.get("dsl", []),
        )


@dataclass
class HttpRequest:
    """HTTP request definition from template"""
    method: str = "GET"
    path: List[str] = field(default_factory=list)
    raw: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    
    matchers: List[Matcher] = field(default_factory=list)
    extractors: List[Extractor] = field(default_factory=list)
    matchers_condition: str = "or"    # and/or (between matchers)
    stop_at_first_match: bool = False
    
    @classmethod
    def from_dict(cls, data: dict) -> "HttpRequest":
        """Parse from YAML dict"""
        matchers = [
            Matcher.from_dict(m) for m in data.get("matchers", [])
        ]
        extractors = [
            Extractor.from_dict(e) for e in data.get("extractors", [])
        ]
        
        return cls(
            method=data.get("method", "GET"),
            path=data.get("path", []),
            raw=data.get("raw", []),
            headers=data.get("headers", {}),
            body=data.get("body", ""),
            matchers=matchers,
            extractors=extractors,
            matchers_condition=data.get("matchers-condition", "or"),
            stop_at_first_match=data.get("stop-at-first-match", False),
        )


@dataclass
class NucleiTemplate:
    """Complete Nuclei template"""
    id: str
    info: TemplateInfo
    http_requests: List[HttpRequest]
    variables: Dict[str, Any] = field(default_factory=dict)
    path: str = ""  # File path for reference


@dataclass
class FridaResponse:
    """Response from Frida network script"""
    status_code: int
    headers: Dict[str, str]
    body: str
    error: Optional[str] = None
    duration: float = 0.0  # Response time in seconds


@dataclass 
class ScanResult:
    """Result of scanning a template against a target"""
    template_id: str
    template_name: str
    severity: Severity
    matched: bool
    target_url: str
    matched_at: str                         # The specific URL that matched
    extracted: List[str] = field(default_factory=list)
    matcher_name: Optional[str] = None
    
    # For storage (populated when match is found)
    request: Optional[str] = None
    response: Optional[str] = None
    response_time: float = 0.0
