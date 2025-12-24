"""Intrascan: iOS/Android security scanner using Nuclei templates via Frida"""

__version__ = "0.1.0"

from .models import (
    NucleiTemplate,
    HttpRequest,
    Matcher,
    Extractor,
    FridaResponse,
    ScanResult,
    Severity,
    MatcherType,
    ExtractorType,
)
from .template_parser import TemplateParser
from .template_discovery import TemplateDiscovery
from .variables import VariableEngine
from .request_builder import RequestBuilder
from .frida_client import FridaNetworkClient
from .matchers import MatcherEngine
from .extractors import ExtractorEngine
from .executor import NucleiExecutor

__all__ = [
    "NucleiTemplate",
    "HttpRequest", 
    "Matcher",
    "Extractor",
    "FridaResponse",
    "ScanResult",
    "Severity",
    "MatcherType",
    "ExtractorType",
    "TemplateParser",
    "TemplateDiscovery",
    "VariableEngine",
    "RequestBuilder",
    "FridaNetworkClient",
    "MatcherEngine",
    "ExtractorEngine",
    "NucleiExecutor",
]
