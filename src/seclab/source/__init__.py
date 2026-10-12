"""Source discovery, language hints, and conservative function discovery."""

from .errors import SourceError, SourceErrorCode
from .function_detector import FunctionDetector, FunctionInfo, detect_functions
from .language_detector import Language, LanguageDetection, LanguageDetector, detect_language
from .source_loader import SUPPORTED_EXTENSIONS, SourceFile, SourceLoader, load_source_tree

__all__ = ["FunctionDetector", "FunctionInfo", "Language", "LanguageDetection", "LanguageDetector",
           "SUPPORTED_EXTENSIONS", "SourceError", "SourceErrorCode", "SourceFile", "SourceLoader",
           "detect_functions", "detect_language", "load_source_tree"]
