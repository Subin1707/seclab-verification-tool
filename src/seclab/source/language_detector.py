"""Language family detection from a source collection."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable

from .source_loader import SourceFile


class Language(StrEnum):
    C = "C"
    CPP = "C++"
    MIXED_C_CPP = "MIXED_C_CPP"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class LanguageDetection:
    language: Language
    source_count: int
    c_files: tuple[str, ...] = ()
    cpp_files: tuple[str, ...] = ()
    header_files: tuple[str, ...] = ()
    reason: str = ""


class LanguageDetector:
    def detect(self, files: Iterable[SourceFile]) -> LanguageDetection:
        items = tuple(files)
        c_files = tuple(item.relative_path for item in items if item.extension == ".c")
        cpp_files = tuple(item.relative_path for item in items if item.extension in {".cc", ".cpp", ".cxx"})
        headers = tuple(item.relative_path for item in items if item.extension in {".h", ".hh", ".hpp", ".hxx"})
        if c_files and cpp_files:
            language, reason = Language.MIXED_C_CPP, "Both C and C++ translation units are present."
        elif c_files:
            language, reason = Language.C, "C translation units are present; headers do not override them."
        elif cpp_files:
            language, reason = Language.CPP, "C++ translation units are present."
        elif headers:
            language, reason = Language.UNKNOWN, "Headers alone do not establish whether the project uses C or C++."
        elif items:
            language, reason = Language.UNSUPPORTED, "Files were found, but none provide supported C/C++ language evidence."
        else:
            language, reason = Language.UNKNOWN, "No supported source files were found."
        return LanguageDetection(language, len(items), c_files, cpp_files, headers, reason)


def detect_language(files: Iterable[SourceFile]) -> LanguageDetection:
    return LanguageDetector().detect(files)
