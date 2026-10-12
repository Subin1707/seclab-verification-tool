from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from seclab.source import (
    FunctionDetector, Language, LanguageDetector, SourceError, SourceLoader,
)


def write(root: Path, relative: str, content: str = "") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_loader_discovers_extensions_nested_excludes_and_hashes_without_mutation(tmp_path: Path) -> None:
    root = tmp_path / "sut"
    source = write(root, "nested dir/main.c", "int main(void) { return 0; }\n")
    write(root, "include/api.hpp", "int api();\n")
    write(root, "lib/thing.cxx")
    write(root, "build/generated.c")
    write(root, "notes.txt")
    before = source.read_bytes()
    files = SourceLoader().load_source_tree(root)
    assert [item.relative_path for item in files] == ["include/api.hpp", "lib/thing.cxx", "nested dir/main.c"]
    entry = next(item for item in files if item.relative_path.endswith("main.c"))
    assert entry.path == source.resolve()
    assert entry.size_bytes == len(before)
    assert entry.sha256 == hashlib.sha256(before).hexdigest()
    assert source.read_bytes() == before


def test_loader_is_deterministic_and_include_exclude_rules_are_configurable(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write(root, "src/a.c")
    write(root, "vendor/b.cpp")
    loader = SourceLoader(include=("src/**",), exclude=())
    assert [item.relative_path for item in loader.load_source_tree(root)] == ["src/a.c"]
    assert [item.relative_path for item in loader.load_source_tree(root)] == ["src/a.c"]


def test_language_detection_handles_c_cpp_mixed_headers_only_empty_and_unsupported(tmp_path: Path) -> None:
    detector = LanguageDetector()
    loader = SourceLoader()
    croot = tmp_path / "c"
    write(croot, "a.c"); write(croot, "x.h")
    assert detector.detect(loader.load_source_tree(croot)).language is Language.C
    cpproot = tmp_path / "cpp"
    write(cpproot, "a.cpp"); write(cpproot, "x.hpp")
    assert detector.detect(loader.load_source_tree(cpproot)).language is Language.CPP
    mixedroot = tmp_path / "mixed"
    write(mixedroot, "a.c"); write(mixedroot, "b.cpp")
    assert detector.detect(loader.load_source_tree(mixedroot)).language is Language.MIXED_C_CPP
    headers = tmp_path / "headers"
    write(headers, "only.h")
    assert detector.detect(loader.load_source_tree(headers)).language is Language.UNKNOWN
    empty = tmp_path / "empty"; empty.mkdir()
    assert detector.detect(loader.load_source_tree(empty)).language is Language.UNKNOWN
    unsupported = tmp_path / "unsupported"; write(unsupported, "readme.txt")
    # SourceLoader ignores unsupported extensions, so an empty supported-source collection is UNKNOWN.
    assert detector.detect(loader.load_source_tree(unsupported)).language is Language.UNKNOWN


def test_loader_rejects_missing_root_and_does_not_follow_symlink(tmp_path: Path) -> None:
    with pytest.raises(SourceError):
        SourceLoader().load_source_tree(tmp_path / "missing")
    root = tmp_path / "root"; root.mkdir()
    outside = write(tmp_path / "outside", "secret.c", "int secret(void) { return 1; }")
    link = root / "linked.c"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are unavailable in this environment")
    assert SourceLoader().load_source_tree(root) == ()


def test_function_detector_finds_definitions_not_calls_control_or_prototypes(tmp_path: Path) -> None:
    source = tmp_path / "functions.c"
    source.write_text('''#include <stdio.h>
int add(int a, int b) {
  if (a) { printf("not a function"); }
  for (;;) { break; }
  while (0) { }
  return a + b;
}
static void reset(void) { }
int prototype(int x);
int main(void) {
  int x = add(1, 2);
  return x;
}
''', encoding="utf-8")
    found = FunctionDetector().detect([source])
    assert [(item.name, item.parameters) for item in found] == [
        ("add", ("int a", "int b")), ("reset", ()), ("main", ())
    ]
    assert found[0].return_type == "int"
    assert found[0].line == 2


def test_function_detector_supports_multiline_signatures_and_skips_comments(tmp_path: Path) -> None:
    source = tmp_path / "multi.cpp"
    source.write_text("// int fake(void) { }\nstatic long\ncompute(\n int x,\n const char* y\n) { return x; }\n", encoding="utf-8")
    found = FunctionDetector().detect([source])
    assert len(found) == 1
    assert found[0].name == "compute"
    assert found[0].parameters == ("int x", "const char* y")


def test_function_detector_ignores_function_like_macros(tmp_path: Path) -> None:
    source = tmp_path / "macro.c"
    source.write_text("#define DEFINE(x) int fake(void) { return (x); }\nint real(void) { return 0; }\n", encoding="utf-8")
    assert [item.name for item in FunctionDetector().detect([source])] == ["real"]
