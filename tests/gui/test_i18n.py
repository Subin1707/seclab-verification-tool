from pathlib import Path

from seclab.gui.i18n import (CHECKER_HELP, MENU_LABELS, MESSAGE_LABELS, STAGE_LABELS,
    STATUS_HELP, STATUS_LABELS, TECH_TERM, UI_TEXT, checker_description, stage_label, status_label)


def test_gui_default_labels_are_vietnamese_first():
    assert UI_TEXT["project"] == "Dự án"
    assert UI_TEXT["specification"] == "Đặc tả (Specification)"
    assert UI_TEXT["results"] == "Kết quả"
    assert "Bằng chứng" in UI_TEXT["evidence"]
    assert "Mô hình trạng thái" in UI_TEXT["model"]


def test_formal_technical_terms_and_checkers_have_vietnamese_explanations():
    for term in ("CTL", "BMC", "SMT", "SAT", "UNSAT", "UNKNOWN", "Kripke Structure"):
        assert "(" in TECH_TERM[term]
    assert "phản ví dụ" in checker_description("BMC")
    assert "mã nguồn" in checker_description("STATIC_ANALYSIS")
    assert "không tự tạo kết luận an toàn" in checker_description("COVERAGE")
    assert "đầu vào" in checker_description("FUZZING")


def test_every_canonical_pipeline_stage_has_a_vietnamese_display_label():
    expected = {"SPECIFICATION", "MODEL", "CTL", "SOURCE", "BMC", "SMT", "CODEGEN", "BUILD",
                "STATIC", "MEMORY", "DYNAMIC", "COVERAGE", "FUZZING", "REPORT"}
    assert expected <= STAGE_LABELS.keys()
    for stage in expected:
        assert "(" in stage_label(stage)


def test_every_canonical_status_has_a_vietnamese_display_label_and_help():
    canonical = {"PASS", "FAIL", "INCONCLUSIVE", "SKIPPED", "NOT_RUN", "TOOL_ERROR",
                 "BUILD_ERROR", "UNSUPPORTED", "ENVIRONMENT_LIMITED"}
    assert canonical <= STATUS_LABELS.keys()
    for status in canonical:
        assert status in status_label(status)
        assert status in STATUS_HELP


def test_primary_user_messages_are_vietnamese_first():
    assert "Vui lòng" in MESSAGE_LABELS["select_project"]
    assert "đặc tả" in MESSAGE_LABELS["invalid_specification"].casefold()
    assert "Chi tiết kỹ thuật" in MESSAGE_LABELS["technical_detail"]
    assert "Chạy toàn bộ" in MESSAGE_LABELS["run_all"]


def test_gui_localization_sources_have_no_common_mojibake_markers():
    gui_root = Path(__file__).parents[2] / "src" / "seclab" / "gui"
    markers = ("D\u00e1\u00bb", "B\u0102", "\u00c4\u0090", "Ch\u00c6", "Th\u00c6", "\u00e2\u20ac", "\u00c3\u00a1")
    for path in gui_root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert not any(marker in text for marker in markers), path


def test_localization_helpers_do_not_transform_identifiers_or_hashes():
    values = ("EV-123", "REQ-456", "PROP-789", "a" * 64)
    assert tuple(status_label(value) for value in values) == values


def test_backend_stage_and_status_ids_remain_canonical():
    from seclab.pipeline.stage import StageStatus
    from seclab.results import VerificationStatus

    assert {item.value for item in StageStatus} == {"NOT_STARTED", "RUNNING", "COMPLETED", "SKIPPED", "FAILED"}
    assert {item.value for item in VerificationStatus} == {
        "PASS", "FAIL", "INCONCLUSIVE", "NOT_RUN", "TOOL_ERROR", "SPEC_ERROR", "BUILD_ERROR",
    }
    assert MENU_LABELS["source"] == "Mã nguồn (Source)"
