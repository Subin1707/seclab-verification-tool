"""Vietnamese presentation labels; backend IDs remain canonical."""
from __future__ import annotations

STAGE_LABELS = {
    "SPECIFICATION": "Đặc tả (Specification)", "MODEL": "Mô hình (Model)",
    "CTL": "Kiểm chứng CTL (CTL)", "SOURCE": "Mã nguồn (Source)",
    "BMC": "Kiểm chứng giới hạn (BMC)", "SMT": "Giải bài toán (SMT)",
    "CODEGEN": "Sinh mã C (Codegen)", "BUILD": "Biên dịch (Build)",
    "STATIC": "Phân tích tĩnh (Static)", "MEMORY": "Kiểm tra bộ nhớ (Memory)",
    "DYNAMIC": "Kiểm thử động (Dynamic)", "COVERAGE": "Độ bao phủ (Coverage)",
    "FUZZING": "Kiểm thử mờ (Fuzzing)", "CROSS_CHECK": "Đối chiếu kết quả (Cross-check)",
    "REPORT": "Báo cáo (Report)", "STATIC_ANALYSIS": "Phân tích tĩnh (Static Analysis)",
    "MEMORY_ANALYSIS": "Phân tích bộ nhớ (Memory Analysis)", "SANITIZER": "Bộ kiểm tra bộ nhớ (Sanitizer)",
    "DYNAMIC_TEST": "Kiểm thử động (Dynamic Testing)", "PIPELINE": "Quy trình kiểm chứng (Pipeline)",
    "LOAD_SPECIFICATION": "Nạp đặc tả (Load Specification)", "VALIDATE": "Kiểm tra đặc tả (Validate)",
    "NORMALIZE": "Chuẩn hóa đặc tả (Normalize)", "REVIEW_MODEL": "Xem mô hình (Review Model)",
    "SOURCE_DISCOVERY": "Tìm mã nguồn (Source Discovery)",
    "BUILD_SPECIFICATION_MODEL": "Tạo mô hình từ đặc tả (Model Generation)",
    "GENERATE_C": "Sinh mã C (Code Generation)", "BUILD_GENERATED_C": "Biên dịch mã C (Build)",
    "RUN_DYNAMIC_TESTS": "Chạy kiểm thử động (Dynamic Testing)",
    "RUN_COVERAGE": "Đo độ bao phủ (Coverage)", "RUN_FUZZING": "Chạy kiểm thử mờ (Fuzzing)",
    "VIEW_RESULTS": "Xem kết quả", "VIEW_EVIDENCE": "Xem bằng chứng",
    "VIEW_TRACEABILITY": "Xem truy vết", "VIEW_ACCURACY": "Xem báo cáo benchmark",
    "VIEW_REPORT": "Xem báo cáo", "SAVE_RUN_HISTORY": "Lưu lịch sử chạy",
    "RUN_VERIFICATION": "Chạy kiểm chứng",
}
STATUS_LABELS = {
    "PASS": "ĐẠT (PASS)", "FAIL": "KHÔNG ĐẠT (FAIL)",
    "INCONCLUSIVE": "CHƯA KẾT LUẬN (INCONCLUSIVE)", "SKIPPED": "BỎ QUA (SKIPPED)",
    "NOT_RUN": "CHƯA CHẠY (NOT_RUN)", "NOT_STARTED": "CHƯA BẮT ĐẦU (NOT_STARTED)",
    "PENDING": "ĐANG CHỜ (PENDING)", "RUNNING": "ĐANG CHẠY (RUNNING)",
    "COMPLETED": "HOÀN TẤT (COMPLETED)", "FAILED": "THẤT BẠI (FAILED)",
    "TOOL_ERROR": "LỖI CÔNG CỤ (TOOL_ERROR)", "BUILD_ERROR": "LỖI BIÊN DỊCH (BUILD_ERROR)",
    "UNSUPPORTED": "CHƯA HỖ TRỢ (UNSUPPORTED)",
    "ENVIRONMENT_LIMITED": "BỊ GIỚI HẠN BỞI MÔI TRƯỜNG (ENVIRONMENT_LIMITED)",
    "NOT_CHECKED": "CHƯA KIỂM TRA (NOT_CHECKED)", "UNKNOWN": "CHƯA XÁC ĐỊNH (UNKNOWN)",
    "INFO": "THÔNG TIN (INFO)", "WARNING": "CẢNH BÁO (WARNING)", "ERROR": "LỖI (ERROR)",
    "DEBUG": "GỠ LỖI (DEBUG)", "VALIDATED": "ĐÃ KIỂM TRA (VALIDATED)",
    "READY FOR REVIEW": "SẴN SÀNG XEM LẠI (READY FOR REVIEW)",
    "VERIFIED": "ĐÃ KIỂM CHỨNG (VERIFIED)", "PREVIEW": "BẢN XEM TRƯỚC (PREVIEW)",
    "CHANGED": "ĐÃ THAY ĐỔI (CHANGED)", "UNHASHED": "CHƯA TÍNH HASH (UNHASHED)",
    "UNCHANGED": "KHÔNG THAY ĐỔI (UNCHANGED)", "INTEGRITY_ERROR": "LỖI TOÀN VẸN (INTEGRITY_ERROR)",
    "MISSING": "THIẾU TỆP (MISSING)",
}
MENU_LABELS = {
    "project": "Dự án", "overview": "Tổng quan", "specification": "Đặc tả (Specification)",
    "requirements": "Yêu cầu", "source": "Mã nguồn (Source)", "model": "Mô hình trạng thái (State Model)",
    "codegen": "Sinh mã C (Code Generation)", "formal": "Kiểm chứng hình thức (Formal Verification)",
    "static": "Phân tích tĩnh (Static Analysis)", "memory": "Phân tích bộ nhớ (Memory Analysis)",
    "dynamic": "Kiểm thử động (Dynamic Testing)", "coverage": "Độ bao phủ (Coverage)",
    "fuzzing": "Kiểm thử mờ (Fuzzing)", "results": "Kết quả", "evidence": "Bằng chứng (Evidence)",
    "traceability": "Truy vết (Traceability)", "accuracy": "Báo cáo benchmark",
    "report": "Báo cáo (Report)", "run_history": "Lịch sử chạy", "settings": "Cài đặt",
}
UI_TEXT = {**MENU_LABELS,
    "cancel_run": "Dừng lần chạy", "start": "Bắt đầu kiểm chứng", "stop": "Dừng",
    "refresh": "Làm mới", "clear": "Xóa", "copy": "Sao chép", "open": "Mở", "save": "Lưu",
    "browse": "Chọn tệp", "error": "Lỗi", "warning": "Cảnh báo", "information": "Thông tin",
    "success": "Thành công", "failed": "Thất bại", "skip": "Bỏ qua"}
MESSAGE_LABELS = {
    "select_project": "Vui lòng chọn dự án trước khi chạy kiểm chứng.",
    "select_specification": "Vui lòng chọn tệp đặc tả trước khi chạy kiểm chứng.",
    "invalid_specification": "Không thể kiểm tra đặc tả. Xem chi tiết kỹ thuật để biết nguyên nhân.",
    "technical_detail": "Chi tiết kỹ thuật", "raw_log": "Chi tiết kỹ thuật / Nhật ký gốc",
    "no_data": "Mở dự án và chạy kiểm chứng để hiển thị dữ liệu tại đây.",
    "start": "Bắt đầu kiểm chứng", "stop": "Dừng lần chạy", "open_project": "Mở dự án",
    "choose_specification": "Chọn đặc tả", "workspace": "Thư mục chạy", "run_all": "Chạy toàn bộ",
}
TOOL_LABELS = {
    "Evidence": "Bằng chứng kiểm chứng (Evidence)", "Traceability": "Truy vết (Traceability)",
    "Artifact": "Tệp bằng chứng (Artifact)", "Run ID": "Mã lần chạy (Run ID)",
    "Stage": "Giai đoạn kiểm chứng (Stage)", "Checker": "Bộ kiểm tra (Checker)",
    "Oracle": "Tiêu chí đối chiếu (Oracle)", "Fixture": "Bộ dữ liệu kiểm thử (Fixture)",
    "Ground Truth": "Kết quả chuẩn tham chiếu (Ground Truth)", "Benchmark": "Bộ đánh giá (Benchmark)",
    "Accuracy": "Độ chính xác (Accuracy)", "Precision": "Độ chính xác cảnh báo (Precision)",
    "Recall": "Khả năng phát hiện (Recall)", "TP": "Phát hiện đúng (TP)",
    "TN": "Nhận diện đúng trường hợp an toàn (TN)", "FP": "Cảnh báo nhầm (FP)", "FN": "Bỏ sót lỗi (FN)",
}
STATUS_HELP = {
    "PASS": "Đạt trong phạm vi kiểm tra đã nêu; không phải kết luận tổng quát cho toàn dự án.",
    "FAIL": "Không đạt: bộ kiểm tra đã tìm thấy vi phạm thuộc tính hoặc tiêu chí đã khai báo.",
    "INCONCLUSIVE": "Chưa đủ bằng chứng để kết luận PASS hay FAIL; có thể do hết thời gian hoặc giới hạn môi trường.",
    "SKIPPED": "Giai đoạn bị bỏ qua vì không được chọn hoặc thiếu điều kiện cần thiết.",
    "NOT_RUN": "Giai đoạn hoặc bộ kiểm tra này chưa chạy.",
    "TOOL_ERROR": "Lỗi công cụ hoặc hạ tầng khiến việc kiểm tra không thể hoàn tất.",
    "BUILD_ERROR": "Không thể biên dịch chương trình hoặc bộ chạy kiểm thử.",
    "UNSUPPORTED": "Cấu trúc hoặc chức năng này chưa được công cụ hỗ trợ.",
    "ENVIRONMENT_LIMITED": "Việc kiểm tra bị giới hạn bởi công cụ hoặc môi trường thực thi.",
}
CHECKER_HELP = {
    "CTL": "Kiểm tra mô hình trạng thái có thỏa mãn thuộc tính logic thời gian đã khai báo hay không.",
    "BMC": "Tìm phản ví dụ trong phạm vi số bước giới hạn bằng cách giải mã hóa hành vi.",
    "SMT": "Kiểm tra tính thỏa mãn của điều kiện số học và logic bằng bộ giải như Z3.",
    "STATIC_ANALYSIS": "Phân tích mã nguồn mà không thực thi chương trình.",
    "MEMORY_ANALYSIS": "Tìm vấn đề bộ nhớ khi biên dịch hoặc chạy chương trình.",
    "DYNAMIC_TEST": "Biên dịch và chạy chương trình với đầu vào kiểm thử rồi ghi nhận quan sát thực tế.",
    "COVERAGE": "Đo mã nguồn hoặc nhánh đã chạy. Coverage không tự tạo kết luận an toàn.",
    "FUZZING": "Fuzzing sinh hoặc biến đổi đầu vào, chạy mục tiêu rồi đối chiếu kết quả với oracle và bộ kiểm tra lỗi. Hãy xem mỗi phát hiện cùng đầu vào và bằng chứng tương ứng.",
}
TECH_TERM = {
    **TOOL_LABELS, "Kripke Structure": "Mô hình Kripke (Kripke Structure)",
    "CTL": "Kiểm chứng CTL (Computation Tree Logic - CTL)", "BMC": STAGE_LABELS["BMC"],
    "SMT": STAGE_LABELS["SMT"], "SAT": "Có nghiệm thỏa mãn (SAT)",
    "UNSAT": "Không có nghiệm thỏa mãn (UNSAT)", "UNKNOWN": "Bộ giải chưa xác định được kết quả (UNKNOWN)",
    "COMPILER-DIAGNOSTICS": "Chẩn đoán trình biên dịch (Compiler Diagnostics)",
    "ADDRESSSANITIZER": "Phát hiện lỗi bộ nhớ (AddressSanitizer)",
    "UNDEFINEDBEHAVIORSANITIZER": "Phát hiện hành vi không xác định (UBSan)",
    "LEAK_CHECKER": "Kiểm tra rò rỉ bộ nhớ (Leak Checker)",
    "TEST_ORACLE": "Đối chiếu tiêu chí kiểm thử (Test Oracle)",
    "BLACKBOX": "Kiểm thử hộp đen (Black-box Fuzzing)", **STATUS_LABELS,
}

def stage_label(stage: str) -> str:
    return STAGE_LABELS.get(stage.upper(), stage)

def status_label(status: str) -> str:
    return STATUS_LABELS.get(status.upper(), status)

def message_label(key: str) -> str:
    return MESSAGE_LABELS.get(key, key)

def checker_description(checker: str) -> str:
    return CHECKER_HELP.get(checker.upper(), "")

def checker_label(checker: str) -> str:
    key = checker.replace("_", " ").upper()
    return TECH_TERM.get(checker, CHECKER_HELP.get(key, checker))

def log_label(stage: str, level: str, message: str) -> str:
    stage_name = stage_label(stage)
    status = status_label(level)
    known = {
        "Validating and normalizing selected specification": "Đang kiểm tra và chuẩn hóa đặc tả đã chọn.",
        "Full verification started": "Đã bắt đầu toàn bộ quy trình kiểm chứng.",
        "Full verification report is ready": "Báo cáo kiểm chứng đã sẵn sàng.",
        "Selected stage report is ready": "Báo cáo các giai đoạn đã chọn đã sẵn sàng.",
    }
    detail = known.get(message, "Giai đoạn kiểm chứng đã hoàn tất." if message == "Stage finished"
                       else f"{MESSAGE_LABELS['technical_detail']}: {message}")
    if level.upper() in {"FAILED", "FAIL", "ERROR", "BUILD_ERROR", "TOOL_ERROR"}:
        prefix = "Lỗi khi thực hiện " + stage_name
    elif level.upper() in {"COMPLETED", "PASS"}:
        prefix = "Hoàn tất " + stage_name
    elif level.upper() == "RUNNING":
        prefix = "Đang thực hiện " + stage_name
    else:
        prefix = "Nhật ký " + stage_name
    return f"{prefix} [{status}]: {detail}"
