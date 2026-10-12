# GUI Core v2 — Generic Verification Workbench

Giao diện desktop là lớp hiển thị và điều khiển tùy chọn dùng PySide6 cho pipeline SecLab hiện có.

## Yêu cầu môi trường

- Python 3.11 trở lên (môi trường dự án hiện dùng Python 3.12).
- PySide6 phiên bản 6.7 trở lên và dưới 7; cài bằng `python -m pip install ".[gui]"` hoặc `python -m pip install PySide6`.
- Để mở workbook đặc tả theo form giáo viên, cài thêm phần XLSX bằng `python -m pip install ".[xlsx]"` (có thể gộp `.[gui,xlsx]`).
- Dự án và bộ công cụ kiểm chứng hiện có. Khả năng dùng sanitizer phụ thuộc vào compiler/runtime đã cài.

Sau khi cài dự án, chạy `seclab-workbench`; hoặc chạy `python -m seclab.gui.app` từ thư mục mã nguồn đã cấu hình.

Khi phát triển, chạy `python -m seclab.gui.app --reload` bằng Python trong môi trường ảo của dự án. Trình theo dõi kiểm tra các tệp `*.py` đã lưu trong `src/seclab`, chờ thao tác ghi của trình soạn thảo hoàn tất rồi mở lại GUI khi phát hiện thay đổi. Cửa sổ hiện tại sẽ đóng khi tải lại, vì vậy trạng thái biểu mẫu chưa lưu sẽ không được giữ. Nhấn Ctrl+C để dừng trình theo dõi.

## Kiến trúc

`MainWindow` quản lý điều hướng, chọn dự án/đặc tả, nút chạy, lịch sử, log và worker. `ProjectController` chuyển việc nạp, kiểm tra schema/ngữ nghĩa/công thức và chuẩn hóa cho `seclab.specification`. Ngoài JSON, GUI nhận workbook `.xlsx` theo form giáo viên qua `Teacher XLSX Adapter`; adapter chiếu các sheet sang schema chuẩn trong bộ nhớ, giữ hash/tệp nguồn bất biến, và không chạy công thức Excel. `VerificationController` gọi `run_full_verification`, nạp báo cáo/manifest đã lưu và tìm bằng chứng trong thư mục của lượt chạy được chọn. GUI không tự phân tích công thức kiểm chứng, gọi solver, biên dịch mã nguồn, chạy testcase hay đưa ra kết luận.

Gói gồm các khu vực dashboard, đặc tả, yêu cầu/thuộc tính/test, chọn giai đoạn và tiến độ, danh mục mã nguồn, mô hình, kiểm chứng hình thức, phân tích tĩnh/bộ nhớ, kiểm thử động/độ bao phủ, fuzzing, báo cáo và cài đặt/bộ công cụ. Trang Báo cáo nhóm kết quả, bằng chứng, truy vết, giới hạn, xuất JSON và lịch sử chạy. Các bảng chỉ đọc. Chức năng xuất HTML/PDF đang tắt vì kho mã chưa có bộ máy tạo các loại báo cáo đó; xuất JSON sẽ tuần tự hóa `PipelineReport` hiện có.

Results can be filtered by backend stage and status and show property/test ID, optional severity metadata, stage completion timestamp, and evidence count. The result contract has no per-result timestamp, so the table labels the available time as the stage timestamp. Evidence rows show artifact ID/type/path/SHA-256/source and open through the controller, which confines the path to the run workspace and checks the content hash. Traceability rows join requirement targets to result/evidence IDs and source files by the report's requirement mapping. Source rows show before/after SHA-256, discovered function names, and changed/unchanged state. Run history shows run ID/time, project, specification, and stage statuses.

## Pipeline interaction and threading

Full and selected-stage runs call the same pipeline API. The Verification Stages area lets users choose stages; selected-stage requests include the pipeline's declared prerequisite closure. Settings map to generic `PipelineOptions` and are passed to a worker before it starts. Project/specification selection and run settings are locked while a run is active. Optional stage progress callbacks publish completed or skipped stage records. Callback failures are isolated from pipeline behavior. The GUI runs the controller in a `QThread` and uses queued Qt signals for stage updates, completion, and errors, keeping the interface available while the backend runs. Specification load/validate/normalize use the specification service; no verification checker runs on the GUI thread.

The workspace is outside the project source tree, consistent with pipeline safety checks. Existing workspace manifests provide history without a GUI database. Reports can be reopened from that workspace.

## Result semantics and limits

Stage lifecycle (`NOT_STARTED`, `RUNNING`, `COMPLETED`, `SKIPPED`, `FAILED`) is shown separately from each `VerificationStatus`. Results preserve `PASS`, `FAIL`, `INCONCLUSIVE`, `BUILD_ERROR`, and `TOOL_ERROR`; unrun targets show `NOT_CHECKED`, while `SKIPPED` remains a stage lifecycle state. The dashboard summary counts backend statuses by their actual scope. It never creates an overall project PASS/FAIL or safety percentage. Clean static results, bounded fuzz campaigns, and coverage remain scoped measurements and retain backend classifications/limitations.

Memory and tool limitations are rendered from backend results and limitations. The GUI does not reinterpret Windows sanitizer/tool restrictions. Evidence opens read-only; text, JSON, and log formats can be viewed, while binary content is represented by metadata. Evidence paths are resolved within the run directory.

## Current environment verification

Pure controller tests and `compileall` can run without the GUI extra. `tests/integration/gui/test_gui_smoke.py` performs an automated Qt offscreen construction/navigation smoke when PySide6 exists. This checks QApplication, MainWindow, controller wiring, sidebar, and page navigation only; it is not a real interactive workflow.

In the validation environment checked on 2026-10-03: Windows 11, Python 3.12.5, pip 24.2, LLVM clang 22.1.7, and MinGW GCC 8.1.0 are present. PySide6 is not installed; `pip install PySide6` was blocked by the environment's network socket policy. The pip wheel cache and registered Python launcher list contain no alternative local PySide6 install. GUI runtime is therefore blocked here, and no launch or interactive workflow is claimed.

## Smoke test procedure

For an interactive verification, launch the application on a desktop with Qt available. Open the demo project, select its JSON specification, then Load, Validate, and Normalize. Run Model, Formal, Static, Dynamic, and Fuzzing from the dashboard controls; open each corresponding page and inspect CTL, BMC, SMT, memory, coverage, and fuzzing records. Open evidence from the Evidence tab or result evidence IDs, inspect traceability and limitations, then inspect/export the run report. Finally run Full Verification and confirm the window remains responsive while stage updates and logs arrive. Treat these steps as a manual smoke workflow; do not infer an overall project verdict.

## Known limitations

- HTML/PDF report controls are disabled because no such backend is implemented; JSON export serializes the existing pipeline report.
- Stage progress arrives as stages complete. The current orchestrator does not publish per-tool/per-property live progress within a stage.
- Dynamic/fuzz campaign stop controls and selected-test execution are not exposed because the pipeline API does not provide GUI cancellation or selection operations.
- Evidence content is opened read-only. Text-like evidence is displayed; binary artifacts show metadata only.
- **Windows/MinGW sanitizer limitation:** sanitizer build/runtime support varies with compiler and runtime. ASan/UBSan build errors, unavailable LeakSanitizer, and StructAnalyzer limitations remain backend/environment outcomes. The GUI displays their recorded statuses and limitations; it does not claim sanitizer support or change these classifications.
- A PySide6-unavailable environment has `GUI_RUNTIME_BLOCKED: PySide6 unavailable in current environment.` Do not report launch or interactive smoke as passed in that case.
