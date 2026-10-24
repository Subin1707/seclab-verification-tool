# CHƯƠNG VI. PHƯƠNG PHÁP: FUZZING

## 6.1. Mục tiêu và phạm vi

Fuzzing khảo sát hành vi thực thi của target khi nhận nhiều đầu vào trong một ngân sách xác định. Phân tích tập trung vào crash, timeout và các vi phạm của oracle đã khai báo. Kết quả dưới đây là campaign fuzzing thực tế trên `generated-model-api`, phạm vi `MODEL_GENERATED_API`; target là API C được sinh từ mô hình. Vì vậy, kết quả đánh giá độ bền thực thi của mã C sinh ra, không thay thế kiểm chứng yêu cầu an toàn trong đặc tả và không đại diện cho các hàm production chưa được cài đặt/nối vào target.

Trong lần chạy này, mã C được sinh và biên dịch trước. Fuzzer cấp payload dữ liệu cho executable; nó không tạo mã C mới ở mỗi vòng. Mỗi observation lưu loại và nội dung/hash input. Các loại input được ghi nhận là `BYTES`, `SCALARS` và `TEXT`. Campaign có 82 input duy nhất trong 100 lần thực thi.

## 6.2. Target và phạm vi mô hình

| Thuộc tính | Giá trị theo kết quả chạy |
|---|---|
| Target | `generated-model-api` |
| Phạm vi phân tích | `MODEL_GENERATED_API` 
| Ca kiểm thử theo báo cáo kết quả | `MODEL-API-db6de4038ca3a181f507fe8e78e98132de4871b6b17a61ac30ca358c77ecdd8e` 
| Hàm ứng dụng gắn với ca kiểm thử | `None` |
| Ca kiểm thử | `MODEL-API-db6de4038ca3a181f507fe8e78e98132de4871b6b17a61ac30ca358c77ecdd8e` |
| Hàm ứng dụng | `None` (không gắn với một hàm ứng dụng production cụ thể) |
| Chiến lược | `BLACKBOX` |
| Seed | `1` |
| Loại executable | `EXECUTABLE` |
| Timeout mỗi input | 2 giây |
| Kích thước input tối đa | 4096 byte |

Mô hình gồm các trạng thái `AUTHENTICATED`, `AUTH_FAILED`, `CHARGING`, `CONNECTED`, `DISCONNECTED`, `DISCONNECTING`, `EMERGENCY`, `OVERHEAT`, `PORT_FAULT`, `RECOVERED_SAFE`, `SOC_FULL`, `START_BLOCKED`, `STOPPED_DISCONNECT`, `STOPPED_EMERGENCY`, `STOPPED_OVERHEAT`, `STOPPED_PORT_FAULT`, `STOPPED_SOC_FULL`, `unreachable_req_auth_01_violation`, `unreachable_req_auth_02_violation`, `unreachable_req_chg_01_violation`, `unreachable_req_chg_02_violation`, `unreachable_req_emg_01_violation`, `unreachable_req_port_01_violation`, `unreachable_req_port_02_violation`, `unreachable_req_port_03_violation`, `unreachable_req_soc_01_violation`, `unreachable_req_soc_02_violation`, `unreachable_req_temp_01_violation`.

Các chuyển tiếp thuộc mô hình (47): `T-022`, `T-003`, `T-023`, `T-005`, `T-025`, `T-014`, `T-012`, `T-008`, `T-010`, `T-006`, `T-002`, `T-004`, `T-021`, `T-001`, `T-020`, `T-030`, `T-015`, `T-029`, `T-013`, `T-027`, `T-009`, `T-028`, `T-011`, `T-019`, `T-036`, `T-026`, `T-007`, `T-024`, `T-035`, `T-017`, `T-034`, `T-018`, `T-032`, `T-016`, `T-033`, `T-031`, `T-037`, `T-038`, `T-045`, `T-046`, `T-047`, `T-042`, `T-043`, `T-044`, `T-039`, `T-040`, `T-041`. Các trạng thái `unreachable_req_*_violation` là trạng thái được mô hình hóa để kiểm chứng; sự hiện diện của chúng không có nghĩa campaign fuzz đã đi tới hoặc kiểm tra các trạng thái đó.

## 6.3. Cấu hình campaign

Artifact campaign `bf0c259bd7d9` ghi nhận:

| Tham số | Giá trị |
|---|---:|
| Iteration yêu cầu / thực thi | 100 / 100 |
| Execution yêu cầu | 100 |
| Input duy nhất | 82 |
| Kích thước corpus cuối | 1 |
| Seed | 1 |
| Strategy | `BLACKBOX` |
| Timeout mỗi input | 2.0 giây |
| Kích thước input tối đa | 4096 byte |
| Thời gian campaign | 28.656 giây |
| Stop reason | `ITERATION_LIMIT` |
| Thay đổi mã nguồn trong campaign | Không (`source_integrity_unchanged=true`) |
| Coverage mới | Không có dữ liệu; `coverage_delta=[]` |
| Oracle | `NO_CRASH` |
| Configuration SHA-256 | `ec7d061647a442aea99352704c6d38af8e0c3c61f6f787396ece4ff5e96e3d2e` |

**Giải thích hai chỉ số input:** `unique_inputs=82` là số payload khác nhau đã được xét trong 100 lần chạy. `corpus_size=1` là kích thước corpus được giữ lại trong summary. Hai giá trị có ý nghĩa khác nhau; không diễn giải corpus size 1 thành chỉ có một input được chạy. Summary cho biết số input duy nhất và số lần thực thi riêng biệt.

## 6.4. Log chạy và bằng chứng

### Log build executable

Các lệnh build dùng C99, bật `-Wall -Wextra -Werror`; cả hai compiler hoàn tất với exit code 0. Observation của các lượt fuzz ghi executable GCC là process được chạy.

```text
GCC:
gcc -std=c99 -Wall -Wextra -Werror generated/source/model.c generated/fuzz/model_fuzz.c generated/fuzz/model_fuzz_driver.c -o generated/build/model-fuzz-gcc.exe
status=COMPLETED
exit_code=0
timed_out=false
stdout=""
stderr=""
sha256(executable)=7b78b183bcbcd070ff041dbdfbbacc79a84fb2528474ec7f7adb2791b919fd13

Clang:
clang -std=c99 -Wall -Wextra -Werror generated/source/model.c generated/fuzz/model_fuzz.c generated/fuzz/model_fuzz_driver.c -o generated/build/model-fuzz-clang.exe
status=COMPLETED
exit_code=0
timed_out=false
stdout=""
stderr=""
sha256(executable)=96b59c73283431d1c9167d757640aa30db628407b567feb9cd41b3a4a2e5f8e8
```

Nguồn gốc: `evidence/build/model-fuzz-gcc.json` và `evidence/build/model-fuzz-clang.json` trong run bên dưới.

### Log một số lần thực thi

Mỗi lượt có một JSON observation riêng. Ví dụ lượt đầu (`fuzz-executions/bf0c259bd7d9-000000-observation.json`):

```text
campaign_id=bf0c259bd7d9
iteration=0
input_id=model-api-e95f86e835314499b6dfe97b555c05a2
input_kind=BYTES
input_size=4
input_base64=AAECAw==
input_sha256=b5b0444d94ce3c58e6f5df63c96da97e6cf87ff4300ff4cc1dd4f12d9e5eec92
executable=model-fuzz-gcc.exe
classification=NORMAL_EXIT
exit_code=0
crashed=false
timed_out=false
stdout=""
stderr=""
```

Ví dụ lượt cuối (`fuzz-executions/bf0c259bd7d9-000099-observation.json`):

```text
iteration=99
input_id=blackbox-00000099
input_kind=TEXT
input_size=41
input_sha256=78fa61a198613f3c54155b3d2b8322c8d8fe72fb4f1b6f6d417796c4d1d5cd7c
classification=NORMAL_EXIT
exit_code=0
crashed=false
timed_out=false
stdout=""
stderr=""
```

Tổng hợp toàn bộ 100 observation bằng cách đếm trường `classification` và `command.exit_code`: `NORMAL_EXIT=100`, `exit_code=0` ở cả 100 lượt. Phân loại input trong log: 37 `BYTES`, 29 `SCALARS`, 34 `TEXT`. Không có crash, timeout, oracle failure hoặc failure signature. Các JSON lưu input (một số dạng base64/typed payload), hash, command, stdout/stderr preview, thời lượng và kết quả oracle; có thể lần theo từng iteration theo tên file đánh số `000000`–`000099`.

### Log tổng kết analyzer

Trích từ `evidence/fuzz-campaigns/bf0c259bd7d9-summary.json`:

```text
campaign_id=bf0c259bd7d9
strategy=BLACKBOX
seed=1
iterations_requested=100
iterations_executed=100
unique_inputs=82
corpus_size=1
crashes=0
timeouts=0
oracle_failures=0
stop_reason=ITERATION_LIMIT
source_integrity_unchanged=true
coverage_delta=[]
status=INCONCLUSIVE
reason_code=NO_FAILURE_FOUND_WITHIN_FUZZ_BUDGET
message="No failure found within this bounded fuzz campaign; this does not establish absence of defects."
```

Kết quả theo giao diện phân tích:

```text
KẾT QUẢ: INCONCLUSIVE · NO_FAILURE_FOUND_WITHIN_FUZZ_BUDGET
Mục tiêu: generated-model-api · phạm vi: MODEL_GENERATED_API
Chiến lược/seed: BLACKBOX / 1
Lượt thực thi: 100 / 100 · đầu vào duy nhất: 82 · kích thước corpus: 1
Oracle thất bại: 0 · crash: 0 · quá thời hạn: 0
Lý do dừng: ITERATION_LIMIT · mã nguồn không bị thay đổi: True
Độ bao phủ mới: không có dữ liệu
Tệp bằng chứng: 104 · kết quả quan sát từng lượt: 100
```

### Vị trí artifact

Thư mục run: `t/codex-smart-ev-gui/test_real_generic_c_project_ru0/runs/e95f86e835314499b6dfe97b555c05a2/`.

| Đường dẫn tương đối trong run | Nội dung |
|---|---|
| `evidence/fuzz-campaigns/bf0c259bd7d9-manifest.json` | Cấu hình tái lập: target, strategy, seed, giới hạn, timeout, oracle và hash cấu hình |
| `evidence/fuzz-campaigns/bf0c259bd7d9-summary.json` | Summary, 100 kết quả theo lượt, số liệu corpus, verdict và danh sách evidence |
| `evidence/fuzz-executions/bf0c259bd7d9-000000-observation.json` … `bf0c259bd7d9-000099-observation.json` | 100 observation, từng input, command, exit, stdout/stderr preview và oracle result |
| `evidence/fuzz-corpus/` | Corpus và index của campaign |
| `evidence/build/model-fuzz-gcc.json`, `model-fuzz-clang.json` | Lệnh và kết quả build harness |
| `evidence/manifest/run-manifest.json` | Môi trường và toolchain |
| `generated/source/model.c` | Mã C model được sinh |
| `generated/fuzz/model_fuzz.c`, `generated/fuzz/model_fuzz_driver.c` | Harness và stdin driver được sinh |

Trang kết quả bạn cung cấp hiển thị 104 tệp bằng chứng và 100 observation. Riêng `summary.json` có 103 mục trong `evidence_ids` và 100 mục `execution_evidence`; hai bộ đếm có thể khác nhau do phạm vi tổng hợp khác nhau, nên báo cáo giữ rõ nguồn của từng con số. Stage `FUZZING` được ghi `COMPLETED`, thời gian `2026-10-23T01:51:53.619927Z`–`2026-10-23T01:52:22.453782Z` (khoảng 28.828 giây), theo `evidence/stage-executions/fuzzing-execution.json`. Từng observation có `output_persisted=false`; stdout/stderr preview vẫn được lưu trong JSON quan sát nhưng không có raw stdout/stderr đầy đủ như file process riêng. Đây là giới hạn khi gọi các artifact là “log”: chúng là log có cấu trúc/preview và dữ liệu input tái lập được lưu, không phải transcript terminal đầy đủ.

## 6.5. Phân tích kết quả và giới hạn oracle

Trong cả 100 lần thực thi, target kết thúc với exit code 0; analyzer không thấy crash, timeout hoặc vi phạm oracle `NO_CRASH`. Campaign dừng vì chạm giới hạn iteration, không phải vì đạt coverage hay chứng minh hoàn tất mọi đường thực thi. Không có dữ liệu coverage mới để biết những nhánh nào được đi qua.

Oracle `NO_CRASH` chỉ kiểm tra tính ổn định thực thi ở mức crash. Nó không kiểm tra các yêu cầu an toàn của mô hình, tính đúng của trạng thái/chuyển tiếp, hay việc các trạng thái vi phạm `unreachable_req_*_violation` có thể tiếp cận hay không. Báo cáo kết quả cũng nêu rõ muốn đánh giá yêu cầu an toàn cần xem trang kiểm chứng hình thức (CTL), nơi có negative control chạy trên mutant và counterexample tương ứng. Fuzzing không thay thế phần kiểm chứng đó.

Đầu vào 82 giá trị duy nhất được xét trong 100 lượt cho thấy có lặp payload hoặc dữ liệu được deduplicate; ngân sách vẫn chỉ là 100 lần thực thi. Tăng iteration đơn thuần không bảo đảm tăng khả năng phát hiện nếu định dạng/seed không kích hoạt sâu API hoặc oracle không quan sát thuộc tính cần bảo vệ. Cải thiện tiếp theo là thiết kế seed/ngữ pháp phù hợp với API và bổ sung oracle theo requirement; sau đó bật/thu coverage nếu backend hỗ trợ và lưu đầy đủ input gây finding để replay.

## 6.6. Kết luận fuzzing

**Verdict:** `INCONCLUSIVE · NO_FAILURE_FOUND_WITHIN_FUZZ_BUDGET`.

Không tìm thấy lỗi mà crash checker, sanitizer hoặc oracle đang cấu hình nhận diện trong 100 lần thực thi. Đây không phải `PASS` và không phải bằng chứng chứng minh target an toàn. Phạm vi kết luận chỉ là độ bền thực thi quan sát được của `generated-model-api` trong campaign `bf0c259bd7d9`, seed 1, chiến lược BLACKBOX và ngân sách đã nêu.
