"""Render a teacher-oriented, evidence-grounded Markdown verification report."""
from __future__ import annotations

import ast
import json
import hashlib
import re
from pathlib import Path
from typing import Any

from .report import PipelineReport


def render_teacher_report(report: PipelineReport) -> str:
    """Render the seven-chapter teacher template from this run's recorded evidence."""
    data = report.to_dict()
    metadata = data.get("metadata", {})
    specification = metadata.get("specification", {})
    specification_info = data.get("specification_info", {})
    stages = {str(item.get("stage_id", "")).upper(): item for item in data.get("stage_summaries", ())}
    results = data.get("results", ())
    evidence_file = _evidence_reader(data)
    provenance = specification.get("metadata", {}).get("source_provenance", {})
    execution_contract = provenance.get("execution_contract", {})
    narrative_tests = provenance.get("narrative_test_cases", ())
    lines = [
        "# Báo cáo tích hợp — Đặc tả → Kripke → Sinh mã → CWE/CVE",
        "",
        f"**Đặc tả:** {specification.get('name', specification_info.get('name', '—'))} · "
        f"`{specification.get('id', specification_info.get('id', '—'))}`",
        "",
        "## Mục lục",
        "",
        "1. [Đặc tả yêu cầu (Specification)](#1-đặc-tả-yêu-cầu-specification)",
        "2. [Kiểm chứng hình thức (Kripke/CTL)](#2-kiểm-chứng-hình-thức-kripkectl)",
        "3. [Mã C sinh ra và Static Checker](#3-mã-c-sinh-ra-và-static-checker)",
        "4. [Trích xuất AST/điều kiện và SMT (Z3)](#4-trích-xuất-astđiều-kiện-và-smt-z3)",
        "5. [Dynamic Fuzzing](#5-dynamic-fuzzing)",
        "6. [Phân loại CWE/CVE tổng hợp](#6-phân-loại-cwecve-tổng-hợp)",
        "7. [Test case truy vết từ đặc tả](#7-test-case-truy-vết-từ-đặc-tả)",
        "",
        "> Báo cáo tổng hợp kết quả của lần chạy này. Kết quả chỉ có ý nghĩa trong phạm vi checker, mã nguồn, "
        "cấu hình và ngân sách thực thi đã ghi nhận; không suy rộng thành bảo đảm an toàn toàn hệ thống.",
        "",
        "## 1. Đặc tả yêu cầu (Specification)",
        "",
    ]
    requirements = specification.get("requirements", ())
    if requirements:
        lines.extend(("| Mã yêu cầu | Loại | Ưu tiên | Nội dung |", "|---|---|---|---|"))
        for item in requirements:
            lines.append("| " + " | ".join(_cell(item.get(key, "—")) for key in
                ("id", "type", "priority", "description")) + " |")
    else:
        lines.append("Không có danh sách yêu cầu trong đặc tả của lần chạy này.")
    lines.extend(("", f"Số biến: {len(specification.get('variables', ()))} · "
                  f"Ràng buộc: {len(specification.get('constraints', ()))} · "
                  f"Hàm khai báo: {len(specification.get('functions', ()))} · "
                  f"Test khai báo: {len(specification.get('tests', ()))}", "",
                  "## 2. Kiểm chứng hình thức (Kripke/CTL)", ""))
    model = stages.get("MODEL", {})
    model_output = model.get("output", {}) if isinstance(model.get("output"), dict) else {}
    stats = model_output.get("statistics", {})
    model_meta = model.get("metadata", {})
    lines.append(f"Trạng thái MODEL: **{model.get('status', 'NOT_RUN')}** · "
                 f"{stats.get('state_count', model_meta.get('state_count', model_output.get('state_count', '—')))} trạng thái · "
                 f"{stats.get('transition_count', model_meta.get('transition_count', model_output.get('transition_count', '—')))} chuyển trạng thái.")
    initial_states = model_meta.get("initial_state_ids", model_output.get("initial_states", ()))
    deadlocks = model_meta.get("deadlock_state_ids", model_output.get("deadlock_state_ids", ()))
    unreachable = model_meta.get("unreachable_state_ids", model_output.get("unreachable_state_ids", ()))
    lines.append(f"Trạng thái ban đầu: {_cell(initial_states)} · Deadlock: {_cell(deadlocks)} · "
                 f"Không tới được: {_cell(unreachable)}.")
    total_states = stats.get("state_count", len(model_output.get("states", ())))
    reachable_count = stats.get("reachable_state_count", len(model_output.get("reachable_state_ids", ())))
    total_transitions = stats.get("transition_count", len(model_output.get("transitions", ())))
    reachability_pct = f"{reachable_count / total_states * 100:.1f}%" if total_states else "n/a"
    lines.append(f"Model-state reachability: {reachable_count}/{total_states} trạng thái từ initial state ({reachability_pct}); "
                 f"đây không phải runtime code coverage. Có {total_transitions} transition khai báo; stage MODEL "
                 "chưa đo riêng tập transition đi qua bởi execution trace.")
    lines.append("")
    formal = [item for item in results if str(item.get("technique", "")).upper() in {"CTL", "BMC"}]
    lines.append(f"Thuộc tính hình thức: {len(formal)} · Đạt: {sum(item.get('status') == 'PASS' for item in formal)} · "
                 f"Không đạt: {sum(item.get('status') == 'FAIL' for item in formal)} · "
                 f"Chưa kết luận/lỗi công cụ: {sum(item.get('status') not in {'PASS', 'FAIL'} for item in formal)}.")
    _append_result_table(lines, formal, ("Bộ kiểm tra / thuộc tính", "Kết quả", "Phản ví dụ / giải thích", "Bằng chứng"))
    lines.extend(("", "### 2.1. Sơ đồ chuyển trạng thái", ""))
    _append_state_diagram(lines, specification)
    lines.append("Bản JSON/DOT đầy đủ được lưu trong artifacts của stage MODEL.")
    lines.extend(("", "## 3. Mã C sinh ra và Static Checker (lỗi bộ nhớ)", ""))
    codegen, build = stages.get("CODEGEN", {}), stages.get("BUILD", {})
    lines.append(f"CODEGEN: **{codegen.get('status', 'NOT_RUN')}** · BUILD: **{build.get('status', 'NOT_RUN')}**.")
    artifact_classes = metadata.get("artifact_classes", {})
    generated_ids = artifact_classes.get("GENERATED_ARTIFACT", ())
    lines.append(f"Bằng chứng mã sinh ra: {', '.join(f'`{item}`' for item in dict.fromkeys(generated_ids)) or 'chưa có artifact được ghi nhận'}.")
    generated_files = codegen.get("metadata", {}).get("generated_files", ())
    if generated_files:
        lines.extend(("", "| Tệp sinh ra | Phân loại | SHA-256 | Evidence |", "|---|---|---|---|"))
        artifact_by_id = {str(item): item for item in generated_ids}
        for item in generated_files:
            if not isinstance(item, dict):
                item = {"path": str(item)}
            evidence_id = _artifact_evidence_id(item, artifact_by_id, evidence_file)
            lines.append("| " + " | ".join(_cell(value) for value in (
                item.get("path", "—"), item.get("artifact_class", "GENERATED_ARTIFACT"),
                _short_hash(item.get("sha256", "—")), _short_ids((evidence_id,)))) + " |")
        c_artifact = next((item for item in generated_files if isinstance(item, dict)
                           and str(item.get("path", "")).replace("\\", "/").endswith("source/model.c")), None)
        if c_artifact:
            c_evidence = _artifact_evidence_id(c_artifact, artifact_by_id, evidence_file)
            loaded = evidence_file(c_evidence) if c_evidence else None
            if loaded:
                source_lines = loaded[1].decode("utf-8", errors="replace").splitlines()
                start = next((index for index, line in enumerate(source_lines) if "seclab_state_count(void)" in line), None)
                if start is not None:
                    excerpt = source_lines[start:min(len(source_lines), start + 24)]
                    excerpt = [line[:88] + " /* truncated */" if len(line) > 88 else line for line in excerpt]
                    lines.extend(("", "### Trích mã C thực tế — API của Kripke model được sinh", "",
                                  "Đây là runtime model do code generator sinh từ đặc tả; không phải phần thân của các hàm probe khai báo riêng trong đặc tả.",
                                  "", "```c", *excerpt, "```"))
    lines.extend(("", "| Checker / ph\u1ea1m vi | Findings | Tr\u1ea1ng th\u00e1i / ghi ch\u00fa | Evidence |",
                  "|---|---:|---|---|"))
    static_results = [item for item in results if _stage(item) in {"STATIC", "MEMORY"}]
    for item in static_results:
        lines.append("| " + " | ".join(_cell(value) for value in (
            f"{item.get('technique', '—')} / {_trim(item.get('scope', '—'), 34)}",
            item.get("metadata", {}).get("finding_count", len(item.get("metadata", {}).get("finding_ids", ()))),
            f"{item.get('status', '—')} / {_trim(item.get('message', ''), 72)}",
            _short_ids(item.get("evidence_ids", ())))) + " |")
    if not static_results:
        lines.append("| — | 0 | Không có kết quả phân tích tĩnh/bộ nhớ trong lần chạy này | — |")
    finding_records = _static_findings(static_results, evidence_file)
    if finding_records:
        lines.extend(("", "### Finding tiêu biểu từ báo cáo analyzer", "",
                      "| Tệp:dòng / analyzer | Mức độ / CWE | Finding | Evidence |",
                      "|---|---|---|---|"))
        for finding in finding_records[:15]:
            explanation = _static_finding_explanation(finding)
            lines.append("| " + " | ".join(_cell(value) for value in (
                f"{_trim(finding.get('file', '—'), 28)}:{finding.get('line') or '—'} / {_trim(finding.get('tool', '—'), 18)}",
                f"{finding.get('severity', finding.get('category', '—'))} / {finding.get('cwe', '—')}",
                _trim(finding.get("message", "—"), 100) + " · " + explanation,
                _short_ids((finding.get("evidence_id", "—"),)))) + " |")
        if len(finding_records) > 15:
            lines.append(f"\nHiển thị 15/{len(finding_records)} finding tiêu biểu; số lượng theo analyzer và CWE được tổng hợp bên dưới. Toàn bộ bản ghi ở evidence.")
    else:
        lines.append("\nKhông có finding có cấu trúc được đính kèm hoặc không đọc được bằng chứng analyzer; xem trạng thái từng checker ở bảng trên.")
    lines.extend(("", "## 4. Trích xuất AST/điều kiện và SMT (Z3)", ""))
    function_links = stages.get("SOURCE", {}).get("metadata", {}).get("function_links", ())
    functions = specification.get("functions", ())
    lines.append(f"Hàm khai báo trong đặc tả: {len(functions)} · Hàm dò thấy trong source inventory: "
                 f"{len(function_links)} · Thân hàm được khai báo trong đặc tả: "
                 f"{'có' if execution_contract.get('declared_function_bodies_present') else 'không'}.")
    if functions:
        link_by_name = {str(item.get("name", "")): item for item in function_links}
        lines.extend(("", "| Hàm / ngôn ngữ | Liên kết source | Yêu cầu | AST / đối chiếu source |",
                      "|---|---|---|---|"))
        for function in functions:
            link = link_by_name.get(str(function.get("name", "")), {})
            lines.append("| " + " | ".join(_cell(value) for value in (
                f"{function.get('name', function.get('id', '—'))} ({function.get('language', '—')})",
                link.get("source_relative_path") or function.get("file") or "chưa liên kết source",
                ", ".join(function.get("requirement_ids", ())) or "—",
                link.get("match_status", "chưa có AST evidence"))) + " |")
    ast_evidence = [item for item in results if "AST" in str(item.get("technique", "")).upper()]
    if ast_evidence:
        _append_result_table(lines, ast_evidence, ("Checker", "Trạng thái", "Chi tiết", "Evidence"))
    elif not execution_contract.get("declared_function_bodies_present"):
        lines.append("Đặc tả chỉ khai báo tên/chữ ký hàm, không chứa thân hàm thực thi; do đó không thể suy ra AST, "
                     "độ phức tạp McCabe hoặc nhánh từ đặc tả. Không ghi nhận AST extractor cho lần chạy này.")
    else:
        lines.append("Không có kết quả AST/điều kiện nhánh được ghi nhận; đây là giới hạn dữ liệu của lần chạy.")
    python_artifact = next((item for item in stages.get("CODEGEN", {}).get("metadata", {}).get("generated_files", ())
                            if isinstance(item, dict) and str(item.get("path", "")).replace("\\", "/").endswith("python/model.py")), None)
    if python_artifact:
        artifact_ids = {str(value): str(value) for value in metadata.get("artifact_classes", {}).get("GENERATED_ARTIFACT", ())}
        evidence_id = _artifact_evidence_id(python_artifact, artifact_ids, evidence_file)
        loaded = evidence_file(evidence_id) if evidence_id else None
        if loaded:
            metrics = _python_ast_metrics(loaded[1].decode("utf-8", errors="replace"))
            lines.extend(("", "### AST của mã Python sinh — model runtime", "",
                          "AST được trích từ artifact hash-verified của lần chạy. Đây là mã model runtime; không đại diện cho các hàm ứng dụng chưa có thân hàm.",
                          "", "| Hàm | Dòng | Biến gán / điều kiện / vòng lặp | McCabe / lồng nhau |",
                          "|---|---:|---|---|"))
            if metrics:
                for metric in metrics:
                    lines.append("| " + " | ".join(_cell(value) for value in (
                        metric["name"], metric["line"],
                        f"vars: {', '.join(metric['variables']) or '—'} · if: {metric['conditions']} · loops: {metric['loops']}",
                        f"{metric['complexity']} / {metric['nesting']}"
                    )) + " |")
            else:
                lines.append("| Không tìm thấy hàm | — | — | 0 | 0 | 1 | 0 |")
    lines.append("")
    smt = [item for item in results if str(item.get("technique", "")).upper() == "SMT"]
    _append_smt_table(lines, smt, evidence_file)
    lines.extend(("", "## 5. Dynamic Fuzzing", ""))
    fuzz = stages.get("FUZZING", {})
    fuzz_output = fuzz.get("output", {}) if isinstance(fuzz.get("output"), dict) else {}
    campaigns = fuzz_output.get("campaigns", [fuzz_output] if fuzz_output else [])
    if campaigns:
        lines.extend(("Black-box quan sát input, output, exit/crash, timeout và oracle mà không dùng instrumentation để chọn nhánh. "
                      "White-box cần instrumentation/coverage feedback; chiến lược CONCOLIC hiện chưa hỗ trợ trong engine.",
                      "Vòng fuzz là số lần chạy input, không phải số vòng lặp bên trong chương trình. Line/branch coverage đo mã nguồn được chạy; model-state reachability ở mục 2 đo đồ thị đặc tả.", "",
                      "| Target / chiến lược | Vòng yêu cầu/thực chạy · input duy nhất | Corpus / coverage đo được | Lỗi / crash / timeout |",
                      "|---|---:|---:|---|"))
        for item in campaigns:
            target_name = _trim(item.get("function_id") or item.get("target", "—"), 28)
            coverage_observed = bool(item.get("coverage_start") or item.get("coverage_end") or item.get("coverage_delta"))
            coverage_text = f"{len(item.get('coverage_delta', ()))} mới" if coverage_observed else "chưa đo"
            lines.append("| " + " | ".join(_cell(value) for value in (
                f"{target_name} · {item.get('strategy', '—')}/{item.get('seed', '—')}",
                f"{item.get('iterations_requested', '—')} / {item.get('iterations_executed', 0)} · {item.get('unique_inputs', 0)}",
                f"{item.get('corpus_size', 0)} / {coverage_text}",
                f"{len(item.get('failures', ()))} / {item.get('crashes', 0)} / {item.get('timeouts', 0)}")) + " |")
            lines.append(f"Dừng: {_trim(item.get('stop_reason', '—'), 72)}.")
        lines.extend(("", f"Hàm Python có thể fuzz theo execution contract: "
                      f"{'có' if execution_contract.get('fuzzing_targets_executable') else 'không'}.",
                      f"Hàm sinh từ đặc tả có thân chạy được: "
                      f"{'có' if execution_contract.get('declared_function_bodies_present') else 'không'}.",
                      "Campaign dưới đây là campaign thật được ghi trong lần chạy; không diễn giải campaign trên model/API thành fuzzing từng hàm ứng dụng."))
        lines.append("")
        lines.append("Phạm vi target được ghi theo từng campaign. Nếu target là MODEL_GENERATED, kết quả kiểm tra "
                     "runtime/mô hình sinh ra và không đại diện cho hành vi của hàm ứng dụng chưa được sinh.")
        findings = [(campaign, finding) for campaign in campaigns for finding in campaign.get("failures", ())]
        lines.extend(("", "### Kết luận phân tích lỗi và vòng lặp", ""))
        for campaign in campaigns:
            target = campaign.get("function_id") or campaign.get("target", "target")
            executed = campaign.get("iterations_executed", 0)
            requested = campaign.get("iterations_requested", campaign.get("executions_requested", 0))
            failures_for_campaign = campaign.get("failures", ())
            verdict = campaign.get("verification_result") or {}
            observations = campaign.get("execution_evidence", ())
            classes: dict[str, int] = {}
            for observation in observations:
                label = str(observation.get("classification", "UNKNOWN"))
                classes[label] = classes.get(label, 0) + 1
            result_summary = ", ".join(f"{name}: {count}" for name, count in sorted(classes.items())) or "không có execution record"
            if failures_for_campaign:
                conclusion = (f"{target}: ghi nhận {len(failures_for_campaign)} lỗi/failure cần xem xét trong "
                              f"{executed}/{requested} vòng fuzz; kết quả phân loại theo từng lỗi ở dưới.")
            elif executed:
                conclusion = (f"{target}: chưa phát hiện lỗi được xác nhận trong {executed}/{requested} vòng fuzz "
                              f"({campaign.get('unique_inputs', 0)} input duy nhất; {campaign.get('crashes', 0)} crash, "
                              f"{campaign.get('timeouts', 0)} timeout, {campaign.get('oracle_failures', 0)} oracle failure).")
            else:
                conclusion = f"{target}: không có input nào được thực thi; run này chưa đưa ra kết luận fuzzing."
            lines.append(conclusion)
            if verdict:
                lines.append(f"Verdict của campaign: **{verdict.get('status', '—')} / {verdict.get('reason_code', '—')}** — "
                             f"{_trim(verdict.get('message', '—'), 220)}")
            oracle_checks = _fuzz_oracle_checks(campaign, evidence_file)
            if oracle_checks:
                oracle_text = ", ".join(f"{check.get('oracle_type', '—')}={check.get('expected', '—')}"
                                         for check in oracle_checks)
                lines.append(f"Oracle đã kiểm tra: {oracle_text}. Đây là phạm vi kiểm tra lỗi của run; "
                             "nếu chỉ có NO_CRASH thì không thể phát hiện sai kết quả nghiệp vụ nếu không có oracle chức năng.")
            lines.append(f"Quan sát runtime: {result_summary}.")
            if not (campaign.get("coverage_start") or campaign.get("coverage_end") or campaign.get("coverage_delta")):
                lines.append("Vòng lặp của engine đã được đếm ở trên; coverage nhánh/vòng lặp bên trong target chưa được thu thập, "
                             "nên không thể kết luận target đã đi qua vòng lặp/nhánh nào.")
            elif campaign.get("coverage_delta"):
                lines.append(f"Coverage ghi nhận {len(campaign['coverage_delta'])} điểm mới; đây là tín hiệu thực thi, không tự nó là lỗi.")
            else:
                lines.append("Coverage đã được thu thập nhưng không có điểm mới trong campaign này.")
        if findings:
            lines.extend(("", "### Lỗi cụ thể được fuzzing phát hiện", ""))
            for index, (campaign, finding) in enumerate(findings, 1):
                fuzz_input = finding.get("input", {})
                minimized = finding.get("minimized_input") or {}
                signature = finding.get("signature", {})
                result = finding.get("verification_result") or {}
                output_excerpt = _fuzz_failure_output(finding.get("evidence_ids", ()), evidence_file)
                lines.extend((f"#### Lỗi {index} — {campaign.get('function_id') or campaign.get('target', 'target')}",
                              f"Phân loại: **{finding.get('classification', '—')} / {signature.get('kind', '—')}** · "
                              f"{signature.get('detail') or signature.get('sanitizer') or signature.get('oracle_id') or 'Không có mô tả chi tiết trong signature.'}",
                              f"Kết quả oracle/run: {_trim(result.get('message') or result.get('reason_code') or '—', 220)}",
                              f"Input gây lỗi: `{fuzz_input.get('id', '—')}` · SHA-256 `{_short_hash(fuzz_input.get('content_hash', '—'))}`",
                              f"Input tối giản: `{minimized.get('id', 'chưa có')}` · SHA-256 `{_short_hash(minimized.get('content_hash', '—'))}` · "
                              f"{finding.get('minimization_executions', 0)} lượt thử tối giản"))
                if output_excerpt:
                    lines.append(f"Output quan sát được: `{_cell(output_excerpt)}`")
                lines.append(f"Evidence: {_short_ids(finding.get('evidence_ids', ()))}")
                lines.append("")
        else:
            lines.append("Không có lỗi cụ thể để liệt kê trong campaign này; các execution record chỉ là bằng chứng cho kết luận có giới hạn ở trên, không phải lỗi.")
    else:
        lines.append(f"FUZZING: **{fuzz.get('status', 'NOT_RUN')}**. "
                     f"{fuzz.get('reason') or 'Không có campaign chi tiết trong report.'}")
    lines.extend(("", "## 6. Phân loại CWE/CVE tổng hợp", ""))
    security_results = [item for item in results if _stage(item) in {"STATIC", "MEMORY", "FUZZING"}]
    cwe_ids, cve_ids = set(), set()
    for item in security_results:
        blob = json.dumps(item, ensure_ascii=False, default=str)
        cwe_ids.update(re.findall(r"\bCWE-\d+\b", blob, flags=re.IGNORECASE))
        cve_ids.update(re.findall(r"\bCVE-\d{4}-\d{4,}\b", blob, flags=re.IGNORECASE))
    cwe_ids.update(str(item.get("cwe", "")).upper() for item in finding_records if item.get("cwe"))
    cve_ids.update(value.upper() for item in finding_records for value in
                   re.findall(r"\bCVE-\d{4}-\d{4,}\b", json.dumps(item, default=str), re.I))
    lines.append("Nguyên nhân/ảnh hưởng được diễn giải từ finding và thông điệp analyzer; cần review source/đường đi thực tế trước khi kết luận mức độ khai thác được.")
    lines.append("**CWE ghi trực tiếp trong finding/evidence:** " +
                 (", ".join(f"`{x.upper()}`" for x in sorted(cwe_ids)) or "không có mã CWE được ghi nhận."))
    lines.append("")
    lines.append("**CVE:** " + (", ".join(f"`{x.upper()}`" for x in sorted(cve_ids)) if cve_ids else
                 "không có CVE được xác minh trong dữ liệu lần chạy. Công cụ không tự ánh xạ CWE thành CVE."))
    lines.extend(("", "| Analyzer / phạm vi | CWE | CVE | Mức độ xác minh |",
                  "|---|---|---|---|"))
    summary_findings = _summary_findings(security_results, finding_records)
    if summary_findings:
        for item in summary_findings:
            tool, scope, count, cwe, cve, confidence = item
            lines.append("| " + " | ".join(_cell(value) for value in (
                f"{tool} / {scope} / {count}", cwe, cve, confidence)) + " |")
    else:
        lines.append("| Không có finding gắn CWE/CVE | — | — | Chưa ghi nhận |")
    lines.append("\nCVE chỉ được liệt kê nếu lần chạy có gắn trực tiếp mã CVE vào bằng chứng. Ví dụ CVE trong tài liệu mẫu của thầy không được sao chép thành phát hiện của lần chạy này.")
    lines.extend(("", "## 7. Test case truy vết từ đặc tả", ""))
    tests = specification.get("tests", ())
    if tests:
        lines.extend(("| Test ID | Hàm | Loại | Yêu cầu | Mô tả |", "|---|---|---|---|---|"))
        for item in tests:
            lines.append("| " + " | ".join(_cell(value) for value in (
                item.get("id", "—"), item.get("function_id", "—"), item.get("kind", "—"),
                ", ".join(item.get("requirement_ids", ())), item.get("description", "—"))) + " |")
    else:
        lines.append("Đặc tả không khai báo test case tường minh.")
    if narrative_tests:
        lines.extend(("", "### Test case theo kịch bản của đặc tả", ""))
        for test in narrative_tests:
            linked = _results_for_test(test, results)
            lines.extend((f"#### {_cell(test.get('id', 'Test'))} — {_cell(test.get('title', ''))}",
                          f"Ưu tiên: {_cell(test.get('priority', '—'))} · Yêu cầu: {_cell(', '.join(test.get('requirement_ids', ())) or '—')}",
                          f"Kết quả mong đợi: {_cell(test.get('expected_result', '—'))}",
                          "Kết quả run: " + ("; ".join(f"{item.get('id')}:{item.get('status')}" for item in linked)
                                               or "Chưa có result ID liên kết trực tiếp.")))
            if test.get("preconditions"):
                lines.append("Điều kiện trước: " + _cell(_trim(test["preconditions"], 260)))
            if test.get("steps"):
                lines.append("Các bước: " + " → ".join(_cell(_trim(step, 110)) for step in test["steps"][:3]))
            lines.append("")
    lines.extend(("", "### Ma trận truy vết", ""))
    trace = data.get("traceability", {})
    if trace:
        for requirement, record in trace.items():
            if not isinstance(record, dict):
                lines.append(f"- **{_cell(requirement)} — LEGACY:** {_cell(record)}")
                continue
            targets = record.get("targets") or {"(tổng hợp)": record}
            target_statuses = sorted({str(target.get("status", record.get("status", "NOT_CHECKED")))
                                      for target in targets.values() if isinstance(target, dict)})
            target_names = list(targets)
            result_ids = list(dict.fromkeys(value for target in targets.values() if isinstance(target, dict)
                                            for value in target.get("results", ())))
            evidence_ids = list(dict.fromkeys(value for target in targets.values() if isinstance(target, dict)
                                              for value in target.get("evidence_ids", ())))
            target_summary = ", ".join(_trim(name, 32) for name in target_names[:3])
            if len(target_names) > 3:
                target_summary += " …"
            evidence_summary = _short_ids(evidence_ids[:3]) if evidence_ids else "—"
            if len(evidence_ids) > 3:
                evidence_summary += f" … (+{len(evidence_ids) - 3})"
            lines.append(f"- **{_cell(requirement)} — {', '.join(target_statuses) or record.get('status', 'NOT_CHECKED')}**: "
                         f"{len(target_names)} target(s) [{_cell(target_summary)}]; {len(result_ids)} result(s); "
                         f"evidence {_cell(evidence_summary)}.")
    else:
        lines.append("Report không có liên kết traceability cho lần chạy này.")
    lines.extend(("", "## Ph\u1ee5 l\u1ee5c \u2014 Th\u00f4ng tin l\u1ea7n ch\u1ea1y v\u00e0 gi\u1edbi h\u1ea1n", "",
                  "| M\u1ee5c | Gi\u00e1 tr\u1ecb |", "|---|---|",
                  f"| Run ID | `{_cell(data.get('run_id', '\u2014'))}` |",
                  f"| B\u1eaft \u0111\u1ea7u | {_cell(data.get('start_time', '\u2014'))} |",
                  f"| K\u1ebft th\u00fac | {_cell(data.get('end_time', '\u2014'))} |",
                  f"| Th\u1eddi l\u01b0\u1ee3ng | {data.get('duration_seconds', 0):.2f}s |",
                  f"| S\u1ed1 k\u1ebft qu\u1ea3 | {len(data.get('results', ()))} |",
                  f"| B\u1eb1ng ch\u1ee9ng | {data.get('evidence_manifest', {}).get('evidence_count', '\u2014')} |",
                  f"| K\u1ebft qu\u1ea3 theo tr\u1ea1ng th\u00e1i | {_cell(data.get('status_counts', {}))} |", ""))
    if data.get("limitations"):
        lines.extend(("### Giới hạn", "", *(f"- {item}" for item in data["limitations"]), ""))
    lines.extend(("---", "", f"Manifest: `{data.get('evidence_manifest', {}).get('path', '—')}`", ""))
    lines.append("Mã evidence và SHA-256 rút gọn trong bảng để dễ đọc; giá trị đầy đủ nằm trong manifest của lần chạy.")
    return "\n".join(lines)


def _append_result_table(lines: list[str], results: list[dict[str, Any]], headers: tuple[str, ...],
                         formula: bool = False) -> None:
    if not results:
        lines.append("Không có kết quả thuộc mục này trong lần chạy hiện tại.")
        return
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("|" + "|".join("---" for _ in headers) + "|")
    for item in results:
        metadata = item.get("metadata", {})
        if formula:
            values = (metadata.get("property_expression", item.get("property_id", "—")),
                      item.get("status", "—"), item.get("reason_code", "—"),
                      _short_ids(item.get("evidence_ids", ())))
        elif headers[0].startswith("Bộ kiểm tra"):
            counterexample = item.get("counterexample")
            detail = item.get("message", "—")
            if counterexample:
                detail = json.dumps(counterexample, ensure_ascii=False, default=str)
            values = (f"{item.get('technique', '—')} / {metadata.get('formula_text', item.get('property_id', '—'))}",
                      item.get("status", "—"), detail,
                      _short_ids(item.get("evidence_ids", ())))
        elif headers[0] == "Thuật toán":
            values = (item.get("technique", "—"), item.get("property_id", "—"), item.get("status", "—"),
                      item.get("reason_code", "—"), _short_ids(item.get("evidence_ids", ())))
        elif headers[0] == "Stage":
            values = (_stage(item), item.get("technique", "—"), item.get("scope", "—"), item.get("status", "—"),
                      item.get("reason_code", "—"), _short_ids(item.get("evidence_ids", ())))
        else:
            values = (item.get("technique", "—"), item.get("status", "—"), item.get("message", "—"),
                      _short_ids(item.get("evidence_ids", ())))
        lines.append("| " + " | ".join(_cell(value) for value in values) + " |")


def _stage(result: dict[str, Any]) -> str:
    technique = str(result.get("technique", "")).upper()
    if technique in {"CTL", "BMC", "SMT"}:
        return technique
    raw = str(result.get("stage", "")).upper()
    return {"STATIC_ANALYSIS": "STATIC", "SANITIZER": "MEMORY", "MEMORY_ANALYSIS": "MEMORY",
            "DYNAMIC_TEST": "DYNAMIC", "COVERAGE": "COVERAGE", "FUZZING": "FUZZING"}.get(raw, raw)


def _append_state_diagram(lines: list[str], specification: dict[str, Any]) -> None:
    states_by_id = {str(item.get("id")): item for item in specification.get("states", ())}
    transitions = list(specification.get("transitions", ()))
    for machine in specification.get("state_machines", ()):
        for item in machine.get("states", ()):
            states_by_id.setdefault(str(item.get("id")), item)
        transitions.extend(machine.get("transitions", ()))
    states = list(states_by_id.values())
    if not states:
        lines.append("Đặc tả không khai báo trạng thái; không thể dựng sơ đồ Kripke.")
        return
    identifiers = {str(item.get("id")): f"S{index}" for index, item in enumerate(states)}
    diagram = ["stateDiagram-v2"]
    initial = specification.get("initial_state")
    for item in states:
        state_id = str(item.get("id", ""))
        alias = identifiers[state_id]
        name = _mermaid_text(state_id)
        diagram.append(f'    state "{name}" as {alias}')
        if item.get("initial") or initial == state_id:
            diagram.append(f"    [*] --> {alias}")
    for item in transitions:
        source, target = str(item.get("source", "")), str(item.get("target", ""))
        if source not in identifiers or target not in identifiers:
            continue
        label = item.get("label") or item.get("guard") or item.get("id", "")
        diagram.append(f"    {identifiers[source]} --> {identifiers[target]} : {_mermaid_text(label)}")
    lines.extend(("```mermaid", *diagram, "```", ""))
    initial_ids = {str(state_id) for state_id in (initial if isinstance(initial, (list, tuple, set)) else (initial,)) if state_id}
    initial_ids.update(str(item.get("id")) for item in states if item.get("initial"))
    lines.extend(("| Trạng thái | Ban đầu | Nhãn / điều kiện quan sát |", "|---|---|---|"))
    for item in states:
        state_id = str(item.get("id", "—"))
        labels = item.get("labels", item.get("propositions", ()))
        lines.append("| " + " | ".join(_cell(value) for value in (
            state_id, "Có" if state_id in initial_ids else "Không",
            ", ".join(map(str, labels)) if isinstance(labels, (list, tuple, set)) else labels or "—")) + " |")
    lines.append("")
    lines.extend(("| Cạnh | Điều kiện / chuyển tiếp | Hành động |",
                  "|---|---|---|"))
    for item in transitions:
        lines.append("| " + " | ".join(_cell(value) for value in (
            f"{item.get('source', '—')} → {item.get('target', '—')} ({item.get('id', '—')})",
            _trim(item.get("guard", "—"), 100), _trim(item.get("action", "—"), 70))) + " |")
    lines.append("")


def _mermaid_text(value: Any) -> str:
    return str(value or "").replace('"', "'").replace("|", "/").replace("\n", " ").replace(":", "-")


def _cell(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, (list, tuple, set)):
        value = ", ".join(map(str, value))
    elif isinstance(value, dict):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")


def _short_ids(values: Any) -> str:
    if isinstance(values, str):
        values = [values]
    return ", ".join(str(value)[:10] for value in values if value and value != "—") or "—"


def _short_hash(value: Any) -> str:
    value = str(value or "—")
    return value[:12] if len(value) > 12 else value


def _trim(value: Any, limit: int) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def _evidence_reader(data: dict[str, Any]):
    """Return an evidence loader that confines and hash-checks files under this run."""
    workspace = data.get("metadata", {}).get("workspace")
    manifest_rel = data.get("evidence_manifest", {}).get("path")
    if not workspace or not manifest_rel:
        return lambda _evidence_id: None
    try:
        root = Path(workspace).resolve(strict=True)
        manifest_path = (root / manifest_rel).resolve(strict=True)
        if not manifest_path.is_relative_to(root):
            return lambda _evidence_id: None
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        index = {str(item.get("id")): item for item in manifest.get("evidence", ())}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return lambda _evidence_id: None

    def read(evidence_id: str):
        item = index.get(str(evidence_id))
        if not item or not item.get("path"):
            return None
        try:
            path = (root / item["path"]).resolve(strict=True)
            if not path.is_relative_to(root) or not path.is_file():
                return None
            payload = path.read_bytes()
            if len(payload) != item.get("size_bytes") or hashlib.sha256(payload).hexdigest() != item.get("hash"):
                return None
            return item.get("path", ""), payload
        except (OSError, ValueError):
            return None
    return read


def _evidence_json(reader, evidence_id: str) -> tuple[str, dict[str, Any]] | None:
    loaded = reader(evidence_id)
    if not loaded:
        return None
    path, payload = loaded
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return path, value if isinstance(value, dict) else {}


def _artifact_evidence_id(generated_file: dict[str, Any], evidence_by_id: dict[str, str], reader) -> str:
    digest = generated_file.get("sha256")
    for evidence_id in evidence_by_id:
        # Generated files are attached to the run manifest as hash-checked evidence.
        loaded = reader(evidence_id)
        if loaded and digest and hashlib.sha256(loaded[1]).hexdigest() == digest:
            return evidence_id
    return str(generated_file.get("evidence_id", ""))


def _static_findings(results: list[dict[str, Any]], reader) -> list[dict[str, Any]]:
    findings: dict[str, dict[str, Any]] = {}
    for result in results:
        for evidence_id in result.get("evidence_ids", ()):
            loaded = _evidence_json(reader, evidence_id)
            if not loaded or not loaded[0].endswith("-findings.json"):
                continue
            payload = loaded[1]
            records = payload.get("findings", ()) if isinstance(payload, dict) else ()
            if isinstance(records, list):
                for item in records:
                    if isinstance(item, dict):
                        key = str(item.get("id") or (result.get("technique"), item.get("file"), item.get("line"), item.get("message")))
                        findings[key] = {**item, "evidence_id": evidence_id}
    return list(findings.values())


def _static_finding_explanation(finding: dict[str, Any]) -> str:
    """Give a cautious CWE-level explanation without inventing source-specific causality."""
    cwe = str(finding.get("cwe") or "").upper()
    explanations = {
        "CWE-476": "Có thể dereference con trỏ null; có thể gây crash hoặc từ chối dịch vụ nếu đường đi này được thực thi.",
        "CWE-120": "Có thể ghi vượt bộ đệm không kiểm tra kích thước; có thể làm hỏng dữ liệu hoặc điều khiển luồng.",
        "CWE-787": "Có thể ghi ngoài vùng nhớ dự kiến; cần xác minh bounds và đường đi gọi.",
        "CWE-125": "Có thể đọc ngoài vùng nhớ; có thể gây crash hoặc lộ dữ liệu tùy ngữ cảnh.",
        "CWE-416": "Có thể dùng vùng nhớ sau khi giải phóng; hành vi không xác định và nguy cơ hỏng dữ liệu.",
        "CWE-415": "Có thể giải phóng cùng vùng nhớ nhiều lần; allocator có thể lỗi hoặc trạng thái heap bị hỏng.",
        "CWE-401": "Có thể không giải phóng tài nguyên đã cấp phát; lặp lại có thể làm cạn bộ nhớ.",
    }
    return explanations.get(cwe, "Review thông điệp, rule và source location của analyzer để xác định nguyên nhân/ảnh hưởng cụ thể.")


def _fuzz_failure_output(evidence_ids: Any, reader) -> str:
    """Return a short stderr excerpt tied to a fuzz finding's verified evidence."""
    if isinstance(evidence_ids, str):
        evidence_ids = (evidence_ids,)
    for evidence_id in evidence_ids or ():
        loaded = reader(str(evidence_id))
        if not loaded:
            continue
        path, payload = loaded
        if Path(str(path)).name.endswith("-stderr.txt"):
            excerpt = payload.decode("utf-8", errors="replace").strip()
            if excerpt:
                return _trim(excerpt, 500)
    return ""


def _fuzz_oracle_checks(campaign: dict[str, Any], reader) -> list[dict[str, Any]]:
    """Read the hashed campaign manifest to report the exact oracle scope."""
    for evidence_id in campaign.get("evidence_ids", ()):
        payload = _evidence_json(reader, str(evidence_id))
        if not payload:
            continue
        path, record = payload
        normalized_path = str(path).replace("\\", "/")
        if ("/fuzz-campaigns/" in normalized_path and record.get("requested_strategy")
                and isinstance(record.get("oracle"), dict)):
            checks = record["oracle"].get("checks", ())
            return [item for item in checks if isinstance(item, dict)]
    return []


def _summary_findings(results: list[dict[str, Any]], findings: list[dict[str, Any]]) -> list[tuple[str, ...]]:
    grouped: dict[tuple[str, str, str], int] = {}
    for item in findings:
        cwe = str(item.get("cwe") or "").upper()
        cves = sorted({value.upper() for value in re.findall(r"\bCVE-\d{4}-\d{4,}\b", json.dumps(item, default=str), re.I)})
        if not cwe and not cves:
            continue
        key = (str(item.get("tool", "—")), cwe or "—", ", ".join(cves) or "—")
        grouped[key] = grouped.get(key, 0) + 1
    for result in results:
        if result.get("technique") in {item.get("tool") for item in findings}:
            continue
        record = {"stage": result.get("stage"), "technique": result.get("technique"),
                  "reason_code": result.get("reason_code"), "message": result.get("message"),
                  "metadata": result.get("metadata", {})}
        blob = json.dumps(record, ensure_ascii=False, default=str)
        cwes = sorted({value.upper() for value in re.findall(r"\bCWE-\d+\b", blob, re.I)})
        cves = sorted({value.upper() for value in re.findall(r"\bCVE-\d{4}-\d{4,}\b", blob, re.I)})
        for cwe in cwes:
            key = (str(result.get("technique", "—")), cwe, ", ".join(cves) or "—")
            grouped[key] = grouped.get(key, 0) + 1
    return [(tool, "nhiều vị trí" if count > 1 else "theo evidence", f"{count} finding(s)", cwe, cve,
             "CWE do analyzer báo; cần review" if cwe != "—" and cve == "—" else
             "CVE có trong evidence" if cve != "—" else "Chưa xác minh")
            for (tool, cwe, cve), count in sorted(grouped.items())]


def _append_smt_table(lines: list[str], results: list[dict[str, Any]], reader) -> None:
    if not results:
        lines.append("Không có truy vấn SMT trong lần chạy này.")
        return
    lines.extend(("| Kiểm tra | Biểu thức | Solver / model SAT (giá trị khác 0) | Evidence |",
                  "|---|---|---|---|"))
    for item in results:
        metadata = item.get("metadata", {})
        formal_run = metadata.get("formal_run", {})
        inputs = formal_run.get("inputs", {})
        expression = metadata.get("property_expression") or inputs.get("property_expression") or item.get("property_id", "—")
        outcome = metadata.get("solver_outcome", "—")
        assignments: dict[str, Any] = {}
        if str(outcome).upper() == "SAT":
            for evidence_id in item.get("evidence_ids", ()):
                payload = _evidence_json(reader, evidence_id)
                if not payload or not ("model-" in payload[0] or "outcome-" in payload[0]):
                    continue
                model = payload[1].get("model", payload[1])
                records = model.get("assignments", ()) if isinstance(model, dict) else ()
                assignments = {str(value.get("variable")): value.get("value") for value in records
                               if isinstance(value, dict) and value.get("value") not in (0, False, None, "0")}
                if assignments:
                    break
        model_text = ", ".join(f"{key}={value}" for key, value in list(assignments.items())[:6]) or (
            "SAT nhưng model không được lưu/không trích được" if str(outcome).upper() == "SAT" else "—")
        if len(assignments) > 6:
            model_text += f" … (+{len(assignments) - 6} biến)"
        lines.append("| " + " | ".join(_cell(value) for value in (
            item.get("property_id", "—"), expression,
            f"{outcome} · {metadata.get('solver_reason') or item.get('status', '—')} · {model_text}",
            _short_ids(item.get("evidence_ids", ())))) + " |")


def _results_for_test(test: dict[str, Any], results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    test_id = str(test.get("id", ""))
    return [item for item in results if test_id and (
        item.get("property_id") == test_id or item.get("metadata", {}).get("test_case_id") == test_id
        or test_id in item.get("metadata", {}).get("test_case_ids", ())) ]


def _python_ast_metrics(source: str) -> list[dict[str, Any]]:
    """Collect a small, reproducible AST inventory without executing generated code."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    records: list[dict[str, Any]] = []

    def visit_scope(node: ast.AST, name: str, line: int) -> None:
        branches = loops = 0
        variables: set[str] = set()
        max_depth = 0

        def walk(current: ast.AST, depth: int) -> None:
            nonlocal branches, loops, max_depth
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) and current is not node:
                return
            max_depth = max(max_depth, depth)
            if isinstance(current, (ast.If, ast.IfExp, ast.Assert, ast.Match)):
                branches += 1
            if isinstance(current, (ast.For, ast.AsyncFor, ast.While)):
                loops += 1
            if isinstance(current, ast.BoolOp):
                branches += max(0, len(current.values) - 1)
            if isinstance(current, ast.Name) and isinstance(current.ctx, (ast.Store, ast.Param)):
                variables.add(current.id)
            child_depth = depth + 1 if isinstance(current, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.Match)) else depth
            for child in ast.iter_child_nodes(current):
                walk(child, child_depth)

        walk(node, 0)
        records.append({"name": name, "line": line, "variables": sorted(variables), "conditions": branches,
                        "loops": loops, "complexity": branches + loops + 1, "nesting": max_depth})

    def collect(node: ast.AST, prefix: str = "") -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit_scope(child, f"{prefix}{child.name}", child.lineno)
                collect(child, f"{prefix}{child.name}.")
            elif isinstance(child, ast.ClassDef):
                collect(child, f"{prefix}{child.name}.")
            else:
                collect(child, prefix)

    collect(tree)
    return records
