from __future__ import annotations

import json

from PySide6.QtWidgets import (QCheckBox, QComboBox, QDoubleSpinBox, QFormLayout, QLineEdit,
                               QSpinBox, QVBoxLayout, QWidget, QLabel, QPlainTextEdit)

from seclab.gui.controllers import GuiRunSettings, parse_tool_list
from seclab.fuzzing import FuzzInput


class SettingsPage(QWidget):
    """Generic PipelineOptions controls; contains no verification implementation."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.toolchain = QLineEdit()
        self.toolchain.setPlaceholderText("Tự nhận diện; hoặc nhập gcc, gcov, z3")
        self.analyzers = QLineEdit("compiler, cppcheck, clang-tidy, clang-static")
        self.memory = QCheckBox("Chạy phân tích bộ nhớ")
        self.memory.setChecked(True)
        self.coverage = QCheckBox("Đo độ bao phủ kiểm thử")
        self.coverage.setChecked(True)
        self.coverage_backend = QComboBox()
        for label, value in (("Tự chọn (auto)", "auto"), ("gcov", "gcov"), ("LLVM", "llvm")):
            self.coverage_backend.addItem(label, value)
        self.analysis_timeout = self._double(60.0)
        self.execution_timeout = self._double(5.0)
        self.build_timeout = self._double(60.0)
        self.fuzz_enabled = QCheckBox("Bật cấu hình Fuzzing")
        self.fuzz_enabled.setChecked(True)
        self.fuzz_strategy = QComboBox()
        for label, value in (("Hộp đen (BLACKBOX)", "BLACKBOX"), ("Đột biến (MUTATION)", "MUTATION"),
                             ("Dẫn hướng bằng độ bao phủ (COVERAGE_GUIDED)", "COVERAGE_GUIDED"),
                             ("Theo ngữ pháp (GRAMMAR)", "GRAMMAR")):
            self.fuzz_strategy.addItem(label, value)
        self.fuzz_iterations = self._integer(100, 1, 1_000_000)
        self.fuzz_timeout = self._double(2.0)
        self.fuzz_seed = self._integer(1, 0, 2_147_483_647)
        self.fuzz_input_size = self._integer(4096, 1, 10_000_000)
        self.fuzz_seeds = QPlainTextEdit()
        self.fuzz_seeds.setPlaceholderText('[{"id":"seed-1","data":{"value":0},"kind":"SCALARS"}]')
        self.fuzz_seeds.setMaximumHeight(90)
        self.fuzz_grammar = QPlainTextEdit()
        self.fuzz_grammar.setPlaceholderText('{"start":"<input>","rules":{"<input>":["{\\"value\\": <number>}"],"<number>":["0","1","-1"]}}')
        self.fuzz_grammar.setMaximumHeight(110)
        form = QFormLayout()
        form.addRow("Bộ công cụ (để trống = tự nhận diện)", self.toolchain)
        form.addRow("Analyzer tĩnh (phân tách bằng dấu phẩy)", self.analyzers)
        form.addRow("", self.memory)
        form.addRow("", self.coverage)
        form.addRow("Backend đo coverage", self.coverage_backend)
        form.addRow("Thời gian chờ phân tích (giây)", self.analysis_timeout)
        form.addRow("Thời gian chờ thực thi (giây)", self.execution_timeout)
        form.addRow("Thời gian chờ build (giây)", self.build_timeout)
        form.addRow("", self.fuzz_enabled)
        form.addRow("Chiến lược Fuzzing", self.fuzz_strategy)
        form.addRow("Số vòng Fuzzing", self.fuzz_iterations)
        form.addRow("Thời gian chờ mỗi input (giây)", self.fuzz_timeout)
        form.addRow("Seed ngẫu nhiên", self.fuzz_seed)
        form.addRow("Kích thước input tối đa", self.fuzz_input_size)
        form.addRow("Fuzz seed corpus (JSON)", self.fuzz_seeds)
        form.addRow("Ngữ pháp fuzzing (JSON)", self.fuzz_grammar)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Các giá trị này cấu hình pipeline hiện có. Tính sẵn có của công cụ và kết quả checker do backend cung cấp."))
        layout.addLayout(form)
        self.environment = QPlainTextEdit()
        self.environment.setReadOnly(True)
        self.environment.setPlaceholderText("Thông tin công cụ và môi trường sẽ xuất hiện tại đây sau khi chạy.")
        layout.addWidget(QLabel("Môi trường ở lần chạy gần nhất"))
        layout.addWidget(self.environment)
        layout.addStretch(1)

    @staticmethod
    def _double(value: float) -> QDoubleSpinBox:
        control = QDoubleSpinBox()
        control.setRange(0.01, 1_000_000.0)
        control.setDecimals(2)
        control.setValue(value)
        return control

    @staticmethod
    def _integer(value: int, minimum: int, maximum: int) -> QSpinBox:
        control = QSpinBox()
        control.setRange(minimum, maximum)
        control.setValue(value)
        return control

    def settings(self) -> GuiRunSettings:
        analyzers = tuple(item for item in parse_tool_list(self.analyzers.text()) or ())
        raw_seeds = self.fuzz_seeds.toPlainText().strip()
        seed_rows = json.loads(raw_seeds) if raw_seeds else []
        if not isinstance(seed_rows, list) or any(not isinstance(item, dict) for item in seed_rows):
            raise ValueError("Fuzz seed corpus must be a JSON array of seed objects")
        seeds = tuple(FuzzInput(**item) for item in seed_rows)
        raw_grammar = self.fuzz_grammar.toPlainText().strip()
        grammar = json.loads(raw_grammar) if raw_grammar else {"start": "<start>", "rules": {}}
        if not isinstance(grammar, dict) or not isinstance(grammar.get("rules", {}), dict):
            raise ValueError("Fuzz grammar must be a JSON object with a rules object")
        return GuiRunSettings(
            static_analyzers=analyzers, toolchain_tools=parse_tool_list(self.toolchain.text()),
            run_memory=self.memory.isChecked(), run_coverage=self.coverage.isChecked(),
            coverage_backend=self.coverage_backend.currentData(),
            analysis_timeout=self.analysis_timeout.value(), execution_timeout=self.execution_timeout.value(),
            build_timeout=self.build_timeout.value(), fuzz_enabled=self.fuzz_enabled.isChecked(),
            fuzz_strategy=self.fuzz_strategy.currentData(), fuzz_iterations=self.fuzz_iterations.value(),
            fuzz_timeout=self.fuzz_timeout.value(), fuzz_seed=self.fuzz_seed.value(),
            fuzz_max_input_size=self.fuzz_input_size.value(),
            fuzz_seeds=seeds,
            fuzz_grammar_start=grammar.get("start", "<start>"),
            fuzz_grammar_rules=grammar.get("rules", {}),
        )

    def set_environment(self, environment: dict) -> None:
        import json
        self.environment.setPlainText(json.dumps(environment, ensure_ascii=False, indent=2, default=str))

    def show_report(self, _report) -> None:
        return None
