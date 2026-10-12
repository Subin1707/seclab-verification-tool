from __future__ import annotations

from PySide6.QtWidgets import QTabWidget, QVBoxLayout, QWidget

from seclab.gui.widgets import ReadOnlyTable


class RequirementsPage(QWidget):
    """Read-only projection of normalized generic requirements and targets."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._specification = None
        self.tabs = QTabWidget(self)
        self.requirements = ReadOnlyTable(("ID", "Mô tả", "Loại", "Ưu tiên", "Thuộc tính", "Chức năng", "Kiểm thử"))
        self.properties = ReadOnlyTable(("ID", "Logic", "Công thức", "Yêu cầu", "Giới hạn bước"))
        self.tests = ReadOnlyTable(("ID", "Chức năng", "Loại", "Mô tả", "Yêu cầu", "Kết quả mong đợi"))
        self.functions = ReadOnlyTable(("ID", "Tên", "Tệp", "Yêu cầu", "Mô tả"))
        self.machines = ReadOnlyTable(("Máy trạng thái", "Trạng thái đầu", "Các trạng thái", "Chuyển trạng thái", "Mô tả"))
        self.tabs.addTab(self.requirements, "Yêu cầu")
        self.tabs.addTab(self.properties, "Thuộc tính cần kiểm chứng")
        self.tabs.addTab(self.tests, "Kiểm thử")
        self.tabs.addTab(self.functions, "Chức năng")
        self.tabs.addTab(self.machines, "Máy trạng thái")
        layout = QVBoxLayout(self)
        layout.addWidget(self.tabs)

    def set_specification(self, specification) -> None:
        self._specification = specification
        self.requirements.set_records(tuple((item.id, item.description, item.type or "", item.priority or "",
            ", ".join(item.property_ids), ", ".join(item.function_ids), ", ".join(item.test_ids))
            for item in specification.requirements))
        self.properties.set_records(tuple((item.id, item.logic, item.formula,
            ", ".join(item.requirement_ids), item.bound if item.bound is not None else "")
            for item in specification.properties))
        self.tests.set_records(tuple((item.id, item.function_id or "", item.kind or "", item.description or "",
            ", ".join(item.requirement_ids), item.expected) for item in specification.tests))
        self.functions.set_records(tuple((item.id, item.name, item.file or "",
            ", ".join(item.requirement_ids), item.description or "") for item in specification.functions))
        machine_rows = [(machine.id, machine.initial_state or "", ", ".join(state.id for state in machine.states),
                         ", ".join(f"{transition.source} → {transition.target}" for transition in machine.transitions),
                         machine.description or "") for machine in specification.state_machines]
        if not machine_rows and specification.states:
            machine_rows.append(("(root)", specification.initial_state or "", ", ".join(state.id for state in specification.states),
                                 ", ".join(f"{transition.source} → {transition.target}" for transition in specification.transitions), ""))
        self.machines.set_records(tuple(machine_rows))

    def clear(self) -> None:
        self._specification = None
        self.requirements.set_records(())
        self.properties.set_records(())
        self.tests.set_records(())
        self.functions.set_records(())
        self.machines.set_records(())

    def show_report(self, _report) -> None:
        # Specification content is populated by the explicit Normalize action.
        return None
