from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLabel, QPushButton, QPlainTextEdit, QVBoxLayout, QWidget
from seclab.gui.i18n import MESSAGE_LABELS, status_label


class SpecificationPage(QWidget):
    actionRequested = Signal(str)
    specificationChosen = Signal(str)

    @staticmethod
    def _vietnamese_preview(preview: str) -> str:
        """Translate display labels while preserving canonical JSON keys and values."""
        import json

        labels = {
            "schema_version": "Phiên bản schema", "id": "Mã định danh", "name": "Tên",
            "description": "Mô tả", "initial_state": "Trạng thái khởi đầu",
            "requirements": "Yêu cầu", "variables": "Biến", "constraints": "Ràng buộc",
            "states": "Trạng thái", "transitions": "Chuyển trạng thái",
            "properties": "Thuộc tính cần kiểm chứng", "functions": "Hàm",
            "tests": "Ca kiểm thử", "metadata": "Thông tin nguồn",
            "initial": "Khởi tạo", "labels": "Nhãn", "values": "Giá trị",
            "source": "Trạng thái nguồn", "target": "Trạng thái đích", "guard": "Điều kiện chuyển",
            "action": "Hành động", "label": "Nhãn chuyển", "bound": "Giới hạn bước",
            "function_id": "Mã hàm", "input": "Đầu vào", "expected": "Kết quả mong đợi",
            "machine_id": "Mã máy trạng thái",
            "domain": "Miền giá trị", "minimum": "Giá trị nhỏ nhất", "maximum": "Giá trị lớn nhất",
            "enum": "Tập giá trị", "expression": "Biểu thức", "requirement_ids": "Mã yêu cầu liên quan",
            "logic": "Logic", "formula": "Công thức", "language": "Ngôn ngữ", "file": "Tệp mã nguồn",
            "project": "Dự án", "state_machines": "Máy trạng thái", "coverage": "Độ bao phủ",
            "fuzzing": "Fuzzing", "property_ids": "Mã thuộc tính liên quan",
            "constraint_ids": "Mã ràng buộc liên quan", "function_ids": "Mã hàm liên quan",
            "test_ids": "Mã kiểm thử liên quan", "priority": "Mức ưu tiên", "type": "Loại",
            "kind": "Phân loại", "dinh_dang_nguon": "Định dạng nguồn",
            "cac_sheet_nguon": "Các sheet nguồn", "cac_cap_loai_tru": "Các cặp loại trừ lẫn nhau",
            "cac_kiem_tra_so_hoc": "Các kiểm tra số học", "ten": "Tên",
            "bien_so_nguyen": "Biến số nguyên", "dieu_kien": "Điều kiện",
            "bieu_thuc_tran": "Biểu thức tràn", "ghi_chu_nhap_xlsx": "Ghi chú nhập Excel",
            "nguon_goc": "Nguồn gốc", "tep_nguon": "Tệp nguồn",
            "ma_bam_sha256": "Mã băm SHA-256",
        }
        sheet_labels = {
            "ThongTin": "Thông tin", "YeuCauChucNang": "Yêu cầu chức năng",
            "YeuCauPhiChucNang": "Yêu cầu phi chức năng", "RangBuoc": "Ràng buộc",
            "MoHinhTrangThai": "Mô hình trạng thái", "ThuocTinhAnToan": "Thuộc tính an toàn",
            "LoaiTruLanNhau": "Loại trừ lẫn nhau", "HamSinhMa": "Hàm sinh mã",
            "KiemTraSoHoc": "Kiểm tra số học", "TestCase": "Ca kiểm thử",
        }
        display_sheet_names = {key: value for key, value in sheet_labels.items()}
        column_labels = {
            "ID": "Mã", "MoTa": "Mô tả", "DanhMuc": "Danh mục", "MucUuTien": "Mức ưu tiên",
            "TrangThai": "Trạng thái", "KhoiTao": "Khởi tạo", "Nhan": "Nhãn",
            "ChuyenDenCacTrangThai": "Chuyển tới trạng thái", "CongThucCTL": "Công thức CTL",
            "MenhDe1": "Mệnh đề 1", "MenhDe2": "Mệnh đề 2", "Ten": "Tên",
            "NgonNgu": "Ngôn ngữ", "Loai": "Loại", "ThamSo": "Tham số",
            "KichThuocBuffer": "Kích thước bộ đệm", "Loi": "Lỗi mô phỏng",
            "GiaTriBiMat1": "Giá trị thử nghiệm 1", "GiaTriBiMat2": "Giá trị thử nghiệm 2",
            "BienSoNguyen": "Biến số nguyên", "DieuKien": "Điều kiện",
            "BieuThucTran": "Biểu thức tràn", "YeuCauLienQuan": "Yêu cầu liên quan",
            "TieuDe": "Tiêu đề", "DieuKienTienQuyet": "Điều kiện tiên quyết",
            "CacBuoc": "Các bước", "KetQuaMongDoi": "Kết quả mong đợi",
            "Truong": "Trường", "GiaTri": "Giá trị",
        }
        display_values = {
            "bieu_mau_xlsx_giao_vien": "Biểu mẫu Excel của giáo viên",
            "safety": "an toàn", "liveness": "tính sống", "functional": "chức năng",
            "security": "bảo mật", "performance": "hiệu năng", "other": "khác",
            "LOW": "THẤP", "MEDIUM": "TRUNG BÌNH", "HIGH": "CAO", "CRITICAL": "NGHIÊM TRỌNG",
            "C": "C", "python": "Python", "buffer_copy": "chép bộ đệm",
            "alloc_release": "cấp phát và giải phóng", "divide": "phép chia",
            "magic_value": "giá trị bí mật", "buffer-overflow": "tràn bộ đệm",
            "memory-leak": "rò rỉ bộ nhớ", "double-free": "giải phóng hai lần",
            "use-after-free": "truy cập sau khi giải phóng",
        }

        def translate(value):
            if isinstance(value, dict):
                return {labels.get(str(key), str(key)): translate(child) for key, child in value.items()}
            if isinstance(value, list):
                return [translate(child) for child in value]
            return value

        def translate_source(value):
            if isinstance(value, dict):
                return {labels.get(str(key), column_labels.get(str(key), str(key))): translate_source(child)
                        for key, child in value.items()}
            if isinstance(value, list):
                return [translate_source(item) for item in value]
            return display_values.get(value, sheet_labels.get(value, value)) if isinstance(value, str) else value

        try:
            data = json.loads(preview)
            if isinstance(data, dict) and isinstance(data.get("sheets"), dict):
                sheets = data["sheets"]
                data = {"Các trang tính nguồn": {
                    display_sheet_names.get(str(sheet), str(sheet)): translate_source(rows)
                    for sheet, rows in sheets.items()}}
            return json.dumps(translate(translate_source(data)), ensure_ascii=False, indent=2)
        except (json.JSONDecodeError, TypeError):
            return preview
    def __init__(self, parent=None) -> None:
        super().__init__(parent); root=QVBoxLayout(self)
        title=QLabel("Đặc tả"); title.setObjectName("pageTitle"); root.addWidget(title)
        self.file_info=QLabel("Chưa chọn đặc tả"); root.addWidget(self.file_info)
        row=QHBoxLayout(); choose=QPushButton("Chọn tệp JSON / Excel…"); choose.clicked.connect(self._choose); row.addWidget(choose)
        for label,action in (("Tải","load"),("Xác thực","validate"),("Chuẩn hóa","normalize")):
            b=QPushButton(label); b.clicked.connect(lambda _=False,a=action:self.actionRequested.emit(a)); row.addWidget(b)
        root.addLayout(row); self.status=QLabel(f"Kiểm tra đặc tả: {status_label('NOT_CHECKED')}"); self.status.setToolTip(status_label("NOT_CHECKED")); root.addWidget(self.status)
        self.errors=QPlainTextEdit(); self.errors.setReadOnly(True); self.errors.setPlaceholderText("Lỗi và thông báo xác thực"); root.addWidget(self.errors)
        self.preview=QPlainTextEdit(); self.preview.setReadOnly(True); self.preview.setPlaceholderText("Bản xem trước đặc tả bằng tiếng Việt; các mã kỹ thuật được giữ nguyên"); root.addWidget(self.preview,1)
        self._workflow_buttons = tuple(row.itemAt(index).widget() for index in range(row.count())
                                       if row.itemAt(index).widget() is not None)
    def _choose(self) -> None:
        path,_=QFileDialog.getOpenFileName(self,"Chọn đặc tả", "", "Đặc tả (*.json *.xlsx);;JSON (*.json);;Excel XLSX (*.xlsx)")
        if path:self.specificationChosen.emit(path)
    def set_file(self,path:str, preview:str="") -> None:
        from pathlib import Path
        import json
        name = Path(path).name
        if Path(path).suffix.casefold() == ".xlsx":
            details = "Định dạng: Excel XLSX theo form giáo viên · Đã chuyển đổi trong bộ nhớ"
            self.file_info.setText(f"Tệp: {name}\nĐường dẫn: {path}\n{details}")
            self.preview.setPlainText(self._vietnamese_preview(preview))
            return
        try:
            data = json.loads(preview)
            details = f"Phiên bản schema: {data.get('schema_version', 'unknown')}   Mã dự án: {data.get('id', 'unknown')}   Tên: {data.get('name', 'unknown')}"
        except (json.JSONDecodeError, AttributeError):
            details = "Chưa đọc được phiên bản schema / thông tin dự án cho đến khi tải JSON"
        self.file_info.setText(f"Tệp: {name}\nĐường dẫn: {path}\n{details}")
        self.preview.setPlainText(preview)
    def set_validation(self,ok:bool,message:str) -> None:
        self.status.setText("Kiểm tra đặc tả: HỢP LỆ" if ok else "Kiểm tra đặc tả: KHÔNG THÀNH CÔNG")
        self.errors.setPlainText(message if ok else
            f"{MESSAGE_LABELS['invalid_specification']}\n\n{MESSAGE_LABELS['technical_detail']}:\n{message}")
    def show_report(self,_report) -> None:
        return None
    def clear_file(self) -> None:
        self.file_info.setText("Chưa chọn đặc tả")
        self.status.setText(f"Kiểm tra đặc tả: {status_label('NOT_CHECKED')}")
        self.errors.clear()
        self.preview.clear()

    def set_running(self, editable: bool) -> None:
        for widget in self.findChildren(QPushButton):
            widget.setEnabled(editable)

    def set_session_active(self, active: bool) -> None:
        for button in self._workflow_buttons:
            button.setEnabled(not active)
