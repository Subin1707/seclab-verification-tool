from __future__ import annotations

import json
import math
from collections import defaultdict, deque

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen, QPolygonF
from PySide6.QtWidgets import (QFileDialog, QGraphicsPathItem,
    QGraphicsPolygonItem, QGraphicsScene, QGraphicsTextItem, QGraphicsView, QHBoxLayout, QFrame,
    QPushButton)

from .base import DataPage
from seclab.gui.i18n import stage_label, status_label


_PALETTE = {
    "canvas": QColor("#f5f7fb"),
    "initial": QColor("#eff6ff"),
    "normal": QColor("#ffffff"),
    "unreachable": QColor("#f8fafc"),
    "deadlock": QColor("#fff1f2"),
    "initial_border": QColor("#3b82f6"),
    "reachable_border": QColor("#10b981"),
    "unreachable_border": QColor("#94a3b8"),
    "deadlock_border": QColor("#f43f5e"),
    "edge": QColor("#94a3b8"),
    "text": QColor("#172033"),
    "muted": QColor("#64748b"),
    "group_fill": QColor("#eef2f7"),
    "group_border": QColor("#cbd5e1"),
}


class _GraphView(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.setBackgroundBrush(QColor("#ffffff"))

    def wheelEvent(self, event):
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.zoom(factor)

    def zoom(self, factor):
        current = self.transform().m11()
        target = max(0.25, min(2.5, current * factor))
        self.scale(target / current, target / current)


class ModelPage(DataPage):
    def __init__(self, parent=None):
        super().__init__("MÔ HÌNH KIỂM CHỨNG / KRIPKE", ("Loại", "ID", "Chi tiết"), parent)
        self.model_data = {}
        self.graph_scene = QGraphicsScene(self)
        self.graph_scene.setItemIndexMethod(QGraphicsScene.ItemIndexMethod.NoIndex)
        self.graph_view = _GraphView(self)
        self.graph_view.setScene(self.graph_scene)
        self.graph_view.setMinimumHeight(320)
        self.graph_view.setFrameShape(QFrame.Shape.NoFrame)
        self.graph_view.setBackgroundBrush(_PALETTE["canvas"])
        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.zoom_in_button = QPushButton("Phóng to +")
        self.zoom_out_button = QPushButton("Thu nhỏ −")
        self.fit_button = QPushButton("Vừa khung")
        self.reset_button = QPushButton("Về state đầu")
        self.export_button = QPushButton("Xuất mô hình")
        for button in (self.zoom_in_button, self.zoom_out_button, self.fit_button, self.reset_button, self.export_button):
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setStyleSheet(
                "QPushButton { background: #ffffff; color: #334155; border: 1px solid #cbd5e1; "
                "border-radius: 7px; padding: 7px 12px; font-weight: 600; }"
                "QPushButton:hover { background: #eff6ff; border-color: #93c5fd; color: #1d4ed8; }"
                "QPushButton:pressed { background: #dbeafe; }"
            )
            controls.addWidget(button)
        controls.addStretch(1)
        self.layout().addLayout(controls)
        self.layout().addWidget(self.graph_view, 1)
        self.fit_button.clicked.connect(self.fit_graph)
        self.reset_button.clicked.connect(self.reset_view)
        self.zoom_in_button.clicked.connect(lambda: self.graph_view.zoom(1.2))
        self.zoom_out_button.clicked.connect(lambda: self.graph_view.zoom(1 / 1.2))
        self.export_button.clicked.connect(self.export_model)

    def _show_model(self, model_data):
        self.model_data = model_data or {}
        self._draw_graph()
        self.fit_graph()

    def _draw_graph(self):
        self.graph_view.setUpdatesEnabled(False)
        try:
            self._populate_graph()
        finally:
            self.graph_view.setUpdatesEnabled(True)
            self.graph_view.viewport().update()

    def _populate_graph(self):
        data = self.model_data
        self.graph_scene.clear()
        states = list(data.get("states", ()))
        edges = list(data.get("transitions", ()))
        if not states:
            self._state_positions = {}
            self._state_heights = {}
            self.graph_scene.setSceneRect(QRectF(0, 0, 1, 1))
            return

        state_by_id = {item["id"]: item for item in states}
        ids = list(state_by_id)
        initial = set(data.get("initial_states", ()))
        initial.update(item["id"] for item in states if item.get("initial"))
        unreachable = set(data.get("unreachable_state_ids", ()))
        deadlocks = set(data.get("deadlock_state_ids", ()))

        # Layer states by shortest distance from an initial state. This keeps the
        # direction of execution visible while giving disconnected states their own column.
        adjacency = defaultdict(list)
        for edge in edges:
            source, target = edge.get("source"), edge.get("target")
            if source in state_by_id and target in state_by_id:
                adjacency[source].append(target)
        distance = {}
        queue = deque()
        for state_id in ids:
            if state_id in initial:
                distance[state_id] = 0
                queue.append(state_id)
        while queue:
            source = queue.popleft()
            for target in adjacency[source]:
                if target not in distance:
                    distance[target] = distance[source] + 1
                    queue.append(target)
        layers = defaultdict(list)
        for state_id in ids:
            if state_id in distance:
                layers[distance[state_id]].append(state_id)
        node_w = 220.0
        gap_x, gap_y = 112.0, 58.0
        text_width = node_w - 40.0
        node_heights = {}
        text_layouts = {}
        required_diameter = node_w
        for state_id in ids:
            state = state_by_id[state_id]
            title_text = state_id.replace("_", " ")
            state_details = sorted(state.get("labels", ())) or [
                f"{key}={value}" for key, value in sorted(state.get("values", {}).items())]
            detail_text = "\n".join(item.replace("_", " ") for item in state_details)
            title_measure = QGraphicsTextItem(title_text)
            title_font = QFont()
            title_font.setBold(True)
            title_font.setPointSize(11)
            title_measure.setFont(title_font)
            title_width = text_width
            title_measure.setTextWidth(title_width)
            title_height = title_measure.boundingRect().height()
            detail_height = 0.0
            detail_font = QFont()
            detail_font.setPointSize(9)
            if detail_text:
                detail_measure = QGraphicsTextItem(detail_text)
                detail_measure.setFont(detail_font)
                detail_measure.setTextWidth(text_width)
                detail_height = detail_measure.boundingRect().height()
            content_height = max(title_height, 20.0) + detail_height + (8.0 if detail_text else 0.0)
            required_diameter = max(required_diameter, content_height + 82.0)
            text_layouts[state_id] = (title_text, title_font, title_width, title_height, detail_text,
                                      detail_height, detail_font)
        node_w = required_diameter
        text_width = node_w - 40.0
        node_heights = {state_id: node_w for state_id in ids}
        positions = {}
        for column in sorted(layers):
            members = layers[column]
            y = 45.0
            for state_id in members:
                positions[state_id] = QPointF(48 + column * (node_w + gap_x), y)
                y += node_heights[state_id] + gap_y

        # Keep disconnected states in a compact grid. Collapsing all of them
        # into one BFS layer created a tall column and made fit-to-view unreadable.
        unreachable_ids = [state_id for state_id in ids if state_id not in distance]
        if unreachable_ids:
            main_height = max((sum(node_heights[state_id] + gap_y for state_id in members) - gap_y
                               for members in layers.values()), default=0.0)
            grid_top = 45 + main_height + 68
            grid_columns = min(4, max(1, len(unreachable_ids)))
            for index, state_id in enumerate(unreachable_ids):
                grid_row, grid_column = divmod(index, grid_columns)
                row_y = grid_top + sum(
                    max(node_heights[item] for item in unreachable_ids[row * grid_columns:
                        (row + 1) * grid_columns]) + gap_y
                    for row in range(grid_row))
                positions[state_id] = QPointF(48 + grid_column * (node_w + gap_x), row_y)
        self._state_positions = positions
        self._state_heights = node_heights

        if unreachable_ids:
            grid_columns = min(4, max(1, len(unreachable_ids)))
            row_heights = [max(node_heights[item] for item in unreachable_ids[row * grid_columns:
                (row + 1) * grid_columns]) for row in range((len(unreachable_ids) + grid_columns - 1) // grid_columns)]
            group_top = positions[unreachable_ids[0]].y() - 40.0
            group_height = sum(row_heights) + gap_y * max(0, len(row_heights) - 1) + 66.0
            group_width = grid_columns * node_w + max(0, grid_columns - 1) * gap_x + 36.0
            group_path = QPainterPath()
            group_path.addRoundedRect(QRectF(30.0, group_top, group_width, group_height), 18.0, 18.0)
            group = QGraphicsPathItem(group_path)
            group.setBrush(QBrush(_PALETTE["group_fill"]))
            group.setPen(QPen(_PALETTE["group_border"], 1.2, Qt.PenStyle.DashLine))
            group.setZValue(-3)
            self.graph_scene.addItem(group)
            group_title = self.graph_scene.addText(f"TRẠNG THÁI KHÔNG THỂ TỚI  |  {len(unreachable_ids)}")
            group_title_font = QFont()
            group_title_font.setBold(True)
            group_title_font.setPointSize(9)
            group_title.setFont(group_title_font)
            group_title.setDefaultTextColor(_PALETTE["muted"])
            group_title.setPos(48.0, group_top + 12.0)
            group_title.setZValue(-2)

        summary = self.graph_scene.addText(
            f"MÔ HÌNH TRẠNG THÁI  |  {len(states)} STATE  |  {len(edges)} CHUYỂN TRẠNG THÁI")
        summary_font = QFont()
        summary_font.setBold(True)
        summary_font.setPointSize(9)
        summary.setFont(summary_font)
        summary.setDefaultTextColor(_PALETTE["muted"])
        summary.setPos(48.0, 12.0)

        # Group parallel edges so their paths and labels remain individually legible.
        grouped = defaultdict(list)
        for edge in edges:
            source, target = edge.get("source"), edge.get("target")
            if source in positions and target in positions:
                grouped[(source, target)].append(edge)
        for (source, target), pair_edges in grouped.items():
            for index, edge in enumerate(pair_edges):
                self._draw_edge(positions[source], positions[target], node_w,
                                node_heights[source], node_heights[target],
                                edge, index, len(pair_edges),
                                source in deadlocks, target in deadlocks)

        for state_id in ids:
            state = state_by_id[state_id]
            x, y = positions[state_id].x(), positions[state_id].y()
            is_initial, is_deadlock = state_id in initial, state_id in deadlocks
            if is_deadlock:
                status, color, border = "BẾ TẮC", _PALETTE["deadlock"], _PALETTE["deadlock_border"]
            elif state_id in unreachable:
                status, color, border = "CHƯA TỚI", _PALETTE["unreachable"], _PALETTE["unreachable_border"]
            elif is_initial:
                status, color, border = "BAN ĐẦU", _PALETTE["initial"], _PALETTE["initial_border"]
            else:
                status, color, border = "TỚI ĐƯỢC", _PALETTE["normal"], _PALETTE["reachable_border"]
            node_h = node_heights[state_id]
            if is_deadlock:
                outer_path = QPainterPath()
                outer_path.addEllipse(QRectF(x - 8.0, y - 8.0, node_w + 16.0, node_h + 16.0))
                outer_ring = QGraphicsPathItem(outer_path)
                outer_ring.setBrush(QBrush(Qt.BrushStyle.NoBrush))
                outer_ring.setPen(QPen(border, 1.8))
                outer_ring.setZValue(0.5)
                outer_ring.setToolTip(f"{state_id} · trạng thái kết thúc (không có chuyển tiếp đi ra)")
                self.graph_scene.addItem(outer_ring)
            node_path = QPainterPath()
            node_path.addEllipse(QRectF(x, y, node_w, node_h))
            node = QGraphicsPathItem(node_path)
            node.setBrush(QBrush(color))
            node.setPen(QPen(border, 1.8))
            node.setZValue(1)
            labels = sorted(state.get("labels", ()))
            values = state.get("values", {})
            tooltip = [state_id]
            if labels:
                tooltip.append("Labels: " + ", ".join(labels))
            if values:
                tooltip.append("Values: " + ", ".join(f"{key}={value}" for key, value in sorted(values.items())))
            tooltip.extend(("Initial state" if is_initial else "Not initial",
                            "Deadlock" if is_deadlock else "Has outgoing transition"))
            node.setToolTip("\n".join(tooltip))
            self.graph_scene.addItem(node)

            (title_text, title_font, title_width, title_height, detail_text,
             detail_height, detail_font) = text_layouts[state_id]
            title = self.graph_scene.addText(title_text)
            title.setDefaultTextColor(_PALETTE["text"])
            title.setFont(title_font)
            title.setTextWidth(title_width)
            title_option = title.document().defaultTextOption()
            title_option.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            title.document().setDefaultTextOption(title_option)
            body_height = title_height + detail_height + (4.0 if detail_text else 0.0)
            body_y = max(50.0, (node_h + 18.0 - body_height) / 2.0)
            title.setPos(x + (node_w - title_width) / 2.0, y + body_y)
            title.setToolTip(node.toolTip())
            title.setZValue(2)
            chip_width = min(node_w - 36.0, max(70.0, len(status) * 6.4 + 20.0))
            chip_path = QPainterPath()
            chip_x = x + (node_w - chip_width) / 2.0
            chip_path.addRoundedRect(QRectF(chip_x, y + 22.0,
                                             chip_width, 20.0), 10.0, 10.0)
            chip = QGraphicsPathItem(chip_path)
            chip.setBrush(QBrush(border.lighter(175)))
            chip.setPen(QPen(border, 0.8))
            chip.setZValue(2)
            self.graph_scene.addItem(chip)
            chip_text = self.graph_scene.addText(status)
            chip_text.setDefaultTextColor(border.darker(135))
            chip_font = QFont()
            chip_font.setBold(True)
            chip_font.setPointSize(7)
            chip_text.setFont(chip_font)
            chip_text.setPos(chip_x + 8.0, y + 23.0)
            chip_text.setZValue(3)
            if detail_text:
                detail = self.graph_scene.addText(detail_text)
                detail.setDefaultTextColor(_PALETTE["muted"])
                detail.setFont(detail_font)
                detail.setTextWidth(text_width)
                detail_option = detail.document().defaultTextOption()
                detail_option.setAlignment(Qt.AlignmentFlag.AlignHCenter)
                detail.document().setDefaultTextOption(detail_option)
                detail.setPos(x + 20.0, title.y() + title.boundingRect().height() + 4.0)
                detail.setToolTip(node.toolTip())
                detail.setZValue(2)

        self.graph_scene.setSceneRect(self.graph_scene.itemsBoundingRect().adjusted(-35, -35, 35, 35))

    def _draw_edge(self, source_pos, target_pos, node_w, source_h, target_h, edge, index, count,
                   source_terminal=False, target_terminal=False):
        source = QPointF(source_pos.x() + node_w / 2, source_pos.y() + source_h / 2)
        target = QPointF(target_pos.x() + node_w / 2, target_pos.y() + target_h / 2)
        color = _PALETTE["edge"]
        pen = QPen(color, 1.5)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        path = QPainterPath()
        if source_pos == target_pos:
            offset = 16 + index * 12
            loop_y = source.y() - source_h / 2 - (9 if source_terminal else 2)
            path.moveTo(source.x() - 25, loop_y)
            path.cubicTo(source.x() - 45 - offset, loop_y - 46 - offset,
                         source.x() + 45 + offset, loop_y - 46 - offset,
                         source.x() + 25, loop_y)
            tip = path.pointAtPercent(1.0)
        else:
            dx, dy = target.x() - source.x(), target.y() - source.y()
            length = max(math.hypot(dx, dy), 1.0)
            ux, uy = dx / length, dy / length
            source_scale = min(node_w, source_h) / 2.0 + (8.0 if source_terminal else 0.0) - 2.0
            target_scale = min(node_w, target_h) / 2.0 + (8.0 if target_terminal else 0.0) - 2.0
            start = QPointF(source.x() + ux * source_scale, source.y() + uy * source_scale)
            end = QPointF(target.x() - ux * target_scale, target.y() - uy * target_scale)
            bend = (index - (count - 1) / 2) * 24
            control = QPointF((start.x() + end.x()) / 2 - uy * bend,
                              (start.y() + end.y()) / 2 + ux * bend)
            path.moveTo(start)
            path.quadTo(control, end)
            tip = end
        # Use the path's screen-coordinate tangent so loops and ordinary edges
        # get the same correctly oriented arrowhead.
        before_tip = path.pointAtPercent(0.99)
        tangent = math.degrees(math.atan2(tip.y() - before_tip.y(), tip.x() - before_tip.x()))
        line = QGraphicsPathItem(path)
        line.setPen(pen)
        line.setZValue(-2)
        self.graph_scene.addItem(line)

        # Qt angles run counterclockwise from the positive x axis.
        radians = math.radians(-tangent)
        back_x, back_y = math.cos(radians), -math.sin(radians)
        side_x, side_y = -back_y, back_x
        size = 10.0
        arrow = QPolygonF([tip,
            QPointF(tip.x() - back_x * size + side_x * size * 0.48,
                    tip.y() - back_y * size + side_y * size * 0.48),
            QPointF(tip.x() - back_x * size - side_x * size * 0.48,
                    tip.y() - back_y * size - side_y * size * 0.48)])
        arrow_item = QGraphicsPolygonItem(arrow)
        arrow_item.setBrush(QBrush(color))
        arrow_item.setPen(QPen(color, 1))
        arrow_item.setZValue(-1)
        self.graph_scene.addItem(arrow_item)

        details = [str(value) for value in (edge.get("label"), edge.get("guard"), edge.get("action")) if value]
        if details:
            label = self.graph_scene.addText(" · ".join(details))
            label.setDefaultTextColor(QColor("#334155"))
            label.setTextWidth(220)
            label.setZValue(2)
            if source_pos == target_pos:
                label.setPos(source.x() - 100, source.y() - source_h / 2 - 65 - index * 12)
            else:
                label.setPos(path.pointAtPercent(0.5) + QPointF(6, -label.boundingRect().height() - 3))
            label.setToolTip("\n".join(details))

    def fit_graph(self):
        if not self.graph_scene.items():
            return
        self.graph_view.fitInView(self.graph_scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def reset_view(self):
        self.graph_view.resetTransform()
        initial = next(iter(self.model_data.get("initial_states", ())), None)
        if initial not in self._state_positions:
            initial = next((item.get("id") for item in self.model_data.get("states", ()) if item.get("initial")), None)
        if initial in self._state_positions:
            position = self._state_positions[initial]
            self.graph_view.centerOn(position.x() + 125,
                                     position.y() + self._state_heights.get(initial, 88.0) / 2)
        elif self.graph_scene.items():
            self.graph_view.centerOn(self.graph_scene.sceneRect().center())

    def export_model(self):
        if not self.model_data:
            return
        path, selected = QFileDialog.getSaveFileName(self, "Xuất mô hình", "model.json",
            "JSON model (*.json);;Graphviz DOT (*.dot)")
        if not path:
            return
        if path.casefold().endswith(".dot") or "DOT" in selected:
            content = self.model_data.get("dot") or self._to_dot(self.model_data)
            if not path.casefold().endswith(".dot"):
                path += ".dot"
            with open(path, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(content)
        else:
            if not path.casefold().endswith(".json"):
                path += ".json"
            with open(path, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(self.model_data, stream, ensure_ascii=False, indent=2, sort_keys=True)

    @staticmethod
    def _to_dot(data):
        def quote(value):
            return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'
        lines = ["digraph Kripke {", "  rankdir=LR;", '  graph [overlap=false, splines=true, nodesep=0.55, ranksep=0.9];',
                 '  node [fontname="Segoe UI", style="filled", fillcolor="#f8fafc", color="#475569"];',
                 '  edge [fontname="Segoe UI", color="#64748b", fontsize=9];']
        initial = set(data.get("initial_states", ()))
        initial.update(item["id"] for item in data.get("states", ()) if item.get("initial"))
        for state in data.get("states", ()):
            label = state["id"] + ("\n" + ", ".join(sorted(state.get("labels", ()))) if state.get("labels") else "")
            shape = "doublecircle" if state["id"] in initial else "ellipse"
            fill = "#dbeafe" if state["id"] in initial else "#fee2e2" if state["id"] in set(data.get("deadlock_state_ids", ())) else "#f8fafc"
            lines.append(f"  {quote(state['id'])} [shape={shape}, fillcolor={quote(fill)}, label={quote(label)}];")
        for edge in data.get("transitions", ()):
            details = [str(value) for value in (edge.get("label"), edge.get("guard"), edge.get("action")) if value]
            suffix = f" [label={quote(' · '.join(details))}]" if details else ""
            lines.append(f"  {quote(edge['source'])} -> {quote(edge['target'])}{suffix};")
        lines.append("}")
        return "\n".join(lines)

    def show_report(self, report, model_data=None):
        if report is None:
            self._draw_graph()
            return super().show_report(report)
        stage = next((item for item in report.stage_summaries if item["stage_id"] == "MODEL"), None)
        if not stage or stage["status"] != "COMPLETED":
            output = model_data or self.model_data
            self._show_model(output)
            reason = stage.get("reason") if stage else None
            self.description.setText(
                f"{stage_label('MODEL')}: {status_label(stage['status'] if stage else 'NOT_STARTED')}"
                + (f" \u00b7 {reason}" if reason else ""))
            self.table.set_records(())
            return
        output = model_data or stage.get("output") or self.model_data
        if not output.get("states"):
            output = self.model_data
        self._show_model(output)
        states = output.get("states", ())
        transitions = output.get("transitions", ())
        rows = [("State", item["id"],
                 f"Nh\u00e3n={item.get('labels', [])}; tr\u1ea1ng th\u00e1i ban \u0111\u1ea7u={item.get('initial')}")
                for item in states]
        rows.extend(("Transition", item.get("id", index),
                     f"{item['source']} \u2192 {item['target']}; nh\u00e3n={item.get('label')}; action={item.get('action')}")
                    for index, item in enumerate(transitions))
        rows.extend(("Tr\u1ea1ng th\u00e1i ban \u0111\u1ea7u", state_id, "\u0110\u01b0\u1ee3c khai b\u00e1o trong \u0111\u1eb7c t\u1ea3")
                    for state_id in output.get("initial_states", ()))
        rows.extend(("C\u00f3 th\u1ec3 t\u1edbi \u0111\u01b0\u1ee3c", state_id, "C\u00f3 \u0111\u01b0\u1eddng \u0111i t\u1eeb tr\u1ea1ng th\u00e1i ban \u0111\u1ea7u")
                    for state_id in output.get("reachable_state_ids", ()))
        rows.extend(("Kh\u00f4ng th\u1ec3 t\u1edbi \u0111\u01b0\u1ee3c", state_id, "Kh\u00f4ng c\u00f3 \u0111\u01b0\u1eddng \u0111i t\u1eeb tr\u1ea1ng th\u00e1i ban \u0111\u1ea7u")
                    for state_id in output.get("unreachable_state_ids", ()))
        rows.extend(("B\u1ebf t\u1eafc", state_id, "Kh\u00f4ng c\u00f3 transition \u0111i ra")
                    for state_id in output.get("deadlock_state_ids", ()))
        stats = output.get("statistics", {})
        self.description.setText(
            f"{stage_label('MODEL')}: {status_label(stage['status'])} \u00b7 "
            f"Model ID: {output.get('model_id', output.get('model_hash', '\u2014'))} \u00b7 "
            f"State: {len(states)} \u00b7 Transition: {len(transitions)} \u00b7 "
            f"T\u1edbi \u0111\u01b0\u1ee3c: {stats.get('reachable_state_count', len(output.get('reachable_state_ids', ())))} \u00b7 "
            f"Kh\u00f4ng t\u1edbi \u0111\u01b0\u1ee3c: {stats.get('unreachable_state_count', len(output.get('unreachable_state_ids', ())))} \u00b7 "
            f"B\u1ebf t\u1eafc: {stats.get('deadlock_state_count', len(output.get('deadlock_state_ids', ())))} \u00b7 "
            "Reachability tính trên graph từ initial state; không phải line/branch coverage khi chạy mã nguồn.")
        self.table.set_records(rows)
        self.fit_graph()

    def show_specification_preview(self, model_data):
        model_data = model_data or {}
        self._show_model(model_data)
        states = model_data.get("states", ())
        transitions = model_data.get("transitions", ())
        rows = [("State", item["id"],
                 f"Nh\u00e3n={item.get('labels', [])}; tr\u1ea1ng th\u00e1i ban \u0111\u1ea7u={item.get('initial')}")
                for item in states]
        rows.extend(("Transition", item.get("id", index),
                     f"{item['source']} \u2192 {item['target']}; nh\u00e3n={item.get('label')}")
                    for index, item in enumerate(transitions))
        rows.extend(("Tr\u1ea1ng th\u00e1i ban \u0111\u1ea7u", state_id, "\u0110\u01b0\u1ee3c khai b\u00e1o trong \u0111\u1eb7c t\u1ea3")
                    for state_id in model_data.get("initial_states", ()))
        self.description.setText(
            f"B\u1ea3n xem tr\u01b0\u1edbc t\u1eeb Specification ({status_label(model_data.get('preview_status', 'PREVIEW'))}) \u00b7 "
            f"{len(states)} state \u00b7 {len(transitions)} transition \u00b7 "
            f"Tr\u1ea1ng th\u00e1i ban \u0111\u1ea7u: {model_data.get('initial_states', [])}\n"
            f"{model_data.get('reason', 'M\u00f4 h\u00ecnh \u0111\u01b0\u1ee3c t\u1ea1o tr\u1ef1c ti\u1ebfp t\u1eeb \u0111\u1eb7c t\u1ea3.')}")
        self.table.set_records(rows)
