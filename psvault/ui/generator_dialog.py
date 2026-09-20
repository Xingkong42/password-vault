"""密码生成器对话框：随机强密码 / 易记短语 / 数字 PIN。"""

from __future__ import annotations

from PySide6.QtCore import QPoint, Qt, QTimer
from PySide6.QtWidgets import (
    QToolTip,
    QButtonGroup,
    QCheckBox,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from ..core import generator, strength
from . import clipboard as clipboard_utils
from . import icons, widgets
from .widgets import IconButton, StrengthMeter, text_button


class GeneratorDialog(QDialog):
    """密码生成器。

    用法：
        password = GeneratorDialog.get_password(parent)     # 返回选中的密码或 None
    """

    MODES = (("random", "随机密码"), ("phrase", "易记短语"), ("pin", "数字 PIN"))

    def __init__(self, parent: QWidget | None = None, initial_length: int = 18,
                 settings=None) -> None:
        super().__init__(parent)
        self.password = ""
        self._settings = settings          # 用于复制后的自动清空秒数
        self.setWindowTitle("密码生成器")
        self.setWindowIcon(icons.app_icon())
        self.setMinimumWidth(520)
        self.setModal(True)

        self._build_ui(initial_length)
        self._switch_mode("random")
        self._generate()

    # ------------------------------------------------------------ 界面

    def _build_ui(self, initial_length: int) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(22, 20, 22, 18)
        root.setSpacing(14)

        title = QLabel("密码生成器")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        # 结果展示卡
        result_card = QFrame()
        result_card.setObjectName("Hero")
        card_layout = QVBoxLayout(result_card)
        card_layout.setContentsMargins(18, 16, 14, 16)
        card_layout.setSpacing(12)

        top_row = QHBoxLayout()
        top_row.setSpacing(10)
        self.result_label = QLabel("")
        self.result_label.setObjectName("Mono")
        self.result_label.setWordWrap(True)
        self.result_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.result_label.setStyleSheet("font-size: 19px; font-weight: 600;")
        top_row.addWidget(self.result_label, 1)

        self.copy_button = IconButton("copy", "复制到剪贴板", box=32, size=17)
        self.copy_button.clicked.connect(self._copy)
        top_row.addWidget(self.copy_button, 0, Qt.AlignTop)

        self.refresh_button = IconButton("refresh", "重新生成 (Ctrl+R)", box=32, size=17)
        self.refresh_button.clicked.connect(self._generate)
        top_row.addWidget(self.refresh_button, 0, Qt.AlignTop)
        card_layout.addLayout(top_row)

        self.strength_meter = StrengthMeter()
        card_layout.addWidget(self.strength_meter)

        self.strength_label = QLabel("")
        self.strength_label.setObjectName("Faint")
        card_layout.addWidget(self.strength_label)
        root.addWidget(result_card)

        # 模式切换
        segment_bar = QFrame()
        segment_bar.setObjectName("SegmentBar")
        segment_layout = QHBoxLayout(segment_bar)
        segment_layout.setContentsMargins(4, 4, 4, 4)
        segment_layout.setSpacing(4)
        self.mode_group = QButtonGroup(self)
        for index, (key, label) in enumerate(self.MODES):
            button = QPushButton(label)
            button.setObjectName("Segment")
            button.setCheckable(True)
            button.setCursor(Qt.PointingHandCursor)
            button.setProperty("mode", key)
            self.mode_group.addButton(button, index)
            segment_layout.addWidget(button)
        self.mode_group.idClicked.connect(lambda i: self._switch_mode(self.MODES[i][0]))
        root.addWidget(segment_bar)

        # 参数区
        self.options_stack = QVBoxLayout()
        self.options_stack.setSpacing(12)
        self.random_panel = self._build_random_panel(initial_length)
        self.phrase_panel = self._build_phrase_panel()
        self.pin_panel = self._build_pin_panel()
        for panel in (self.random_panel, self.phrase_panel, self.pin_panel):
            self.options_stack.addWidget(panel)
        root.addLayout(self.options_stack)

        # 候选列表
        root.addWidget(widgets.section_title("候选密码（点击选用）"))
        self.candidates = QListWidget()
        self.candidates.setFixedHeight(112)
        self.candidates.itemClicked.connect(self._pick_candidate)
        root.addWidget(self.candidates)

        # 底部按钮
        root.addWidget(widgets.divider())
        bottom = QHBoxLayout()
        bottom.addStretch(1)
        cancel = text_button("取消")
        cancel.clicked.connect(self.reject)
        bottom.addWidget(cancel)
        use = text_button("使用此密码", kind="Primary", icon_name="check",
                          token="accent_text", size=16)
        use.clicked.connect(self._accept)
        bottom.addWidget(use)
        root.addLayout(bottom)

    def _slider_row(self, caption: str, minimum: int, maximum: int, value: int,
                    on_change) -> tuple[QWidget, QSlider, QLabel]:
        """构造"标题 + 滑块 + 数值"的一行。"""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        header = QHBoxLayout()
        label = QLabel(caption)
        label.setObjectName("FieldLabel")
        header.addWidget(label)
        header.addStretch(1)
        value_label = QLabel(str(value))
        value_label.setObjectName("Mono")
        header.addWidget(value_label)
        layout.addLayout(header)

        slider = QSlider(Qt.Horizontal)
        slider.setRange(minimum, maximum)
        slider.setValue(value)
        slider.valueChanged.connect(lambda v: (value_label.setText(str(v)), on_change()))
        layout.addWidget(slider)
        return container, slider, value_label

    def _build_random_panel(self, initial_length: int) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        row, self.length_slider, _ = self._slider_row("密码长度", 6, 64, initial_length,
                                                      self._on_option_changed)
        layout.addWidget(row)

        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(8)
        self.lower_check = QCheckBox("小写字母 a-z")
        self.upper_check = QCheckBox("大写字母 A-Z")
        self.digit_check = QCheckBox("数字 0-9")
        self.symbol_check = QCheckBox("符号 !@#$")
        for check in (self.lower_check, self.upper_check, self.digit_check, self.symbol_check):
            check.setChecked(True)
            check.stateChanged.connect(self._on_option_changed)
        grid.addWidget(self.lower_check, 0, 0)
        grid.addWidget(self.upper_check, 0, 1)
        grid.addWidget(self.digit_check, 1, 0)
        grid.addWidget(self.symbol_check, 1, 1)

        self.ambiguous_check = QCheckBox("排除易混淆字符（0 O 1 l I）")
        self.ambiguous_check.stateChanged.connect(self._on_option_changed)
        grid.addWidget(self.ambiguous_check, 2, 0, 1, 2)

        self.require_check = QCheckBox("保证每类字符至少出现一次")
        self.require_check.setChecked(True)
        self.require_check.stateChanged.connect(self._on_option_changed)
        grid.addWidget(self.require_check, 3, 0, 1, 2)
        layout.addLayout(grid)
        return panel

    def _build_phrase_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        row, self.words_slider, _ = self._slider_row("单词数量", 3, 8, 4, self._on_option_changed)
        layout.addWidget(row)

        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(8)
        self.capitalize_check = QCheckBox("每个单词首字母大写")
        self.capitalize_check.stateChanged.connect(self._on_option_changed)
        grid.addWidget(self.capitalize_check, 0, 0)
        self.append_number_check = QCheckBox("末尾追加两位数字")
        self.append_number_check.setChecked(True)
        self.append_number_check.stateChanged.connect(self._on_option_changed)
        grid.addWidget(self.append_number_check, 0, 1)
        layout.addLayout(grid)

        hint = QLabel("短语密码更易记忆，适合作为主密码；词与词之间用短横线连接")
        hint.setObjectName("Faint")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        return panel

    def _build_pin_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        row, self.pin_slider, _ = self._slider_row("PIN 位数", 4, 12, 6, self._on_option_changed)
        layout.addWidget(row)
        hint = QLabel("纯数字口令安全性有限，仅建议用于银行卡、门禁等场景")
        hint.setObjectName("Faint")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        return panel

    # ------------------------------------------------------------ 交互

    def _switch_mode(self, mode: str) -> None:
        self.mode = mode
        panels = {"random": self.random_panel, "phrase": self.phrase_panel, "pin": self.pin_panel}
        for key, panel in panels.items():
            panel.setVisible(key == mode)
        for index, (key, _) in enumerate(self.MODES):
            button = self.mode_group.button(index)
            button.setChecked(key == mode)
        self._generate()

    def _on_option_changed(self) -> None:
        self._generate()

    def _current_options(self) -> generator.GeneratorOptions:
        return generator.GeneratorOptions(
            length=self.length_slider.value(),
            use_lowercase=self.lower_check.isChecked(),
            use_uppercase=self.upper_check.isChecked(),
            use_digits=self.digit_check.isChecked(),
            use_symbols=self.symbol_check.isChecked(),
            exclude_ambiguous=self.ambiguous_check.isChecked(),
            require_each_type=self.require_check.isChecked(),
        )

    def _generate(self) -> None:
        """按当前模式生成候选并选中第一条。"""
        try:
            if self.mode == "random":
                options = self._current_options()
                candidates = generator.generate_batch(options, 6)
            elif self.mode == "phrase":
                candidates = [
                    generator.generate_passphrase(
                        words=self.words_slider.value(),
                        capitalize=self.capitalize_check.isChecked(),
                        add_number=self.append_number_check.isChecked(),
                    )
                    for _ in range(6)
                ]
            else:
                candidates = [generator.generate_pin(self.pin_slider.value()) for _ in range(6)]
        except generator.GeneratorError as exc:
            self.result_label.setText("请至少选择一种字符类型")
            self.strength_meter.set_state(0, "")
            self.strength_label.setText(str(exc))
            self.candidates.clear()
            return

        self.candidates.clear()
        for item in candidates:
            row = QListWidgetItem(item)
            row.setData(Qt.UserRole, item)
            self.candidates.addItem(row)
        self.candidates.setCurrentRow(0)
        self._set_result(candidates[0])

    def _set_result(self, password: str) -> None:
        self.password = password
        self.result_label.setText(password)
        report = strength.evaluate(password)
        self.strength_meter.set_state(report.score, report.label)
        detail = f"强度：{report.label}　·　约 {report.entropy_bits:.0f} 位熵　·　{len(password)} 个字符"
        if report.warnings:
            detail += "　·　" + "；".join(report.warnings[:2])
        self.strength_label.setText(detail)

    def _pick_candidate(self, item: QListWidgetItem) -> None:
        self._set_result(item.data(Qt.UserRole))

    def _copy(self) -> None:
        """复制生成的密码。

        走和主窗口一致的通道：声明"不记入剪贴板历史、不同步到云"，并按设置
        若干秒后自动清空——这里复制的可是马上要拿去用的真密码，
        不能因为它是"生成器"就绕过保护。
        """
        if not self.password:
            return
        clipboard_utils.put_text(self.password, sensitive=True)

        seconds = int(getattr(self._settings, "clipboard_clear_seconds", 0) or 0)
        if seconds > 0:
            expected = self.password
            QTimer.singleShot(seconds * 1000,
                              lambda: clipboard_utils.clear_if_unchanged(expected))
            tip = f"已复制，{seconds} 秒后自动清空剪贴板"
        else:
            tip = "已复制到剪贴板"
        QToolTip.showText(self.copy_button.mapToGlobal(QPoint(0, -30)), tip)

    def _accept(self) -> None:
        if not self.password:
            self._generate()
        self.accept()

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        if event.key() == Qt.Key_R and event.modifiers() & Qt.ControlModifier:
            self._generate()
            return
        super().keyPressEvent(event)

    # ------------------------------------------------------------ 静态入口

    @staticmethod
    def get_password(parent: QWidget | None = None, initial_length: int = 18,
                     settings=None) -> str | None:
        """弹出生成器，返回用户选定的密码；取消则返回 None。

        settings 传入后，对话框里的"复制"会按其中的剪贴板策略处理。
        """
        dialog = GeneratorDialog(parent, initial_length, settings)
        if dialog.exec() == QDialog.Accepted:
            return dialog.password
        return None
