import json
import os
import sys
import ctypes
import threading
import time
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTreeWidget, QTreeWidgetItem, QAbstractItemView,
    QMessageBox, QFrame, QSizePolicy, QTextEdit
)
from PyQt6.QtCore import Qt, pyqtSignal
import pydivert
from ping3 import ping


try:
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
except:
    pass

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_base_path():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

class ServerBlocker(QMainWindow):
    update_ping_results = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Stalcraft Server Blocker")
        self.setFixedSize(800, 600)
        self.base_path = get_base_path()
        self.servers_file = os.path.join(self.base_path, "Servers.json")
        self.selected_file = os.path.join(self.base_path, "selected_servers.json")
        try:
            with open(self.servers_file, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except FileNotFoundError:
            QMessageBox.critical(self, "Ошибка", f"Файл Servers.json не найден в {self.base_path}")
            sys.exit(1)

        self.selected = self.load_selected()
        self.stop_flag = False
        self.blocking_thread = None
        self.selected_ips = set()
        self.initializing = False
        self.divert = None
        self.address_to_name = {}
        self.build_address_name_map()

        self.initUI()
        self.update_ping_results.connect(self.display_ping_results)

    def build_address_name_map(self):
        def traverse_pools(pools):
            for pool in pools:
                if "tunnels" in pool:
                    for server in pool["tunnels"]:
                        if "address" in server and "name" in server:
                            self.address_to_name[server["address"]] = server["name"]
        traverse_pools(self.data["pools"])

    def load_selected(self):
        if os.path.exists(self.selected_file):
            try:
                with open(self.selected_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except:
                return []
        return []

    def save_selected(self):
        with open(self.selected_file, "w", encoding="utf-8") as f:
            json.dump(self.selected, f, indent=2, ensure_ascii=False)

    def initUI(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #000000;
                color: #ffffff;
            }
        """)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)

        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.tree.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.tree.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.tree.setStyleSheet("""
            QTreeWidget {
                background-color: #0a0a0a;
                border: 2px solid #9932CC;
                border-radius: 5px;
                color: #e0e0e0;
                font-size: 14px;
                padding: 5px;
                font-family: 'Arial';
            }
            QTreeWidget::item {
                padding: 8px;
                border-bottom: 1px solid #1a1a1a;
                font-weight: bold;
                color: #e0e0e0;
            }
            QTreeWidget::item:hover {
                background-color: #1f1f1f;
                color: #FF00FF;
                border-left: 3px solid #9932CC;
            }
            QTreeWidget::item:checked {
                color: #FF00FF;
                background-color: #1a1a1a;
            }
            QTreeWidget::branch {
                background-color: #0a0a0a;
                color: #9932CC;
            }
            QTreeWidget::indicator {
                width: 20px;
                height: 20px;
                background-color: #1a1a1a;
                border: 2px solid #9932CC;
                border-radius: 4px;
            }
            QTreeWidget::indicator:checked {
                background-color: #FF00FF;
                border: 2px solid #FF00FF;
            }
            QTreeWidget::indicator:unchecked:hover {
                background-color: #2a2a2a;
            }
            QScrollBar:vertical {
                background-color: #0a0a0a;
                width: 12px;
                border: 1px solid #9932CC;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background-color: #9932CC;
                min-height: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #8B008B;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                background: none;
                border: none;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }
            QScrollBar::up-arrow:vertical, QScrollBar::down-arrow:vertical {
                background: none;
                border: none;
            }
        """)
        main_layout.addWidget(self.tree, 2)

        right_panel = QVBoxLayout()
        right_panel.setAlignment(Qt.AlignmentFlag.AlignTop)
        right_panel.setSpacing(10)
        main_layout.addLayout(right_panel, 1)

        title = QLabel("SBT")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("""
            font-weight: bold;
            font-size: 24px;
            color: #9932CC;
            margin-bottom: 10px;
            font-family: 'Arial';
        """)
        right_panel.addWidget(title)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        line.setStyleSheet("""
            border: 2px solid #9932CC;
            background-color: #9932CC;
            margin: 10px 0;
        """)
        right_panel.addWidget(line)

        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(5)

        self.start_btn = QPushButton("▶ Заблокировать")
        self.start_btn.clicked.connect(self.start_blocking)
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #9932CC;
                color: #ffffff;
                font-weight: bold;
                font-size: 14px;
                padding: 10px;
                border-radius: 6px;
                border: 2px solid #FF00FF;
                font-family: 'Arial';
            }
            QPushButton:hover {
                background-color: #8B008B;
            }
            QPushButton:pressed {
                background-color: #7B2CBF;
            }
            QPushButton:disabled {
                background-color: #333333;
                color: #666666;
                border-color: #333333;
            }
        """)
        buttons_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("■ Разблокировать")
        self.stop_btn.clicked.connect(self.stop_blocking)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF4444;
                color: #ffffff;
                font-weight: bold;
                font-size: 14px;
                padding: 10px;
                border-radius: 6px;
                border: 2px solid #FF0000;
                font-family: 'Arial';
            }
            QPushButton:hover {
                background-color: #CC0000;
            }
            QPushButton:pressed {
                background-color: #AA0000;
            }
            QPushButton:disabled {
                background-color: #333333;
                color: #666666;
                border-color: #333333;
            }
        """)
        buttons_layout.addWidget(self.stop_btn)

        self.ping_btn = QPushButton("Проверить пинг")
        self.ping_btn.clicked.connect(self.check_ping)
        self.ping_btn.setStyleSheet("""
            QPushButton {
                background-color: #00CED1;
                color: #ffffff;
                font-weight: bold;
                font-size: 14px;
                padding: 10px;
                border-radius: 6px;
                border: 2px solid #20B2AA;
                font-family: 'Arial';
            }
            QPushButton:hover {
                background-color: #00B7EB;
            }
            QPushButton:pressed {
                background-color: #009ACD;
            }
            QPushButton:disabled {
                background-color: #333333;
                color: #666666;
                border-color: #333333;
            }
        """)
        buttons_layout.addWidget(self.ping_btn)

        right_panel.addLayout(buttons_layout)

        line2 = QFrame()
        line2.setFrameShape(QFrame.Shape.HLine)
        line2.setFrameShadow(QFrame.Shadow.Sunken)
        line2.setStyleSheet("""
            border: 2px solid #9932CC;
            background-color: #9932CC;
            margin: 10px 0;
        """)
        right_panel.addWidget(line2)

        self.status_label = QLabel(f"Выбрано: {len(self.selected)} серверов")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("""
            font-size: 14px;
            color: #ffffff;
            margin-top: 10px;
            padding: 10px;
            background-color: #0a0a0a;
            border-radius: 5px;
            font-family: 'Arial';
        """)
        right_panel.addWidget(self.status_label)

        self.ping_results = QTextEdit()
        self.ping_results.setReadOnly(True)
        self.ping_results.setFixedHeight(150)
        self.ping_results.setStyleSheet("""
            QTextEdit {
                background-color: #0a0a0a;
                color: #e0e0e0;
                border: 2px solid #9932CC;
                border-radius: 5px;
                padding: 10px;
                font-size: 14px;
                font-family: 'Arial';
            }
        """)
        right_panel.addWidget(self.ping_results)

        usage_label = QLabel("Чтобы проверить пинг, выделите нужные сервера и нажмите '<span style='color:#ffffff; font-weight:bold; background-color:#00CED1; padding:2px 4px; border-radius:3px;'>Проверить пинг</span>'.\nЕсли <span style='color:#ffffff; font-weight:bold; background-color:#9932CC; padding:2px 4px; border-radius:3px;'>заблокировать</span> выделенные сервера, игра не сможет подключиться к ним.")
        usage_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        usage_label.setWordWrap(True)
        usage_label.setStyleSheet("""
            font-size: 14px;
            color: #cccccc;
            margin: 10px 0;
            padding: 10px;
            font-family: 'Arial';
        """)
        right_panel.addWidget(usage_label)

        right_panel.addStretch(1)

        credit_label = QLabel("by YungDaggerStab & WeedSellerBand")
        credit_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        credit_label.setStyleSheet("""
            font-size: 12px;
            color: #888888;
            font-family: 'Arial';
        """)
        right_panel.addWidget(credit_label)

        self.initializing = True
        self.populate_tree()
        self.initializing = False

        self.tree.itemChanged.connect(self.on_item_changed)

    def populate_tree(self):
        self.tree.clear()

        def add_items(parent, data):
            for entry in data:
                item = QTreeWidgetItem(parent, [entry["name"]])
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                if "address" in entry:
                    item.setData(0, Qt.ItemDataRole.UserRole, {"type": "server", "address": entry["address"]})
                    item.setCheckState(0, Qt.CheckState.Checked if entry["address"] in self.selected else Qt.CheckState.Unchecked)
                else:
                    item.setData(0, Qt.ItemDataRole.UserRole, {"type": "pool", "name": entry["name"]})
                    item.setCheckState(0, Qt.CheckState.Unchecked)
                    if "tunnels" in entry and entry["tunnels"]:
                        add_items(item, entry["tunnels"])

        add_items(self.tree.invisibleRootItem(), self.data["pools"])
        self.tree.expandAll()

    def on_item_changed(self, item, column):
        if self.initializing:
            return

        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data:
            return

        self.tree.blockSignals(True)

        if data["type"] == "pool":
            self.set_children_check_state(item, item.checkState(0))
        elif data["type"] == "server":
            address = data["address"]
            if item.checkState(0) == Qt.CheckState.Checked:
                if address not in self.selected:
                    self.selected.append(address)
            else:
                if address in self.selected:
                    self.selected.remove(address)

        self.update_parent_check_state(item)
        self.save_selected()
        self.status_label.setText(f"Выбрано: {len(self.selected)} серверов")

        self.tree.blockSignals(False)

        if not self.stop_flag and self.blocking_thread and self.blocking_thread.is_alive():
            self.update_selected_ips()
        elif not self.selected:
            self.stop_blocking()

    def set_children_check_state(self, item, state):
        for i in range(item.childCount()):
            child = item.child(i)
            child.setCheckState(0, state)
            data = child.data(0, Qt.ItemDataRole.UserRole)
            if data and data["type"] == "server":
                addr = data["address"]
                if state == Qt.CheckState.Checked:
                    if addr not in self.selected:
                        self.selected.append(addr)
                else:
                    if addr in self.selected:
                        self.selected.remove(addr)
            self.set_children_check_state(child, state)

    def update_parent_check_state(self, item):
        parent = item.parent()
        while parent:
            total = parent.childCount()
            checked = sum(parent.child(i).checkState(0) == Qt.CheckState.Checked for i in range(total))
            if checked == total:
                parent.setCheckState(0, Qt.CheckState.Checked)
            elif checked == 0:
                parent.setCheckState(0, Qt.CheckState.Unchecked)
            else:
                parent.setCheckState(0, Qt.CheckState.PartiallyChecked)
            parent = parent.parent()

    def update_selected_ips(self):
        self.selected_ips = {addr.split(":")[0] for addr in self.selected}

    def start_blocking(self):
        if not is_admin():
            QMessageBox.warning(self, "Ошибка", "Запусти программу от имени администратора!")
            return
        if not self.selected:
            QMessageBox.information(self, "Инфо", "Выбери хотя бы один сервер для блокировки.")
            return

        self.update_selected_ips()
        self.stop_flag = False
        self.blocking_thread = threading.Thread(target=self.block_packets, daemon=True)
        self.blocking_thread.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.ping_btn.setEnabled(False)
        self.status_label.setText("Блокировка активна")

    def stop_blocking(self):
        self.stop_flag = True
        if self.blocking_thread and self.blocking_thread.is_alive():
            self.blocking_thread.join(timeout=2)
        if self.divert:
            try:
                self.divert.close()
            except:
                pass
        self.divert = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.ping_btn.setEnabled(True)
        self.status_label.setText(f"Выбрано: {len(self.selected)} серверов")

    def block_packets(self):
        filter_str = "ip and (tcp.DstPort >= 29450 and tcp.DstPort <= 29460 or tcp.SrcPort >= 29450 and tcp.SrcPort <= 29460 or udp.DstPort >= 29450 and udp.DstPort <= 29460 or udp.SrcPort >= 29450 and udp.SrcPort <= 29460)"
        try:
            self.divert = pydivert.WinDivert(filter_str)
            self.divert.open()
            while not self.stop_flag:
                try:
                    packet = self.divert.recv()
                    dst_ip = str(packet.ipv4.dst_addr)
                    src_ip = str(packet.ipv4.src_addr)
                    drop = False

                    if packet.tcp:
                        dst_port = packet.tcp.dst_port
                        src_port = packet.tcp.src_port
                        if (29450 <= dst_port <= 29460 or 29450 <= src_port <= 29460) and (
                            dst_ip in self.selected_ips or src_ip in self.selected_ips
                        ):
                            drop = True
                    elif packet.udp:
                        dst_port = packet.udp.dst_port
                        src_port = packet.udp.src_port
                        if (29450 <= dst_port <= 29460 or 29450 <= src_port <= 29460) and (
                            dst_ip in self.selected_ips or src_ip in self.selected_ips
                        ):
                            drop = True

                    if not drop:
                        self.divert.send(packet)
                except Exception as e:
                    if self.stop_flag:
                        break
                    time.sleep(0.1)
                    continue
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось запустить блокировку: {e}")
        finally:
            if self.divert:
                self.divert.close()

    def check_ping(self):
        if not self.selected:
            QMessageBox.information(self, "Инфо", "Выбери хотя бы один сервер для проверки пинга.")
            return

        self.ping_btn.setEnabled(False)
        self.ping_results.setText("Проверка пинга...\n")
        threading.Thread(target=self.run_ping_check, daemon=True).start()

    def run_ping_check(self):
        results = []
        total_pings = 20
        ping_delay = 0.1
        for addr in self.selected:
            ip = addr.split(":")[0]
            pings = []
            loss_count = 0
            for _ in range(total_pings):
                try:
                    response_time = ping(ip, timeout=3)
                    if response_time is not None:
                        pings.append(response_time * 1000)
                    else:
                        loss_count += 1
                except (OSError, Exception):
                    loss_count += 1
                time.sleep(ping_delay)
            loss_percentage = (loss_count / total_pings) * 100
            avg_ping = sum(pings) / len(pings) if pings else "N/A"
            min_ping = min(pings) if pings else "N/A"
            max_ping = max(pings) if pings else "N/A"
            server_name = self.address_to_name.get(addr, addr)
            results.append((server_name, avg_ping, min_ping, max_ping, loss_percentage))

        self.update_ping_results.emit(results)

    def display_ping_results(self, results):
        text = "Результаты проверки пинга:\n\n"
        for server_name, avg_ping, min_ping, max_ping, loss in results:
            ping_str = f"{avg_ping:.2f} мс" if avg_ping != "N/A" else "N/A"
            min_ping_str = f"{min_ping:.2f} мс" if min_ping != "N/A" else "N/A"
            max_ping_str = f"{max_ping:.2f} мс" if max_ping != "N/A" else "N/A"
            text += f"Сервер {server_name}:\n"
            text += f"  Средний пинг: {ping_str}\n"
            text += f"  Минимальный пинг: {min_ping_str}\n"
            text += f"  Максимальный пинг: {max_ping_str}\n"
            text += f"  Потери: {loss:.2f}%\n\n"
        
        self.ping_results.setText(text)
        self.ping_btn.setEnabled(True)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = ServerBlocker()
    window.show()
    sys.exit(app.exec())