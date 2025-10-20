import json
import os
import sys
import ctypes
import threading
import time
import socket
import struct
import select
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTreeWidget, QTreeWidgetItem, QAbstractItemView,
    QMessageBox, QFrame, QSizePolicy, QTextEdit, QDialog
)
from PyQt6.QtCore import Qt, pyqtSignal
import pydivert

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
        self.base_path = get_base_path()
        self.servers_file = os.path.join(self.base_path, "Servers.json")
        self.settings_file = os.path.join(self.base_path, "Settings.json")
        self.trans = {
            "en": {
                "window_title": "Stalcraft Server Blocker",
                "error": "Error",
                "file_not_found": "Servers.json not found in {}",
                "block": "▶ Block Servers",
                "unblock": "■ Unblock Servers",
                "check_ping": "Check Server Ping",
                "selected_servers": "Selected: {} servers",
                "blocking_active": "Blocking is active",
                "run_as_admin": "Run the program as administrator!",
                "select_server_block": "Select at least one server to block.",
                "info": "Information",
                "blocking_failed": "Failed to start blocking: {}",
                "select_server_ping": "Select at least one server to check ping.",
                "checking_ping": "Checking ping...",
                "ping_results_header": "Ping check results:<br><br>",
                "server": "Server {}:<br>",
                "avg_ping": "  Average ping: ",
                "min_ping": "  Minimum ping: ",
                "max_ping": "  Maximum ping: ",
                "loss": "  Packet loss: ",
                "ms": " ms",
                "percent": "{:.2f}%",
                "na": "N/A",
                "usage": "To check ping, select desired servers and click '<span style='color:#ffffff; font-weight:bold; background-color:#00CED1; padding:2px 4px; border-radius:3px;'>Check Server Ping</span>'.\nIf you <span style='color:#ffffff; font-weight:bold; background-color:#9932CC; padding:2px 4px; border-radius:3px;'>block</span> selected servers, the game will not connect to them.",
                "choose_language": "Please choose your preferred language:"
            },
            "ru": {
                "window_title": "Stalcraft Server Blocker",
                "error": "Ошибка",
                "file_not_found": "Файл Servers.json не найден в {}",
                "block": "▶ Заблокировать",
                "unblock": "■ Разблокировать",
                "check_ping": "Проверить пинг",
                "selected_servers": "Выбрано: {} серверов",
                "blocking_active": "Блокировка активна",
                "run_as_admin": "Запустите программу от имени администратора!",
                "select_server_block": "Выберите хотя бы один сервер для блокировки.",
                "info": "Информация",
                "blocking_failed": "Не удалось запустить блокировку: {}",
                "select_server_ping": "Выберите хотя бы один сервер для проверки пинга.",
                "checking_ping": "Проверка пинга...",
                "ping_results_header": "Результаты проверки пинга:<br><br>",
                "server": "Сервер {}:<br>",
                "avg_ping": "  Средний пинг: ",
                "min_ping": "  Минимальный пинг: ",
                "max_ping": "  Максимальный пинг: ",
                "loss": "  Потери: ",
                "ms": " мс",
                "percent": "{:.2f}%",
                "na": "N/A",
                "usage": "Чтобы проверить пинг, выберите нужные сервера и нажмите '<span style='color:#ffffff; font-weight:bold; background-color:#00CED1; padding:2px 4px; border-radius:3px;'>Проверить пинг</span>'.\nЕсли <span style='color:#ffffff; font-weight:bold; background-color:#9932CC; padding:2px 4px; border-radius:3px;'>заблокировать</span> выбранные сервера, игра не сможет к ним подключиться.",
                "choose_language": "Пожалуйста, выберите предпочитаемый язык:"
            }
        }
        self.selected = self.load_selected()
        self.current_region = self.load_region()
        self.language = self.load_language()
        if self.language is None:
            self.language = self.ask_language()
            self.save_settings()
        self.setWindowTitle(self.trans[self.language]["window_title"])
        self.setFixedSize(800, 600)
        try:
            with open(self.servers_file, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except FileNotFoundError:
            QMessageBox.critical(self, self.trans[self.language]["error"], self.trans[self.language]["file_not_found"].format(self.base_path))
            sys.exit(1)

        self.stop_flag = False
        self.blocking_thread = None
        self.selected_ips = set()
        self.initializing = False
        self.divert = None
        self.address_to_name = {}
        self.build_address_name_map()
        self.initUI()
        self.update_ping_results.connect(self.display_ping_results)

    def load_language(self):
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("language", "ru")
            except:
                return "ru"
        return None

    def save_settings(self):
        settings = {
            "language": self.language,
            "region": self.current_region,
            "selected_servers": self.selected
        }
        with open(self.settings_file, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2, ensure_ascii=False)

    def ask_language(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Choose Language / Выберите Язык")
        dialog.setStyleSheet("""
            QDialog {
                background-color: #000000;
                color: #ffffff;
            }
            QLabel {
                font-size: 14px;
                color: #e0e0e0;
                font-family: 'Arial';
                padding: 10px;
            }
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
        """)
        layout = QVBoxLayout()
        label = QLabel(self.trans["ru"]["choose_language"] + "\n" + self.trans["en"]["choose_language"])
        layout.addWidget(label)
        hbox = QHBoxLayout()
        btn_en = QPushButton("English")
        btn_ru = QPushButton("Русский")
        self.language_choice = "ru"
        def set_en():
            self.language_choice = "en"
            dialog.accept()
        def set_ru():
            self.language_choice = "ru"
            dialog.accept()
        btn_en.clicked.connect(set_en)
        btn_ru.clicked.connect(set_ru)
        hbox.addWidget(btn_en)
        hbox.addWidget(btn_ru)
        layout.addLayout(hbox)
        dialog.setLayout(layout)
        dialog.exec()
        return self.language_choice

    def build_address_name_map(self):
        def traverse_pools(pools):
            for pool in pools:
                if "tunnels" in pool:
                    for server in pool["tunnels"]:
                        if "address" in server and "name" in server:
                            self.address_to_name[server["address"]] = server["name"]
        traverse_pools(self.data["pools"])

    def load_selected(self):
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("selected_servers", [])
            except:
                return []
        return []

    def load_region(self):
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("region", "RU")
            except:
                return "RU"
        return "RU"

    def save_region(self):
        self.save_settings()

    def save_selected(self):
        self.save_settings()

    def initUI(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #000000;
                color: #ffffff;
            }
        """)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        region_layout = QHBoxLayout()
        region_layout.setSpacing(5)
        regions = ["EU", "NA", "RU", "SEA"]
        self.region_buttons = {}
        for region in regions:
            btn = QPushButton(region)
            btn.clicked.connect(lambda checked, r=region: self.set_region(r))
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #9932CC;
                    color: #ffffff;
                    font-weight: bold;
                    font-size: 12px;
                    padding: 5px 10px;
                    border-radius: 4px;
                    border: 1px solid #FF00FF;
                    font-family: 'Arial';
                }
                QPushButton:hover {
                    background-color: #8B008B;
                }
                QPushButton:pressed {
                    background-color: #7B2CBF;
                }
                QPushButton:checked {
                    background-color: #FF00FF;
                    color: #000000;
                }
            """)
            btn.setCheckable(True)
            if region == self.current_region:
                btn.setChecked(True)
            region_layout.addWidget(btn)
            self.region_buttons[region] = btn
        main_layout.addLayout(region_layout)
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

        content_layout = QHBoxLayout()
        content_layout.setSpacing(10)
        content_layout.addWidget(self.tree, 2)
        right_panel = QVBoxLayout()
        right_panel.setAlignment(Qt.AlignmentFlag.AlignTop)
        right_panel.setSpacing(10)
        content_layout.addLayout(right_panel, 1)
        main_layout.addLayout(content_layout)
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
        self.start_btn = QPushButton(self.trans[self.language]["block"])
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
        self.stop_btn = QPushButton(self.trans[self.language]["unblock"])
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
        self.ping_btn = QPushButton(self.trans[self.language]["check_ping"])
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
        self.status_label = QLabel(self.trans[self.language]["selected_servers"].format(len(self.selected)))
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
        self.ping_results.setFixedHeight(250)
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
        usage_label = QLabel(self.trans[self.language]["usage"])
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

    def set_region(self, region):
        for r, btn in self.region_buttons.items():
            btn.setChecked(r == region)
        self.current_region = region
        self.save_region()
        self.populate_tree()

    def populate_tree(self):
        self.tree.clear()
        def add_items(parent, data):
            for entry in data:
                if "address" in entry:
                    item = QTreeWidgetItem(parent, [entry["name"]])
                    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    item.setData(0, Qt.ItemDataRole.UserRole, {"type": "server", "address": entry["address"]})
                    item.setCheckState(0, Qt.CheckState.Checked if entry["address"] in self.selected else Qt.CheckState.Unchecked)
                else:
                    if entry.get("region") == self.current_region:
                        item = QTreeWidgetItem(parent, [entry["name"]])
                        item.setData(0, Qt.ItemDataRole.UserRole, {"type": "pool", "name": entry["name"]})
                        item.setCheckState(0, Qt.CheckState.Unchecked)
                        if "tunnels" in entry and entry["tunnels"]:
                            add_items(item, entry["tunnels"])
        add_items(self.tree.invisibleRootItem(), self.data["pools"])
        self.tree.expandAll()
        self.status_label.setText(self.trans[self.language]["selected_servers"].format(len(self.selected)))

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
        self.status_label.setText(self.trans[self.language]["selected_servers"].format(len(self.selected)))
        self.tree.blockSignals(False)
        self.update_selected_ips()
        if not self.selected and not self.stop_flag and self.blocking_thread and self.blocking_thread.is_alive():
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
            QMessageBox.warning(self, self.trans[self.language]["error"], self.trans[self.language]["run_as_admin"])
            return
        if not self.selected:
            QMessageBox.information(self, self.trans[self.language]["info"], self.trans[self.language]["select_server_block"])
            return
        self.update_selected_ips()
        self.stop_flag = False
        self.blocking_thread = threading.Thread(target=self.block_packets, daemon=True)
        self.blocking_thread.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.ping_btn.setEnabled(False)
        self.status_label.setText(self.trans[self.language]["blocking_active"])

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
        self.status_label.setText(self.trans[self.language]["selected_servers"].format(len(self.selected)))

    def block_packets(self):
        current_selected = set()
        while not self.stop_flag:
            if self.selected_ips != current_selected:
                if self.divert:
                    self.divert.close()
                    self.divert = None
                current_selected = self.selected_ips.copy()
                if not current_selected:
                    break
                ip_filters = " or ".join(f"ip.DstAddr == {ip}" for ip in current_selected)
                filter_str = f"outbound and ({ip_filters}) and (tcp.DstPort >= 29450 and tcp.DstPort <= 29460 or udp.DstPort >= 29450 and udp.DstPort <= 29460)"
                try:
                    self.divert = pydivert.WinDivert(filter_str)
                    self.divert.open()
                except Exception as e:
                    QMessageBox.critical(self, self.trans[self.language]["error"], self.trans[self.language]["blocking_failed"].format(e))
                    break
            try:
                packets = self.divert.recv(num=500, timeout=0.01)
                for packet in packets:
                    pass
            except Exception as e:
                if self.stop_flag:
                    break
                time.sleep(0.1)
                continue
            time.sleep(0.01)
        if self.divert:
            self.divert.close()
            self.divert = None

    def check_ping(self):
        if not self.selected:
            QMessageBox.information(self, self.trans[self.language]["info"], self.trans[self.language]["select_server_ping"])
            return

        self.ping_btn.setEnabled(False)
        self.ping_results.setHtml(f"<html><body>{self.trans[self.language]['checking_ping']}<br></body></html>")
        threading.Thread(target=self.run_ping_check, daemon=True).start()

    def calculate_checksum(self, data):
        if len(data) % 2:
            data += b'\x00'
        words = struct.unpack('!%dH' % (len(data) // 2), data)
        sum = 0
        for word in words:
            sum += word
        sum = (sum >> 16) + (sum & 0xFFFF)
        sum += sum >> 16
        return ~sum & 0xFFFF

    def ping(self, host, timeout=1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(timeout)
            icmp_type = 8
            icmp_code = 0
            icmp_checksum = 0
            icmp_id = os.getpid() & 0xFFFF
            icmp_seq = 1
            header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
            data = b'ping'
            checksum = self.calculate_checksum(header + data)
            header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
            packet = header + data
            start_time = time.time()
            sock.sendto(packet, (host, 0))
            recv_packet, addr = sock.recvfrom(1024)
            end_time = time.time()
            sock.close()
            return (end_time - start_time) * 1000
        except socket.timeout:
            return None
        except Exception:
            return None

    def run_ping_check(self):
        results = []
        total_pings = 20
        ping_delay = 0.1
        for addr in self.selected:
            ip, port_str = addr.split(":")
            pings = []
            loss_count = 0
            for _ in range(total_pings):
                response_time = self.ping(ip, timeout=1)
                if response_time is not None:
                    pings.append(response_time)
                else:
                    loss_count += 1
                time.sleep(ping_delay)
            loss_percentage = (loss_count / total_pings) * 100
            avg_ping = sum(pings) / len(pings) if pings else float('inf')
            min_ping = min(pings) if pings else float('inf')
            max_ping = max(pings) if pings else float('inf')
            server_name = self.address_to_name.get(addr, addr)
            results.append((server_name, avg_ping, min_ping, max_ping, loss_percentage))
        results.sort(key=lambda x: x[1])
        self.update_ping_results.emit(results)

    def get_ping_color(self, ping):
        if ping == float('inf'):
            return "#888888"
        if ping <= 30:
            return "#00FF00"
        elif ping >= 100:
            return "#FF0000"
        else:
            ratio = (ping - 30) / (100 - 30)
            r = int(255 * ratio)
            g = int(255 * (1 - ratio))
            return f"#{r:02x}{g:02x}00"

    def display_ping_results(self, results):
        text = "<html><body>" + self.trans[self.language]["ping_results_header"]
        for server_name, avg_ping, min_ping, max_ping, loss in results:
            color = self.get_ping_color(avg_ping)
            ping_str = f"{avg_ping:.2f}{self.trans[self.language]['ms']}" if avg_ping != float('inf') else self.trans[self.language]["na"]
            min_ping_str = f"{min_ping:.2f}{self.trans[self.language]['ms']}" if min_ping != float('inf') else self.trans[self.language]["na"]
            max_ping_str = f"{max_ping:.2f}{self.trans[self.language]['ms']}" if max_ping != float('inf') else self.trans[self.language]["na"]
            text += self.trans[self.language]["server"].format(server_name)
            text += self.trans[self.language]["avg_ping"] + f"<span style='color:{color};'>{ping_str}</span><br>"
            text += self.trans[self.language]["min_ping"] + f"{min_ping_str}<br>"
            text += self.trans[self.language]["max_ping"] + f"{max_ping_str}<br>"
            text += self.trans[self.language]["loss"] + self.trans[self.language]["percent"].format(loss) + "<br><br>"
        text += "</body></html>"
        self.ping_results.setHtml(text)
        self.ping_btn.setEnabled(True)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = ServerBlocker()
    window.show()
    sys.exit(app.exec())
