#!/usr/bin/env python3

import sys
import os
import re
import binascii
from pathlib import Path
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QTextEdit, QPushButton, QMessageBox, QGridLayout
)
from PyQt5.QtGui import QClipboard
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def to_bytes_from_hex(hex_str: str) -> bytes:
    hex_str = hex_str.strip().replace('\n', '').replace(' ', '')
    if len(hex_str) == 0:
        return b""
    if len(hex_str) % 2 != 0:
        raise ValueError("Hex string length must be even")
    return binascii.unhexlify(hex_str)


class AESGui(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AES-256-GCM Crpter")
        self.resize(900, 700)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        central.setLayout(layout)

        grid = QGridLayout()
        layout.addLayout(grid)

        lbl_in = QLabel("Hex Input:")
        lbl_in.setFont(lbl_in.font())
        grid.addWidget(lbl_in, 0, 0)

        self.txt_input = QTextEdit()
        self.txt_input.setPlaceholderText("Enter hex data only (example: 4a6f686e...)\nSpaces/newlines will be removed.")
        self.txt_input.setFixedHeight(120)
        grid.addWidget(self.txt_input, 1, 0, 1, 3)

        btn_to_bytes = QPushButton("Convert Hex to Raw Bytes")
        btn_to_bytes.clicked.connect(self.convert_hex_to_bytes)
        grid.addWidget(btn_to_bytes, 2, 0)

        self.line_rawbytes = QTextEdit()
        self.line_rawbytes.setReadOnly(True)
        self.line_rawbytes.setPlaceholderText("Raw bytes preview (C++ style available below).")
        self.line_rawbytes.setFixedHeight(80)
        grid.addWidget(self.line_rawbytes, 2, 1, 1, 2)

        hbox = QHBoxLayout()
        layout.addLayout(hbox)

        btn_gen_key = QPushButton("Generate New Random Key")
        btn_gen_key.clicked.connect(self.generate_key)
        hbox.addWidget(btn_gen_key)

        btn_encrypt = QPushButton("Encrypt (AES-256-GCM)")
        btn_encrypt.clicked.connect(self.encrypt)
        hbox.addWidget(btn_encrypt)

        btn_copy_ct = QPushButton("Copy Ciphertext (C++ array)")
        btn_copy_ct.clicked.connect(lambda: self.copy_to_clipboard(self.cpp_ciphertext()))
        hbox.addWidget(btn_copy_ct)

        btn_copy_key = QPushButton("Copy Key (C++ array)")
        btn_copy_key.clicked.connect(lambda: self.copy_to_clipboard(self.cpp_key()))
        hbox.addWidget(btn_copy_key)

        btn_save_loader = QPushButton("Generate C++")
        btn_save_loader.clicked.connect(self.save_to_loader_cpp)
        hbox.addWidget(btn_save_loader)

        out_grid = QGridLayout()
        layout.addLayout(out_grid)

        out_grid.addWidget(QLabel("Key (C++ format):"), 0, 0)
        self.txt_key = QTextEdit()
        self.txt_key.setReadOnly(True)
        self.txt_key.setFixedHeight(80)
        out_grid.addWidget(self.txt_key, 0, 1)

        out_grid.addWidget(QLabel("Nonce/IV (C++ format):"), 1, 0)
        self.txt_nonce = QTextEdit()
        self.txt_nonce.setReadOnly(True)
        self.txt_nonce.setFixedHeight(80)
        out_grid.addWidget(self.txt_nonce, 1, 1)

        out_grid.addWidget(QLabel("Ciphertext (C++ format):"), 2, 0)
        self.txt_ciphertext = QTextEdit()
        self.txt_ciphertext.setReadOnly(True)
        self.txt_ciphertext.setFixedHeight(140)
        out_grid.addWidget(self.txt_ciphertext, 2, 1)

        out_grid.addWidget(QLabel("Tag (C++ format):"), 3, 0)
        self.txt_tag = QTextEdit()
        self.txt_tag.setReadOnly(True)
        self.txt_tag.setFixedHeight(80)
        out_grid.addWidget(self.txt_tag, 3, 1)

        self.lbl_status = QLabel("Ready — outputs are formatted as C++ byte arrays (e.g. 0x7f, 0x20, ...).")
        layout.addWidget(self.lbl_status)

        self._key = None
        self._nonce = None
        self._ciphertext = b''
        self._tag = b''

        self.apply_dark_style()
        self.generate_key()

    def apply_dark_style(self):
        ss = """
        QWidget { background-color: #1a0026; color: #e8d7ff; font-family: 'Segoe UI', Roboto, Sans-Serif; }
        QTextEdit { background-color: #2a0038; border: 1px solid #4b2a57; padding: 6px; }
        QPushButton { background-color: #42003a; border: 1px solid #6d2f66; padding: 8px; border-radius: 6px; }
        QPushButton:hover { background-color: #5a0a52; }
        QLabel { color: #f3e8ff; }
        QToolTip { color: #ffffff; background-color: #5b2b5e; border: 1px solid white; }
        """
        self.setStyleSheet(ss)

    def bytes_to_cpp_list(self, b: bytes, wrap: bool = True) -> str:
        if not b:
            return "{}"
        items = ', '.join(f"0x{c:02x}" for c in b)
        if wrap:
            return '{ ' + items + ' }'
        return items

    def cpp_array_declaration(self, name: str, b: bytes, type_name: str = 'unsigned char') -> str:
        arr = self.bytes_to_cpp_list(b, wrap=True)
        return f"{type_name} {name}[] = {arr};"

    def convert_hex_to_bytes(self):
        txt = self.txt_input.toPlainText()
        try:
            b = to_bytes_from_hex(txt)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to parse hex: {e}")
            self.lbl_status.setText("Error: Invalid hex input.")
            return
        self.line_rawbytes.setPlainText(self.bytes_to_cpp_list(b, wrap=False))
        self.lbl_status.setText(f"Hex converted to {len(b)} bytes.")

    def generate_key(self):
        self._key = get_random_bytes(32)
        self._nonce = get_random_bytes(12)
        self.txt_key.setPlainText(self.cpp_array_declaration('key', self._key))
        self.txt_nonce.setPlainText(self.cpp_array_declaration('nonce', self._nonce))
        self.lbl_status.setText("New key and nonce generated.")

    def encrypt(self):
        txt = self.txt_input.toPlainText()
        try:
            data = to_bytes_from_hex(txt)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to parse hex: {e}")
            self.lbl_status.setText("Error: Invalid hex input.")
            return
        if self._key is None or self._nonce is None:
            QMessageBox.warning(self, "Missing Key", "Please generate a key first.")
            return
        if len(self._key) != 32:
            QMessageBox.critical(self, "Key Error", "Key length must be 32 bytes (256 bits).")
            return
        try:
            cipher = AES.new(self._key, AES.MODE_GCM, nonce=self._nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data)
        except Exception as e:
            QMessageBox.critical(self, "Encryption Error", f"Encryption failed: {e}")
            return
        self._ciphertext = ciphertext
        self._tag = tag
        self.txt_ciphertext.setPlainText(self.cpp_array_declaration('ciphertext', ciphertext))
        self.txt_tag.setPlainText(self.cpp_array_declaration('tag', tag))
        self.lbl_status.setText(f"Encryption successful — ciphertext: {len(ciphertext)} bytes, tag: {len(tag)} bytes.")

    def cpp_key(self) -> str:
        return self.cpp_array_declaration('key', self._key)

    def cpp_ciphertext(self) -> str:
        return self.cpp_array_declaration('ciphertext', self._ciphertext)

    def copy_to_clipboard(self, txt: str):
        if not txt:
            QMessageBox.information(self, "Empty", "No data to copy.")
            return
        QApplication.clipboard().setText(txt, mode=QClipboard.Clipboard)
        self.lbl_status.setText("Copied to clipboard.")

    def save_to_loader_cpp(self):
        try:
            script_dir = Path(__file__).resolve().parent
        except Exception:
            script_dir = Path(os.getcwd())
        loader_path = script_dir / 'loader.cpp'

        key_decl = self.cpp_array_declaration('key', self._key) if self._key is not None else 'unsigned char key[] = { };'
        nonce_decl = self.cpp_array_declaration('nonce', self._nonce) if self._nonce is not None else 'unsigned char nonce[] = { };'
        ciphertext_decl = self.cpp_array_declaration('ciphertext', self._ciphertext) if self._ciphertext is not None else 'unsigned char ciphertext[] = { };'
        tag_decl = self.cpp_array_declaration('tag', self._tag) if self._tag is not None else 'unsigned char tag[] = { };'

        if not loader_path.exists():
            create = QMessageBox.question(self, "Create loader.cpp?",
                                          f"loader.cpp not found in {script_dir}. Create new file and write arrays?",
                                          QMessageBox.Yes | QMessageBox.No)
            if create != QMessageBox.Yes:
                self.lbl_status.setText("Save cancelled: loader.cpp not found.")
                return
            template = (
                "#include <cstddef>\n\n"
                f"{key_decl}\n\n"
                f"{nonce_decl}\n\n"
                f"{ciphertext_decl}\n\n"
                f"{tag_decl}\n"
            )
            try:
                loader_path.write_text(template, encoding='utf-8')
                self.lbl_status.setText(f"Created and wrote arrays to {loader_path}.")
                QMessageBox.information(self, "Saved", f"loader.cpp created and arrays written to:\n{loader_path}")
            except Exception as e:
                QMessageBox.critical(self, "Write Error", f"Failed to write loader.cpp: {e}")
            return

        try:
            content = loader_path.read_text(encoding='utf-8')
        except Exception as e:
            QMessageBox.critical(self, "Read Error", f"Failed to read loader.cpp: {e}")
            return

        def replace_or_append(pattern_name: str, new_decl: str, text: str) -> (str, bool):
            pattern = re.compile(rf"unsigned\s+char\s+{pattern_name}\s*\[\s*\]\s*=\s*\{{.*?\}}\s*;", re.DOTALL)
            if pattern.search(text):
                text, n = pattern.subn(new_decl, text)
                return text, True
            else:
                return text + "\n\n" + new_decl + "\n", False


        content, replaced_key = replace_or_append('key', key_decl, content)
        content, replaced_nonce = replace_or_append('nonce', nonce_decl, content)
        content, replaced_ct = replace_or_append('ciphertext', ciphertext_decl, content)
        content, replaced_tag = replace_or_append('tag', tag_decl, content)

        try:
            loader_path.write_text(content, encoding='utf-8')
        except Exception as e:
            QMessageBox.critical(self, "Write Error", f"Failed to update loader.cpp: {e}")
            return

        msg = "Updated loader.cpp and wrote arrays."
        details = []
        details.append(f"key: {'replaced' if replaced_key else 'appended'}")
        details.append(f"nonce: {'replaced' if replaced_nonce else 'appended'}")
        details.append(f"ciphertext: {'replaced' if replaced_ct else 'appended'}")
        details.append(f"tag: {'replaced' if replaced_tag else 'appended'}")
        self.lbl_status.setText(msg + ' ' + '; '.join(details))
        QMessageBox.information(self, "Saved", f"loader.cpp updated in:\n{loader_path}\n\n" + '\n'.join(details))


def main():
    app = QApplication(sys.argv)
    win = AESGui()
    win.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
