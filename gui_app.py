"""Tkinter desktop GUI for AES file transfer workflows."""

from __future__ import annotations

import queue
import socket
import struct
import threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk

from cli_parsers import parse_hex_iv, parse_hex_key
from file_crypto import read_binary_file, write_binary_file
from modes import cbc_decrypt
from network_sender import send_file
from protocol import parse_header, recv_exact

_PREFIX_STRUCT = struct.Struct("!4sBH")
_SUFFIX_STRUCT = struct.Struct("!Q16sQ")

RECEIVER_HOST = "0.0.0.0"
RECEIVER_PORT = 9000
RECEIVER_OUTPUT_DIR = Path("received")


class AESGuiApp(tk.Tk):
    """Desktop app that provides sender and decrypt tools."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Python AES File Transfer")
        self.geometry("900x620")
        self.minsize(800, 560)

        self._receiver_thread: threading.Thread | None = None
        self._receiver_stop_event = threading.Event()
        self._log_queue: queue.Queue[str] = queue.Queue()

        self._send_file_var = tk.StringVar()
        self._send_key_var = tk.StringVar()
        self._send_iv_var = tk.StringVar()

        self._decrypt_file_var = tk.StringVar()
        self._decrypt_key_var = tk.StringVar()

        self._build_ui()
        self.after(120, self._drain_log_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        root_frame = ttk.Frame(self, padding=12)
        root_frame.pack(fill=tk.BOTH, expand=True)

        top_bar = ttk.Frame(root_frame)
        top_bar.pack(fill=tk.X)

        self.start_listening_button = ttk.Button(
            top_bar,
            text="Start Listening",
            command=self._on_start_listening,
        )
        self.start_listening_button.pack(side=tk.LEFT)

        self.listener_status_var = tk.StringVar(value="Receiver: stopped")
        status_label = ttk.Label(top_bar, textvariable=self.listener_status_var)
        status_label.pack(side=tk.LEFT, padx=(12, 0))

        notebook = ttk.Notebook(root_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(12, 8))

        send_tab = ttk.Frame(notebook, padding=12)
        decrypt_tab = ttk.Frame(notebook, padding=12)
        notebook.add(send_tab, text="Send")
        notebook.add(decrypt_tab, text="Decrypt")

        self._build_send_tab(send_tab)
        self._build_decrypt_tab(decrypt_tab)

        log_label = ttk.Label(root_frame, text="Status log")
        log_label.pack(anchor=tk.W)

        self.log_text = scrolledtext.ScrolledText(root_frame, height=10, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=False)

    def _build_send_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(1, weight=1)

        ttk.Label(parent, text="File").grid(row=0, column=0, sticky=tk.W, pady=6)
        ttk.Entry(parent, textvariable=self._send_file_var).grid(
            row=0,
            column=1,
            sticky=tk.EW,
            pady=6,
        )
        ttk.Button(parent, text="Browse", command=self._pick_send_file).grid(
            row=0,
            column=2,
            padx=(8, 0),
            pady=6,
        )

        ttk.Label(parent, text="Key hex (32 chars)").grid(row=1, column=0, sticky=tk.W, pady=6)
        ttk.Entry(parent, textvariable=self._send_key_var).grid(
            row=1,
            column=1,
            columnspan=2,
            sticky=tk.EW,
            pady=6,
        )

        ttk.Label(parent, text="IV hex (32 chars)").grid(row=2, column=0, sticky=tk.W, pady=6)
        ttk.Entry(parent, textvariable=self._send_iv_var).grid(
            row=2,
            column=1,
            columnspan=2,
            sticky=tk.EW,
            pady=6,
        )

        self.send_button = ttk.Button(parent, text="Encrypt & Send", command=self._on_encrypt_send)
        self.send_button.grid(row=3, column=0, columnspan=3, sticky=tk.W, pady=(12, 0))

    def _build_decrypt_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(1, weight=1)

        ttk.Label(parent, text="Received file (.enc)").grid(row=0, column=0, sticky=tk.W, pady=6)
        ttk.Entry(parent, textvariable=self._decrypt_file_var).grid(
            row=0,
            column=1,
            sticky=tk.EW,
            pady=6,
        )
        ttk.Button(parent, text="Browse", command=self._pick_decrypt_file).grid(
            row=0,
            column=2,
            padx=(8, 0),
            pady=6,
        )

        ttk.Label(parent, text="Key hex (32 chars)").grid(row=1, column=0, sticky=tk.W, pady=6)
        ttk.Entry(parent, textvariable=self._decrypt_key_var).grid(
            row=1,
            column=1,
            columnspan=2,
            sticky=tk.EW,
            pady=6,
        )

        ttk.Button(parent, text="Decrypt", command=self._on_decrypt).grid(
            row=2,
            column=0,
            columnspan=3,
            sticky=tk.W,
            pady=(12, 0),
        )

        hint = (
            "Decrypt expects files in IV+ciphertext format (.enc) created by receiver logics in this GUI."
        )
        ttk.Label(parent, text=hint, wraplength=720, foreground="#444").grid(
            row=3,
            column=0,
            columnspan=3,
            sticky=tk.W,
            pady=(10, 0),
        )

    def _pick_send_file(self) -> None:
        selected = filedialog.askopenfilename(title="Choose file to send")
        if selected:
            self._send_file_var.set(selected)

    def _pick_decrypt_file(self) -> None:
        selected = filedialog.askopenfilename(title="Choose file to decrypt")
        if selected:
            self._decrypt_file_var.set(selected)

    def _on_start_listening(self) -> None:
        if self._receiver_thread and self._receiver_thread.is_alive():
            messagebox.showinfo("Receiver", "Receiver is already listening.")
            return

        RECEIVER_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        self._receiver_stop_event.clear()
        self._receiver_thread = threading.Thread(target=self._receiver_loop, daemon=True)
        self._receiver_thread.start()
        self.listener_status_var.set(
            f"Receiver: listening on {RECEIVER_HOST}:{RECEIVER_PORT} -> {RECEIVER_OUTPUT_DIR}"
        )
        self._append_log(
            f"[receiver] Background listener started on {RECEIVER_HOST}:{RECEIVER_PORT}"
        )

    def _on_encrypt_send(self) -> None:
        try:
            input_path = self._validate_existing_file(self._send_file_var.get(), "Send file")
            key = parse_hex_key(self._send_key_var.get())
            iv = parse_hex_iv(self._send_iv_var.get())
        except Exception as error:
            messagebox.showerror("Validation error", str(error))
            return

        host = simpledialog.askstring(
            "Receiver IP",
            "Enter receiver IP or hostname:",
            initialvalue="127.0.0.1",
            parent=self,
        )
        if host is None:
            return
        host = host.strip()
        if not host:
            messagebox.showerror("Validation error", "Receiver IP/host must not be empty.")
            return

        port_raw = simpledialog.askstring(
            "Receiver Port",
            "Enter receiver port:",
            initialvalue="9000",
            parent=self,
        )
        if port_raw is None:
            return

        try:
            port = self._parse_port(port_raw)
        except ValueError as error:
            messagebox.showerror("Validation error", str(error))
            return

        self.send_button.configure(state=tk.DISABLED)
        self._append_log(f"[sender] Encrypting and sending '{input_path.name}' to {host}:{port}")

        def worker() -> None:
            try:
                send_file(host=host, port=port, input_path=str(input_path), key=key, iv=iv)
            except Exception as error:
                self.after(
                    0,
                    lambda: self._on_send_finished(
                        False,
                        f"Send failed: {error}",
                    ),
                )
                return

            self.after(
                0,
                lambda: self._on_send_finished(
                    True,
                    f"Send completed: {input_path.name} -> {host}:{port}",
                ),
            )

        threading.Thread(target=worker, daemon=True).start()

    def _on_send_finished(self, success: bool, message: str) -> None:
        self.send_button.configure(state=tk.NORMAL)
        self._append_log(f"[sender] {message}")
        if success:
            messagebox.showinfo("Send", message)
        else:
            messagebox.showerror("Send", message)

    def _on_decrypt(self) -> None:
        try:
            encrypted_path = self._validate_existing_file(
                self._decrypt_file_var.get(),
                "Decrypt file",
            )
            key = parse_hex_key(self._decrypt_key_var.get())
        except Exception as error:
            messagebox.showerror("Validation error", str(error))
            return

        try:
            data = read_binary_file(str(encrypted_path))
            if len(data) < 16:
                raise ValueError("Encrypted file is too short. Expected IV(16 bytes)+ciphertext.")

            iv = data[:16]
            ciphertext = data[16:]
            plaintext = cbc_decrypt(ciphertext=ciphertext, key=key, iv=iv)
            output_path = self._resolve_decrypt_output_path(encrypted_path)
            write_binary_file(str(output_path), plaintext)
        except Exception as error:
            messagebox.showerror("Decrypt", f"Decrypt failed: {error}")
            self._append_log(f"[decrypt] Failed for {encrypted_path}: {error}")
            return

        message = f"Decrypted file saved: {output_path}"
        self._append_log(f"[decrypt] {message}")
        messagebox.showinfo("Decrypt", message)

    def _resolve_decrypt_output_path(self, encrypted_path: Path) -> Path:
        if encrypted_path.suffix.lower() == ".enc":
            candidate = encrypted_path.with_suffix("")
            if not candidate.name:
                candidate = encrypted_path.with_name("decrypted_output")
            return candidate
        return encrypted_path.with_suffix(encrypted_path.suffix + ".dec")

    def _receiver_loop(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind((RECEIVER_HOST, RECEIVER_PORT))
                server_socket.listen(5)
                server_socket.settimeout(1.0)
                self._append_log(
                    f"[receiver] Listening on {RECEIVER_HOST}:{RECEIVER_PORT} ({RECEIVER_OUTPUT_DIR})"
                )

                while not self._receiver_stop_event.is_set():
                    try:
                        connection, client_address = server_socket.accept()
                    except socket.timeout:
                        continue

                    with connection:
                        connection.settimeout(10.0)
                        self._append_log(
                            f"[receiver] Incoming connection from {client_address[0]}:{client_address[1]}"
                        )
                        self._handle_client_packet(connection)
        except OSError as error:
            self._append_log(f"[receiver] Listener error: {error}")
            self.after(
                0,
                lambda: messagebox.showerror("Receiver", f"Failed to listen: {error}"),
            )
        finally:
            self.after(0, lambda: self.listener_status_var.set("Receiver: stopped"))

    def _handle_client_packet(self, connection: socket.socket) -> None:
        try:
            prefix = recv_exact(connection, _PREFIX_STRUCT.size)
            _magic, _version, filename_length = _PREFIX_STRUCT.unpack(prefix)
            file_name_bytes = recv_exact(connection, filename_length)
            suffix = recv_exact(connection, _SUFFIX_STRUCT.size)
            _file_size, iv, ciphertext_length = _SUFFIX_STRUCT.unpack(suffix)
            ciphertext = recv_exact(connection, ciphertext_length)

            packet = prefix + file_name_bytes + suffix + ciphertext
            header, ciphertext_offset, declared_ciphertext_length = parse_header(packet)
            packet_ciphertext = packet[
                ciphertext_offset : ciphertext_offset + declared_ciphertext_length
            ]

            encrypted_file_path = RECEIVER_OUTPUT_DIR / f"{header.file_name}.enc"
            write_binary_file(str(encrypted_file_path), iv + packet_ciphertext)
            self._append_log(f"[receiver] Saved encrypted: {encrypted_file_path}")

            key = self._try_parse_receiver_key()
            if key is None:
                self._append_log(
                    "[receiver] Skip auto-decrypt: set valid key in Decrypt tab (32 hex chars)."
                )
                return

            plaintext = cbc_decrypt(packet_ciphertext, key=key, iv=header.iv)
            output_file = RECEIVER_OUTPUT_DIR / header.file_name
            write_binary_file(str(output_file), plaintext)
            self._append_log(f"[receiver] Auto-decrypted and saved: {output_file}")
        except Exception as error:
            self._append_log(f"[receiver] Failed to process packet: {error}")

    def _try_parse_receiver_key(self) -> bytes | None:
        raw = self._decrypt_key_var.get().strip()
        if not raw:
            return None
        try:
            return parse_hex_key(raw)
        except Exception:
            return None

    def _validate_existing_file(self, raw_path: str, field_name: str) -> Path:
        normalized = raw_path.strip()
        if not normalized:
            raise ValueError(f"{field_name} is required.")
        path_obj = Path(normalized)
        if not path_obj.exists() or not path_obj.is_file():
            raise FileNotFoundError(f"{field_name} does not exist: {path_obj}")
        return path_obj

    def _parse_port(self, value: str) -> int:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Port is required.")
        try:
            parsed = int(stripped)
        except ValueError as error:
            raise ValueError("Port must be an integer in range 1..65535.") from error

        if parsed < 1 or parsed > 65535:
            raise ValueError("Port must be in range 1..65535.")
        return parsed

    def _append_log(self, message: str) -> None:
        self._log_queue.put(message)

    def _drain_log_queue(self) -> None:
        while not self._log_queue.empty():
            entry = self._log_queue.get_nowait()
            self.log_text.configure(state=tk.NORMAL)
            self.log_text.insert(tk.END, entry + "\n")
            self.log_text.see(tk.END)
            self.log_text.configure(state=tk.DISABLED)
        self.after(120, self._drain_log_queue)

    def _on_close(self) -> None:
        self._receiver_stop_event.set()
        self.destroy()


def main() -> int:
    """Run Tkinter application."""
    app = AESGuiApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())