import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import os
import threading
import queue

CHUNK_SIZE = 8 * 1024 * 1024  # đọc 8MB/lần, không tốn RAM với file nặng

ALGO_MAP = {"MD5": "md5", "SHA-1": "sha1", "SHA-256": "sha256", "SHA-512": "sha512"}
HASH_LEN_TO_ALGO = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}


class ChecksumTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Checksum Checker — MD5 / SHA-1 / SHA-256 / SHA-512")
        self.root.geometry("980x600")
        self.root.configure(bg="#f4f7f7")

        self.files = {}          # path -> {size, md5, sha1, sha256, sha512, status}
        self.queue = queue.Queue()
        self.worker_thread = None
        self.stop_flag = False

        self.algo_vars = {name: tk.BooleanVar(value=(name in ["MD5", "SHA-256"]))
                           for name in ALGO_MAP}

        self._build_ui()
        self.root.after(100, self._poll_queue)

    # ---------------- UI ----------------
    def _build_ui(self):
        title = tk.Label(self.root, text="Checksum Checker",
                          font=("Segoe UI", 16, "bold"), fg="#00615A", bg="#f4f7f7")
        title.pack(pady=(14, 0))
        tk.Label(self.root, text="Kiểm tra & xác minh mã băm hàng loạt cho file / thư mục",
                 font=("Segoe UI", 9), fg="#6b7d7a", bg="#f4f7f7").pack(pady=(0, 10))

        # Toolbar 1: thao tác file
        bar1 = tk.Frame(self.root, bg="#f4f7f7")
        bar1.pack(fill="x", padx=14)

        self._btn(bar1, "Thêm file...", self.add_files).pack(side="left", padx=3)
        self._btn(bar1, "Thêm thư mục...", self.add_folder).pack(side="left", padx=3)
        self._btn(bar1, "Xoá mục chọn", self.remove_selected).pack(side="left", padx=3)
        self._btn(bar1, "Xoá tất cả", self.clear_all).pack(side="left", padx=3)

        # Toolbar 2: thuật toán + tính toán
        bar2 = tk.Frame(self.root, bg="#f4f7f7")
        bar2.pack(fill="x", padx=14, pady=(8, 0))

        tk.Label(bar2, text="Thuật toán:", bg="#f4f7f7", font=("Segoe UI", 9)).pack(side="left")
        for name in ALGO_MAP:
            cb = tk.Checkbutton(bar2, text=name, variable=self.algo_vars[name],
                                 bg="#f4f7f7", font=("Segoe UI", 9))
            cb.pack(side="left", padx=4)

        self.compute_btn = self._btn(bar2, "Tính Checksum", self.start_compute,
                                      bg="#00857A", fg="white")
        self.compute_btn.pack(side="right", padx=3)

        # Toolbar 3: verify / save
        bar3 = tk.Frame(self.root, bg="#f4f7f7")
        bar3.pack(fill="x", padx=14, pady=(8, 8))

        self._btn(bar3, "Nạp file checksum để Verify...", self.load_and_verify).pack(side="left", padx=3)
        self._btn(bar3, "Lưu kết quả ra file...", self.save_results).pack(side="left", padx=3)

        # Treeview
        columns = ("size", "md5", "sha1", "sha256", "sha512", "status")
        self.tree = ttk.Treeview(self.root, columns=columns, show="tree headings", height=18)
        self.tree.heading("#0", text="File")
        self.tree.heading("size", text="Dung lượng")
        self.tree.heading("md5", text="MD5")
        self.tree.heading("sha1", text="SHA-1")
        self.tree.heading("sha256", text="SHA-256")
        self.tree.heading("sha512", text="SHA-512")
        self.tree.heading("status", text="Trạng thái")

        self.tree.column("#0", width=220)
        self.tree.column("size", width=80, anchor="e")
        self.tree.column("md5", width=110)
        self.tree.column("sha1", width=110)
        self.tree.column("sha256", width=110)
        self.tree.column("sha512", width=110)
        self.tree.column("status", width=90, anchor="center")

        vsb = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(14, 0), pady=(0, 10))
        vsb.pack(side="left", fill="y", padx=(0, 14), pady=(0, 10))

        self.tree.tag_configure("ok", foreground="#1f9d55")
        self.tree.tag_configure("failed", foreground="#d64545")
        self.tree.tag_configure("missing", foreground="#b58b00")

        # context menu
        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="Copy MD5", command=lambda: self.copy_field("md5"))
        self.menu.add_command(label="Copy SHA-1", command=lambda: self.copy_field("sha1"))
        self.menu.add_command(label="Copy SHA-256", command=lambda: self.copy_field("sha256"))
        self.menu.add_command(label="Copy SHA-512", command=lambda: self.copy_field("sha512"))
        self.menu.add_separator()
        self.menu.add_command(label="Xoá dòng này", command=self.remove_selected)
        self.tree.bind("<Button-3>", self._show_menu)

        # Status bar
        bottom = tk.Frame(self.root, bg="#f4f7f7")
        bottom.pack(fill="x", padx=14, pady=(0, 12))

        self.progress = ttk.Progressbar(bottom, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", side="left", expand=True, padx=(0, 10))

        self.status_label = tk.Label(bottom, text="Sẵn sàng", bg="#f4f7f7",
                                      font=("Segoe UI", 9), fg="#6b7d7a")
        self.status_label.pack(side="right")

    def _btn(self, parent, text, cmd, bg="#ffffff", fg="#00857A"):
        return tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg,
                          relief="solid" if bg == "#ffffff" else "flat",
                          bd=1, font=("Segoe UI", 9), padx=8, pady=4,
                          activebackground="#00615A" if bg != "#ffffff" else "#eafaf8")

    def _show_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.menu.post(event.x_root, event.y_root)

    # ---------------- Thao tác file ----------------
    def add_files(self):
        paths = filedialog.askopenfilenames(title="Chọn file cần kiểm tra")
        for p in paths:
            self._add_file(p)

    def add_folder(self):
        folder = filedialog.askdirectory(title="Chọn thư mục cần quét")
        if not folder:
            return
        for root_dir, _, filenames in os.walk(folder):
            for fn in filenames:
                self._add_file(os.path.join(root_dir, fn))

    def _add_file(self, path):
        if path in self.files:
            return
        try:
            size = os.path.getsize(path)
        except OSError:
            return
        self.files[path] = {"size": size, "md5": "", "sha1": "", "sha256": "", "sha512": "", "status": ""}
        self.tree.insert("", "end", iid=path, text=os.path.basename(path),
                          values=(self._fmt_size(size), "", "", "", "", ""))

    def remove_selected(self):
        for iid in self.tree.selection():
            self.tree.delete(iid)
            self.files.pop(iid, None)

    def clear_all(self):
        self.tree.delete(*self.tree.get_children())
        self.files.clear()

    def _fmt_size(self, size):
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def copy_field(self, field):
        sel = self.tree.selection()
        if not sel:
            return
        value = self.files[sel[0]].get(field, "")
        if value:
            self.root.clipboard_clear()
            self.root.clipboard_append(value)

    # ---------------- Tính toán (chạy nền) ----------------
    def start_compute(self):
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showinfo("Đang xử lý", "Vui lòng chờ tác vụ hiện tại hoàn tất.")
            return
        if not self.files:
            messagebox.showwarning("Trống", "Chưa có file nào trong danh sách.")
            return

        algos = [ALGO_MAP[name] for name, var in self.algo_vars.items() if var.get()]
        if not algos:
            messagebox.showwarning("Chưa chọn", "Vui lòng chọn ít nhất một thuật toán.")
            return

        self.compute_btn.config(state="disabled")
        self.worker_thread = threading.Thread(target=self._compute_worker, args=(algos,), daemon=True)
        self.worker_thread.start()

    def _compute_worker(self, algos):
        paths = list(self.files.keys())
        total = len(paths)

        for idx, path in enumerate(paths, 1):
            hashers = {a: hashlib.new(a) for a in algos}
            try:
                size = os.path.getsize(path)
                processed = 0
                with open(path, "rb") as f:
                    while True:
                        chunk = f.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        for h in hashers.values():
                            h.update(chunk)
                        processed += len(chunk)
                        file_pct = int((processed / size) * 100) if size else 100
                        self.queue.put(("file_progress", path, file_pct, idx, total))

                result = {a: h.hexdigest() for a, h in hashers.items()}
                self.queue.put(("done", path, result))
            except Exception as e:
                self.queue.put(("error", path, str(e)))

        self.queue.put(("all_done", None, None))

    def _poll_queue(self):
        try:
            while True:
                item = self.queue.get_nowait()
                self._handle_queue_item(item)
        except queue.Empty:
            pass

        self.root.after(100, self._poll_queue)

    def _handle_queue_item(self, item):
        kind = item[0]
        if kind == "file_progress":
            _, path, file_pct, idx, total = item
            overall = int(((idx - 1) / total) * 100 + file_pct / total)
            self.progress["value"] = overall
            self.status_label.config(text=f"Đang xử lý {idx}/{total}: {os.path.basename(path)} ({file_pct}%)")
        elif kind == "done":
            _, path, result = item
            self.files[path].update(result)
            self.tree.item(path, values=(
                self._fmt_size(self.files[path]["size"]),
                result.get("md5", ""), result.get("sha1", ""),
                result.get("sha256", ""), result.get("sha512", ""), ""
            ))
        elif kind == "error":
            _, path, msg = item
            self.tree.item(path, tags=("failed",))
            self.status_label.config(text=f"Lỗi: {os.path.basename(path)} — {msg}")
        elif kind == "all_done":
            self.compute_btn.config(state="normal")
            self.progress["value"] = 100
            self.status_label.config(text="Hoàn tất tính checksum.")
        elif kind == "verify_add":
            _, path, size = item
            self.files[path] = {"size": size, "md5": "", "sha1": "", "sha256": "", "sha512": "", "status": ""}
            if not self.tree.exists(path):
                self.tree.insert("", "end", iid=path, text=os.path.basename(path),
                                  values=(self._fmt_size(size), "", "", "", "", ""))
        elif kind == "verify_result":
            _, path, (algo, actual_hash, status) = item
            self.files[path][algo] = actual_hash
            self.files[path]["status"] = status
            vals = list(self.tree.item(path, "values"))
            col_idx = {"md5": 1, "sha1": 2, "sha256": 3, "sha512": 4}[algo]
            vals[col_idx] = actual_hash
            vals[5] = "OK" if status == "ok" else "FAILED"
            self.tree.item(path, values=vals, tags=(status,))
        elif kind == "verify_missing":
            _, path, filename = item
            self.status_label.config(text=f"Không tìm thấy file: {filename}")
        elif kind == "verify_error":
            _, path, msg = item
            self.status_label.config(text=f"Lỗi verify {os.path.basename(path)}: {msg}")
        elif kind == "verify_progress":
            _, _, pct = item
            self.progress["value"] = pct
            self.status_label.config(text=f"Đang verify... {pct}%")

    # ---------------- Verify từ file checksum có sẵn ----------------
    def load_and_verify(self):
        checksum_path = filedialog.askopenfilename(
            title="Chọn file checksum (.md5, .sha1, .sha256, .sha512, .txt)",
            filetypes=[("Checksum files", "*.md5 *.sha1 *.sha256 *.sha512 *.txt"), ("All files", "*.*")]
        )
        if not checksum_path:
            return

        base_dir = os.path.dirname(checksum_path)
        entries = []  # (expected_hash, algo, filename)

        try:
            with open(checksum_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith(";"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) != 2:
                        continue
                    hash_val, filename = parts[0].strip(), parts[1].strip().lstrip("*")
                    algo = HASH_LEN_TO_ALGO.get(len(hash_val))
                    if algo:
                        entries.append((hash_val.lower(), algo, filename))
        except Exception as e:
            messagebox.showerror("Lỗi đọc file", str(e))
            return

        if not entries:
            messagebox.showwarning("Không nhận diện được",
                                    "Không tìm thấy dòng checksum hợp lệ trong file này.\n"
                                    "Định dạng cần: <hash>  <tên file>")
            return

        self.compute_btn.config(state="disabled")
        threading.Thread(target=self._verify_worker, args=(entries, base_dir), daemon=True).start()

    def _verify_worker(self, entries, base_dir):
        total = len(entries)
        for idx, (expected_hash, algo, filename) in enumerate(entries, 1):
            full_path = filename if os.path.isabs(filename) else os.path.join(base_dir, filename)

            if not os.path.isfile(full_path):
                self.queue.put(("verify_missing", full_path, filename))
                continue

            if full_path not in self.files:
                size = os.path.getsize(full_path)
                self.queue.put(("verify_add", full_path, size))

            hasher = hashlib.new(algo)
            try:
                with open(full_path, "rb") as f:
                    while True:
                        chunk = f.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        hasher.update(chunk)
                actual_hash = hasher.hexdigest().lower()
                status = "ok" if actual_hash == expected_hash else "failed"
                self.queue.put(("verify_result", full_path, (algo, actual_hash, status)))
            except Exception as e:
                self.queue.put(("verify_error", full_path, str(e)))

            self.queue.put(("verify_progress", None, int((idx / total) * 100)))

        self.queue.put(("all_done", None, None))

    # ---------------- Lưu kết quả ----------------
    def save_results(self):
        if not self.files:
            messagebox.showwarning("Trống", "Chưa có kết quả nào để lưu.")
            return

        algo_choice = None
        for name, var in self.algo_vars.items():
            if var.get():
                algo_choice = ALGO_MAP[name]
                break
        if not algo_choice:
            algo_choice = "sha256"

        save_path = filedialog.asksaveasfilename(
            title="Lưu kết quả checksum",
            defaultextension=f".{algo_choice}",
            filetypes=[("Checksum file", f"*.{algo_choice}"), ("Text file", "*.txt")]
        )
        if not save_path:
            return

        base_dir = os.path.dirname(save_path)
        lines = []
        for path, data in self.files.items():
            h = data.get(algo_choice, "")
            if h:
                rel = os.path.relpath(path, base_dir)
                lines.append(f"{h}  {rel}")

        with open(save_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        messagebox.showinfo("Đã lưu", f"Đã lưu {len(lines)} kết quả vào:\n{save_path}")


if __name__ == "__main__":
    root = tk.Tk()
    app = ChecksumTool(root)
    root.mainloop()
