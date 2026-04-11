# gui_wms_modern_full.py
import os
import sys
import subprocess
import threading
import time
import csv
import platform
import re

try:
    import customtkinter as ctk
except Exception as e:
    print("Missing customtkinter. Install with: pip install customtkinter")
    raise

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Configuration générale de l'apparence de l'application
# Mode sombre avec thème bleu
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
# Utilisation de l'interpréteur Python courant
PYTHON_EXE = sys.executable

# # Détermination du répertoire du projet
# Utilisé pour localiser le moteur de scan (wms.py)
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
WMS_SCRIPT = os.path.join(PROJECT_DIR, "wms.py")

# Cette classe représente l'application graphique principale
#  du scanner de malwares SUPMTI.
#  Elle gère l'interface utilisateur, le lancement du scan,
# l'affichage des résultats et l'exportation.
class ModernWMS(ctk.CTk):
    def __init__(self):
        super().__init__()
        # Paramètres de la fenêtre principale
        self.title("SUPMTI Malware Scanner — Modern")
        self.geometry("1100x700")
        self.minsize(900,600)
# Variables utilisées pour gérer le processus de scan
        self.proc = None
        self._thread = None
        self._rows = []
        self.signatures_path = None

         # Expressions régulières utilisées pour analyser la sortie du scanner
        self.re_infected = re.compile(r'Infected file \((.*?)\) found: (.*)', re.IGNORECASE)
        self.re_insecure = re.compile(r'Insecure permission .* found on: (.*)', re.IGNORECASE)
        self.re_progress = re.compile(r'\((\d{1,3})%\)')
        self.re_ansi = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        # Construction de l’interface graphique
        self._build_ui()

       # Création de tous les composants graphiques :
       # champs, boutons, barre de progression, logs et tableau de résultats.
    def _build_ui(self):
         # Zone supérieure : sélection du dossier à analyser
        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=12, pady=8)

        ctk.CTkLabel(top, text="Folder:", width=60).pack(side="left")
        self.path_var = tk.StringVar()
        ctk.CTkEntry(top, textvariable=self.path_var, width=640).pack(side="left", padx=8)
        ctk.CTkButton(top, text="Browse", command=self.browse).pack(side="left", padx=4)
        ctk.CTkButton(top, text="Signatures", command=self.choose_signatures).pack(side="left", padx=4)

         # Options supplémentaires
        opts = ctk.CTkFrame(self)
        opts.pack(fill="x", padx=12, pady=(0,8))
        # Activation du contrôle des permissions Windows (ACL)
        self.acl_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(opts, text="Enable Windows ACL check (slow)", variable=self.acl_var).pack(side="left", padx=6)
        # Champ de filtrage des résultats
        ctk.CTkLabel(opts, text="Filter:").pack(side="left", padx=(18,6))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.apply_filter())
        ctk.CTkEntry(opts, textvariable=self.filter_var, width=300).pack(side="left")

        # Buttons
        btns = ctk.CTkFrame(self)
        btns.pack(fill="x", padx=12, pady=(0,8))
        # Bouton de démarrage du scan
        self.btn_start = ctk.CTkButton(btns, text="Start", command=self.start_scan)
        self.btn_start.pack(side="left", padx=6)
         # Bouton d'arrêt du scan
        self.btn_stop = ctk.CTkButton(btns, text="Stop", command=self.stop_scan, state="disabled")
        self.btn_stop.pack(side="left", padx=6)
        # Boutons utilitaires
        ctk.CTkButton(btns, text="Clear", command=self.clear_all).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Export CSV", command=self.export_csv).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Open File", command=self.open_selected).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Reveal in Explorer", command=self.reveal_selected).pack(side="left", padx=6)

        # Progress
        prog = ctk.CTkFrame(self)
        prog.pack(fill="x", padx=12)
        ctk.CTkLabel(prog, text="Progress:").pack(side="left")
        self.progress = ctk.CTkProgressBar(prog, orientation="horizontal")
        self.progress.set(0)
        self.progress.pack(side="left", fill="x", expand=True, padx=8)

         # Zone principale
        main = ctk.CTkFrame(self)
        main.pack(fill="both", expand=True, padx=12, pady=12)

        # Zone gauche : affichage des messages du scanner
        left = ctk.CTkFrame(main)
        left.pack(side="left", fill="both", expand=True, padx=6)
        ctk.CTkLabel(left, text="Scanner Output").pack(anchor="w", padx=6, pady=(6,0))
        self.txt = ctk.CTkTextbox(left, wrap="none")
        self.txt.pack(fill="both", expand=True, padx=6, pady=6)

        # Zone droite : tableau des résultats détectés
        right = ctk.CTkFrame(main)
        right.pack(side="right", fill="both", expand=True, padx=6)
        ctk.CTkLabel(right, text="Results (infected / insecure)").pack(anchor="w", padx=6, pady=(6,0))

        columns = ("type","malware","path")
        self.tree = ttk.Treeview(right, columns=columns, show="headings")
        for c in columns:
            self.tree.heading(c, text=c.capitalize())
        self.tree.column("type", width=100, anchor="center")
        self.tree.column("malware", width=220)
        self.tree.column("path", width=460)
         # Barre de défilement verticale
        vsb = ttk.Scrollbar(right, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True, padx=(6,0), pady=6)

        self.status = ctk.CTkLabel(self, text="Ready", anchor="w")
        self.status.pack(fill="x", side="bottom", padx=12, pady=(0,8))

    def browse(self):
        folder = filedialog.askdirectory(initialdir=os.path.expanduser("~"))
        if folder:
            self.path_var.set(folder)

    def choose_signatures(self):
        fld = filedialog.askdirectory(initialdir=PROJECT_DIR)
        if fld:
            self.signatures_path = fld
            self.append_log(f"Signatures folder chosen: {fld}\n")

    def append_log(self, text):
        def _do():
            self.txt.insert("end", text)
            self.txt.see("end")
        self.txt.after(0, _do)

    def add_result(self, rtype, malware, path):
        def _do():
            self._rows.append({"type":rtype,"malware":malware,"path":path})
            self.tree.insert("", "end", values=(rtype, malware, path))
        self.tree.after(0, _do)

    def apply_filter(self):
        q = self.filter_var.get().lower()
        # clear tree
        for i in self.tree.get_children():
            self.tree.delete(i)
        # reinsert filtered rows
        for r in self._rows:
            if q=="" or q in r["path"].lower() or q in r["malware"].lower() or q in r["type"].lower():
                self.tree.insert("", "end", values=(r["type"], r["malware"], r["path"]))

    def ensure_wms_script(self):
        global WMS_SCRIPT
        if os.path.isfile(WMS_SCRIPT):
            return WMS_SCRIPT
        alt = os.path.join(os.path.dirname(PROJECT_DIR), "wms.py")
        if os.path.isfile(alt):
            WMS_SCRIPT = alt
            return WMS_SCRIPT
        # ask user
        self.append_log("wms.py not found. Please locate wms.py\n")
        path = filedialog.askopenfilename(title="Locate wms.py", initialdir=PROJECT_DIR,
                                          filetypes=[("Python files","*.py"),("All files","*.*")])
        if path and os.path.isfile(path):
            WMS_SCRIPT = path
            self.append_log(f"Using wms.py: {path}\n")
            return WMS_SCRIPT
        messagebox.showerror("wms.py not found", "Cannot find wms.py. Please ensure wms.py is next to this GUI or select it manually.")
        return None

    def start_scan(self):
        wms_path = self.ensure_wms_script()
        if not wms_path:
            return
        target = self.path_var.get().strip()
        if not target or not os.path.isdir(target):
            messagebox.showerror("Error","Please select a valid folder to scan.")
            return
        if self.proc and self.proc.poll() is None:
            messagebox.showwarning("Running","A scan is already running.")
            return

        self.clear_all_logs()
        self.status.configure(text="Starting scan...")
        cmd = [PYTHON_EXE, wms_path, os.path.abspath(target)]
        env = os.environ.copy()
        if getattr(self, "signatures_path", None):
            env["WMS_SIGNATURES"] = self.signatures_path
            self.append_log(f"Using signatures from: {self.signatures_path}\n")
        env["WMS_ENABLE_ACL"] = "1" if self.acl_var.get() else "0"

        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
        except Exception as e:
            messagebox.showerror("Error","Failed to start scanner: "+str(e))
            return

        self._rows.clear()
        for i in self.tree.get_children(): self.tree.delete(i)
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.status.configure(text="Scanning...")
        self.progress.set(0)

        self._thread = threading.Thread(target=self._reader_thread, daemon=True)
        self._thread.start()

    def _reader_thread(self):
        try:
            for raw in iter(self.proc.stdout.readline, ''):
                if raw is None:
                    break
                line = raw
                if not line.endswith("\n"):
                    line += "\n"
                clean = self.re_ansi.sub("", line).replace("\r", "\n")
                self.append_log(line)
                self._process_line(clean)
            self.proc.wait()
            code = self.proc.returncode
            self.append_log(f"\nProcess finished with exit code {code}\n")
            self._on_process_finish(code)
        except Exception as e:
            self.append_log("Reader thread error: "+str(e)+"\n")
            self._safe_set_status("Error reading output")
        finally:
            self._safe_enable_start_button()

    def _process_line(self, line):
        m = self.re_progress.search(line)
        if m:
            try:
                pct = int(m.group(1))
                self.progress.set(pct/100.0)
            except:
                pass
        mi = self.re_infected.search(line)
        if mi:
            malware = mi.group(1).strip()
            path = mi.group(2).strip()
            self.add_result("infected", malware, path)
            return
        ms = self.re_insecure.search(line)
        if ms:
            path = ms.group(1).strip()
            self.add_result("insecure", "", path)
            return

    def _on_process_finish(self, code):
        self.status.configure(text=f"Finished (exit {code})")
        self.progress.set(0)
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")

    def _safe_set_status(self, text):
        self.after(0, lambda: self.status.configure(text=text))

    def _safe_enable_start_button(self):
        self.after(0, lambda: (self.btn_start.configure(state="normal"), self.btn_stop.configure(state="disabled"), self.progress.set(0.0)))

    def stop_scan(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.append_log("\nTermination signal sent.\n")
                def _wait_and_kill():
                    time.sleep(2)
                    if self.proc and self.proc.poll() is None:
                        try:
                            self.proc.kill()
                            self.append_log("\nProcess killed.\n")
                        except Exception as e:
                            self.append_log("Error killing process: "+str(e)+"\n")
                threading.Thread(target=_wait_and_kill, daemon=True).start()
            except Exception as e:
                self.append_log("Error stopping: "+str(e)+"\n")

    def clear_all(self):
        self.clear_all_logs()
        self._rows.clear()
        for i in self.tree.get_children(): self.tree.delete(i)

    def clear_all_logs(self):
        self.txt.delete("1.0","end")
        self.progress.set(0)
        self.status.configure(text="Ready")

    def export_csv(self):
        if not self._rows:
            messagebox.showinfo("Export CSV","No results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV","*.csv")],
                                            initialfile="wms_results.csv")
        if not path:
            return
        try:
            with open(path, "w", newline='', encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["type","malware","path"])
                for r in self._rows:
                    writer.writerow([r["type"], r["malware"], r["path"]])
            messagebox.showinfo("Export CSV", f"Saved: {path}")
        except Exception as e:
            messagebox.showerror("Export CSV", str(e))

    def open_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Open file","Select a row first.")
            return
        path = self.tree.item(sel[0], "values")[2]
        if os.path.isfile(path):
            try:
                self._open_path(path)
            except Exception as e:
                messagebox.showerror("Open file", str(e))
        else:
            messagebox.showinfo("Open file","Selected path is not a file.")

    def reveal_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Reveal","Select a row first.")
            return
        path = self.tree.item(sel[0], "values")[2]
        if os.path.exists(path):
            try:
                folder = path if os.path.isdir(path) else os.path.dirname(path)
                self._open_path(folder)
            except Exception as e:
                messagebox.showerror("Reveal", str(e))
        else:
            messagebox.showinfo("Reveal","Path does not exist.")

    def _open_path(self, path):
        if platform.system() == "Windows":
            os.startfile(path)
        elif platform.system() == "Darwin":
            subprocess.run(["open", path])
        else:
            subprocess.run(["xdg-open", path])

# run 
if __name__ == "__main__":
    app = ModernWMS()
    app.mainloop()
