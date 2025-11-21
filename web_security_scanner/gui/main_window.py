import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from .controllers.scan_controller import ScanController
from ..utils.i18n import i18n

class MainWindow:
    """
    Main Window for the Web Security Scanner GUI.
    """
    def __init__(self, root: tk.Tk, controller: ScanController):
        self.root = root
        self.controller = controller
        
        self.root.title(i18n.get('gui.title'))
        self.root.geometry("1000x700")
        
        self.vulnerabilities_map = {}  # Store full vulnerability data
        self.report_path = None
        
        self._setup_ui()
        self._setup_callbacks()

    def _setup_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # URL Input
        input_frame = ttk.LabelFrame(main_frame, text=i18n.get('gui.target'), padding="5")
        input_frame.pack(fill=tk.X, pady=5)
        
        self.url_var = tk.StringVar()
        self.url_entry = ttk.Entry(input_frame, textvariable=self.url_var, width=50)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Profile Selector
        ttk.Label(input_frame, text=i18n.get('gui.profiles.label')).pack(side=tk.LEFT, padx=5)
        self.profile_var = tk.StringVar(value="balanced")
        profiles = {
            i18n.get('gui.profiles.mapping'): "mapping",
            i18n.get('gui.profiles.quick'): "quick",
            i18n.get('gui.profiles.balanced'): "balanced",
            i18n.get('gui.profiles.intense'): "intense"
        }
        # Reverse map for display
        self.profile_map = {v: k for k, v in profiles.items()}
        
        self.profile_combo = ttk.Combobox(input_frame, textvariable=self.profile_var, state="readonly")
        self.profile_combo['values'] = list(profiles.keys())
        self.profile_combo.current(2) # Default to Balanced
        self.profile_combo.pack(side=tk.LEFT, padx=5)
        
        self.scan_btn = ttk.Button(input_frame, text=i18n.get('gui.start_scan'), command=self._start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.open_report_btn = ttk.Button(input_frame, text=i18n.get('gui.open_report'), command=self._open_report, state="disabled")
        self.open_report_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress
        self.progress_var = tk.StringVar(value=i18n.get('gui.ready'))
        self.status_label = ttk.Label(main_frame, textvariable=self.progress_var)
        self.status_label.pack(fill=tk.X, pady=2)
        
        self.progress_bar = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress_bar.pack(fill=tk.X, pady=2)
        
        # Results Area
        results_frame = ttk.LabelFrame(main_frame, text=i18n.get('gui.scan_results'), padding="5")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Treeview for vulnerabilities
        columns = ('type', 'severity', 'url', 'payload')
        self.tree = ttk.Treeview(results_frame, columns=columns, show='headings')
        
        self.tree.heading('type', text=i18n.get('gui.columns.vulnerability'))
        self.tree.heading('severity', text=i18n.get('gui.columns.severity'))
        self.tree.heading('url', text=i18n.get('gui.columns.url'))
        self.tree.heading('payload', text=i18n.get('gui.columns.payload'))
        
        self.tree.column('type', width=150)
        self.tree.column('severity', width=80)
        self.tree.column('url', width=300)
        self.tree.column('payload', width=200)
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double click
        self.tree.bind("<Double-1>", self._on_tree_double_click)
        
        # Log Area
        log_frame = ttk.LabelFrame(main_frame, text=i18n.get('gui.logs'), padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5, ipady=20)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, state='disabled')
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def _setup_callbacks(self):
        self.controller.set_callback('on_start', self.on_scan_start)
        self.controller.set_callback('on_progress', self.on_progress)
        self.controller.set_callback('on_vulnerability', self.on_vulnerability)
        self.controller.set_callback('on_complete', self.on_scan_complete)
        self.controller.set_callback('on_error', self.on_error)
        self.controller.set_callback('on_log', self.on_log)

    def _start_scan(self):
        url = self.url_var.get()
        if not url:
            messagebox.showwarning("Error", i18n.get('gui.messages.enter_url'))
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            self.url_var.set(url)
            
        # Get internal profile name from display name
        display_name = self.profile_combo.get()
        profiles = {
            i18n.get('gui.profiles.mapping'): "mapping",
            i18n.get('gui.profiles.quick'): "quick",
            i18n.get('gui.profiles.balanced'): "balanced",
            i18n.get('gui.profiles.intense'): "intense"
        }
        profile = profiles.get(display_name, "balanced")
            
        self.controller.start_scan(url, profile)

    def _on_tree_double_click(self, event):
        item_id = self.tree.identify_row(event.y)
        if item_id:
            self._show_details(item_id)

    def _show_details(self, item_id):
        if item_id not in self.vulnerabilities_map:
            return
            
        vuln = self.vulnerabilities_map[item_id]
        
        details_window = tk.Toplevel(self.root)
        details_window.title(i18n.get('gui.details.title'))
        details_window.geometry("600x500")
        
        # Helper to add fields
        def add_field(label, value):
            frame = ttk.Frame(details_window, padding="5")
            frame.pack(fill=tk.X)
            ttk.Label(frame, text=label, font=('bold')).pack(anchor=tk.W)
            
            text = tk.Text(frame, height=4, wrap=tk.WORD, font=('Segoe UI', 9))
            text.insert("1.0", str(value))
            text.config(state='disabled', bg='#f0f0f0')
            text.pack(fill=tk.X)

        add_field(i18n.get('gui.columns.vulnerability'), vuln.get('type', ''))
        add_field(i18n.get('gui.columns.severity'), vuln.get('severity', ''))
        add_field(i18n.get('gui.columns.url'), vuln.get('url', ''))
        add_field(i18n.get('gui.details.evidence'), vuln.get('evidence', ''))
        add_field(i18n.get('gui.columns.payload'), vuln.get('payload', ''))
        
        # Add description/remediation if available (would need to come from tester)
        # For now we just show what we have in the vulnerability dict
        
        ttk.Button(details_window, text=i18n.get('gui.details.close'), command=details_window.destroy).pack(pady=10)

    # Thread-safe UI updates
    def on_scan_start(self, url):
        self.root.after(0, lambda: self._ui_scan_start(url))

    def _ui_scan_start(self, url):
        self.scan_btn.config(state='disabled')
        self.progress_bar.start(10)
        self.progress_var.set(i18n.get('gui.scanning', url=url))
        self._log(f"Started scan on {url}")
        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)

    def on_progress(self, message):
        self.root.after(0, lambda: self.progress_var.set(message))

    def on_vulnerability(self, vulnerability):
        self.root.after(0, lambda: self._ui_add_vulnerability(vulnerability))

    def _ui_add_vulnerability(self, vuln):
        values = (
            vuln.get('type', 'Unknown'),
            vuln.get('severity', 'Info'),
            vuln.get('url', ''),
            vuln.get('payload', '')
        )
        item_id = self.tree.insert('', 'end', values=values)
        self.vulnerabilities_map[item_id] = vuln
        self._log(f"FOUND: {vuln.get('type')} at {vuln.get('url')}")

    def on_scan_complete(self):
        self.root.after(0, self._ui_scan_complete)

    def _ui_scan_complete(self):
        self.scan_btn.config(state='normal')
        self.progress_bar.stop()
        self.progress_var.set(i18n.get('gui.status.complete'))
        self._log("Scan finished.")
        messagebox.showinfo(i18n.get('gui.messages.done'), i18n.get('gui.messages.scan_finished'))

    def on_error(self, error):
        self.root.after(0, lambda: self._ui_error(error))

    def _ui_error(self, error):
        self._log(f"ERROR: {error}")
        self.progress_var.set(i18n.get('gui.status.error', error=error))
        self.scan_btn.config(state='normal')
        self.progress_bar.stop()

    def on_log(self, message):
        self.root.after(0, lambda: self._ui_log(message))

    def _ui_log(self, message):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')
        
        if "Report generated:" in message:
            try:
                self.report_path = message.split("Report generated:")[1].strip()
                self.open_report_btn.config(state="normal")
            except:
                pass

    def _open_report(self):
        if self.report_path:
            import os
            import platform
            import subprocess
            
            try:
                if platform.system() == 'Windows':
                    os.startfile(self.report_path)
                elif platform.system() == 'Darwin':
                    subprocess.call(('open', self.report_path))
                else:
                    subprocess.call(('xdg-open', self.report_path))
            except Exception as e:
                messagebox.showerror("Error", f"Could not open report: {e}")

    def _log(self, message):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')
