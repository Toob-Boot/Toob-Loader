import customtkinter as ctk
import tkinter.filedialog as fd
import threading
import sys
import os
import time

# FIX: Purge any inherited ghost proxy configurations from Windows/IDE
# that cause `[Errno 11001] getaddrinfo failed` when `httpx` or `grpc`
# tries to resolve the proxy server's hostname instead of the actual endpoint.
for k in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"]:
    if k in os.environ:
        del os.environ[k]
os.environ["NO_PROXY"] = "*"

from pipeline_core import ToobfuzzerPipeline, StateContext

# Attempt to configure CTk appearance
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class RedirectText:
    """Redirects stdout/stderr to a CTkTextbox and optionally to a file."""

    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.log_file = None

        # Configure tags
        self.text_widget.tag_config("error", foreground="#FF4444")
        self.text_widget.tag_config("success", foreground="#00FF00")
        self.text_widget.tag_config("info", foreground="#00BFFF")

    def set_log_file(self, path):
        if self.log_file == path:
            return
        self.log_file = path
        # Truncate existing log for a fresh run
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write("")

    def write(self, string):
        tag = None
        if "[!]" in string or "Exception" in string or "[FAILED]" in string:
            tag = "error"
        elif "[SUCCESS]" in string or "[*]" in string or "[✓]" in string:
            tag = "success"
        elif (
            "[GENERATE]" in string
            or "[COMPILE]" in string
            or "[DEPLOY]" in string
            or "[LISTEN]" in string
            or "[>>>]" in string
            or "[🔄]" in string
        ):
            tag = "info"

        if tag:
            self.text_widget.insert("end", string, tag)
        else:
            self.text_widget.insert("end", string)

        self.text_widget.see("end")  # Scroll to bottom
        if self.log_file:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(string)
            except Exception:
                pass

    def flush(self):
        pass


class ToobfuzzerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Toobfuzzer: Autonomous Firmware Factory")
        self.geometry("1400x850")

        # Grid Layout: 3 columns (Config, History, Main Content)
        self.grid_columnconfigure(1, weight=0)  # History Fixed Width
        self.grid_columnconfigure(2, weight=1)  # Main Dynamic Width
        self.grid_rowconfigure(0, weight=1)

        self.svd_path = None
        self.trm_path = None

        self.create_sidebar()
        self.create_history_sidebar()
        self.create_main_view()

        # Redirect stdout
        sys.stdout = RedirectText(self.console_textbox)
        sys.stderr = RedirectText(self.console_textbox)

        print(
            r"""
  _______          _       __                              
 |__   __|        | |     / _|                             
    | | ___   ___ | |__  | |_ _   _ ___________ _ __ 
    | |/ _ \ / _ \| '_ \ |  _| | | |_  /_  / _ | '__|
    | | (_) | (_) | |_) || | | |_| |/ / / /  __| |   
    |_|\___/ \___/|_.__/ |_|  \__,_/___/___\___|_|   
                                                       
Welcome to the Autonomous V3 Firmware Factory.
Ready for Datasheet ingestion.
        """
        )

    def create_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(20, weight=1)

        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="Pipeline Config",
            font=ctk.CTkFont(size=20, weight="bold"),
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # SVD Upload Block
        self.svd_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="📎 Add SVD / XML",
            command=self.upload_svd,
            fg_color="transparent",
            border_width=2,
        )
        self.svd_btn.grid(row=1, column=0, padx=20, pady=(10, 5))

        self.svd_label = ctk.CTkLabel(
            self.sidebar_frame, text="[ ] No SVD loaded", text_color="gray"
        )
        self.svd_label.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="w")

        # TRM Upload Block
        self.trm_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="📎 Add TRM / PDF",
            command=self.upload_trm,
            fg_color="transparent",
            border_width=2,
        )
        self.trm_btn.grid(row=3, column=0, padx=20, pady=(10, 5))

        self.trm_label = ctk.CTkLabel(
            self.sidebar_frame, text="[ ] No TRM loaded", text_color="gray"
        )
        self.trm_label.grid(row=4, column=0, padx=20, pady=(0, 20), sticky="w")

        # Chip Target Display
        self.chip_title = ctk.CTkLabel(
            self.sidebar_frame,
            text="Chip Target:",
            font=ctk.CTkFont(weight="bold"),
            anchor="w",
        )
        self.chip_title.grid(row=5, column=0, padx=20, pady=(0, 0), sticky="ew")

        self.chip_var = ctk.StringVar(value="Waiting for SVD...")
        self.chip_display = ctk.CTkLabel(
            self.sidebar_frame,
            textvariable=self.chip_var,
            text_color="cyan",
            anchor="w",
        )
        self.chip_display.grid(row=6, column=0, padx=20, pady=(0, 10), sticky="ew")

        # Architecture Display
        self.arch_title = ctk.CTkLabel(
            self.sidebar_frame,
            text="Architecture:",
            font=ctk.CTkFont(weight="bold"),
            anchor="w",
        )
        self.arch_title.grid(row=7, column=0, padx=20, pady=(0, 0), sticky="ew")

        self.arch_var = ctk.StringVar(value="Waiting for SVD...")
        self.arch_display = ctk.CTkLabel(
            self.sidebar_frame,
            textvariable=self.arch_var,
            text_color="cyan",
            anchor="w",
        )
        self.arch_display.grid(row=8, column=0, padx=20, pady=(0, 0), sticky="ew")

        self.arch_tooltip = ctk.CTkLabel(
            self.sidebar_frame,
            text="(Auto-detected from SVD)",
            text_color="gray",
            font=ctk.CTkFont(size=10),
        )
        self.arch_tooltip.grid(row=9, column=0, padx=20, pady=(0, 10), sticky="w")

        # Consistency Runs
        self.runs_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="Consistency Runs:",
            font=ctk.CTkFont(weight="bold"),
            anchor="w",
        )
        self.runs_label.grid(row=10, column=0, padx=20, pady=(10, 0), sticky="ew")
        self.runs_var = ctk.StringVar(value="1")
        self.runs_entry = ctk.CTkOptionMenu(
            self.sidebar_frame,
            values=["1", "2", "3", "5", "7"],
            variable=self.runs_var,
            width=80,
        )
        self.runs_entry.grid(row=11, column=0, padx=20, pady=(5, 20), sticky="w")

        # Verbose Debug Logs
        self.debug_mode_var = ctk.BooleanVar(value=False)
        self.debug_checkbox = ctk.CTkCheckBox(
            self.sidebar_frame,
            text="Verbose Debug Logs",
            variable=self.debug_mode_var,
            font=ctk.CTkFont(size=12)
        )
        self.debug_checkbox.grid(row=12, column=0, padx=20, pady=(0, 20), sticky="w")

        # Start Button
        self.start_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="▶ START PIPELINE",
            command=self.start_pipeline_thread,
            fg_color="#2E8B57",
            hover_color="#3CB371",
            state="disabled",  # Disabled by default until BOTH files are loaded
        )
        self.start_btn.grid(row=13, column=0, padx=20, pady=10)

        self.restart_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="🔄 RESTART APP",
            command=self.restart_app,
            fg_color="#B22222",
            hover_color="#8B0000",
        )
        self.restart_btn.grid(row=14, column=0, padx=20, pady=10)

    def create_history_sidebar(self):
        self.history_frame = ctk.CTkScrollableFrame(
            self, width=250, corner_radius=0, fg_color="#2B2B2B"
        )
        self.history_frame.grid(row=0, column=1, sticky="nsew")

        self.history_top_frame = ctk.CTkFrame(
            self.history_frame, fg_color="transparent"
        )
        self.history_top_frame.grid(
            row=0, column=0, padx=10, pady=(20, 10), sticky="ew"
        )

        self.history_title = ctk.CTkLabel(
            self.history_top_frame,
            text="Run History",
            font=ctk.CTkFont(size=20, weight="bold"),
            anchor="w",
            width=140,
        )
        self.history_title.pack(side="left")

        self.history_refresh_btn = ctk.CTkButton(
            self.history_top_frame,
            text="🔄",
            width=30,
            command=self.populate_history,
            fg_color="#3A3A3A",
            hover_color="#4A4A4A",
        )
        self.history_refresh_btn.pack(side="right")

        self.populate_history()

    def populate_history(self):
        # Clear existing children except the top frame
        for widget in self.history_frame.winfo_children():
            if widget != self.history_top_frame:
                widget.destroy()

        blueprints_dir = os.path.join(os.path.dirname(__file__), "blueprints")
        build_dir = os.path.join(os.path.dirname(__file__), "build")

        if not os.path.exists(blueprints_dir):
            return

        row_idx = 1
        for chip in os.listdir(blueprints_dir):
            chip_path = os.path.join(blueprints_dir, chip)
            if not os.path.isdir(chip_path):
                continue

            # Chip Header
            lbl = ctk.CTkLabel(
                self.history_frame,
                text=chip.upper(),
                text_color="cyan",
                font=ctk.CTkFont(weight="bold"),
            )
            lbl.grid(row=row_idx, column=0, padx=10, pady=(15, 5), sticky="w")
            row_idx += 1

            runs = []
            for run in os.listdir(chip_path):
                if run.startswith("run_"):
                    runs.append(run)

            # Sort runs by run number (run_1, run_2, etc)
            runs.sort(
                key=lambda x: (
                    int(x.split("_")[1])
                    if "_" in x and x.split("_")[1].isdigit()
                    else 0
                )
            )

            for index, run in enumerate(runs):
                is_latest = index == len(runs) - 1

                # Heuristic success check: was a binary produced? Or is there a terminal output indicating success?
                # For now, check if the build directory for this specific run exists and has a binary.
                # Currently the pipeline uses `build/esp32/run_latest`, so history binaries might not be saved properly yet.
                # Let's assume a basic `[?]` state until we refactor pipeline_core to output into `build/esp32/run_X`.
                state_symbol = "⭐" if is_latest else "📄"

                btn = ctk.CTkButton(
                    self.history_frame,
                    text=f"{state_symbol} {run.capitalize()}",
                    command=lambda r=run, c=chip: self.load_historical_run(c, r),
                    fg_color="#3A3A3A",
                    hover_color="#4A4A4A",
                    anchor="w",
                )
                btn.grid(row=row_idx, column=0, padx=20, pady=2, sticky="ew")
                row_idx += 1

    def load_historical_run(self, chip, run):
        """Loads terminal logs and stages internal context for a Re-Run."""
        self.selected_history_chip = chip
        self.selected_history_run = run

        # Visually signify the selected run
        short_run = run if len(run) <= 7 else run[:5] + ".."
        self.history_title.configure(text=f"View: {short_run}")
        print(f"\n[*] Loaded historical context from {chip} / {run}")

        # Attempt to load the archived terminal trace
        log_path = os.path.join(
            os.path.dirname(__file__), "blueprints", chip, run, "terminal_output.txt"
        )
        self.console_textbox.delete("1.0", "end")
        self.full_historical_lines = []
        if os.path.exists(log_path):
            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    self.full_historical_lines = f.readlines()
            except Exception as e:
                self.full_historical_lines = [
                    f"[!] Error reading historical logs: {e}\n"
                ]
        else:
            self.full_historical_lines = [
                f"[!] No terminal trace found for {chip}/{run}.\n"
            ]

        # Determine max reached node and if error
        max_node = 0
        is_error = False
        for line in self.full_historical_lines:
            if "[>>>] Initializing Keelhaul SVD Generator" in line:
                max_node = 1
            elif "[GENERATE]" in line:
                max_node = 2
            elif "[COMPILE]" in line:
                max_node = 5 if run != "run_1" else 3
            elif "[DEPLOY]" in line:
                max_node = 6 if run != "run_1" else 4
            elif "[SUCCESS]" in line:
                max_node = 7

            if "[!]" in line or "Exception" in line or "[FAILED]" in line:
                is_error = True

        # Update UI to the max node reached
        self.update_phase_ui(max_node, is_error=is_error)
        self.rerun_node_var.set(max_node)
        self.render_terminal_slice(max_node)

    def on_timeline_click(self):
        self.render_terminal_slice(self.rerun_node_var.get())

    def render_terminal_slice(self, target_idx):
        if not hasattr(self, "full_historical_lines"):
            return
        self.console_textbox.delete("1.0", "end")

        current_node = 0
        for line in self.full_historical_lines:
            if "[>>>] Initializing Keelhaul SVD Generator" in line:
                current_node = 1
            elif "[GENERATE]" in line:
                current_node = 2
            elif "[COMPILE]" in line:
                current_node = 5 if self.selected_history_run != "run_1" else 3
            elif "[DEPLOY]" in line:
                current_node = 6 if self.selected_history_run != "run_1" else 4
            elif "[SUCCESS]" in line:
                current_node = 7

            if current_node <= target_idx:
                tag = None
                if "[!]" in line or "Exception" in line or "[FAILED]" in line:
                    if (
                        "[!]" in line
                        and "Error reading historical logs" not in line
                        and "No terminal trace found" not in line
                    ):
                        tag = "error"
                    else:
                        tag = "error"
                elif "[SUCCESS]" in line or "[*]" in line or "[✓]" in line:
                    tag = "success"
                elif (
                    "[GENERATE]" in line
                    or "[COMPILE]" in line
                    or "[DEPLOY]" in line
                    or "[LISTEN]" in line
                    or "[>>>]" in line
                    or "[🔄]" in line
                ):
                    tag = "info"

                if tag:
                    self.console_textbox.insert("end", line, tag)
                else:
                    self.console_textbox.insert("end", line)

        self.console_textbox.see("end")

    def create_main_view(self):
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=2, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_rowconfigure(0, weight=0)  # Flow frame fixed
        self.main_frame.grid_rowconfigure(1, weight=0)  # Toolbar fixed
        self.main_frame.grid_rowconfigure(2, weight=1)  # Console stretches
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Top Flow Indicator (Interactive Timeline)
        self.flow_frame = ctk.CTkScrollableFrame(
            self.main_frame, height=120, orientation="horizontal", fg_color="#2B2B2B"
        )
        self.flow_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.rerun_node_var = ctk.IntVar(value=0)  # Index of the selected node
        self.ai_checkbox_vars = [ctk.BooleanVar(value=True) for _ in range(3)]

        self.pipeline_nodes = [
            "1. Uploads",
            "2. SVD Meta",
            "3. AI Extraction",
            "4. Compile (Ping)",
            "5. Flash + Read (Ping)",
            "6. Compile (Pong)",
            "7. Flash + Read (Pong)",
            "8. Synthesis",
        ]

        self.node_widgets = []
        col_idx = 0
        i = 0
        while i < len(self.pipeline_nodes):
            text = self.pipeline_nodes[i]

            # Container for the node
            node_container = ctk.CTkFrame(self.flow_frame, fg_color="transparent")
            node_container.grid(row=0, column=col_idx * 2, padx=5, sticky="nsew")

            if text == "3. AI Extraction":
                # Parent RadioButton for Phase 3
                rb = ctk.CTkRadioButton(
                    node_container,
                    text=text,
                    variable=self.rerun_node_var,
                    value=i,
                    font=ctk.CTkFont(weight="bold"),
                    command=self.on_timeline_click,
                )
                rb.pack(pady=(10, 5), anchor="w")
                self.node_widgets.append(rb)

                # 3 Multiple-Choice Checkboxes under Phase 3
                sub_labels = ["a. Layout", "b. Registers", "c. Hooks"]
                for j in range(3):
                    cb = ctk.CTkCheckBox(
                        node_container,
                        text=sub_labels[j],
                        variable=self.ai_checkbox_vars[j],
                        font=ctk.CTkFont(size=11),
                        border_width=2,
                        checkbox_width=18,
                        checkbox_height=18,
                    )
                    cb.pack(pady=2, padx=(25, 0), anchor="w")
                i += 1
            else:
                # Normal inline node
                rb = ctk.CTkRadioButton(
                    node_container,
                    text=text,
                    variable=self.rerun_node_var,
                    value=i,
                    font=ctk.CTkFont(weight="bold"),
                    command=self.on_timeline_click,
                )
                rb.pack(pady=10, anchor="w")
                self.node_widgets.append(rb)
                i += 1

            # Arrow
            if i < len(self.pipeline_nodes):
                arrow = ctk.CTkLabel(
                    self.flow_frame,
                    text="➔",
                    text_color="gray",
                    font=ctk.CTkFont(size=20),
                )
                arrow.grid(row=0, column=col_idx * 2 + 1, padx=5)

            col_idx += 1

        # Re-Run Action Toolbar
        self.toolbar_frame = ctk.CTkFrame(
            self.main_frame, height=40, fg_color="transparent"
        )
        self.toolbar_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="ew")

        self.rerun_btn = ctk.CTkButton(
            self.toolbar_frame,
            text="🔄 Re-Run From Selected Node",
            command=self.trigger_rerun_from_node,
            fg_color="#0052cc",
            hover_color="#0066ff",
        )
        self.rerun_btn.pack(side="left", padx=5)

        self.report_btn = ctk.CTkButton(
            self.toolbar_frame,
            text="📊 View SoC Dashboard",
            command=self.open_soc_dashboard,
            fg_color="#2E8B57",
            hover_color="#3CB371",
        )
        self.report_btn.pack(side="right", padx=5)

        # Terminal Log
        self.console_textbox = ctk.CTkTextbox(
            self.main_frame,
            width=250,
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color="#00FF00",
            fg_color="#1E1E1E",
        )
        self.console_textbox.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

    def open_soc_dashboard(self):
        chip = getattr(self, "selected_history_chip", None)
        run = getattr(self, "selected_history_run", None)

        # Fallback to current active run if nothing is selected in sidebar
        if not chip or not run:
            if hasattr(self, "chip_name_internal"):
                chip = self.chip_name_internal
                # Find the highest run_X directory
                base_dir = os.path.join(os.path.dirname(__file__), "blueprints", chip)
                if os.path.exists(base_dir):
                    runs = [
                        d
                        for d in os.listdir(base_dir)
                        if d.startswith("run_") and "pong" not in d
                    ]
                    if runs:
                        runs.sort(key=lambda x: int(x.split("_")[1]), reverse=True)
                        run = runs[0]

        if not chip or not run:
            print(
                "[!] Could not determine the latest run. Please select one from the sidebar."
            )
            return

        run_dir = os.path.join(os.path.dirname(__file__), "blueprints", chip, run)

        scripts_dir = os.path.join(os.path.dirname(__file__), "scripts")
        if scripts_dir not in sys.path:
            sys.path.append(scripts_dir)

        try:
            from report_generator import generate_soc_report
            import webbrowser

            print(f"[*] Generating SoC Dashboard for {chip} ({run})...")
            out_file = generate_soc_report(run_dir)
            if out_file and os.path.exists(out_file):
                webbrowser.open(f"file://{os.path.abspath(out_file)}")
            else:
                print(
                    "[!] Failed to compile dashboard. Are you missing telemetry logic?"
                )
        except Exception as e:
            print(f"[!] Dashboard Error: {e}")

    def trigger_rerun_from_node(self):
        node_idx = self.rerun_node_var.get()
        print(
            f"\n[🔄] Re-Run requested starting from node: {self.pipeline_nodes[node_idx]} ({node_idx})"
        )

        if not hasattr(self, "selected_history_chip") or not hasattr(
            self, "selected_history_run"
        ):
            print("[!] Please select a historical Run from the sidebar to Re-Run from.")
            return

        chip = self.selected_history_chip
        old_run = self.selected_history_run

        from pipeline_core import PipelineState, StateContext, ToobfuzzerPipeline

        # Map UI Index to Pipeline state
        if node_idx <= 2:
            target_state = PipelineState.GENERATE
            target_run_id = 1
        elif node_idx == 3:
            target_state = PipelineState.COMPILE
            target_run_id = 1
        elif node_idx == 4:
            target_state = PipelineState.DEPLOY
            target_run_id = 1
        elif node_idx == 5:
            target_state = PipelineState.COMPILE
            target_run_id = 2
        elif node_idx == 6:
            target_state = PipelineState.DEPLOY
            target_run_id = 2
        else:  # >= 7
            target_state = PipelineState.SUCCESS
            target_run_id = 2

        print(
            f"[*] AI Extraction Toggles: Layout={'ON' if self.ai_checkbox_vars[0].get() else 'OFF'}, Registers={'ON' if self.ai_checkbox_vars[1].get() else 'OFF'}, Hooks={'ON' if self.ai_checkbox_vars[2].get() else 'OFF'}"
        )

        # Create new run directory and copy artifacts
        import shutil

        base_dir = os.path.join(os.path.dirname(__file__), "blueprints", chip)
        old_dir = os.path.join(base_dir, old_run)

        run_num = 1
        while os.path.exists(os.path.join(base_dir, f"run_{run_num}")):
            run_num += 1

        new_dir = os.path.join(base_dir, f"run_{run_num}")
        os.makedirs(new_dir, exist_ok=True)

        # Copy crucial JSONs
        for f in ["blueprint.json", "confidence.json", "aggregated_scan.json"]:
            src = os.path.join(old_dir, f)
            if os.path.exists(src):
                shutil.copy(src, os.path.join(new_dir, f))

        print(f"[*] State Cached: Copied artifacts from {old_run} to run_{run_num}.")

        # Launch pipeline
        arch = getattr(self, "arch_name_internal", "RISC-V")
        runs = int(self.runs_var.get())

        self.console_textbox.delete("1.0", "end")
        self.update_phase_ui(node_idx)
        self.start_btn.configure(state="disabled", text="Running Re-Run...")

        print(
            f"\n[>>>] Initializing Re-Run starting at {self.pipeline_nodes[node_idx]}..."
        )

        threading.Thread(
            target=self.run_pipeline_thread_custom,
            args=(chip, arch, runs, target_state, run_num),
            daemon=True,
        ).start()

    def run_pipeline_thread_custom(
        self, chip, arch, runs, start_state, expected_run_id
    ):
        try:
            from pipeline_core import StateContext, ToobfuzzerPipeline

            ctx = StateContext(chip, arch, self.trm_path, runs)
            ctx.run_id = expected_run_id
            ctx.debug_mode = self.debug_mode_var.get()

            pipeline = ToobfuzzerPipeline(
                context=ctx,
                gui_callback=self.update_phase_ui,
            )
            pipeline.state = start_state

            pipeline.run()
        except Exception as e:
            print(f"[!] Caught Pipeline Exception: {e}")
        finally:
            self.start_btn.configure(state="normal", text="▶ START PIPELINE")
            # Refresh history UI
            self.after(0, self.populate_history)

    def validate_start_conditions(self):
        """Checks if the run button can be enabled based on user inputs."""
        if (
            self.svd_path is not None
            and self.trm_path is not None
            and hasattr(self, "chip_name_internal")
        ):
            self.start_btn.configure(state="normal")
        else:
            self.start_btn.configure(state="disabled")

    def upload_svd(self):
        filepath = fd.askopenfilename(
            title="Select Keelhaul SVD",
            filetypes=[
                ("SVD Files", "*.svd *.xml"),
                ("All Files", "*.*"),
            ],
        )
        if filepath:
            self.svd_path = filepath
            filename = os.path.basename(filepath)
            self.svd_label.configure(text=f"[✓] {filename}", text_color="#00FF00")
            print(f"[*] Attached Keelhaul Context: {filepath}")

            # Immediately trigger SVD parsing in background
            chip_guess = os.path.splitext(filename)[0].lower().replace(" ", "_")
            print(f"\n[>>>] Initializing Keelhaul SVD Generator for {chip_guess}...")
            # We want the user to wait for SVD extraction before starting the pipeline
            self.start_btn.configure(state="disabled")
            threading.Thread(
                target=self.run_svd_thread, args=(chip_guess,), daemon=True
            ).start()

    def upload_trm(self):
        filepath = fd.askopenfilename(
            title="Select TRM PDF",
            filetypes=[
                ("Document Files", "*.pdf *.txt *.md"),
                ("All Files", "*.*"),
            ],
        )
        if filepath:
            self.trm_path = filepath
            filename = os.path.basename(filepath)
            self.trm_label.configure(text=f"[✓] {filename}", text_color="#00FF00")
            print(f"[*] Attached TRM Context: {filepath}")
            self.validate_start_conditions()

    def update_phase_ui(self, phase_index, is_error=False):
        """Highlights the active phase in the interactive timeline."""
        for i, rb in enumerate(self.node_widgets):
            if i == phase_index and is_error:
                rb.configure(text_color="#FF4444")  # Crash / Error
            elif i < phase_index:
                rb.configure(text_color="#3CB371")  # Done (Green)
            elif i == phase_index:
                rb.configure(text_color="#FFD700")  # Active (Yellow)
            else:
                rb.configure(text_color="gray")  # Pending

        # Optionally auto-select the node as we progress
        if phase_index >= 0:
            self.rerun_node_var.set(phase_index)

    def start_pipeline_thread(self):
        chip = getattr(self, "chip_name_internal", "unknown")
        arch = getattr(self, "arch_name_internal", "RISC-V")
        runs = int(self.runs_var.get())

        # Clear the Terminal Textbox
        self.console_textbox.delete("1.0", "end")

        # Reset Phase indicators to gray
        self.update_phase_ui(-1)

        self.start_btn.configure(state="disabled", text="Running...")

        print(
            f"\n[>>>] Initializing Autonomous Pipeline for {chip} ({arch}) with {runs}x Runs/Stage..."
        )
        threading.Thread(
            target=self.run_pipeline_thread, args=(chip, arch, runs), daemon=True
        ).start()

    def run_svd_thread(self, chip):
        try:
            sys.path.append(os.path.join(os.path.dirname(__file__), "linker_gen"))
            from svd_to_c import generate_keelhaul_header
            from pipeline_core import StateContext, ToobfuzzerPipeline, PipelineState

            build_dir = os.path.join(
                os.path.dirname(__file__), "build", chip, "run_latest"
            )
            os.makedirs(build_dir, exist_ok=True)
            output_c = os.path.join(build_dir, "keelhaul_svd.c")

            self.update_phase_ui(0)  # Generating
            metadata = generate_keelhaul_header(self.svd_path, output_c, chip)

            def update_ui():
                self.chip_name_internal = (
                    metadata.get("name", chip).lower().replace(" ", "")
                )
                self.chip_var.set(self.chip_name_internal)

                cpu_raw = metadata.get("cpu")
                cpu_str = str(cpu_raw) if cpu_raw else ""
                cpu_upper = cpu_str.upper()

                if "XTENSA" in cpu_upper:
                    self.arch_name_internal = "Xtensa (ESP32)"
                elif "CORTEX-M" in cpu_upper or "ARM" in cpu_upper:
                    self.arch_name_internal = "ARM Cortex-M"
                elif "RISC-V" in cpu_upper or "RV32" in cpu_upper:
                    self.arch_name_internal = "RISC-V"
                else:
                    self.arch_name_internal = "Unknown"
                self.arch_var.set(self.arch_name_internal)

                vendor = str(metadata.get("vendor") or "Unknown")

                print(
                    f"\n[SUCCESS] Extracted SVD Metadata. Auto-Detected: Vendor={vendor}, CPU={cpu_str}"
                )
                print(
                    f"[SUCCESS] Discovered {metadata.get('uart_count', 0)} UARTs and {metadata.get('wdt_count', 0)} Watchdogs."
                )
                print(
                    "[SUCCESS] SVD Arrays successfully extracted to Keelhaul C structures."
                )

                self.validate_start_conditions()

            self.after(0, update_ui)
            self.update_phase_ui(1)  # Compilation Ready
        except Exception as e:
            print(f"[!] SVD Parsing Failed: {e}")

            def enable_start():
                self.validate_start_conditions()

            self.after(0, enable_start)

    def run_pipeline_thread(self, chip, arch, runs):
        try:
            # Prepare the state context with user inputs
            from pipeline_core import StateContext, ToobfuzzerPipeline, PipelineState

            ctx = StateContext(chip, arch, self.trm_path, runs)
            ctx.debug_mode = self.debug_mode_var.get()

            # Instantiate the State Machine, passing our GUI progress updater
            pipeline = ToobfuzzerPipeline(
                context=ctx, gui_callback=self.update_phase_ui
            )

            # Launch the autonomous loop
            pipeline.run()

        except Exception as e:
            print(f"[!] Caught Pipeline Exception: {e}")
        finally:
            self.start_btn.configure(state="normal", text="▶ START PIPELINE")

    def restart_app(self):
        """Forcefully reloads the python process to reset the GUI."""
        print("[*] Restarting application...")
        import subprocess

        subprocess.Popen([sys.executable] + sys.argv)
        sys.exit(0)


if __name__ == "__main__":
    app = ToobfuzzerGUI()
    app.mainloop()
