import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import subprocess
import time
import threading
from datetime import datetime
from pathlib import Path
import os
import json
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

class uArchOptimizerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("uArchOptimizer")
        self.root.geometry("900x700")
        self.debug_mode = tk.BooleanVar()
        self.dark_mode = tk.BooleanVar(value=False)
        self.benchmark_data = {"pre": [], "post": [], "speedups": []}
        self.benchmark_results = {}
        
        # Set default theme
        self.set_theme()
        
        # Create main notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Create tabs
        self.main_tab = ttk.Frame(self.notebook)
        self.visualization_tab = ttk.Frame(self.notebook)
        self.decompile_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.main_tab, text="Main")
        self.notebook.add(self.visualization_tab, text="Visualization")
        self.notebook.add(self.decompile_tab, text="Decompilation")
        self.notebook.add(self.settings_tab, text="Settings")
        
        # Setup each tab
        self.setup_main_tab()
        self.setup_visualization_tab()
        self.setup_decompile_tab()
        self.setup_settings_tab()
        
        # Initialize with detection
        self.log("Launching uArchOptimizer GUI...")
        self.update_cpu_info()
        
        # Load previous benchmark results if they exist
        self.load_benchmark_history()

    def set_theme(self):
        if self.dark_mode.get():
            # Set dark theme
            self.root.configure(bg="#2d2d2d")
            self.fg_color = "#ffffff"
            self.bg_color = "#2d2d2d"
            self.highlight_color = "#3c78d8"
            self.entry_bg = "#3d3d3d"
        else:
            # Set light theme
            self.root.configure(bg="#f5f5f5")
            self.fg_color = "#000000"
            self.bg_color = "#f5f5f5"
            self.highlight_color = "#4285f4"
            self.entry_bg = "#ffffff"
            
        self.style = ttk.Style()
        self.style.configure("TFrame", background=self.bg_color)
        self.style.configure("TNotebook", background=self.bg_color)
        self.style.configure("TNotebook.Tab", background=self.bg_color, foreground=self.fg_color)
        self.style.map("TNotebook.Tab", background=[("selected", self.highlight_color)], 
                       foreground=[("selected", "#ffffff")])
        self.style.configure("TLabel", background=self.bg_color, foreground=self.fg_color)
        self.style.configure("TButton", background=self.highlight_color, foreground=self.fg_color)
        
    # ========== MAIN TAB SETUP ========== #
    def setup_main_tab(self):
        # ========== CPU Info Display ========== #
        self.cpu_frame = ttk.LabelFrame(self.main_tab, text="Detected System Info")
        self.cpu_frame.pack(padx=10, pady=5, fill="x")

        self.cpu_label = ttk.Label(self.cpu_frame, text="Processor: (unknown)", font=("Segoe UI", 10, "bold"))
        self.cpu_label.pack(fill="x", padx=5)

        self.microarch_label = ttk.Label(self.cpu_frame, text="Microarchitecture: (unknown)", font=("Segoe UI", 10, "bold"))
        self.microarch_label.pack(fill="x", padx=5)

        self.detect_button = ttk.Button(self.cpu_frame, text="Detect uArch", command=self.update_cpu_info)
        self.detect_button.pack(pady=5)

        # ========== Executable Selection ========== #
        self.file_frame = ttk.LabelFrame(self.main_tab, text="Choose Executable for Optimization Test")
        self.file_frame.pack(padx=10, pady=5, fill="x")

        self.file_path_var = tk.StringVar()
        self.file_entry = ttk.Entry(self.file_frame, textvariable=self.file_path_var, state="readonly", width=60)
        self.file_entry.pack(side="left", padx=5, pady=5)

        self.browse_button = ttk.Button(self.file_frame, text="Browse", command=self.select_file)
        self.browse_button.pack(side="right", padx=5, pady=5)

        # ========== Benchmark Options ========== #
        self.options_frame = ttk.LabelFrame(self.main_tab, text="Benchmark Options")
        self.options_frame.pack(padx=10, pady=5, fill="x")
        
        # Benchmark type selection
        self.benchmark_type_var = tk.StringVar(value="combined")
        self.benchmark_types = {
            "Combined": "combined",
            "Scalar Compute": "scalar",
            "Vector/SIMD": "vector",
            "Branch Prediction": "branch",
            "Memory Access": "memory"
        }
        
        benchmark_type_frame = ttk.Frame(self.options_frame)
        benchmark_type_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(benchmark_type_frame, text="Benchmark Type:").pack(side="left", padx=5)
        self.benchmark_type_combo = ttk.Combobox(benchmark_type_frame, 
                                                 values=list(self.benchmark_types.keys()),
                                                 textvariable=self.benchmark_type_var,
                                                 state="readonly")
        self.benchmark_type_combo.pack(side="left", padx=5)
        self.benchmark_type_combo.current(0)
        
        # Iterations
        iterations_frame = ttk.Frame(self.options_frame)
        iterations_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(iterations_frame, text="Iterations:").pack(side="left", padx=5)
        self.iterations_var = tk.StringVar(value="10000000")
        self.iterations_entry = ttk.Entry(iterations_frame, textvariable=self.iterations_var, width=15)
        self.iterations_entry.pack(side="left", padx=5)

        # ========== Benchmark Output ========== #
        self.benchmark_frame = ttk.LabelFrame(self.main_tab, text="Benchmark Results")
        self.benchmark_frame.pack(padx=10, pady=5, fill="x")

        self.benchmark_label = ttk.Label(
            self.benchmark_frame,
            text="Pre-Optimization Time: ---\nPost-Optimization Time: ---\nEstimated Speedup: ---",
            justify="left"
        )
        self.benchmark_label.pack(fill="x", padx=5, pady=5)

        button_frame = ttk.Frame(self.benchmark_frame)
        button_frame.pack(fill="x", padx=5, pady=5)

        self.run_button = ttk.Button(button_frame, text="Run Benchmark", command=self.run_benchmark)
        self.run_button.pack(side="left", padx=5)
        
        self.save_button = ttk.Button(button_frame, text="Save Results", command=self.save_benchmark_results)
        self.save_button.pack(side="left", padx=5)
        
        self.visualize_button = ttk.Button(button_frame, text="Visualize", 
                                         command=lambda: self.notebook.select(1))  # Switch to visualization tab
        self.visualize_button.pack(side="left", padx=5)

        # ========== Status Terminal ========== #
        self.terminal_frame = ttk.LabelFrame(self.main_tab, text="Status Log")
        self.terminal_frame.pack(padx=10, pady=5, fill="both", expand=True)

        self.terminal = scrolledtext.ScrolledText(self.terminal_frame, height=10, state="disabled")
        self.terminal.pack(padx=5, pady=5, fill="both", expand=True)
        
        # Debug mode checkbox
        self.debug_checkbox = ttk.Checkbutton(self.terminal_frame, text="Debug Mode", 
                                            variable=self.debug_mode)
        self.debug_checkbox.pack(anchor="w", padx=5, pady=2)
    
    # ========== VISUALIZATION TAB SETUP ========== #
    def setup_visualization_tab(self):
        # Create frames for different visualizations
        self.viz_control_frame = ttk.Frame(self.visualization_tab)
        self.viz_control_frame.pack(padx=10, pady=5, fill="x")
        
        # Visualization type selection
        ttk.Label(self.viz_control_frame, text="Visualization Type:").pack(side="left", padx=5)
        self.viz_type_var = tk.StringVar(value="speedup")
        self.viz_type_combo = ttk.Combobox(self.viz_control_frame, 
                                          values=["Speedup Comparison", "Performance Timeline", 
                                                 "Benchmark Type Comparison"],
                                          textvariable=self.viz_type_var,
                                          state="readonly")
        self.viz_type_combo.pack(side="left", padx=5)
        self.viz_type_combo.bind("<<ComboboxSelected>>", self.update_visualization)
        
        # Create frame for the plot
        self.plot_frame = ttk.Frame(self.visualization_tab)
        self.plot_frame.pack(padx=10, pady=5, fill="both", expand=True)
        
        # Initial empty plot
        self.fig, self.ax = plt.subplots(figsize=(8, 6))
        self.ax.set_title("No Benchmark Data Available")
        self.ax.set_xlabel("Run Performance Benchmarks to Generate Data")
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.plot_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        
    # ========== DECOMPILE TAB SETUP ========== #
    def setup_decompile_tab(self):
        # File selection for decompilation
        self.decomp_file_frame = ttk.Frame(self.decompile_tab)
        self.decomp_file_frame.pack(padx=10, pady=5, fill="x")
        
        ttk.Label(self.decomp_file_frame, text="Selected Executable:").pack(side="left", padx=5)
        self.decomp_file_var = tk.StringVar()
        self.decomp_file_entry = ttk.Entry(self.decomp_file_frame, textvariable=self.decomp_file_var, 
                                          state="readonly", width=50)
        self.decomp_file_entry.pack(side="left", padx=5, fill="x", expand=True)
        
        self.decomp_browse_button = ttk.Button(self.decomp_file_frame, text="Browse", 
                                             command=self.select_decompile_file)
        self.decomp_browse_button.pack(side="right", padx=5)
        
        # Decompilation options
        self.decomp_options_frame = ttk.LabelFrame(self.decompile_tab, text="Decompilation Options")
        self.decomp_options_frame.pack(padx=10, pady=5, fill="x")
        
        # Ghidra options
        self.use_ghidra_var = tk.BooleanVar(value=True)
        self.use_ghidra_check = ttk.Checkbutton(self.decomp_options_frame, text="Use Ghidra", 
                                               variable=self.use_ghidra_var)
        self.use_ghidra_check.pack(anchor="w", padx=5, pady=2)
        
        # Function filter
        function_frame = ttk.Frame(self.decomp_options_frame)
        function_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(function_frame, text="Function Filter:").pack(side="left", padx=5)
        self.function_filter_var = tk.StringVar()
        self.function_filter_entry = ttk.Entry(function_frame, textvariable=self.function_filter_var, width=30)
        self.function_filter_entry.pack(side="left", padx=5)
        ttk.Label(function_frame, text="(e.g., 'main', leave empty for all)").pack(side="left", padx=5)
        
        # Button to run decompilation
        self.run_decompile_button = ttk.Button(self.decomp_options_frame, text="Run Decompilation", 
                                             command=self.run_ghidra)
        self.run_decompile_button.pack(pady=10)
        
        # Decompilation output
        self.decomp_output_frame = ttk.LabelFrame(self.decompile_tab, text="Decompilation Output")
        self.decomp_output_frame.pack(padx=10, pady=5, fill="both", expand=True)
        
        self.decomp_output = scrolledtext.ScrolledText(self.decomp_output_frame, height=20, 
                                                     state="normal", wrap=tk.WORD)
        self.decomp_output.pack(padx=5, pady=5, fill="both", expand=True)
        
    # ========== SETTINGS TAB SETUP ========== #
    def setup_settings_tab(self):
        # Appearance settings
        self.appearance_frame = ttk.LabelFrame(self.settings_tab, text="Appearance")
        self.appearance_frame.pack(padx=10, pady=5, fill="x")
        
        self.dark_mode_check = ttk.Checkbutton(self.appearance_frame, text="Dark Mode", 
                                             variable=self.dark_mode, 
                                             command=self.set_theme)
        self.dark_mode_check.pack(anchor="w", padx=5, pady=5)
        
        # Paths settings
        self.paths_frame = ttk.LabelFrame(self.settings_tab, text="Configuration Paths")
        self.paths_frame.pack(padx=10, pady=5, fill="x")
        
        # Ghidra path
        ghidra_frame = ttk.Frame(self.paths_frame)
        ghidra_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(ghidra_frame, text="Ghidra Path:").pack(side="left", padx=5)
        self.ghidra_path_var = tk.StringVar(value=str(Path(__file__).resolve().parent.parent.parent / 
                                                     "ghidra" / "ghidra_11.2.1_PUBLIC"))
        self.ghidra_path_entry = ttk.Entry(ghidra_frame, textvariable=self.ghidra_path_var, width=50)
        self.ghidra_path_entry.pack(side="left", padx=5, fill="x", expand=True)
        
        self.ghidra_browse_button = ttk.Button(ghidra_frame, text="Browse", 
                                              command=self.browse_ghidra_path)
        self.ghidra_browse_button.pack(side="right", padx=5)
        
        # Project directory
        project_frame = ttk.Frame(self.paths_frame)
        project_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(project_frame, text="Project Directory:").pack(side="left", padx=5)
        self.project_dir_var = tk.StringVar(value=str(Path(__file__).resolve().parent / "projects"))
        self.project_dir_entry = ttk.Entry(project_frame, textvariable=self.project_dir_var, width=50)
        self.project_dir_entry.pack(side="left", padx=5, fill="x", expand=True)
        
        self.project_browse_button = ttk.Button(project_frame, text="Browse", 
                                               command=self.browse_project_path)
        self.project_browse_button.pack(side="right", padx=5)
        
        # Save settings button
        self.save_settings_button = ttk.Button(self.settings_tab, text="Save Settings", 
                                             command=self.save_settings)
        self.save_settings_button.pack(pady=10)
        
    # ========================== UTILITY FUNCTIONS ========================== #
    
    def log(self, message):
        timestamp = time.strftime("[%H:%M:%S]")
        self.terminal.configure(state="normal")
        self.terminal.insert("end", f"{timestamp} {message}\n")
        self.terminal.see("end")
        self.terminal.configure(state="disabled")

    def debug(self, message):
        if self.debug_mode.get():
            self.log(f"[DEBUG] {message}")
            
    def update_cpu_info(self):
        try:
            self.log("Detecting CPU and microarchitecture...")
            exe_path = Path(__file__).resolve().parent.parent.parent / "build" / "uArchDetector.exe"
            
            self.debug(f"Resolved EXE path: {exe_path}")
            self.debug(f"File exists: {exe_path.exists()}")

            # Check if the executable exists
            if not exe_path.exists():
                self.log(f"[ERROR] uArchDetector.exe not found at {exe_path}")
                self.cpu_label.config(text="Detected CPU: uArchDetector.exe not found")
                self.microarch_label.config(text="Microarchitecture: (unknown)")
                self.cpu_info = {"processor": "Not detected", "microarch": "Unknown"}
                return

            output = subprocess.check_output([str(exe_path)], text=True)
            lines = output.strip().splitlines()

            if len(lines) >= 2:
                self.cpu_label.config(text=lines[0])
                self.microarch_label.config(text=lines[1])
                
                # Save CPU info for reference in benchmarks
                self.cpu_info = {
                    "processor": lines[0].replace("Detected CPU: ", "").strip(),
                    "microarch": lines[1].replace("Microarchitecture: ", "").strip()
                }
            else:
                self.cpu_label.config(text="Detected CPU: (unknown)")
                self.microarch_label.config(text="Microarchitecture: (unknown)")
                self.cpu_info = {"processor": "Unknown", "microarch": "Unknown"}

            self.debug(f"CPU Output Raw:\n{output.strip()}")

        except Exception as e:
            self.cpu_label.config(text="Error detecting CPU info.")
            self.microarch_label.config(text="Microarchitecture: (unknown)")
            self.log(f"[ERROR] CPU detection failed: {e}")
            self.cpu_info = {"processor": "Error", "microarch": "Error"}

    def select_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Executables", "*.exe")])
        if file_path:
            self.file_path_var.set(file_path)
            self.decomp_file_var.set(file_path)  # Set the same file for decompilation tab
            self.log(f"Selected file: {file_path}")
            self.debug(f"Executable path absolute: {os.path.abspath(file_path)}")
            
    def select_decompile_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Executables", "*.exe")])
        if file_path:
            self.decomp_file_var.set(file_path)
            self.log(f"Selected file for decompilation: {file_path}")
            
    def browse_ghidra_path(self):
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.ghidra_path_var.set(dir_path)
            
    def browse_project_path(self):
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.project_dir_var.set(dir_path)
            
    def save_settings(self):
        try:
            settings = {
                "ghidra_path": self.ghidra_path_var.get(),
                "project_dir": self.project_dir_var.get(),
                "dark_mode": self.dark_mode.get()
            }
            
            settings_dir = Path(__file__).resolve().parent / "config"
            settings_dir.mkdir(exist_ok=True)
            
            with open(settings_dir / "settings.json", "w") as f:
                json.dump(settings, f, indent=4)
                
            self.log("Settings saved successfully.")
        except Exception as e:
            self.log(f"[ERROR] Failed to save settings: {e}")
            
    def load_settings(self):
        try:
            settings_path = Path(__file__).resolve().parent / "config" / "settings.json"
            if settings_path.exists():
                with open(settings_path, "r") as f:
                    settings = json.load(f)
                    
                self.ghidra_path_var.set(settings.get("ghidra_path", ""))
                self.project_dir_var.set(settings.get("project_dir", ""))
                self.dark_mode.set(settings.get("dark_mode", False))
                self.set_theme()
                
                self.log("Settings loaded.")
        except Exception as e:
            self.log(f"[ERROR] Failed to load settings: {e}")
    
    def run_benchmark(self):
        exe_path = self.file_path_var.get()
        if not exe_path:
            self.log("[ERROR] No executable selected.")
            return

        self.log("Starting benchmark...")
        try:
            # For demo/development, use simulated times if executable doesn't exist
            use_simulated = not os.path.exists(exe_path)
            if use_simulated:
                self.log("[NOTE] Using simulated benchmark data (executable not found)")
                # Get benchmark options
                benchmark_type = self.benchmark_types[self.benchmark_type_combo.get()]
                iterations = self.iterations_var.get()
                
                # Simulate benchmark times
                import random
                pre_time = random.uniform(2.0, 5.0)
                post_time = random.uniform(0.8, 2.0)
            else:
                # Get benchmark options
                benchmark_type = self.benchmark_types[self.benchmark_type_combo.get()]
                iterations = self.iterations_var.get()
                
                # Run pre-optimization benchmark
                self.log("Running pre-optimization benchmark...")
                pre_time = self.run_benchmark_process(exe_path, benchmark_type, iterations, False)
                
                # Run post-optimization benchmark
                self.log("Running post-optimization benchmark with optimizations...")
                post_time = self.run_benchmark_process(exe_path, benchmark_type, iterations, True)
            
            # Calculate speedup
            speedup = pre_time / post_time if post_time > 0 else 0

            # Update the results label
            result_text = f"Pre-Optimization Time: {pre_time:.6f} sec\n"
            result_text += f"Post-Optimization Time: {post_time:.6f} sec\n"
            result_text += f"Estimated Speedup: {speedup:.2f}x"
            self.benchmark_label.config(text=result_text)
            
            # Store results for visualization
            self.benchmark_results = {
                "timestamp": datetime.now().isoformat(),
                "executable": os.path.basename(exe_path),
                "cpu_info": self.cpu_info,
                "benchmark_type": self.benchmark_type_combo.get(),
                "iterations": iterations,
                "pre_time": pre_time,
                "post_time": post_time,
                "speedup": speedup
            }
            
            # Add to history
            self.benchmark_data["pre"].append(pre_time)
            self.benchmark_data["post"].append(post_time)
            self.benchmark_data["speedups"].append(speedup)
            
            # Update visualization
            self.update_visualization()

            self.log("Benchmark complete.")
            self.debug(f"Speedup calculation: {pre_time} / {post_time} = {speedup}")
            
            # Log results
            log_dir = Path(__file__).resolve().parent / "logs"
            log_dir.mkdir(exist_ok=True)
            
            with open(log_dir / "benchmark_log.txt", "a") as log_file:
                log_file.write(f"Benchmark {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                log_file.write(f"File: {exe_path}\n")
                log_file.write(f"CPU: {self.cpu_info['processor']}\n")
                log_file.write(f"Microarch: {self.cpu_info['microarch']}\n")
                log_file.write(f"Benchmark Type: {self.benchmark_type_combo.get()}\n")
                log_file.write(f"Pre: {pre_time:.6f}s | Post: {post_time:.6f}s | Speedup: {speedup:.2f}x\n\n")
                
        except Exception as e:
            self.log(f"[ERROR] Benchmark failed: {e}")
            import traceback
            self.debug(traceback.format_exc())

    def run_benchmark_process(self, exe_path, benchmark_type, iterations, optimize):
        try:
            # Construct the command
            cmd = [exe_path]
            
            # Add benchmark type flag
            if benchmark_type != "combined":
                cmd.append(f"--{benchmark_type}")
                
            # Add iterations
            cmd.extend(["--iterations", iterations])
            
            # Add optimization flag if needed
            if optimize:
                cmd.append("--optimize")
                
            self.debug(f"Running command: {' '.join(cmd)}")
            
            # Execute and time
            start = time.perf_counter()
            proc = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True, 
                bufsize=1
            )
            
            # Capture output
            output = []
            for line in iter(proc.stdout.readline, ""):
                if line.strip():
                    output.append(line.strip())
                    self.debug(f"[BENCHMARK] {line.strip()}")
            
            proc.wait()
            elapsed = time.perf_counter() - start
            
            # Extract execution time from benchmark output if available
            for line in output:
                if "Execution time:" in line:
                    try:
                        elapsed = float(line.split("Execution time:")[1].strip().split()[0])
                        break
                    except (IndexError, ValueError):
                        pass
            
            return elapsed
            
        except subprocess.TimeoutExpired:
            self.log("[ERROR] Benchmark run timed out.")
            return float('inf')
        except Exception as e:
            self.log(f"[ERROR] Benchmark process error: {e}")
            return float('inf')
            
    def save_benchmark_results(self):
        if not hasattr(self, 'benchmark_results') or not self.benchmark_results:
            self.log("[ERROR] No benchmark results to save.")
            return
            
        try:
            # Create results directory if it doesn't exist
            results_dir = Path(__file__).resolve().parent / "results"
            results_dir.mkdir(exist_ok=True)
            
            # Create filename based on timestamp and executable
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            exe_name = os.path.basename(self.file_path_var.get()).replace(".exe", "")
            filename = f"{exe_name}_{timestamp}.json"
            
            # Save results
            with open(results_dir / filename, "w") as f:
                json.dump(self.benchmark_results, f, indent=4)
                
            self.log(f"Benchmark results saved to {filename}")
        except Exception as e:
            self.log(f"[ERROR] Failed to save benchmark results: {e}")
            
    def load_benchmark_history(self):
        try:
            results_dir = Path(__file__).resolve().parent / "results"
            if not results_dir.exists():
                return
                
            # Load all result files
            history = []
            for file in results_dir.glob("*.json"):
                try:
                    with open(file, "r") as f:
                        data = json.load(f)
                        history.append(data)
                except:
                    continue
                    
            # Sort by timestamp
            history.sort(key=lambda x: x.get("timestamp", ""))
            
            # Extract data for visualization
            self.benchmark_data = {
                "pre": [h.get("pre_time", 0) for h in history],
                "post": [h.get("post_time", 0) for h in history],
                "speedups": [h.get("speedup", 0) for h in history],
                "types": [h.get("benchmark_type", "Unknown") for h in history],
                "executables": [h.get("executable", "Unknown") for h in history],
                "timestamps": [h.get("timestamp", "") for h in history]
            }
            
            self.log(f"Loaded {len(history)} benchmark results from history.")
            
            # Update visualization if we have data
            if history:
                self.update_visualization()
                
        except Exception as e:
            self.log(f"[ERROR] Failed to load benchmark history: {e}")
            
    def update_visualization(self, event=None):
        try:
            # Clear the current plot
            self.ax.clear()
            
            # Check if we have data
            if not self.benchmark_data["pre"]:
                self.ax.set_title("No Benchmark Data Available")
                self.ax.set_xlabel("Run Performance Benchmarks to Generate Data")
                self.canvas.draw()
                return
                
            # Get the selected visualization type
            viz_type = self.viz_type_var.get()
            
            if viz_type == "Speedup Comparison" or not viz_type:
                # Plot speedup comparison
                x = np.arange(len(self.benchmark_data["speedups"]))
                self.ax.bar(x, self.benchmark_data["speedups"], color='#3498db')
                self.ax.set_title("Benchmark Speedup Comparison")
                self.ax.set_ylabel("Speedup Factor (x)")
                self.ax.set_xlabel("Benchmark Run")
                
                # Add labels with executable names
                if self.benchmark_data.get("executables"):
                    self.ax.set_xticks(x)
                    self.ax.set_xticklabels([f"Run {i+1}" for i in range(len(x))], rotation=45, ha="right")
                    
                # Add a reference line at y=1
                self.ax.axhline(y=1, color='r', linestyle='-', alpha=0.3)
                
                for i, v in enumerate(self.benchmark_data["speedups"]):
                    self.ax.text(i, v + 0.1, f"{v:.2f}x", ha='center')
                    
            elif viz_type == "Performance Timeline":
                # Plot performance timeline
                x = np.arange(len(self.benchmark_data["pre"]))
                width = 0.35
                
                self.ax.bar(x - width/2, self.benchmark_data["pre"], width, label='Pre-Optimization', color='#e74c3c')
                self.ax.bar(x + width/2, self.benchmark_data["post"], width, label='Post-Optimization', color='#2ecc71')
                
                self.ax.set_title("Performance Timeline Comparison")
                self.ax.set_ylabel("Execution Time (seconds)")
                self.ax.set_xlabel("Benchmark Run")
                
                # Add labels
                if self.benchmark_data.get("executables"):
                    self.ax.set_xticks(x)
                    self.ax.set_xticklabels([f"Run {i+1}" for i in range(len(x))], rotation=45, ha="right")
                
                self.ax.legend()
                
            elif viz_type == "Benchmark Type Comparison":
                # Group by benchmark type
                types = {}
                for i, btype in enumerate(self.benchmark_data.get("types", [])):
                    if btype not in types:
                        types[btype] = {"pre": [], "post": [], "speedup": []}
                    types[btype]["pre"].append(self.benchmark_data["pre"][i])
                    types[btype]["post"].append(self.benchmark_data["post"][i])
                    types[btype]["speedup"].append(self.benchmark_data["speedups"][i])
                
                # Calculate averages
                avg_speedups = []
                type_names = []
                
                for btype, data in types.items():
                    if data["speedup"]:
                        avg_speedups.append(sum(data["speedup"]) / len(data["speedup"]))
                        type_names.append(btype)
                
                # Plot
                x = np.arange(len(type_names))
                self.ax.bar(x, avg_speedups, color='#9b59b6')
                self.ax.set_title("Average Speedup by Benchmark Type")
                self.ax.set_ylabel("Average Speedup Factor (x)")
                self.ax.set_xlabel("Benchmark Type")
                
                # Add labels
                self.ax.set_xticks(x)
                self.ax.set_xticklabels(type_names, rotation=45, ha="right")
                
                for i, v in enumerate(avg_speedups):
                    self.ax.text(i, v + 0.1, f"{v:.2f}x", ha='center')
            
            # Update the plot
            self.ax.grid(True, linestyle='--', alpha=0.7)
            self.fig.tight_layout()
            self.canvas.draw()
            
        except Exception as e:
            self.log(f"[ERROR] Failed to update visualization: {e}")
            import traceback
            self.debug(traceback.format_exc())
            
    def run_ghidra(self):
        exe_path = self.decomp_file_var.get()
        if not exe_path:
            self.log("[ERROR] No executable selected for decompilation.")
            return

        def ghidra_worker():
            self.log("Launching Ghidra headless decompilation...")
            try:
                # Get the Ghidra directory from settings
                ghidra_dir = Path(self.ghidra_path_var.get())
                
                analyze_script = ghidra_dir / "support" / "analyzeHeadless.bat"
                if not analyze_script.exists():
                    self.log(f"[ERROR] Ghidra script not found at: {analyze_script}")
                    return

                # Get project directory from settings
                project_dir = Path(self.project_dir_var.get())
                project_dir.mkdir(exist_ok=True)
                
                project_name = "uArchOptimizerProject"
                
                # Create a timestamped log filename
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                exe_name = Path(exe_path).stem
                log_filename = f"ghidra_{exe_name}_{timestamp}.log"
                log_path = Path(__file__).resolve().parent / "logs" / log_filename
                
                # Ensure logs directory exists
                log_dir = Path(__file__).resolve().parent / "logs"
                log_dir.mkdir(exist_ok=True)
                
                # Get function filter if any
                function_filter = self.function_filter_var.get()
                
                # Create DecompileFunction.java script dynamically
                script_path = Path(__file__).resolve().parent / "scripts"
                script_path.mkdir(exist_ok=True)
                
                # Simple script to decompile specific functions or all functions
                decompile_script = """import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;

public class DecompileFunction extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("Starting decompilation...");
        
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        
        String filter = "%s"; // Function filter from GUI
        
        FunctionManager functionManager = currentProgram.getFunctionManager();
        for (Function function : functionManager.getFunctions(true)) {
            try {
                String funcName = function.getName();
                
                // Apply filter if it exists
                if (!"".equals(filter) && !funcName.contains(filter)) {
                    continue;
                }
                
                println("\\n==== DECOMPILING: " + funcName + " ====");
                println("Address: " + function.getEntryPoint());
                
                // Get decompiled code
                DecompileResults results = decompiler.decompileFunction(function, 30, null);
                
                if (results.decompileCompleted()) {
                    println(results.getDecompiledFunction().getC());
                } else {
                    println("Failed to decompile. Errors:");
                    for (String error : results.getErrorMessages()) {
                        println("  " + error);
                    }
                }
            } catch (Exception e) {
                println("Error decompiling " + function.getName() + ": " + e.getMessage());
            }
        }
        
        println("\\nDecompilation complete.");
    }
}
""" % function_filter
                
                # Write the script to disk
                script_file = script_path / "DecompileFunction.java"
                with open(script_file, "w") as f:
                    f.write(decompile_script)
                    
                self.debug(f"Created decompilation script at: {script_file}")
                
                # Build the command
                cmd = [
                    str(analyze_script),
                    str(project_dir),
                    project_name,
                    "-import", exe_path,
                    "-postScript", str(script_file)
                ]

                self.debug(f"Ghidra CMD: {' '.join(cmd)}")
                
                # Clear the output text
                self.decomp_output.delete(1.0, tk.END)
                self.decomp_output.insert(tk.END, "Starting Ghidra decompilation...\n\n")
                
                # Run Ghidra headless
                with open(log_path, "w", encoding="utf-8") as logfile:
                    process = subprocess.Popen(
                        cmd, 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.STDOUT, 
                        text=True, 
                        bufsize=1
                    )
                    
                    # Process output lines
                    for line in iter(process.stdout.readline, ""):
                        if line.strip():
                            # Write to log file
                            logfile.write(line)
                            
                            # Update GUI
                            self.root.after(0, self.log, f"[GHIDRA] {line.strip()}")
                            self.root.after(0, self.update_decomp_output, line)
                    
                    process.wait()

                # Complete notification
                self.root.after(0, self.log, f"Ghidra decompilation complete. Log saved to: {log_path.name}")
                self.root.after(0, self.update_decomp_output, "\n--- DECOMPILATION COMPLETE ---\n")

            except Exception as e:
                self.root.after(0, self.log, f"[ERROR] Ghidra decompilation failed: {e}")
                import traceback
                self.root.after(0, self.debug, traceback.format_exc())

        # Start decompilation in a separate thread
        threading.Thread(target=ghidra_worker, daemon=True).start()
        
    def update_decomp_output(self, line):
        """Update the decompilation output text widget"""
        self.decomp_output.insert(tk.END, line)
        self.decomp_output.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = uArchOptimizerGUI(root)
    
    # Load saved settings if available
    app.load_settings()
    
    # Center the window
    window_width = 900
    window_height = 700
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    center_x = int(screen_width/2 - window_width/2)
    center_y = int(screen_height/2 - window_height/2)
    root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
    
    root.mainloop()