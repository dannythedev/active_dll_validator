import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue

# Import necessary components from other modules
from utils import PYWIN32_AVAILABLE
import scanner # Import the scanner module

class ProcessScannerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Process & Active DLL Validator")
        self.master.geometry("1050x650")

        self.scan_queue = queue.Queue()
        self.all_results = []
        self.running_scan = False

        # Sort State
        self.sort_column_id = None
        self.sort_reverse = False
        self.column_ids = ("PID", "Name", "Type", "Path", "SHA256", "Signature")

        self._setup_gui() # Renamed internal setup method

        # Check dependency status after GUI is built
        if not PYWIN32_AVAILABLE:
            messagebox.showwarning("Dependency Missing",
                                   "pywin32 missing or failed to load.\nSignature checking disabled.\nInstall: pip install pywin32")

        # Start the queue processor
        self.master.after(100, self._process_queue)

    def _setup_gui(self):
        # Controls Frame
        self.control_frame = ttk.Frame(self.master, padding="10")
        self.control_frame.pack(fill=tk.X)

        # Left controls
        self.scan_button = ttk.Button(self.control_frame, text="Start Scan", command=self.start_scan_thread)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        self.search_label = ttk.Label(self.control_frame, text="Filter:")
        self.search_label.pack(side=tk.LEFT, padx=(10, 5))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(self.control_frame, textvariable=self.search_var, width=40)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.search_var.trace_add("write", self._handle_search_change)

        # Right controls
        self.about_button = ttk.Button(self.control_frame, text="About", command=self._show_about_dialog)
        self.about_button.pack(side=tk.RIGHT, padx=(10, 0))

        # Status label
        self.status_label = ttk.Label(self.control_frame, text="Status: Idle", relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 10))

        # Treeview Frame
        self.tree_frame = ttk.Frame(self.master, padding=(10, 0, 10, 10))
        self.tree_frame.pack(fill=tk.BOTH, expand=True)

        # Treeview Widget
        self.tree = ttk.Treeview(
            self.tree_frame, columns=self.column_ids, show="headings", selectmode="extended"
        )
        headings_props = { "PID": {"width": 60, "anchor": tk.W}, "Name": {"width": 180, "anchor": tk.W}, "Type": {"width": 60, "anchor": tk.W}, "Path": {"width": 350, "anchor": tk.W}, "SHA256": {"width": 150, "anchor": tk.W}, "Signature": {"width": 100, "anchor": tk.W} }
        for col in self.column_ids:
            props = headings_props.get(col, {"width": 100, "anchor": tk.W})
            self.tree.heading(col, text=col, anchor=props["anchor"], command=lambda _col=col: self._sort_column(_col))
            self.tree.column(col, width=props["width"], anchor=props["anchor"], stretch=tk.NO)

        # Scrollbars
        self.vsb = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        self.hsb = ttk.Scrollbar(self.tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=self.vsb.set, xscrollcommand=self.hsb.set)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Bindings
        self.tree.bind("<Control-c>", self._copy_selection_to_clipboard)
        self.search_entry.focus_set()

    # --- Public Methods / Event Handlers ---

    def start_scan_thread(self):
        """Starts the background scanning process."""
        if self.running_scan:
            messagebox.showwarning("Scan in Progress", "A scan is already running.")
            return
        self.running_scan = True
        self.all_results = []
        self._clear_treeview()
        self.scan_button.config(state=tk.DISABLED)
        self._set_status("Scanning...")
        # Run scanner.perform_scan in a thread
        self.scan_thread = threading.Thread(target=scanner.perform_scan,
                                           args=(self.scan_queue,),
                                           daemon=True)
        self.scan_thread.start()

    # --- Internal Methods / Callbacks (prefixed with _) ---

    def _show_about_dialog(self):
        """Displays the About information box."""
        messagebox.showinfo(
            title="About Process Scanner",
            message=            "Process & Active DLL Validator\n\n"
            "This tool inspects running Windows processes and their loaded modules (DLLs).\n\n"
            "It displays the file path, calculates the SHA256 hash, "
            "and verifies the digital signature status offline for "
            "both executables and loaded libraries, to verify integrity.\n\n"
            "Developed by dannythedev."  # Keep your attribution here # Ensure your name is here
        )


    def _copy_selection_to_clipboard(self, event=None):
        """Copies the selected row(s) data to the clipboard, aligned."""
        selected_iids = self.tree.selection()
        if not selected_iids:
            self._set_status("No rows selected to copy.")
            return
        # (Keep the detailed aligned copy logic from the previous answer here)
        selected_rows_data = [self.tree.item(iid, 'values') for iid in selected_iids]
        if not selected_rows_data: return
        num_columns = len(self.column_ids)
        if num_columns == 0: return
        max_widths = [0] * num_columns
        for row_values in selected_rows_data:
            processed_values = list(row_values) + [None] * (num_columns - len(row_values))
            for i, value in enumerate(processed_values):
                 cell_width = len(str(value))
                 if cell_width > max_widths[i]: max_widths[i] = cell_width
        formatted_lines = []
        column_separator = "  "
        for row_values in selected_rows_data:
            padded_cells = []
            processed_values = list(row_values) + [None] * (num_columns - len(row_values))
            for i, value in enumerate(processed_values):
                cell_str = str(value)
                padded_cell = cell_str.ljust(max_widths[i])
                padded_cells.append(padded_cell)
            formatted_lines.append(column_separator.join(padded_cells))
        clipboard_string = "\n".join(formatted_lines)
        try:
            self.master.clipboard_clear()
            self.master.clipboard_append(clipboard_string)
            self._set_status(f"Copied {len(selected_iids)} aligned row(s) to clipboard.")
        except tk.TclError:
             self._set_status("Error: Could not access clipboard.")
             messagebox.showerror("Clipboard Error", "Failed to copy data to clipboard.")

    def _get_sort_key(self, item_value, col_id):
        """Generate a sortable key, handling types appropriately."""
        if item_value is None: return ""
        value_str = str(item_value)
        if col_id == "PID":
            try: return int(value_str)
            except (ValueError, TypeError): return -1 # Treat non-int PIDs consistently
        else: return value_str.lower() # Case-insensitive string sort

    def _sort_column(self, col_id, keep_reverse_state=False):
        """Sort treeview contents when a column header is clicked."""
        if not col_id: return
        if not keep_reverse_state:
            if self.sort_column_id == col_id: self.sort_reverse = not self.sort_reverse
            else: self.sort_reverse = False
            self.sort_column_id = col_id

        items = [(self.tree.set(iid, col_id), iid) for iid in self.tree.get_children('')]
        try:
            items.sort(key=lambda item: self._get_sort_key(item[0], col_id), reverse=self.sort_reverse)
        except Exception as e:
            print(f"Error during sort: {e}") # Avoid crashing on unexpected sort data
            return # Abort sort if key function fails

        for index, (val, iid) in enumerate(items):
            try:
                self.tree.move(iid, '', index)
            except tk.TclError:
                # Item might have vanished between get_children and move
                # print(f"Warning: Item {iid} disappeared during sort.")
                continue
        self._update_sort_indicator()

    def _update_sort_indicator(self):
        """Add ▲ or ▼ to the currently sorted column header."""
        for col in self.column_ids:
            current_text = col
            if col == self.sort_column_id:
                arrow = " ▼" if self.sort_reverse else " ▲"
                current_text += arrow
            # Re-apply command binding as changing text might clear it
            try:
                 self.tree.heading(col, text=current_text, command=lambda _col=col: self._sort_column(_col))
            except tk.TclError:
                # Can happen if tree is destroyed during update? Unlikely here.
                print(f"Warning: Failed to update heading for column {col}")


    def _set_status(self, message):
        self.status_label.config(text=f"Status: {message}")

    def _clear_treeview(self):
        try:
            self.tree.delete(*self.tree.get_children())
        except tk.TclError:
             # Handle cases where the tree might be destroyed during clear
            print("Warning: Treeview cleared while potentially being destroyed.")


    def _add_item_to_treeview(self, item_data):
        try:
             self.tree.insert("", tk.END, values=item_data)
        except tk.TclError:
            # Handle cases where the tree might be destroyed during insert
            print("Warning: Item added while treeview potentially being destroyed.")


    def _handle_search_change(self, *args):
        self._apply_filter_or_refresh()

    def _apply_filter_or_refresh(self):
        """Clears, repopulates treeview based on filter, then applies current sort."""
        search_term = self.search_var.get().strip().lower()
        self._clear_treeview()
        count = 0
        filtered_data = []

        if self.all_results:
            for item_data in self.all_results:
                match = False
                if not search_term: match = True
                else:
                    try: # Check if search term is in any value (converted to string)
                        if any(search_term in str(val).lower() for val in item_data):
                            match = True
                    except Exception: continue # Ignore errors comparing item data
                if match:
                    filtered_data.append(item_data)
                    count += 1

        # Batch insert might be slightly faster for large redraws, but individual is fine
        for item_data in filtered_data:
            self._add_item_to_treeview(item_data)

        # Apply sort if needed
        if self.sort_column_id:
            self._sort_column(self.sort_column_id, keep_reverse_state=True)
        else: # Ensure headers are correct even if no sort active
            self._update_sort_indicator()

        # Update status
        total_items = len(self.all_results)
        visible_items = count # Items just added are the visible ones now
        status_text = ""
        if search_term: status_text = f"Filtered: {visible_items} of {total_items} items match."
        elif self.running_scan: status_text = f"Scan in progress... {total_items} items found."
        else: status_text = f"Scan Complete. Showing {visible_items} of {total_items} items."
        self._set_status(status_text)

    def _process_queue(self):
        """Processes items from the scanner thread queue."""
        items_processed_this_cycle = 0
        try:
            while True: # Process all items currently in queue
                item_data = self.scan_queue.get_nowait()
                if item_data is None: # Sentinel: Scan finished
                    self._scan_finished()
                    break # Exit loop for this cycle
                else:
                    self.all_results.append(item_data)
                    items_processed_this_cycle += 1
        except queue.Empty:
            pass # No more items for now
        except Exception as e:
            print(f"Error processing queue: {e}")


        # Optionally update status less frequently during scan
        if self.running_scan and items_processed_this_cycle > 0:
             self._set_status(f"Scanning... {len(self.all_results)} items found so far.")

        # Reschedule check
        self.master.after(100, self._process_queue)

    def _scan_finished(self):
        """Actions to perform when the scan worker thread completes."""
        self.running_scan = False
        try:
            self.scan_button.config(state=tk.NORMAL)
        except tk.TclError:
             print("Warning: Scan button state update failed (widget destroyed?).")
        self._apply_filter_or_refresh() # Show results and update status