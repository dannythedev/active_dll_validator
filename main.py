import tkinter as tk
from tkinter import messagebox
import sys
import os

# Check admin privileges (Windows specific)
def is_admin_windows():
    """Checks for administrator privileges on Windows."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

# Import the GUI application class AFTER potential admin check logic
from GUI import ProcessScannerApp

if __name__ == "__main__":
    admin_required = True # Set to False if admin isn't strictly needed but recommended
    is_admin = False

    if sys.platform == 'win32':
        is_admin = is_admin_windows()
        if admin_required and not is_admin:
            print("ERROR: Administrator privileges are recommended for full functionality.")
            # Optionally, show a message box immediately or try to relaunch as admin
            # For simplicity, we'll just print and show a warning later in the GUI.
            # sys.exit("Relaunch as administrator.")

    elif os.geteuid() == 0: # Basic root check for Linux/macOS (though app targets Windows)
        is_admin = True


    # Set up the main Tkinter window
    root = tk.Tk()
    app = ProcessScannerApp(root) # Instantiate the GUI

    # Show non-admin warning within the GUI context if applicable
    if sys.platform == 'win32' and not is_admin:
         root.after(200, lambda: messagebox.showwarning(
             "Permissions",
             "Not running as Administrator.\n"
             "Some process details or signature checks might fail due to insufficient permissions."
         ))

    # Start the Tkinter event loop
    root.mainloop()