# Active DLL & Process Validator

A Python graphical user interface (GUI) application that scans running processes and their loaded DLLs on a local Windows machine. It displays information including Process ID (PID), name, type (Process/DLL), full path, SHA256 hash, and digital signature status.

The tool is designed to run **entirely offline**, performing signature checks without contacting external servers.

## Features

*   Lists running processes and their associated loaded DLLs.
*   Calculates the SHA256 hash for process executables and DLL files.
*   Checks the Authenticode digital signature status (Signed, Not Signed/Invalid, Error) using the native Windows API (`WinVerifyTrust`).
*   GUI built with Python's standard `tkinter` library.
*   Real-time filtering of results via a search bar (searches all columns).
*   Sort results by clicking column headers (cycles through ascending/descending).
*   Copy selected rows to the clipboard (Ctrl+C) with automatic column alignment for easy pasting into text editors or spreadsheets.
*   Includes an "About" dialog crediting the author.

## Requirements

*   **Operating System:** Windows (required for `pywin32` signature checking).
*   **Python:** Python 3.6 or newer recommended.
*   **Python Packages:** `psutil`, `pywin32` (see `requirements.txt`).

## Installation

1.  **Save the Code:** Save the Python script provided earlier to a file named `process_scanner_gui.py` (or your preferred name).
2.  **Save Requirements:** Save the `requirements.txt` content above into a file named `requirements.txt` in the same directory as the script.
3.  **Open Terminal:** Open a command prompt or PowerShell terminal in the directory where you saved the files.
4.  **Install Dependencies:** Run the following command:
    ```bash
    pip install -r requirements.txt
    ```
    *Note: If you encounter issues with `pywin32`, sometimes running `python Scripts/pywin32_postinstall.py -install` from your Python environment's directory with administrator privileges might be necessary, although `pip` usually handles this correctly now.*

## Usage

1.  **Run as Administrator:** For the tool to access information about all processes (including system processes) and their modules, and to perform signature checks reliably, it's **highly recommended** to run the script with administrator privileges.
    *   Right-click the `.py` script file and select "Run as administrator".
    *   Alternatively, open a command prompt or PowerShell *as Administrator* and run the script:
        ```bash
        python main.py
        ```
2.  **GUI Controls:**
    *   **Start Scan:** Click this button to begin scanning all running processes and their loaded modules. This may take some time depending on the number of processes and system speed. The button will be disabled during the scan.
    *   **Filter:** Type text into this box. The table will update in real-time, showing only rows where the typed text appears in *any* of the columns (case-insensitive). Clear the box to show all results again.
    *   **Results Table:**
        *   Displays the scanned information.
        *   Click any column header to sort the *currently displayed* rows by that column. Clicking the same header again reverses the sort order. An arrow (▲/▼) indicates the sorted column and direction.
        *   Select one or more rows (use Shift+Click or Ctrl+Click for multiple selection).
        *   Press **Ctrl+C** to copy the data of the selected row(s) to the clipboard. The data will be formatted with spaces to align columns when pasted into a monospaced font environment.
    *   **About:** Click this button to display program information and attribution.
    *   **Status Bar:** Shows the current status (Idle, Scanning, Scan Complete, Filtered results count, Copy confirmation).

## Offline Operation

The digital signature check uses the Windows `WinVerifyTrust` API. Crucially, it is called with the `WTD_REVOKE_NONE` flag, which explicitly prevents the system from performing online checks (like CRL or OCSP lookups) for certificate revocation. This ensures the tool operates fully offline, relying only on the signature data embedded in the files and the local certificate stores.

## Author

Process & Active DLL Scanner by dannythedev.

## License

Freeware.