import os
import psutil
import time # Optional for timing/debugging

from utils import calculate_sha256, check_signature

def perform_scan(output_queue):
    """
    Scans running processes and their memory maps for executables and DLLs.
    Puts result tuples onto the output_queue.
    Signals completion by putting None onto the queue.
    """
    processed_files = set()
    # scan_start_time = time.time() # Optional

    # Request necessary attributes including memory_maps
    try:
        process_iterator = psutil.process_iter(['pid', 'name', 'exe', 'memory_maps'])
    except Exception as e:
        print(f"ERROR: Failed to initialize process iteration: {e}")
        output_queue.put(None) # Signal immediate failure/completion
        return

    for proc in process_iterator:
        # --- Start of Process Loop ---
        pid = proc.info['pid']
        proc_name = proc.info['name'] or "N/A"
        exe_path = proc.info['exe']
        process_entry_added = False # Track if we added the main process row

        # --- Process Executable ---
        try:
            if exe_path and os.path.isfile(exe_path) and exe_path not in processed_files:
                file_hash = calculate_sha256(exe_path)
                signature = check_signature(exe_path)
                output_queue.put((pid, proc_name, "Process", exe_path, file_hash, signature))
                processed_files.add(exe_path)
                process_entry_added = True
            elif exe_path and exe_path not in processed_files: # Path exists but isn't file/accessible
                 output_queue.put((pid, proc_name, "Process", exe_path, "Path Invalid/Inaccessible", "N/A"))
                 processed_files.add(exe_path)
                 process_entry_added = True
            elif not exe_path and pid is not None: # Process exists but no exe path
                 type_str = "System" if proc_name in ("System Idle Process", "System", "Registry") else "Process"
                 output_queue.put((pid, proc_name, type_str, "N/A", "N/A", "N/A"))
                 process_entry_added = True
        except Exception as e:
             # Error processing the executable itself
             if not process_entry_added and pid is not None:
                  output_queue.put((pid, proc_name, "Process", exe_path or "N/A", f"Exe Error ({type(e).__name__})", "Error"))
                  if exe_path: processed_files.add(exe_path) # Avoid reprocessing error


        # --- Process Mapped Files (DLLs, etc.) ---
        try:
            # Make sure memory_maps is not None before iterating
            mapped_files = proc.info['memory_maps']
            if mapped_files is None:
                 # This implies access was denied at the iterator level for maps
                 raise psutil.AccessDenied(pid=pid, name=proc_name, msg="memory_maps fetch denied")

            for mmap in mapped_files:
                dll_path = mmap.path
                if (dll_path and
                    os.path.isfile(dll_path) and # Check it's an actual file
                    dll_path not in processed_files and
                    dll_path != exe_path): # Avoid reprocessing the main exe if mapped

                    file_hash = calculate_sha256(dll_path)
                    signature = check_signature(dll_path)
                    dll_name = os.path.basename(dll_path)
                    output_queue.put((pid, dll_name, "DLL", dll_path, file_hash, signature))
                    processed_files.add(dll_path)

        # --- Exception Handling for Maps ---
        except psutil.AccessDenied:
             # Add placeholder only if main process entry wasn't added AND we have PID/Name
             if not process_entry_added and pid is not None and proc_name != "N/A":
                 output_queue.put((pid, proc_name, "Process", exe_path or "N/A", "Modules Access Denied", "N/A"))
        except psutil.NoSuchProcess:
            continue # Process ended, skip to next in iterator
        except FileNotFoundError:
             continue # Mapped path vanished, skip this map entry
        except OSError as e:
             # Log OS error during map processing if process wasn't added
             if not process_entry_added and pid is not None and proc_name != "N/A":
                output_queue.put((pid, proc_name, "Process", exe_path or "N/A", f"Map Read OS Error ({e.errno})", "Error"))
        except Exception as e: # Catch-all for unexpected map processing errors
             # print(f"DEBUG: Unexpected map error for PID {pid} ({proc_name}): {e}") # Debugging
             if not process_entry_added and pid is not None and proc_name != "N/A":
                output_queue.put((pid, proc_name, "Process", exe_path or "N/A", f"Map Error ({type(e).__name__})", "Error"))
        # --- End of Process Loop ---

    # --- Signal Completion ---
    output_queue.put(None)
    # scan_end_time = time.time() # Optional
    # print(f"Scan worker finished in {scan_end_time - scan_start_time:.2f} seconds.")