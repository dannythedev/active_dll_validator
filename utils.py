import os
import hashlib
import sys

# --- pywin32 check and check_signature function ---
PYWIN32_AVAILABLE = False
# Default placeholder function
def check_signature(filename):
    return "N/A (pywin32 missing)"

# Only attempt pywin32 imports on Windows
if sys.platform == 'win32':
    try:
        from win32api import GetFileVersionInfo, LOWORD, HIWORD
        from wintrust import (
            WTD_UI_NONE, WTD_REVOKE_NONE, WTD_CHOICE_FILE,
            WTD_STATEACTION_VERIFY, WTD_PROVIDER_DLL,
            WINTRUST_ACTION_GENERIC_VERIFY_V2, WTD_STATEACTION_CLOSE
        )
        import pywintypes
        import winerror
        import wintrust

        # Define the WinVerifyTrust function (simplified signature check)
        def check_signature_win32(filename):
            if not os.path.exists(filename):
                return "File Not Found"
            try:
                file_info = pywintypes.WINTRUST_FILE_INFO()
                file_info.pcwszFilePath = filename
                file_info.hFile = None
                file_info.pgKnownSubject = None

                trust_data = pywintypes.WINTRUST_DATA()
                trust_data.cbStruct = pywintypes.sizeof(trust_data)
                trust_data.dwUIChoice = WTD_UI_NONE
                trust_data.fdwRevocationChecks = WTD_REVOKE_NONE # No online check
                trust_data.dwUnionChoice = WTD_CHOICE_FILE
                trust_data.dwStateAction = WTD_STATEACTION_VERIFY
                trust_data.dwProvFlags = 0
                trust_data.pPolicyCallbackData = None
                trust_data.pSIPClientData = None
                trust_data.dwUIContext = 0
                trust_data.lpFileInfo = file_info

                action_id = WINTRUST_ACTION_GENERIC_VERIFY_V2
                result = wintrust.WinVerifyTrust(0, action_id, trust_data)

                # Cleanup
                trust_data.dwStateAction = WTD_STATEACTION_CLOSE
                wintrust.WinVerifyTrust(0, action_id, trust_data)

                TRUST_E_NOSIGNATURE = -2146869246 # 0x800B0100
                TRUST_E_SUBJECT_FORM_UNKNOWN = -2146869244 # 0x800B0104
                TRUST_E_PROVIDER_UNKNOWN = -2146869243 # 0x800B0105
                TRUST_E_BAD_DIGEST = -2146869232 # 0x800B0110
                TRUST_E_SUBJECT_NOT_TRUSTED = -2146762487 # 0x800B0009

                if result == winerror.ERROR_SUCCESS:
                    return "Signed"
                elif result in (TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN,
                                TRUST_E_PROVIDER_UNKNOWN, winerror.CERT_E_CHAINING,
                                TRUST_E_BAD_DIGEST, TRUST_E_SUBJECT_NOT_TRUSTED):
                    return "Not Signed / Invalid"
                else:
                    return f"Check Error ({result:#0x})"

            except FileNotFoundError: return "File Not Found"
            except PermissionError: return "Access Denied"
            except pywintypes.error as e:
                 if e.winerror == winerror.E_ACCESSDENIED: return "Access Denied"
                 if e.winerror == -2146885629: return "WinTrust Provider Error" # 0x80092003
                 return f"WinTrust Error ({e.winerror:#0x})"
            except Exception as e:
                # Catch potential issues like buffer too small, etc.
                return f"Check Error ({type(e).__name__})"

        # Overwrite the placeholder if imports succeed
        check_signature = check_signature_win32
        PYWIN32_AVAILABLE = True

    except ImportError:
        print("WARNING: pywin32 library not found or failed to import.")
        print("         Digital signature checking will be disabled.")
        print("         Install it using: pip install pywin32")
        # check_signature remains the placeholder, PYWIN32_AVAILABLE remains False

# --- calculate_sha256 function ---
def calculate_sha256(filepath):
    """Calculates the SHA256 hash of a file."""
    if not os.path.exists(filepath):
        return "File Not Found"
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except PermissionError:
        return "Access Denied"
    except OSError as e:
        # print(f"OS Error hashing {filepath}: {e}") # Debugging
        return f"Hashing Error (OS: {e.errno})"
    except Exception as e:
        # print(f"Unexpected error hashing {filepath}: {e}") # Debugging
        return f"Hashing Error ({type(e).__name__})"