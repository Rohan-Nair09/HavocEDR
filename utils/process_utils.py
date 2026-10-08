import os
import hashlib
import logging
from abc import ABC, abstractmethod
import ctypes
from ctypes import wintypes

logger = logging.getLogger(__name__)

# --- Interfaces ---

class ISignatureVerifier(ABC):
    """Interface for digital signature verification."""
    @abstractmethod
    def verify(self, file_path: str) -> str:
        """Returns the signature status as a string (e.g., 'Valid', 'Invalid', 'Unsigned')."""
        pass

# --- Implementations ---

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_uint8 * 8)
    ]

class WindowsSignatureVerifier(ISignatureVerifier):
    """
    Windows Authenticode signature verifier using WinVerifyTrust via ctypes.
    Abstracted so it can be swapped later if needed.
    """
    def __init__(self):
        # Define necessary constants and structures for WinVerifyTrust
        self.WTD_UI_NONE = 2
        self.WTD_REVOKE_NONE = 0
        self.WTD_CHOICE_FILE = 1
        self.WTD_STATEACTION_IGNORE = 0
        self.WTD_UICONTEXT_EXECUTE = 0

        # Action ID for WINTRUST_ACTION_GENERIC_VERIFY_V2
        self.WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
            0x00AAC56B, 0xCD44, 0x11d0, 
            (ctypes.c_uint8 * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
        )

    def verify(self, file_path: str) -> str:
        if not os.path.exists(file_path):
            return "File Not Found"

        try:
            # We use ctypes here as a standard robust way on Windows.
            # While the user mentioned pywin32, WinVerifyTrust is most reliably called via ctypes windll.
            # (pywin32's win32crypt doesn't directly expose WinVerifyTrust easily).
            
            class WINTRUST_FILE_INFO(ctypes.Structure):
                _fields_ = [
                    ("cbStruct", wintypes.DWORD),
                    ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE),
                    ("pgKnownSubject", ctypes.POINTER(GUID)),
                ]

            class WINTRUST_DATA(ctypes.Structure):
                _fields_ = [
                    ("cbStruct", wintypes.DWORD),
                    ("pPolicyCallbackData", wintypes.LPVOID),
                    ("pSIPClientData", wintypes.LPVOID),
                    ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD),
                    ("dwUnionChoice", wintypes.DWORD),
                    ("pInfo", ctypes.POINTER(WINTRUST_FILE_INFO)),
                    ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE),
                    ("pwszURLReference", wintypes.LPCWSTR),
                    ("dwProvFlags", wintypes.DWORD),
                    ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", wintypes.LPVOID),
                ]

            wintrust = ctypes.windll.wintrust
            wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.POINTER(WINTRUST_DATA)]
            wintrust.WinVerifyTrust.restype = wintypes.LONG

            file_info = WINTRUST_FILE_INFO()
            file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
            file_info.pcwszFilePath = file_path
            file_info.hFile = None
            file_info.pgKnownSubject = None

            trust_data = WINTRUST_DATA()
            trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
            trust_data.pPolicyCallbackData = None
            trust_data.pSIPClientData = None
            trust_data.dwUIChoice = self.WTD_UI_NONE
            trust_data.fdwRevocationChecks = self.WTD_REVOKE_NONE
            trust_data.dwUnionChoice = self.WTD_CHOICE_FILE
            trust_data.pInfo = ctypes.pointer(file_info)
            trust_data.dwStateAction = self.WTD_STATEACTION_IGNORE
            trust_data.hWVTStateData = None
            trust_data.pwszURLReference = None
            trust_data.dwProvFlags = 0
            trust_data.dwUIContext = self.WTD_UICONTEXT_EXECUTE
            trust_data.pSignatureSettings = None

            result = wintrust.WinVerifyTrust(
                None, 
                ctypes.byref(self.WINTRUST_ACTION_GENERIC_VERIFY_V2), 
                ctypes.byref(trust_data)
            )

            # 0 is ERROR_SUCCESS meaning the file is trusted and signed
            if result == 0:
                return "Valid"
            elif result == -2146762496: # TRUST_E_NOSIGNATURE
                return "Unsigned"
            else:
                return f"Invalid ({hex(result & 0xFFFFFFFF)})"

        except Exception as e:
            logger.debug(f"Failed to verify signature for {file_path}: {e}")
            return "Error"

# Global default verifier
signature_verifier: ISignatureVerifier = WindowsSignatureVerifier()


# --- General Process Utils ---

def calculate_sha256(file_path: str) -> str:
    """Calculates the SHA256 hash of a file."""
    if not os.path.exists(file_path):
        return ""
    
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.debug(f"Could not hash {file_path}: {e}")
        return ""

def verify_file_signature(file_path: str, verifier: ISignatureVerifier = None) -> str:
    """Utility wrapper for signature verification."""
    v = verifier or signature_verifier
    return v.verify(file_path)
