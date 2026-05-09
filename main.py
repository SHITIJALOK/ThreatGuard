

import sys
import os
import subprocess

from threatguard.app import create_application
from threatguard.main_window import MainWindow

def _is_admin() -> bool:
    
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

                    
    try:
        return os.geteuid() == 0
    except Exception:
        return False

def _show_admin_required_message():
    
    msg = (
        "ThreatGuard must be run as Administrator.\n\n"
        "Please allow the UAC prompt to continue."
    )

    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                0,
                msg,
                "ThreatGuard - Administrator Required",
                0x10,                
            )
            return
        except Exception:
            pass

    print(msg)

def _request_uac_elevation() -> bool:
    
    if os.name != "nt":
        return False

    try:
        import ctypes

        script_path = os.path.abspath(__file__)
        args = [script_path, *sys.argv[1:]]
        parameters = subprocess.list2cmdline(args)

                                        
        rc = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            parameters,
            None,
            1,                 
        )
        return rc > 32
    except Exception:
        return False

def main():
    if not _is_admin():
        if _request_uac_elevation():
            sys.exit(0)
        _show_admin_required_message()
        sys.exit(1)

    app = create_application(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
