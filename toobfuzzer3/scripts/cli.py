import sys
import os
import argparse
import subprocess


def main():
    parser = argparse.ArgumentParser(description="Toobfuzzer3 Command Line Interface")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Frontend Command
    frontend_parser = subparsers.add_parser(
        "frontend", help="Manage the Toobfuzzer GUI"
    )
    frontend_parser.add_argument(
        "--start", action="store_true", help="Launch the CustomTkinter GUI"
    )

    args = parser.parse_args()

    if args.command == "frontend":
        if args.start:
            print("[*] Spawning Toobfuzzer3 GUI...")
            gui_script = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), "toobfuzzer_gui.py"
            )

            # 1. Use the global Windows Python Launcher to bypass ESP-IDF environments.
            # The IDF python.exe lacks `tkinter`. `pyw.exe -3` ensures we use the system install and hides the console.
            exec_path = "pyw"
            gui_args = ["-3", gui_script]

            # 2. Apply Windows CREATE_NO_WINDOW flag (0x08000000)
            DETACHED_PROCESS = 0x00000008
            CREATE_NO_WINDOW = 0x08000000

            subprocess.Popen(
                [exec_path] + gui_args,
                cwd=os.path.dirname(os.path.dirname(__file__)),
                creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW,
                close_fds=True,
            )
            print("[*] GUI successfully detached (Ghost Mode).")
        else:
            frontend_parser.print_help()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
