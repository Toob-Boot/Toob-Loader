import os
import sys
import shutil
import subprocess
import json


class ToolLocator:
    """
    A generic, chip-agnostic toolchain locator.
    Replaces the old hardcoded 'espressif.py' or 'generic.py' search logic.
    """

    # Common directories where vendors often hide their toolchains
    # Ordered by specificity to avoid walking massive directories unnecessarily
    COMMON_SEARCH_PATHS = [
        # Windows - Highly Specific Vendor Dirs
        r"C:\Espressif\tools",
        os.path.expanduser(r"~\.espressif\tools"),
        r"C:\ST\STM32CubeIDE",
        r"C:\Program Files\Nordic Semiconductor",
        os.path.expanduser(r"~\AppData\Local\Arduino15\packages"),
        # Windows - Generic/Fallback (Slow to walk)
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        # Linux/macOS
        "/opt",
        "/usr/local/bin",
        os.path.expanduser("~/.espressif/tools"),
        os.path.expanduser("~/ncs/toolchains"),
    ]

    # Initialize custom paths once when the module loads
    USER_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "user_tools.json")
    MAX_DEPTH = 6  # Default maximum recursion depth

    @classmethod
    def load_user_paths(cls):
        """Loads custom user-defined tool directories from user_tools.json if it exists."""
        if os.path.exists(cls.USER_CONFIG_PATH):
            try:
                with open(cls.USER_CONFIG_PATH, "r") as f:
                    config = json.load(f)
                    if "max_depth" in config:
                        cls.MAX_DEPTH = config["max_depth"]

                    custom_paths = config.get("custom_search_paths", [])
                    if custom_paths:
                        expanded_paths = []
                        for p in custom_paths:
                            expanded = os.path.expandvars(os.path.expanduser(p))
                            # Handle variables that expand to multiple paths (e.g. %PATH%)
                            if os.pathsep in expanded:
                                expanded_paths.extend(
                                    [
                                        path.strip()
                                        for path in expanded.split(os.pathsep)
                                        if path.strip()
                                    ]
                                )
                            else:
                                expanded_paths.append(expanded)

                        print(
                            f"[*] ToolLocator loaded {len(expanded_paths)} custom paths (max_depth={cls.MAX_DEPTH}) from user_tools.json"
                        )
                        # Prepend custom paths so they are searched before generics
                        cls.COMMON_SEARCH_PATHS = (
                            expanded_paths + cls.COMMON_SEARCH_PATHS
                        )
            except Exception as e:
                print(f"[!] Errer reading user_tools.json: {e}")

    @classmethod
    def create_template(cls):
        """Creates a template user_tools.json to help the user configure their environment."""
        template = {
            "max_depth": 6,
            "custom_search_paths": [
                "C:\\MyCustomCompany\\CompilerSuite",
                "D:\\VendorTools\\bin",
                "%PATH%",
            ],
        }
        with open(cls.USER_CONFIG_PATH, "w") as f:
            json.dump(template, f, indent=4)
        print(
            f"\n[!] A template configuration file was created at: {cls.USER_CONFIG_PATH}"
        )
        print(
            "[!] Please add the directory containing your missing compiler to 'custom_search_paths'."
        )

    @classmethod
    def find_tool(cls, tool_name, is_python_module=False):
        """
        Attempts to locate a tool. If `is_python_module` is true and it's missing,
        it will attempt to install it via pip.
        """
        # 1. Ask the OS (Standard PATH)
        cmd_path = shutil.which(tool_name)
        if not cmd_path:
            base_tool = os.path.splitext(tool_name)[0]
            cmd_path = shutil.which(base_tool) or shutil.which(f"{base_tool}.exe")

        if cmd_path:
            return cmd_path

        # 2. Heuristic Search in common vendor directories
        print(
            f"[*] Tool '{tool_name}' not in PATH. Searching common vendor directories (Max Depth: {cls.MAX_DEPTH})..."
        )
        for base_path in cls.COMMON_SEARCH_PATHS:
            if not os.path.exists(base_path):
                continue

            # If path ends in a separator, normalize it for accurate depth calculation
            base_path = os.path.normpath(base_path)

            for root, dirs, files in os.walk(base_path):
                # 1. Enforce Maximum Traversal Depth to prevent hanging on C:\
                rel_path = os.path.relpath(root, base_path)
                depth = 0 if rel_path == "." else rel_path.count(os.sep) + 1

                if depth >= cls.MAX_DEPTH:
                    dirs[:] = []  # Stop descending
                    continue

                # 2. Prune irrelevant directories in-place to drastically speed up search
                dirs[:] = [
                    d
                    for d in dirs
                    if d.lower()
                    not in [
                        ".git",
                        "node_modules",
                        "eclipse",
                        "dist",
                        "build",
                        "__pycache__",
                        "doc",
                        "docs",
                        "src",
                        "include",
                        "lib",
                        "share",
                        "examples",
                        "tests",
                        "components",
                    ]
                ]

                base_tool = os.path.splitext(tool_name)[0]
                possible_names = [
                    tool_name,
                    f"{base_tool}.exe",
                    f"{base_tool}.bat",
                    f"{base_tool}.cmd",
                ]

                for p_name in possible_names:
                    if p_name in files:
                        found_path = os.path.join(root, p_name)
                        print(f"    [+] Found at: {found_path}")
                        return found_path

        # 3. Fallback: Auto-Install if it's a known Python tool
        if (
            is_python_module
            or tool_name.endswith(".py")
            or tool_name in ["imgtool", "esptool", "cysecuretools"]
        ):
            print(
                f"[!] Python module '{tool_name}' missing. Attempting auto-install..."
            )
            package_name = tool_name.replace(".py", "")  # basic mapping

            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", package_name]
                )
                # Check PATH again after install. Pip often installs .exe without .py extension on Windows.
                cmd_path = shutil.which(tool_name) or shutil.which(package_name)
                if cmd_path:
                    print(f"    [+] Successfully installed and located: {cmd_path}")
                    return cmd_path
            except subprocess.CalledProcessError:
                print(f"    [-] Auto-install failed for {package_name}.")

        # 4. Final Failure: Ask the user to configure the JSON
        print(f"\n[-] FATAL: Could not locate toolchain binary: '{tool_name}'")
        if not os.path.exists(cls.USER_CONFIG_PATH):
            cls.create_template()
        else:
            print(
                f"[-] Hint: Ensure the path containing '{tool_name}' is listed in user_tools.json"
            )

        raise FileNotFoundError(
            f"{tool_name} not found. Edit user_tools.json to add its path."
        )


# Auto-load the user configuration on import
ToolLocator.load_user_paths()

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        try:
            path = ToolLocator.find_tool(sys.argv[1])
            print(f"SUCCESS: {path}")
        except Exception as e:
            print(f"ERROR: {e}")
