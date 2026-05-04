@echo off
:: Redirect execution to the Windows Python Launcher (py) unconditionally.
:: This breaks out of the stripped-down ESP-IDF python.exe which lacks Tkinter.
py -3 "%~dp0scripts\cli.py" %*
