# Static Standard-Library-Only De-obfuscation

`cmd-unmask` is implemented exclusively using the Python 3 standard library and performs 100% static analysis without invoking `eval()`, `exec()`, or child shells (`powershell.exe`, `cmd.exe`, `bash`). SOC analysts run this Tracer Script directly on restricted workstations against live, potentially destructive malware command lines copied from SIEM/EDR offenses; executing any portion of a payload risks host compromise, and third-party package dependencies impede portable deployment across locked-down environments.
