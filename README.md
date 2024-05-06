# EPMAuditr
A tool to audit CyberArk EPM Policy for security misconfigurations

![image](https://github.com/z3mms/EPMAuditr/assets/1330657/bd49a2ab-bd48-42d2-a1a8-20d2a276dea6)

Usage:
- ./epmaudit.py --file <filename.epmp>
- ./epmaudit.py --api


Features:
- Offline auditing of .epmp files exported from CyberArk's dashboard
- Online auditing via CyberArk EPM API
- Detect LOLBAS/GFTFOBins binaries

Future enhancements:
- Generate full report in HTML
