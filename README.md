#  WannaCry YARA Rule - Custom Detection

This repository contains a custom Yara rule created as part of a malware analysis report on the WannaCry ransomware.

Developed by Shira Borochovich
January 2025  
Tested on real samples from theZoo ransomware collection

About:

This YARA rule was written as part of an in-depth technical report focused on the static and dynamic analysis of the WannaCry ransomware. The rule detects core behavioral indicators that are unique to WannaCry, including mutex usage, dropper artifacts, encryption patterns, and TOR communication strings.

- Detects `.WNCRY` extension used on encrypted files  
- Flags the ransomware's dropper name `@WanaDecryptor@`  
- Matches unique service name: `mssecsvc2.0`  
- Identifies TOR usage via the string `tor2web`  
- Detects known mutex: `Global\\MsWinZonesCacheCounterMutexA`  
- Includes specific language resource filename used in payload


Files:

- `wannacry_custom.yar` — The YARA rule

---

How to Use:

To scan a folder for WannaCry indicators:

```bash
yara -r wannacry_custom.yar /path/to/files
