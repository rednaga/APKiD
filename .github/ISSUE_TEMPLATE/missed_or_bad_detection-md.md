---
name: Missed_or_Bad_Detection.md
about: Create a missed or bad detection report to help improve detection rules
title: "[DETECTION]"
labels: detection-issue
assignees: ''

---

**Provide the file**
Please attach the file to this issue if possible.
If not possible, please add url or link to download the file.
If neither of the above are possible, add hash which can be found online (e.g. - via VT) for download.

*If you do no fill in this section, the issue with be closed due to lack of the bare minimum of information needed for people to reproduce. We CANNOT test things if you don't tell use what to test*

**Describe the detection issue**
Please describe what was expected to be detected, a packer, protector, obfuscator, antidebug, etc?
What supporting information can you provide to aid in why you believe this should be detected as such?
Is the protector known, if so, please provide reference links to any site/marketing material/etc.

**APKiD current results...**
Please provide current output from APKiD on this file. Include the APKiD header which provides the version, e.g. -
```
diff@larry: apkid .      
[+] APKiD 2.1.0 :: from RedNaga :: rednaga.io
[*] ./myapp.apk
 |-> packer : APKProtect 6.x
[*] ./myapp.apk!classes.dex
 |-> compiler : dx
[*] ./classes.dex
 |-> compiler : dx
```

**Additional context**
Add any other context about the problem here.
