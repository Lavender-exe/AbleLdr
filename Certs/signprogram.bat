@echo off

"C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe" sign /f "D:\Cyber Security\Shared Disk\Malware Development\AbleLdr\Certs\ablecert.pfx" /p AbleCert  /t http://timestamp.digicert.com /fd sha256 