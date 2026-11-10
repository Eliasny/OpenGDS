OpenGDS Auditor for Windows (desktop installer)
===============================================

This installs the OpenGDS Auditor, a free OPC 10000-12 (Part 12) test tool
for push-managed servers, pull clients and GDSs. Its results are a
self-test, not OPC Foundation certification.

Start "OpenGDS Auditor" from the Start menu for the desktop UI. The
headless engine is in the same folder and runs from a Command Prompt or
PowerShell:

    "C:\Program Files\OpenGDS Auditor\bin\gdsaudit.exe" run plan.toml

The UI keeps its runs, targets and work folder in your user profile
(%LOCALAPPDATA%\gdsaudit). The Auditor's private keys are written there and
are protected by the folder's permissions.

In the UI, Pause, Resume and Abort work as on Linux. The headless engine
on its own has no pause; Ctrl-C aborts a run and the target is still
restored.

Operator guide, test catalogues and plan file format:
https://github.com/Eliasny/OpenGDS/tree/main/docs/auditor

Licences: licenses\ (OpenGDS and open62541: MPL 2.0; OpenSSL: Apache 2.0;
GTK, GLib and the other libraries of the UI: LGPL and their own terms,
listed in licenses\THIRD-PARTY-PACKAGES.txt). Those libraries are MSYS2's
builds, used unchanged; their sources are the MSYS2 packages of the listed
names and versions (https://packages.msys2.org).
