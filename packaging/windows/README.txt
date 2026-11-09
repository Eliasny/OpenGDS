OpenGDS Auditor (gdsaudit) for Windows
======================================

gdsaudit.exe is the headless OpenGDS Auditor: a free OPC 10000-12 (Part 12)
test tool for push-managed servers, pull clients and GDSs. Its results are a
self-test, not OPC Foundation certification.

It is one static program: copy it anywhere and run it from a Command Prompt
or PowerShell. It needs 64-bit Windows 10 or later, nothing else.

    gdsaudit.exe server --work C:\Users\me\gdsaudit --init-only
    gdsaudit.exe server --url opc.tcp://plc:4840 --server-cert plc.der ^
        --work C:\Users\me\gdsaudit --report results
    gdsaudit.exe run plan.toml

Keep the work folder in your user profile: the Auditor's private keys are
written there and are protected by the folder's permissions.

Windows differences from Linux:
- Ctrl-C and Ctrl-Break abort a run (the target is still restored); there
  is no pause signal.
- The client profile's trigger may be a .exe, or a .bat/.cmd (run through
  cmd.exe /c). A trigger that runs past its timeout is terminated.
- --restart-cmd and --setup-cmd run through cmd.exe /c, so give a
  Windows command (a .bat, or ssh to the device).
- --prompts reads a plain file of operator answers; it is read once to its
  end (no waiting for lines to be appended).

Operator guide, test catalogues and plan file format:
https://github.com/Eliasny/OpenGDS/tree/main/docs/auditor

Licences: licenses\ (OpenGDS and open62541: MPL 2.0; OpenSSL: Apache 2.0;
the MinGW-w64 runtime: its own permissive terms).
