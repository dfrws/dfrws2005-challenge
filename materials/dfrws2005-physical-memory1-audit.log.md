```
Forensic Acquisition Utilities, 1, 0, 0, 1035
dd, 3, 16, 2, 1035
Copyright (C) 2002-2004 George M. Garner Jr.

Command Line: ..\Acquisition\FAU\dd.exe if=\\.\PhysicalMemory of=F:\intrusion2005\dfrws2005-physical-memory1.dmp conv=noerror --md5sum --verifymd5  --md5out=F:\intrusion2005\dfrws2005-physical-memory1.dmp.md5 --log=F:\intrusion2005\dfrws2005-physical-memory1-audit.log
Based on original version developed by Paul Rubin, David MacKenzie, and Stuart Kemp
Microsoft Windows: Version 5.0 (Build 2195.Professional Service Pack 1)

05/06/2005  14:53:45 (UTC)
05/06/2005  10:53:45 (local time)

Current User: VAIO\Administrator

Total physical memory reported: 129004 KB
Copying physical memory...
E:\Acquisition\FAU\dd.exe: 
	Stopped reading physical memory: 
	
The parameter is incorrect.\2d767dbc338075f7c7594894716f3290 [\\\\.\\PhysicalMemory] *F:\\intrusion2005\\dfrws2005-physical-memory1.dmp

Verifying output file...
\2d767dbc338075f7c7594894716f3290 [F:\\intrusion2005\\physicalmemory.dd] *F:\\intrusion2005\\dfrws2005-physical-memory1.dmp
The checksums do match.
The operation completed successfully.
Output F:\intrusion2005\dfrws2005-physical-memory1.dmp (132640768 bytes)
32383+0 records in
32383+0 records out
```
