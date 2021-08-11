# Memparser Analysis Tool by Chris Betz
THE MEMPARSER program enables the examiner to load a physical memory dump of certain Windows systems, reconstruct process information, and extract data relating to specific processes.

## Load Memory File
The name of the file containing the physical memory dump is passed as an argument to the memparser program on the command line.

```
C:\>memparser dfrws2005-physical-memory1.dmp

MemParser v1.2 Chris Betz, (c) 2005
No process list loaded.
In Windows 2000 Mode
Options:
z:      Change to Windows 2000 mode
x:      Change to Windows XP mode
c:      Change to Windows 2003 mode
l:      Load the process list
:       Quit
```

## Reconstruct Process List
The process list is loaded using the "l" menu option.

```
l [return]

Searching for processes in memory dump
00%--05%--10%--15%--20%--25%--30%--35%--40%--45%--50%--55%--60%--65%-
-70%--75%--80%--85%--90%--95%--100%
Enumerating process structures.
Sorting processes by PID
MemParser v1.2 Chris Betz, (c) 2005
Process List:
 Proc#           PPID           PID             Name:
   0               0               0            Idle
   1               0               8            System
   2               8             156            smss.exe
   3             144             164            winlogon.exe
   4             144             168            csrss.exe
   5             156             176            winlogon.exe
   6             156             176            winlogon.exe
   7             156             180            csrss.exe
   8             176             228            services.exe
   9             176             240            lsass.exe
  10            1112             284            dd.exe
  11             820             324            helix.exe
  12             228             408            svchost.exe
  13             228             436            spoolsv.exe
  14             228             464            Avsynmgr.exe
  15             228             480            svchost.exe
  16             228             540            regsvc.exe
  17             228             552            MSTask.exe
  18             228             592            dfrws2005.exe
  19             464             612            VsStat.exe
  20             464             628            Avconsol.exe
  21             600             668            UMGR32.EXE
  22             228             672            WinMgmt.exe
  23             800             820            Explorer.Exe
  24             820             964            Apoint.exe
  25             820             972            HKserv.exe
  26             820             972            HKserv.exe
  27             820             988            DragDrop.exe
  28             820            1008            alogserv.exe
  29             820            1012            tgcmd.exe
  30             820            1048            PcfMgr.exe
  31             408            1064            JogServ2.exe
  32             864            1072            Apntex.exe
  33             820            1076            cmd.exe
  34             592            1096            nc.exe
  35             324            1112            cmd2k.exe
  36             324            1132            cmd2k.exe
In Windows 2000 Mode
Options:
#:      Select a process
s:      Show System Information
:        Quit
```

## Extract Memory Contents of Specific Process
Using the reference number in the first column to select a specific process, the examiner can extract information from the memory dump relating to that process. In addition to saving the contents of process memory to a file, strings and other more specific information can be extracted.

```
34 [return]

1096: nc.exe selected:
1       Dump Process Memory (No System Memory Included) to Disk
2       Dump Process Memory (Including System Memory Space) to Disk
3       Dump Process Strings (No System Memory Included) to Disk
4       Dump Process Strings (Including System Memory Space) to Disk
        (Takes a long time)
5       Display Process Environment Information
6       Display all DLLs loaded by process
:       quit
```
The process environment option may include the full path of the executable and command line options:

```
5 [return]

Process Environment Information:
        Executable File:  c:\winnt\system32\nc.exe
        Command Line:     "c:\winnt\system32\nc.exe" -L -p 3000 -t -e cmd.exe
        Window Title:     c:\winnt\system32\nc.exe
        Desktop Info:
        Shell Info:
        Runtime Data:
        Dll Path:         c:\winnt\system32;.;C:\WINNT\System32;C:
                          \WINNT\system;C:\WINNT;C:\WINNT\system32;C:
                          \WINNT;C:\WINNT\System32\Wbem
```

The display loaded DDLs option provides a list of dynamic link libraries that were associated with the process in question:

```
1096: nc.exe selected:
1       Dump Process Memory (No System Memory Included) to Disk
2       Dump Process Memory (Including System Memory Space) to Disk
3       Dump Process Strings (No System Memory Included) to Disk
4       Dump Process Strings (Including System Memory Space) to Disk
        (Takes a long time)
5       Display Process Environment Information
6       Display all DLLs loaded by process
:       quit
6
Base Dll Name: nc.exe           Full Name: c:\winnt\system32\nc.exe
Base Dll Name: ntdll.dll        Full Name: C:\WINNT\System32\ntdll.dll
Base Dll Name: KERNEL32.dll     Full Name: C:\WINNT\system32\KERNEL32.dll
Base Dll Name: WSOCK32.dll      Full Name: c:\winnt\system32\WSOCK32.dll
Base Dll Name: WS2_32.DLL       Full Name: c:\winnt\system32\WS2_32.DLL
Base Dll Name: MSVCRT.DLL       Full Name: C:\WINNT\system32\MSVCRT.DLL
Base Dll Name: ADVAPI32.DLL     Full Name: C:\WINNT\system32\ADVAPI32.DLL
Base Dll Name: RPCRT4.DLL       Full Name: C:\WINNT\system32\RPCRT4.DLL
Base Dll Name: WS2HELP.DLL      Full Name: c:\winnt\system32\WS2HELP.DLL
Base Dll Name: rnr20.dll        Full Name: C:\WINNT\System32\rnr20.dll
Base Dll Name: USER32.DLL       Full Name: C:\WINNT\system32\USER32.DLL
Base Dll Name: GDI32.DLL        Full Name: C:\WINNT\system32\GDI32.DLL
Base Dll Name: DNSAPI.DLL       Full Name: c:\winnt\system32\DNSAPI.DLL
Base Dll Name: winrnr.dll       Full Name: C:\WINNT\System32\winrnr.dll
Base Dll Name: WLDAP32.DLL      Full Name: C:\WINNT\system32\WLDAP32.DLL
Base Dll Name: rasadhlp.dll     Full Name: c:\winnt\system32\rasadhlp.dll
Base Dll Name: RTUTILS.DLL      Full Name: c:\winnt\system32\RTUTILS.DLL
Base Dll Name: msafd.dll        Full Name: C:\WINNT\system32\msafd.dll
Base Dll Name: IPHLPAPI.DLL     Full Name: c:\winnt\system32\IPHLPAPI.DLL
Base Dll Name: ICMP.DLL         Full Name: c:\winnt\system32\ICMP.DLL
Base Dll Name: MPRAPI.DLL       Full Name: c:\winnt\system32\MPRAPI.DLL
Base Dll Name: SAMLIB.DLL       Full Name: c:\winnt\system32\SAMLIB.DLL
Base Dll Name: NETAPI32.DLL     Full Name: c:\winnt\system32\NETAPI32.DLL
Base Dll Name: SECUR32.DLL      Full Name: c:\winnt\system32\SECUR32.DLL
Base Dll Name: NETRAP.DLL       Full Name: c:\winnt\system32\NETRAP.DLL
Base Dll Name: OLE32.DLL        Full Name: C:\WINNT\system32\OLE32.DLL
Base Dll Name: OLEAUT32.DLL     Full Name: C:\WINNT\system32\OLEAUT32.DLL
Base Dll Name: ACTIVEDS.DLL     Full Name: c:\winnt\system32\ACTIVEDS.DLL
Base Dll Name: ADSLDPC.DLL      Full Name: c:\winnt\system32\ADSLDPC.DLL
Base Dll Name: SETUPAPI.DLL     Full Name: c:\winnt\system32\SETUPAPI.DLL
Base Dll Name: USERENV.DLL      Full Name: c:\winnt\system32\USERENV.DLL
Base Dll Name: RASAPI32.DLL     Full Name: c:\winnt\system32\RASAPI32.DLL
Base Dll Name: RASMAN.DLL       Full Name: c:\winnt\system32\RASMAN.DLL
Base Dll Name: TAPI32.DLL       Full Name: c:\winnt\system32\TAPI32.DLL
Base Dll Name: COMCTL32.DLL     Full Name: C:\WINNT\system32\COMCTL32.DLL
Base Dll Name: SHLWAPI.DLL      Full Name: C:\WINNT\system32\SHLWAPI.DLL
Base Dll Name: DHCPCSVC.DLL     Full Name: c:\winnt\system32\DHCPCSVC.DLL
Base Dll Name: CLBCATQ.DLL      Full Name: c:\winnt\system32\CLBCATQ.DLL
Base Dll Name: wshtcpip.dll     Full Name: C:\WINNT\System32\wshtcpip.dll

q

Thank you for using MemParser (c) 2005 Chris Betz.
```
