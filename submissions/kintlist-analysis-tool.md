# Kntlist Analysis Tool by George M. Garner Jr.

THE KNTLIST PROGRAM has both an acquisition and examination capability, enabling the examiner to dump physical memory from a live Windows system into a file, as well as extract information from a physical memory dump.

## Command Options
This utility has a number of options, including the ability to dump memory from a live system onto a named removable device. An audit log and cryptographic hash of the output can be created for forensic documentary purposes as shown in the following command line:

```
C:\>kntlist -v -i -o Evidence\xpsp2mem --volumelabel CASE101 --log 
--cryptsum sha1 --eject
```

The -o option takes a relative path, and the directory "Evidence" must exist. "CASE101" represents a strongly unique volume name that is given to the thumbdrive. If the thumbdrive is formatted to FAT32 the volume name must be upper case. NTFS is better because you can use NTFS compression but you need to flush the drive before removing it. The --eject option will flush and dismount the thumbdrive but should only be used if you do not intend to write additional evidence to the thumbdrive. A summary of the command line options as displayed in the online help is provided here:

```
kntlist kernel object auditing utility, 1, 0, 0, 1700
Copyright (C) 2004-2005 GMG Systems, Inc.

Command Line: kntlist --help
beta 1 Interim release.  Licensed to Eoghan Casey.
Microsoft Windows Microsoft Windows  5.1 (Build 2600.Personal Service Pack 2)

28/08/2005  18:15:31 (UTC)
28/08/2005  14:15:31 (local time)

Current User: Computer\Eoghan Casey

Usage: kntlist.exe [OPTION] [INPUT_FILE]...
OPTIONS:
-v --verbose  Display verbose output.
-a --analyze  Analyze kernel objects in memory.
-i --image  Copy physical memory to an output file.
-c --compress [ALGORITHM] Compress output using the specified
   compression algorithm.  ALGORITHM may be one of the following:
   zlib    zlib compression.
   zlib+   zlib with optimal compression.
   gzip    gzip compression.
   gzip+   gzip with optimal compression.
   bzip2   compression.
--cryptsum [ALGORITHM] Generate cryptographic checksums for image
  and output files using the specified has algorithm.  The
  following thumbprint algorithms are supported on all platforms:
  "md2", "md4", "md5" and "sha" or "sha1".
The following thumbprint algorithms are supported on Windows
Server 2003 and later:
  "sha_256", "sha_384" and "sha_512".
-o --out {OUTPUT_FILE]  Send output to the specified OUTPUT_FILE.

--iport {PORT]  Send image output to the specified tcpip PORT
--aport {PORT]  Send analysis output to the specified tcpip PORT
.
--lport {PORT]  Send log output to the specified tcpip PORT.
--tport {PORT]  Send cryptographic thumbprints to the specified
                tcpip PORT.
                If --iport, --aport, --lport or --tport options are specified,
                the OUTPUT_FILE specified with the -o --out option will be
                interpreted as an IP address.

The following Qos options may be used with the --iport and --aport
  options:
  --peak_bandwidth [RATE]  Specifies the peak bandwidth in
    bits-per-second.
  --peak_bandwidth [PERCENT]  Specifies the peak bandwidth
    as a percent of link speed.
  --token_bucket_size [SIZE]  Specifies the token bucket size in
    bits-per-second
  --qos_service_type [TYPE]  Specifies the Qos service type.
    Valid service types are:
    1   SERVICETYPE_BESTEFFORT
    2   SERVICETYPE_CONTROLLEDLOAD
    3   SERVICETYPE_GUARANTEED
    10  SERVICETYPE_NETWORK_CONTROL
    13  SERVICETYPE_QUALITATIVE

-l --log [LOG_FILE]  Send log output to the specified OUTPUT_FILE.

--oblock [BLOCK_SIZE] specifies a blocksize that will be used
  to buffer image and analysis output.  The default output
  blocksize is 8192 bytes if the OUTPUT_FILE is an ip address
  and 4096 bytes otherwise.
  The output block size may include binary suffixes,
  e.g. 1Kib equals 1000h, 1Mib equals 1000000h.

--volumelabel [VOLUME_LABEL] Send output to a volume on a removable
  drive with the specified volume label.  If --volumelabel is
  specified,the volume name is prepended to the path specified
  by -o --out.
--eject  Dismount and, if possible, eject the volume specified
  by the -volumelabel option.
--localwrt  Enables writing output to a local fixed drive.

\\.\PhysicalMemory and \\.\DebugMemory are supported as input files.
```

The --localwrt switch is needed to write to a local fixed drive,and \\.\DebugMemory is a pseudo-device that is supported on Windows XP and later. If \\.\DebugMemory is included on the command line memory is acquired using NtSystemDebugControl. Otherwise \Device\PhysicalMemory is used. Neither method is able to read all of the system memory.

## Extracting Information from Memory Dumps
The name of the file containing the physical memory dump is passed as an argument to the kntlist program on the command line as follows:

```
kntlist.exe -v -a -o analysis --kernel ntoskrnl.exe 
dfrws2005-physical-memory1.dmp --log --cryptsum sha1 --localwrt
```

The --kernel switch indicates the location of the Windows kernel that was running on the system from which the physical memory dump was captured. It is necessary to place this kernel file in a folder and create a subdirectory called "drivers," which contains the file "tcpip.sys" from the subject system.

## Data
The kntlist output data extracted from the DFRWS2005 forensic challenge memory dump files are provided here:

- [kntlist-dfrws2005-physical-memory1.log](kntlist-dfrws2005-physical-memory1.log)
- [kntlist-dfrws2005-physical-memory1.txt](kntlist-dfrws2005-physical-memory1.txt)
- [kntlist-dfrws2005-physical-memory2.log](kntlist-dfrws2005-physical-memory2.log)
- [kntlist-dfrws2005-physical-memory2.txt](kntlist-dfrws2005-physical-memory2.txt)

## Illustrative Example
The following example involving a directory listing and Windows timestamps is provided to illustrate why extracting strings from a memory dump has limitations. The following excerpt from the associated report is apparently part of the communication which UMGR32 (a.k.a. B02k) sent back to the attacker. The passage includes what appears to be a file directory listing with embedded 64-bit Windows timestamps. What is interesting is that some of the timestamps are more recent than the kernel boot time. We are looking at the attacker's view of the file system. All of this, except for the file names, is lost when you run strings.

```
KeBootTime: 0x8046B318 (***46b318***) 
Value: 0x1c569660cf6aac0 2005-06-05 00:32:27Z
0046B318  C0 AA F6 0C 66 69 C5 01
03DE68B0  70 00 00 00 60 EE 00 00  E0 19 3E C9 69 69 C5 01  p...`î..à.>ÉiiÅ.
03DE68C0  00 A0 D1 E0 B9 68 C5 01  00 1D 83 CA 69 69 C5 01  . ÑàhÅ...ÊiiÅ.
03DE68D0  00 00 00 00 00 00 00 00  00 C0 01 00 00 00 00 00  .........À......
03DE68E0  00 C0 01 00 00 00 00 00  20 00 00 00 12 00 00 00  .À.............
03DE68F0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
03DE6900  00 00 00 00 00 00 00 00  00 00 00 00 00 00 66 00  ..............f.
03DE6910  70 00 6F 00 72 00 74 00  2E 00 65 00 78 00 65 00  p.o.r.t...e.x.e.
```

The above hex dump contains the following three Windows timestamps which correspond with the date stamps of fport.exe in the timeline:
```
E0 19 3E C9 69 69 C5 01 = Sun, 05 June 2005 00:59:11  UTC (created)
00 A0 D1 E0 B9 68 C5 01 = Sat, 04 June 2005 04:00:00  UTC (last accessed)
00 1D 83 CA 69 69 C5 01 = Sun, 05 June 2005 00:59:14  UTC (last modified)
```
Note that two of these timestamps are more recent than the boot time above. The value "00 C0 01 00 00 00 00 00" in the above hex dump is probably the 64-bit file size. The value agrees with the file size of fport.exe in the timeline: 114688(0x01c000).
