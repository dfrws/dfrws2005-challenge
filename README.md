# DFRWS 2005 Forensics Challenge


MEMORY ANALYSIS was one of the primary themes of DFRWS 2005. In an effort to motivate discourse, research and tool development in this area, the Organizing Committee created the intrusion/intellectual property theft scenario detailed below. This memory challenge was open to all, and team efforts were encouraged. An award was given to the people (below) who extracted the most information from the memory dumps, and the quality of documentation and novelty of techniques were considered when choosing the winners. Network traffic associated with this intrusion was made available during the workshop (below).

## The Results
The joint winners of the Memory Analysis Challenge, announced at DFRWS 2005, were:
| Winners | Summary | Submission |
| --- | --- | --- |
| Chris Betz	| Developed [memparser](submissions/memparser.md) to reconstruct process list and extract information from process memory.	| [Report & Answers](submissions/betz-report.md)
| George M. Garner Jr. & Robert-Jan Mora | Developed [kntlist](submissions/kintlist-analysis-tool.md) to interpret structures in memory and maintain an audit log and integrity checks. | [Preliminary Analysis](submissions/rossettoecioccolato-DFRWSChallengeOverview.pdf) and [Answers](submissions/RossettoeCioccolato-Responses.pdf)

## The Memory Analysis Challenge 
For several years, Professor Goatboy has been performing secret research that is of great interest to a certain foreign government. In May 2005, rumors spread that he had written several papers detailing key aspects of his work but that he was being pressured not to publish them. To escape these pressures, the professor moved to a new research facility where he would be permitted to continue his work without interference.

In the last week of May, Professor Goatboy settled into his new office and moved his work onto the new laptop he had been assigned. Unfortunately, he was too busy during the first week at his new job to get much work done, and did not have time to secure the fresh installation of Windows 2000 on his laptop.

On Sunday June 5th, the research lab's incident response coordinator, Tom "Blackout Jack" Daniels, was examining network logs from the previous night and noticed unusual traffic coming from Professor Goatboy's computer. He promptly located the laptop in the professor's office, and used Helix 1.6 to dump physical memory ([dfrws2005-physical-memory1.dmp](https://www.dropbox.com/s/cspavwi3w4wskuh/dfrws2005-physical-memory1.dmp.bz2?dl=0)) (MD5 = 2d767dbc338075f7c7594894716f3290). He attempted to find signs of intrusion on the system but had difficulty executing some of his tools. Specifically, the system would not run "pslist.exe" or "fport.exe" to gather information about running processes. In addition, while he was attempting to create forensic duplicate of the drive, the system rebooted unexpectedly.

When the system came back up, Daniels acquired the physical memory again ([dfrws2005-physical-memory2.dmp](https://www.dropbox.com/s/syr47y9nljpeguf/dfrws2005-physical-memory2.dmp.bz2?dl=0)) (MD5 = dbca88eeb7b8dbd42f406a405e6f56cf), and again tried to acquire an image of the disk using Helix 1.6 under Windows without success. Finally, he rebooted the system using the Helix CD and acquired the drive using Grab 1.2.2.

The lab administration is seeking help in determining what occurred. In addition to the memory dumps, the following information is available:

[dfrws2005-timeline.txt](materials/dfrws2005-timeline.txt.zip) (MD5 = c6bda8e2d9933167c3174e1ef31bbea1 of the raw file): File system timeline generated using the Sleuthkit

[dfrws2005-body-file.fls](materials/dfrws2005-body-file.fls.bz2) (MD5 = 896a33f0ba5be435d6f9fa7edd52ad92): The same file system metadata in mactime format obtained using the Sleuthkit command fls -m '/' -r /dev/hda1

Specific files from the system could be requested by providing the names of the file via email. For instance, "ntoskrnl.exe," the kernel module from the original system containing various memory management functions may be useful for your analysis.

## DFRWS 2005 Forensics Challenge Questions
- What hidden processes were running on the system, and how were they hidden?
- What other evidence of the intrusion can be extracted from the memory dumps?
- Why did "plist.exe" and "fport.exe" not work on the compromised system?
- Was the intruder specifically seeking Professor Goatboy's research materials?
- Did the intruder obtain the Professor's research?
- What computer was the intrusion launched from?
- Is there any indication of who the intruder might be?

## Additional Files (Released at DFRWS 2005)

## Additional Files Released at DFRWS 2005
| File Name | MD5 | Info |
| --- | --- | --- |
[dfrws2005-network-capture.tcp](materials/dfrws2005-body-file.fls.bz2) | f239127c208e91b069ebfabef4c9084a | Network capture log
[ntoskrnl.exe](materials/NTOSKRNL.EXE.bz2) | b100ac8cb500765127b23e2ac098047d | Kernel file
[tcpip.sys](materials/TCPIP.SYS.bz2) | 5ca6397605ce0ae8414f996a29354cbb | Driver file
[dfrws2005-physical-memory1-audit.log](materials/dfrws2005-physical-memory1-audit.log.md) | n/a | Acquisition audit logs
[dfrws2005-physical-memory2-audit.log](materials/dfrws2005-physical-memory2-audit.log.md) | n/a | Acquisition audit logs
