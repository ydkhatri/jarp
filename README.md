# jarp - Just Another broken Registry Parser

A parser for corrupted registry hives that won't load into registry parser tools due to missing headers or corrupted structures.

## License
MIT

## Requirements & Installation
Python 3.7+ and the following modules
- construct

You can install this via pip easily.
```
pip3 install construct
```

## Purpose
We encountered some strains of ransomware that would encrypt the Windows 
registry NTUSER.DAT files, however the ransomware would only encrypt the 
first few KBs of the file and in some instances bands of a few other KB 
throughout the file. This meant there was still a lot of data that was
salvageable and usable but no tools would mount these hives. So I wrote
JARP primarily to enhance my understanding of how the windows registry
stores data, and what is recoverable realistically.

## Usage
JARP will output all recovered keys, values and resolved key paths to an
sqlite database, with an option to output to csv as well. You can also 
filter for keywords which searches the key path, key name and value name
and only displays output with hits. So for example, if you only care about 
"WordWheelQuery", that can be used as a keyword, and everything else is 
filtered out.

```
% python3 jarp.py -h
usage: jarp.py [-h] [-o OUTPUT_PATH] [-p] [-n] [-f FILTER]
               [-r REGEX_FILTER] [-k]
               reg_path

  _  _  _  _ 
   //_//_//_/
(_// // \/    v 0.7.2 (c) Yogesh Khatri 2023 @swiftforensics

positional arguments:
  reg_path              Path to registry hive (file)

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT_PATH, --output_path OUTPUT_PATH
                        Output file name and path (for sqlite output)
  -p, --print_to_screen
                        Print output to screen
  -n, --no_UA_decode    Do NOT decode rot13 for UserAssist (Default is to decode)
  -f FILTER, --filter FILTER
                        Filter keys and values. Eg: -f "UserAssist"
  -r REGEX_FILTER, --regex_filter REGEX_FILTER
                        Filter keys and values with regex. Eg: -f "User[a-zA-Z]+"
  -k, --parse_known_keys
                        Read and parse UserAssist & RecentItems

Just Another (broken) Registry Parser (JARP) was created to read 
registry files that were partially corrupted and/or encrypted. 
JARP will write all recovered keys & values to an sqlite
database and/or output recovered data on the console.

The filter options only apply to the console output (-p option).
```

## Examples
1. Looking for RDP (mstsc) usage
```
% python3 jarp.py -p -f "Terminal server client/server" ./test_hives/NTUSER.DAT
[+] Read 2010 NK objects and 3339 VK objects
[+] Located path for 3281 vk entries, 58 vk are orphan, 4 vk not present in file
KeyPath, ValueName, RegType, KeyLastModifiedDate
**UNKNOWN**/Terminal Server Client/Servers/twtd-d10-hv12, UsernameHint, RegSZ, twtd\marion, key_mod_date=2022-06-19 03:24:10.28038
**UNKNOWN**/Terminal Server Client/Servers/twtd-d10-hv13, UsernameHint, RegSZ, twtd\marion, key_mod_date=2022-09-19 02:26:57.12534
**UNKNOWN**/Terminal Server Client/Servers/twtd-d10-bdr01, UsernameHint, RegSZ, twtd\marion, key_mod_date=2022-09-22 01:31:19.072456
**UNKNOWN**/Terminal Server Client/Servers/twtd-d10-dc01, UsernameHint, RegSZ, twtd\marion, key_mod_date=2022-10-19 03:52:11.02866
**UNKNOWN**/Terminal Server Client/Servers/twtd-d10-hv14, UsernameHint, RegSZ, twtd\marion, key_mod_date=2022-12-19 04:39:53.082502
[+] 5 items matched filter "Terminal\ server\ client/server" 
```
2. Parse known artifacts (-k), this parses UserAssist, RecentItems and WordWheelQuery
```
% python3 jarp.py -p -k /Users/ykhatri/Downloads/NTUSER.DAT
[+] Read 2010 NK objects and 3339 VK objects
[+] Located path for 3281 vk entries, 58 vk are orphan, 4 vk not present in file

[+] UserAssist Items = 34
Path, Session ID, Count, Last Used Date, Focus Time (ms), Focus Count, KeyTimestamp
C:\support\MSM_Windows\MSM17050002\DISK1\setup.exe, 0, 1, 2021-08-26 19:39:12.107000, 0, 0, 2022-10-18 02:57:38.986660
Microsoft.Windows.WindowsInstaller, 0, 0, , 235, 0, 2022-10-18 02:57:38.986660
UEME_CTLCUACount:ctor, -1, 0, , 0, 0, 2022-10-18 02:57:38.986660
{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\SnippingTool.exe, 0, 14, 2021-08-26 19:36:16.065280, 420000, 21, 2022-10-18 02:57:38.986660
UEME_CTLCUACount:ctor, -1, 0, , 0, 0, 2022-10-18 02:53:49.742934
{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\Accessories\Snipping Tool.lnk, 0, 14, 2021-08-26 19:36:16.065280, 14, 0, 2022-10-18 02:53:49.742934
{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\mspaint.exe, 0, 8, 2021-08-26 19:36:16.065280, 240000, 12, 2022-10-18 02:57:38.986660
{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\Accessories\Paint.lnk, 0, 8, 2021-08-26 19:36:16.065280, 8, 0, 2022-10-18 02:53:49.742934
{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\notepad.exe, 0, 3, 2021-11-04 00:08:06.388000, 149827, 4, 2022-10-18 02:57:38.986660
{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}\Accessories\Notepad.lnk, 0, 2, 2021-08-26 19:36:16.065280, 2, 0, 2022-10-18 02:53:49.742934
{F38BF404-1D43-42F2-9305-67DE0B28FC23}\SystemApps\Microsoft.LockApp_cw5n1h2txyewy\LockApp.exe, 0, 0, , 162578, 3, 2022-10-18 02:57:38.986660
Microsoft.Windows.Shell.RunDialog, 0, 0, , 6048, 1, 2022-10-18 02:57:38.986660
{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\win32calc.exe, 0, 0, , 8187, 1, 2022-10-18 02:57:38.986660
{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\ServerManager.exe, 0, 0, , 607924, 11, 2022-10-18 02:57:38.986660
... output snipped ...

[+] RecentItems = 6
Path, Arguments, DisplayName, LastAccessedTime, KeyTimestamp
C:\Windows\System32\mstsc.exe, /v:"twtd-d10-bdr01", twtd-d10-bdr01, 0, 2022-09-22 01:31:19.123700
C:\Users\marion\Downloads\Windows10_Windows_Server_2016_2019\README.txt, , README.txt, 0, 2021-11-04 00:08:06.466182
C:\Windows\System32\mstsc.exe, /v:"twtd-d10-hv12", twtd-d10-hv12, 0, 2022-06-19 03:24:10.28038
C:\Windows\System32\mstsc.exe, /v:"twtd-d10-hv13", twtd-d10-hv13, 0, 2022-09-19 02:26:57.12534
C:\Windows\System32\mstsc.exe, /v:"twtd-d10-dc01", twtd-d10-dc01, 0, 2022-10-19 03:52:11.02866
C:\Windows\System32\mstsc.exe, /v:"twtd-d10-hv14", twtd-d10-hv14, 0, 2022-12-19 04:39:53.082502

[+] WordWheelQuery Items = 6
MRU order [1, 5, 4, 3, 2, 0]
ID, Search Term, KeyTimestamp
0, serv, 2023-02-06 23:48:16.597754
2, cre, 2023-02-06 23:48:16.597754
3, indexing, 2023-02-06 23:48:16.597754
4, sear, 2023-02-06 23:48:16.597754
5, mstsc, 2023-02-06 23:48:16.597754
1, psexec, 2023-02-06 23:48:16.597754
```

## Other tools
The repo also hosts an updated [010](https://www.sweetscape.com/010editor/) 
template which can read reg hives without the valid header "regf" and adds 
reading of Reg Values as well. This builds upon the work of Eric Zimmerman who wrote the 
first verion of this template. This was used to study the corrupted hives and 
build JARP.
