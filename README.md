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

## Other tools
The repo also hosts an updated 010 template which can read reg hives without the
valid header "regf". This builds upon the work of Eric Zimmerman who wrote the 
first verion of this template. This was used to study the corrupted hives and 
build JARP.
