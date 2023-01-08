"""
(c) 2023 Yogesh Khatri, @swiftforensics

Recover registry records from partially overwritten
registry hives.

Scan for VK records, record offsets in dict,
then scan for parent NK records.

"""

import argparse
import construct
import datetime
import os
import mmap
import re
import sqlite3
import struct
import sys

from construct import *
from construct.core import Int32ul, Int64ul, Int16ul, Int8ul, Int32sl

NKCELL = Struct(
    "size" / Int32sl,
    "signature" / Const(b"nk"),
    "flags" / Int16ul,
    "last_write_time" / Int64ul,
    "spare" / Int32ul,
    "parent_cell_offset" / Int32ul,
    "subkey_count_stable" / Int32ul,
    "subkey_count_volatile" / Int32ul,
    "subkey_list_offset_stable" / Int32ul,
    "subkey_list_offset_volatile" / Int32ul,
    "value_count" / Int32ul,
    "value_list_offset" / Int32ul,
    "security_key_offset" / Int32ul,
    "class_offset" / Int32ul,
    "max_name_length" / Int16ul,
    "user_virt_flags" / Int8ul,
    "debug" / Int8ul,
    "maxClassLength" / Int32ul,
    "max_value_name_length" / Int32ul,
    "max_value_data_length" / Int32ul,
    "work_var" / Int32ul,
    "name_length" / Int16ul,
    "class_length" / Int16ul
    # followed by Name and Class strings 
    # followed by Padding to defined size (stored as -ve)
)

VKCELL = Struct(
    "size" / Int32sl,
    "signature" / Const(b"vk"),
    "name_length" / Int16ul,
    "data_length" / ByteSwapped (BitStruct( 
        "data_flag" / BitsInteger(4),
        "length" / BitsInteger(28))
        ),
    "data_offset" / Int32ul, #ByteSwapped (BitStruct( 
        #"unknown" / BitsInteger(4),
        #"offset" / BitsInteger(28))
        #),
    "type" / Int32ul,
    "flags" / Int16ul,
    "spare" / Int16ul

    # followed by Name string
    # followed by Padding to defined size (stored as -ve)
)

class NkCell:
    def __init__(self, flags, last_write_time, parent_cell_offset, 
                subkey_count_stable, subkey_list_offset_stable, value_count,
                value_list_offset, security_key_offset, name) -> None:
        self.flags = flags
        self.last_write_time = last_write_time
        self.parent_cell_offset = parent_cell_offset
        self.subkey_count_stable = subkey_count_stable
        self.subkey_list_offset_stable = subkey_list_offset_stable
        self.value_count = value_count
        self.value_list_offset = value_list_offset
        self.security_key_offset = security_key_offset
        self.name = name
        self.path = ''


class VkCell:
    def __init__(self, flags, name, data_length, data_offset, value_type) -> None:
        self.flags = flags
        self.name = name
        self.data_length = data_length
        self.data_offset = data_offset
        self.value_type = value_type
        self.value = None


def ReadWinFileTime(win64_timestamp): # FILETIME is 100ns ticks since 1601-1-1
    '''Returns datetime object, or empty string upon error'''
    if win64_timestamp not in ( 0, None, ''):
        try:
            if isinstance(win64_timestamp, str):
                win64_timestamp = float(win64_timestamp)

            return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=win64_timestamp/10)
        except Exception as ex:
            print("ReadWinFileTime() Failed to convert timestamp from value " + str(win64_timestamp) + " Error was: " + str(ex))
    return ''

def main():
    input_path = sys.argv[1]
    output_path = sys.argv[2]

    nk_pattern = b'\xFF\xFFnk'
    vk_pattern = b'\xFF\xFFvk'

    all_pattern = b'\xFF\xFF(v|n)k'

    vk_objects = {}
    nk_objects = {}

    file_size = os.path.getsize(input_path)
    with open(input_path, 'rb') as f:
        if os.name == 'nt':
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        else:
            mm = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)

        for match in re.finditer(all_pattern, mm):
            #print(match)
            start_pos = match.start() - 2
            f.seek(start_pos)
            size = -struct.unpack("<i", f.read(4))[0]
            #print(f"0x{size:X}")
            f.seek(start_pos)
            if match.group(0)[2:3] == b'v':
                vk_data = f.read(size)
                vk = VKCELL.parse(vk_data)
                #print(vk)
                if vk.name_length > 0:
                    name = vk_data[24 : 24 + vk.name_length].decode('utf8')
                else:
                    name = ''
                #print(f"name = {name}")
                data = None

                if vk.data_length.length > 0:

                    if vk.data_length.data_flag & 8 == 8: # data is stored in data_offset
                        data = vk_data[12:16]
                    elif vk.data_offset > 0 and \
                            (vk.data_offset + 4100) < file_size: # Can jump to data and read it now! Checks needed.
                        if vk.type in (1, 2, 3, 7, 11): # RegSZ, expandsz, bin, multisz, qword
                            f.seek(4096 + vk.data_offset + 4)
                            data = f.read(vk.data_length.length)
                        elif vk.type == 4: # DWORD
                            f.seek(4096 + vk.data_offset)
                            data = f.read(vk.data_length.length)
                    
                    if data:
                        if vk.type in (1, 2, 7): # TODO multisz
                            data_interpreted = data.decode('UTF-16LE', 'ignore')
                            #print('str ', data_interpreted)
                        elif vk.type == 7:
                            data_interpreted = data
                        elif vk.type == 4:
                            data_interpreted = struct.unpack('<I', data[0:4])[0]
                            #print('int ', data_interpreted)
                        elif vk.type == 11: # qword
                            data_interpreted = struct.unpack('<Q', data[0:8])[0]
                if vk.type not in (0, 1, 2, 3, 4, 7, 11):
                    print(vk.type, name, data)

                vk_cell = VkCell(vk.flags, name, vk.data_length.length, vk.data_offset, vk.type)
                vk_objects[start_pos - 4100] = vk_cell
                #break
            elif match.group(0)[2:3] == b'n':
                nk_data = f.read(size)
                nk = NKCELL.parse(nk_data)
                if nk.name_length > 0:
                    name = nk_data[80 : 80 + nk.name_length].decode('utf8')
                    #print(f"timestamp = {ReadWinFileTime(nk.last_write_time)} name = {name}")
                    nk_cell = NkCell(nk.flags, nk.last_write_time, nk.parent_cell_offset, nk.subkey_count_stable,
                                    nk.subkey_list_offset_stable, nk.value_count, nk.value_list_offset,
                                    nk.security_key_offset, name)
                    nk_objects[start_pos - 4100] = nk_cell

    print(len(nk_objects), len(vk_objects))

    # Try to read values
    

if __name__ == "__main__":
    main()
