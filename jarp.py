"""
(c) 2023 Yogesh Khatri, @swiftforensics

Recover registry records from partially overwritten
registry hives.

Does not scan SK (security) records yet.

"""

import argparse
import codecs
import datetime
import os
import mmap
import re
import sqlite3
import struct

from construct import *
from construct.core import Int32ul, Int64ul, Int16ul, Int8ul, Int32sl
from enum import IntEnum

__VERSION = "0.6.1"

rot13 = lambda x : codecs.getencoder("ROT-13")(x)[0]

class RegTypes(IntEnum):
    RegNone = 0
    RegSZ = 1
    RegExpandSZ = 2
    RegBin = 3
    RegDWord = 4
    RegBigEndian = 5
    RegLink = 6
    RegMultiSZ = 7
    RegResourceList = 8
    RegFullResourceDescriptor = 9
    RegResourceRequirementsList = 0xA
    RegQWord = 0xB
    RegFileTime = 0x10

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
    "data_offset" / Int32ul,
    "type" / Int32ul,
    "flags" / Int16ul,
    "spare" / Int16ul
    # followed by Name string
    # followed by Padding to defined size (stored as -ve)
)

class NkCell:
    id = 1
    def __init__(self, flags, last_write_time, parent_cell_offset, 
                subkey_count_stable, subkey_list_offset_stable, value_count,
                value_list_offset, security_key_offset, name, file_offset) -> None:
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
        self.file_offset = file_offset
        # assign unique id for DB
        self.id = NkCell.id
        NkCell.id += 1

class VkCell:
    def __init__(self, flags, name, data_length, data_offset, value_type, value, file_offset) -> None:
        self.flags = flags
        self.name = name
        self.data_length = data_length
        self.data_offset = data_offset
        self.value_type = value_type
        self.value = value
        self.file_offset = file_offset
        self.nk_parent = None

def ReadWinFileTime(win64_timestamp): # FILETIME is 100ns ticks since 1601-1-1
    '''Returns datetime object, or empty string upon error'''
    if win64_timestamp not in ( 0, None, ''):
        try:
            if isinstance(win64_timestamp, str):
                win64_timestamp = float(win64_timestamp)

            return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=win64_timestamp/10)
        except Exception as ex:
            print("[!] ReadWinFileTime() Failed to convert timestamp from value " + str(win64_timestamp) + " Error was: " + str(ex))
    return ''

def main():
    description =  f"\nJARP version {__VERSION}\n (c) Yogesh Khatri 2023 @swiftforensics\n"
    epilog = 'Just Another (broken) Registry Parser (JARP) was created to read \n'\
            'registry files that were partially corrupted and/or encrypted. \n'\
            'JARP will write all recovered keys & values to an sqlite\n'\
            'database and also output data on the console (if needed).\n'
    parser = argparse.ArgumentParser(
        description=description, epilog=epilog, 
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('reg_path', help='Path to ESE database file')
    parser.add_argument('-o', '--output_path', help='Output file name and path')
    parser.add_argument('-p', '--print_to_screen', action='store_true', help='Print output to screen')
    parser.add_argument('-n', '--no_UA_decode', action='store_true', help='Do NOT decode rot13 for UserAssist (Default is to decode)')
    
    args = parser.parse_args()

    input_path = args.reg_path
    output_path = args.output_path

    # Check inputs
    try:
        if os.path.exists(input_path) and os.path.isfile(input_path):
            pass
        else:
            print("[!] Registry path is not valid! Path provided was {}".format(input_path))
            print("[!] Exiting..")
            return
    except (IOError, OSError) as ex:
        print("[!] Unknown error with ese db path. Error was {}".format(str(ex)))
        print("[!] Exiting..")
        return

    if not output_path:
        output_path = input_path + '.sqlite.db'

    if os.path.exists(output_path):
        print ("[+] File {} already exists, trying to delete it.".format(output_path))
        try:
            os.remove(output_path)
        except OSError as ex:
            print("[!] Failed to delete existing file {} \nError was {}".format(output_path, str(ex)))
            print("[!] Exiting..")
            return

    RecoverRegToSqlite(input_path, output_path, not args.no_UA_decode, args.print_to_screen)

def RecoverRegToSqlite(input_path, output_path, user_assist_decode, print_to_screen=False):
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
            start_pos = match.start() - 2
            f.seek(start_pos)
            size = -struct.unpack("<i", f.read(4))[0]
            f.seek(start_pos)
            if match.group(0)[2:3] == b'v':
                vk_data = f.read(size)
                vk = VKCELL.parse(vk_data)
                if vk.name_length > 0:
                    name = vk_data[24 : 24 + vk.name_length].decode('utf8')
                else:
                    name = ''

                data = None
                data_interpreted = None

                if vk.data_length.length > 0:

                    if vk.data_length.data_flag & 8 == 8: # data is stored in data_offset
                        data = vk_data[12:16]
                    elif vk.data_offset > 0 and \
                        (vk.data_offset + 4096 + vk.data_length.length) <= file_size:
                        if vk.type in (RegTypes.RegSZ, RegTypes.RegExpandSZ, RegTypes.RegBin, RegTypes.RegMultiSZ, RegTypes.RegQWord): # types 1, 2, 3, 7, 11
                            f.seek(4096 + vk.data_offset + 4)
                            data = f.read(vk.data_length.length)
                        elif vk.type == RegTypes.RegDWord: # type 4
                            f.seek(4096 + vk.data_offset)
                            data = f.read(vk.data_length.length)
                    
                    if data:
                        if vk.type == RegTypes.RegBin:
                            data_interpreted = data
                        elif vk.type in (RegTypes.RegSZ, RegTypes.RegExpandSZ):
                            data_interpreted = data.decode('UTF-16LE', 'ignore')
                        elif vk.type == RegTypes.RegMultiSZ: # 7
                            data_interpreted = data.decode('UTF-16LE', 'ignore')#.replace('\x00', '\n').rstrip('\n')
                        elif vk.type == RegTypes.RegDWord: # 4
                            data_interpreted = struct.unpack('<I', data[0:4])[0]
                        elif vk.type == RegTypes.RegQWord: # 11
                            data_interpreted = struct.unpack('<Q', data[0:8])[0]
                if vk.type not in (0, 1, 2, 3, 4, 7, 11):
                    print("[-] Type not seen before", vk.type, name, data)

                vk_cell = VkCell(vk.flags, name, vk.data_length.length, vk.data_offset, vk.type, data_interpreted, start_pos)
                vk_objects[start_pos - 4096] = vk_cell

            elif match.group(0)[2:3] == b'n':
                nk_data = f.read(size)
                nk = NKCELL.parse(nk_data)
                if nk.name_length > 0:
                    name = nk_data[80 : 80 + nk.name_length].decode('utf8')
                    nk_cell = NkCell(nk.flags, nk.last_write_time, nk.parent_cell_offset, nk.subkey_count_stable,
                                    nk.subkey_list_offset_stable, nk.value_count, nk.value_list_offset,
                                    nk.security_key_offset, name, start_pos)
                    nk_objects[start_pos - 4096] = nk_cell

        print(f"[+] Read {len(nk_objects)} NK objects and {len(vk_objects)} VK objects")

        # Try to get parents
        for address, nk in nk_objects.items():
            nk.path = FindPath(nk_objects, nk, '')
            #print(f'{nk.path}/{nk.name}')

        # For each nk, go to value_list_offset and read value_count items, each item is offset to vk
        parent_present_count = 0
        mising_vk_count = 0
        for address, nk in nk_objects.items():
            if nk.value_count > 0:
                offset = nk.value_list_offset
                if offset > 0 and (offset + 4096 + 4*nk.value_count) < file_size:
                    f.seek(offset + 4096)
                    data = f.read(4 + (nk.value_count * 4))
                    size = struct.unpack('<i', data[0:4])[0]
                    if size >= -3 or (size + len(data) >= 8): # size is -ve, difference can't be more than 8 bytes!
                        continue
                    offsets = struct.unpack(f'<{nk.value_count}I', data[4:])
                    
                    for offset in offsets:
                        vk = vk_objects.get(offset, None)
                        if vk:
                            vk.nk_parent = nk
                            parent_present_count += 1
                        else:
                            mising_vk_count += 1

        # Add to SQLITE db
        if AddToSqliteDb(output_path, vk_objects, nk_objects, user_assist_decode):
            print('[+] Sqlite db written')
        # PRINT results
        if print_to_screen:
            orphan_count = 0
            for address, vk in vk_objects.items():
                if vk.nk_parent is None:
                    orphan_count += 1
                else:
                    if user_assist_decode and re.search('UserAssist/{[^}]*}/Count', vk.nk_parent.path + '/' + vk.nk_parent.name):
                        print(f'{vk.nk_parent.path}/{vk.nk_parent.name}', rot13(vk.name), RegTypes(vk.value_type).name, vk.value, f"key_mod_date={ReadWinFileTime(vk.nk_parent.last_write_time)}")
                    else:
                        print(f'{vk.nk_parent.path}/{vk.nk_parent.name}', vk.name, RegTypes(vk.value_type).name, vk.value, f"key_mod_date={ReadWinFileTime(vk.nk_parent.last_write_time)}")
            print(f"[+] Located path for {parent_present_count} vk entries, {orphan_count} vk are orphan, {mising_vk_count} vk not present in file")

def OpenSqliteDbConn(sqlite_path):
    try:
        conn = sqlite3.connect(sqlite_path)
        return conn
    except Exception as ex:
        print('[!] Failed to create sqlite db at {}'.format(sqlite_path))    
    return None

def ExecuteQuery(cursor, query):
    try:
        cursor.execute(query)
        return True
    except sqlite3.Error as ex:
        print('[!] Failed to execute query {query}')
        print('[!] Error was', str(ex))
    return False

def insert_rows_into_db(cursor, exec_many_query, table_name, rows):
    try:
        cursor.executemany(exec_many_query, rows)
    except:
        print(f'[!] Error inserting data to sqlite db table "{table_name}"')

def AddToSqliteDb(sqlite_path, vk_objects, nk_objects, user_assist_decode):
    conn = OpenSqliteDbConn(sqlite_path)
    if not conn:
        return False

    c = conn.cursor()
    createQuery = 'CREATE TABLE IF NOT EXISTS "RegKeys" (Id INTEGER NOT NULL PRIMARY KEY, Name TEXT, Path TEXT, LastWriteTime TEXT, SubkeyCount INTEGER, ValueCount INTEGER, NKoffset INTEGER)'
    if not ExecuteQuery(c, createQuery):
        return False

    createQuery = 'CREATE TABLE IF NOT EXISTS "RegValues" (Name TEXT, KeyId INTEGER, Type TEXT, ValueStr TEXT, ValueBin BLOB, ValueInt INTEGER, VKoffset INTEGER)'
    if not ExecuteQuery(c, createQuery):
        return False

    add_keys_query = 'INSERT INTO "RegKeys" VALUES (?,?,?,?,?,?,?)'
    rows = []
    for _, nk in nk_objects.items():
        rows.append((nk.id, nk.name, nk.path, ReadWinFileTime(nk.last_write_time), nk.subkey_count_stable, nk.value_count, nk.file_offset))
    insert_rows_into_db(c, add_keys_query, 'RegKeys', rows)

    add_values_query = 'INSERT INTO "RegValues" VALUES (?,?,?,?,?,?,?)'
    rows = []
    for _, vk in vk_objects.items():
        value_str = None
        value_blob = None
        value_int = None
        name = vk.name
        id = -1            
        if vk.nk_parent:
            id = vk.nk_parent.id
            if user_assist_decode and re.search('UserAssist/{[^}]*}/Count', vk.nk_parent.path + '/' + vk.nk_parent.name):
                name = rot13(name)
        if vk.value:
            if vk.value_type in (RegTypes.RegSZ, RegTypes.RegExpandSZ, RegTypes.RegMultiSZ):
                value_str = vk.value.rstrip('\x00')
            elif vk.value_type in (RegTypes.RegQWord, RegTypes.RegDWord):
                value_int = vk.value
            elif vk.value_type == RegTypes.RegBin:
                value_blob = vk.value
        rows.append((name, id, RegTypes(vk.value_type).name, value_str, value_blob, value_int, vk.file_offset))
    insert_rows_into_db(c, add_values_query, 'RegValues', rows)
    
    # create view
    view_query = """
        CREATE VIEW View1 AS
        SELECT
            CASE KeyId
                WHEN -1 THEN "Unknown-ORPHANED"
                ELSE (RegKeys.Path || '/' || RegKeys.Name) END KeyPath, 
            CASE RegValues.Name 
                WHEN '' THEN '(Default)'
                ELSE RegValues.Name END ValueName, 
            Type, ValueStr, ValueBin, ValueInt, 
            RegKeys.LastWriteTime as KeyLastMod
        FROM RegValues LEFT JOIN RegKeys ON RegKeys.Id=RegValues.KeyId
        WHERE NOT (RegValues.Name LIKE "" and Type LIKE "RegSZ" and RegValues.ValueStr LIKE "")
        ORDER BY KeyPath
    """
    conn.commit()
    conn.close()
    return True

def insert_rows_into_db(cursor, exec_many_query, table_name, rows):
    try:
        cursor.executemany(exec_many_query.format(table_name), rows)
    except sqlite3.Error as ex:
        print(f'[!] Error inserting data to sqlite db table "{table_name}"')

def FindPath(objects, node, path):
    if node.flags & 0xC == 0xC:
        # node is root
        return path
    parent_node = objects.get(node.parent_cell_offset, None)
    if parent_node:
        if path:
            path = parent_node.name + '/' + path
        else:
            path = parent_node.name
        path = FindPath(objects, parent_node, path)
    else:
        if path:
            path = '**UNKNOWN**/' + path
        else:
            path = '**UNKNOWN**'
    
    return path

if __name__ == "__main__":
    main()
