#!/usr/bin/env python
# coding: utf-8

import angr
import os
import cle
import json
from capstone import *
from capstone.arm64 import *
from angrutils import *
import time

ARM64_OP_REG = 1
ARM64_OP_MEM = 3

def check_library_func(proj):
    ret_val = False
    symtab = proj.loader.main_object.symbols  # imports
    for symbol in symtab:
        if symbol.name is not None and (symbol.name.startswith("EVP_") or "crypt" in symbol.name):
            print(symbol.name)
            ret_val = True

def check_cryptoConstants(proj):
    with open('database_full.json', 'r') as json_file:
        json_data = json_file.read()

    try:
        parsed_data = json.loads(json_data)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        return

    ret_val = False
    for item in parsed_data:
        name = item.get('name', 'N/A')
        pattern = bytes.fromhex(item.get('hexBytes', 'N/A'))
        results = proj.loader.memory.find(pattern)
        sBox_loc = set()
        for addr in results:
            sBox_loc.add(addr)
            print(f"{name} found at address: 0x{addr:08x}")

def analyze_directory(directory_path):
    #exe_paths = [os.path.join(directory_path, 'dbclient.exe')]  # initial executable path
    exe_paths =[]
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        if os.path.isfile(file_path) and filename.lower().endswith(('.exe', '.dll')):
            exe_paths.append(file_path)

    proj_list = {}
    for exe_path in exe_paths:
        proj = angr.Project(exe_path, load_options={'auto_load_libs': False})
        print(f"Analyzing {exe_path}")
        print(proj.loader.all_objects)
        check_library_func(proj)
        check_cryptoConstants(proj)

def main(directory_path):
    analyze_directory(directory_path)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python script_name.py <directory_path>")
        sys.exit(1)
    main(sys.argv[1])
