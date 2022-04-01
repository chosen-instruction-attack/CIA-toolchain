#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    :   batchForCAA.py
@Time    :   2020/11/04 17:53:28
@Author  :   Spook3r 
@Version :   1.0
@Contact :   
@License :   BSD
@Desc    :   None
'''

# call caller.py iteratively
import sys, getopt
import os
import json

# target instruction mapping tables directory
insPath = './ins_records/'

def main(argv):
    obfuscator = ""
    simulation = "0"
    json_store = "0"
    file_dir = ""
    less = "0"

    try:
        opts, args = getopt.getopt(argv, "ho:f:j:sl")
    except getopt.GetoptError:
        print("batchForCAA.py -o Obfuscator -f file_dir -j json_store [-s -l]")
        sys.exit(2)
    
    for opt, arg in opts:
        if opt == '-h':
            print("batchForCAA.py -o Obfuscator -f file_dir -j json_store [-s -l]")
            sys.exit(2)
        
        # obfuscator type: VMProtect or CV
        elif opt =='-o':
            obfuscator = arg
        
        # directory of test files
        elif opt =='-f':
            file_dir = arg
        
        # storage path of result json file
        elif opt =='-j':
            json_store = arg
            if not os.path.exists(json_store):
                os.makedirs(json_store)
        
        # symbolic execution
        elif opt =='-s':
            simulation = "1"

        # less version: only record the kernel instruction list
        elif opt =='-l':
            less = "1"

    # selection of target instruction mapping table
    if obfuscator == "VMProtect":
        ins_dir = os.path.join(insPath, "out_vmp3_formal.json")
    elif obfuscator == "CV":
        ins_dir = os.path.join(insPath, "out_cvtiger_formal.json")
    else:
        ins_dir = os.path.join(insPath, "out_for_OBS.json")

    with open(ins_dir, "r") as ins_file:
        ins_list = json.load(ins_file)
        for ins_data in ins_list:
            print(ins_data["ins"])
            os.system('python caller.py -t {filename}.log -p {filename}.exe -i "{ins}" -o {obf} -s {sim} -j {str} -l {less}'
                .format(filename = os.path.join(file_dir, ins_data["name"]), ins = ins_data["ins"], obf = obfuscator, sim = simulation, str = json_store, less = less))


if __name__ == "__main__":
    main(sys.argv[1:])
