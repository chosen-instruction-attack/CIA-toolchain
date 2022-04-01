#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    :   caller.py
@Time    :   2020/10/25 17:52:58
@Author  :   Neko
@Version :   1.0
@Contact :
@License :   BSD
@Desc    :   None
'''

# here put the import lib
import sys, getopt
from TraceAnalysis import TraceAnalysis, l
from DataType import Register
import logging

def analysis(tracePath, programPath, originalINS, obfuscator, mode, simulation, less, json_store):
    toperator = TraceAnalysis(traceFileName=tracePath, programFileName=programPath, anchor=None, originalINS=originalINS, originalRegister=None, obfuscator=obfuscator)

    if mode == "context":
        toperator.searchContextSwitch(mode="standard",flag=True)
    else:
        # toperator.searchContextSwitch(mode="standard",flag=False)
        toperator.backwardSlicing(toperator._dstRegister)
        if json_store:
            # toperator.printSlicesToFile(json_store, "full")
            toperator.printSlicesToFile(json_store, "kernel")
            return
        # print("\n")

        if obfuscator == "VMProtect":
            if originalINS != "rdtsc":
                toperator.forwardConcrete() # cannot work for rdtsc in vmp3 if on
            toperator.concreteMemory()
            # toperator.printSlices(False)
            
            # if json_store:
            #     toperator.printSlicesToFile(json_store, "kernel")

            # toperator._KERNEL_INS_LIST = toperator._KERNEL_INS_LIST[:18]
            # originalLen = len(toperator._KERNEL_INS_LIST)
            # toperator.valueSetAnalysis()

            tmp = toperator._INS_LIST
            toperator._INS_LIST=toperator._KERNEL_INS_LIST
            toperator._KERNEL_INS_LIST=[]
            toperator.backwardSlicing(toperator._dstRegister)
            toperator._INS_LIST=tmp
            # TODO VSA introduce reduandant instructions
            toperator._KERNEL_INS_LIST = list(dict.fromkeys(toperator._KERNEL_INS_LIST))
            # newLen = len(toperator._KERNEL_INS_LIST)
            # print("Lenght of trace", (originalLen-newLen)/originalLen)

            if json_store:
                toperator.printSlicesToFile(json_store, "kernel")
       
        else:
            pass
            toperator.concreteMemory()
            # if json_store:
            #     toperator.printSlicesToFile(json_store, "kernel")
            # if json_store:
            #     toperator.printSlicesToFile(json_store, "kernel")
            #     toperator.printSlicesToFile("tmpdir", "full")
        
        if simulation:
            toperator.symbolicExecution()
        
    # print("[+] Final result")
    # print('-'*30)
    # toperator.printSlices(False)
    if json_store:
        toperator.outputToFile(json_store, less)
    
    # print("[+] Final result")
    # print('-'*30)
    # toperator.printSlices(False)

    # print("[+] Insturctions with Hanlder Mark")
    # print('-'*30)
    # toperator.exportHandlerSlices(flag=False)

    
def main(argv):
    tracePath = ""
    programPath = ""
    originalINS = ""
    obfuscator = ""
    mode = ""
    simulation = False
    json_store = ""
    less = False

    try:
        opts, args = getopt.getopt(argv, "ht:p:i:o:m:s:j:l:")
    except getopt.GetoptError:
        print("caller.py -t TraceFile -p VirtualizedProgram -i OriginalInstruction -o Obfuscator -m Mode -s simulation -j json_file -l less")
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print("caller.py -t TraceFile -p VirtualizedProgram -i OriginalInstruction -o Obfuscator -m Mode -s simulation -j json_file -l less")
            sys.exit(2)

        elif opt == '-t':
            # trace file path
            tracePath = arg

        elif opt == '-p':
            # program file path
            programPath = arg

        elif opt =='-i':
            # orignal instruction string
            originalINS = arg

        elif opt =='-o':
            # obfuscator type: vmprotect or CV
            obfuscator = arg
        
        elif opt == '-m':
            # mode: context
            mode = arg
        
        elif opt =='-s':
            # symbolic execution
            if arg == "1":
                simulation = True
        
        elif opt =='-l':
            # less version: only record the kernel instruction list
            if arg == "1":
                less = True
        
        elif opt =='-j':
            # path of result json file to store
            json_store = arg

    analysis(tracePath, programPath, originalINS, obfuscator, mode, simulation, less, json_store)


if __name__ == "__main__":
    l.setLevel(logging.INFO)
    main(sys.argv[1:])
