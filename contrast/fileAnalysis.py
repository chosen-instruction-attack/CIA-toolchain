#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    :   fileAnalysis.py
@Time    :   2021/03/15 14:53:17
@Author  :   Spook3r 
@Version :   1.0
@Contact :   
@License :   BSD
@Desc    :   None
'''

# call ContrastForVM.py iteratively and generate reports
import sys, getopt
import os
import json
import openpyxl
from ContrastForVM import ContrastForVM

insPath = './ins_records/'

def empty_test(obfuscator, filePath):
    """
    Test if the benchmark is complete for contrast
    """
    tmpContrast = ContrastForVM(filePath=filePath, obfuscator=obfuscator, full_list=False)

    if obfuscator == "VMProtect":
        ins_dir = os.path.join(insPath, "file_vmp3_formal.json")

    elif obfuscator == "CV":
        ins_dir = os.path.join(insPath, "file_cvtiger_formal.json")

    with open(ins_dir, "r") as ins_file:
        insMap = json.load(ins_file)
    
    for filename in insMap:
        Found = tmpContrast._dataImport(filename + ".json")
        if not Found:
            print("[-]" + filename + "not found")
            continue
        
        if tmpContrast.kernelCheck():
            print(filename)
        
        tmpContrast.flush()

def run(obfuscator, filePath, full_list=False, simple=False, reportPath="", contrast=False, excelName="", log=False, deobfPath="", vmhuntPath=""):
    tmpContrast = ContrastForVM(filePath=filePath, obfuscator=obfuscator, full_list=full_list)
    
    if obfuscator == "VMProtect":
        ins_dir = os.path.join(insPath, "file_vmp3_formal.json")

    elif obfuscator == "CV":
        ins_dir = os.path.join(insPath, "file_cvtiger_formal.json")

    with open(ins_dir, "r") as ins_file:
        # instruction mapping table
        insMap = json.load(ins_file)
        if contrast:
            tmpContrast._contrastPrepare(insMap=insMap, deobfPath=deobfPath, vmhuntPath=vmhuntPath)
    
    if reportPath:
        if not os.path.exists(reportPath):
            os.mkdir(reportPath)
    
    if excelName:
        wb = openpyxl.Workbook()
        ws = wb['Sheet']
        ws.append(["index", "filename", "instruction", "valid_amount", "kernel_amount", "deobf_recovery", "deobf_total", "deobf_reduced", "deobf_redun_T", "deobf_redun_R", "deobf_rate", "vmhunt_recovery", "vmhunt_total", "vmhunt_reduced", "vmhunt_redun_T", "vmhunt_redun_R", "vmhunt_rate", "simulation_result"])
        wb.save(excelName + '.xlsx')
    
    for filename in insMap:
        Found = tmpContrast._dataImport(filename)
        if not Found:
            print("[-]" + filename + "not found")
            continue
        
        tmpContrast.insListFilter()

        if reportPath:
            tmpContrast.outputHtmlReport(reportPath)
        
        if simple:
            tmpContrast.printListToFile(choice = "kernel")
        
        if contrast:
            tmpContrast._contrastUpdate()
            if obfuscator == "VMProtect":
                if deobfPath:
                    tmpContrast.contrastForVMP_Deobf(log)
                if vmhuntPath:
                    tmpContrast.contrastForVMP_VMHunt_anchor(log)
            
            elif obfuscator == "CV":
                if deobfPath:
                    tmpContrast.contrastForCV_Deobf(log)
                if vmhuntPath:
                    tmpContrast.contrastForCV_VMHunt(log)

            if excelName:
                tmpContrast.excelGeneration(excelName)
        
        tmpContrast.flush()
    
    if reportPath:
        tmpContrast.makeTemplateFiles(reportPath)


def main(argv):
    obfuscator = ""
    filePath = ""
    contrast = False
    excelName = ""
    reportPath = ""
    deobfPath = ""
    vmhuntPath = ""
    log = False
    default_set = False
    full_list = False
    test = False
    simple = False

    try:
        opts, args = getopt.getopt(argv, "ho:p:arcelmd:v:tz")
    except getopt.GetoptError:
        print("fileAnalysis.py -o Obfuscator -p filePath [-a -r reportPath -c -e excelName -l -m -d deobfPath -v vmhuntPath -t]")
        sys.exit(2)
    
    for opt, arg in opts:
        if opt == '-h':
            print("fileAnalysis.py -o Obfuscator -p filePath [-a -r reportPath -c -e excelName -l -m -d deobfPath -v vmhuntPath -t]")
            sys.exit(2)
        
        elif opt =='-o':
            # obfuscator type: vmprotect or CV
            obfuscator = arg
        
        elif opt =='-p':
            # trace files path
            filePath = arg
        
        elif opt =='-a':
            # consider full instruction list
            full_list = True
        
        elif opt =='-r':
            # HTML report path to store
            reportPath = arg
        
        elif opt =='-c':
            # launch a contrast
            contrast = True
        
        elif opt =='-e':
            # generate an excel file
            excelName = arg
        
        elif opt =='-l':
            # print log
            log = True
        
        elif opt =='-d':
            # file path for Deobfuscator's results
            deobfPath = arg
        
        elif opt =='-v':
            # file path for VMHunt's results
            vmhuntPath = arg
        
        elif opt =='-t':
            # test if the benchmark is complete
            test = True
        
        elif opt =='-z':
            # print kernel lists to text files
            simple = True
        
        elif opt =='-m':
            # default mode
            default_set = True
        
    if test:
        empty_test(obfuscator, filePath)
        return

    if default_set:
        obfuscator = "VMProtect"
        full_list = True
        log = False
        contrast = True
        index = "first"
        type = "vmp3"
        deobfPath = f'./deobfTraces/simplified_{type}_final/{index}/'
        vmhuntPath = f'./deobfTraces/vmhunt_{type}/{index}/'
        filePath = f'./CAA_result/{type}_formal/{index}/'
        reportPath = os.path.join(filePath + "report")
        excelName = f'{type}_anchor_formal_{index}'
    
    run(obfuscator, filePath, full_list, simple, reportPath, contrast, excelName, log, deobfPath, vmhuntPath)


if __name__ == "__main__":
    main(sys.argv[1:])
