#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    :   ContrastForVM.py
@Time    :   2021/03/12 10:12:38
@Author  :   Spook3r 
@Version :   1.0
@Contact :   
@License :   BSD
@Desc    :   None
'''

import openpyxl
import os
import re
import json
from FileHandleType import *
from html import escape

# extract information from Deobfuscator's traces
extractFromDeobf = re.compile('.*?: \\[0x0{0,7}(.*?)\\] (.*?) .*?', re.S)

class ContrastForVM(object):
    
    _INS_LIST = []        # original instruction list
    _KERNEL_LIST = []     # kernel instruction list (in normal order)
    _CORE_LIST = []       # _KERNEL_LIST removed transfer instructions (in normal order)

    _transfer_ins = ['mov', 'lea', 'push', 'pop', 'xchg', 'cmpxchg', 'pushfd', 'popfd', 'pushad', 'popad', 'pushal', 'popal', 'movzx', 'movsx'] # 'movzx', 'movsx'
    
    def __init__(self, filePath: str, obfuscator: str, full_list: bool):
        """
        """
        self._filePath = filePath
        self._obfuscator = obfuscator
        self._full_list = full_list
    
    def _dataImport(self, filename: str):
        """
        Import data from json file according to the filename
        """
        if "mov" in filename and "movzx" in self._transfer_ins: # when testing movzx/movsx, exclude them from "transfer instruction" list
            self._transfer_ins.remove("movzx")
            self._transfer_ins.remove("movsx")

        if "mov" not in filename and "movzx" not in self._transfer_ins:
            self._transfer_ins += ["movzx", "movsx"]
        
        try:
            with open(os.path.join(self._filePath, filename + ".json"), "r") as f:
                self._data = json.load(f)
                for ins in self._data["kernel_list"]:
                    self._KERNEL_LIST.append(InsLine(ins))
                
                if self._full_list:
                    for ins in self._data["full_list"]:
                        self._INS_LIST.append(InsLine(ins))
            return True
        except:
            return False
    
    def _contrastPrepare(self, insMap: dict, deobfPath: str, vmhuntPath: str):
        """
        Initialization for contrast 
        """
        self._deobfPath = deobfPath
        self._vmhuntPath = vmhuntPath
        self._insMap = insMap
        self._compare = DataLine()
        
        # import deobfucator redundancy data
        if self._deobfPath:
            with open(os.path.join(self._deobfPath, "redundancy.txt"), "r") as r:
                redunList = r.readlines()
                for key, redun in zip(self._insMap, redunList):
                    self._insMap[key] = redun.strip()
    
    def insListFilter(self):
        """
        Divide instructions into 3 types:
           kernel: instructions for core operations
           transfer: instructions for value transfers
           garbage: redundant instructions sliced out (default)
        """
        if self._obfuscator == "CV":
            for ins in self._KERNEL_LIST[::-1]:    # reversed order
                # there is only one kernel instruction in a CV trace
                if ins.mnemonic not in self._transfer_ins and not self._CORE_LIST:
                    ins.type = "kernel"
                    self._CORE_LIST.append(ins)
                else:
                    ins.type = "transfer"
        
        elif self._obfuscator == "VMProtect":
            for ins in self._KERNEL_LIST:
                if ins.mnemonic in self._transfer_ins:
                    ins.type = "transfer"
                else:
                    ins.type = "kernel"
                    self._CORE_LIST.append(ins)
        
        if self._full_list:
            kernel_index_list = []
            transfer_index_list = []
            for ins in self._KERNEL_LIST:
                if ins.type == "kernel":
                    kernel_index_list.append(ins.index)
                else:
                    transfer_index_list.append(ins.index)

            for ins in self._INS_LIST:
                if ins.index in kernel_index_list:
                    ins.type = "kernel"
                elif ins.index in transfer_index_list:
                    ins.type = "transfer"
                    
    def kernelCheck(self):
        """
        Empty benchmark test
            Test if a result's kernel list contains no core instruction (only transfer instructions)
            If so, this one could not be used for contrast
        """
        for ins in self._KERNEL_LIST:
            if ins.mnemonic not in self._transfer_ins:
                return False
        return True  # empty core list
    
    def _contrastUpdate(self):
        """
        Update data in contrast result
        """
        self._compare.valid_amount = len(self._CORE_LIST)
        self._compare.kernel_amount = len(self._KERNEL_LIST)
    
    def contrastForVMP_Deobf(self, log=False):
        """
        Contrast between Deobfuscator's results and benchmark for VMProtect
        """
        redundant_num = self._insMap[self._data["filename"]]
        
        if self._deobfPath:
            if log:
                print("{filename}: {instr}".format(filename=self._data["filename"], instr=self._data["ins"]))
            # [1] Deobfuscator part
            if redundant_num == "x":    # Deobfuscator failed to handle
                print('Deobfuscator failed to handle\n')
                
            else:
                redundant_num = int(redundant_num)
                with open(os.path.join(self._deobfPath, self._data["filename"] + '.simplified'), 'r') as f:
                    simplifiedDeobf = f.readlines()
                    # empty result
                    if not simplifiedDeobf:
                        self._compare.deobf.recovery = self._compare.deobf.reduced = 0
                    else:
                        self._compare.deobf.recovery, self._compare.deobf.reduced, success = self.calculateRatios(simplifiedDeobf, self._CORE_LIST, "deobf")

                if log:
                    if self._compare.deobf.recovery == self._compare.valid_amount:
                        print("[success] {all}/{all} {full}".format(all=self._compare.valid_amount, full=self._compare.deobf.reduced))
                    elif 0 < self._compare.deobf.recovery < self._compare.valid_amount:
                        print("[partly] {c}/{all} {full}".format(c=self._compare.deobf.recovery, all=self._compare.valid_amount, full=self._compare.deobf.reduced))
                        for s in success:
                            print("[{addr}] {m} {o}".format(addr=s.address, m=(s.mnemonic), o=(s.op_str)))
                    elif self._compare.deobf.recovery == 0:
                        print("[failed] 0/{all}".format(all=self._compare.valid_amount))
                    print("original:")
                    for c in self._CORE_LIST:
                        print("[{addr}] {m} {o}".format(addr=c.address, m=(c.mnemonic), o=(c.op_str)))
                
                try:
                    self._compare.deobf.rate  = self._compare.deobf.recovery/self._compare.valid_amount
                except:
                    self._compare.deobf.rate = 0

                self._compare.deobf.total = self._compare.deobf.reduced + redundant_num
                if self._compare.deobf.recovery == 0:
                    self._compare.deobf.redun_T = self._compare.deobf.redun_R = None
                else:
                    self._compare.deobf.redun_T = 1 - self._compare.deobf.recovery/self._compare.deobf.total
                    self._compare.deobf.redun_R = 1 - self._compare.deobf.recovery/self._compare.deobf.reduced
 
    def contrastForVMP_VMHunt_anchor(self, log=False):
        """
        Contrast between results of VMHunt (with anchor) and benchmark for VMProtect
        """
        with open(os.path.join(self._vmhuntPath, self._data["filename"] + '.txt'), 'r') as f:
            simplifiedVM = f.readlines()
            self._compare.vmhunt.recovery, self._compare.vmhunt.reduced, _ = self.calculateRatios(simplifiedVM, self._CORE_LIST, "this")
            try:
                self._compare.vmhunt.rate  = self._compare.vmhunt.recovery/self._compare.valid_amount
            except:
                self._compare.vmhunt.rate = 0
            
            self._compare.vmhunt.total = self._compare.vmhunt.reduced
            if self._compare.vmhunt.recovery == 0:
                self._compare.vmhunt.redun_T = self._compare.vmhunt.redun_R = None
            else:
                self._compare.vmhunt.redun_T = self._compare.vmhunt.redun_R = 1 - self._compare.vmhunt.recovery/self._compare.vmhunt.reduced


    def contrastForCV_Deobf(self, log=False):
        """
        Contrast between results of Deobfuscator and benchmark for Code Virtualizer
        """
        redundant_num = self._insMap[self._data["filename"]]

        if not self._CORE_LIST: # trace has no core instruction
            if log:
                print("pass")
        else:
            coreIns = self._CORE_LIST[0]
            if log:
                print("{filename}: {instr}".format(filename=self._data["filename"], instr=self._data["ins"]))
                print("coreIns: {}: {}, {} {};".format(coreIns.index, coreIns.address, coreIns.mnemonic, coreIns.op_str))
            
            if redundant_num == "x":
                if log:
                    print("Deobfuscator failed to handle")
            else:
                redundant_num = int(redundant_num)
                with open(self._deobfPath + self._data["filename"] + '.simplified', 'r') as f:
                    simplifiedDeobf = f.readlines()
                    # empty result
                    if not simplifiedDeobf:
                        self._compare.deobf.recovery = self._compare.deobf.reduced = 0
                    else:
                        self._compare.deobf.recovery, self._compare.deobf.reduced, _ = self.calculateRatios(simplifiedDeobf, self._CORE_LIST, "deobf")
                
                self._compare.deobf.rate = self._compare.deobf.recovery
                self._compare.deobf.total = self._compare.deobf.reduced + redundant_num
                if self._compare.deobf.recovery == 0:
                    self._compare.deobf.redun_T = self._compare.deobf.redun_R = None
                    if log:
                        print("[deobf failed] full:{0}, locate:{1}".format(self._compare.deobf.total, self._compare.deobf.reduced))
                else:
                    self._compare.deobf.redun_T = 1 - 1/self._compare.deobf.total
                    self._compare.deobf.redun_R = 1 - 1/self._compare.deobf.reduced
                    if log:
                        print("[deobf success] full:{0}, locate:{1}".format(self._compare.deobf.total, self._compare.deobf.reduced))

    
    def contrastForCV_VMHunt(self, log=False):
        """
        Contrast between results of VMhunt and benchmark for Code Virtualizer
        """
        if not self._CORE_LIST: # trace has no core instruction
            if log:
                print("pass")
        else:
            coreIns = self._CORE_LIST[0]

            files = os.popen("grep -l '{addr};' {path}/*.trace".format(addr = coreIns.address[2:], path = self._vmhuntPath + self._data["filename"])).read().split("\n")
            
            if len(files) > 1:
                self._compare.vmhunt.recovery = self._compare.vmhunt.rate = 1
                files.pop() # remove an empty string at the end

                anchor = open(os.path.join(self._vmhuntPath, self._data["filename"], "anchorfile"), "r")
                anchorBegin, anchorEnd = anchor.read().split(";")
                anchorBegin, anchorEnd = int(anchorBegin), int(anchorEnd)
                anchor.close()

                N_origin = N_locate = 0
                origins = []   # original length of trace
                locates = []   # length of trace between anchors

                for s in files:
                    trace = open(s, "r")
                    for ins in trace.readlines():
                        mnemonic = ins.split(";")[1].split(" ")[0]
                        if mnemonic not in self._transfer_ins and "j" not in mnemonic:
                            num = int(ins.split(",")[-1].strip())
                            N_origin += 1
                            if anchorBegin < num < anchorEnd:
                                N_locate += 1

                    origins.append(N_origin)
                    locates.append(N_locate)
                    N_origin = N_locate = 0
                    trace.close()
                
                self._compare.vmhunt.total = sum(origins)/len(origins) # average length for all results
                if 0 in locates:
                    self._compare.vmhunt.reduced = self._compare.vmhunt.redun_T = self._compare.vmhunt.redun_R = self._compare.vmhunt.recovery = self._compare.vmhunt.rate = None
                    if log:
                        print("[vmhunt abnormal] 0 appears")
                else:
                    self._compare.vmhunt.reduced = sum(locates)/len(locates)  # average length
                    self._compare.vmhunt.redun_T = 1 - 1/self._compare.vmhunt.total
                    self._compare.vmhunt.redun_R = 1 - 1/self._compare.vmhunt.reduced
                    if log:
                        print("[vmhunt success] full:{0}, locate:{1}".format(self._compare.vmhunt.total, self._compare.vmhunt.reduced))
            
            else:
                self._compare.vmhunt.recovery = self._compare.vmhunt.total = self._compare.vmhunt.reduced = self._compare.vmhunt.rate = 0
                self._compare.vmhunt.redun_T = self._compare.vmhunt.redun_R = None
                if log:
                    print("[vmhunt failed]")

    def contrastForCV_VMHunt_anchor(self, log=False):
        """
        Contrast between results of VMHunt (with anchor) and benchmark for Code Virtualizer
        """
        if not self._CORE_LIST: # trace has no core instruction
            if log:
                print("pass")
        else:
            coreIns = self._CORE_LIST[0]
            if log:
                print("{filename}: {instr}".format(filename=self._data["filename"], instr=self._data["ins"]))
                print("coreIns: {}: {}, {} {};".format(coreIns.index, coreIns.address, coreIns.mnemonic, coreIns.op_str))

            with open(os.path.join(self._vmhuntPath, self._data["filename"] + '.vm.trace'), 'r') as f:
                simplifiedVM = f.readlines()
                self._compare.vmhunt.recovery, self._compare.vmhunt.reduced, _ = self.calculateRatios(simplifiedVM, self._CORE_LIST, "vmhunt")
                
                self._compare.vmhunt.rate = self._compare.vmhunt.recovery
                self._compare.vmhunt.total = self._compare.vmhunt.reduced
                if self._compare.vmhunt.recovery == 0:
                    self._compare.vmhunt.redun_T = self._compare.vmhunt.redun_R = None
                    if log:
                        print("[vmhunt failed] full:{0}, locate:{1}".format(self._compare.vmhunt.total, self._compare.vmhunt.reduced))
                else:
                    self._compare.vmhunt.redun_T = self._compare.vmhunt.redun_R = 1 - 1/self._compare.vmhunt.reduced
                    if log:
                        print("[vmhunt success] full:{0}, locate:{1}".format(self._compare.vmhunt.total, self._compare.vmhunt.reduced))

    def flush(self):
        """
        flush the trace data
        """
        self._INS_LIST = []
        self._KERNEL_LIST = []
        self._CORE_LIST = []
    
    def calculateRatios(self, originalList, controlList, type):
        """
        Calculate contrast results with extracted information
        """
        N = 0
        identifiedList = []
        recognizedAddrs = []
        lenOfDeobf = len(originalList)
        for o in originalList:
            if type == "deobf":
                addr1, mnemonic = extractFromDeobf.findall(o)[0]

            elif type == "vmhunt":
                tmp = o.split(";")
                addr1 = tmp[0]
                mnemonic = tmp[1].split()[0]
            
             # used in VMHunt (with anchor) for VMProtect
            elif type == "this":
                tmp = o.split()
                addr1 = tmp[1][2:-1]
                mnemonic = tmp[2]
            
            if "j" in mnemonic or mnemonic in self._transfer_ins:
                lenOfDeobf -= 1
                continue

            # remove duplication
            if addr1 in recognizedAddrs:
                continue
            for c in controlList:
                addr2 = c.address[2:]
                if addr1 == addr2:
                    N += 1
                    recognizedAddrs.append(addr1)
                    identifiedList.append(c)
        return (N, lenOfDeobf, identifiedList)
    
    def outputHtmlReport(self, reportPath, full_output=True):
        """
        Output a HTML report
        """
        html = INITIAL_HTML_TEMPLATE.format(filename = self._data["filename"], ins = self._data["ins"], template = templatePath)
        pre_type = ""
        
        if full_output and self._full_list:
            tmp_list = self._INS_LIST
        else:
            tmp_list = self._KERNEL_LIST
        
        # color instructions depend on the type
        for ins in tmp_list:
            if ins.type != pre_type:
                html += '</span><span class="{}">{}: {}, {} {}<br>\n'.format(ins.type, ins.index, ins.address, ins.mnemonic, ins.op_str)
            else:
                html += '{}: {}, {} {}<br>\n'.format(ins.index, ins.address, ins.mnemonic, ins.op_str)
            pre_type = ins.type
        
        html += '</span></p></div>\n'
        
        if self._data["simulation"]:
            html += '<div class="simulation"><p><b>symbolic expression:</b><br>'
            html += '{}</p></div>\n'.format(escape(self._data["simulation"]))
        
        html += '</body></html>'
        
        with open(os.path.join(reportPath, self._data["filename"] + ".html"), "w") as f:
            f.write(html)
    
    def makeTemplateFiles(self, reportPath):
        """
        Make template files for HTML reports
        """
        path = os.path.join(reportPath, templatePath)
        os.mkdir(path)
        with open(os.path.join(path, "func.js"), "w") as f:
            f.write(FUNC_JS)
        with open(os.path.join(path, "basic.css"), "w") as f:
            f.write(BASIC_CSS)

    def excelGeneration(self, excelName: str):
        """
        Generate an excel file
        """
        wb = openpyxl.load_workbook(excelName + '.xlsx')
        ws = wb['Sheet']
        ws.append([None, self._data["filename"], self._data["ins"], self._compare.valid_amount, self._compare.kernel_amount,
            self._compare.deobf.recovery,  self._compare.deobf.total,  self._compare.deobf.reduced,  self._compare.deobf.redun_T, self._compare.deobf.redun_R, self._compare.deobf.rate, 
            self._compare.vmhunt.recovery, self._compare.vmhunt.total, self._compare.vmhunt.reduced, self._compare.vmhunt.redun_T, self._compare.vmhunt.redun_R, self._compare.vmhunt.rate,
            self._data["simulation"]
        ])
        wb.save(excelName + '.xlsx')
    
    def printList(self, choice="kernel"):
        """
        Simple print
        """
        if choice == "kernel":
            tmplist = self._KERNEL_LIST
        elif choice == "core":
            tmplist = self._CORE_LIST
        else:
            tmplist = self._INS_LIST

        for ins in tmplist:
            print("{}: {}, {} {}".format(ins.index ,ins.address, ins.mnemonic, ins.op_str))
    
    def printListToFile(self, choice="kernel"):
        """
        Print instruction list to text file
        """
        if choice == "kernel":
            tmplist = self._KERNEL_LIST
        elif choice == "core":
            tmplist = self._CORE_LIST
        else:
            tmplist = self._INS_LIST

        with open(self._data["filename"] + ".txt", "w") as f:
            for ins in tmplist:
                f.write("{}: {}, {} {}\n".format(ins.index ,ins.address, ins.mnemonic, ins.op_str))
