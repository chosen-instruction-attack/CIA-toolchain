#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    :   TraceAnalysis.py
@Time    :   2019/11/21 16:14:05
@Author  :   Neko 
@Version :   1.0
@Contact :   
@License :   BSD
@Desc    :   None
'''

import json
import angr
import claripy
from DataType import *
import logging
import re
import os
from multiprocessing import Pool, cpu_count
l = logging.getLogger(name=__name__)

extractFilename = re.compile(".*\/(.*?)\.log")

_garbage_ins=["test", "stc", "clc", "cmp", "cmc","call", "bt", "nop"]
_eax_dst_ins=["aaa", "aad", "aam", "aas", "rdtsc", "lahf", "cwde", "cbw", "mul", "div", "idiv"]  # special instructions whose destination is eax
_edx_dst_ins=["cwd", "cdq"]
_eax_related_ins = ["rdtsc", "cwd", "cdq", "cwde", "cbw", "mul", "div", "idiv"]

def multiLoadProcess(lineList, startIndex, proj, mode, obfuscator):
    """
    Loading and Initalization for multiprocess
    """
    # TODO support handler list
    # l.debug("{} {} {} {}".format(startIndex, proj, mode, obfuscator))
    index = startIndex
    realindex = 0
    xorlist = []
    tmpINSList = []
    for line in lineList:
        ins = Instruction(line, index, proj, mode=mode)
        index += 1
        if ins.mnemonic in _garbage_ins or "j" in ins.mnemonic:
            continue
        tmpINSList.append(ins)
        realindex += 1

        if obfuscator=="CV" and ins.mnemonic=="xor" and ins.src.flag!="IMM":
            xorlist.append(realindex)

    if obfuscator=="CV":
        if (len(tmpINSList)-1)==xorlist[-1]:
            l.info("[MultiProcess] the xor instruction falling into the edge")
        
        delete_ins = []
        maxslen_xorlist = len(xorlist) - 2
        maxslen_tmpINSList = len(tmpINSList) - 2
        for index, xorindex in enumerate(xorlist):
            # replace 3 xor to xchg
            if index<maxslen_xorlist and xorindex<maxslen_tmpINSList and (xorlist[index]+xorlist[index+2])/2==xorlist[index+1]:
                ins = tmpINSList[xorindex]
                nextins = tmpINSList[xorindex+1]
                nextnextins = tmpINSList[xorindex+2]
                if ins.src==nextins.dst and ins.dst==nextins.src and ins.src==nextnextins.src and ins.dst==nextnextins.dst:
                    ins.rewrite("xchg {}".format(ins.op_str), proj)
                    delete_ins.append(nextins)
                    delete_ins.append(nextnextins)
                    ins.insn = Insn(ins.insn)

        for ins in delete_ins:
            tmpINSList.remove(ins)

    return tmpINSList

class TraceAnalysis(object):
    """
    Analysis the recorded trace 
    """
    _INS_LIST = [] # Save instructions between the start and end of anchors
    _KERNEL_INS_LIST = [] # Save sliced instructions
    _slice_operand = [] # Save the
    _handlers = []
    _context_switch = []
    _simulation_expression = ""

    def __init__(self, traceFileName: str, programFileName: str, anchor: str, originalINS: Instruction, originalRegister: Register, obfuscator="VMProtect", cpuCore="single"):
        """
        """
        self._anchor = anchor
        self._originalINS = originalINS
        self._originalINS_str = originalINS
        self._dstRegister = originalRegister
        self._secondOperand = None
        self._obfuscator = obfuscator
        if cpuCore == "single":
            cpus = 1
        elif cpuCore =="server":
            # use multiple core when deployed in the server
            cpus = 16 
        else:
            cpus = cpu_count()
        
        l.debug("CPU Cores: {}".format(cpus))
        self._preProcess(traceFileName, programFileName, cpus)
    
    def _preProcess(self, traceFileName: str, programFileName: str, CPUCore: int):
        """
        Transform the trace file to Instruction class list
        """
        self._filename = extractFilename.findall(traceFileName)[0]

        self.proj = angr.Project(programFileName)
        handlerINS = [] # instructions in single handler
        index = 0
        MODE = "standard"
        if self._obfuscator=="Obsidium":
            MODE = "pack"

        if CPUCore == 1:
            with open(traceFileName, 'r') as f:
                for line in f:
                    ins = Instruction(line, index, self.proj, mulCPU=False, mode=MODE)
                    index += 1
                    if ins.mnemonic in _garbage_ins or "j" in ins.mnemonic:
                        continue
                    self._INS_LIST.append(ins)

                    # construct handler list
                    #TODO instruction add Hanlder mark
                    handlerINS.append(ins)
                    # indirect jump
                    if ins.mnemonic == "ret" or (ins.mnemonic == "jmp" and ins.dst.flag=="REG"):
                        self._handlers.append(Handler(handlerINS))
                        handlerINS=[]
        else:
            """
            Operations for multiple process to load trace file
            """
            insList = []
            insLineNum = 0
            with open(traceFileName, 'r') as f:
                for line in f:
                    insList.append(line)
                    insLineNum+=1
            linesplit = int(insLineNum/CPUCore)
            start = 0

            arg1list = []
            arg2list = []
            arg3list = [self.proj]*CPUCore
            arg4list = [MODE]*CPUCore
            arg5list = [self._obfuscator]*CPUCore

            for index in range(0, insLineNum, linesplit):
                if start == (CPUCore-1) or index+linesplit>insLineNum:
                    arg1list.append(insList[index:])
                    arg2list.append(index)
                    break
                arg1list.append(insList[index:index+linesplit])
                arg2list.append(index)
                start += 1
            arglist = []
            for i in range(CPUCore):
                arglist.append([arg1list[i], arg2list[i], arg3list[i], arg4list[i],arg5list[i]])

            del insList, arg1list, arg2list, arg3list, arg4list #release memory
            # l.info("{} {} {} {}".format(len(arg1list),len(arg2list),len(arg3list),len(arg4list),len(arg5list)))

            with Pool(CPUCore) as p:
                result = p.starmap(multiLoadProcess, arglist)

            for i in result:
                self._INS_LIST += i
            
            del arglist
            l.debug("Length of trace file: {}".format(len(self._INS_LIST)))


        # for backward slicing
        self._INS_LIST = self._INS_LIST[::-1]

        if self._originalINS != None:
            self._originalINS = Instruction(self._originalINS, 0, self.proj, mulCPU=False, mode="fast")
            
            # special disposal of instructions with specific source and destination
            if self._originalINS.dst.flag=="MEM":
                # if "xadd" in self._originalINS.mnemonic or "xchg" in self._originalINS.mnemonic:
                #     self._dstRegister = self._originalINS.src
                #     self._secondOperand = self._originalINS.dst
                if self._originalINS.mnemonic in ["div", "idiv"] or (self._originalINS.mnemonic in ["mul", "imul"] and len(self._originalINS.operands)==1):
                    self._dstRegister = Register("eax")
            else:
                if self._originalINS.mnemonic in _eax_dst_ins or (self._originalINS.mnemonic=="imul" and len(self._originalINS.operands)==1):
                    self._dstRegister = Register("eax")
                elif self._originalINS.mnemonic in _edx_dst_ins:
                    self._dstRegister = Register("edx")
                elif self._originalINS.dst.flag=="REG":
                    self._dstRegister = self._originalINS.dst
                
                if self._originalINS.src:
                    self._secondOperand = self._originalINS.src
        
        # Optimization for Code Virtualizer. Considering for the performance, the optimization will not apply to all obfuscators.
        if self._obfuscator == "CV" and CPUCore==1:
            delete_ins = []
            for ins in self._INS_LIST:
                # transfer three xor to single xchg
                if ins.mnemonic=="xor" and ins.src.flag!="IMM":
                    nextins = self._INS_LIST[self._INS_LIST.index(ins)-1]
                    nextnextins = self._INS_LIST[self._INS_LIST.index(ins)-2]
                    if nextins.mnemonic=="xor" and nextnextins.mnemonic=="xor" and ins.src==nextins.dst and ins.dst==nextins.src:
                        ins.rewrite("xchg {}".format(ins.op_str),self.proj)
                        delete_ins.append(nextins)
                        delete_ins.append(nextnextins)
            for ins in delete_ins:
                self._INS_LIST.remove(ins)

        elif self._obfuscator =="Obsidium":
            for ins in self._INS_LIST:
                # rewrite xor REG, REG to mov REG, 0 (e.g., xor eax, eax to mov eax, 0)
                if ins.mnemonic=="xor" and ins.src==ins.dst and ins.src.flag=="REG":
                        ins.rewrite("mov {}, 0".format(ins.src.realType),self.proj)
                        continue


    def searchAnchor(self, flag=True):
        """
        Search anchor instruction
        """
        counter = 0
        anchorlist = []

        for ins in self._INS_LIST:
            if self._anchor == "{} {}".format(ins.mnemonic,ins.op_str):
                counter += 1
                anchorlist.append(ins)
                l.debug("{}: {}, {} {}; ESP={}".format(ins.index, hex(ins.address), ins.mnemonic, ins.op_str, hex(ins.regs.esp)))
        
        if flag:
            return counter
        else:
            return counter, anchorlist

    def searchContextSwitch(self, flag=False, mode="standard"):
        """
        Search context switch
            1. pop, push: reg_write(30)
            2. mov [esp], reg
        """
        tmplist = []
        regs = []

        # switch source and destination
        if self._originalINS.mnemonic in ["xchg","xadd"]:
            regs = [self._originalINS.src.type, self._originalINS.dst.type]

    
        pushfd_list = []
        for reg in ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "eflags"]:
            if mode=="clean":
                leastpart = []
            self.backwardSlicing(Register(reg))
            
            if regs!=[] and reg in regs:
                reg = regs

            for ins in self._KERNEL_INS_LIST:

                if ins.reg_write(30) \
                    or (ins.mnemonic=="mov" and (ins.src.flag=="MEM" or ins.dst.flag=="MEM") and "esp" in ins.op_str) \
                    or (ins.mnemonic=="xchg" and (ins.src.flag=="MEM" and (ins.dst.flag=="REG")) and "esp" in ins.op_str):
                    # esp=30                        
                    # xchg exchange operands
                    if (ins.src.type!=None and ins.dst.type!=None) and ((ins.src.type in reg or ins.dst.type in reg))  and ins.src.flag!="IMM" and ins.src.flag!="IMM":
                        if mode=="standard":
                            tmplist.append(ins)
                        if mode=="clean":
                            leastpart.append(ins)
                    elif ins.mnemonic in ["pushfd","popfd"]:
                        if ins.mnemonic == "pushfd":
                            pushfd_list.append(ins)
                        if mode=="standard":
                            tmplist.append(ins)
                        if mode=="clean":
                            leastpart.append(ins)
                        
            if mode=="clean":
                if leastpart!=[]:
                    tmplist+=[leastpart[0],leastpart[-1]]
            # self.printSlices()
            # print("="*30)
            self.flush()
        tmplist.sort(key=lambda x:x.index)

        # remove reduandant pushfd
        for i in pushfd_list[:-1]:
            if i in tmplist:
                tmplist.remove(i)

        tmplist = tmplist[::-1]
        self._KERNEL_INS_LIST = tmplist
        self._context_switch = tmplist

        if flag:
            print("[+] Context Switch information")
            self.printSlices(flag)

        self.flush()

    def isReadBytecode(self, addr):
        """
        return whether the insturction reading a RX/RWX section
        """
        obj = self.proj.loader.main_object
        region = obj.find_section_containing(addr)
        
        # RX/RWX section
        if region and region.is_executable and region.is_readable:
            return True
        else:
            return False
        
    def backwardSlicing(self, target, optimize=True):
        """
        backward slicing
        """
        for ins in self._INS_LIST:
            # if ins.mnemonic in ["cbw", "cwde"] and target == Register('eax'):
            #     self._KERNEL_INS_LIST.append(ins)
            if ins.dst == target:
                if ins.isDataTransfer():
                    # Data transfer Instructions
                    # "push", "pop", "pushfd", "popfd", "mov", "movzx",...
                    if ins.src.flag != "IMM" and (ins.waddr!=0 or ins.raddr!=0):
                        # not change target when meet not mov operation (e.g. add sub)
                        # e.g. (1) mov reg, [mem]/ mov [mem], reg ; (2) push reg/[mem]
                        target = ins.src

                    elif ins.src.flag == "IMM":
                        # Immediate value -> stop recording
                        # (1) mov reg/[mem], imm ; (2)push imm
                        target = ""

                    elif "mov" in ins.mnemonic:
                        if ins.src.flag == "REG" and ins.dst.flag == "REG":
                            # mov reg, reg
                            target = ins.src
                        # elif ins.src.flag == "IMM" and len(ins.operands)==2:
                        #     # mov reg/[mem], imm
                        #     # stop recording
                        #     target = ""
                
                elif ins.dst.flag == "REG" and ins.src.flag !="IMM" and len(ins.operands)==2:
                    # #if follow the add will lead to the push encrypt_key @VMProtect_2.x version
                    # <mnemonic> REG, REG/MEM
                    if "xchg" not in ins.mnemonic:
                        # add/sub/xxx reg, [mem]/reg
                        if ins.src not in self._slice_operand:
                            if self._obfuscator=="CV" and ins.src.flag == "MEM":
                                # easy to stop following the obfuscation used by CV
                                continue
                            # l.debug("[1]{} {} {} ".format(ins.index, ins.src.flag, ins.dst.flag))
                            self._slice_operand.append(ins.src)
                    else:
                        # xchg reg, reg/[mem];
                        # l.info("[xchg0]{} {} {} ".format(hex(ins.addr), ins.src.flag, ins.dst.flag))
                        target = ins.src

                elif ins.dst.flag == "MEM" and ins.src.flag =="REG" and len(ins.operands)==2:
                    # <mnemonic> MEM, REG
                    # add/sub/xxx [mem], reg
                    if ins.src not in self._slice_operand:
                        l.debug("[2]{} {} {} ".format(ins.index, ins.src.flag, ins.dst.flag))
                        self._slice_operand.append(ins.src)

                elif "xchg" in ins.mnemonic:
                    # xchg reg/[mem], reg/[mem];
                    target = ins.src

                elif "div" in ins.mnemonic or "mul" in ins.mnemonic: 
                    # div, mul
                    if self.proj.arch.name == "X86":
                        self._slice_operand.append(Register("eax"))
                    elif self.proj.arch.name == "AMD64":
                        self._slice_operand.append(Register("rax"))

                self._KERNEL_INS_LIST.append(ins)

            elif "xchg" in ins.mnemonic and ins.src == target:
                # xchg reg/[mem], reg/[mem];
                target = ins.dst

            elif "div" in ins.mnemonic or "mul" in ins.mnemonic:
                if target!="" and self.proj.arch.name=="X86" and target.type=="eax":
                    # div, mul
                    self._slice_operand.append(target)
                    target=ins.src
                    # self._slice_operand.append(Register("eax"))
                    self._KERNEL_INS_LIST.append(ins)

            # Searching instructions related to new operand 
            for newop in self._slice_operand:
                if ins.dst == newop:
                    # l.debug(f"[backwardSlicing] {ins.index}, {ins.src.flag}, {ins.dst.flag}, {self._slice_operand}")
                    if ins in self._KERNEL_INS_LIST:
                        self._slice_operand.pop(self._slice_operand.index(newop))
                        break
                    self._KERNEL_INS_LIST.append(ins)

                    if ins.isDataTransfer():
                        # Data transfer
                        # "push", "pop", "pushfd", "popfd", "mov", "movzx",...
                        if ins.src.flag != "IMM" and (ins.waddr!=0 or ins.raddr!=0):
                            # Data transfer e.g. mov reg, [mem]/ mov [mem], reg ; push reg/[mem]
                            self._slice_operand[self._slice_operand.index(newop)]=ins.src
                        elif ins.src.flag == "IMM":
                            # (1) mov reg/[mem], imm ; (2)push imm
                            # stop recording
                            self._slice_operand.pop(self._slice_operand.index(newop))
                        elif "mov" in ins.mnemonic:
                            if ins.dst.flag == "REG" and ins.src.flag == "REG":
                                # mov reg, reg
                                self._slice_operand[self._slice_operand.index(newop)] = ins.src
                            # elif ins.src.flag == "IMM" and len(ins.operands)==2:
                            #     # mov reg/mem, imm
                            #     self._slice_operand.pop(self._slice_operand.index(newop))

                    elif ins.dst.flag == "REG" and ins.src.flag !="IMM" and len(ins.operands)==2:
                        # if ins.isDataTransfer():
                        #     # mov reg, reg
                        #     self._slice_operand[self._slice_operand.index(newop)]=(ins.src)
                        if "xchg" not in ins.mnemonic:
                            # add/sub/xxx reg, [mem])
                            if self._obfuscator!="CV" and ins.src not in self._slice_operand:
                                self._slice_operand.append(ins.src)
                            else:
                                continue
                        else:
                            self._slice_operand[self._slice_operand.index(newop)]=ins.src

                    elif "xchg" in ins.mnemonic:
                        # xchg reg/[mem], reg/[mem]
                        self._slice_operand[self._slice_operand.index(newop)]=ins.src
                
                elif "xchg" in ins.mnemonic and ins.src == newop:
                        # xchg reg/[mem], reg/[mem]
                        self._slice_operand[self._slice_operand.index(newop)]=ins.dst

                elif type(ins.dst) == list and newop in ins.dst:
                    if "div" in ins.mnemonic or "mul" in ins.mnemonic:
                        l.warning("Abnormal instruction: {}: {} {} {}", ins.index, ins.address, ins.mnemonic, ins.op_str)
                        # self._slice_operand.pop(self._slice_operand.index(newop))
                        # self._slice_operand += ins.src
                        # self._KERNEL_INS_LIST.append(ins)
        
        if optimize or self._obfuscator=="CV":
            for i in range(3):
                self.optimization()
    
    def inputRecoginition(self):
        inputs = []
        concreteInputs = []
        
        # TODO based on the sub slice or context switch
        start_ins = self._KERNEL_INS_LIST[-15:] # first 10 instructions
        # self.searchContextSwitch()
        start_ins = self._context_switch.copy()[::-1] # from context switch
        for ins in start_ins:
            if ins.src == self._dstRegister and ins.waddr!=0:
                if ins.isDataTransfer("IN"):
                    inputs.append(ins)
                    break
            elif ins.mnemonic == "xchg" and ins.dst == self._dstRegister:
                inputs.append(ins)
                break
        
        if self._secondOperand != None:
            if self._secondOperand.flag=="REG":
                for ins in start_ins:
                    if ins.src == self._secondOperand:
                        if ins.isDataTransfer("IN") and ins.waddr!=0:
                            inputs.append(ins)
                            break
                    elif ins.mnemonic=="pushfd":
                            inputs.append(ins)
                return inputs

            if self._secondOperand.flag=="IMM":
                for ins in self._KERNEL_INS_LIST[::-1]:
                    if self.isReadBytecode(ins.raddr):
                        concreteInputs.append(ins)
                return inputs#, concreteInputs
        else:
            return inputs


    def optimization(self):
        """
        remove push pop for code virtualizer
        """
        tmp = self._KERNEL_INS_LIST
        tlen = len(tmp)

        # peephole optimization
        removelist = []
        if self._obfuscator=="CV":
            for index, ins in enumerate(tmp):
                if index<tlen-3:
                    nextins = tmp[index+1]
                    nextnextins = tmp[index+2]
                    nextnextnextins = tmp[index+3]

                    if ins.mnemonic in ["mov","pop"] and nextins.mnemonic in ["mov", "push"] and (ins.raddr==nextins.waddr and ins.dst==nextins.src):
                        removelist.append(ins)
                        removelist.append(nextins)
                    elif ins.mnemonic == nextins.mnemonic == "xor" and ins.op_str==nextins.op_str:
                        # remove same operation
                        # l.debug(f"[optimization] Found junk xor {ins.index}, {nextins.index}")
                        removelist.append(ins)
                        removelist.append(nextins)
                    elif {ins.mnemonic, nextins.mnemonic} == {"sub", "add"} and ins.op_str==nextins.op_str:
                        # remove same operation
                        # l.debug(f"[optimization] Found junk add sub pair {ins.index}, {nextins.index}")
                        removelist.append(ins)
                        removelist.append(nextins)

        # l.info(f"[optimization] Junk Instructions: {removelist}")
        for ins in set(removelist):
            if ins in self._KERNEL_INS_LIST:
                self._KERNEL_INS_LIST.remove(ins)



    def valueSetAnalysis(self):
        # abandoned
        tmp = self._KERNEL_INS_LIST.copy()
        tmp = tmp[::-1] # change to forward

        valuelist = []
        inputs = self.inputRecoginition()
        print(f"[+] Recognized inputs: {inputs}")

        for ins in inputs:
            newvalue = ValueLabel(name=ins.src.type, waddr=ins.waddr,ins=ins)
            newvalue.flag=False
            newvalue.operation=True
            valuelist.append(newvalue)

        # tmp = tmp[tmp.index(ins):]
        for ins in tmp:
            #TODO liveness analysis
            for value in valuelist[::-1]:
                # print(value.name, value.waddr, ins.raddr)
                # if ins.waddr == value.waddr:
                #     print(ins.index, value.index)
                #     valuelist[valuelist.index(value)].overwrited=True

                if value.waddr==ins.raddr and not ins.concrete:
                    # READ: create variable
                    # print("++++", ins.index,value.index, value.overwrited)
                    newvalue = ValueLabel(name=ins.dst.type, raddr=ins.raddr,ins=ins)
                    valuelist.append(newvalue)
                    break
                elif ins.src.flag=="REG" and ins.src.type == value.name and ins.mnemonic=="mov" and ins.waddr!=0 and value.flag:
                    # WIRTE: variable die
                    value.addOP(ins)
                    value.setWaddr(ins.waddr)
                    value.flag=False
                    break
                elif value.flag and ins.raddr==0 and ins.waddr==0 and (ins.dst.type == value.name or ins.src.type == value.name):
                    #TODO add support for div, mul
                    # variable operation
                    if len(ins.operands)==2 and ins.dst.type!=value.name:
                        # value.flag=False
                        # continue
                        isappear = False
                        start = valuelist.index(value)
                        for svalue in valuelist[start-1::-1]:
                            if svalue.flag and ins.dst.type==svalue.name:
                                isappear=True
                                break
                        if isappear:
                            value.flag=False
                            continue
                        if ins.concrete and ins.src.flag!="IMM":
                            # value.name=ins.dst.type
                            nextins = tmp[tmp.index(ins)+1]
                            l.debug("[ValueSetAnalysis] original: {} {} {}".format(ins, ins.mnemonic, ins.op_str))

                            l.debug("[ValueSetAnalysis] Concrete operands: {}, Rewrited:{} {}, {}, Next operands: {}, Rewrited: {} {}".format(ins, ins.mnemonic, ins.src.realType, hex(ins.dst.value), nextins, nextins.mnemonic, nextins.op_str.replace(ins.dst.realType, ins.src.realType)))
                            if "sh" in ins.mnemonic[:2] and nextins.isDataTransfer():
                                if nextins.src.mark!=ins.src.mark:
                                    if nextins.src.mark==32:
                                        newtype = "e"+ ins.src.realType[0] + "x"
                                    if nextins.src.mark==16:
                                        newtype = ins.src.realType[0] + "x"
                                    newvalue = nextins.src.value
                                    nextins.rewrite("{} {}".format(nextins.mnemonic, nextins.op_str.replace(ins.dst.realType, newtype)), self.proj)
                                    ins.rewrite("mov {}, {}".format(newtype, hex(newvalue)), self.proj)
                                print("{} {}".format(nextins.mnemonic, nextins.op_str.replace(ins.dst.realType, newtype)))
                                print("mov {}, {}".format(newtype, hex(newvalue)))
                                
                            else:
                                nextins.rewrite("{} {}".format(nextins.mnemonic, nextins.op_str.replace(ins.dst.realType, ins.src.realType)), self.proj)
                                ins.rewrite("{} {}, {}".format(ins.mnemonic, ins.src.realType, hex(ins.dst.value)), self.proj)

                            value.addOP(ins)
                            print(ins, value.name)
                    #     else:
                    #         value.name=ins.dst.type
                    #         ins.rewrite("{} {}, {}".format(ins.mnemonic, ins.src.type, ins.dst.value), self.proj)
                    #         value.addOP(ins)
                    #     value.operation=True

                    else:
                        if ins.concrete and len(ins.operands)==2 and ins.src.flag=="REG":
                            l.debug("[ValueSetAnalysis] original: {} {} {}".format(ins, ins.mnemonic, ins.op_str))
                            if ins.src.mark==16:
                                ins.src.value=ins.src.value & 0xffff
                            if ins.src.mark==8:
                                ins.src.value=ins.src.value & 0xff
                            l.debug("[ValueSetAnalysis] Concrete operands: {}, Rewrited: {} {}, {}".format(ins, ins.mnemonic, ins.dst.realType, hex(ins.src.value)))

                            ins.rewrite("{} {}, {}".format(ins.mnemonic, ins.dst.realType, hex(ins.src.value)), self.proj)
                        value.addOP(ins)
                        value.operation=True
                    break
                elif ins.src.flag=="REG" and ins.waddr == ins.raddr and ins.waddr!=0 and not ins.isDataTransfer():
                        if ins.waddr==value.waddr:
                            if ins.concrete:
                                l.debug("[ValueSetAnalysis] {} Concrete operands: {} {}; Rewrited: {} {}".format(ins, ins.mnemonic, ins.op_str, ins.mnemonic, ins.op_str.replace(ins.src.realType, hex(ins.src.value))))
                                ins.rewrite("{} {}".format(ins.mnemonic, ins.op_str.replace(ins.src.realType, hex(ins.src.value))), self.proj)
                            value.addOP(ins)
                            value.operation=True
                        elif ins.src.type == value.name:
                            l.debug("[ValueSetAnalysis] Concrete operands: {}, Rewrited: {}".format(ins, ins.mnemonic))
                            #TODO concrete memory
                            if ins.concrete:
                                pass
                            value.addOP(ins)
                            value.operation=True
                            value.setWaddr(ins.waddr)
                            value.flag=False

        for i in valuelist:
            i.updateSE()
        valuelist.sort(key=lambda x:x.end)
        result = []
        for ins in self._KERNEL_INS_LIST[::-1]:
            for value in valuelist:
                # if value.operation:
                    if ins in value._op_list:
                        result.append(ins)
        self._KERNEL_INS_LIST=result[::-1]

    def forwardConcrete(self): 
        """
        concrete instructions
        """
        concreteValue = ""
        for ins in self._KERNEL_INS_LIST[::-1]:

            if  self._obfuscator!="CV" and ins.raddr!=0 and self.isReadBytecode(ins.raddr): # 把isReadBytecode的指令认为是构建VM环境的指令，这些指令所涉及的reg和mem应该被concrete(语义无关)
                ins.concrete=True
                ins.conVal = ins.dst
                concreteValue=ins.dst
            
            elif "mov" in ins.mnemonic and ins.src.flag=="IMM":
                # immediate value (mainly for CV)
                # mov [mem]/reg, imm
                ins.concrete=True
                ins.conVal = ins.dst
                concreteValue=ins.dst

            elif ins.dst == concreteValue:
                ins.concrete=True
                ins.conVal = ins.dst
                if "mov" in ins.mnemonic:
                    # the value is over written
                    concreteValue = ""
                if self._obfuscator!="CV" and ins.mnemonic in ["or", "and","add"] and ins.src.flag=="REG":
                    # avoid over concrete
                    concreteValue = ""

            elif ins.src == concreteValue:
                ins.concrete=True
                ins.conVal = ins.src
                if "mov" in ins.mnemonic and (ins.waddr!=0 or ins.raddr!=0):
                    # test
                    nextins = self._KERNEL_INS_LIST[self._KERNEL_INS_LIST.index(ins)-1]
                    if ins.dst.flag=="REG":
                        # mov reg, [mem]/reg -> mov reg, imm
                        newvalue = nextins.regs.registers[ins.dst.type]
                        # l.error(f"{ins.mnemonic} {ins.dst.realType}, {hex(newvalue)}")
                        ins.rewrite(f"{'mov'} {ins.dst.realType}, {hex(newvalue)}", self.proj, flag="IMM")
                        # stop tracking handler input
                        concreteValue=""

                    elif ins.src.flag=="REG" and ins.dst.flag=="MEM":
                        # mov [mem], reg -> mov [mem], imm
                        newvalue = ins.regs.registers[ins.src.type]
                        # l.error(f"{ins.mnemonic} {ins.op_str.replace(ins.src.realType, hex(newvalue))}")
                        ins.rewrite(f"{'mov'} {ins.op_str.replace(ins.src.realType, hex(newvalue))}", self.proj, flag="IMM")
                        concreteValue=ins.dst
                # elif ins.dst.flag=="REG":
                #     l.error(f"{ins.index}, {ins.op_str}")
                #     concreteValue = ""
                # elif len(ins.operands)==2: 
                #     concreteValue = ""


    def concreteMemory(self):
        """
        concrete the memory operand used in instructions
        """
        for ins in self._KERNEL_INS_LIST:
            if ins.mnemonic in ["pushfd", "pushad", "pushal", "popfd", "popad", "popal", "pusha", "popa"]:
                continue
            # elif "push" in ins.mnemonic:
            elif ins.mnemonic == "push":
                if ins.src.flag=="MEM" and ins.dst.flag=="MEM":
                    # for CV
                    restr = re.sub(r'\[(.*)\]', '['+hex(ins.raddr)+']', ins.op_str)
                    ins.rewrite(f"{ins.mnemonic} {restr}", self.proj)
                    continue
                elif ins.src.flag=="REG":
                    # push reg -> mov [esp+num], reg
                    tmpname = "dword ptr [{}]".format(hex(ins.waddr))
                    ins.rewrite(f"{'mov'} {tmpname}, {ins.op_str}", self.proj)

            elif "mov" in ins.mnemonic:
                if ins.raddr!=0:
                    if self.isReadBytecode(ins.raddr) and ins.concrete==True:
                        if self._obfuscator=="CV":
                            nextins = self._KERNEL_INS_LIST[self._KERNEL_INS_LIST.index(ins)-1]
                            regname = ins.op_str.split(',')[0]
                            value = nextins.regs.registers[ins.dst.type]
                            ins.rewrite("{} {}, {}".format("mov", regname, hex(value)), self.proj)
                            continue
                        nextins = self._KERNEL_INS_LIST[self._KERNEL_INS_LIST.index(ins)-1]
                        regname = ins.op_str.split(',')[0]
                        value = self._KERNEL_INS_LIST[self._KERNEL_INS_LIST.index(nextins)-1].regs.registers[ins.dst.type]
                        # print(ins.mnemonic, regname, hex(value))
                        # TODO handle bx ebx bl encrypt register
                        nextins.rewrite("{} {}, {}".format("mov", regname, hex(value)), self.proj)
                        # ins.raddr=0
                    restr = re.sub(r'\[(.*)\]', '['+hex(ins.raddr)+']', ins.op_str)

                    for seg in ["ss:", "es:"]:
                        if seg in restr:
                            restr = restr.replace(seg, "")

                    l.debug("[concreteMemory] {} Original: {} {}, Rewrited: {} {}".format(ins, ins.mnemonic, ins.op_str, ins.mnemonic, restr))
                    try:
                        ins.rewrite("{} {}".format(ins.mnemonic, restr), self.proj)
                    except:
                        l.error("[concreteMemory] {} Rewrited {}, {}".format(ins, ins.mnemonic, restr))
                    # print("READ",ins.src.type, ins.op_str, ins.raddr)
                elif ins.waddr!=0:
                    restr = re.sub(r'\[(.*)\]', '['+hex(ins.waddr)+']', ins.op_str)
                    ins.rewrite("{} {}".format(ins.mnemonic, restr), self.proj)

            # elif "pop" in ins.mnemonic:
            elif ins.mnemonic == "pop":
                if ins.src.flag=="MEM" and ins.dst.flag=="MEM":
                    # for CV
                    restr = re.sub(r'\[(.*)\]', '['+hex(ins.waddr)+']', ins.op_str)
                    ins.rewrite("{} {}".format(ins.mnemonic, restr), self.proj)
                    continue
                tmpname = "dword ptr [{}]".format(hex(ins.raddr))
                ins.rewrite("{} {}, {}".format("mov",ins.op_str,tmpname), self.proj)
            
            elif ins.src.flag=="MEM" or ins.dst.flag=="MEM":
                # for CV
                # e.g. add [mem], reg
                if ins.mnemonic=="pop":
                    restr = re.sub(r'\[(.*)\]', '['+hex(ins.waddr)+']', ins.op_str)
                    ins.rewrite("{} {}".format(ins.mnemonic, restr), self.proj)
                else:
                    restr = re.sub(r'\[(.*)\]', '['+hex(ins.raddr)+']', ins.op_str)
                    ins.rewrite("{} {}".format(ins.mnemonic, restr), self.proj)
                
            elif ins.raddr!=0:
                # for CV
                # e.g. add [mem], reg
                restr = re.sub(r'\[(.*)\]', '['+hex(ins.raddr)+']', ins.op_str)
                ins.rewrite("{} {}".format(ins.mnemonic, restr), self.proj)

            elif ins.waddr!=0:
                # for CV
                # e.g. add[mem], reg
                # usually is useless, since ins.raddr==ins.waddr
                restr = re.sub(r'\[(.*)\]', '['+hex(ins.waddr)+']', ins.op_str)
                ins.rewrite("{} {}".format(ins.mnemonic, restr), self.proj)

    def concreteEFLAGS(self):
        # abandoned
        for ins in self._KERNEL_INS_LIST:
            if ins.mnemonic=="pushfd":
                tmpname = "dword ptr [{}]".format(hex(ins.waddr))
                ins.rewrite("mov {}, {}".format(tmpname, hex(ins.regs.registers['eflags'])),self.proj)            

    def symbolicExecution(self):
        """
        symbolic execution and verification
        """
        #ins_bytes = bytearray()
        ins_bytes = ""
        espvalue = 0

        if len(self._KERNEL_INS_LIST)==0:
            l.error("[!] The _KERNEL_INS_LIST is empty, the recover is failed.")
            return 1

        for ins in self._KERNEL_INS_LIST[::-1]:
            # bytearry might cannot loaded by the angr
            #ins_bytes+=ins.bytes
            if espvalue==0 and "push" in ins.mnemonic:
                espvalue = ins.regs.registers['esp']
            ins_bytes+="{} {}\n".format(ins.mnemonic,ins.op_str)

        try:
            proj = angr.project.load_shellcode(ins_bytes, arch=self.proj.arch)
        except:
            l.error(ins_bytes)
            exit()
        regName = self._dstRegister.type
        # if use SYMBOL_FILL_UNCONSTRAINED_MEMORY, it introduce mess memory variable.
        state = proj.factory.entry_state(add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
        if espvalue>0:
            state.registers.store("esp",espvalue)
        else:
            state.registers.store("esp",self._KERNEL_INS_LIST[-1].regs.registers['esp'])
        
        if self._originalINS.mnemonic in _eax_related_ins or(self._originalINS.mnemonic=="imul" and len(self._originalINS.operands)==1):
            state.registers.store("eax", claripy.BVS(regName,32))
        
        state.registers.store(regName, claripy.BVS(regName,32)) # ecx
        state.registers.store("edx", claripy.BVS("edx",32))  # source
        state.registers.store("eflags", claripy.BVS("eflags", 32))

        l.info("[symbolicExecution] ORIGINAL INS: {}".format(self._originalINS.mnemonic+' '+self._originalINS.op_str))
        # l.info("[SYMBOLIC EXECUTION] RECOVER BEFORE: {}".format(state.registers.load(regName)))

        if proj.factory.block(proj.entry).instructions == 0:
            l.error("[!] [symbolicExecution] angr cannot recognize instructions, the instruction sequences is empty")

        sm = proj.factory.simgr(state)
        sm.step()
        try:
            laststate = sm.active[0]
        except:
            l.error("[!] [symbolicExecution] cannot generate correct expressions")
            return
        self._simulation_expression = laststate.registers.load(regName)
        l.info("[symbolicExecution] RECOVER AFTER: {}".format(self._simulation_expression))

        extendINS = b"\x89\xc9" # mov ecx, ecx ; update wide
        originProj = angr.project.load_shellcode(self._originalINS.bytes+extendINS, arch=self.proj.arch)
        originState = originProj.factory.entry_state(add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
        
        if self._originalINS.mnemonic in _eax_related_ins or (self._originalINS.mnemonic=="imul" and len(self._originalINS.operands)==1):
            originState.registers.store("eax", claripy.BVS(regName,32))
        
        originState.registers.store(regName, claripy.BVS(regName,32)) # ecx
        originState.registers.store("edx", claripy.BVS("edx",32)) # source
        originState.registers.store("eflags", claripy.BVS("eflags", 32))

        originSm = originProj.factory.simgr(originState)
        originSm.step()
        originLaststate = originSm.active[0]
        l.info("[symbolicExecution] ORIGINAL EXPRESS: {}".format(originLaststate.registers.load(regName)))

        # print(laststate.solver.simplify(laststate.registers.load(regName)))
        evalResult = laststate.solver.eval(laststate.registers.load(regName)==originLaststate.registers.load(regName))
        l.info("[symbolicExecution] EVAL RESULT: {}".format(evalResult))

    def flush(self):
        """
        flush the sliced result
        """
        self._KERNEL_INS_LIST = []
        self._slice_operand = []

    def printSlices(self, status=True):
        """
        Simple print
        """
        for ins in self._KERNEL_INS_LIST[::-1]:
            if status:
                print(f"{ins.index}: {hex(ins.address)}, {ins.mnemonic} {ins.op_str}; READ={hex(ins.raddr)}, WRITE={hex(ins.waddr)}, ESP={hex(ins.regs.esp)}")
            else:
                print("{}: {}, {} {}; EAX={}, EBX={}, ECX={}, EDX={}, ESI={}, EDI={}, ESP={}, EBP={}, EFLAGS={}, READ={}, WRITE={}, CONCRET={}".format(ins.index,hex(ins.address), ins.mnemonic,ins.op_str,*[hex(ins.regs.registers[j]) for j in ins.regs.registers.keys()],hex(ins.raddr),hex(ins.waddr),ins.concrete))

    def exportHandlerSlices(self, flag=False):
        """
        Export instructions with handler mark
        """
        address = []
        for handler in self._handlers:
            for ins in handler.ins_list:
                if ins.mnemonic in _garbage_ins:
                    continue
                elif ins.mnemonic[0] == "j" and ins.dst.flag!="REG":
                    continue

                address.append(hex(ins.address))
                # print(f"{i.index}: {hex(i.address)}, {i.mnemonic} {i.op_str}; READ={hex(i.raddr)}, WRITE={hex(i.waddr)}, ESP={hex(i.regs.esp)}")
                print("{}: {}, {} {}; EAX={}, EBX={}, ECX={}, EDX={}, ESI={}, EDI={}, ESP={}, EBP={}, EFLAGS={}, READ={}, WRITE={}".format(ins.index,hex(ins.address), ins.mnemonic,ins.op_str,*[hex(ins.regs.registers[j]) for j in ins.regs.registers.keys()],hex(ins.raddr),hex(ins.waddr)))
            print("="*30)

        if flag==True:
            address_dict = {}
            for ins_addr in set(address):
                address_dict[ins_addr]=address.count(ins_addr)
            print(sorted(address_dict.items(), key= lambda kv:(kv[1], kv[0])))

    def printSlicesToFile(self, path: str, select: str):
        """
        Print instruction list to text file
        """
        if select == "kernel":
            tmp = self._KERNEL_INS_LIST[::-1]
        elif select == "full":
            tmp = self._INS_LIST[::-1]
        else:
            return

        with open(os.path.join(path, self._filename + f".{select}.txt"), 'w') as f:
            for ins in tmp:
                f.writelines("{}: {}, {} {}; EAX={}, EBX={}, ECX={}, EDX={}, ESI={}, EDI={}, ESP={}, EBP={}, EFLAGS={}, READ={}, WRITE={}, CONCRET={}\n".format(ins.index,hex(ins.address), ins.mnemonic,ins.op_str,*[hex(ins.regs.registers[j]) for j in ins.regs.registers.keys()],hex(ins.raddr),hex(ins.waddr),ins.concrete))

    def outputToFile(self, storeDir: str, less=False):
        """
        Print instruction list to json file for further analysis
        """
        f = open(os.path.join(storeDir, self._filename+".json"), "w")
        
        kernel_list = []
        for ins in self._KERNEL_INS_LIST[::-1]:
            kernel_list.append([ins.index, hex(ins.address), ins.mnemonic, ins.op_str])
        
        full_list = []
        if not less:
            for ins in self._INS_LIST[::-1]:
                full_list.append([ins.index, hex(ins.address), ins.mnemonic, ins.op_str])
        
        data = {"filename":self._filename, "ins":self._originalINS_str, "kernel_list":kernel_list, "full_list":full_list, "simulation":str(self._simulation_expression)}
        f.write(json.dumps(data, indent=4))
        f.close()
    

if __name__ == "__main__":

    l.setLevel(20)
    originalINS = "xor ebx, 0xdead"
    originalRegister=Register("ebx")
    # originalRegister=Memory(0x69fe94,0x69fe94)
    test = TraceAnalysis(traceFileName="instrace.txt", programFileName="VMnew_cmpxchg64.vmp.exe", anchor="fadd st(7)", originalINS=originalINS, originalRegister=originalRegister, obfuscator="VMProtect")

    # test.searchContextSwitch(mode="standard")

    # test.isReadBytecode()

    test.backwardSlicing(originalRegister)
    print("\n")
    print(test.inputRecoginition())
    test.printSlices(False)

    test.symbolicExecution()
