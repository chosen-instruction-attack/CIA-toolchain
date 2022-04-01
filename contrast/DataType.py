#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    :   DataType.py
@Time    :   2019/11/21 16:14:05
@Author  :   Neko
@Version :   1.0
@Contact :
@License :   BSD
@Desc    :   None
'''

import logging
import re
from capstone import CsInsn

l = logging.getLogger(name=__name__)

EAX_LIST = ["rax", "eax", "ax", "al", "ah"]
EBX_LIST = ["rbx", "ebx", "bx", "bl", "bh"]
ECX_LIST = ["rcx", "ecx", "cx", "cl", "ch"]
EDX_LIST = ["rdx", "edx", "dx", "dl", "dh"]
EBP_LIST = ["rbp", "ebp", "bp"]
ESI_LIST = ["rsi", "esi", "si", "sil","sih"]
EDI_LIST = ["rdi", "edi", "di","dil","dih"]
ESP_LIST = ["rsp", "esp", "sp"]

REG64_LIST = ["rax", "rbx", "rcx", "rdx", "rbp", "rsi", "rdi", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
REG32_LIST = ["eax", "ebx", "ecx", "edx", "ebp", "esi", "edi", "esp"]
REG16_LIST = ["ax", "bx", "cx", "dx", "bp", "si", "di", "sp"]
REG8_LIST = ["al", "bl", "cl", "dl", "ah", "bh", "ch", "dh"]

IS_X32ARCH= True

def setArch(arch: bool):
    global IS_X32ARCH 
    IS_X32ARCH = arch

class Insn(object):
    # for pickle serialization
    def __init__(self, insn):
        # self.address = insn.address
        self.op_str = insn.op_str
        self.mnemonic = insn.mnemonic
        # self.operands = insn.operands
        self.regs_read = insn.regs_read
        self.regs_write = insn.regs_write
        pass


class ConcretRegister(object):

    def __init__(self):
        super(ConcretRegister, self).__setattr__('registers', {"eax":0, "ebx":0, "ecx":0, "edx":0, "esi":0, "edi":0, "esp":0, "ebp":0, "eflags":0})

    def __getstate__(self):
        state = self.__dict__.copy()
        l.info(self.__dict__)
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)

    def __getattr__(self, k):
        if isinstance(k,str):
            try:
                return self.registers[k]
            except KeyError:
                l.warning("no such keyword {}".format(k))

    def __setattr__(self, k, v):
        if isinstance(k,str):
            try:
                self.registers[k]=v
                return True
            except KeyError:
                l.warning("no such keyword {}".format(k))

    def __len__(self):
        return len(self.registers)

    def __dir__(self):
        return self.__registers.keys()

class Register(object):
    # al ax ah eax rax
    # bl bx bh ebx rbx
    mark = None
    _Reg64Mark = _Reg32Mark = _Reg16Mark = _Reg8Mark = False
    flag = "REG"

    def __init__(self, regName: str):
        self.realType = regName
        self.setType(regName)
        self.setMark(regName)

    def __eq__(self, var):
        try:
            if self.flag == var.flag and self.type == var.type:# and self.value == var.value:
                return True
            else:
                return False
        except:
            return False

    @property
    def isReg32(self):
        return self._Reg32Mark

    @property
    def isReg16(self):
        return self._Reg16Mark

    @property
    def isReg8(self):
        return self._Reg8Mark

    def setType(self, reg: str):
        if IS_X32ARCH:
            if reg in EAX_LIST:
                self.type = "eax"
            elif reg in EBX_LIST:
                self.type = "ebx"
            elif reg in ECX_LIST:
                self.type = "ecx"
            elif reg in EDX_LIST:
                self.type = "edx"
            elif reg in EBP_LIST:
                self.type = "ebp"
            elif reg in ESI_LIST:
                self.type = "esi"
            elif reg in EDI_LIST:
                self.type = "edi"
            elif reg in ESP_LIST:
                self.type = "esp"
            else:
                self.type = reg
        else:
            if reg in EAX_LIST:
                self.type = "rax"
            elif reg in EBX_LIST:
                self.type = "rbx"
            elif reg in ECX_LIST:
                self.type = "rcx"
            elif reg in EDX_LIST:
                self.type = "rdx"
            elif reg in EBP_LIST:
                self.type = "rbp"
            elif reg in ESI_LIST:
                self.type = "rsi"
            elif reg in EDI_LIST:
                self.type = "rdi"
            elif reg in ESP_LIST:
                self.type = "rsp"
            else:
                self.type = reg

    def setMark(self, reg: str):
        if reg in REG64_LIST:
            self.mark = 64
            self._Reg32Mark = True
        elif reg in REG32_LIST:
            self.mark = 32
            self._Reg32Mark = True
        elif reg in REG16_LIST:
            self.mark = 16
            self._Reg16Mark = True
        elif reg in REG8_LIST:
            self.mark = 8
            self._Reg8Mark = True

    def setValue(self, regValue: int):
        self.value = regValue

class Memory(object):
    flag = "MEM"

    def __init__(self, operand, memAddr):
        self.type = operand
        self.memAddr = memAddr

    def __eq__(self, var):
        try:
            if self.flag == var.flag and self.memAddr == var.memAddr:
                return True
            else:
                return False
        except:
            return False

class Immediate(object):
    flag = "IMM"

    def __init__(self, imm):
        self.type = None
        self.value = imm

    def __eq__(self, var):
        try:
            if self.flag == var.flag and self.type == var.type:
                return True
            else:
                return False
        except:
            return False


class Handler(object):

    def __init__(self, ins_list: list):
        super().__init__()
        self.ins_list = ins_list

    @property
    def size(self):
        return len(self.ins_list)

    @property
    def start(self):
        return self.ins_list[0].index

    @property
    def end(self):
        return self.ins_list[-1].index



class Instruction(object):
    """
    Instruction context order:
        addr asm eax ebx ecx edx esi edi esp ebp eflags read write
    """
    # read & write address
    raddr = waddr = None
    # instruction destination and source
    insn = dst = src = None
    # index in the INS_List
    index = None
    concrete = False
    conVal = None
    _mulCPU = False

    def __init__(self, INS: str, index: int, proj, mulCPU=True, mode="standard"):
        super().__init__()
        self.regs = ConcretRegister()
        if mode == "standard":
            self._envInit(INS, proj)
        elif mode == "fast":
            self._fastEnvInit(INS, proj)
        elif mode == "pack":
            self._packEnvInit(INS, proj)
        self.index = index
        self.proj = proj
        self._mulCPU = mulCPU
        self._setSrcDst()
        if mulCPU:
            # for solving "ValueError: ctypes objects containing pointers cannot be pickled"
            self.insn = Insn(self.insn)

    def __getstate__(self):
        state = self.__dict__.copy()
        l.info(self.__dict__)
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.insn = list(self.proj.arch.capstone.disasm(self.insnbytes,self.addr))[0]
        l.info(self.insn)

    def _envInit(self,INS: str, proj):
        InsInfo = INS.split('; ')

        InsInfo = [int(i,16) for i in InsInfo[:-1]]
        addr = InsInfo.pop(0)
        self.addr = addr
        byteSize = InsInfo.pop(0)
        insnbytes = proj.loader.memory.load(addr,byteSize)
        self.insnbytes = insnbytes
        # ----------------------------------------------------------------------------------------------
        
        # full trace
        # ----------------------------------------------------------------------------------------------
        # insnbytes = bytes.fromhex(InsInfo[-2])  # nengmao of OBS
        # InsInfo = [int(i,16) for i in InsInfo[:-2]] 
        # addr = InsInfo.pop(0)
        # byteSize = InsInfo.pop(0)
        # ----------------------------------------------------------------------------------------------

        try:
            self.insn = list(proj.arch.capstone.disasm(insnbytes,addr))[0]
        except:
            l.error(f"[!] Capstone cannot handle the instruction at addr={hex(addr)}, insnbytes={insnbytes}")
            exit()

        # set registers value
        for key,value in zip(self.regs.registers.keys(),InsInfo[:len(self.regs)]):
            self.regs.registers[key]=value
        try:
            self.raddr, self.waddr = InsInfo[len(self.regs):]
        except:
            l.error(f"[!] Logs Error! Cannot handle the instruction at addr={hex(addr)}, insnbytes={insnbytes}, insinfo={INS}, regslen={len(self.regs)}")
            exit()

    def _fastEnvInit(self, ins:str, proj):
        addr = 0
        byteSize = 0
        insbytes = proj.arch.asm(ins, 0, as_bytes=True)
        self.insn = list(proj.arch.capstone.disasm(insbytes, 0))[0]

        for key in self.regs.registers.keys():
            self.regs.registers[key]=0

        self.raddr = 0
        self.waddr = 0
        self._setSrcDst()

    def _packEnvInit(self,INS: str, proj):
        InsInfo = INS.split('; ')
        InsInfo.pop(-1)
        # l.error(InsInfo)
        insnbytes = bytes.fromhex(InsInfo.pop(-1))
        InsInfo = [int(i,16) for i in InsInfo]

        # disasm instruction with angr loaded program
        addr = InsInfo.pop(0)
        byteSize = InsInfo.pop(0)
        try:
            self.insn = list(proj.arch.capstone.disasm(insnbytes,addr))[0]
        except:
            l.error(f"[!] Capstone cannot handle the instruction at addr={hex(addr)}, insnbytes={insnbytes}")
            exit()

        # set registers value
        for key,value in zip(self.regs.registers.keys(),InsInfo[:len(self.regs)]):
            self.regs.registers[key]=value
        try:
            self.raddr, self.waddr = InsInfo[len(self.regs):]
        except:
            l.error(f"[!] Logs Error! Cannot handle the instruction at addr={hex(addr)}, insnbytes={insnbytes}, insinfo={INS}, regslen={len(self.regs)}")
            exit()

    def _bitMask(self, target: Register, ins: str):
        value = int(ins.split(',')[-1], 16)
        if target.mark==16:
            return ins.replace(hex(value), hex(value & 0xffff))

        elif target.mark==8:
            return ins.replace(hex(value), hex(value & 0xff))
        return ins

    def rewrite(self, ins: str, proj, flag=None):
        if flag=="IMM":
            # mask the immediate to correct size
            if self.src.flag=="REG":
                # l.error(ins)
                ins = self._bitMask(self.src, ins)

            elif self.dst.flag=="REG" and self.mnemonic=="xchg":
                # l.error(ins)
                ins = self._bitMask(self.dst, ins)

        # l.error(ins)
        insbytes = proj.arch.asm(ins, self.addr, as_bytes=True)
        self.insbytes = insbytes
        self.insn = list(proj.arch.capstone.disasm(insbytes,self.addr))[0]
        # self.raddr = 0
        # self.waddr = 0
        self._setSrcDst()


    def __getattr__(self, item):
        # Methods of CsInsn
        if item in ('__str__', '__repr__'):
            return self.__getattribute__(item)
        if hasattr(self.insn, item):
            return getattr(self.insn, item)
        l.warning("no such keyword {}".format(item))
        raise AttributeError()

    def __repr__(self):
        return '<Instruction "%s" for %#x>' % (self.mnemonic, self.address)

    def _setSrcDst(self):
        #

        if len(self.insn.operands)>2:
            # more than two operand
            #TODO new handlers
            self.src = self._constructPara(self.insn.operands[2])
            self.dst = self._constructPara(self.insn.operands[0])
            pass
        elif len(self.insn.operands)==2:
            # two operand
            if self.insn.mnemonic == "xchg":
                self.src, self.dst = [self._constructPara(i) for i in self.insn.operands]
            elif "rep" in self.insn.mnemonic:
                self.dst, self.src = [self._constructPara(i,order=index,mode="M2M") for index,i in enumerate(self.insn.operands)]
            # elif "mov" in self.insn.mnemonic and self.waddr != 0 and self.raddr != 0:  
            #     mem_marks = re.findall('\[.*?\]',self.insn.op_str)
            #     self.dst = Memory(mem_marks[0], self.waddr)
            #     self.src = Memory(mem_marks[1], self.raddr)
            else:
                self.dst, self.src = [self._constructPara(i) for i in self.insn.operands]

        elif len(self.insn.operands)==1:
            # one operand
            # if "div" in self.insn.mnemonic:
            #     # div idiv
            #     operandsize = self.insn.operands[0].size
            #     if operandsize == 8:
            #         self.src = [Register('rax'), Register('rdx'), self._constructPara(self.insn.operands[0])]
            #         self.dst = [Register('rax'), Register('rdx')]
            #     elif operandsize == 4:
            #         self.src = [Register('eax'), Register('edx'), self._constructPara(self.insn.operands[0])]
            #         self.dst = [Register('eax'), Register('edx')]
            #     elif operandsize == 2:
            #         self.src = [Register('ax'), Register('dx'), self._constructPara(self.insn.operands[0])]
            #         self.dst = [Register('ax'), Register('dx')]
            #     elif operandsize == 1:
            #         self.src = [Register('ax'), self._constructPara(self.insn.operands[0])]
            #         self.dst = [Register('ax')]
            #     return

            # elif "mul" in self.insn.mnemonic:
            #     # mul imul
            #     operandsize = self.insn.operands[0].size
            #     if operandsize == 8:
            #         self.src = [Register('rax'), self._constructPara(self.insn.operands[0])]
            #         self.dst = [Register('rax'), Register('rdx')]
            #     elif operandsize == 4:
            #         self.src = [Register('eax'), self._constructPara(self.insn.operands[0])]
            #         self.dst = [Register('eax'), Register('edx')]
            #     elif operandsize == 2:
            #         self.src = [Register('eax'), self._constructPara(self.insn.operands[0])]
            #         self.dst = [Register('ax'), Register('dx')]
            #     elif operandsize == 1:
            #         self.src = [Register('ax'), self._constructPara(self.insn.operands[0])]
            #         self.dst = [Register('ax')]
            #     return

            if self.waddr!=0 and self.raddr!=0:
                self.src = Memory(None, self.raddr)
                self.dst = Memory(None, self.waddr)
            elif self.waddr!=0:
                # write to memory
                self.src = self._constructPara(self.insn.operands[0])
                self.dst = Memory("esp", self.waddr)
            elif self.raddr!=0:
                # read from memory
                self.dst = self._constructPara(self.insn.operands[0])
                self.src = Memory("esp", self.raddr)
            else:
                # other operation (e.g. not)
                self.src = self.dst = self._constructPara(self.insn.operands[0])

        elif len(self.insn.operands)==0:
            # no operand (e.g. nop, pushfd)
            if self.insn.mnemonic in ["pushfd", "popfd"]:
                if self.waddr!=0:
                    # write to memory
                    self.src = Register('eflags')
                    self.dst = Memory(None, self.waddr)
                elif self.raddr!=0:
                    # read from memory
                    self.dst = Register('eflags')
                    self.src = Memory(None, self.raddr)
            
            elif self.insn.mnemonic in ["cwd", "cdq"]:
                self.src = Register('eax')
                self.dst = Register('edx')
            elif self.insn.mnemonic == "rdtsc":
                self.dst = Register('eax')
                self.src = Memory(None, self.raddr)
            elif self.insn.mnemonic == "lahf":
                self.src = Register('eflags')
                self.dst = Register('eax')
            elif self.insn.mnemonic == "sahf":
                self.dst = Register('eflags')
                self.src = Register('eax')
            else:
                self.src = self.dst = None
                srcReg = self.insn.regs_read
                dstReg = self.insn.regs_write
                if len(srcReg) > 0:
                    # no operands but have register access e.g. cbw/cwde/cdqe
                    srcReg=Register(self.insn.reg_name(srcReg[0]))
                    regValue = self.regs.__getattr__(srcReg.type)
                    srcReg.setValue(regValue)
                    self.src = srcReg
                if len(dstReg) > 0:
                    dstReg=Register(self.insn.reg_name(dstReg[0]))
                    regValue = self.regs.__getattr__(dstReg.type)
                    dstReg.setValue(regValue)
                    self.dst = dstReg
                # self.src = self.dst = None

    def _constructPara(self, operand, mode="", order=0):
        memaddr = None
        if mode=="M2M":
            memaddr = [self.waddr, self.raddr][order]
        else:
            if self.waddr!=0:
                memaddr = self.waddr
            elif self.raddr!=0:
                memaddr = self.raddr

        if operand.type==3:
            # X86_OP_MEM = 3
            return Memory(re.search('\[.*\]',self.insn.op_str).group(0), memaddr) # origin
            # return Memory(re.search('\[.*?\]',self.insn.op_str).group(0), memaddr)
        elif operand.type==2:
            # X86_OP_IMM = 2
            return Immediate(operand.imm)
        elif operand.type==1:
            # X86_OP_REG = 1
            regName = self.insn.reg_name(operand.reg)
            tmp = Register(regName)
            regValue = self.regs.__getattr__(tmp.type) #setting for small size
            tmp.setValue(regValue)
            return tmp
    
    def isDataTransfer(self, flag="ALL"):
        if flag=="ALL":
            tins = ["push", "pop", "pushfd", "popfd"]
        elif flag=="IN":
            tins = ["push", "pushfd"]
        elif flag=="OUT":
            tins = ["pop", "popfd"]
        if "mov" in self.insn.mnemonic or self.insn.mnemonic in tins:
            return True
        else:
            return False

class ValueLabel(object):

    def __init__(self, name: str, ins:Instruction, raddr=None, waddr=None,):
        self.operation = False
        self.name = name
        self.raddr = raddr
        self.waddr = waddr
        self._op_list = []
        self.flag = True
        self.index = ins.index
        self._op_list.append(ins)
        self.overwrited = False
        self.start = 0
        self.end = 0
        pass

    def setRaddr(self, raddr: int):
        self.raddr = raddr

    def setWaddr(self, waddr: int):
        self.waddr = waddr

    def addOP(self, ins: Instruction):
        self._op_list.append(ins)

    def updateSE(self):
        self.start = self._op_list[0].index
        self.end = self._op_list[-1].index
