#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    :   AnchorFinder.py
@Time    :   2020/10/13
@Author  :   nen9mA0 
@Version :   1.0
@Contact :   
@License :   GPL
@Desc    :   None
'''
# Modified from TraceAnalysis.py
# Used to find anchors from testset. Simply compare the mnemonic and oprands of every instructions in testset trace. If we find an instruction in trace which is totally the same as the instruction we test in source code, we regard this instruction as an potential anchor.

import capstone
import keystone
import logging
import os
import sys
import getopt
import shutil
import pickle

from InsHexLst import *
from suffix import *


anchor = "cmpxchg eax, eax"

class Logger:
    # stream_loglevel = (logging.WARNING, logging.ERROR, logging.DEBUG,)
    # stream_loglevel = (logging.INFO, )
    stream_loglevel = (None, )
    file_loglevel = (logging.WARNING, logging.ERROR, logging.INFO, )

    def __init__(self, filename):
        self.log = logging.getLogger()
        self.log.setLevel(logging.NOTSET)

        self.streamlog = logging.StreamHandler(sys.stderr)
        stream_filter = logging.Filter()
        stream_filter.filter = lambda record: record.levelno in self.stream_loglevel
        self.streamlog.addFilter(stream_filter)
        self.log.addHandler(self.streamlog)

        if filename != "":
            self.filelog = logging.FileHandler(filename, "w")
            filefilter = logging.Filter()
            filefilter.filter = lambda record: record.levelno in self.file_loglevel
            self.filelog.addFilter(filefilter)
            self.log.addHandler(self.filelog)

    def __getattr__(self, attr):
        return getattr(self.log, attr)


class AnchorFinder(object):
    def __init__(self, logger):
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
        self.logger = logger
        self.set_sourcepath = False

    def SetSourcePath(self, path):
        self.set_sourcepath = True
        self.source_path = path

    def GetSourceFile(self, traceFileName):
        if not self.set_sourcepath:
            source_path = "."
        else:
            source_path = self.source_path
        if "_" in traceFileName:
            filename = os.path.split(traceFileName)[1]
            index = filename.index("_")
            filename = filename[:index] + suffix
            tmp = os.path.split(traceFileName)[0]
            dirname = os.path.split(tmp)[1]
            filepath = os.path.join(source_path, dirname, filename)
            return filepath
        else:
            raise ValueError("TraceFileName")

    def AsmToHex(self, ins_str):
        global ins_hex_lst
        if ins_str in ins_hex_lst:
            ret = (ins_hex_lst[ins_str], 1)
        else:
            try:
                ret = self.ks.asm(ins_str)
            except Exception as err:
                print(ins_str)
                raise err
        return ret

    def GetTstIns(self, sourcefile):
        global anchor
        with open(sourcefile) as f:
            insns = f.read()
            anchor_begin = insns.find(anchor) + len(anchor)
            anchor_begin += insns[anchor_begin:].find("\n") + 1
            anchor_end = anchor_begin + insns[anchor_begin:].find(anchor)
            anchor_end -= anchor_end - anchor_begin - insns[anchor_begin:anchor_end].rfind("\n")
            ins_begin = anchor_begin + insns[anchor_begin:anchor_end].find("\"")
            ins_end = ins_begin+1 + insns[ins_begin+1:anchor_end].find("\"")
            newanchor_str = insns[ins_begin+1:ins_end-1]
        return newanchor_str

    def SearchNewAnchor(self, traceFileName):
        anchorlst = []
        index = 0

        sourcefile = self.GetSourceFile(traceFileName)

        newanchor_str = self.GetTstIns(sourcefile)
        newanchor_asm = self.AsmToHex(newanchor_str)
        newanchor = bytes(newanchor_asm[0])

        with open(traceFileName) as f:
            self.logger.debug("Searching File %s" %traceFileName)
            for line in f:
                index += 1
                try:
                    ins_info = line.split(';')
                    addr = int(ins_info[0], 16)
                    byteSize = int(ins_info[1])

                    if ins_info[13][-1] == '\n':
                        tmp = ins_info[13][:-1]     # remove \n
                    else:
                        tmp = ins_info[13]
                    tmp = tmp.strip()
                    i = tmp.find("0x")
                    if i != -1:
                        tmp = tmp[i+2:]
                    ins_hex = bytes.fromhex(tmp)
                    if newanchor == ins_hex:
                        anchorlst.append((newanchor_str, addr))
                except Exception as e:
                    self.logger.error("File: %s   line: %d" %(traceFileName, index))
                    self.logger.error(str(e))
        return anchorlst

    def SearchRetAnchor(self, traceFileName):
        ret_hex = [0xc3, 0xcb, 0xc2, 0xca]
        anchorlst = []
        index = 0

        sourcefile = self.GetSourceFile(traceFileName)

        newanchor_str = self.GetTstIns(sourcefile)
        newanchor_asm = self.AsmToHex(newanchor_str)
        newanchor = bytes(newanchor_asm[0])

        with open(traceFileName) as f:
            self.logger.debug("Searching File %s" %traceFileName)
            prev_hex = None
            for line in f:
                index += 1
                try:
                    ins_info = line.split(';')
                    # disasm instruction with angr loaded program
                    addr = int(ins_info[0], 16)
                    byteSize = int(ins_info[1])
                    # ins_hex = bytes.fromhex(ins_info[3])
                    if ins_info[13][-1] == '\n':
                        tmp = ins_info[13][:-1]     # remove \n
                    else:
                        tmp = ins_info[13]
                    tmp = tmp.strip()
                    i = tmp.find("0x")
                    if i != -1:
                        tmp = tmp[i+2:]
                    ins_hex = bytes.fromhex(tmp)
                    if newanchor == ins_hex:
                        if prev_hex[0] in ret_hex:
                            anchorlst.append((newanchor_str, addr))
                            break
                except Exception as e:
                    self.logger.error("File: %s   line: %d" %(traceFileName, index))
                    self.logger.error(str(e))
                prev_hex = ins_hex
        return anchorlst


def FindVerifyAnchor(dir_path, finder, logger=None, in_folders=None):
    logfiles = {}
    if in_folders:
        folders = in_folders
    else:
        folders = os.listdir(dir_path)
    for folder in folders:
        tmp = os.path.join(dir_path, folder)
        if os.path.isdir(tmp):
            os.chdir(tmp)
            new_path = tmp
            for files in os.listdir():
                tmp = os.path.join(new_path, files)
                if not os.path.isdir(tmp):
                    if tmp.endswith(".log") and not tmp.endswith("\\pin.log"):
                        tracefile = tmp
                        res = finder.SearchNewAnchor(tmp)
                        if len(res) != 0:
                            logfiles[tracefile] = res
                            anchor, addr = res[0]
                            if logger != None:
                                logger.info("%s:" %(files.rstrip(".log")))
                                if len(res) == 1:
                                    logger.info("==== only occur one time ====\n    %x: %s" %(addr, anchor))
                                else:
                                    logger.info("____ occur %d times ____\n    %x: %s" %(len(res), addr, anchor))
                            # for anchor, addr in res:
                            #     logger.info("    %x: %s" %(addr, anchor))
    os.chdir(dir_path)
    return logfiles


def FindVerifyRetAnchor(dir_path, finder, logger=None, in_folders=None):
    logfiles = {}
    if in_folders:
        folders = in_folders
    else:
        folders = os.listdir(dir_path)
    for folder in folders:
        tmp = os.path.join(dir_path, folder)
        if os.path.isdir(tmp):
            os.chdir(tmp)
            new_path = tmp
            for files in os.listdir():
                tmp = os.path.join(new_path, files)
                if not os.path.isdir(tmp):
                    if tmp.endswith(".log") and not tmp.endswith("\\pin.log"):
                        tracefile = tmp
                        res = finder.SearchRetAnchor(tmp)
                        if len(res) != 0:
                            logfiles[tracefile] = res
                            anchor, addr = res[0]
                            if logger != None:
                                logger.info("%s:" %(files.rstrip(".log")))
                                if len(res) == 1:
                                    logger.info("==== only occur one time ====\n    %x: %s" %(addr, anchor))
                                else:
                                    logger.info("____ occur %d times ____\n    %x: %s" %(len(res), addr, anchor))
                            # for anchor, addr in res:
                            #     logger.info("    %x: %s" %(addr, anchor))
    os.chdir(dir_path)
    return logfiles


def GetVmpexe(folder):
    folder_name = os.path.basename(folder)
    vmpexe_suffix = vmp_suffix      # by default
    if "themida" in folder_name:
        vmpexe_suffix = themida_suffix
    elif "cv" in folder_name:
        vmpexe_suffix = cv_suffix
    elif "eni" in folder_name:
        vmpexe_suffix = enigma_suffix
    elif "vmp" in folder_name:
        vmpexe_suffix = vmp_suffix
    elif "obs" in folder_name:
        vmpexe_suffix = obsidium_suffix
    return vmpexe_suffix

def GetVmpNum(file_lst, suffix):
    max_num = 0
    suffix_begin = -len(suffix)
    for file in file_lst:
        if file.endswith(suffix):
            num_begin_index = file[:suffix_begin].rfind("_")
            num = int(file[num_begin_index+1:suffix_begin])
            if num > max_num:
                max_num = num
    return max_num


def help():
    print("python AnchorFinder.py -d dir1 dir2... -m mode [-a anchor -b base_dir -l logfile]")
    print("mode can be 3 or r, represent 3anchor or retanchor")
    exit()


def ParseDirs(dir_str):
    return dir_str.split(' ')


if __name__ == "__main__":
    base_dir = ""
    logfile = ""

    try:
        opts, args = getopt.getopt(sys.argv[1:], "a:b:d:l:m:h")
    except Exception as err:
        print(err)
        help()

    for opt, arg in opts:
        if opt == '-h':
            help()
        elif opt == '-d':
            folders = ParseDirs(arg)
        elif opt == '-l':
            logfile = arg
        elif opt == '-b':
            base_dir = arg
        elif opt == '-a':
            anchor = arg
            anchor = anchor.strip('\"')
        elif opt == '-m':
            mode = arg

    try:        # check param
        for dir_tmp in folders:
            tstdir = os.path.join(base_dir, dir_tmp)
            if not os.path.exists(tstdir):
                raise ValueError("folder %s invalid" %tstdir)
        if len(logfile) > 0:
            log_dir = os.path.dirname(logfile)
            if not os.path.exists(log_dir):
                raise ValueError("log folder %s invalid" %log_dir)
        if not mode in ('3', 'r'):
            raise ValueError("mode error")
    except Exception as err:
        print(err)
        help()

    if not base_dir == "":
        verify_dir = base_dir
        in_folders = folders
    else:
        verify_dir = os.path.dirname(folders[0])
        in_folders = [os.path.basename(folder) for folder in folders]

    logger = Logger(logfile)
    finder = AnchorFinder(logger)


    dir_path = os.getcwd()

    if mode == '3':
        testdict = FindVerifyAnchor(verify_dir, finder, logger=logger, in_folders=in_folders)
    elif mode == 'r':
        testdict = FindVerifyRetAnchor(verify_dir, finder, logger=logger, in_folders=in_folders)

    anchorset = {}
    for key in testdict:
        filename = key[:-6]
        if filename in anchorset:
            anchorset[filename].append(len(testdict[key]))
        else:
            anchorset[filename] = [len(testdict[key])]

    for key in anchorset:
        if len(anchorset[key]) != 3:
            logger.error("File: %s   len != 3, len = %d" %(key, len(anchorset[key])))
            print("File: %s   len != 3, len = %d" %(key, len(anchorset[key])))
        else:
            flag = 0
            for i in anchorset[key]:
                if i == 1:
                    flag += 1
            if flag == 3:
                res = testdict[key+"_1.log"]
                anchor, addr = res[0]
                logger.warning("%s  ; File: %s" %(anchor, key))
                print("%s" %anchor)
