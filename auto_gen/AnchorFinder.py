#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    :   AnchorFinder.py
@Time    :   2020/10/13
@Author  :   nen9mA0 
@Version :   1.0
@Contact :   
@License :   BSD
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
log_threshold = 10*1024
except_logfile = ["pin.log", "pintool.log"]

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


def FindVerifyAnchor(dir_path, finder, in_folder, logger=None):
    global log_threshold

    logfiles = {}
    logfailed = {}
    tmp = os.path.join(dir_path, in_folder)
    if os.path.isdir(tmp):
        os.chdir(tmp)
        new_path = tmp
        for files in os.listdir():
            tmp = os.path.join(new_path, files)
            if not os.path.isdir(tmp):
                if tmp.endswith(".log"):
                    filename = os.path.basename(tmp)
                    if filename in except_logfile:
                        continue
                    fsize = os.path.getsize(tmp)
                    if fsize > log_threshold:
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
                    else:
                        keyname_index = files.find("_")
                        keyname = files[:keyname_index]
                        if keyname in logfailed:
                            logfailed[keyname] += 1
                        else:
                            logfailed[keyname] = 1
                        if logger != None:
                            logger.info("%s:" %(files.rstrip(".log")))
                            logger.info("LOG LENGTH TOO SHORT")
    os.chdir(dir_path)
    return logfiles, logfailed


def FindVerifyRetAnchor(dir_path, finder, in_folder, logger=None):
    global log_threshold

    logfiles = {}
    logfailed = {}
    tmp = os.path.join(dir_path, in_folder)
    if os.path.isdir(tmp):
        os.chdir(tmp)
        new_path = tmp
        for files in os.listdir():
            tmp = os.path.join(new_path, files)
            if not os.path.isdir(tmp):
                if tmp.endswith(".log"):
                    filename = os.path.basename(tmp)
                    if filename in except_logfile:
                        continue
                    fsize = os.path.getsize(tmp)
                    if fsize > log_threshold:
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
                    else:
                        keyname_index = files.find("_")
                        keyname = files[:keyname_index]
                        if keyname in logfailed:
                            logfailed[keyname] += 1
                        else:
                            logfailed[keyname] = 1
                        if logger != None:
                            logger.info("%s:" %(files.rstrip(".log")))
                            logger.info("LOG LENGTH TOO SHORT")
    os.chdir(dir_path)
    return logfiles, logfailed


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


def GetFileNum(file_lst, suffix):
    suffix_begin = -len(suffix)
    file_dict = {}
    for file in file_lst:
        if file.endswith(suffix) and file[:suffix_begin].rfind(".") == -1:
            num_begin_index = file[:suffix_begin].rfind("_")
            if num_begin_index != -1:
                filename = file[:num_begin_index]
                if filename in file_dict:
                    file_dict[filename] += 1
                else:
                    file_dict[filename] = 1
            else:
                filename = file[:suffix_begin]
                if filename in file_dict:
                    raise ValueError("filename: %s has in dict" %filename)
                else:
                    file_dict[filename] = 1
    return max_num, file_dict


def help():
    print("python AnchorFinder.py -d dir -m mode [-a anchor -b base_dir -l logfile]")
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
            folder = arg
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
        tstdir = os.path.join(base_dir, folder)
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
        in_folder = folder
    else:
        verify_dir = os.path.basename(folder)
        in_folder = os.path.dirname(folder)

    logger = Logger(logfile)
    finder = AnchorFinder(logger)
    finder.SetSourcePath(verify_dir)

# ====================
    dir_path = os.getcwd()

    max_num = 0
    vmpexe_suffix = GetVmpexe(in_folder)
    tmp = os.path.join(base_dir, in_folder)
    if os.path.isdir(tmp):
        os.chdir(tmp)
        files = os.listdir()
        tmp_num = GetVmpNum(files, vmpexe_suffix)
        if tmp_num > max_num:
            max_num = tmp_num
    else:
        raise ValueError("%s is not a folder" %tmp)

    os.chdir(dir_path)
# ====================

    if mode == '3':
        testdict, logfailed = FindVerifyAnchor(verify_dir, finder, in_folder, logger=logger)
    elif mode == 'r':
        testdict, logfailed = FindVerifyRetAnchor(verify_dir, finder, in_folder, logger=logger)

    anchorset = {}
    for key in testdict:
        filename = os.path.basename(key)
        index = filename.rfind("_")
        newkey = filename[:index]
        if newkey in anchorset:
            anchorset[newkey].append(len(testdict[key]))
        else:
            anchorset[newkey] = [len(testdict[key])]


    a, srcfiledict = GetFileNum(files, suffix)          # get source files
    a, exefiledict = GetFileNum(files, exe_suffix)      # get exe files
    a, vmpfiledict = GetFileNum(files, vmpexe_suffix)   # get vmp files
    a, logfiledict = GetFileNum(files, log_suffix)      # get log files

    noexe_lst = []
    novmp_lst = []
    nolog_lst = []
    lossvmp_lst = []
    losslog_lst = []

    anchor_lst = []
    not_always_appear = []
    appear_multiple = []


    for file in srcfiledict:                            # traverse every source file
        if file in exefiledict:                         # traverse every executable
            if file in vmpfiledict:                     # traverse every obfuscated file
                if vmpfiledict[file] != max_num:
                    lossvmp_lst.append(file)            # some executable cannot be obfuscated
                if file in logfiledict:
                    if logfiledict[file] != max_num:    # some obfuscated files have error in running pintools
                        losslog_lst.append(file)
                    log_num = logfiledict[file]
                    if file in logfailed:               # some trace files are too small, which indicates that something goes wrong when obfuscating
                        log_num -= logfailed[file]
                    if file in anchorset and log_num>0:
                        if len(anchorset[file]) != log_num:
                            for i in range(1, max_num+1):
                                keyname = os.path.join(tmp, file+"_%d.log"%i)
                                if keyname in testdict:
                                    res = testdict[keyname]
                                    break
                            inst, addr = res[0]
                            not_always_appear.append( (inst, log_num, file, os.path.join(tmp, file)) )
                        else:
                            flag = 0
                            for i in anchorset[file]:
                                if i == 1:
                                    flag += 1
                            if flag == log_num:
                                for i in range(1, max_num+1):
                                    keyname = os.path.join(tmp, file+"_%d.log"%i)
                                    if keyname in testdict:
                                        res = testdict[keyname]
                                        break
                                anchor, addr = res[0]
                                anchor_lst.append( (anchor, log_num, os.path.join(tmp, file)) )
                            else:
                                for i in range(1, max_num+1):
                                    keyname = os.path.join(tmp, file+"_%d.log"%i)
                                    if keyname in testdict:
                                        res = testdict[keyname]
                                        break
                                inst, addr = res[0]
                                appear_multiple.append( (inst, flag, log_num, file, os.path.join(tmp, file)) )
                else:                                   # if we have obfuscated files but don't have any trace file, the obfuscated file has error in running pintools
                    nolog_lst.append(file)
            else:                                       # if we have executable but don't have any obfusated file, the executable has error in obfuscate
                novmp_lst.append(file)
        else:                                           # if we have source file but don't have executable, the source file has compile error
            noexe_lst.append(file)


    logger.error("========= Anchor =========")
    for anchor, log_num, filepath in anchor_lst:
        logger.error("%s  ; %d ; File: %s.c" %(anchor, log_num, filepath))
        print("%s" %anchor)

    logger.error("========= Not Always Appear =========")
    for inst, log_num, file, filepath in not_always_appear:
        logger.error("%s ; %d/%d ; %s ; File: %s.c" %(inst, len(anchorset[file]), log_num, anchorset[file], filepath))
        print("%s ; %d/%d ; %s ; File: %s.c" %(inst, len(anchorset[file]), log_num, anchorset[file], filepath))

    logger.error("========= Appear Multiple Times =========")
    for inst, flag, log_num, file, filepath in appear_multiple:
        logger.error("%s  ; %d/%d ; %s ; File: %s.c" %(inst, flag, log_num, anchorset[file], filepath))

    logger.error("=== No EXE ===")
    for exe in noexe_lst:
        logger.error(exe)

    logger.error("=== No VMP ===")
    for vmp in novmp_lst:
        logger.error(vmp)

    logger.error("=== No LOG ===")
    for log in nolog_lst:
        logger.error(log)

    logger.error("=== Loss VMP ===")
    for vmpfile in lossvmp_lst:
        logger.error("%s : %d/%d" %(vmpfile, max_num - vmpfiledict[vmpfile], max_num))

    logger.error("=== Loss LOG ===")
    for logfile in losslog_lst:
        logger.error("%s : %d/%d" %(logfile, max_num - logfiledict[logfile], max_num))

    logger.error("=== LOG TOO SHORT ===")
    for logfile in logfailed:
        logger.error("%s : %d" %(logfile, logfailed[logfile]))

