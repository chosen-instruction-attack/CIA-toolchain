#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    :   LogCompare.py
@Time    :   2021/05/20
@Author  :   nen9mA0 
@Version :   1.0
@Contact :   
@License :   GPL
@Desc    :   None
'''
# Used to compare the length of log with anchor and without anchor.

import os
import sys
import getopt
import logging
from itertools import (takewhile, repeat)

class Logger:
    # stream_loglevel = (logging.WARNING, logging.ERROR, logging.DEBUG,)
    stream_loglevel = (logging.INFO, )
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

def CountLines(filename):
    buffer = 1024 * 1024
    with open(filename) as f:
        buf_gen = takewhile(lambda x: x, (f.read(buffer) for _ in repeat(None)))
        return sum(buf.count('\n') for buf in buf_gen)

def help():
    print("python LogCompare.py -s source_dir -d dest_dir -l logfile")
    print("source dir contains log file, dst dir contains logcmp file")
    exit()

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "s:d:l:h")
    except:
        help()
    src = ""
    dst = ""
    logfile = ""
    for opt, arg in opts:
        if opt == '-h':
            help()
        elif opt == '-s':
            src = arg
        elif opt == '-d':
            dst = arg
        elif opt == '-l':
            logfile = arg
    if len(dst) == 0:
        dst = src
    elif len(src) == 0:
        src = dst
    try:        # check param
        if len(src) == 0:
            raise ValueError("src and dst are both empty")
        if not os.path.exists(src):
            raise ValueError("source folder %s invalid" %src)
        if not os.path.exists(dst):
            raise ValueError("target folder %s invalid" %dst)
        if len(logfile) > 0:
            log_dir = os.path.dirname(logfile)
            if not os.path.exists(log_dir):
                raise ValueError("log folder %s invalid" %log_dir)
    except Exception as err:
        print(err)
        help()
    # log_dirpath = "E:\\CSA_data\\AnchorVerify_2"
    # log_subpath = "base_ring3_output_themida_tiger_black"

    # log_dirpath = "F:\\anti_vmp\\AnchorVerify"
    # log_subpath = "base_ring3_output_cvtiger_red"

    logger = Logger(logfile)

    suffix = ".logcmp"
    suffix_len = len(suffix)

    threshold = 10*1024          # log less than threshold will not be counted

    dst_files = os.listdir(dst)

    cmp_res = []
    for myfile in dst_files:
        if myfile.endswith(suffix):
            file_size = os.path.getsize(os.path.join(dst, myfile))
            if file_size < threshold:
                continue
            len_logcmp = CountLines(os.path.join(dst, myfile))

            cmpfile = myfile.replace(suffix, "_1.log")
            if not os.path.exists(os.path.join(src, cmpfile)):
                logger.log.warning("cmplog %s not exist" %(cmpfile))
                continue
            cmpfile_size = os.path.getsize(os.path.join(src, cmpfile))
            if cmpfile_size < threshold:
                continue
            len_log = CountLines(os.path.join(src, cmpfile))

            cmp_res.append((myfile[:-suffix_len], len_logcmp, len_log))

    for item in cmp_res:
        logger.log.warning("%s: %d %d" %(item[0], item[1], item[2]))

    sum_len_log = 0
    sum_len_logcmp = 0
    for item in cmp_res:
        sum_len_log += item[2]
        sum_len_logcmp += item[1]

    logger.log.info("len log sum: %d  avg: %d" %(sum_len_log, sum_len_log/len(cmp_res)))
    logger.log.info("len logcmp sum: %d  avg: %d" %(sum_len_logcmp, sum_len_logcmp/len(cmp_res)))
