import os
import sys
import getopt
import logging

from suffix import *

anchor = "cmpxchg eax, eax"

full_test_set = []
test_set = []
gcc_failed_set = []
vmp_failed_set = []
log_failed_set = []


class Logger:
    stream_loglevel = (logging.INFO, )
    file_loglevel = (logging.WARNING, logging.ERROR)

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


def FindInsn(insns, anchor):
    anchor_begin = insns.find(anchor) + len(anchor)
    anchor_begin += insns[anchor_begin:].find("\n") + 1
    anchor_end = anchor_begin + insns[anchor_begin:].find(anchor)
    anchor_end -= anchor_end - anchor_begin - insns[anchor_begin:anchor_end].rfind("\n")
    ins_begin = anchor_begin + insns[anchor_begin:anchor_end].find("\"")
    ins_end = ins_begin+1 + insns[ins_begin+1:anchor_end].find("\"")
    return insns[ins_begin+1:ins_end-1]


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


def ParseDirs(dir_str):
    return dir_str.split(' ')


def help():
    print("python FetchTestSet.py -d dir1 dir2 -l logfile [-b base_dir -a anchor_str]")
    exit()

if __name__ == "__main__":
    base_dir = ""
    logfile = ""
    try:
        opts, args = getopt.getopt(sys.argv[1:], "d:e:l:b:a:h")
    except:
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

    try:        # check param
        for dir_tmp in folders:
            tstdir = os.path.join(base_dir, dir_tmp)
            if not os.path.exists(tstdir):
                raise ValueError("folder %s invalid" %tstdir)
        if not logfile == "":
            log_dir = os.path.dirname(logfile)
            if not os.path.exists(log_dir):
                raise ValueError("log folder %s invalid" %log_dir)
    except Exception as err:
        print(err)
        help()

    logger = Logger(logfile)

    old_path = os.getcwd()
    # ===== for general cases =====
    for folder in folders:
        vmpexe_suffix = GetVmpexe(folder)
        tmp = os.path.join(base_dir, folder)
        if os.path.isdir(tmp):
            os.chdir(tmp)
            files = os.listdir()
            max_num = GetVmpNum(files, vmpexe_suffix)

            for myfile in files:
                if myfile.endswith(suffix):
                    with open(myfile) as f:
                        tmp = f.read()
                    ins = FindInsn(tmp, anchor)
                    if myfile[:suffix_index] + exe_suffix in files:
                        flag = True
                        for i in range(max_num):
                            log_failed_set.append([])
                            vmp_failed_set.append([])
                            test_set.append([])
                            if myfile[:suffix_index] + "_%d"%(i+1) + vmpexe_suffix in files:
                                if myfile[:suffix_index] + "_%d"%(i+1) + log_suffix in files:
                                    test_set[i].append((folder, myfile[:suffix_index], ins))
                                else:
                                    log_failed_set[i].append((folder, myfile[:suffix_index], ins))
                                    flag = False
                            else:
                                vmp_failed_set[i].append((folder, myfile[:suffix_index], ins))
                                flag = False
                        if flag:
                            full_test_set.append((folder, myfile[:suffix_index], ins))
                    else:
                        gcc_failed_set.append((folder, myfile[:suffix_index], ins))


    os.chdir(old_path)

    # print test set
    logger.warning("==============Full Test Set==============")
    prev_folder = ""
    tmp_lst = []
    for folder, filename, ins in full_test_set:
        if prev_folder != folder:
            logger.warning("    =============%s=============" %folder)
            prev_folder = folder
        tmp_lst.append((filename, ins))
    for filename, ins in tmp_lst:
        logger.warning("file: %s  \t  ins: %s" %(filename, ins))
    for filename, ins in tmp_lst:
        logger.info("%s" %ins)

    logger.warning("==============GCC Failed Set==============")
    for folder, filename, ins in gcc_failed_set:
        if prev_folder != folder:
            logger.warning("    =============%s=============" %folder)
            prev_folder = folder
        logger.warning("file: %s  \t  ins: %s" %(filename, ins))

    for i in range(max_num):
        logger.warning("///===========Failed Set: %d===========\\\\\\" %(i+1))
        logger.warning("==============VMP Failed Set==============")
        for folder, filename, ins in vmp_failed_set[i]:
            if prev_folder != folder:
                logger.warning("    =============%s=============" %folder)
                prev_folder = folder
            logger.warning("file: %s  \t  ins: %s" %(filename, ins))

        logger.warning("==============LOG Failed Set==============")
        for folder, filename, ins in log_failed_set[i]:
            if prev_folder != folder:
                logger.warning("    =============%s=============" %folder)
                prev_folder = folder
            logger.warning("file: %s  \t  ins: %s" %(filename, ins))

        # logger.warning("==============Test Set==============")
