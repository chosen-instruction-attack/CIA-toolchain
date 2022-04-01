import os
import sys
import getopt
import logging
import json

threshold = 1000

def help():
    print("python LogCompare_filter.py -a source_log -b source_logcmp -t test_ins(json)")
    exit()

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "a:b:t:h")
    except:
        help()
    src_log = ""
    src_logcmp = ""
    tst_json = ""

    for opt, arg in opts:
        if opt == '-h':
            help()
        elif opt == '-a':
            src_log = arg
        elif opt == '-b':
            src_logcmp = arg
        elif opt == '-t':
            tst_json = arg

    try:        # check param
        if not os.path.exists(src_log):
            raise ValueError("source_log %s invalid" %src_log)
        if not os.path.exists(src_logcmp):
            raise ValueError("source_logcmp %s invalid" %src_logcmp)
        if not os.path.exists(tst_json):
            raise ValueError("test_ins %s invalid" %tst_json)
    except Exception as err:
        print(err)
        help()

    # src_log = "D:\\Project\\anti_vmp\\InsGen\\logcmp\\base_ring3_themida_fish_logcmp.txt"
    # tst_json = "D:\\Project\\anti_vmp\\InsGen\\logcmp\\test_ins\\out_for_tmdfish.json"

    with open(tst_json) as f:
        testset = json.load(f)

    with open(src_log) as f:
        log = f.readlines()

    with open(src_logcmp) as f:
        logcmp = f.readlines()

    testset_lst = []
    for test in testset:
        name = test["name"]
        index = name.find(".")
        name = name[:index]
        testset_lst.append(name)

    log_line = {}
    for line in log:
        index = line.find(":")
        name = line[:index]
        if name in testset_lst:
            log_line[name] = line

    logcmp_line = {}
    for line in logcmp:
        index = line.find(":")
        name = line[:index]
        if name in testset_lst:
            logcmp_line[name] = line

    ret_line = []
    len_log_sum = 0
    len_logcmp_sum = 0
    log_num = 0
    for name in testset_lst:
        if not name in log_line:
            print("program %s not in log" %name)
            continue
        if not name in logcmp_line:
            print("program %s not in logcmp" %name)
            continue
        log_str = log_line[name]
        index = log_str.find(":")
        len_log = int(log_str[index+1:])

        logcmp_str = logcmp_line[name]
        index = logcmp_str.find(":")
        len_logcmp = int(logcmp_str[index+1:])

        if len_log > threshold and len_logcmp > threshold:
            len_log_sum += len_log
            len_logcmp_sum += len_logcmp
            log_num += 1
            ret_line.append("%s: %d %d" %(name, len_logcmp, len_log))
        else:
            print("program %s doesn't reach threshold: %d %d" %(name, len_logcmp, len_log))

    ret_line.sort()
    for line in ret_line:
        print(line)

    print("len log sum: %d  avg: %d" %(len_log_sum, len_log_sum//log_num))
    print("len logcmp sum: %d  avg: %d" %(len_logcmp_sum, len_logcmp_sum//log_num))