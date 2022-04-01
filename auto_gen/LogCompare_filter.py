import os
import sys
import getopt
import logging
import json

threshold = 1000

def help():
    print("python LogCompare_filter.py -s source_log -t test_ins(json)")
    exit()

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "s:t:h")
    except:
        help()
    src_log = ""
    tst_json = ""

    for opt, arg in opts:
        if opt == '-h':
            help()
        elif opt == '-s':
            src_log = arg
        elif opt == '-t':
            tst_json = arg

    try:        # check param
        if not os.path.exists(src_log):
            raise ValueError("source_log %s invalid" %src)
        if not os.path.exists(tst_json):
            raise ValueError("test_ins %s invalid" %dst)
    except Exception as err:
        print(err)
        help()

    # src_log = "D:\\Project\\anti_vmp\\InsGen\\logcmp\\base_ring3_themida_fish_logcmp.txt"
    # tst_json = "D:\\Project\\anti_vmp\\InsGen\\logcmp\\test_ins\\out_for_tmdfish.json"

    with open(tst_json) as f:
        testset = json.load(f)

    with open(src_log) as f:
        log = f.readlines()

    testset_lst = []
    for test in testset:
        name = test["name"]
        index = name.find(".")
        name = name[:index]
        testset_lst.append(name)

    ret_line = []
    len_log_sum = 0
    len_logcmp_sum = 0
    log_num = 0

    matched_program = []
    for line in log:
        index = line.find(":")
        name = line[:index]
        if name in testset_lst:
            len_lst = line[index+1:].split()
            len_logcmp = int(len_lst[0])
            len_log = int(len_lst[1])
            if len_log > threshold and len_logcmp > threshold:
                len_log_sum += len_log
                len_logcmp_sum += len_logcmp
                log_num += 1
                matched_program.append(name)
                ret_line.append(line.strip())
            else:
                print("program %s doesn't reach threshold: %d %d" %(name, len_logcmp, len_log))

    for program in testset_lst:
        if not program in matched_program:
            print("program %s not in ret_lst" %(program))

    ret_line.sort()
    for line in ret_line:
        print(line)

    print("len log sum: %d  avg: %d" %(len_log_sum, len_log_sum//log_num))
    print("len logcmp sum: %d  avg: %d" %(len_logcmp_sum, len_logcmp_sum//log_num))