import re
import sys
import os
import getopt


pinlog_str = "pin -t"
exp_str = "exception"

log_pattern = re.compile(r".*\.exe:.*;\d+;\d+;\d+")

ignore = False      # ignore duplicate

loglen_threshold = 1000

# inputfile = "F:\\anti_vmp\\AnchorVerify\\base_ring3_output_cvshark\\err_log\\pin_out.log"

def GetAnchor(data):
    retanchor = []
    anchor3 = []
    avg_log = {}
    for ins in data:
        flag = False
        if not len(data[ins]) == 3:
            if len(data[ins]) == 0:
                raise ValueError("len data[ins] == 0")
            else:
                # log_state = [False] * 3
                log_num = 0
                for i in range(1,4):
                    name = ins + "_%01d"%i
                    if not name in data[ins]:
                        print("no log %s" %name)
                    else:
                        log_num += 1
                if log_num != len(data[ins]):
                    raise ValueError("len data[ins] != log_num")
                else:
                    flag = True
        else:
            flag = True
            log_num = 3

        if flag:
            retanchor_pos = 0
            anchor3_pos = 0
            log_len = 0
            for i in range(1, 4):
                name = ins + "_%01d"%i
                try:
                    tmp = data[ins][name]
                except:
                    continue
                if tmp[1] == "1":
                    retanchor_pos += 1
                if tmp[2] == "1":
                    anchor3_pos += 1
                log_len += int(tmp[3])
            retanchor.append((ins, tmp[0], retanchor_pos, log_num))
            anchor3.append((ins, tmp[0], anchor3_pos, log_num))
            avg_log[ins] = log_len // log_num
    return retanchor, anchor3, avg_log


def GetData(lines):
    result = {}
    for line in lines:
        try:
            tmp = line.split(":")
            program = tmp[0]
            content = tmp[1]
            content_lst = content.split(";")
            ins = content_lst[0]
            is_retanchor = content_lst[1]
            appear_time = content_lst[2]
            loglen = content_lst[3]
        except:
            raise ValueError("Parse Error: %s" %line)

        ins_name = program[:program.rfind("_")]
        if not ins_name in result:
            result[ins_name] = {}
        program_name = program[:program.rfind("_")+2]
        if program_name in result[ins_name]:
            if ignore:
                print("%s duplicated" %program)
            else:
                raise ValueError("%s duplicated" %program)
        else:
            result[ins_name][program_name] = (ins, is_retanchor, appear_time, loglen)
    return result


# def FliterOut(lines):
#     ret_lst = []
#     for line in lines:
#         if line.find(pinlog_str) == -1 and line.find(exp_str) == -1:
#             ret_lst.append(line)
#     return ret_lst

def FliterOut(lines):
    ret_lst = []
    for line in lines:
        p = log_pattern.match(line)
        if p:
            ret_lst.append(line)
    return ret_lst

def PrintAnchor(anchor_lst):
    anchor_lst.sort()
    for ins in anchor_lst:
        if ins[2] != 0 and ins[2] != 3:
            print("File: %s   len != 3, len = %d" %(ins[0], ins[2]))
    for ins in anchor_lst:
        if ins[2] == ins[3]:
            print(ins[1])


def PrintLogAvg(avg_dct):
    key_lst = list(avg_dct.keys())
    key_lst.sort()
    for key in key_lst:
        print("%s: %d" %(key, avg_dct[key]))

def PrintSum(avg_dct):
    key_lst = list(avg_dct.keys())
    key_lst.sort()

    logsum = 0
    lognum = 0
    for key in key_lst:
        length = avg_dct[key]
        if length > loglen_threshold:
            logsum += length
            lognum += 1
    print("len log sum: %d  avg: %d" %(logsum, logsum // lognum))


def help():
    print("python pin_anchorfinder.py -i inputfile -t 3/r/l -I")
    print("-a: 3 for 3anchor, r for retanchor, l for log average")
    print("-I ignore duplicate")
    exit()

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:t:Ih")
    except:
        help()

    for opt, arg in opts:
        if opt == '-h':
            help()
        elif opt == '-i':
            inputfile = arg
        elif opt == '-I':
            ignore = True
        elif opt == '-t':
            anchor_type = arg

    try:        # check param
        if not os.path.exists(inputfile):
            raise ValueError("inputfile invalid")
        if not anchor_type in ('3', 'r', 'l'):
            raise ValueError("Error Type %s" %anchor_type)
    except Exception as err:
        print(err)
        help()

    # just for test
    # inputfile = "F:\\anti_vmp\\AnchorVerify\\x87_output_vmp3\\err_log\\pin_out.log"
    # anchor_type = "r"


    with open(inputfile) as f:
        lines = f.readlines()

    new_lines = FliterOut(lines)
    data = GetData(new_lines)

    retanchor, anchor3, avg_log = GetAnchor(data)

    if anchor_type == "r":
        PrintAnchor(retanchor)
    elif anchor_type == "3":
        PrintAnchor(anchor3)
    elif anchor_type == "l":
        PrintLogAvg(avg_log)
        PrintSum(avg_log)