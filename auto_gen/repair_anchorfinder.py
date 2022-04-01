import sys
import getopt
import os
import re
import copy


getnum = re.compile(r"File: (?P<file>\S+)   len != 3, len = (?P<num>\d)")

threshold = 10*1024        # 10KB
total_lognum = 3
anchor = "cmpxchg eax, eax;"


def GetVmpexe(folder):
    folder_name = os.path.basename(folder)
    if "themida" in folder_name:
        vmpexe_suffix = ".vm.exe"
    elif "cv" in folder_name:
        vmpexe_suffix = ".cv.exe"
    elif "eni" in folder_name:
        vmpexe_suffix = ".eni.exe"
    elif "vmp" in folder_name:
        vmpexe_suffix = ".vmp.exe"
    elif "obs" in folder_name:
        vmpexe_suffix = ".obs.exe"
    return vmpexe_suffix


def CompareDict(filedict, losslog_dict, files, vmpexe_suffix):
    global total_lognum
    # get no log files
    for name in losslog_dict:
        if len(losslog_dict[name]) == 3:
            print("no log: %s" %name)

    # compare
    result = []
    for name in filedict:
        if not name in losslog_dict:
            names = [name+("_%d"%(i+1))+vmpexe_suffix for i in range(total_lognum)]
            exist = [True for i in range(total_lognum)]
            flag = True
            for i in range(total_lognum):
                if not names[i] in files:
                    flag = False
                    exist[i] = False
            if not flag:
                for i in range(total_lognum):
                    if not exist[i]:
                        print("no exe: %s" %(names[i]))
            # else:
            #     raise ValueError("filedict larger than losslog_dict")
        else:
            if not filedict[name][0] == total_lognum-len(losslog_dict[name]):
                print("%s   filedict: %d  losslog_dict: %d" %(name, filedict[name][0], len(losslog_dict[name])))
            else:
                result.append(name)
    return result


def GetSourceFile(name):
    return name + ".c"


def GetAsm(name):
    sourcefile = GetSourceFile(name)
    global anchor
    with open(sourcefile) as f:
        tmp = f.read()
        anchor_begin = tmp.find(anchor) + len(anchor)
        anchor_begin += tmp[anchor_begin:].find("\n") + 1
        anchor_end = anchor_begin + tmp[anchor_begin:].find(anchor)
        anchor_end -= anchor_end - anchor_begin - tmp[anchor_begin:anchor_end].rfind("\n")
        ins_begin = anchor_begin + tmp[anchor_begin:anchor_end].find("\"")
        ins_end = ins_begin+1 + tmp[ins_begin+1:anchor_end].find("\"")
        return tmp[ins_begin+1:ins_end-1]


def help():
    print("python repair_anchorfinder.py -a %s -d %s -i %s [-f]")
    print("f for fix_anchorfile which remove 'len != 3' patterns in inputfile")
    exit()


if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:d:a:fh")
    except Exception as err:
        print(err)
        help()

    fix_anchorfile = False
    for opt, arg in opts:
        if opt == '-h':
            help()
        elif opt == '-i':
            inputfile = arg
        elif opt == '-d':
            target_folder = arg
        elif opt == '-a':
            anchor = arg
        elif opt == '-f':
            fix_anchorfile = True

    try:        # check param
        if not os.path.exists(inputfile):
            raise ValueError("inputfile %s invalid" %inputfile)
        if not os.path.exists(target_folder) or not os.path.isdir(target_folder):
            raise ValueError("target folder %s invalid" %target_folder)
    except Exception as err:
        print(err)
        help()

    vmpexe_suffix = GetVmpexe(target_folder)

    filedict = {}
    with open(inputfile) as f:
        lines = f.readlines()

    # find num of lost log
    march_mark = []
    index = 0
    for line in lines:
        tmp = getnum.match(line)
        if tmp:
            march_mark.append(True)
            filepath = tmp.group("file")
            match_num = int(tmp.group("num"))
            filename = ""
            for i in range(len(filepath)-1, -1, -1):
                if filepath[i] == "\\":
                    filename = filepath[i+1:]
                    break
            if not len(filename):
                filename = filepath
            filedict[filename] = (match_num, index)
        else:
            march_mark.append(False)
        index += 1


    # find log file that smaller than threshold in folder
    old_dir = os.getcwd()
    os.chdir(target_folder)
    files = os.listdir()
    cur_dir = os.getcwd()

    losslog_dict = {}
    num = 0
    for myfile in files:
        if myfile.endswith(".log"):
            fsize = os.path.getsize(os.path.join(cur_dir, myfile))
            if fsize < threshold:
                num += 1
                tmp_name = myfile[:-6]
                if tmp_name in losslog_dict:
                    losslog_dict[tmp_name].append(myfile)
                else:
                    losslog_dict[tmp_name] = [myfile]

    # print(num)

    result = CompareDict(filedict, losslog_dict, files, vmpexe_suffix)
    # print("find %d matches, replace now?(Y/N)" %(len(result)))
    # a = input()
    # if a == "Y":
    newlines = copy.deepcopy(lines)
    for name in result:
        index = filedict[name][1]
        asm = GetAsm(name)
        newlines[index] = asm + "\n"
        march_mark[index] = False

    for i in range(len(newlines)):
        if not march_mark[i]:
            print(newlines[i], end='')

    if fix_anchorfile:              # delete all 'len != 3'
        newlines = []
        for i in range(len(lines)):
            if march_mark[i] == False:
                newlines.append(lines[i])

        with open(inputfile, "w") as f:
           f.writelines(newlines)

    os.chdir(old_dir)
