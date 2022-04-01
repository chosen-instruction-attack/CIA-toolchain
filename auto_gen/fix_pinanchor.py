import re
import sys
import os
import getopt

err_pattern = re.compile(r"make: \*\*\* \[(.*)\]")
cmd_pattern = "pin -t F:\\anti_vmp\\output\\pin_anchorfinder_themida.dll -s %s -i ..\\anchor.txt -- %s 1>>err_log\\pin_out.log 2>>err_log\\pin_err.log"

def help():
    print("python fix_pinanchor.py -i inputfile [-d]")
    print("d for debug")
    exit()

if __name__ == "__main__":
    debug = False

    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:dh")
    except:
        help()

    for opt, arg in opts:
        if opt == '-h':
            help()
        elif opt == '-i':
            inputfile = arg
        elif opt == '-d':
            debug = True

    try:        # check param
        if not os.path.exists(inputfile):
            raise ValueError("inputfile invalid")
    except Exception as err:
        print(err)
        help()

    # inputfile = "F:\\anti_vmp\\AnchorVerify\\x87_output_themida_shark\\err_log\\pin_err.log"

    err_log = os.path.dirname(inputfile)
    dir_path = os.path.dirname(err_log)

    with open(inputfile) as f:
        lines = f.readlines()

    old_path = os.getcwd()
    os.chdir(dir_path)
    if debug:
        print("change directory to %s" %dir_path)

    cmd_lst = []
    for line in lines:
        p = err_pattern.match(line)
        if p:
            logname = p.group(1)
            exename = logname.replace(".log", ".vm.exe")
            cmd = cmd_pattern %(exename, exename)
            cmd_lst.append(cmd)

    for cmd in cmd_lst:
        print(cmd)
        if not debug:
            os.system(cmd)

    os.chdir(old_path)