import sys
import os
import json
import getopt

default_anchor = "\"cmpxchg eax, eax\""

cmd4gen = [
    "python insset_test.py -i %s -o %s -t %s -m %s"
]

cmd4make = [
    "mkdir err_log",
    "make exe -j8 -k 1>nul 2>err_log/gcc_err.log",
    "make vmp1 -j8 -k 1>nul 2>err_log/vmp1_err.log",
    "make vmp2 -j8 -k 1>nul 2>err_log/vmp2_err.log",
    "make vmp3 -j8 -k 1>nul 2>err_log/vmp3_err.log",
]

cmd4pin = [
    "make pin -j8 -k 1>nul 2>err_log/pin_err.log"
]

cmd4makelogcmp = [
    "mkdir err_log",
    "make exe -j8 -k 1>nul 2>err_log/gcc_err.log",
    "make vmp1 -j8 -k 1>nul 2>err_log/vmp1_err.log",
    "make logcmp -j8 -k 1>nul 2>err_log/logcmp_err.log"
]

cmd4cmplog = [
    "make logcmp -j8 -k 1>nul 2>err_log/logcmp_err.log"
]

cmd4anchorpin = [
    "make pin -j8 -k 1>err_log/pin_out.log 2>err_log/pin_err.log"
]

# 注意这里是2>
cmd4test = [
    "python FetchTestSet.py -a %s -d %s -l %s -b %s 2> %s",
    "python AnchorFinder.py -a %s -b %s -d %s -l %s -m 3 > %s",
    "python AnchorFinder.py -a %s -b %s -d %s -l %s -m r > %s",
    "python repair_anchorfinder.py -a %s -d %s -i %s > %s"
]

cmd4testcmplog = [
    "python LogCompare.py -d %s -l %s"
]

def GetOuputDir(cfg):
    testset_name = cfg["testset"]
    filename = os.path.basename(testset_name)
    if not filename.endswith(".txt"):
        raise ValueError("Testset file must end with txt")
    output_dir = filename[:-4]
    output_dir += "_"
    output_dir += cfg["vmp"]
    output_dir = os.path.join(cfg["output_dir"], output_dir)
    return output_dir

def GetTestSetName(cfg):
    testset_name = cfg["testset"]
    filename = os.path.basename(testset_name)
    if not filename.endswith(".txt"):
        raise ValueError("Testset file must end with txt")
    logname = filename[:-4]
    if logname.endswith("output"):
        logname = logname[:-7]
    return logname

def GetTestsetLogFile(cfg, overwrite=False):     # 格式类似 base_ring3_themida_tiger_testset.log
                                # 注意要单独处理下_output（这告诉我们一开始的命名规则应该搞个人性化点的）
    logname = GetTestSetName(cfg)
    logname += "_"
    logname += cfg["vmp"]
    logname += "_testset.log"
    logname = os.path.join(cfg["testset_log_dir"], logname)
    if not overwrite:
        if os.path.exists(logname):
            raise ValueError("File %s exist" %logname)
    return logname

def GetTestsetOutputFile(cfg, overwrite=False):      # 格式类似 base_ring3_final_testset_themida_tiger.txt
    logname = GetTestSetName(cfg)
    logname += "_final_testset_"
    logname += cfg["vmp"]
    logname += ".txt"
    logname = os.path.join(cfg["testset_out_dir"], logname)
    if not overwrite:
        if os.path.exists(logname):
            raise ValueError("File %s exist" %logname)
    return logname

def Get3AnchorLogFile(cfg, overwrite=False):         # 格式类似 base_ring3_output_3anchor_themida_tiger.log
    testset_name = cfg["testset"]
    filename = os.path.basename(testset_name)
    if not filename.endswith(".txt"):
        raise ValueError("Testset file must end with txt")
    logname = filename[:-4]
    logname += "_3anchor_"
    logname += cfg["vmp"]
    logname += ".log"
    logname = os.path.join(cfg["anchor_log"], logname)
    if not overwrite:
        if os.path.exists(logname):
            raise ValueError("File %s exist" %logname)
    return logname

def GetRetanchorLogFile(cfg, overwrite=False):         # 格式类似 base_ring3_output_retanchor_themida_tiger.log
    testset_name = cfg["testset"]
    filename = os.path.basename(testset_name)
    if not filename.endswith(".txt"):
        raise ValueError("Testset file must end with txt")
    logname = filename[:-4]
    logname += "_retanchor_"
    logname += cfg["vmp"]
    logname += ".log"
    logname = os.path.join(cfg["anchor_log"], logname)
    if not overwrite:
        if os.path.exists(logname):
            raise ValueError("File %s exist" %logname)
    return logname

def Get3AnchorOutputFile(cfg, overwrite=False):         # 格式类似 base_ring3_output_3anchor_themida_tiger.log
    logname = GetTestSetName(cfg)
    logname += "_3anchor_"
    logname += cfg["vmp"]
    logname += ".txt"
    logname = os.path.join(cfg["anchor_out"], logname)
    if not overwrite:
        if os.path.exists(logname):
            raise ValueError("File %s exist" %logname)
    return logname

def GetRetanchorOutputFile(cfg, overwrite=False):         # 格式类似 base_ring3_output_retanchor_themida_tiger.log
    logname = GetTestSetName(cfg)
    logname += "_retanchor_"
    logname += cfg["vmp"]
    logname += ".txt"
    logname = os.path.join(cfg["anchor_out"], logname)
    if not overwrite:
        if os.path.exists(logname):
            raise ValueError("File %s exist" %logname)
    return logname

def GetRepairOuputfile(anchor_outputfile, overwrite=False):
    repair_outputfile = anchor_outputfile.replace(".txt", "_repair.txt")
    if not overwrite:
        if os.path.exists(repair_outputfile):
            raise ValueError("File %s exist" %repair_outputfile)
    return repair_outputfile

def GetLogcmpFile(cfg, overwrite=False):
    logname = GetTestSetName(cfg)
    logname += "_"
    logname += cfg["vmp"]
    logname += ".txt"
    logname = os.path.join(cfg["logcmp_log"], logname)
    if not overwrite:
        if os.path.exists(logname):
            raise ValueError("File %s exist" %logname)
    return logname

def GenCleanCmd(cfg):
    testset_log = GetTestsetLogFile(cfg, True)
    testset_file = GetTestsetOutputFile(cfg, True)
    anchor3_logfile = Get3AnchorLogFile(cfg, True)
    anchor3_outputfile = Get3AnchorOutputFile(cfg, True)
    anchorret_logfile = GetRetanchorLogFile(cfg, True)
    anchorret_outputfile = GetRetanchorOutputFile(cfg, True)
    logfile = GetLogcmpFile(cfg, True)

    del_lst = [testset_log, testset_file, anchor3_logfile, anchor3_outputfile, anchorret_logfile, anchorret_outputfile, logfile]
    cmd_lst = []

    for myfile in del_lst:
        cmd = "del %s" %myfile
        cmd_lst.append(cmd)
    return cmd_lst

def GenTstProgramCmd(cfg):
    output_dir = GetOuputDir(cfg)
    cmd = "python insset_test.py -i %s -o %s -t %s -m %s" %(cfg["testset"], output_dir, cfg["c_template"], cfg["makefile_template"])
    return [cmd]

def GenTestCmd(cfg, debug=False):
    output_dir = GetOuputDir(cfg)
    testset_log = GetTestsetLogFile(cfg, debug)
    testset_file = GetTestsetOutputFile(cfg, debug)
    anchor = cfg["anchor"]

    get_testset = "python FetchTestSet.py -a %s -d %s -l %s 2> %s" %(anchor, output_dir, testset_log, testset_file)

    sort1 = "python sort.py -i %s" %testset_file

    anchor_logfile = Get3AnchorLogFile(cfg, debug)
    anchor_outputfile = Get3AnchorOutputFile(cfg, debug)
    get_3anchor = "python AnchorFinder.py -a %s -d %s -l %s -m 3 > %s" %(anchor, output_dir, anchor_logfile, anchor_outputfile)

    repair_outputfile = GetRepairOuputfile(anchor_outputfile, debug)
    repair_3anchor = "python repair_anchorfinder.py -a %s -d %s -i %s > %s" %(anchor, output_dir, anchor_outputfile, repair_outputfile)

    sort2 = "python sort.py -i %s" %anchor_outputfile
    sort3 = "python sort.py -i %s" %repair_outputfile

    anchor_logfile = GetRetanchorLogFile(cfg, debug)
    anchor_outputfile = GetRetanchorOutputFile(cfg, debug)
    get_retanchor = "python AnchorFinder.py -a %s -d %s -l %s -m r > %s" %(anchor, output_dir, anchor_logfile, anchor_outputfile)

    repair_outputfile = GetRepairOuputfile(anchor_outputfile, debug)
    repair_retanchor = "python repair_anchorfinder.py -a %s -d %s -i %s > %s" %(anchor, output_dir, anchor_outputfile, repair_outputfile)

    sort4 = "python sort.py -i %s" %anchor_outputfile
    sort5 = "python sort.py -i %s" %repair_outputfile

    cmd_lst = [get_testset, get_3anchor, repair_3anchor, get_retanchor, repair_retanchor, sort1, sort2, sort3, sort4, sort5]
    # cmd_lst = [repair_3anchor, repair_retanchor, sort3, sort5]    # repair only
    return cmd_lst

def GenLogcmpCmd(cfg, debug=False):
    output_dir = GetOuputDir(cfg)
    logfile = GetLogcmpFile(cfg, debug)
    if "logcmp_src" in cfg:
        logcmp_src = cfg["logcmp_src"]
        if not os.path.isdir(logcmp_src):
            raise ValueError("logcmp_src %s not invalid" %logcmp_src)
        cmd = "python LogCompare.py -s %s -d %s -l %s" %(logcmp_src, output_dir, logfile)
    else:
        cmd = "python LogCompare.py -d %s -l %s" %(output_dir, logfile)

    cmd_lst = [cmd]
    return cmd_lst


# def ExecCmd(cmd_lst, test_only=True):
def ExecCmd(cmd_lst, test_only=False):
    for cmd in cmd_lst:
        try:
            print(cmd)      # test
            if not test_only:
                os.system(cmd)
        except KeyboardInterrupt:
            print("Executing %s" %cmd)
            print("Interrupt...")
            exit()
        except Exception as err:
            print("Executing %s" %cmd)
            print(err)
            exit()


def help():
    print("python caller.py -c configfile")
    exit()


if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "c:dh")
    except:
        help()

    debug = False
    for opt, arg in opts:
        if opt == '-h':
            help()
        if opt == '-d':
            debug = True
        elif opt == '-c':
            configfile = arg

    try:        # check param
        if not os.path.exists(configfile):
            raise ValueError("config file %s invalid" %configfile)
    except Exception as err:
        print(err)
        help()

    with open(configfile) as f:
        all_config = json.load(f)

    # vmp cannot be the same
    config_dict = {}
    for config in all_config:
        testset = os.path.basename(config["testset"])
        vmp = config["vmp"]
        if vmp in config_dict and testset in config_dict[vmp]:
            raise ValueError("Find the same vmp in config, this is not allow because it may overwrite other files")
        else:
            if not vmp in config_dict:
                config_dict[vmp] = []
            config_dict[vmp].append(testset)

    num = 0
    for config in all_config:
        print("====== %s %s ======" %(config["vmp"], GetTestSetName(config)))
        flag = True
        if not "state" in config:
            print("Config %d Has No State" %num)
            flag = False
        elif config["state"] != "enable":
            print("Config %d State disabled" %num)
            flag = False
        elif not "action" in config:
            print("Config %d No Action Specify" %num)
            flag = False

        if flag:
            action = config["action"]

            if not "anchor" in config:
                config["anchor"] = default_anchor

            # clean the output files that current config generated
            if "clean" in action:
                cmd_lst = GenCleanCmd(config)
                ExecCmd(cmd_lst, debug)
            # generate test program
            if "gen" in action:
                cmd_lst = GenTstProgramCmd(config)
                ExecCmd(cmd_lst, debug)
            if "make" in action:
                old_path = os.getcwd()
                output_dir = GetOuputDir(config)
                if not debug:
                    os.chdir(output_dir)
                ExecCmd(cmd4make, debug)
                if not debug:
                    os.chdir(old_path)
            if "pin" in action:
                old_path = os.getcwd()
                output_dir = GetOuputDir(config)
                if not debug:
                    os.chdir(output_dir)
                ExecCmd(cmd4pin, debug)
                if not debug:
                    os.chdir(old_path)
            if "anchor_pin" in action:
                old_path = os.getcwd()
                output_dir = GetOuputDir(config)
                if not debug:
                    os.chdir(output_dir)
                ExecCmd(cmd4anchorpin, debug)
                if not debug:
                    os.chdir(old_path)
            if "makelogcmp" in action:
                old_path = os.getcwd()
                output_dir = GetOuputDir(config)
                if not debug:
                    os.chdir(output_dir)
                ExecCmd(cmd4makelogcmp, debug)
                if not debug:
                    os.chdir(old_path)
            if "logcmp" in action:
                old_path = os.getcwd()
                output_dir = GetOuputDir(config)
                if not debug:
                    os.chdir(output_dir)
                ExecCmd(cmd4cmplog, debug)
                if not debug:
                    os.chdir(old_path)
            if "test" in action:
                cmd_lst = GenTestCmd(config, debug)
                ExecCmd(cmd_lst, debug)
            if "makelogcmp_test" in action:
                cmd_lst = GenLogcmpCmd(config, debug)
                ExecCmd(cmd_lst, debug)
            if "logcmp" in action:
                cmd_lst = GenLogcmpCmd(config, debug)
                ExecCmd(cmd_lst, debug)

        print("============\n")
        num += 1
