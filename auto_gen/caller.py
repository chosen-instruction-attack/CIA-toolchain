import sys
import os
import json
import getopt

default_anchor = "\"cmpxchg eax, eax\""
python_cmd = "python3 "

gen_program_cmd = python_cmd + "insset_test.py -i %s -o %s -t %s -n %s -p %s"
gen_testset_cmd = python_cmd + "FetchTestSet.py -a %s -d %s -l %s 2> %s"
sort_cmd = python_cmd + "sort.py -i %s"
gen_3anchor_cmd = python_cmd + "AnchorFinder.py -a %s -d %s -l %s -m 3 > %s"
gen_retanchor_cmd = python_cmd + "AnchorFinder.py -a %s -d %s -l %s -m r > %s"


cmd4gen = [
    gen_program_cmd
]

cmd4make = [
    "mkdir err_log",
    "make build -j"
]

# cmd4make = [
#     "mkdir err_log",
#     "make exe -j8 -k 1>nul 2>err_log/gcc_err.log",
#     "make vmp1 -j8 -k 1>nul 2>err_log/vmp1_err.log",
#     "make vmp2 -j8 -k 1>nul 2>err_log/vmp2_err.log",
#     "make vmp3 -j8 -k 1>nul 2>err_log/vmp3_err.log",
# ]

cmd4pin = [
    "make pin -j -k 1>nul 2>err_log/pin_err.log"
]

cmd4anchorpin = [
    "make anchor_pin -j -k 1>err_log/pin_out.log 2>err_log/pin_err.log"
]

# 注意这里是2>
cmd4test = [
    gen_testset_cmd,
    gen_3anchor_cmd,
    gen_retanchor_cmd
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

def GenCleanCmd(cfg):
    testset_log = GetTestsetLogFile(cfg, True)
    testset_file = GetTestsetOutputFile(cfg, True)
    anchor3_logfile = Get3AnchorLogFile(cfg, True)
    anchor3_outputfile = Get3AnchorOutputFile(cfg, True)
    anchorret_logfile = GetRetanchorLogFile(cfg, True)
    anchorret_outputfile = GetRetanchorOutputFile(cfg, True)

    del_lst = [testset_log, testset_file, anchor3_logfile, anchor3_outputfile, anchorret_logfile, anchorret_outputfile]
    cmd_lst = []

    for myfile in del_lst:
        if os.path.exists(myfile):
            cmd = "del %s" %myfile
            cmd_lst.append(cmd)
    return cmd_lst

def GenTstProgramCmd(cfg):
    output_dir = GetOuputDir(cfg)
    cmd = gen_program_cmd %(cfg["testset"], output_dir, cfg["c_template"], cfg["vmp"], cfg["makefile_template_config"])
    return [cmd]

def GenTestCmd(cfg, debug=False):
    output_dir = GetOuputDir(cfg)
    testset_log = GetTestsetLogFile(cfg, debug)
    testset_file = GetTestsetOutputFile(cfg, debug)
    anchor = cfg["anchor"]

    get_testset = gen_testset_cmd %(anchor, output_dir, testset_log, testset_file)

    sort1 = sort_cmd %testset_file

    anchor_logfile = Get3AnchorLogFile(cfg, debug)
    anchor_outputfile = Get3AnchorOutputFile(cfg, debug)
    get_3anchor = gen_3anchor_cmd %(anchor, output_dir, anchor_logfile, anchor_outputfile)

    sort2 = sort_cmd %anchor_outputfile

    anchor_logfile = GetRetanchorLogFile(cfg, debug)
    anchor_outputfile = GetRetanchorOutputFile(cfg, debug)
    get_retanchor = gen_retanchor_cmd %(anchor, output_dir, anchor_logfile, anchor_outputfile)


    sort3 = sort_cmd %anchor_outputfile

    cmd_lst = [get_testset, get_3anchor, get_retanchor, sort1, sort2, sort3]
    # cmd_lst = [repair_3anchor, repair_retanchor, sort3, sort5]    # repair only
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
            if "test" in action:
                cmd_lst = GenTestCmd(config, debug)
                ExecCmd(cmd_lst, debug)

        print("============\n")
        num += 1
