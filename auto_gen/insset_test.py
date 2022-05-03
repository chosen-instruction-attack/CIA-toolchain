import os
from re import A
import keystone
import logging
import sys
import json

from InsHexLst import *
from suffix import *

except_ins = [ "nop  cx, dx", "ud0", "ud2b" ]
ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)

anchor = 'cmpxchg eax, eax'
log_path = ""
logger = None


class Logger:
    stream_loglevel = (logging.INFO,)
    file_loglevel = (logging.INFO, logging.WARNING, logging.ERROR)

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


class GenTestFile:
    def __init__(self, filepath, anchor_ins, output_dir, makefile_template, c_template=None):
        with open(filepath) as f:
            self.ins_lst = f.readlines()
        self.tstfile = TstFile(anchor_ins, output_dir, c_template)
        self.output_dir = output_dir
        self.makefile_template = makefile_template

        if anchor_ins[-1] == ';':
            anchor_ins = anchor_ins[:-1]
        self.anchor_ins = anchor_ins

    def WriteFiles(self, clear=True):
        if clear:
            if os.path.exists(self.output_dir):
                for onefile in os.listdir(self.output_dir):
                    file_path = os.path.join(self.output_dir, onefile)
                    if not os.path.isdir(file_path):
                        os.remove(file_path)
            else:
                os.mkdir(self.output_dir)
        with open(os.path.join(self.output_dir, "makefile"), "w") as f:
            f.writelines(self.makefile_template)

        with open(os.path.join(self.output_dir, "anchor.txt"), "w") as f:
            f.write(self.anchor_ins)

        ins_file_map = []
        for insn in self.ins_lst:
            insn_str = insn.strip()
            filename = self.tstfile.WriteGenTstFile(insn_str)
            ins_file_map.append((filename, insn_str))
        return ins_file_map


class TstFile:
    replace_text = "%REPLACE%"
    anchor_text = "%ANCHOR%"
    def __init__(self, anchor_ins, output_dir, c_template=None):
        if not c_template:
            with open("template.c") as f:
                self.temp = f.read()
        else:
            if isinstance(c_template, list):
                tmp = ""
                for i in c_template:
                    tmp += i
                self.temp = tmp
            elif isinstance(c_template, str):
                with open(c_template) as f:
                    self.temp = f.read()
            else:
                raise TypeError()
        self.output_dir = output_dir
        self.anchor_ins = anchor_ins
        self.filename = []

    def WriteGenTstFile(self, insn_str):
        insn_split = insn_str.split()
        mnemonic = insn_split[0]
        tmp = self.temp.replace(self.replace_text, insn_str)
        tmp = tmp.replace(self.anchor_text, self.anchor_ins)
        if not insn_str in except_ins:
            if insn_str in ins_hex_lst:
                encode = ins_hex_lst[insn_str]
            else:
                try:
                    encode, count = ks.asm(insn_str)
                except Exception as err:
                    print(insn_str)
                    print(err)
                    exit()
            encode_hex = ""
            for i in encode:
                encode_hex += "%02x" %i
            line1 = "// " + encode_hex + " " + insn_str + "\n"
            tmp = line1 + tmp
        filename = mnemonic + "0" + suffix
        filepath = os.path.join(self.output_dir, filename)
        length = len(mnemonic)

        while os.path.exists(filepath):
            num = int(filename[length:suffix_index])
            filename = "%s%d%s" %(mnemonic, num+1, suffix)
            filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w") as f:
            f.write(tmp)
            self.filename.append(filename)
        return filename

def MakefileTemplateReplace(template, config):
    patterns = []
    options = []
    for key in config:
        if not (key in ["name", "makefile_template", "customize"]):
            patterns.append("# " + key)
            options.append( (1, key) )
        elif key == "customize":
            for option in config[key]:
                patterns.append("# " + key)
                options.append( (2, key) )
    new_lines = []
    for line in template:
        for i in range(len(patterns)):
            pattern = patterns[i]
            flag = False
            if line.find(pattern, 0, len(pattern)) != -1:
                option = options[i]
                flag = True
                if option[0] == 1:
                    key = option[1]
                    new_line = key + " = " + config[key] + "\n"
                else:
                    new_line = key + " = " + config["customize"][key] + "\n"
                break
        if not flag:
            new_line = line
        new_lines.append(new_line)
    return new_lines

def GetMakeTemplate(makefile_template_path, config):
    try:
        with open(makefile_template_path) as f:
            makefile_template = f.readlines()
    except:
        raise ValueError("Makefile template path %s invaild" %os.path.abspath(makefile_template_path))
    makefile_template_name = os.path.basename(makefile_template_path)
    new_makefile_template = MakefileTemplateReplace(makefile_template, config)
    return new_makefile_template

def help():
    print("python insset_test.py -i testset -o output_dir -t c_template -n makefile_template_config_name -p makefile_template_config_path [-a anchor] [-l log_path]")
    exit()


import sys
import getopt

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:o:t:n:p:a:l:h")
    except:
        help()

    for opt, arg in opts:
        if opt == '-h':
            help()
        elif opt == '-i':
            test_ins = arg
        elif opt == '-o':
            output_dir = arg
        elif opt == '-t':
            c_template = arg
        elif opt == '-n':
            makefile_template_config_name = arg
        elif opt == '-p':
            makefile_template_config_path = arg
        elif opt == '-a':
            anchor = arg
        elif opt == '-l':
            log_path = arg

    try:        # check param
        if not os.path.exists(test_ins):
            raise ValueError("Testset file invalid: %s" %os.path.abspath(test_ins))
        if not os.path.exists(os.path.dirname(output_dir)):
            raise ValueError("Parent dir of output_dir not exists: %s" %os.path.abspath(output_dir))
        if not os.path.exists(c_template):
            raise ValueError("Template file invalid: %s" %os.path.abspath(c_template))
        if not os.path.exists(makefile_template_config_path):
            raise ValueError("Makefile template config invalid: %s" %os.path.abspath(makefile_template_config_path))
        if log_path != "":
            if not os.path.exists(os.path.dirname(log_path)):
                raise ValueError("Parent dir of log_path not exists: %s" %os.path.abspath(os.path.dirname(log_path)))
    except Exception as err:
        print(err)
        help()

    index = anchor.rfind(";")
    if index != -1:
        anchor = anchor[:index]

    try:
        ks.asm(anchor)
    except Exception as err:
        print("anchor instruction is unavailable")
        print(err)
        exit()

    anchor_ins = anchor + ";"           # must add an semicolon for assembler syntax

    logger = Logger(log_path)           # logger is defined as a global variable, so we don't need to pass it as a parameter


    with open(makefile_template_config_path) as f:
        makefile_configs = json.load(f)
    makefile_config = None
    for config in makefile_configs:
        if config["name"] == makefile_template_config_name:
            makefile_config = config
            break
    if makefile_config:
        makefile_template_path = makefile_config["makefile_template"]
        makefile_template = GetMakeTemplate(makefile_template_path, makefile_config)
    else:
        raise ValueError("Cannot find makefile config [%s] in makefile config file" %makefile_template_config_name)

    gentstfile = GenTestFile(test_ins, anchor_ins, output_dir, makefile_template, c_template)
    file_ins_map = gentstfile.WriteFiles()

    logger.info("File:\t\t\tIns:")
    logger.info("="*32)
    for i in file_ins_map:
        tab_num = 3 - len(i[0]) // 8
        fmt_str = "%s:" + "\t"*tab_num + "%s"
        logger.info(fmt_str %(i[0], i[1]))
