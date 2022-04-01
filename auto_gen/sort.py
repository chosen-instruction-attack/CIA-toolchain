import sys
import getopt


def help():
    print("python sort.py -i inputfile [-o outputfile | -p]")
    print("-p print only")


inputfile = ""
outputfile = ""
print_only = False
opts, args = getopt.getopt(sys.argv[1:], "i:o:ph")
for o, a in opts:
    if o in "-i":
        inputfile = a
    elif o in "-o":
        outputfile = a
    elif o in "-p":
        print_only = True
    elif o in "-h":
        help()

if inputfile == "":
    print("Please Specify Input File")
    exit()
else:
    if not print_only:
        if outputfile == "":
            outputfile = inputfile
        elif inputfile != outputfile:
            print("Input File Different With Output File, Press c To Continue")
            a = input()
            if a.strip() == "c":
                pass
            else:
                exit()

with open(inputfile) as f:
    lines = f.readlines()

lines.sort()

if not print_only:
    with open(outputfile, "w") as f:
        f.writelines(lines)
else:
    for line in lines:
        print(line.strip())