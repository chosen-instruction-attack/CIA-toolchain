import keystone

def help():
    print("python TestIns.py -i testset.txt")
    exit()


# if __name__ == "__main__":
#     try:
#         opts, args = getopt.getopt(sys.argv[1:], "i:h")
#     except:
#         help()

#     for opt, arg in opts:
#         if opt == '-h':
#             help()
#         elif opt == '-i':
#             testset_file = arg

#     try:        # check param
#         if not os.path.exists(testset_file):
#             raise ValueError("testset file %s invalid" %testset_file)
#     except Exception as err:
#         print(err)
#         help()
testset_file = "D:\\Project\\anti_vmp\\InsGen\\InsTest\\20210412\\base_insdel_output.txt"

ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)

with open(testset_file) as f:
    lines = f.readlines()

for insn_str in lines:
    try:
        encode, count = ks.asm(insn_str)
    except Exception as err:
        print(insn_str, end='')
        print(err)