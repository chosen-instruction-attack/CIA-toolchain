import os

result_dir = "D:\\Project\\anti_vmp\\InsGen\\result\\20210412"

index2name = [
    "cvfish",
    "cvtiger",
    "cvtiger_red",
    # "cvtiger_black",
    "obsidium",
    "themida_fish",
    "themida_tiger",
    "themida_tiger_red",
    "themida_tiger_black",
    "vmp2",
    "vmp3"
]

base_testset = [
    "base_ring3_final_testset_cvfish.txt",
    "base_ring3_final_testset_cvtiger.txt",
    "base_ring3_final_testset_cvtiger_red.txt",
    # "base_ring3_final_testset_cvtiger_black.txt",
    "base_ring3_final_testset_obsidium.txt",
    "base_ring3_final_testset_themida_fish.txt",
    "base_ring3_final_testset_themida_tiger.txt",
    "base_ring3_final_testset_themida_tiger_red.txt",
    "base_ring3_final_testset_themida_tiger_black.txt",
    "base_ring3_final_testset_vmp2.txt",
    "base_ring3_final_testset_vmp3.txt"
]

x87_testset = [
    "x87_final_testset_cvfish.txt",
    "x87_final_testset_cvtiger.txt",
    "x87_final_testset_cvtiger_red.txt",
    # "x87_final_testset_cvtiger_black.txt",
    "x87_final_testset_obsidium.txt",
    "x87_final_testset_themida_fish.txt",
    "x87_final_testset_themida_tiger.txt",
    "x87_final_testset_themida_tiger_red.txt",
    "x87_final_testset_themida_tiger_black.txt",
    "x87_final_testset_vmp2.txt",
    "x87_final_testset_vmp3.txt"
]

sse_testset = [
    "sse_final_testset_cvfish.txt",
    "sse_final_testset_cvtiger.txt",
    "sse_final_testset_cvtiger_red.txt",
    # "sse_final_testset_cvtiger_black.txt",
    "sse_final_testset_obsidium.txt",
    "sse_final_testset_themida_fish.txt",
    "sse_final_testset_themida_tiger.txt",
    "sse_final_testset_themida_tiger_red.txt",
    "sse_final_testset_themida_tiger_black.txt",
    "sse_final_testset_vmp2.txt",
    "sse_final_testset_vmp3.txt"
]

base_files = [
    "base_ring3_retanchor_cvfish.txt",
    "base_ring3_retanchor_cvtiger.txt",
    "base_ring3_retanchor_cvtiger_red.txt",
    # "base_ring3_retanchor_cvtiger_black.txt",
    "base_ring3_retanchor_obsidium.txt",
    "base_ring3_retanchor_themida_fish.txt",
    "base_ring3_retanchor_themida_tiger.txt",
    "base_ring3_retanchor_themida_tiger_red.txt",
    "base_ring3_retanchor_themida_tiger_black.txt",
    "base_ring3_retanchor_vmp2.txt",
    "base_ring3_retanchor_vmp3.txt"
]

x87_files = [
    "x87_retanchor_cvfish_repair.txt",
    "x87_retanchor_cvtiger_repair.txt",
    "x87_retanchor_cvtiger_red_repair.txt",
    # "x87_retanchor_cvtiger_black_repair.txt",
    "x87_retanchor_obsidium_repair.txt",
    "x87_retanchor_themida_fish_repair.txt",
    "x87_retanchor_themida_tiger_repair.txt",
    "x87_retanchor_themida_tiger_red_repair.txt",
    "x87_retanchor_themida_tiger_black_repair.txt",
    "x87_retanchor_vmp2_repair.txt",
    "x87_retanchor_vmp3_repair.txt"
]

sse_files = [
    "sse_retanchor_cvfish_repair.txt",
    "sse_retanchor_cvtiger_repair.txt",
    "sse_retanchor_cvtiger_red_repair.txt",
    # "sse_retanchor_cvtiger_black_repair.txt",
    "sse_retanchor_obsidium_repair.txt",
    "sse_retanchor_themida_fish_repair.txt",
    "sse_retanchor_themida_tiger_repair.txt",
    "sse_retanchor_themida_tiger_red_repair.txt",
    "sse_retanchor_themida_tiger_black_repair.txt",
    "sse_retanchor_vmp2_repair.txt",
    "sse_retanchor_vmp3_repair.txt"
]

def PrintTestsetDiff(testset_union, all_testset, print_name):
    print("Testset Total: %d" %len(testset_union))
    for i in range(len(all_testset)):
        tmp = testset_union - all_testset[i]
        tmp_lst = list(tmp)
        tmp_lst.sort()
        print("==== %s_%s ====" %(index2name[i], print_name))
        for ins in tmp_lst:
            print(ins)
        print("==== ====")

def GetAllTestset(target_dir, testset):
    all_set = []

    for file in testset:
        path = os.path.join(target_dir, file)
        with open(path) as f:
            lines = f.readlines()
        ins_tmp = []
        for line in lines:
            if not len(line) == 0:
                ins_tmp.append(line.strip())
        if not len(ins_tmp) == 0:
            all_set.append(set(ins_tmp))
    return all_set


def GetSet(target_dir, files, testset, print_name):
    all_set = []
    lost_ins = {}

    for file in files:
        path = os.path.join(target_dir, file)
        with open(path) as f:
            lines = f.readlines()
        ins_tmp = []
        for line in lines:
            if not len(line) == 0:
                ins_tmp.append(line.strip())
        if not len(ins_tmp) == 0:
            all_set.append(set(ins_tmp))

    all_testset = GetAllTestset(target_dir, testset)
    testset_union = None
    for i in all_testset:
        if testset_union:
            testset_union = testset_union | i
        else:
            testset_union = i

    ins_set = None
    for i in range(len(all_set)):
        tmp = testset_union - all_testset[i]
        tmp = tmp | all_set[i]
        if ins_set:
            ins_set = ins_set & tmp
        else:
            ins_set = tmp

    PrintTestsetDiff(testset_union, all_testset, print_name)
    return ins_set

def PrintSet(myset):
    mylst = list(myset)
    mylst.sort()

    print("==========")
    for i in mylst:
        print(i)
    print("==========")


if __name__ == "__main__":
    base_insset = GetSet(result_dir, base_files, base_testset, "base")
    x87_insset = GetSet(result_dir, x87_files, x87_testset, "x87")
    sse_insset = GetSet(result_dir, sse_files, sse_testset, "sse")

    PrintSet(base_insset)
    PrintSet(x87_insset)
    PrintSet(sse_insset)
