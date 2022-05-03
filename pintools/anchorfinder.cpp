/*
 * A pin tool to record all instructions in a binary execution.
 *
 */

#include <stdio.h>
#include <pin.H>
#include <map>
#include <iostream>
#include <string>
#include <fstream>

#define __anchorfinder__
// #define __trace__
// #define __readable__

#define THRESHOLD 1 // When taint is True, must record at least THRESHOLD instructions
#define ALLINS_MAX 70000000

using std::ifstream;
using std::string;

const char *anchorfile = "anchor.txt";
const char *default_file = "";

unsigned int appear_time = 0;
bool is_retanchor = false;
bool has_prev = false;
unsigned char prev_ins[20];
const unsigned char ret_hex[] = {0xc3, 0xcb, 0xc2, 0xca};
string line;
char c_file[50];
const char *ins_str = NULL;
char hex_buffer[20];
char *ins_hex = NULL;
int ins_hexlen;
bool reach_end = false;

string anchorstr;
bool taint = false;
ADDRINT finish_addr = 0;
// bool isFinished = false;
unsigned long insn_num = 0;
unsigned long allins_num = 0;
unsigned long log_num = 0;

std::map<ADDRINT, string> opcmap;
FILE *fp = NULL;

using namespace std;

ADDRINT filter_ip_low, filter_ip_high;

KNOB<string> KnobTestProgram(KNOB_MODE_WRITEONCE, "pintool",
                             "s", default_file, "test program name");
KNOB<string> KnobInputFile(KNOB_MODE_WRITEONCE, "pintool",
                           "i", anchorfile, "anchor file");
//KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
//    "o", default_file, "anchor hex");

void CloseFile(FILE *fp)
{
    static bool isclose = false;

    if (fp && !isclose)
    {
        fflush(fp);
        fclose(fp);
        isclose = true;
    }
}

VOID ImageLoad(IMG img, VOID *v)
{
    for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img))
    {
        if (IMG_IsMainExecutable(img))
        {
            filter_ip_low = IMG_LowAddress(img);
            filter_ip_high = IMG_HighAddress(img);
            cerr << "[-] Log range:" << StringFromAddrint(filter_ip_low) << "-" << StringFromAddrint(filter_ip_high) << endl;
        }
    }

    cerr << "[+] Images loads. " << IMG_Name(img) << endl;
    if (IMG_IsMainExecutable(img))
    {
        filter_ip_low = IMG_LowAddress(img);
        filter_ip_high = IMG_HighAddress(img);
        cerr << "[-] Log range:" << StringFromAddrint(filter_ip_low) << "-" << StringFromAddrint(filter_ip_high) << endl;
    }
}

void getctx(ADDRINT addr, ADDRINT inssize, CONTEXT *fromctx, ADDRINT raddr, ADDRINT waddr)
{
    std::map<ADDRINT, string>::iterator iter = opcmap.find(waddr);
    if (iter != opcmap.end())
        opcmap.erase(iter);
    //cout << hex << addr << " : " << opcmap[addr] << endl;
    //fprintf(stdout, "%x: EAX=0x%x, EBX=0x%x, ECX=0x%x, EDX=0x%x, ESI=0x%x, EDI=0x%x, ESP=0x%x, EBP=0x%x, EFLAGS=0x%x, Read=0x%x, Write=0x%x", addr,
    //    PIN_GetContextReg(fromctx, REG_EAX),
    //    PIN_GetContextReg(fromctx, REG_EBX),
    //    PIN_GetContextReg(fromctx, REG_ECX),
    //    PIN_GetContextReg(fromctx, REG_EDX),
    //    PIN_GetContextReg(fromctx, REG_ESI),
    //    PIN_GetContextReg(fromctx, REG_EDI),
    //    PIN_GetContextReg(fromctx, REG_ESP),
    //    PIN_GetContextReg(fromctx, REG_EBP),
    //    PIN_GetContextReg(fromctx, REG_EFLAGS),
    //    raddr, waddr);

    //fprintf(stdout, "%x: ", addr);
    //for (int i = 0; i < inssize; i++)
    //    fprintf(stdout, "%02x", *((char*)addr + i) & 0xff);
    //fprintf(stdout, "; %s\n", opcmap[addr].c_str());

    int cmp_len = inssize < ins_hexlen ? inssize : ins_hexlen;
    if (memcmp((void *)addr, ins_hex, cmp_len) == 0) // current ins is the ins we tested
    {
        appear_time += 1;
        // printf("appear %d: has_prev: %d\n", appear_time, has_prev);
        if (has_prev)
        {
            bool flag = false;

            for (int i = 0; i < sizeof(ret_hex) / sizeof(char); i++)
            {
                if (prev_ins[0] == ret_hex[i])
                {
                    flag = true;
                    break;
                }
            }
            if (flag)
                is_retanchor = true;
        }
    }

    memcpy(prev_ins, (void *)addr, inssize);
    has_prev = true;

    log_num++;

    if (finish_addr == addr)
    {
        reach_end = true;
        std::cout << KnobTestProgram.Value().c_str() << ":" << ins_str << ";" << is_retanchor << ";" << appear_time << ";" << dec << log_num << endl;
        PIN_ExitApplication(0);
    }
}


static void instruction(INS ins, void *v)
{
    static bool first = false;
    string a;

    int flag = taint;
    ADDRINT addr = INS_Address(ins);

    if (addr <= 0x10000000)
    {
        bool isAnchor = false;

        allins_num++;
        if (allins_num > ALLINS_MAX)
        {
            std::cout << "Reach ALLINS_MAX" << std::endl;
            std::cout << KnobTestProgram.Value().c_str() << ":" << ins_str << ";" << is_retanchor << ";" << appear_time << ";" << log_num << endl;
            PIN_ExitApplication(0);
        }

        if (opcmap.find(addr) == opcmap.end())
        {
            opcmap.insert(std::pair<ADDRINT, string>(addr, INS_Disassemble(ins)));
        }

        // cout << taint << " " << hex << addr << dec << " : " << opcmap[addr] << endl;

        if (anchorstr.compare(opcmap[addr].c_str()) == 0)
        {
            // cout << hex << addr << " " << opcmap[addr].c_str() << endl;
            isAnchor = true;
            if (taint && insn_num > THRESHOLD)
                taint = !taint;
            else if (!taint)
                taint = !taint;
        }

        if (taint && !isAnchor)
            insn_num++;

        USIZE inssize = INS_Size(ins);
        if (isAnchor || taint)
        {
            if (INS_IsMemoryRead(ins) && INS_IsMemoryWrite(ins))
            {
                //fprintf(stdout, "  memread memwrite  \n");  // debug
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA, IARG_END);
            }
            else if (INS_IsMemoryRead(ins))
            {
                //fprintf(stdout, "  memread  \n");  // debug
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_ADDRINT, 0, IARG_END);
            }
            else if (INS_IsMemoryWrite(ins))
            {
                //fprintf(stdout, "  memwrite  \n");  // debug
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_MEMORYWRITE_EA, IARG_END);
            }
            else
            {
                //fprintf(stdout, "  others  \n");  // debug
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_ADDRINT, 0, IARG_END);
            }
        }
        if (isAnchor && !taint)
        {
            finish_addr = addr;
            // cout << "finish addr: " << hex << addr << endl;
            // cout << opcmap[addr] << endl;
        }
    }
}

static void instruction_from_main(INS ins, void *argv)
{
    static int flag = false;
    ADDRINT addr = INS_Address(ins);

    ADDRINT *pargv = (ADDRINT *)argv;

    if (addr <= 0x10000000)
    {
        if (addr == pargv[0])
            flag = true;

        if (flag)
        {
            if (opcmap.find(addr) == opcmap.end())
            {
                opcmap.insert(std::pair<ADDRINT, string>(addr, INS_Disassemble(ins)));
            }

            if (INS_IsMemoryRead(ins) && INS_IsMemoryWrite(ins))
            {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA, IARG_END);
            }
            else if (INS_IsMemoryRead(ins))
            {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_ADDRINT, 0, IARG_END);
            }
            else if (INS_IsMemoryWrite(ins))
            {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_MEMORYWRITE_EA, IARG_END);
            }
            else
            {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_ADDRINT, 0, IARG_END);
            }
        }
        if (addr == pargv[1] && flag == true)
        {
            flag = false;
            finish_addr = addr;
        }
    }
}

int Hex2Int(char s)
{
    if (s >= '0' && s <= '9')
        return s - '0';
    else if (s >= 'a' && s <= 'f')
        return s - 'a' + 10;
    else if (s >= 'A' && s <= 'F')
        return s - 'A' + 10;
    else
        return -1;
}

char *Hex2Buf(const char *hex_str, int length, int *buflen) // buflen is a return value
{
    int len;

    if (length > 0)
        len = length;
    else
        len = strlen(hex_str);

    *buflen = len / 2;
    char *buf = hex_buffer;

    for (int i = 0; i < len / 2; i++)
    {
        int num = Hex2Int(hex_str[i * 2]);
        int tmp = Hex2Int(hex_str[i * 2 + 1]);
        if (num == -1 || tmp == -1)
        {
            buf = NULL;
            break;
        }
        num = num << 4;
        num += tmp;
        buf[i] = num;
    }
    return buf;
}

int ParseLine(string &line) // global var ins_hex and ins_str is changed here
{
    int i = 0, j;
    const char *buf = line.c_str();

    if (line.find("//") == line.npos)
    {
        cout << KnobTestProgram.Value().c_str() << " header not found" << endl;
        exit(-1);
    }
    for (i; i < line.size(); i++)
    {
        if (line[i] == ' ')
        {
            break;
        }
    }
    i++;

    for (j = i; j < line.size(); j++)
    {
        if (line[j] == ' ')
        {
            break;
        }
    }
    ins_hex = Hex2Buf(&buf[i], j - i, &ins_hexlen);
    if (ins_hex == NULL)
        return -1;
    else
    {
        j++;
        ins_str = &buf[j];
        return 0;
    }
}

static void on_fini(INT32 code, void *v)
{
    CloseFile(fp);
    // cout << "exit normally" << endl;
}

static void Onsig(THREADID threadIndex,
                  CONTEXT_CHANGE_REASON reason,
                  const CONTEXT *ctxtFrom,
                  CONTEXT *ctxtTo,
                  INT32 sig,
                  VOID *v)
{
    if (!reach_end && log_num > 0)
    {
        std::cout << "exception" << std::endl;
        std::cout << KnobTestProgram.Value().c_str() << ":" << ins_str << ";" << is_retanchor << ";" << appear_time << ";" << log_num << endl;
        fflush(stdout);
    }
    //PIN_ExitApplication(-1);
}

static void OnsigDebug(THREADID threadIndex,
                       CONTEXT_CHANGE_REASON reason,
                       const CONTEXT *ctxtFrom,
                       CONTEXT *ctxtTo,
                       INT32 sig,
                       VOID *v)
{
    // has bug here ?
    //ADDRINT address = PIN_GetContextReg(ctxtFrom, REG_INST_PTR);
    //cout << "SIG signal=" << sig << " on thread " << threadIndex
    //    << " at address " << hex << address << dec << " ";

    switch (reason)
    {
    case CONTEXT_CHANGE_REASON_FATALSIGNAL:
        cout << "FATALSIG" << sig;
        break;
    case CONTEXT_CHANGE_REASON_SIGNAL:
        cout << "SIGNAL " << sig;
        break;
    case CONTEXT_CHANGE_REASON_SIGRETURN:
        cout << "SIGRET";
        break;

    case CONTEXT_CHANGE_REASON_APC:
        cout << "APC";
        break;

    case CONTEXT_CHANGE_REASON_EXCEPTION:
        cout << "EXCEPTION";
        break;

    case CONTEXT_CHANGE_REASON_CALLBACK:
        cout << "CALLBACK";
        break;

    default:
        break;
    }
    cout << std::endl;
    fflush(stdout);
    if (!reach_end && log_num > 0)
    {
        std::cout << "exception" << std::endl;
        std::cout << KnobTestProgram.Value().c_str() << ":" << ins_str << ";" << is_retanchor << ";" << appear_time << ";" << log_num << endl;
    }
    // PIN_ExitApplication(-1);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    PIN_ERROR("This tool prints a log of image load and unload events\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv))
        return Usage();

    ifstream file(KnobInputFile.Value().c_str(), ifstream::in);
    if (file.good())
    {
        getline(file, anchorstr);
    }
    file.close();
    file.clear();

    // get C file name
    int i;
    const char *buf = KnobTestProgram.Value().c_str();
    for (i = KnobTestProgram.Value().size() - 1; i >= 0; i--)
    {
        if (buf[i] == '_')
            break;
    }

    memcpy(c_file, buf, i);
    c_file[i] = '.';
    c_file[i + 1] = 'c';
    c_file[i + 2] = '\0';

    // cout << c_file << endl;
    file.open(c_file);
    if (file.good())
    {
        getline(file, line);
    }
    file.close();
    file.clear();

    int ret = ParseLine(line);
    if (ret == -1)
    {
        cout << "ParseLine error" << endl;
        exit(-1);
    }

    // for debug
    //printf("%d\n", ins_hexlen);
    //for (int i = 0; i < ins_hexlen; i++)
    //    printf("%02x ", ins_hex[i] & 0xff);
    //printf("\n");

    PIN_InitSymbols();
    PIN_AddContextChangeFunction(Onsig, 0);
    PIN_AddFiniFunction(on_fini, 0);
    /* IMG_AddInstrumentFunction(ImageLoad, 0); */
    INS_AddInstrumentFunction(instruction, 0);
    PIN_StartProgram(); // Never returns

    CloseFile(fp);
    return 0;
}
