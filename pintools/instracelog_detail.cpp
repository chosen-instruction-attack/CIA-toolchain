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

#define THRESHOLD 10 // When taint is True, must record at least THRESHOLD instructions

using std::ifstream;
using std::string;

const char *tracefile = "instrace.txt";
const char *anchorfile = "anchor.txt";
string anchorstr;
bool taint = false;
ADDRINT finish_addr = 0;
// bool isFinished = false;
unsigned long insn_num = 0;

std::map<ADDRINT, string> opcmap;
FILE *fp;

using namespace std;

ADDRINT filter_ip_low, filter_ip_high;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
                            "o", tracefile, "trace file");
KNOB<string> KnobInputFile(KNOB_MODE_WRITEONCE, "pintool",
                           "i", anchorfile, "anchor file");

void CloseFile(FILE *fp)
{
    static bool isclose = false;

    if (!isclose)
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

#if defined(__readable__)
// for readable
void getctx(ADDRINT addr, CONTEXT *fromctx, ADDRINT raddr, ADDRINT waddr)
{
    fprintf(fp, "%x: %s ;EAX=0x%x, EBX=0x%x, ECX=0x%x, EDX=0x%x, ESI=0x%x, EDI=0x%x, ESP=0x%x, EBP=0x%x, EFLAGS=0x%x, Read=0x%x, Write=0x%x\n", addr, opcmap[addr].c_str(),
            PIN_GetContextReg(fromctx, REG_EAX),
            PIN_GetContextReg(fromctx, REG_EBX),
            PIN_GetContextReg(fromctx, REG_ECX),
            PIN_GetContextReg(fromctx, REG_EDX),
            PIN_GetContextReg(fromctx, REG_ESI),
            PIN_GetContextReg(fromctx, REG_EDI),
            PIN_GetContextReg(fromctx, REG_ESP),
            PIN_GetContextReg(fromctx, REG_EBP),
            PIN_GetContextReg(fromctx, REG_EFLAGS),
            raddr, waddr);
    if (isFinished)
    {
        fflush(fp);
        PIN_ExitApplication(0);
    }
}

#elif defined(__script__)
// for script
void getctx(ADDRINT addr, ADDRINT inssize, CONTEXT *fromctx, ADDRINT raddr, ADDRINT waddr)
{

    fprintf(fp, "0x%x; %u; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x\n", addr, inssize,
            PIN_GetContextReg(fromctx, REG_EAX),
            PIN_GetContextReg(fromctx, REG_EBX),
            PIN_GetContextReg(fromctx, REG_ECX),
            PIN_GetContextReg(fromctx, REG_EDX),
            PIN_GetContextReg(fromctx, REG_ESI),
            PIN_GetContextReg(fromctx, REG_EDI),
            PIN_GetContextReg(fromctx, REG_ESP),
            PIN_GetContextReg(fromctx, REG_EBP),
            PIN_GetContextReg(fromctx, REG_EFLAGS),
            raddr, waddr);

    if (isFinished)
    {
        fflush(fp);
        PIN_ExitApplication(0);
    }
}
#elif defined(__simple__)
void getctx(ADDRINT addr, CONTEXT *fromctx)
{
    fprintf(fp, "0x%x: %s\n", addr, opcmap[addr].c_str());
}

#elif defined(__anchorfinder__)
void getctx(ADDRINT addr, ADDRINT inssize, CONTEXT *fromctx, ADDRINT raddr, ADDRINT waddr)
{
    fprintf(fp, "0x%x; %u; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; ", addr, inssize,
            PIN_GetContextReg(fromctx, REG_EAX),
            PIN_GetContextReg(fromctx, REG_EBX),
            PIN_GetContextReg(fromctx, REG_ECX),
            PIN_GetContextReg(fromctx, REG_EDX),
            PIN_GetContextReg(fromctx, REG_ESI),
            PIN_GetContextReg(fromctx, REG_EDI),
            PIN_GetContextReg(fromctx, REG_ESP),
            PIN_GetContextReg(fromctx, REG_EBP),
            PIN_GetContextReg(fromctx, REG_EFLAGS),
            raddr, waddr);

    // for self-modify code
    std::map<ADDRINT, string>::iterator iter = opcmap.find(waddr);
    if (iter != opcmap.end())
        opcmap.erase(iter);
    // ===

    for (int i = 0; i < inssize; i++)
        fprintf(fp, "%02x", *((char *)addr + i) & 0xff);
    fprintf(fp, "; %s\n", opcmap[addr].c_str());
    if (finish_addr == addr)
    {
        fflush(fp);
        PIN_ExitApplication(0);
    }
}
#elif defined(__trace__)
#pragma message("MACRO  getctx: __trace__")
void getctx(ADDRINT addr, ADDRINT inssize, CONTEXT *fromctx, ADDRINT raddr, ADDRINT waddr)
{

    fprintf(fp, "0x%x; %u; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; ", addr, inssize,
            PIN_GetContextReg(fromctx, REG_EAX),
            PIN_GetContextReg(fromctx, REG_EBX),
            PIN_GetContextReg(fromctx, REG_ECX),
            PIN_GetContextReg(fromctx, REG_EDX),
            PIN_GetContextReg(fromctx, REG_ESI),
            PIN_GetContextReg(fromctx, REG_EDI),
            PIN_GetContextReg(fromctx, REG_ESP),
            PIN_GetContextReg(fromctx, REG_EBP),
            PIN_GetContextReg(fromctx, REG_EFLAGS),
            raddr, waddr);
    for (int i = 0; i < inssize; i++)
        fprintf(fp, "%02x", *((char *)addr + i) & 0xff);
    fprintf(fp, "\n");

    if (isFinished)
    {
        fflush(fp);
        PIN_ExitApplication(0);
    }
}
#endif

static void instruction(INS ins, void *v)
{
    int flag = taint;
    ADDRINT addr = INS_Address(ins);
    if (addr <= 0x10000000)
    {
        bool isAnchor = false;

        if (opcmap.find(addr) == opcmap.end())
        {
            opcmap.insert(std::pair<ADDRINT, string>(addr, INS_Disassemble(ins)));
        }

        if (anchorstr.compare(opcmap[addr].c_str()) == 0)
        {
            cout << hex << addr << " " << opcmap[addr].c_str() << endl;
            isAnchor = true;
            if (taint && insn_num > THRESHOLD)
                taint = !taint;
            else if (!taint)
                taint = !taint;
        }
        if (taint || isAnchor)
        {
            insn_num++;
            //fprintf(fp, "%x %d: %s\n", addr, insn_num, opcmap[addr].c_str());
        }
#if defined(__readable__)
        if (flag || taint)
        {
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
#elif defined(__script__) || defined(__trace__)
#pragma message("MACRO  instruction: __script__ or  __trace__ ")
        USIZE inssize = INS_Size(ins);
        if (isAnchor || taint)
        {
            if (INS_IsMemoryRead(ins) && INS_IsMemoryWrite(ins))
            {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA, IARG_END);
            }
            else if (INS_IsMemoryRead(ins))
            {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_ADDRINT, 0, IARG_END);
            }
            else if (INS_IsMemoryWrite(ins))
            {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_MEMORYWRITE_EA, IARG_END);
            }
            else
            {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_ADDRINT, 0, IARG_END);
            }
        }
#elif defined(__anchorfinder__)
        USIZE inssize = INS_Size(ins);
        if (isAnchor || taint)
        {
            if (INS_IsMemoryRead(ins) && INS_IsMemoryWrite(ins))
            {
                //fprintf(fp, "  memread memwrite  \n");  // debug
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA, IARG_END);
            }
            else if (INS_IsMemoryRead(ins))
            {
                //fprintf(fp, "  memread  \n");  // debug
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_ADDRINT, 0, IARG_END);
            }
            else if (INS_IsMemoryWrite(ins))
            {
                //fprintf(fp, "  memwrite  \n");  // debug
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_MEMORYWRITE_EA, IARG_END);
            }
            else
            {
                //fprintf(fp, "  others  \n");  // debug
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_ADDRINT, 0, IARG_END);
            }
        }
#endif
        if (isAnchor && !taint)
        {
            finish_addr = addr;
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

static void on_fini(INT32 code, void *v)
{
    CloseFile(fp);
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

    fp = fopen(KnobOutputFile.Value().c_str(), "w");

    PIN_InitSymbols();

    /* IMG_AddInstrumentFunction(ImageLoad, 0); */
    INS_AddInstrumentFunction(instruction, 0);

    PIN_AddFiniFunction(on_fini, 0);

    PIN_StartProgram(); // Never returns

    CloseFile(fp);
    return 0;
}
