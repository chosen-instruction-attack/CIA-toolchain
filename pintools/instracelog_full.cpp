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

#define __readable__

using std::string;
using std::ifstream;

string anchorstr;
bool taint = false;
bool isFinished = false;


std::map<ADDRINT, string> opcmap;
FILE* fp;

using namespace std;

ADDRINT filter_ip_low, filter_ip_high;

std::string target_name;


void CloseFile(FILE* fp)
{
    static bool isclose = false;

    if (!isclose)
    {
        fflush(fp);
        fclose(fp);
        isclose = true;
    }
}

VOID ImageLoad(IMG img, VOID* v) {
    for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
        if (IMG_IsMainExecutable(img)) {
            filter_ip_low = IMG_LowAddress(img);
            filter_ip_high = IMG_HighAddress(img);
            cerr << "[-] Log range:" << StringFromAddrint(filter_ip_low) << "-" << StringFromAddrint(filter_ip_high) << endl;
        }

    }

    cerr << "[+] Images loads. " << IMG_Name(img) << endl;
    if (IMG_IsMainExecutable(img)) {
        filter_ip_low = IMG_LowAddress(img);
        filter_ip_high = IMG_HighAddress(img);
        cerr << "[-] Log range:" << StringFromAddrint(filter_ip_low) << "-" << StringFromAddrint(filter_ip_high) << endl;
    }
}

#if defined(__readable__)
// for readable
void getctx(ADDRINT addr, CONTEXT* fromctx, ADDRINT raddr, ADDRINT waddr)
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
    
    // for self-modify code
    std::map<ADDRINT, string>::iterator iter = opcmap.find(waddr);
    if (iter != opcmap.end())
        opcmap.erase(iter);
    // ===

    if (isFinished) {
        fflush(fp);
        PIN_ExitApplication(0);
    }
}

#elif defined(__script__)
// for script
void getctx(ADDRINT addr, ADDRINT inssize, CONTEXT* fromctx, ADDRINT raddr, ADDRINT waddr)
{

    fprintf(fp, "0x%x; %u; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0;\n", addr, inssize,
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

    if (isFinished) {
        fflush(fp);
        PIN_ExitApplication(0);
    }
}
#elif defined(__simple__)
void getctx(ADDRINT addr, CONTEXT* fromctx) {
    fprintf(fp, "0x%x: %s\n", addr, opcmap[addr].c_str());
}
#endif

// Recording methods
/*
static void record_order(INS ins, ADDRINT addr){
        if (opcmap.find(addr) == opcmap.end()) {
              opcmap.insert(std::pair<ADDRINT, string>(addr, INS_Disassemble(ins)));
         }
          INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_END);
}
*/

static void instruction(INS ins, void* v)
{
    ADDRINT addr = INS_Address(ins);
    if (addr <= 0x10000000) {

        if (opcmap.find(addr) == opcmap.end()) {
            opcmap.insert(std::pair<ADDRINT, string>(addr, INS_Disassemble(ins)));
        }

#if defined(__readable__)
        if (INS_IsMemoryRead(ins) && INS_IsMemoryWrite(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA, IARG_END);
        }
        else if (INS_IsMemoryRead(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_ADDRINT, 0, IARG_END);
        }
        else if (INS_IsMemoryWrite(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_MEMORYWRITE_EA, IARG_END);
        }
        else {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_ADDRINT, 0, IARG_END);
        }

#elif defined(__script__)
        USIZE inssize = INS_Size(ins);
        if (isAnchor || taint) {
            if (INS_IsMemoryRead(ins) && INS_IsMemoryWrite(ins)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA, IARG_END);
            }
            else if (INS_IsMemoryRead(ins)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_ADDRINT, 0, IARG_END);
            }
            else if (INS_IsMemoryWrite(ins)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_MEMORYWRITE_EA, IARG_END);
            }
            else {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_ADDRINT, 0, IARG_END);
            }
        }
#endif

    }

}


static void instruction_from_main(INS ins, void* argv)
{
    static int flag = false;
    ADDRINT addr = INS_Address(ins);

    ADDRINT* pargv = (ADDRINT*)argv;

    if (addr <= 0x10000000) {
        if (addr == pargv[0])
            flag = true;

        if (flag) {
            if (opcmap.find(addr) == opcmap.end()) {
                opcmap.insert(std::pair<ADDRINT, string>(addr, INS_Disassemble(ins)));
            }

            if (INS_IsMemoryRead(ins) && INS_IsMemoryWrite(ins)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA, IARG_END);
            }
            else if (INS_IsMemoryRead(ins)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_ADDRINT, 0, IARG_END);
            }
            else if (INS_IsMemoryWrite(ins)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_MEMORYWRITE_EA, IARG_END);
            }
            else {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_ADDRINT, 0, IARG_END);
            }
        }
        if (addr == pargv[1] && flag == true)
        {
            flag = false;
            isFinished = true;
        }
    }
}


static void on_fini(INT32 code, void* v)
{
    CloseFile(fp);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage() {
    PIN_ERROR("This tool prints a log of image load and unload events\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

std::string extractFilename(const std::string& filename)
{
    unsigned int lastBackslash = filename.rfind("\\");
    unsigned int lastdot = filename.rfind(".");

    if (lastBackslash != std::string::npos && lastdot != std::string::npos) {
        return filename.substr(lastBackslash + 1, lastdot - lastBackslash - 1);
    }
    else if (lastBackslash == std::string::npos && lastdot != std::string::npos) {
        return filename.substr(0, filename.length() - lastdot);
    }
    else if (lastdot == std::string::npos && lastBackslash != std::string::npos) {
        return filename.substr(lastBackslash + 1);
    }
    else {
        return filename;
    }
}

int main(int argc, char* argv[])
{
    ADDRINT callback_argv[] = { 0x4015c0, 0x4015f1 };

    if (PIN_Init(argc, argv))  return Usage();

    char* tracefile = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            tracefile = argv[i + 1];
            break;
        }
    }

    target_name = extractFilename(tracefile) + ".log";

    KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
        "o", target_name, "trace file");

    fp = fopen(KnobOutputFile.Value().c_str(), "w");

    PIN_InitSymbols();

    /* IMG_AddInstrumentFunction(ImageLoad, 0); */
    INS_AddInstrumentFunction(instruction, callback_argv);

    PIN_AddFiniFunction(on_fini, 0);

    PIN_StartProgram(); // Never returns

    CloseFile(fp);
    return 0;
}