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

#define THRESHOLD 10       // When taint is True, must record at least THRESHOLD instructions

using std::string;
using std::ifstream;

const char *tracefile = "instrace.txt";
const char *anchorfile = "anchor.txt";
const char* default_file = "";


unsigned int appear_time = 0;
bool is_retanchor = false;
bool has_prev = false;
unsigned char prev_ins[20];
const unsigned char ret_hex[] = { 0xc3, 0xcb, 0xc2, 0xca };
string line;
char c_file[50];
const char* ins_str = NULL;
char hex_buffer[20];
char* ins_hex = NULL;
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
FILE *fp;

using namespace std;

ADDRINT filter_ip_low, filter_ip_high;

KNOB<string> KnobTestProgram(KNOB_MODE_WRITEONCE, "pintool",
    "s", default_file, "test program name");
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

VOID ImageLoad(IMG img, VOID *v) {
    for( IMG img= APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img) ){
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


void getctx(ADDRINT addr, ADDRINT inssize, CONTEXT* fromctx, ADDRINT raddr, ADDRINT waddr)
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
        fprintf(fp, "%02x", *((char*)addr+i)&0xff);
    fprintf(fp, "; %s\n", opcmap[addr].c_str());
    fflush(fp);
    if (finish_addr == addr) {
        // fflush(fp);
        PIN_ExitApplication(0);
    }
}

void PrintInsDel(ADDRINT addr, ADDRINT inssize)
{
    fprintf(fp, "0x%x; %u; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; 0x%x; ", addr, inssize,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0, 0);

    for (int i = 0; i < inssize; i++)
        fprintf(fp, "%02x", ins_hex[i] & 0xff);
    fprintf(fp, "; %s\n", opcmap[addr].c_str());
    fflush(fp);
    if (finish_addr == addr) {
        // fflush(fp);
        PIN_ExitApplication(0);
    }
}


static void instruction(INS ins, void *v)
{
    int flag = taint;
    unsigned char opcode[20];

    ADDRINT addr = INS_Address(ins);
    if (addr<=0x10000000){
        bool isAnchor = false;

        if (opcmap.find(addr) == opcmap.end()) {
            opcmap.insert(std::pair<ADDRINT, string>(addr, INS_Disassemble(ins)));
        }

        if (anchorstr.compare(opcmap[addr].c_str()) == 0) {
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

        USIZE inssize = INS_Size(ins);
        if (isAnchor || taint) {
        //if(true) {
            bool is_del = inssize == ins_hexlen;
            if (is_del)
            {
                PIN_SafeCopy(opcode, (void*)addr, inssize);
                int tmp = memcmp(opcode, ins_hex, inssize);
                is_del = is_del && (tmp == 0);
            }
            if(!is_del)
            {
                if (INS_IsMemoryRead(ins) && INS_IsMemoryWrite(ins)) {
                    //fprintf(fp, "  memread memwrite  \n");  // debug
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA, IARG_END);
                }
                else if (INS_IsMemoryRead(ins)) {
                    //fprintf(fp, "  memread  \n");  // debug
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_ADDRINT, 0, IARG_END);
                }
                else if (INS_IsMemoryWrite(ins)) {
                    //fprintf(fp, "  memwrite  \n");  // debug
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_MEMORYWRITE_EA, IARG_END);
                }
                else {
                    //fprintf(fp, "  others  \n");  // debug
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_ADDRINT, 0, IARG_END);
                }
            }
            else
            {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)PrintInsDel, IARG_INST_PTR, IARG_ADDRINT, inssize, IARG_END);
                INS_Delete(ins);
                cerr << KnobTestProgram.Value() << "Delete Ins at " << hex << addr << endl;
                fflush(stderr);
            }
        }

        if (isAnchor && !taint) {
            finish_addr = addr;
        }
	}

}


static void instruction_from_main(INS ins, void* argv)
{
    static int flag = false;
    ADDRINT addr = INS_Address(ins);

    ADDRINT *pargv = (ADDRINT*)argv;

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

char* Hex2Buf(const char* hex_str, int length, int* buflen)       // buflen is a return value
{
    int len;

    if (length > 0)
        len = length;
    else
        len = strlen(hex_str);

    *buflen = len / 2;
    char* buf = hex_buffer;

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

int ParseLine(string& line)     // global var ins_hex and ins_str is changed here
{
    int i = 0, j;
    const char* buf = line.c_str();

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
}

 /* ===================================================================== */
 /* Print Help Message                                                    */
 /* ===================================================================== */
 INT32 Usage(){
              PIN_ERROR("This tool prints a log of image load and unload events\n" + KNOB_BASE::StringKnobSummary() + "\n");
              return -1;
               }

 /* ===================================================================== */
 /* Main                                                                  */
 /* ===================================================================== */


int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv))  return Usage();

    ifstream file(KnobInputFile.Value().c_str(), ifstream::in);
    if (file.good()) {
        getline(file, anchorstr);
    }
    file.close();
    file.clear();

    // get C file name
    int i;
    const char* buf = KnobTestProgram.Value().c_str();
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
    if (file.good()) {
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

     fp = fopen(KnobOutputFile.Value().c_str(), "w");

     PIN_InitSymbols();

     /* IMG_AddInstrumentFunction(ImageLoad, 0); */
     INS_AddInstrumentFunction(instruction, 0);

     PIN_AddFiniFunction(on_fini, 0);

     PIN_StartProgram(); // Never returns

     CloseFile(fp);
     return 0;
}
