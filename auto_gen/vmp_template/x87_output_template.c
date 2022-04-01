#undef _WIN64

#include <stdio.h>

#include "windows.h"
#include "VMProtectSDK.h"
//#include <iostream>

void useless(double* p)
{
    p[0] = 1.0;

    // specify registers
    __asm (
        "mov edx, 0x1;"
        "mov ecx, 0x2;"
        :
        :
        : "edx", "ecx"
    );

    // specify memory
    __asm (
        "mov esi, %0;"
        "mov edi, 0x0;"
        :
        : "p"(p)
        : "esi", "edi"
    );

    __asm (
        "fld qword ptr [esi];"
        :
        :
        :
    );

    __asm ( "fnop" ); //start

    VMProtectBegin(""); // eax will be modified after obfuscation
    // instruction
    __asm (
    "%ANCHOR%"
    "%REPLACE%;"
    "%ANCHOR%"
    );
    VMProtectEnd();

    __asm ( "fnop" );//end
}

int main()
{
    //std::cout << "start test" << std::endl;
    void *p = malloc(1024);
    useless((double*)p);
    //std::cout << "end test" << std::endl;
}