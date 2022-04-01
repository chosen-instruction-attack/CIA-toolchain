#undef _WIN64

#include <stdio.h>

#include "windows.h"
#include "VMProtectSDK.h"
//#include <iostream>

void useless(void *p1, void *p2)
{
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
        "mov edi, %1;"
        :
        : "p"(p1), "p"(p2)
        : "esi", "edi"
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
    void *p1 = malloc(1024);
    void *p2 = malloc(1024);
    memset(p1, 0, 1024);
    memset(p2, 0, 1024);
    useless(p1, p2);
    //std::cout << "end test" << std::endl;
}