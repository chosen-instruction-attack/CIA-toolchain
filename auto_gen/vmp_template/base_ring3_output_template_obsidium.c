#undef _WIN64

#include <stdio.h>

#include "windows.h"
//#include <iostream>

#define OBSIDIUM_VM_START		__asm__ (".byte 0xEB,0x04,0x0F,0x0B,0x0F,0x0B");
#define OBSIDIUM_VM_END			__asm__ (".byte 0xEB,0x04,0x0F,0x0B,0x0F,0x06");

void useless(void *p)
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
        "mov edi, 0x0;"
        :
        : "p"(p)
        : "esi", "edi"
    );

    __asm ( "fnop" ); //start

    OBSIDIUM_VM_START; // eax will be modified after obfuscation
    // instruction
    __asm (
    "%ANCHOR%"
    "%REPLACE%;"
    "%ANCHOR%"
    );
    OBSIDIUM_VM_END;

    __asm ( "fnop" );//end
}

int main()
{
    //std::cout << "start test" << std::endl;
    void *p = malloc(1024);
    useless(p);
    //std::cout << "end test" << std::endl;
}