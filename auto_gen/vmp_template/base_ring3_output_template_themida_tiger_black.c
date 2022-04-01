#undef _WIN64

#include <stdio.h>

#include "windows.h"
#include "ThemidaSDK.h"
//#include <iostream>

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

    VM_TIGER_BLACK_START
    // instruction
    __asm (
    "%ANCHOR%"
    "%REPLACE%;"
    "%ANCHOR%"
    );
    VM_TIGER_BLACK_END

    __asm ( "fnop" );//end
}

int main()
{
    //std::cout << "start test" << std::endl;
    void *p = malloc(1024);
    useless(p);
    //std::cout << "end test" << std::endl;
}