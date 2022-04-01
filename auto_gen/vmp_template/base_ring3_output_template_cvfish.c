#pragma warning( disable : 4996)
#undef _WIN64
#include <stdio.h>
#include <stdlib.h>
#include "VirtualizerSDK.h"
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

    __asm ("fnop;");

    VIRTUALIZER_FISH_WHITE_START; // eax will be modified after obfuscation
    // instruction
    __asm (
        "%ANCHOR%"
        "%REPLACE%;"
        "%ANCHOR%"
        );
    VIRTUALIZER_FISH_WHITE_END;

    __asm ("fnop;");  //end
}

int main()
{
    void *p = malloc(1024);
    useless(p);
    return 0;
}
