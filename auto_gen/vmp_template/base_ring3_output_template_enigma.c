#include<stdio.h>
#include<stdlib.h>
#define ENIGMA_VM_START         __asm__ (".byte 0xEB,0x08,0x56,0x4D,0x42,0x45,0x47,0x49,0x4E,0x00")
#define ENIGMA_VM_END           __asm__ (".byte 0xEB,0x08,0x56,0x4D,0x45,0x4E,0x44,0x00,0x00,0x00")
#define ENIGMA_RISC_VM_BEGIN    __asm__ (".byte 0xEB,0x08,0x56,0x4D,0x42,0x45,0x47,0x49,0x4E,0x31")
#define ENIGMA_RISC_VM_END      __asm__ (".byte 0xEB,0x08,0x56,0x4D,0x45,0x4E,0x44,0x31,0x00,0x00")

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

    ENIGMA_VM_START; // eax will be modified after obfuscation
    // instruction
    __asm (
    "%ANCHOR%"
    "%REPLACE%;"
    "%ANCHOR%"
    );
    ENIGMA_VM_END;

    __asm ( "fnop" );//end
}

int main()
{
    //std::cout << "start test" << std::endl;
    void *p = malloc(1024);
    useless(p);
    //std::cout << "end test" << std::endl;
}
