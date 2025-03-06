// compile : gcc -o shellcode.exe shellcode.c -m32

#include <windows.h>

int main() {
    
    // Get kernel32.dll base address
    char *PEB;
    __asm__ ("movl %%fs:0x30, %0" : "=r" (PEB)); // Accessing the fs register using Inline Assembly (gcc)
    char *Ldr = (char *)*(int *)(PEB + 0x0C);
    char *InMemoryOrderModuleList = (char *)*(int *)(Ldr + 0x14);
    char *ntdll = (char *)*(int *)(InMemoryOrderModuleList + 0x00);
    char *kernel32 = (char *)*(int *)(ntdll + 0x00); 
    char *DllBase = (char *)*(int *)(kernel32 + 0x10);

    // Get Export Table address
    int e_lfanew = *(int *)(DllBase + 0x3C);
    char *NT_Header = (char *)(DllBase + e_lfanew);
    char *Optional_Header = (char *)(NT_Header + 0x18);
    char *Data_Directory = (char *)(Optional_Header + 0x60);
    int Export_Table_RVA = *(int *)(Data_Directory + 0x00);
    char *Export_Table_Addr = (char *)(DllBase + Export_Table_RVA);

    // Get Export Table Fields address
    char *AddressOfFunctions = (char *)(DllBase + *(int *)(Export_Table_Addr + 0x1C));
    char *AddressOfNames = (char *)(DllBase + *(int *)(Export_Table_Addr + 0x20));
    char *AddressOfNameOrdinals = (char *)(DllBase + *(int *)(Export_Table_Addr + 0x24));

    int i = 0;

    char WinExec_Name[] = {0x57, 0x69, 0x6E, 0x45, 0x78, 0x65, 0x63, 0x00};

    while (1) { // Find WinExec
        char *Func_Name = (char *)*(int *)(AddressOfNames + i * sizeof(int)) + (int)DllBase;
        if (Func_Name[0] == WinExec_Name[0] &&
            Func_Name[1] == WinExec_Name[1] &&
            Func_Name[2] == WinExec_Name[2] &&
            Func_Name[3] == WinExec_Name[3] &&
            Func_Name[4] == WinExec_Name[4] &&
            Func_Name[5] == WinExec_Name[5] &&
            Func_Name[6] == WinExec_Name[6]) {
            break;
        }

        i++;
    }

    int WinExec_index = i;


    // Get Export Table Fields address
    short ordinal = *(short*)(AddressOfNameOrdinals + WinExec_index * sizeof(short));
    int WinExec_RVA = *(int*)(AddressOfFunctions + ordinal * sizeof(int));
    char* WinExec_Addr = (char*)(DllBase + WinExec_RVA);

    char calcexe[] = {0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00};

    // Call WinExec
    int (*WinExec)(const char *, unsigned int) = (int (*)(const char *, unsigned int))WinExec_Addr;
    WinExec(calcexe, 0);

    return 0;
}