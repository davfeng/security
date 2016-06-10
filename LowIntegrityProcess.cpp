// LowIntegrityProcess.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <Windows.h>
#include <sddl.h>
BOOL CreateLowProcess()
{

    BOOL                  fRet;
    HANDLE                hToken = NULL;
    HANDLE                hNewToken = NULL;
    PSID                  pIntegritySid = NULL;
    TOKEN_MANDATORY_LABEL TIL = { 0 };
    PROCESS_INFORMATION   ProcInfo = { 0 };
    STARTUPINFO           StartupInfo = { 0 };

    // Notepad is used as an example
    WCHAR wszProcessName[MAX_PATH] =
        L"C:\\Windows\\System32\\Notepad.exe";

    // Low integrity SID
    WCHAR wszIntegritySid[20] = L"S-1-16-4096";

    fRet = OpenProcessToken(GetCurrentProcess(),
        TOKEN_DUPLICATE |
        TOKEN_ADJUST_DEFAULT |
        TOKEN_QUERY |
        TOKEN_ASSIGN_PRIMARY,
        &hToken);

    if (!fRet)
    {
        goto CleanExit;
    }

    fRet = DuplicateTokenEx(hToken,
        0,
        NULL,
        SecurityImpersonation,
        TokenPrimary,
        &hNewToken);

    if (!fRet)
    {
        goto CleanExit;
    }

    fRet = ConvertStringSidToSid(wszIntegritySid, &pIntegritySid);

    if (!fRet)
    {
        goto CleanExit;
    }

    TIL.Label.Attributes = SE_GROUP_INTEGRITY;
    TIL.Label.Sid = pIntegritySid;

    //
    // Set the process integrity level
    //

    fRet = SetTokenInformation(hNewToken,
        TokenIntegrityLevel,
        &TIL,
        sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pIntegritySid));

    if (!fRet)
    {
        goto CleanExit;
    }

    //
    // Create the new process at Low integrity
    //

    fRet = CreateProcessAsUser(hNewToken,
        NULL,
        wszProcessName,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &StartupInfo,
        &ProcInfo);

CleanExit:

    if (ProcInfo.hProcess != NULL)
    {
        CloseHandle(ProcInfo.hProcess);
    }

    if (ProcInfo.hThread != NULL)
    {
        CloseHandle(ProcInfo.hThread);
    }

    LocalFree(pIntegritySid);

    if (hNewToken != NULL)
    {
        CloseHandle(hNewToken);
    }

    if (hToken != NULL)
    {
        CloseHandle(hToken);
    }

    return fRet;
}

int main()
{
    CreateLowProcess();
    return 0;
}

