// checksd.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <tchar.h>
#include <stdio.h>
//#include <lmcons.h>
#include <Windows.h>

#include <lm.h>
#include <tchar.h>
#include <stdio.h>

//
// access for network shares.  these are based on the values set by
// explorer
//
#define READ        0x000001BF
#define CHANGE      0x000000A9
#define WRITE       0x00000040

//
// helper definitions, helper.c
//
#define UNKNOWNSIDS 4

//
// helper functions, helper.c
//
BOOL ConvertSid(PSID pSid, LPTSTR pszSidText, LPDWORD dwBufferLen);
void DisplayError(DWORD dwError, LPTSTR pszAPI);
BOOL Privilege(LPTSTR pszPrivilege, BOOL bEnable);
void LookupAccountOtherSid(PSID psidCheck, LPTSTR pszName, LPDWORD pcbName, LPTSTR pszDomain, LPDWORD pcbDomain, PSID_NAME_USE psnu);

//
// functions for obtaining information from a security descriptor, sd.c
//
DWORD DumpAclInfo(PACL pacl, BOOL bDacl);
void  DumpControl(PSECURITY_DESCRIPTOR psd);
void  DumpDacl(PSECURITY_DESCRIPTOR psd, TCHAR c, BOOL bDacl);
void  DumpOwnerGroup(PSECURITY_DESCRIPTOR psd, BOOL bOwner);
void  DumpSD(PSECURITY_DESCRIPTOR psd, TCHAR c);
void  DumpSDInfo(PSECURITY_DESCRIPTOR psd);

//
// functions for obtaining a security descriptor for a variety of securable objects,
// secobjects.c
//
void DumpFile(LPTSTR pszFile, TCHAR c);
void DumpKernelObject(LPTSTR pszObject, TCHAR c);
void DumpNetShare(LPTSTR pszShare);
void DumpPrinter(LPTSTR pszPrinter);
void DumpRegistryKey(LPTSTR pszKey);
void DumpService(LPTSTR pszServer, LPTSTR pszService);
void DumpUserObject(LPTSTR pszObject, TCHAR c);

void DumpFile(LPTSTR pszFile, TCHAR c)
{
    DWORD                dwSize = 0;
    PSECURITY_DESCRIPTOR psd = NULL;
    SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;

    //
    // enable the privilege
    //
    Privilege(SE_SECURITY_NAME, TRUE);

    //
    // get the size
    //
    if (!GetFileSecurity(pszFile, si, psd, dwSize, &dwSize)){
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER){
            psd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSize);
            if (psd == NULL)
                DisplayError(GetLastError(), TEXT("LocalAlloc"));

            if (!GetFileSecurity(pszFile, si, psd, dwSize, &dwSize))
                DisplayError(GetLastError(), TEXT("GetFileSecurity"));
        }
        else
            DisplayError(GetLastError(), TEXT("GetFileSecurity"));
    }

    //
    // enable the privilege
    //
    Privilege(SE_SECURITY_NAME, FALSE);

    //
    // dump security descriptor
    //
    DumpSD(psd, c);

    //
    // free the buffer
    //
    LocalFree((HLOCAL)psd);
}

void DumpKernelObject(LPTSTR pszObject, TCHAR c)
{
    DWORD                dwPid;
    DWORD                dwSize = 0;
    HANDLE               hObject;
    HANDLE               hProcess;
    PSECURITY_DESCRIPTOR psd = NULL;
    SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;

    //
    // enable the privilege
    //
    Privilege(SE_SECURITY_NAME, TRUE);

    //
    // obtain a handle
    //
    switch (c){
    case 'e':
        hObject = OpenEvent(READ_CONTROL | ACCESS_SYSTEM_SECURITY, FALSE, pszObject);
        if (hObject == NULL)
            DisplayError(GetLastError(), TEXT("OpenEvent"));
        break;
    case 'm':
        hObject = OpenMutex(READ_CONTROL | ACCESS_SYSTEM_SECURITY, FALSE, pszObject);
        if (hObject == NULL)
            DisplayError(GetLastError(), TEXT("OpenMutex"));
        break;
    case 's':
        hObject = OpenSemaphore(READ_CONTROL | ACCESS_SYSTEM_SECURITY, FALSE, pszObject);
        if (hObject == NULL)
            DisplayError(GetLastError(), TEXT("OpenSemaphore"));
        break;
    case 'p':
        //
        // convert name to a pid
        //
        dwPid = _ttol(pszObject);

        hObject = OpenProcess(READ_CONTROL | ACCESS_SYSTEM_SECURITY, FALSE, dwPid);
        if (hObject == NULL)
            DisplayError(GetLastError(), TEXT("OpenProcess"));
        break;

    case 'o':
        dwPid = _ttol(pszObject);

        //
        // SD in access token does not support SACLS
        //
        si = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);
        if (hProcess == NULL)
            DisplayError(GetLastError(), TEXT("OpenProcess"));

        if (!OpenProcessToken(hProcess, READ_CONTROL, &hObject))
            DisplayError(GetLastError(), TEXT("OpenProcessToken"));

        if (!CloseHandle(hProcess))
            DisplayError(GetLastError(), TEXT("CloseHandle"));
        break;
    case 'i':
        hObject = OpenFileMapping(READ_CONTROL | ACCESS_SYSTEM_SECURITY, FALSE, pszObject);
        if (hObject == NULL)
            DisplayError(GetLastError(), TEXT("OpenFileMapping"));
        break;
    case 'a':
    case 'n':
        hObject = CreateFile(pszObject, READ_CONTROL | ACCESS_SYSTEM_SECURITY, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hObject == INVALID_HANDLE_VALUE)
            DisplayError(GetLastError(), TEXT("CreateFile"));
    default:
        break;
    }

    //
    // disable the privilege
    //
    Privilege(SE_SECURITY_NAME, FALSE);

    //
    // obtain the size
    //
    if (!GetKernelObjectSecurity(hObject, si, psd, dwSize, &dwSize)){
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER){
            psd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSize);
            if (psd == NULL)
                DisplayError(GetLastError(), TEXT("LocalAlloc"));

            if (!GetKernelObjectSecurity(hObject, si, psd, dwSize, &dwSize))
                DisplayError(GetLastError(), TEXT("GetKernelObjectSecurity"));
        }
        else
            DisplayError(GetLastError(), TEXT("GetKernelObjectSecurity"));
    }

    //
    // dump security descriptor
    //
    DumpSD(psd, c);

    //
    // free the buffer
    //
    LocalFree((HLOCAL)psd);

    if (!CloseHandle(hObject))
        DisplayError(GetLastError(), TEXT("CloseHandle"));
}

void DumpNetShare(LPTSTR pszShare)
{
    DWORD                dwSize = 0;
    LPTSTR               pszShareAdjusted;
    LPTSTR               pszShareName;
    NET_API_STATUS       nas;
    PSECURITY_DESCRIPTOR psd = NULL;
    PSHARE_INFO_502      psi502;
    TCHAR                szServer[CNLEN] = TEXT("");

#ifndef UNICODE
    WCHAR                szWServer[CNLEN] = L"";
    WCHAR                szWShare[NNLEN] = L"";
#endif

    //
    // remove \\ if exists
    //
    pszShareAdjusted = _tcsstr(pszShare, TEXT("\\\\"));
    if (pszShareAdjusted != NULL)
        pszShareAdjusted = pszShareAdjusted + 2;
    else
        pszShareAdjusted = pszShare;

    //
    // find the subkey
    //
    pszShareName = _tcschr(pszShareAdjusted, '\\');
    if (pszShareName == NULL)
        return;
    else
        pszShareName++;

    //
    // find the main key
    //
    _tcsncpy(szServer, pszShareAdjusted, (UINT)(pszShareName - pszShareAdjusted - 1));


#ifndef UNICODE

    //
    // handle ANSI situation
    //
    MultiByteToWideChar(CP_ACP, 0, (LPCTSTR)szServer, -1, szWServer, sizeof(szWServer));

    MultiByteToWideChar(CP_ACP, 0, (LPCTSTR)pszShareName, -1, szWShare, sizeof(szWShare));

    nas = NetShareGetInfo(szWServer, szWShare, 502, (LPBYTE *)&psi502);

#else

    nas = NetShareGetInfo(szServer, pszShareName, 502, (LPBYTE *)&psi502);

#endif

    if (nas != NERR_Success)
        DisplayError(nas, TEXT("NetShareGetInfo"));

    //
    // obtain the SD
    //
    psd = psi502->shi502_security_descriptor;

    //
    // dump security descriptor
    //
    DumpSD(psd, 't');

    //
    // free the buffer
    //
    NetApiBufferFree((LPVOID)psi502);
}

void DumpPrinter(LPTSTR pszPrinter)
{
    DWORD                dwSize = 0;
    HANDLE               hPrinter;
    PRINTER_DEFAULTS     pd;
    PRINTER_INFO_3       *ppi3 = NULL;
    PSECURITY_DESCRIPTOR psd = NULL;

    ZeroMemory(&pd, sizeof(PRINTER_DEFAULTS));
    pd.DesiredAccess = READ_CONTROL;

    //
    // obtain a handle to the printer
    //
    if (!OpenPrinter(pszPrinter, &hPrinter, &pd))
        DisplayError(GetLastError(), TEXT("OpenPrinter"));

    //
    // get the size
    //
    if (!GetPrinter(hPrinter, 3, (LPBYTE)ppi3, dwSize, &dwSize)){
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER){
            ppi3 = (PPRINTER_INFO_3)LocalAlloc(LPTR, dwSize);
            if (ppi3 == NULL)
                DisplayError(GetLastError(), TEXT("LocalAlloc"));

            if (!GetPrinter(hPrinter, 3, (LPBYTE)ppi3, dwSize, &dwSize))
                DisplayError(GetLastError(), TEXT("GetPrinter"));
        }
    }

    //
    // cast buffer
    //
    psd = ppi3->pSecurityDescriptor;

    //
    // dump security descriptor information
    //
    DumpSDInfo(psd);

    //
    // dump the control bits
    //
    DumpControl(psd);

    //
    // get the owner
    //
    DumpOwnerGroup(psd, TRUE);

    //
    // get the group
    //
    DumpOwnerGroup(psd, FALSE);

    //
    // get the dacl
    //
    DumpDacl(psd, 'l', TRUE);

    //
    // printer object does not have a SACL
    //

    //
    // free the buffer
    //
    LocalFree((HLOCAL)ppi3);

    if (!ClosePrinter(hPrinter))
        DisplayError(GetLastError(), TEXT("ClosePrinter"));
}

void DumpRegistryKey(LPTSTR pszKey)
{
    DWORD                dwAccess = READ_CONTROL;
    DWORD                dwSize = 0;
    HKEY                 hKey;
    HKEY                 hMainKey;
    LONG                 lErrorCode;
    LPTSTR               pszSubKey = NULL;
    PSECURITY_DESCRIPTOR psd = NULL;
    SECURITY_INFORMATION si;
    TCHAR                szMainKey[256] = TEXT("");

    //
    // find the subkey
    //
    pszSubKey = _tcschr(pszKey, '\\');
    if (pszSubKey == NULL){
        lstrcpy(szMainKey, pszKey);
        si = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    }
    else{
        pszSubKey++;

        //
        // find the main key
        //
        _tcsncpy(szMainKey, pszKey, (UINT)(pszSubKey - pszKey - 1));

        si = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;
    }

    //
    // parse the main key
    //
    if (!lstrcmp(szMainKey, TEXT("HKEY_LOCAL_MACHINE"))){
        hMainKey = HKEY_LOCAL_MACHINE;
    }
    else if (!lstrcmp(szMainKey, TEXT("HKEY_CLASSES_ROOT"))){
        hMainKey = HKEY_CLASSES_ROOT;
    }
    else if (!lstrcmp(szMainKey, TEXT("HKEY_USERS"))){
        hMainKey = HKEY_USERS;
    }
    else if (!lstrcmp(szMainKey, TEXT("HKEY_CURRENT_USER"))){
        hMainKey = HKEY_CURRENT_USER;
    }
    else if (!lstrcmp(szMainKey, TEXT("HKEY_CLASSES_ROOT"))){
        hMainKey = HKEY_CLASSES_ROOT;
    }
    else
        hMainKey = 0;

    //
    // enable the privilege
    //
    if (pszSubKey != NULL){
        Privilege(SE_SECURITY_NAME, TRUE);
        dwAccess |= ACCESS_SYSTEM_SECURITY;
    }

    //
    // open the key
    //
    lErrorCode = RegOpenKeyEx(hMainKey, pszSubKey, 0, dwAccess, &hKey);
    if (lErrorCode != ERROR_SUCCESS)
        DisplayError(lErrorCode, TEXT("RegOpenKeyEx"));

    //
    // disable the privilege
    //
    if (pszSubKey != NULL)
        Privilege(SE_SECURITY_NAME, FALSE);

    //
    // get key security information
    //
    lErrorCode = RegGetKeySecurity(hKey, si, psd, &dwSize);
    if (lErrorCode == ERROR_INSUFFICIENT_BUFFER){
        //
        // allocate memory for psd
        //
        psd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSize);
        if (psd == NULL)
            DisplayError(GetLastError(), TEXT("LocalAlloc"));

        //
        // call the api again
        //
        lErrorCode = RegGetKeySecurity(hKey, si, psd, &dwSize);
        if (lErrorCode != ERROR_SUCCESS)
            DisplayError(lErrorCode, TEXT("RegGetKeySecurity"));
    }
    else
        DisplayError(lErrorCode, TEXT("RegGetKeySecurity"));

    //
    // dump security descriptor
    //
    DumpSD(psd, 'r');

    //
    // free the buffer
    //
    LocalFree((HLOCAL)psd);

    //
    // close the key
    //
    lErrorCode = RegCloseKey(hKey);
    if (lErrorCode != ERROR_SUCCESS)
        DisplayError(lErrorCode, TEXT("RegCloseKey"));
}

void DumpService(LPTSTR pszServer, LPTSTR pszService)
{
    DWORD                dwSize = 0;
    PSECURITY_DESCRIPTOR psd = (PSECURITY_DESCRIPTOR)1;  // if initialized to NULL, QueryServiceObjectSecurity() returns error code 87
    SC_HANDLE            schService;
    SC_HANDLE            schManager;
    SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;

    schManager = OpenSCManager(pszServer, NULL, SC_MANAGER_CONNECT);
    if (schManager == NULL)
        DisplayError(GetLastError(), TEXT("OpenSCManager"));

    //
    // enable the privilege
    //
    Privilege(SE_SECURITY_NAME, TRUE);

    schService = OpenService(schManager, pszService, READ_CONTROL | ACCESS_SYSTEM_SECURITY);
    if (schService == NULL)
        DisplayError(GetLastError(), TEXT("OpenService"));

    //
    // disable the privilege
    //
    Privilege(SE_SECURITY_NAME, FALSE);

    //
    // obtain the size
    //
    if (!QueryServiceObjectSecurity(schService, si, psd, dwSize, &dwSize)){
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER){
            psd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSize);
            if (psd == NULL)
                DisplayError(GetLastError(), TEXT("LocalAlloc"));

            if (!QueryServiceObjectSecurity(schService, si, psd, dwSize, &dwSize))
                DisplayError(GetLastError(), TEXT("QueryServicelObjectSecurity"));
        }
        else
            DisplayError(GetLastError(), TEXT("QueryServiceObjectSecurity"));
    }


    //
    // dump security descriptor
    //
    DumpSD(psd, 'v');

    //
    // free the buffer
    //
    LocalFree((HLOCAL)psd);

    if (!CloseServiceHandle(schService))
        DisplayError(GetLastError(), TEXT("CloseServiceHandle"));

    if (!CloseServiceHandle(schManager))
        DisplayError(GetLastError(), TEXT("CloseServiceHandle"));
}

void DumpUserObject(LPTSTR pszObject, TCHAR c)
{
    DWORD                dwSize = 0;
    HANDLE               hObject;
    HWINSTA              hwinsta;
    HWINSTA              hwinstaCurrent;
    LPTSTR               pszDesktop;
    PSECURITY_DESCRIPTOR psd = NULL;
    SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;
    TCHAR                szWinsta[256] = TEXT("");

    //
    // enable the privilege
    //
    Privilege(SE_SECURITY_NAME, TRUE);

    //
    // obtain a handle
    //
    switch (c){
    case 'w':
        hObject = OpenWindowStation(pszObject, FALSE, READ_CONTROL | ACCESS_SYSTEM_SECURITY);
        if (hObject == NULL)
            DisplayError(GetLastError(), TEXT("OpenWindowStation"));
        break;

    case 'k':
        //
        // find the desktop
        //
        pszDesktop = _tcschr(pszObject, '\\');
        if (pszDesktop == NULL)
            return;
        else
            pszDesktop++;

        //
        // find the main key
        //
        _tcsncpy(szWinsta, pszObject, (UINT)(pszDesktop - pszObject - 1));

        //
        // obtain a handle to the window station
        //
        hwinsta = OpenWindowStation(szWinsta, FALSE, WINSTA_ENUMDESKTOPS);
        if (hwinsta == NULL)
            DisplayError(GetLastError(), TEXT("OpenWindowStation"));

        hwinstaCurrent = GetProcessWindowStation();
        if (hwinstaCurrent == NULL)
            DisplayError(GetLastError(), TEXT("GetProcessWindowStation"));

        if (!SetProcessWindowStation(hwinsta))
            DisplayError(GetLastError(), TEXT("SetProcessWindowStation"));

        hObject = OpenDesktop(pszDesktop, 0, FALSE, READ_CONTROL | ACCESS_SYSTEM_SECURITY);
        if (hObject == NULL)
            DisplayError(GetLastError(), TEXT("OpenDesktop"));

        if (!SetProcessWindowStation(hwinstaCurrent))
            DisplayError(GetLastError(), TEXT("SetProcessWindowStation"));

        if (!CloseWindowStation(hwinsta))
            DisplayError(GetLastError(), TEXT("CloseWindowStation"));
        break;
    default:
        break;
    }

    //
    // disable the privilege
    //
    Privilege(SE_SECURITY_NAME, FALSE);

    //
    // obtain the size
    //
    if (!GetUserObjectSecurity(hObject, &si, psd, dwSize, &dwSize)){
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER){
            psd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSize);
            if (psd == NULL)
                DisplayError(GetLastError(), TEXT("LocalAlloc"));

            if (!GetUserObjectSecurity(hObject, &si, psd, dwSize, &dwSize))
                DisplayError(GetLastError(), TEXT("GetUserObjectSecurity"));
        }
        else
            DisplayError(GetLastError(), TEXT("GetUserObjectSecurity"));
    }

    //
    // dump security descriptor
    //
    DumpSD(psd, c);

    //
    // free the buffer
    //
    LocalFree((HLOCAL)psd);

    if (!CloseHandle(hObject))
        DisplayError(GetLastError(), TEXT("CloseHandle"));
}

BOOL ConvertSid(PSID pSid, LPTSTR pszSidText, LPDWORD dwBufferLen)
{
    DWORD                     dwSubAuthorities;
    DWORD                     dwSidRev = SID_REVISION;
    DWORD                     dwCounter;
    DWORD                     dwSidSize;
    PSID_IDENTIFIER_AUTHORITY psia;

    //
    // test if Sid passed in is valid
    //
    if (!IsValidSid(pSid))
        return FALSE;

    //
    // obtain SidIdentifierAuthority
    //
    psia = GetSidIdentifierAuthority(pSid);

    //
    // obtain sidsubauthority count
    //
    dwSubAuthorities = *GetSidSubAuthorityCount(pSid);

    //
    // compute buffer length
    // S-SID_REVISION- + identifierauthority- + subauthorities- + NULL
    //
    dwSidSize = (15 + 12 + (12 * dwSubAuthorities) + 1) * sizeof(TCHAR);

    //
    // check provided buffer length.
    // If not large enough, indicate proper size and setlasterror
    //
    if (*dwBufferLen < dwSidSize){
        *dwBufferLen = dwSidSize;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    //
    // prepare S-SID_REVISION-
    //
    dwSidSize = wsprintf(pszSidText, TEXT("S-%lu-"), dwSidRev);

    //
    // prepare SidIdentifierAuthority
    //
    if ((psia->Value[0] != 0) || (psia->Value[1] != 0)){
        dwSidSize += wsprintf(pszSidText + lstrlen(pszSidText),
            TEXT("0x%02hx%02hx%02hx%02hx%02hx%02hx"),
            (USHORT)psia->Value[0],
            (USHORT)psia->Value[1],
            (USHORT)psia->Value[2],
            (USHORT)psia->Value[3],
            (USHORT)psia->Value[4],
            (USHORT)psia->Value[5]);
    }
    else{
        dwSidSize += wsprintf(pszSidText + lstrlen(pszSidText),
            TEXT("%lu"),
            (ULONG)(psia->Value[5]) +
            (ULONG)(psia->Value[4] << 8) +
            (ULONG)(psia->Value[3] << 16) +
            (ULONG)(psia->Value[2] << 24));
    }

    //
    // loop through SidSubAuthorities
    //
    for (dwCounter = 0; dwCounter < dwSubAuthorities; dwCounter++){
        dwSidSize += wsprintf(pszSidText + dwSidSize, TEXT("-%lu"),
            *GetSidSubAuthority(pSid, dwCounter));
    }

    return TRUE;
}

void DisplayError(DWORD dwError, LPTSTR pszAPI)
{
    LPVOID lpvMessageBuffer;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, dwError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), //The user default language
        (LPTSTR)&lpvMessageBuffer, 0, NULL);

    //
    //... now display this string
    //
    _tprintf(TEXT("ERROR: API        = %s.\n"), pszAPI);
    _tprintf(TEXT("       error code = %d.\n"), dwError);
    _tprintf(TEXT("       message    = %s.\n"), (LPTSTR)lpvMessageBuffer);

    //
    // Free the buffer allocated by the system
    //
    LocalFree(lpvMessageBuffer);

    ExitProcess(0);
}

BOOL Privilege(LPTSTR pszPrivilege, BOOL bEnable)
{
    HANDLE           hToken;
    TOKEN_PRIVILEGES tp;

    //
    // obtain the token, first check the thread and then the process
    //
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, TRUE, &hToken)){
        if (GetLastError() == ERROR_NO_TOKEN){
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
                return FALSE;
        }
        else
            return FALSE;
    }

    //
    // get the luid for the privilege
    //
    if (!LookupPrivilegeValue(NULL, pszPrivilege, &tp.Privileges[0].Luid))
        return FALSE;

    tp.PrivilegeCount = 1;

    if (bEnable)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    //
    // enable or disable the privilege
    //
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, 0))
        return FALSE;

    if (!CloseHandle(hToken))
        return FALSE;

    return TRUE;
}

void LookupAccountOtherSid(PSID psidCheck, LPTSTR pszName, LPDWORD pcbName, LPTSTR pszDomain, LPDWORD pcbDomain, PSID_NAME_USE psnu)
{
    int                      i;
    PSID                     psid[UNKNOWNSIDS];
    PSID                     psidLogonSid;
    SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
    TCHAR                    szName[UNKNOWNSIDS][18] = { TEXT("ACCOUNT OPERATORS"), TEXT("SERVER OPERATORS"), TEXT("PRINTER OPERATORS"), TEXT("BACKUP OPERATORS") };

    //
    // name should be bigger than 18, builtin should be greater than 8
    //

    //
    // create account operators
    //
    if (!AllocateAndInitializeSid(&sia, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ACCOUNT_OPS, 0, 0, 0, 0, 0, 0, &psid[0]))
        DisplayError(GetLastError(), TEXT("AllocateAndInitializeSid"));

    //
    // create system operators
    //
    if (!AllocateAndInitializeSid(&sia, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_SYSTEM_OPS, 0, 0, 0, 0, 0, 0, &psid[1]))
        DisplayError(GetLastError(), TEXT("AllocateAndInitializeSid"));

    //
    // create printer operators
    //
    if (!AllocateAndInitializeSid(&sia, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_PRINT_OPS, 0, 0, 0, 0, 0, 0, &psid[2]))
        DisplayError(GetLastError(), TEXT("AllocateAndInitializeSid"));

    //
    // create backup operators
    //
    if (!AllocateAndInitializeSid(&sia, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_BACKUP_OPS, 0, 0, 0, 0, 0, 0, &psid[3]))
        DisplayError(GetLastError(), TEXT("AllocateAndInitializeSid"));

    //
    // create a logon SID
    //
    if (!AllocateAndInitializeSid(&sia, 2, 0x00000005, 0, 0, 0, 0, 0, 0, 0, &psidLogonSid))
        DisplayError(GetLastError(), TEXT("AllocateAndInitializeSid"));

    *psnu = SidTypeAlias;

    for (i = 0; i < 4; i++){
        if (EqualSid(psidCheck, psid[i])){
            lstrcpy(pszName, szName[i]);
            lstrcpy(pszDomain, TEXT("BUILTIN"));
            break;
        }
    }

    if (EqualPrefixSid(psidCheck, psidLogonSid)){
        lstrcpy(pszName, TEXT("LOGON SID"));
    }

    //
    // free the sids
    //
    for (i = 0; i<4; i++){
        FreeSid(psid[i]);
    }

    FreeSid(psidLogonSid);
}

DWORD DumpAclInfo(PACL pacl, BOOL bDacl)
{
    int    aic;
    BYTE                     pByte[2][12];

    //
    // is the acl valid
    //
    _tprintf(TEXT("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n"));
    if (bDacl)
        _tprintf(TEXT(">>                 DACL INFORMATION                    >>\n"));
    else
        _tprintf(TEXT(">>                 SACL INFORMATION                    >>\n"));

    _tprintf(TEXT(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n"));
    _tprintf(TEXT("valid .............. "));

    if (!IsValidAcl(pacl)){
        _tprintf(TEXT("no\n"));
        return 0;
    }
    else
        _tprintf(TEXT("yes\n"));

    for (aic = 1; aic<3; aic++){
        if (!GetAclInformation(pacl, (LPVOID)pByte[aic - 1], sizeof(ACL_SIZE_INFORMATION), (ACL_INFORMATION_CLASS)aic))
            DisplayError(GetLastError(), TEXT("GetAclInformation"));
    }

    _tprintf(TEXT("revision ........... %u\n\n"), *((PACL_REVISION_INFORMATION)pByte[0]));
    _tprintf(TEXT("ace count .......... %u\n"), ((PACL_SIZE_INFORMATION)pByte[1])->AceCount);
    _tprintf(TEXT("acl bytes in use ... %u byte(s)\n"), ((PACL_SIZE_INFORMATION)pByte[1])->AclBytesInUse);
    _tprintf(TEXT("acl bytes free ..... %u byte(s)\n"), ((PACL_SIZE_INFORMATION)pByte[1])->AclBytesFree);

    return ((PACL_SIZE_INFORMATION)pByte[1])->AceCount;
}

void DumpControl(PSECURITY_DESCRIPTOR psd)
{
    DWORD                       dwRevision;
    SECURITY_DESCRIPTOR_CONTROL sdc;

    if (!GetSecurityDescriptorControl(psd, &sdc, &dwRevision))
        DisplayError(GetLastError(), TEXT("GetSecurityDescriptorControl"));

    _tprintf(TEXT("revision ........... %u\n"), dwRevision);
    _tprintf(TEXT("control bits ....... 0x%X\n"), sdc);

    if ((sdc & SE_DACL_DEFAULTED) == SE_DACL_DEFAULTED)
        _tprintf(TEXT(".................... SE_DACL_DEFAULTED\n"));
    if ((sdc & SE_DACL_PRESENT) == SE_DACL_PRESENT)
        _tprintf(TEXT(".................... SE_DACL_PRESENT\n"));
    if ((sdc & SE_GROUP_DEFAULTED) == SE_GROUP_DEFAULTED)
        _tprintf(TEXT(".................... SE_GROUP_DEFAULTED\n"));
    if ((sdc & SE_OWNER_DEFAULTED) == SE_OWNER_DEFAULTED)
        _tprintf(TEXT(".................... SE_OWNER_DEFAULTED\n"));
    if ((sdc & SE_SACL_DEFAULTED) == SE_SACL_DEFAULTED)
        _tprintf(TEXT(".................... SE_SACL_DEFAULTED\n"));
    if ((sdc & SE_SACL_PRESENT) == SE_SACL_PRESENT)
        _tprintf(TEXT(".................... SE_SACL_PRESENT\n"));
    if ((sdc & SE_SELF_RELATIVE) == SE_SELF_RELATIVE)
        _tprintf(TEXT(".................... SE_SELF_RELATIVE\n"));
    if ((sdc & SE_DACL_AUTO_INHERITED) == SE_DACL_AUTO_INHERITED) // NT5.0
        _tprintf(TEXT(".................... SE_DACL_AUTO_INHERITED\n"));
    if ((sdc & SE_SACL_AUTO_INHERITED) == SE_SACL_AUTO_INHERITED) // NT5.0
        _tprintf(TEXT(".................... SE_SACL_AUTO_INHERITED\n"));
    if ((sdc & SE_SACL_PROTECTED) == SE_SACL_PROTECTED) // NT5.0
        _tprintf(TEXT(".................... SE_SACL_PROTECTED\n"));
    if ((sdc & SE_DACL_PROTECTED) == SE_DACL_PROTECTED) // NT5.0
        _tprintf(TEXT(".................... SE_DACL_PROTECTED\n"));
}

void DumpDacl(PSECURITY_DESCRIPTOR psd, TCHAR c, BOOL bDacl)
{
    ACCESS_ALLOWED_ACE *pace;
    BOOL                bDaclPresent;
    BOOL                bDaclDefaulted;
    DWORD               dwAceCount;
    DWORD               cbName;
    DWORD               cbReferencedDomainName;
    DWORD               dwSize;
    int                 i;
    PACL                pacl;
    PSID                psid = NULL;
    SID_NAME_USE        snu;
    TCHAR               szName[UNLEN];
    TCHAR               szReferencedDomainName[DNLEN];
    TCHAR               szSidText[256];
    TCHAR               szSidType[][17] = { TEXT("User"), TEXT("Group"), TEXT("Domain"), TEXT("Alias"), TEXT("Well Known Group"), TEXT("Deleted Account"), TEXT("Invalid"), TEXT("Unknown") };

    if (bDacl){
        if (!GetSecurityDescriptorDacl(psd, &bDaclPresent, &pacl, &bDaclDefaulted))
            DisplayError(GetLastError(), TEXT("GetSecurityDescriptorDacTEXT("));
    }
    else{
        if (!GetSecurityDescriptorSacl(psd, &bDaclPresent, &pacl, &bDaclDefaulted))
            DisplayError(GetLastError(), TEXT("GetSecurityDescriptorSacTEXT("));
    }

    if (bDaclPresent){
        //
        // dump the dacl
        //
        if (pacl == NULL){
            if (bDacl)
                _tprintf(TEXT("\ndacl ............... NULL\n"));
            else
                _tprintf(TEXT("\nsacl ............... NULL\n"));
        }
        else{
            dwAceCount = DumpAclInfo(pacl, bDacl);

            for (i = 0; i < (int)dwAceCount; i++){
                if (!GetAce(pacl, i, (LPVOID*)&pace))
                    DisplayError(GetLastError(), TEXT("GetAce"));

                _tprintf(TEXT("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n"));
                _tprintf(TEXT(">>                  ACE #%u                             >>\n"), i + 1);
                _tprintf(TEXT(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n"));
                _tprintf(TEXT("type ............... "));

                switch (pace->Header.AceType){
                case ACCESS_ALLOWED_ACE_TYPE:
                    _tprintf(TEXT("ACCESS_ALLOWED_ACE\n"));
                    break;
                case ACCESS_DENIED_ACE_TYPE:
                    _tprintf(TEXT("ACCESS_DENIED_ACE\n"));
                    break;
                case SYSTEM_AUDIT_ACE_TYPE:
                    _tprintf(TEXT("SYSTEM_AUDIT_ACE\n"));
                    break;
                case ACCESS_ALLOWED_OBJECT_ACE_TYPE: // NT5.0
                    _tprintf(TEXT("ACCESS_ALLOWED_OBJECT_ACE_TYPE\n"));
                    break;
                case ACCESS_DENIED_OBJECT_ACE_TYPE: // NT5.0
                    _tprintf(TEXT("ACCESS_DENIED_OBJECT_ACE_TYPE\n"));
                    break;
                case SYSTEM_AUDIT_OBJECT_ACE_TYPE: // NT5.0
                    _tprintf(TEXT("SYSTEM_AUDIT_OBJECT_ACE_TYPE\n"));
                    break;
                }

                _tprintf(TEXT("flags .............. 0x%X\n"), pace->Header.AceFlags);

                if ((pace->Header.AceFlags & CONTAINER_INHERIT_ACE) == CONTAINER_INHERIT_ACE)
                    _tprintf(TEXT(".................... CONTAINER_INHERIT_ACE\n"));

                if ((pace->Header.AceFlags & INHERIT_ONLY_ACE) == INHERIT_ONLY_ACE)
                    _tprintf(TEXT(".................... INHERIT_ONLY_ACE\n"));

                if ((pace->Header.AceFlags & NO_PROPAGATE_INHERIT_ACE) == NO_PROPAGATE_INHERIT_ACE)
                    _tprintf(TEXT(".................... NO_PROPAGATE_INHERIT_ACE\n"));

                if ((pace->Header.AceFlags & OBJECT_INHERIT_ACE) == OBJECT_INHERIT_ACE)
                    _tprintf(TEXT(".................... OBJECT_INHERIT_ACE\n"));

                if ((pace->Header.AceFlags & FAILED_ACCESS_ACE_FLAG) == FAILED_ACCESS_ACE_FLAG)
                    _tprintf(TEXT(".................... FAILED_ACCESS_ACE_FLAG\n"));

                if ((pace->Header.AceFlags & SUCCESSFUL_ACCESS_ACE_FLAG) == SUCCESSFUL_ACCESS_ACE_FLAG)
                    _tprintf(TEXT(".................... SUCCESSFUL_ACCESS_ACE_FLAG\n"));

                if ((pace->Header.AceFlags & INHERITED_ACE) == INHERITED_ACE) // NT5.0
                    _tprintf(TEXT(".................... INHERITED_ACE\n"));

                _tprintf(TEXT("size ............... %u byte(s)\n"), pace->Header.AceSize);
                _tprintf(TEXT("mask ............... 0x%X\n"), pace->Mask);

                switch (c){
                case 'r':
                    //
                    // registry SPECIFIC access rights
                    //
                    if ((pace->Mask & KEY_CREATE_LINK) == KEY_CREATE_LINK)
                        _tprintf(TEXT(".................... KEY_CREATE_LINK\n"));
                    if ((pace->Mask & KEY_CREATE_SUB_KEY) == KEY_CREATE_SUB_KEY)
                        _tprintf(TEXT(".................... KEY_CREATE_SUB_KEY\n"));
                    if ((pace->Mask & KEY_ENUMERATE_SUB_KEYS) == KEY_ENUMERATE_SUB_KEYS)
                        _tprintf(TEXT(".................... KEY_ENUMERATE_SUB_KEYS\n"));
                    if ((pace->Mask & KEY_EXECUTE) == KEY_EXECUTE)
                        _tprintf(TEXT(".................... KEY_EXECUTE\n"));
                    if ((pace->Mask & KEY_NOTIFY) == KEY_NOTIFY)
                        _tprintf(TEXT(".................... KEY_NOTIFY\n"));
                    if ((pace->Mask & KEY_QUERY_VALUE) == KEY_QUERY_VALUE)
                        _tprintf(TEXT(".................... KEY_QUERY_VALUE\n"));
                    if ((pace->Mask & KEY_READ) == KEY_READ)
                        _tprintf(TEXT(".................... KEY_READ\n"));
                    if ((pace->Mask & KEY_SET_VALUE) == KEY_SET_VALUE)
                        _tprintf(TEXT(".................... KEY_SET_VALUE\n"));
                    if ((pace->Mask & KEY_WRITE) == KEY_WRITE)
                        _tprintf(TEXT(".................... KEY_WRITE\n"));
                    break;
                case 'f':
                    if ((pace->Mask & FILE_READ_DATA) == FILE_READ_DATA)
                        _tprintf(TEXT(".................... FILE_READ_DATA\n"));
                    if ((pace->Mask & FILE_WRITE_DATA) == FILE_WRITE_DATA)
                        _tprintf(TEXT(".................... FILE_WRITE_DATA\n"));
                    if ((pace->Mask & FILE_APPEND_DATA) == FILE_APPEND_DATA)
                        _tprintf(TEXT(".................... FILE_APPEND_DATA\n"));
                    if ((pace->Mask & FILE_READ_EA) == FILE_READ_EA)
                        _tprintf(TEXT(".................... FILE_READ_EA\n"));
                    if ((pace->Mask & FILE_WRITE_EA) == FILE_WRITE_EA)
                        _tprintf(TEXT(".................... FILE_WRITE_EA\n"));
                    if ((pace->Mask & FILE_EXECUTE) == FILE_EXECUTE)
                        _tprintf(TEXT(".................... FILE_EXECUTE\n"));
                    if ((pace->Mask & FILE_READ_ATTRIBUTES) == FILE_READ_ATTRIBUTES)
                        _tprintf(TEXT(".................... FILE_READ_ATTRIBUTES\n"));
                    if ((pace->Mask & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES)
                        _tprintf(TEXT(".................... FILE_WRITE_ATTRIBUTES\n"));
                    break;
                case 'd':
                    if ((pace->Mask & FILE_LIST_DIRECTORY) == FILE_LIST_DIRECTORY)
                        _tprintf(TEXT(".................... FILE_LIST_DIRECTORY\n"));
                    if ((pace->Mask & FILE_ADD_FILE) == FILE_ADD_FILE)
                        _tprintf(TEXT(".................... FILE_ADD_FILE\n"));
                    if ((pace->Mask & FILE_ADD_SUBDIRECTORY) == FILE_ADD_SUBDIRECTORY)
                        _tprintf(TEXT(".................... FILE_ADD_SUBDIRECTORY\n"));
                    if ((pace->Mask & FILE_READ_EA) == FILE_READ_EA)
                        _tprintf(TEXT(".................... FILE_READ_EA\n"));
                    if ((pace->Mask & FILE_WRITE_EA) == FILE_WRITE_EA)
                        _tprintf(TEXT(".................... FILE_WRITE_EA\n"));
                    if ((pace->Mask & FILE_TRAVERSE) == FILE_TRAVERSE)
                        _tprintf(TEXT(".................... FILE_TRAVERSE\n"));
                    if ((pace->Mask & FILE_DELETE_CHILD) == FILE_DELETE_CHILD)
                        _tprintf(TEXT(".................... FILE_DELETE_CHILD\n"));
                    if ((pace->Mask & FILE_READ_ATTRIBUTES) == FILE_READ_ATTRIBUTES)
                        _tprintf(TEXT(".................... FILE_READ_ATTRIBUTES\n"));
                    if ((pace->Mask & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES)
                        _tprintf(TEXT(".................... FILE_WRITE_ATTRIBUTES\n"));
                    break;
                case 'e':
                    if ((pace->Mask & EVENT_MODIFY_STATE) == EVENT_MODIFY_STATE)
                        _tprintf(TEXT(".................... EVENT_MODIFY_STATE\n"));
                    break;
                case 'm':
                    if ((pace->Mask & MUTANT_QUERY_STATE) == MUTANT_QUERY_STATE)
                        _tprintf(TEXT(".................... MUTANT_QUERY_STATE\n"));
                    break;
                case 's':
                    if ((pace->Mask & SEMAPHORE_MODIFY_STATE) == SEMAPHORE_MODIFY_STATE)
                        _tprintf(TEXT(".................... SEMAPHORE_MODIFY_STATE\n"));
                    break;
                case 'p':
                    if ((pace->Mask & PROCESS_TERMINATE) == PROCESS_TERMINATE)
                        _tprintf(TEXT(".................... PROCESS_TERMINATE\n"));
                    if ((pace->Mask & PROCESS_CREATE_THREAD) == PROCESS_CREATE_THREAD)
                        _tprintf(TEXT(".................... PROCESS_CREATE_THREAD\n"));
                    if ((pace->Mask & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
                        _tprintf(TEXT(".................... PROCESS_VM_OPERATION\n"));
                    if ((pace->Mask & PROCESS_VM_READ) == PROCESS_VM_READ)
                        _tprintf(TEXT(".................... PROCESS_VM_READ\n"));
                    if ((pace->Mask & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
                        _tprintf(TEXT(".................... PROCESS_VM_WRITE\n"));
                    if ((pace->Mask & PROCESS_DUP_HANDLE) == PROCESS_DUP_HANDLE)
                        _tprintf(TEXT(".................... PROCESS_DUP_HANDLE\n"));
                    if ((pace->Mask & PROCESS_CREATE_PROCESS) == PROCESS_CREATE_PROCESS)
                        _tprintf(TEXT(".................... PROCESS_CREATE_PROCESS\n"));
                    if ((pace->Mask & PROCESS_SET_QUOTA) == PROCESS_SET_QUOTA)
                        _tprintf(TEXT(".................... PROCESS_SET_QUOTA\n"));
                    if ((pace->Mask & PROCESS_SET_INFORMATION) == PROCESS_SET_INFORMATION)
                        _tprintf(TEXT(".................... PROCESS_SET_INFORMATION\n"));
                    if ((pace->Mask & PROCESS_QUERY_INFORMATION) == PROCESS_QUERY_INFORMATION)
                        _tprintf(TEXT(".................... PROCESS_QUERY_INFORMATION\n"));
                    break;
                case 'i':
                    if ((pace->Mask & SECTION_QUERY) == SECTION_QUERY)
                        _tprintf(TEXT(".................... SECTION_QUERY\n"));
                    if ((pace->Mask & SECTION_MAP_WRITE) == SECTION_MAP_WRITE)
                        _tprintf(TEXT(".................... SECTION_MAP_WRITE\n"));
                    if ((pace->Mask & SECTION_MAP_READ) == SECTION_MAP_READ)
                        _tprintf(TEXT(".................... SECTION_MAP_READ\n"));
                    if ((pace->Mask & SECTION_MAP_EXECUTE) == SECTION_MAP_EXECUTE)
                        _tprintf(TEXT(".................... SECTION_MAP_EXECUTE\n"));
                    if ((pace->Mask & SECTION_EXTEND_SIZE) == SECTION_EXTEND_SIZE)
                        _tprintf(TEXT(".................... SECTION_EXTEND_SIZE\n"));
                    break;
                case 'v':
                    if ((pace->Mask & SERVICE_CHANGE_CONFIG) == SERVICE_CHANGE_CONFIG)
                        _tprintf(TEXT(".................... SERVICE_CHANGE_CONFIG\n"));
                    if ((pace->Mask & SERVICE_ENUMERATE_DEPENDENTS) == SERVICE_ENUMERATE_DEPENDENTS)
                        _tprintf(TEXT(".................... SERVICE_ENUMERATE_DEPENDENTS\n"));
                    if ((pace->Mask & SERVICE_INTERROGATE) == SERVICE_INTERROGATE)
                        _tprintf(TEXT(".................... SERVICE_INTERROGATE\n"));
                    if ((pace->Mask & SERVICE_PAUSE_CONTINUE) == SERVICE_PAUSE_CONTINUE)
                        _tprintf(TEXT(".................... SERVICE_PAUSE_CONTINUE\n"));
                    if ((pace->Mask & SERVICE_QUERY_CONFIG) == SERVICE_QUERY_CONFIG)
                        _tprintf(TEXT(".................... SERVICE_QUERY_CONFIG\n"));
                    if ((pace->Mask & SERVICE_QUERY_STATUS) == SERVICE_QUERY_STATUS)
                        _tprintf(TEXT(".................... SERVICE_QUERY_STATUS\n"));
                    if ((pace->Mask & SERVICE_START) == SERVICE_START)
                        _tprintf(TEXT(".................... SERVICE_START\n"));
                    if ((pace->Mask & SERVICE_STOP) == SERVICE_STOP)
                        _tprintf(TEXT(".................... SERVICE_STOP\n"));
                    if ((pace->Mask & SERVICE_USER_DEFINED_CONTROL) == SERVICE_USER_DEFINED_CONTROL)
                        _tprintf(TEXT(".................... SERVICE_USER_DEFINED_CONTROL\n"));
                    break;
                case 'w':
                    if ((pace->Mask & WINSTA_ACCESSCLIPBOARD) == WINSTA_ACCESSCLIPBOARD)
                        _tprintf(TEXT(".................... WINSTA_ACCESSCLIPBOARD\n"));
                    if ((pace->Mask & WINSTA_ACCESSGLOBALATOMS) == WINSTA_ACCESSGLOBALATOMS)
                        _tprintf(TEXT(".................... WINSTA_ACCESSGLOBALATOMS\n"));
                    if ((pace->Mask & WINSTA_CREATEDESKTOP) == WINSTA_CREATEDESKTOP)
                        _tprintf(TEXT(".................... WINSTA_CREATEDESKTOP\n"));
                    if ((pace->Mask & WINSTA_ENUMDESKTOPS) == WINSTA_ENUMDESKTOPS)
                        _tprintf(TEXT(".................... WINSTA_ENUMDESKTOPS\n"));
                    if ((pace->Mask & WINSTA_ENUMERATE) == WINSTA_ENUMERATE)
                        _tprintf(TEXT(".................... WINSTA_ENUMERATE\n"));
                    if ((pace->Mask & WINSTA_EXITWINDOWS) == WINSTA_EXITWINDOWS)
                        _tprintf(TEXT(".................... WINSTA_EXITWINDOWS\n"));
                    if ((pace->Mask & WINSTA_READATTRIBUTES) == WINSTA_READATTRIBUTES)
                        _tprintf(TEXT(".................... WINSTA_READATTRIBUTES\n"));
                    if ((pace->Mask & WINSTA_READSCREEN) == WINSTA_READSCREEN)
                        _tprintf(TEXT(".................... WINSTA_READSCREEN\n"));
                    if ((pace->Mask & WINSTA_WRITEATTRIBUTES) == WINSTA_WRITEATTRIBUTES)
                        _tprintf(TEXT(".................... WINSTA_WRITEATTRIBUTES\n"));
                    break;
                case 'k':
                    if ((pace->Mask & DESKTOP_CREATEMENU) == DESKTOP_CREATEMENU)
                        _tprintf(TEXT(".................... DESKTOP_CREATEMENU\n"));
                    if ((pace->Mask & DESKTOP_CREATEWINDOW) == DESKTOP_CREATEWINDOW)
                        _tprintf(TEXT(".................... DESKTOP_CREATEWINDOW\n"));
                    if ((pace->Mask & DESKTOP_ENUMERATE) == DESKTOP_ENUMERATE)
                        _tprintf(TEXT(".................... DESKTOP_ENUMERATE\n"));
                    if ((pace->Mask & DESKTOP_HOOKCONTROL) == DESKTOP_HOOKCONTROL)
                        _tprintf(TEXT(".................... DESKTOP_HOOKCONTROL\n"));
                    if ((pace->Mask & DESKTOP_JOURNALPLAYBACK) == DESKTOP_JOURNALPLAYBACK)
                        _tprintf(TEXT(".................... DESKTOP_JOURNALPLAYBACK\n"));
                    if ((pace->Mask & DESKTOP_JOURNALRECORD) == DESKTOP_JOURNALRECORD)
                        _tprintf(TEXT(".................... DESKTOP_JOURNALRECORD\n"));
                    if ((pace->Mask & DESKTOP_READOBJECTS) == DESKTOP_READOBJECTS)
                        _tprintf(TEXT(".................... DESKTOP_READOBJECTS\n"));
                    if ((pace->Mask & DESKTOP_SWITCHDESKTOP) == DESKTOP_SWITCHDESKTOP)
                        _tprintf(TEXT(".................... DESKTOP_SWITCHDESKTOP\n"));
                    if ((pace->Mask & DESKTOP_WRITEOBJECTS) == DESKTOP_WRITEOBJECTS)
                        _tprintf(TEXT(".................... DESKTOP_WRITEOBJECTS\n"));
                    break;
                case 'l':
                    if ((pace->Mask & SERVER_ACCESS_ADMINISTER) == SERVER_ACCESS_ADMINISTER)
                        _tprintf(TEXT(".................... SERVER_ACCESS_ADMINISTER\n"));
                    if ((pace->Mask & SERVER_ACCESS_ENUMERATE) == SERVER_ACCESS_ENUMERATE)
                        _tprintf(TEXT(".................... SERVER_ACCESS_ENUMERATE\n"));
                    if ((pace->Mask & PRINTER_ACCESS_ADMINISTER) == PRINTER_ACCESS_ADMINISTER)
                        _tprintf(TEXT(".................... PRINTER_ACCESS_ADMINISTER\n"));
                    if ((pace->Mask & PRINTER_ACCESS_USE) == PRINTER_ACCESS_USE)
                        _tprintf(TEXT(".................... PRINTER_ACCESS_USE\n"));
                    if ((pace->Mask & JOB_ACCESS_ADMINISTER) == JOB_ACCESS_ADMINISTER)
                        _tprintf(TEXT(".................... JOB_ACCESS_ADMINISTER\n"));
                    break;
                case 't':
                    if ((pace->Mask & READ) == READ)
                        _tprintf(TEXT(".................... READ\n"));
                    if ((pace->Mask & CHANGE) == CHANGE)
                        _tprintf(TEXT(".................... CHANGE\n"));
                    if ((pace->Mask & WRITE) == WRITE)
                        _tprintf(TEXT(".................... WRITE\n"));
                    break;
                case 'o':
                    if ((pace->Mask & TOKEN_ADJUST_DEFAULT) == TOKEN_ADJUST_DEFAULT)
                        _tprintf(TEXT(".................... TOKEN_ADJUST_DEFAULT\n"));
                    if ((pace->Mask & TOKEN_ADJUST_GROUPS) == TOKEN_ADJUST_GROUPS)
                        _tprintf(TEXT(".................... TOKEN_ADJUST_GROUPSE\n"));
                    if ((pace->Mask & TOKEN_ADJUST_PRIVILEGES) == TOKEN_ADJUST_PRIVILEGES)
                        _tprintf(TEXT(".................... TOKEN_ADJUST_PRIVILEGES\n"));
                    if ((pace->Mask & TOKEN_ALL_ACCESS) == TOKEN_ALL_ACCESS)
                        _tprintf(TEXT(".................... TOKEN_ALL_ACCESS\n"));
                    if ((pace->Mask & TOKEN_ASSIGN_PRIMARY) == TOKEN_ASSIGN_PRIMARY)
                        _tprintf(TEXT(".................... TOKEN_ASSIGN_PRIMARY\n"));
                    if ((pace->Mask & TOKEN_DUPLICATE) == TOKEN_DUPLICATE)
                        _tprintf(TEXT(".................... TOKEN_DUPLICATE\n"));
                    if ((pace->Mask & TOKEN_EXECUTE) == TOKEN_EXECUTE)
                        _tprintf(TEXT(".................... TOKEN_EXECUTE\n"));
                    if ((pace->Mask & TOKEN_IMPERSONATE) == TOKEN_IMPERSONATE)
                        _tprintf(TEXT(".................... TOKEN_IMPERSONATE\n"));
                    if ((pace->Mask & TOKEN_QUERY) == TOKEN_QUERY)
                        _tprintf(TEXT(".................... TOKEN_QUERY\n"));
                    if ((pace->Mask & TOKEN_QUERY_SOURCE) == TOKEN_QUERY_SOURCE)
                        _tprintf(TEXT(".................... TOKEN_QUERY_SOURCE\n"));
                    if ((pace->Mask & TOKEN_READ) == TOKEN_READ)
                        _tprintf(TEXT(".................... TOKEN_READ\n"));
                    if ((pace->Mask & TOKEN_WRITE) == TOKEN_WRITE)
                        _tprintf(TEXT(".................... TOKEN_WRITE\n"));
                    break;
                case 'n':
                case 'a':
                    break;
                default:
                    break;
                }

                //
                // object rights
                //
                if ((pace->Mask & READ_CONTROL) == READ_CONTROL)
                    _tprintf(TEXT(".................... READ_CONTROL\n"));
                if ((pace->Mask & WRITE_OWNER) == WRITE_OWNER)
                    _tprintf(TEXT(".................... WRITE_OWNER\n"));
                if ((pace->Mask & WRITE_DAC) == WRITE_DAC)
                    _tprintf(TEXT(".................... WRITE_DAC\n"));
                if ((pace->Mask & DELETE) == DELETE)
                    _tprintf(TEXT(".................... DELETE\n"));
                if ((pace->Mask & SYNCHRONIZE) == SYNCHRONIZE)
                    _tprintf(TEXT(".................... SYNCHRONIZE\n"));
                if ((pace->Mask & ACCESS_SYSTEM_SECURITY) == ACCESS_SYSTEM_SECURITY)
                    _tprintf(TEXT(".................... ACCESS_SYSTEM_SECURITY\n"));

                //
                // GENERIC access rights
                //
                if ((pace->Mask & GENERIC_ALL) == GENERIC_ALL)
                    _tprintf(TEXT(".................... GENERIC_ALL\n"));
                if ((pace->Mask & GENERIC_EXECUTE) == GENERIC_EXECUTE)
                    _tprintf(TEXT(".................... GENERIC_EXECUTE\n"));
                if ((pace->Mask & GENERIC_READ) == GENERIC_READ)
                    _tprintf(TEXT(".................... GENERIC_READ\n"));
                if ((pace->Mask & GENERIC_WRITE) == GENERIC_WRITE)
                    _tprintf(TEXT(".................... GENERIC_WRITE\n"));

                //
                // display sid
                //
                cbName = sizeof(szName);
                cbReferencedDomainName = sizeof(szReferencedDomainName);
                ZeroMemory(szName, cbName);
                ZeroMemory(szReferencedDomainName, cbReferencedDomainName);

                if (!LookupAccountSid(NULL, &(pace->SidStart), szName, &cbName, szReferencedDomainName, &cbReferencedDomainName, &snu)){
                    if (GetLastError() == ERROR_NONE_MAPPED)
                        LookupAccountOtherSid(&(pace->SidStart), szName, &cbName, szReferencedDomainName, &cbReferencedDomainName, &snu);
                    else
                        DisplayError(GetLastError(), TEXT("LookupAccountSid"));
                }

                _tprintf(TEXT("\nuser ............... %s\\%s\n"), szReferencedDomainName, szName);
                dwSize = sizeof(szSidText);
                ZeroMemory(szSidText, dwSize);
                ConvertSid(&(pace->SidStart), szSidText, &dwSize);
                _tprintf(TEXT("sid ................ %s\n"), szSidText);
                _tprintf(TEXT("sid type ........... %s\n"), szSidType[snu - 1]);
                _tprintf(TEXT("sid size ........... %u bytes\n"), GetLengthSid(&(pace->SidStart)));
            }
        }
    }
    else{
        _tprintf(TEXT("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n"));
        if (bDacl)
            _tprintf(TEXT(">>                 NO DACL PRESENT                     >>\n"));
        else
            _tprintf(TEXT(">>                 NO SACL PRESENT                     >>\n"));


        _tprintf(TEXT(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n"));
    }
}

void DumpOwnerGroup(PSECURITY_DESCRIPTOR psd, BOOL bOwner)
{
    BOOL         bOwnerDefaulted;
    TCHAR        szSidType[][17] = { TEXT("User"), TEXT("Group"), TEXT("Domain"), TEXT("Alias"), TEXT("Well Known Group"), TEXT("Deleted Account"), TEXT("Invalid"), TEXT("Unknown") };
    PSID         psid = NULL;
    SID_NAME_USE snu;
    TCHAR        szName[UNLEN];
    TCHAR        szReferencedDomainName[DNLEN];
    DWORD        cbName = sizeof(szName);
    DWORD        cbReferencedDomainName = sizeof(szReferencedDomainName);
    TCHAR        szSidText[256] = TEXT("");
    DWORD        dwSize = sizeof(szSidText);
    TCHAR        szType[6] = TEXT("");

    if (bOwner){
        if (!GetSecurityDescriptorOwner(psd, &psid, &bOwnerDefaulted))
            DisplayError(GetLastError(), TEXT("GetSecurityDescriptorOwner"));
        lstrcpy(szType, TEXT("owner"));
    }
    else{
        if (!GetSecurityDescriptorGroup(psd, &psid, &bOwnerDefaulted))
            DisplayError(GetLastError(), TEXT("GetSecurityDescriptorGroup"));
        lstrcpy(szType, TEXT("group"));
    }

    if (psid == NULL)
        _tprintf(TEXT("%s .............. none\n"), szType);
    else{
        ZeroMemory(szName, cbName);
        ZeroMemory(szReferencedDomainName, cbReferencedDomainName);

        //
        // get the owner of the sid
        //
        if (!LookupAccountSid(NULL, psid, szName, &cbName, szReferencedDomainName, &cbReferencedDomainName, &snu)){
            if (GetLastError() != ERROR_NONE_MAPPED)
                DisplayError(GetLastError(), TEXT("LookupAccountSid"));
        }

        _tprintf(TEXT("\n%s .............. %s\\%s\n"), szType, szReferencedDomainName, szName);
        ConvertSid(psid, szSidText, &dwSize);
        _tprintf(TEXT("sid ................ %s\n"), szSidText);
        _tprintf(TEXT("sid type ........... %s\n"), szSidType[snu - 1]);
    }
}

void DumpSD(PSECURITY_DESCRIPTOR psd, TCHAR c)
{
    //
    // dump security descriptor information
    //
    DumpSDInfo(psd);

    //
    // dump the control bits
    //
    DumpControl(psd);

    //
    // get the owner
    //
    DumpOwnerGroup(psd, TRUE);

    //
    // get the group
    //
    DumpOwnerGroup(psd, FALSE);

    //
    // get the dacl
    //
    DumpDacl(psd, c, TRUE);

    //
    // get the sacl
    //
    DumpDacl(psd, c, FALSE);
}

void DumpSDInfo(PSECURITY_DESCRIPTOR psd)
{
    DWORD dwSDLength;

    //
    // is the security descriptor valid
    //
    _tprintf(TEXT("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n"));
    _tprintf(TEXT(">>          SECURITY DESCRIPTOR INFORMATION            >>\n"));
    _tprintf(TEXT(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\nvalid .............. "));

    if (!IsValidSecurityDescriptor(psd)){
        _tprintf(TEXT("no\n"));
        return;
    }
    else
        _tprintf(TEXT("yes\n"));

    //
    // security descriptor size???
    //
    dwSDLength = GetSecurityDescriptorLength(psd);

    _tprintf(TEXT("length ............. %u byte(s)\n"), dwSDLength);
}


void DisplayUsage(void)
{
    _tprintf(TEXT("\nUsage: check_sd [object] [name]\n"));
    _tprintf(TEXT(" -a : mailslot, use \\\\[server]\\mailslot\\[mailslotname]\n"));
    _tprintf(TEXT(" -d : directory or driver letter, use \\\\.\\[driveletter]\n"));
    _tprintf(TEXT(" -e : event\n"));
    _tprintf(TEXT(" -f : file\n"));
    _tprintf(TEXT(" -i : memory mapped file\n"));
    _tprintf(TEXT(" -k : desktop, use [window station\\desktop]\n"));
    _tprintf(TEXT(" -l : printer, use \\\\[server]\\[printername]\n"));
    _tprintf(TEXT(" -m : mutex\n"));
    _tprintf(TEXT(" -n : named pipe, use \\\\[server or .]\\pipe\\[pipename]\n"));
    _tprintf(TEXT(" -o : process access token, use pid instead of name\n"));
    _tprintf(TEXT(" -p : process, use pid instead of name\n"));
    _tprintf(TEXT(" -r : registry key\n"));
    _tprintf(TEXT(" -s : sempahore\n"));
    _tprintf(TEXT(" -t : network share, use [server\\sharename]\n"));
    _tprintf(TEXT(" -v : service\n"));
    _tprintf(TEXT(" -w : window station\n"));
    return;
}

int _tmain(int argc, TCHAR *argv[])
{
    //
    // display usage
    //
    if (argc != 3){
        DisplayUsage();
        return 0;
    }

    _tprintf(TEXT(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n"));
    _tprintf(TEXT(">>                 SECURITY INFORMATION                >>\n"));
    _tprintf(TEXT(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n\n"));
    _tprintf(TEXT("object name ........ %s\n"), argv[2]);
    _tprintf(TEXT("object type ........ "));

    switch (argv[1][1])
    {
    case 'a':
        _tprintf(TEXT("mailslot\n"));
        DumpKernelObject(argv[2], argv[1][1]);
        break;
    case 'e':
        _tprintf(TEXT("event\n"));
        DumpKernelObject(argv[2], argv[1][1]);
        break;
    case 'f':
        _tprintf(TEXT("file\n"));
        DumpFile(argv[2], argv[1][1]);
        break;
    case 'd':
        _tprintf(TEXT("directory\n"));
        DumpFile(argv[2], argv[1][1]);
        break;
    case 'm':
        _tprintf(TEXT("mutex\n"));
        DumpKernelObject(argv[2], argv[1][1]);
        break;
    case 'r':
        _tprintf(TEXT("registry\n"));
        DumpRegistryKey(argv[2]);
        break;
    case 's':
        _tprintf(TEXT("semaphore\n"));
        DumpKernelObject(argv[2], argv[1][1]);
        break;
    case 'p':
        _tprintf(TEXT("process\n"));
        DumpKernelObject(argv[2], argv[1][1]);
        break;
    case 'i':
        _tprintf(TEXT("memory mapped file\n"));
        DumpKernelObject(argv[2], argv[1][1]);
        break;
    case 'v':
        _tprintf(TEXT("service\n"));
        DumpService(NULL, argv[2]);
        break;
    case 'w':
        _tprintf(TEXT("window station\n"));
        DumpUserObject(argv[2], argv[1][1]);
        break;
    case 'k':
        _tprintf(TEXT("desktop\n"));
        DumpUserObject(argv[2], argv[1][1]);
        break;
    case 'n':
        _tprintf(TEXT("named pipe\n"));
        DumpKernelObject(argv[2], argv[1][1]);
        break;
    case 'o':
        _tprintf(TEXT("process access token\n"));
        DumpKernelObject(argv[2], argv[1][1]);
        break;
    case 'l':
        _tprintf(TEXT("printer\n"));
        DumpPrinter(argv[2]);
        break;
    case 't':
        _tprintf(TEXT("network share\n"));
        DumpNetShare(argv[2]);
        break;
    default:
        DisplayUsage();
    }
    return 0;
}
