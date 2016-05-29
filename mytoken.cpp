// mytoken.cpp : Defines the entry point for the console application.
//




/*

Module: MYTOKEN.C

When you log on to a Microsoft Windows NT workstation, NT generates
an Access Token that describes who you are, what groups you belong to,
and what privileges you have on that workstation.

The following sample code demonstrates how to extract this interesting
information from the current process token. When I look at this information
I tend to seperate it into three categories

1. User identification and miscellaneous info
2. Group information
3. Privileges

Notes about the group information:

1) You will see a group sid with the form DOMAIN\NONE_MAPPED. This is
the login SID generated for this particular logon session. It is
unique until the server is rebooted.

2) Many of the group SIDS are well-known SIDs and RIDs. Consult the
documentation for information about these well-known Identifiers.

Notes about the privileges information:

The attributes number is simply a bit flag. 1 indicates that the
privilege is enabled and 2 indicates that the privilege is enabled
by default. 3, of course, indicates that it is enabled by default
and currently enabled.


This code sample requires the following import libraries:

advapi32.lib
user32.lib

David Mowers (davemo)   16-Feb-98

*/

#include "stdafx.h"
#include <windows.h>
#include <conio.h>
#include <stdio.h>

#define MAX_NAME 256


LPVOID AllocateTokenInfoBuffer(
    HANDLE hToken,
    TOKEN_INFORMATION_CLASS InfoClass,
    DWORD *dwSize);

void wmain(int argc, wchar_t *argv[])
{

    WORD i; // how could we do without an i?
    BOOL           bRes;

    // Handles

    HANDLE hProcess;
    HANDLE hToken;

    // various info buffers

    TOKEN_GROUPS *pGroupInfo;
    TOKEN_USER *pUserInfo;
    TOKEN_OWNER *pOwnerInfo;
    TOKEN_STATISTICS *pStatistics;
    TOKEN_PRIMARY_GROUP *pPrimaryInfo;
    TOKEN_PRIVILEGES *pPrivileges;
    TOKEN_SOURCE *pSource;

    // privilege variables

    TCHAR          szPrivilegeName[128];
    DWORD          dwPrivilegeNameLength;
    DWORD dwSize = 0;
    DWORD dwResult;

    // SID variables

    SID_NAME_USE SidType;
    char lpName[MAX_NAME];
    char lpDomain[MAX_NAME];


    hProcess = GetCurrentProcess();
    OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken);


    //
    // Get User Information
    //

    pUserInfo = (TOKEN_USER *)AllocateTokenInfoBuffer(hToken, TokenUser, &dwSize);

    bRes = GetTokenInformation(
        hToken,
        TokenUser,
        pUserInfo,
        dwSize, &dwSize);

    if (FALSE == bRes)
    {
        wprintf(L"GetTokenInformation failed\n");
        ExitProcess(EXIT_FAILURE);
    }

    if (!LookupAccountSid(
        NULL,                      // lookup on local system
        pUserInfo->User.Sid,
        lpName,                    // buffer to recieve name
        &dwSize,
        lpDomain,
        &dwSize,
        &SidType))
    {
        dwResult = GetLastError();
        if (dwResult == ERROR_NONE_MAPPED)
            strcpy(lpName, "NONE_MAPPED");
        else
        {
            printf("LookupAccountSid Error %u\n", GetLastError());
            exit(0);
        }
    }

    printf("User : %s\\%s\n", lpDomain, lpName);

    LocalFree(pUserInfo);

    //
    // Get Owner information
    //

    pOwnerInfo = (PTOKEN_OWNER)AllocateTokenInfoBuffer(hToken, TokenOwner, &dwSize);

    // Make the "real" call
    //
    bRes = GetTokenInformation(hToken,
        TokenOwner,
        pOwnerInfo,
        dwSize, &dwSize);
    if (FALSE == bRes)
    {
        printf("GetTokenInformation failed (%lui)\n", GetLastError());
        ExitProcess(EXIT_FAILURE);
    }

    if (!LookupAccountSid(
        NULL,                      // lookup on local system
        pOwnerInfo->Owner,
        lpName,                    // buffer to recieve name
        &dwSize,
        lpDomain,
        &dwSize,
        &SidType))
    {
        dwResult = GetLastError();
        if (dwResult == ERROR_NONE_MAPPED)
            strcpy(lpName, "NONE_MAPPED");
        else
        {
            printf("LookupAccountSid Error %u\n", GetLastError());
            exit(0);
        }
    }

    printf("Owner : %s\\%s\n", lpDomain, lpName);

    LocalFree(pOwnerInfo);

    //
    // Now get Primary Group
    //

    pPrimaryInfo = (PTOKEN_PRIMARY_GROUP)AllocateTokenInfoBuffer(
        hToken,
        TokenPrimaryGroup,
        &dwSize);

    // Make the "real" call
    //
    bRes = GetTokenInformation(hToken,
        TokenPrimaryGroup,
        pPrimaryInfo,
        dwSize, &dwSize);
    if (FALSE == bRes) {
        fprintf(stderr, "GetTokenInformation failed\n");
        ExitProcess(EXIT_FAILURE);
    }

    if (!LookupAccountSid(
        NULL,                      // lookup on local system
        pPrimaryInfo->PrimaryGroup,
        lpName,                    // buffer to recieve name
        &dwSize,
        lpDomain,
        &dwSize,
        &SidType))
    {
        dwResult = GetLastError();
        if (dwResult == ERROR_NONE_MAPPED)
            strcpy(lpName, "NONE_MAPPED");
        else
        {
            printf("LookupAccountSid Error %u\n", GetLastError());
            exit(0);
        }
    }

    printf("Primary Group : %s\\%s\n", lpDomain, lpName);

    LocalFree(pPrimaryInfo);


    //
    // Display some of the token statistics information
    //

    pStatistics = (PTOKEN_STATISTICS)AllocateTokenInfoBuffer(
        hToken,
        TokenStatistics,
        &dwSize);

    bRes = GetTokenInformation(hToken,
        TokenStatistics,
        pStatistics,
        dwSize, &dwSize);

    if (FALSE == bRes) {
        fprintf(stderr, "GetTokenInformation failed\n");
        ExitProcess(EXIT_FAILURE);
    }

    printf("LUID for this instance of token %i64\n", pStatistics->TokenId);
    printf("LUID for this logon session     %i64\n", pStatistics->AuthenticationId);

    if (pStatistics->TokenType == TokenPrimary)
        printf("Token is type PRIMARY\n");
    else
        printf("Token is type IMPERSONATION\n");

    //
    // Display source of token
    //

    pSource = (PTOKEN_SOURCE)AllocateTokenInfoBuffer(hToken, TokenSource, &dwSize);

    bRes = GetTokenInformation(
        hToken,
        TokenSource,
        pSource,
        dwSize,
        &dwSize);

    if (FALSE == bRes) {
        fprintf(stderr, "GetTokenInformation failed\n");
        ExitProcess(EXIT_FAILURE);
    }

    printf("Token source is <%s>\n", pSource->SourceName);

    LocalFree(pSource);

    //
    //  List all groups
    //

    printf("\nRetrieving Group information from current process token\n");

    pGroupInfo = (PTOKEN_GROUPS)AllocateTokenInfoBuffer(
        hToken,
        TokenGroups,
        &dwSize);

    // make the real call
    if (!GetTokenInformation(hToken, TokenGroups, pGroupInfo, dwSize, &dwSize))
    {
        dwResult = GetLastError();
        printf("GetTokenInformation Error %u\n", dwResult);
        exit(0);
    }

    for (i = 0; i<pGroupInfo->GroupCount; i++)
    {

        dwSize = MAX_NAME;

        if (!LookupAccountSid(
            NULL,                      // lookup on local system
            pGroupInfo->Groups[i].Sid,
            lpName,                    // buffer to recieve name
            &dwSize,
            lpDomain,
            &dwSize,
            &SidType))
        {
            dwResult = GetLastError();
            if (dwResult == ERROR_NONE_MAPPED)
                strcpy(lpName, "NONE_MAPPED");
            else
            {
                printf("LookupAccountSid Error %u\n", GetLastError());
                exit(0);
            }
        }


        printf("SID %d Group: %s\\%s\n", i, lpDomain, lpName);

    }

    LocalFree(pGroupInfo);

    //
    // Display privileges associated with this token
    //

    pPrivileges = (PTOKEN_PRIVILEGES)AllocateTokenInfoBuffer(hToken, TokenPrivileges, &dwSize);

    bRes = GetTokenInformation(
        hToken,
        TokenPrivileges,
        pPrivileges,
        dwSize, &dwSize);

    if (FALSE == bRes) {
        fprintf(stderr, "GetTokenInformation failed\n");
        ExitProcess(EXIT_FAILURE);
    }

    printf("\nPrivileges associated with this token (%lu)\n", pPrivileges->PrivilegeCount);

    for (i = 0; i<pPrivileges->PrivilegeCount; i++)
    {
        dwPrivilegeNameLength = 128;

        if (LookupPrivilegeName(
            NULL,
            &pPrivileges->Privileges[i].Luid,
            szPrivilegeName,
            &dwPrivilegeNameLength))

            printf("%s - (attributes) %lu\n", szPrivilegeName, pPrivileges->Privileges[i].Attributes);
        else
            printf("LookupPrivilegeName failed - %lu\n", GetLastError());

    }

    LocalFree(pPrivileges);

}


LPVOID AllocateTokenInfoBuffer(
    HANDLE hToken,
    TOKEN_INFORMATION_CLASS InfoClass,
    DWORD *dwSize)
{
    BOOL bRes;

    *dwSize = 0;
    //
    // Determine size of buffer needed
    //

    bRes = GetTokenInformation(
        hToken,
        InfoClass,
        NULL,
        *dwSize, dwSize);

    //
    // Allocate a buffer for our token data
    //
    return(LocalAlloc(LPTR, *dwSize));

}


