// ListGroups.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <lm.h>

void PrintLocalGroups() 
{
    ULONG_PTR lResume = 0;
    ULONG  lTotal = 0;
    ULONG  lReturned = 0;
    ULONG  lIndex = 0;
    NET_API_STATUS netStatus;
    //LOCALGROUP_INFO_0* pinfoGroup;
    LOCALGROUP_INFO_1* pinfoGroup;

    do {
        netStatus = NetLocalGroupEnum(NULL, 1, (PBYTE*)&pinfoGroup,
            MAX_PREFERRED_LENGTH, &lReturned, &lTotal, &lResume);
        if ((netStatus == ERROR_MORE_DATA) ||
            (netStatus == NERR_Success)) {

            for (lIndex = 0; lIndex < lReturned; lIndex++) {
                //wprintf(L"%s\n", pinfoGroup[lIndex].lgrpi1_name);
                wprintf(L"%s %s\n", pinfoGroup[lIndex].lgrpi1_name, pinfoGroup[lIndex].lgrpi1_comment);
            }
            NetApiBufferFree(pinfoGroup);
        }
    } while (netStatus == ERROR_MORE_DATA);
}

void PrintLocalGroups1()
{
    PNET_DISPLAY_GROUP pBuff, p;
    DWORD res, dwRec, i = 0;
    
    //
    //pass a NULL or empty stringto retrieve the local information.
    //
    TCHAR szServer[255] = TEXT("");
    do
    {
        //
        // Call the NetQueryDisplayInformation function, specify information level 3 (group account information).
        //
        res = NetQueryDisplayInformation(szServer, 3, i, 1000, MAX_PREFERRED_LENGTH, &dwRec, (PVOID*)&pBuff);
        //
        // If the call succeeds,
        //
        if ((res == ERROR_SUCCESS) || (res == ERROR_MORE_DATA))
        {
            p = pBuff;
            for (; dwRec > 0; dwRec--)
            {
                //
                // Print the retrieved group information.
                //
                printf("Name:      %S\n"
                    "Comment:   %S\n"
                    "Group ID:  %u\n"
                    "Attributes: %u\n"
                    "--------------------------------\n",
                    p->grpi3_name,
                    p->grpi3_comment,
                    p->grpi3_group_id,
                    p->grpi3_attributes);
                //
                // If there is more data, set the index.
                //
                i = p->grpi3_next_index;
                p++;
            }
            //
            // Free the allocated memory.
            //
            NetApiBufferFree(pBuff);
        }
        else
            printf("Error: %u\n", res);
        //
        // Continue while there is more data.
        //
    } while (res == ERROR_MORE_DATA); // end do
}

void PrintLocalUsers1()
{
    PNET_DISPLAY_USER pBuff, p;
    DWORD res, dwRec, i = 0;

    //
    //pass a NULL or empty stringto retrieve the local information.
    //
    TCHAR szServer[255] = TEXT("");
    do
    {
        //
        // Call the NetQueryDisplayInformation function, specify information level 3 (group account information).
        //
        res = NetQueryDisplayInformation(szServer, 1, i, 1000, MAX_PREFERRED_LENGTH, &dwRec, (PVOID*)&pBuff);
        //
        // If the call succeeds,
        //
        if ((res == ERROR_SUCCESS) || (res == ERROR_MORE_DATA))
        {
            p = pBuff;
            for (; dwRec > 0; dwRec--)
            {
                //
                // Print the retrieved group information.
                //
                printf(L"Name:      %ws\n"
                    L"Comment:   %ws\n"
                    L"Full Name:  %ws\n"
                    L"Id: %u\n"
                    L"--------------------------------\n",
                    p->usri1_name,
                    p->usri1_comment,
                    p->usri1_full_name,
                    p->usri1_user_id);
                //
                // If there is more data, set the index.
                //
                i = p->usri1_next_index;
                p++;
            }
            //
            // Free the allocated memory.
            //
            NetApiBufferFree(pBuff);
        }
        else
            printf("Error: %u\n", res);
        //
        // Continue while there is more data.
        //
    } while (res == ERROR_MORE_DATA); // end do
}

int _tmain(int argc, _TCHAR* argv[])
{
    PrintLocalUsers1();
	return 0;
}

