/******************************************************************************
Module:  EditTrusteeList.h
Notices: Copyright (c) 2000 Jeffrey Richter
******************************************************************************/


//#include "..\CmnHdr.h"                 // See Appendix A.
//#include <WindowsX.h>

#include <CommCtrl.h>
#pragma comment(lib, "ComCtl32")


// State and parameter data for the trustee dialog box
typedef struct _TrusteeListInfo {
   // In parameter
   LOCALGROUP_MEMBERS_INFO_0* m_pinfoTrustees;
   int                        m_nTrusteeCount;
   PTSTR                      m_szTitle;
   PTSTR                      m_szSystem;

   // Out parameter
   LOCALGROUP_MEMBERS_INFO_0* m_pinfoTrusteesAdded;
   int                        m_nAddedCount;
   LOCALGROUP_MEMBERS_INFO_0* m_pinfoTrusteesRemoved;
   int                        m_nRemovedCount;

   // State
   BOOL                       m_fOk;
   CUILayout                  m_UILayout;
   int                        m_nTotalAddedSIDBytes;
   int                        m_nTotalRemovedSIDBytes;
   PBOOL                      m_pfRemovedMap;
} TRUSTEELISTINFO, *PTRUSTEELISTINFO;


// Structure associated with trustee items in the trustee dialog box
typedef struct _TrusteeItemInfo {
   PSID m_pSID;
   int  m_nOriginalIndex; // -1 if Added
} TRUSTEEITEMINFO, *PTRUSTEEITEMINFO;


///////////////////////////////////////////////////////////////////////////////


void InsertTrustee(HWND hwndList, PTRUSTEELISTINFO ptlInfo, PSID pSid,
   PTSTR pszName, PTSTR pszDomain, SID_NAME_USE sidUse, int nOriginalIndex) {

   try { {
      // Create caption
      CAutoBuf<TCHAR, sizeof(TCHAR)> szCaption;
      szCaption = lstrlen(pszDomain) + lstrlen(pszName) + 2;
      lstrcpy(szCaption, pszDomain);
      lstrcat(szCaption, TEXT("\\"));
      lstrcat(szCaption, pszName);

      // Allocate buffer for item info
      PTRUSTEEITEMINFO pinfoItem = (PTRUSTEEITEMINFO) 
         LocalAlloc(LPTR, sizeof(*pinfoItem));
      if (pinfoItem == NULL)
         goto leave;

      PSID pSidNew = NULL;
      pinfoItem->m_nOriginalIndex = nOriginalIndex;
      if (nOriginalIndex >= 0) {
         // Did we already have the SID?
         pinfoItem->m_pSID = 
            ptlInfo->m_pinfoTrustees[nOriginalIndex].lgrmi0_sid;
      } else {
         // This is a real addition requiring an allocation for a SID
         pSidNew = LocalAlloc(LPTR, GetLengthSid(pSid));
         if (pSidNew == NULL) {
            LocalFree(pinfoItem);
            goto leave;
         }
         CopySid(GetLengthSid(pSid), pSidNew, pSid);
         pinfoItem->m_pSID = pSidNew;
      }

      // Setup the item
      LVITEM lvItem = { 0 };
      lvItem.mask = LVIF_TEXT | LVIF_PARAM | LVIF_IMAGE;
      lvItem.iItem = 0;
      lvItem.iSubItem = 0;
      lvItem.pszText = szCaption;
      lvItem.lParam = (LPARAM) pinfoItem;
      
      switch (sidUse) {
      case SidTypeUser:
         lvItem.iImage = 1;
         break;

      case SidTypeAlias:
      case SidTypeWellKnownGroup:
      case SidTypeGroup:
         lvItem.iImage = 0;
         break;

      default:
         lvItem.iImage = 5;
      }
      ListView_InsertItem(hwndList, &lvItem);
   } 
leave:;
   }
   catch (...) {
   }
}


///////////////////////////////////////////////////////////////////////////////


void RemoveSelectedTrustees(HWND hwndList, PTRUSTEELISTINFO ptlInfo) {

   // Find selected items
   int nIndex;
   while ((nIndex = ListView_GetNextItem(hwndList, -1, LVNI_SELECTED)) != -1) {

      LVITEM lvItem = {0};
      lvItem.mask = LVIF_PARAM;
      lvItem.iItem = nIndex;
      lvItem.iSubItem = 0;
      ListView_GetItem(hwndList, &lvItem);

      // Get an info structure
      PTRUSTEEITEMINFO pinfoItem = (PTRUSTEEITEMINFO) lvItem.lParam;

      // Did the user add this trustee
      if (pinfoItem->m_nOriginalIndex < 0) {

         // Unadd him then, and free the SID
         ptlInfo->m_nTotalAddedSIDBytes -= GetLengthSid(pinfoItem->m_pSID);
         ptlInfo->m_nAddedCount--;
         LocalFree(pinfoItem->m_pSID);
      } else {
         // Original trustee?  Then add him to the removed list
         ptlInfo->m_nRemovedCount++;
         ptlInfo->m_pfRemovedMap[pinfoItem->m_nOriginalIndex] = TRUE;
         ptlInfo->m_nTotalRemovedSIDBytes += GetLengthSid(pinfoItem->m_pSID);
      }

      // Free the info structure and delete item from control
      LocalFree(pinfoItem);
      ListView_DeleteItem(hwndList, nIndex);
   }
}


///////////////////////////////////////////////////////////////////////////////


void TrusteeToAddedList(HWND hwndList, PTRUSTEELISTINFO ptlInfo, PSID pSid,
   PTSTR pszDomain, PTSTR pszName, SID_NAME_USE sidUse) {

   try {
      BOOL fAdd = TRUE;
      
      // Iterate through original trustees
      int nIndex = ptlInfo->m_nTrusteeCount;
      while (nIndex-- > 0) {

         // Are we adding a trustee that is in our original list?
         if (EqualSid(pSid, ptlInfo->m_pinfoTrustees[nIndex].lgrmi0_sid)) {

            // If yes, did we previously remove the trustee?
            if (ptlInfo->m_pfRemovedMap[nIndex]) {

               // Then insert him
               InsertTrustee(hwndList, ptlInfo, pSid, pszName, pszDomain,
                  sidUse, nIndex);

               // No longer removed, account for that
               ptlInfo->m_pfRemovedMap[nIndex] = FALSE;
               ptlInfo->m_nRemovedCount--;
               ptlInfo->m_nTotalRemovedSIDBytes -= GetLengthSid(pSid);
            }
            
            // Either way, no need to add the trustee to the "added list"
            fAdd = FALSE;

         } // else we don't need to add it because it is already there
      }

      if (fAdd) {
         // Add trustee to the "added list"
         InsertTrustee(hwndList, ptlInfo, pSid, pszName, pszDomain,
            sidUse, -1);
         ptlInfo->m_nAddedCount++;
         ptlInfo->m_nTotalAddedSIDBytes += GetLengthSid(pSid);
      }
   }
   catch (...) {
   }
}


///////////////////////////////////////////////////////////////////////////////


void PickTrustees(HWND hwnd, PTRUSTEELISTINFO ptlInfo) {

   BOOL fGotStgMedium = FALSE;
   STGMEDIUM stgmedium = { TYMED_HGLOBAL, NULL, NULL };
   IDsObjectPicker* pdsObjectPicker = NULL;
   IDataObject* pdoNames = NULL;

   try { {
      FORMATETC formatetc = {
        (CLIPFORMAT) RegisterClipboardFormat(CFSTR_DSOP_DS_SELECTION_LIST),
        NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };

      // Yes the object picker is a COM interface
      HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
      if (FAILED(hr)) goto leave;

      // Create an instance of the object picker.
      hr = CoCreateInstance(CLSID_DsObjectPicker, NULL, CLSCTX_INPROC_SERVER,
         IID_IDsObjectPicker, (void**) &pdsObjectPicker);
      if (FAILED(hr)) goto leave;

      // Initialize the object picker instance.
      // The scope in our case is the the current system
      DSOP_SCOPE_INIT_INFO dsopScopeInitInfo[2];
      ZeroMemory(dsopScopeInitInfo, sizeof(dsopScopeInitInfo));
      dsopScopeInitInfo[0].cbSize = sizeof(DSOP_SCOPE_INIT_INFO);
      dsopScopeInitInfo[0].flType = DSOP_SCOPE_TYPE_TARGET_COMPUTER;
      dsopScopeInitInfo[0].flScope = DSOP_SCOPE_FLAG_STARTING_SCOPE
         | DSOP_SCOPE_FLAG_WANT_PROVIDER_WINNT;

      // What are we selecting?
      dsopScopeInitInfo[0].FilterFlags.Uplevel.flBothModes = DSOP_FILTER_USERS
         | DSOP_FILTER_BUILTIN_GROUPS
         | DSOP_FILTER_UNIVERSAL_GROUPS_SE
         | DSOP_FILTER_GLOBAL_GROUPS_SE
         | DSOP_FILTER_DOMAIN_LOCAL_GROUPS_SE;
      dsopScopeInitInfo[0].FilterFlags.flDownlevel =
         DSOP_DOWNLEVEL_FILTER_ALL_WELLKNOWN_SIDS
         | DSOP_DOWNLEVEL_FILTER_LOCAL_GROUPS
         | DSOP_DOWNLEVEL_FILTER_GLOBAL_GROUPS
         | DSOP_DOWNLEVEL_FILTER_USERS;

      // The scope in our case is just about everything
      dsopScopeInitInfo[1].cbSize = sizeof(DSOP_SCOPE_INIT_INFO);
      dsopScopeInitInfo[1].flType = DSOP_SCOPE_TYPE_DOWNLEVEL_JOINED_DOMAIN
         | DSOP_SCOPE_TYPE_USER_ENTERED_DOWNLEVEL_SCOPE
         | DSOP_SCOPE_TYPE_ENTERPRISE_DOMAIN
         | DSOP_SCOPE_TYPE_USER_ENTERED_UPLEVEL_SCOPE;
      dsopScopeInitInfo[1].flScope = DSOP_SCOPE_FLAG_WANT_PROVIDER_WINNT;

      // What are we selecting?
      dsopScopeInitInfo[1].FilterFlags.Uplevel.flBothModes =
         DSOP_FILTER_USERS
         | DSOP_FILTER_BUILTIN_GROUPS
         | DSOP_FILTER_GLOBAL_GROUPS_SE
         | DSOP_FILTER_UNIVERSAL_GROUPS_SE
         | DSOP_FILTER_DOMAIN_LOCAL_GROUPS_SE;

      dsopScopeInitInfo[1].FilterFlags.flDownlevel =
         DSOP_DOWNLEVEL_FILTER_ALL_WELLKNOWN_SIDS
         | DSOP_DOWNLEVEL_FILTER_LOCAL_GROUPS
         | DSOP_DOWNLEVEL_FILTER_GLOBAL_GROUPS
         | DSOP_DOWNLEVEL_FILTER_USERS;

      // Initialize the DSOP_INIT_INFO structure.
      DSOP_INIT_INFO dsopInitInfo = { 0 };
      dsopInitInfo.cbSize = sizeof(dsopInitInfo);
      dsopInitInfo.pwzTargetComputer = ptlInfo->m_szSystem;  // local computer
      dsopInitInfo.cDsScopeInfos = 2;
      dsopInitInfo.aDsScopeInfos = dsopScopeInitInfo;
      dsopInitInfo.flOptions = DSOP_FLAG_MULTISELECT;

      // Actually initialize the object
      hr = pdsObjectPicker->Initialize(&dsopInitInfo);
      if (FAILED(hr)) goto leave;

      // Invoke the modal dialog where the user selects the user or group
      hr = pdsObjectPicker->InvokeDialog(hwnd, &pdoNames);
      if (FAILED(hr)) goto leave;

      if (hr == S_OK) {
         // Get the global memory block containing the user's selections.
         hr = pdoNames->GetData(&formatetc, &stgmedium);
         if (FAILED(hr)) goto leave;
         fGotStgMedium = TRUE;

         // Retrieve pointer to DS_SELECTION_LIST structure.
         PDS_SELECTION_LIST pdsSelList = (PDS_SELECTION_LIST)
            GlobalLock(stgmedium.hGlobal);
         if (pdsSelList == NULL) goto leave;

         CAutoBuf<SID> pSid;
         CAutoBuf<TCHAR, sizeof(TCHAR)> szDomain;
         int nIndex = pdsSelList->cItems;
         while (nIndex-- != 0) {
            SID_NAME_USE sidUse;
            BOOL fOk;
            do {
               fOk = LookupAccountName(ptlInfo->m_szSystem,
                  pdsSelList->aDsSelection[nIndex].pwzName, pSid, pSid,
                  szDomain, szDomain, &sidUse);
            } while (!fOk && (GetLastError() == ERROR_INSUFFICIENT_BUFFER));
            if (fOk)
               TrusteeToAddedList(GetDlgItem(hwnd, IDL_TRUSTEES), ptlInfo, pSid,
                  szDomain, pdsSelList->aDsSelection[nIndex].pwzName, sidUse);
         }
      }
   } 
leave:;
   }
   catch (...) {
   }

   if (fGotStgMedium)  {
      // Unlock that buffer
      GlobalUnlock(stgmedium.hGlobal);
      // Release the data
      ReleaseStgMedium(&stgmedium);
   }
   // Release the picker
   if (pdsObjectPicker != NULL)
      pdsObjectPicker->Release();
   // Release the data
   if (pdoNames != NULL)
      pdoNames->Release();
   // Done with COM for the moment
   CoUninitialize();
}


///////////////////////////////////////////////////////////////////////////////


LOCALGROUP_MEMBERS_INFO_0* BuildAddedArray(PTRUSTEELISTINFO ptlInfo,
   HWND hwndList) {

   LOCALGROUP_MEMBERS_INFO_0* pinfoMembers = NULL;

   try { {
      // None added?  Bail out
      if (ptlInfo->m_nAddedCount == 0) goto leave;

      // Calculate the size of our returned "added" buffer
      int nBufSize = ptlInfo->m_nTotalAddedSIDBytes + 
         (ptlInfo->m_nAddedCount * sizeof(LOCALGROUP_MEMBERS_INFO_0));

      // Allocate the buffer
      PBYTE pbPlaceHolder = (PBYTE) LocalAlloc(LPTR, nBufSize);
      if (pbPlaceHolder == NULL) goto leave;

      // Beginning of our array
      pinfoMembers = (LOCALGROUP_MEMBERS_INFO_0*) pbPlaceHolder;

      // Pointing to the start of the SID block after the array
      pbPlaceHolder += sizeof(LOCALGROUP_MEMBERS_INFO_0)
         * ptlInfo->m_nAddedCount;

      // Iterate through items in the list control
      int nIndex = ListView_GetItemCount(hwndList);
      int nAdded = 0;
      while (nIndex-- != 0) {
         LVITEM lvItem = { 0 };
         lvItem.iItem = nIndex;
         lvItem.iSubItem = 0;
         lvItem.mask = LVIF_PARAM;
         ListView_GetItem(hwndList, &lvItem);

         // Get item info
         PTRUSTEEITEMINFO pinfoItem = (PTRUSTEEITEMINFO) lvItem.lParam;
         
         // Was the item added?
         if (pinfoItem->m_nOriginalIndex == -1) {

            // Copy the SID into our buffer
            PSID psidDest = (PSID) pbPlaceHolder;
            int nSidLength = GetLengthSid(pinfoItem->m_pSID);
            CopySid(nSidLength, psidDest, pinfoItem->m_pSID);
            
            // Update the place holder
            pbPlaceHolder += nSidLength;
            
            // Set the pointer in our array
            pinfoMembers[nAdded++].lgrmi0_sid = psidDest;
         }
      }
   } 
leave:;
   }
   catch (...) {
   }
   return(pinfoMembers);
}


///////////////////////////////////////////////////////////////////////////////


LOCALGROUP_MEMBERS_INFO_0* BuildRemovedArray(PTRUSTEELISTINFO ptlInfo) {

   LOCALGROUP_MEMBERS_INFO_0* pinfoMembers = NULL;
   try { {
      // None removed bail out
      if (ptlInfo->m_nRemovedCount == 0) goto leave;

      // Calculate the return buffer size for removed sids
      int nBufSize = ptlInfo->m_nTotalRemovedSIDBytes
         + (ptlInfo->m_nRemovedCount * sizeof(LOCALGROUP_MEMBERS_INFO_0));

      // Allocate the buffer
      PBYTE pbPlaceHolder = (PBYTE) LocalAlloc(LPTR, nBufSize);
      if (pbPlaceHolder == NULL) goto leave;

      // Beginning of array of structures
      pinfoMembers = (LOCALGROUP_MEMBERS_INFO_0*) pbPlaceHolder;

      // Pointing to the start of the SID block (after the array of structures)
      pbPlaceHolder += sizeof(LOCALGROUP_MEMBERS_INFO_0) 
         * ptlInfo->m_nRemovedCount;

      // Iterate through the original sids
      int nIndex = ptlInfo->m_nTrusteeCount;
      int nRemoved = 0;
      while (nIndex-- != 0) {
         // Is it removed?
         if (ptlInfo->m_pfRemovedMap[nIndex]) {

            // Copy the SID into our buffer
            int nSidLength =
               GetLengthSid(ptlInfo->m_pinfoTrustees[nIndex].lgrmi0_sid);
            PSID psidDest = (PSID) pbPlaceHolder;
            CopySid(nSidLength, psidDest,
               ptlInfo->m_pinfoTrustees[nIndex].lgrmi0_sid);
      
            // Update the placeholder for our next SID
            pbPlaceHolder += nSidLength;
            
            // Set the pointer in the array
            pinfoMembers[nRemoved++].lgrmi0_sid = psidDest;
         }
      }
   } 
leave:;
   }
   catch (...) {
   }
   return(pinfoMembers);
}


///////////////////////////////////////////////////////////////////////////////


void TLEnableControls( HWND hwnd ) {
      
   int nItem = ListView_GetNextItem(GetDlgItem(hwnd, IDL_TRUSTEES), 
      -1, LVNI_SELECTED);      
   EnableWindow(GetDlgItem(hwnd, IDB_REMOVE), nItem != -1);
}


///////////////////////////////////////////////////////////////////////////////


BOOL TLDlg_OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam) {
    int nIndex = 0;
   InitCommonControls();

   // Set the pointer to the state structure as user data in the window
   PTRUSTEELISTINFO ptlInfo = (PTRUSTEELISTINFO) lParam;
   SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) ptlInfo);

   // Set the dialog title
   if (ptlInfo->m_szTitle != NULL)
      SetWindowText(hwnd, ptlInfo->m_szTitle);

   // Initialize the state structure
   ptlInfo->m_fOk = FALSE;
   ptlInfo->m_nTotalAddedSIDBytes = 0;
   ptlInfo->m_nTotalRemovedSIDBytes = 0;
   ptlInfo->m_nRemovedCount = 0;
   ptlInfo->m_nAddedCount = 0;

   // Setup the removed map of the sate structure object
   ptlInfo->m_pfRemovedMap = new int[ptlInfo->m_nTrusteeCount];
   for (nIndex = 0; nIndex < ptlInfo->m_nTrusteeCount; nIndex++)
      ptlInfo->m_pfRemovedMap[nIndex] = FALSE;

   // Create a resize handler object
   ptlInfo->m_UILayout.Initialize(hwnd); 
   ptlInfo->m_UILayout.AnchorControl(CUILayout::AP_TOPLEFT, CUILayout::AP_BOTTOMRIGHT, IDL_TRUSTEES, FALSE);
   ptlInfo->m_UILayout.AnchorControls(CUILayout::AP_BOTTOMRIGHT, CUILayout::AP_BOTTOMRIGHT, FALSE, IDOK, IDCANCEL, (UINT) -1);
   ptlInfo->m_UILayout.AnchorControls(CUILayout::AP_BOTTOMLEFT, CUILayout::AP_BOTTOMLEFT, FALSE, IDB_ADD, IDB_REMOVE, (UINT) -1);

   // Load image list and set to list control
   HWND hwndList = GetDlgItem(hwnd, IDL_TRUSTEES);
   HIMAGELIST himage = ImageList_LoadBitmap(GetModuleHandle(NULL),
      MAKEINTRESOURCE(IDB_IMAGE), 16, 1, RGB(255, 0, 255));
   chASSERT(himage != NULL);
   ListView_SetImageList(hwndList, himage, LVSIL_SMALL);

   CAutoBuf<TCHAR, sizeof(TCHAR)> szName;
   CAutoBuf<TCHAR, sizeof(TCHAR)> szDomain;
   nIndex = ptlInfo->m_nTrusteeCount;
   while (nIndex-- != 0)  {

      SID_NAME_USE sidUse;
      BOOL fSuccess;
      do {
         fSuccess = LookupAccountSid(ptlInfo->m_szSystem,
            ptlInfo->m_pinfoTrustees[nIndex].lgrmi0_sid, szName, szName,
            szDomain, szDomain, &sidUse);
      } while (!fSuccess && (GetLastError() == ERROR_INSUFFICIENT_BUFFER));
      if (!fSuccess) {

         // No name, we try to connvert the SID to a string
         PWSTR pwstr;
         if (!ConvertSidToStringSid(
            ptlInfo->m_pinfoTrustees[nIndex].lgrmi0_sid, &pwstr)) continue;
         szName = (lstrlen(pwstr) + 1);
         lstrcpy(szName, pwstr);
         LocalFree(pwstr);
         szDomain = 1;
         szDomain[0] = 0;
      }

      // Add the trustee to the list control
      InsertTrustee(hwndList, ptlInfo,
         ptlInfo->m_pinfoTrustees[nIndex].lgrmi0_sid, szName, szDomain,
         sidUse, nIndex);
   }
   TLEnableControls(hwnd);

   return(TRUE);
}


///////////////////////////////////////////////////////////////////////////////


void TLDlg_OnCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify) {

   // Get the state information
   PTRUSTEELISTINFO ptlInfo = (PTRUSTEELISTINFO) 
      GetWindowLongPtr(hwnd, DWLP_USER);

   switch (id) {
   case IDOK:
      // Set the state to OK
      ptlInfo->m_fOk = TRUE;
      EndDialog(hwnd, ptlInfo->m_fOk);
      break;

   case IDCANCEL:
      ptlInfo->m_fOk = FALSE;
      EndDialog(hwnd, ptlInfo->m_fOk);
      break;

   case IDB_REMOVE:
      RemoveSelectedTrustees(GetDlgItem(hwnd, IDL_TRUSTEES), ptlInfo);
      break;

   case IDB_ADD:
      PickTrustees(hwnd, ptlInfo);
      break;
   }
}


///////////////////////////////////////////////////////////////////////////////


void TLDlg_OnDestroy(HWND hwnd) {

   // Get State structure
   PTRUSTEELISTINFO ptlInfo = (PTRUSTEELISTINFO) 
      GetWindowLongPtr(hwnd, DWLP_USER);

   HWND hwndList = GetDlgItem(hwnd, IDL_TRUSTEES);

   // If the selected OK then build the added and removed arrays
   if (ptlInfo->m_fOk) {

      ptlInfo->m_pinfoTrusteesAdded = BuildAddedArray(ptlInfo, hwndList);
      ptlInfo->m_pinfoTrusteesRemoved = BuildRemovedArray(ptlInfo);
   }

   // Delete the "removed map" array
   delete[](ptlInfo->m_pfRemovedMap);

   // Cleanup entries in list box
   int nIndex = ListView_GetItemCount(hwndList);
   while (nIndex-- != 0) {

      LVITEM lvItem = { 0 };
      lvItem.iItem = nIndex;
      lvItem.iSubItem = 0;
      lvItem.mask = LVIF_PARAM;

      // Get the item from the list box
      ListView_GetItem(hwndList, &lvItem);

      // Translate the parameter to the tristeeiteminfo structure
      PTRUSTEEITEMINFO pinfoItem = (PTRUSTEEITEMINFO) lvItem.lParam;
      if (pinfoItem->m_nOriginalIndex == -1) {

         // If it is one we added, free the SID
         LocalFree(pinfoItem->m_pSID);
      }
      // Free the info structure
      LocalFree(pinfoItem);
   }
}


///////////////////////////////////////////////////////////////////////////////


void TLDlg_OnSize(HWND hwnd, UINT state, int cx, int cy) {

   PTRUSTEELISTINFO ptlInfo = (PTRUSTEELISTINFO) 
      GetWindowLongPtr(hwnd, DWLP_USER);

   // Simply call the adjustcontrols function of our handy resizer class
   ptlInfo->m_UILayout.AdjustControls(cx, cy);
}


///////////////////////////////////////////////////////////////////////////////


void TLDlg_OnGetMinMaxInfo(HWND hwnd, PMINMAXINFO pMinMaxInfo) {

   PTRUSTEELISTINFO ptlInfo = (PTRUSTEELISTINFO) 
      GetWindowLongPtr(hwnd, DWLP_USER);

   // Just calling another resizer function
   ptlInfo->m_UILayout.HandleMinMax(pMinMaxInfo);
}


///////////////////////////////////////////////////////////////////////////////


BOOL TLDlg_OnNotify(HWND hwnd, int idCtrl, LPNMHDR pnmhdr) {

   BOOL fReturn = FALSE;
   switch (pnmhdr->code) {
   case LVN_ITEMCHANGED:
      TLEnableControls(hwnd);
      break;
   }
   return(fReturn);
}


///////////////////////////////////////////////////////////////////////////////


INT_PTR CALLBACK TLDlg_Proc(HWND hwnd, UINT uMsg, WPARAM wParam, 
                            LPARAM lParam){

   switch (uMsg) {
   chHANDLE_DLGMSG(hwnd, WM_INITDIALOG,    TLDlg_OnInitDialog);
   chHANDLE_DLGMSG(hwnd, WM_DESTROY,       TLDlg_OnDestroy);
   chHANDLE_DLGMSG(hwnd, WM_SIZE,          TLDlg_OnSize);
   chHANDLE_DLGMSG(hwnd, WM_GETMINMAXINFO, TLDlg_OnGetMinMaxInfo);
   chHANDLE_DLGMSG(hwnd, WM_COMMAND,       TLDlg_OnCommand);
   chHANDLE_DLGMSG(hwnd, WM_NOTIFY,        TLDlg_OnNotify);
   }
   return(FALSE);
}


///////////////////////////////////////////////////////////////////////////////


BOOL EditTrusteeList(HWND hwnd, PTSTR szSystem,
   LOCALGROUP_MEMBERS_INFO_0* pinfoTrustees, int nTrusteeCount,
   LOCALGROUP_MEMBERS_INFO_0** ppinfoTrusteesAdded, int* pnAddedCount,
   LOCALGROUP_MEMBERS_INFO_0** ppinfoTrusteesRemoved, int* pnRemovedCount,
   PTSTR szTitle) {

   // Fill in state structure for the dialog box
   TRUSTEELISTINFO tlInfo;
   tlInfo.m_nTrusteeCount = nTrusteeCount;
   tlInfo.m_pinfoTrustees = pinfoTrustees;
   tlInfo.m_szTitle       = szTitle;
   tlInfo.m_szSystem      = szSystem;

   // Invoke the edit trustees dialog box
   BOOL fRet = DialogBoxParam(GetModuleHandle(NULL), 
      MAKEINTRESOURCE(IDD_TRUSTEELIST), hwnd, TLDlg_Proc, (LPARAM) &tlInfo);
   if (fRet) {

      // If the user selected Ok, then fill the return variables with the lists
      *ppinfoTrusteesRemoved = tlInfo.m_pinfoTrusteesRemoved;
      *pnRemovedCount        = tlInfo.m_nRemovedCount;
      *ppinfoTrusteesAdded   = tlInfo.m_pinfoTrusteesAdded;
      *pnAddedCount          = tlInfo.m_nAddedCount;
      
      // If the user made no additions or deletions, "Ok" becomes "Cancel"
      if ((tlInfo.m_nRemovedCount == 0) && (tlInfo.m_nAddedCount == 0))
         fRet = FALSE;

   } else {

      // The user selected cancel
      *pnRemovedCount = 0;
      *pnAddedCount = 0;
      *ppinfoTrusteesRemoved = NULL;
      *ppinfoTrusteesAdded = NULL;
   }
   return(fRet);
}


///////////////////////////////// End of File /////////////////////////////////