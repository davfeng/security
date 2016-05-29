/******************************************************************************
Module:  TrusteeMan.cpp
Notices: Copyright (c) 2000 Jeffrey Richter
******************************************************************************/

#include "stdafx.h"

#include <windowsx.h>
#include <CommCtrl.h>
#pragma comment(lib, "ComCtl32")

#include <ActiveDS.h>
#include <NTSecAPI.h>
#include <LMAccess.h>
#include <LMAPIBuf.h>
#include <LMErr.h>
#pragma comment(lib, "NetAPI32")

#include <ObjSel.h>
#include <SDDL.h>
#include <LM.h>
#include <objbase.h>
#include <AclUI.h>

#include "Resource.h"

// Force linking against the ACLUI library   
#pragma comment(lib, "ACLUI.lib")

#define UILAYOUT_IMPL

#define AUTOBUF_IMPL

#define PRINTBUF_IMPL

#define SECINFO_IMPL

//////////////////////////////// chDIMOF Macro ////////////////////////////////


// This macro evaluates to the number of elements in an array. 
#define chDIMOF(Array) (sizeof(Array) / sizeof(Array[0]))

// Sets the dialog box icons
inline void chSETDLGICONS(HWND hwnd, int idi) {
    SendMessage(hwnd, WM_SETICON, TRUE, (LPARAM)
        LoadIcon((HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE),
            MAKEINTRESOURCE(idi)));
    SendMessage(hwnd, WM_SETICON, FALSE, (LPARAM)
        LoadIcon((HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE),
            MAKEINTRESOURCE(idi)));
}

/////////////////////////// Quick MessageBox Macro ////////////////////////////


inline void chMB(PCSTR s) {
    char szTMP[128];
    GetModuleFileNameA(NULL, szTMP, chDIMOF(szTMP));
    MessageBoxA(GetActiveWindow(), s, szTMP, MB_OK);
}


//////////////////////////// Assert/Verify Macros /////////////////////////////


inline void chFAIL(PSTR szMsg) {
    chMB(szMsg);
    DebugBreak();
}


// Put up an assertion failure message box.
inline void chASSERTFAIL(LPCSTR file, int line, PCSTR expr) {
    char sz[128];
    wsprintfA(sz, "File %s, line %d : %s", file, line, expr);
    chFAIL(sz);
}

/////////////////////////// chHANDLE_DLGMSG Macro /////////////////////////////


// The normal HANDLE_MSG macro in WindowsX.h does not work properly for dialog
// boxes because DlgProc return a BOOL instead of an LRESULT (like
// WndProcs). This chHANDLE_DLGMSG macro corrects the problem:
#define chHANDLE_DLGMSG(hwnd, message, fn)                 \
   case (message): return (SetDlgMsgResult(hwnd, uMsg,     \
      HANDLE_##message((hwnd), (wParam), (lParam), (fn))))

// Put up a message box if an assertion fails in a debug build.
#ifdef _DEBUG
#define chASSERT(x) if (!(x)) chASSERTFAIL(__FILE__, __LINE__, #x)
#else
#define chASSERT(x)
#endif


// Assert in debug builds, but don't remove the code in retail builds.
#ifdef _DEBUG
#define chVERIFY(x) chASSERT(x)
#else
#define chVERIFY(x) (x)
#endif

////////////////////////////// chINRANGE Macro ////////////////////////////////


// This macro returns TRUE if a number is between two others
#define chINRANGE(low, Num, High) (((low) <= (Num)) && ((Num) <= (High)))


typedef enum AM_SECURETYPE {
    AM_FILE = 0, AM_DIR, AM_SERVICE,
    AM_PRINTER, AM_REGISTRY, AM_SHARE,
    AM_PROCESS, AM_THREAD, AM_JOB,
    AM_SEMAPHORE, AM_EVENT, AM_MUTEX,
    AM_MAPPING, AM_TIMER, AM_TOKEN,
    AM_NAMEDPIPE, AM_ANONPIPE,
    AM_WINDOWSTATION, AM_DESKTOP
};

typedef struct _ObjEntry {
    AM_SECURETYPE  m_nSpecificType;
    SE_OBJECT_TYPE m_objType;
    PTSTR          m_pszComboText;
    PTSTR          m_pszUsageText;
    BOOL           m_fUseName;
    BOOL           m_fUseHandle;
    BOOL           m_fUsePID;
    BOOL           m_fIsChild;
    BOOL           m_fIsContainer;
} ObjEntry;

typedef struct _ObjInf {
    ObjEntry*   m_pEntry;
    HANDLE      m_hHandle;
    TCHAR       m_szName[1024];
    TCHAR       m_szObjectName[2048];
} ObjInf;




#ifndef UNICODE   
#error This module must be compiled natively using Unicode.   
#endif   

///////////////////////////////////////////////////////////////////////////////


class CPrintBuf {
public:
    CPrintBuf(SIZE_T nMaxSizeInBytes = 64 * 1024); // 64KB is default
    virtual ~CPrintBuf();

    BOOL Print(PCTSTR pszFmt, ...);
    BOOL PrintError(DWORD dwError = GetLastError());
    operator PCTSTR() { return(m_pszBuffer); }
    void Clear();

private:
    LONG Filter(EXCEPTION_POINTERS* pep);

private:
    int   m_nMaxSizeInBytes;
    int   m_nCurSize;
    PTSTR m_pszBuffer;
};


CPrintBuf::CPrintBuf(SIZE_T nMaxSizeInBytes) {

    // This constructor sets initial values of members, and reserves a block
    // of addresses of size nMaxSizeInBytes and commits a single page.
    m_nMaxSizeInBytes = nMaxSizeInBytes;
    m_nCurSize = 0;
    m_pszBuffer = (PTSTR)
        VirtualAlloc(NULL, m_nMaxSizeInBytes, MEM_RESERVE, PAGE_READWRITE);
    chASSERT(m_pszBuffer != NULL);
    chVERIFY(VirtualAlloc(m_pszBuffer, 1, MEM_COMMIT, PAGE_READWRITE) != NULL);
}


///////////////////////////////////////////////////////////////////////////////


CPrintBuf::~CPrintBuf() {

    VirtualFree(m_pszBuffer, 0, MEM_RELEASE);
}


///////////////////////////////////////////////////////////////////////////////


void CPrintBuf::Clear() {

    VirtualFree(m_pszBuffer, m_nMaxSizeInBytes, MEM_DECOMMIT);
    chVERIFY(VirtualAlloc(m_pszBuffer, 1, MEM_COMMIT, PAGE_READWRITE) != NULL);
    m_nCurSize = 0;
}


///////////////////////////////////////////////////////////////////////////////


LONG CPrintBuf::Filter(EXCEPTION_POINTERS* pep) {

    LONG lDisposition = EXCEPTION_EXECUTE_HANDLER;
    EXCEPTION_RECORD* per = pep->ExceptionRecord;
    __try {
        // Is exception is an access violation in the data buffer's region?
        if (per->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
            __leave;

        if (!chINRANGE(m_pszBuffer, (PVOID)per->ExceptionInformation[1],
            ((PBYTE)m_pszBuffer) + m_nMaxSizeInBytes - 1)) {
            __leave;
        }

        // Attempt to commit storage to the region
        if (VirtualAlloc((PVOID)pep->ExceptionRecord->ExceptionInformation[1],
            1, MEM_COMMIT, PAGE_READWRITE) == NULL) {
            __leave;
        }

        lDisposition = EXCEPTION_CONTINUE_EXECUTION;
    }
    __finally {
    }
    return(lDisposition);
}


///////////////////////////////////////////////////////////////////////////////


int CPrintBuf::Print(PCTSTR pszFmt, ...) {

    // This function appends text to the formatted print buffer.
    int nLength = -1; // Assume failure
    va_list arglist;
    va_start(arglist, pszFmt);
    __try {
        // Append string to end of buffer
        nLength = _vstprintf(m_pszBuffer + m_nCurSize, pszFmt, arglist);
        if (nLength > 0)
            m_nCurSize += nLength;
    }
    __except (Filter(GetExceptionInformation())) {
        chMB("CPrintBuf attempted to go over the maximum size.");
        DebugBreak();
    }
    va_end(arglist);
    return(nLength);
}


///////////////////////////////////////////////////////////////////////////////


BOOL CPrintBuf::PrintError(DWORD dwErr) {

    // Append the last error string text to the buffer.
    PTSTR pszMsg = NULL;
    BOOL fOk = (0 != FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL,
        dwErr, 0, (PTSTR)&pszMsg, 0, NULL));
    fOk = fOk && (Print(TEXT("Error %d: %s"), dwErr, pszMsg) >= 0);
    if (pszMsg != NULL)
        LocalFree(pszMsg);
    return(fOk);
}

///////////////////////////////////////////////////////////////////////////////   
class CUILayout {
public:
    enum ANCHORPOINT {
        AP_TOPLEFT,
        AP_TOPMIDDLE,
        AP_TOPRIGHT,
        AP_MIDDLERIGHT,
        AP_BOTTOMRIGHT,
        AP_BOTTOMMIDDLE,
        AP_BOTTOMLEFT,
        AP_MIDDLELEFT,
        AP_CENTER
    };

public:
    void Initialize(HWND hwndParent, int nMinWidth = 0, int nMinHeight = 0);
    BOOL AnchorControl(ANCHORPOINT apUpperLeft, ANCHORPOINT apLowerRight,
        int nID, BOOL fRedraw = FALSE);
    BOOL AnchorControls(ANCHORPOINT apUpperLeft, ANCHORPOINT apLowerRight,
        BOOL fRedraw, ...);

    BOOL AdjustControls(int cx, int cy);
    void HandleMinMax(PMINMAXINFO pMinMax)
    {
        pMinMax->ptMinTrackSize = m_ptMinParentDims;
    }

private:
    struct CONTROL {
        int         m_nID;
        BOOL        m_fRedraw;
        ANCHORPOINT m_apUpperLeft;
        ANCHORPOINT m_apLowerRight;
        POINT       m_ptULDelta;
        POINT       m_ptLRDelta;
    };

private:
    void PixelFromAnchorPoint(ANCHORPOINT ap,
        int cxParent, int cyParent, PPOINT ppt);

private:
    CONTROL m_CtrlInfo[255]; // Max controls allowed in a dialog template
    int     m_nNumControls;
    HWND    m_hwndParent;
    POINT   m_ptMinParentDims;
};


///////////////////////////////////////////////////////////////////////////////


void CUILayout::Initialize(HWND hwndParent, int nMinWidth, int nMinHeight) {

    m_hwndParent = hwndParent;
    m_nNumControls = 0;

    if ((nMinWidth == 0) || (nMinHeight == 0)) {
        RECT rc;
        GetWindowRect(m_hwndParent, &rc);
        m_ptMinParentDims.x = rc.right - rc.left;
        m_ptMinParentDims.y = rc.bottom - rc.top;
    }
    if (nMinWidth != 0) m_ptMinParentDims.x = nMinWidth;
    if (nMinHeight != 0) m_ptMinParentDims.y = nMinHeight;
}


///////////////////////////////////////////////////////////////////////////////


BOOL CUILayout::AnchorControl(ANCHORPOINT apUpperLeft,
    ANCHORPOINT apLowerRight, int nID, BOOL fRedraw) {

    BOOL fOk = FALSE;
    try {
        {
            HWND hwndControl = GetDlgItem(m_hwndParent, nID);
            if (hwndControl == NULL) goto leave;
            if (m_nNumControls >= chDIMOF(m_CtrlInfo)) goto leave;

            m_CtrlInfo[m_nNumControls].m_nID = nID;
            m_CtrlInfo[m_nNumControls].m_fRedraw = fRedraw;
            m_CtrlInfo[m_nNumControls].m_apUpperLeft = apUpperLeft;
            m_CtrlInfo[m_nNumControls].m_apLowerRight = apLowerRight;

            RECT rcControl;
            GetWindowRect(hwndControl, &rcControl);  // Screen coords of control
                                                     // Convert coords to parent-relative coordinates
            MapWindowPoints(HWND_DESKTOP, m_hwndParent, (PPOINT)&rcControl, 2);

            RECT rcParent;
            GetClientRect(m_hwndParent, &rcParent);

            POINT pt;
            PixelFromAnchorPoint(apUpperLeft, rcParent.right, rcParent.bottom, &pt);
            m_CtrlInfo[m_nNumControls].m_ptULDelta.x = pt.x - rcControl.left;
            m_CtrlInfo[m_nNumControls].m_ptULDelta.y = pt.y - rcControl.top;

            PixelFromAnchorPoint(apLowerRight, rcParent.right, rcParent.bottom, &pt);
            m_CtrlInfo[m_nNumControls].m_ptLRDelta.x = pt.x - rcControl.right;
            m_CtrlInfo[m_nNumControls].m_ptLRDelta.y = pt.y - rcControl.bottom;

            m_nNumControls++;
            fOk = TRUE;
        }
    leave:;
    }
    catch (...) {
    }
    chASSERT(fOk);
    return(fOk);
}


///////////////////////////////////////////////////////////////////////////////


BOOL CUILayout::AnchorControls(ANCHORPOINT apUpperLeft,
    ANCHORPOINT apLowerRight, BOOL fRedraw, ...) {

    BOOL fOk = TRUE;

    va_list arglist;
    va_start(arglist, fRedraw);
    int nID = va_arg(arglist, int);
    while (fOk && (nID != -1)) {
        fOk = fOk && AnchorControl(apUpperLeft, apLowerRight, nID, fRedraw);
        nID = va_arg(arglist, int);
    }
    va_end(arglist);
    return(fOk);
}


///////////////////////////////////////////////////////////////////////////////


BOOL CUILayout::AdjustControls(int cx, int cy) {
    BOOL fOk = FALSE;

    // Create region consisting of all areas occupied by controls
    HRGN hrgnPaint = CreateRectRgn(0, 0, 0, 0);
    for (int n = 0; n < m_nNumControls; n++) {

        HWND hwndControl = GetDlgItem(m_hwndParent, m_CtrlInfo[n].m_nID);
        RECT rcControl;
        GetWindowRect(hwndControl, &rcControl);  // Screen coords of control
                                                 // Convert coords to parent-relative coordinates
        MapWindowPoints(HWND_DESKTOP, m_hwndParent, (PPOINT)&rcControl, 2);

        HRGN hrgnTemp = CreateRectRgnIndirect(&rcControl);
        CombineRgn(hrgnPaint, hrgnPaint, hrgnTemp, RGN_OR);
        DeleteObject(hrgnTemp);
    }

    for (int n = 0; n < m_nNumControls; n++) {

        // Get control's upper/left position w/respect to parent's width/height
        RECT rcControl;
        PixelFromAnchorPoint(m_CtrlInfo[n].m_apUpperLeft,
            cx, cy, (PPOINT)&rcControl);
        rcControl.left -= m_CtrlInfo[n].m_ptULDelta.x;
        rcControl.top -= m_CtrlInfo[n].m_ptULDelta.y;

        // Get control's lower/right position w/respect to parent's width/height
        PixelFromAnchorPoint(m_CtrlInfo[n].m_apLowerRight,
            cx, cy, (PPOINT)&rcControl.right);
        rcControl.right -= m_CtrlInfo[n].m_ptLRDelta.x;
        rcControl.bottom -= m_CtrlInfo[n].m_ptLRDelta.y;

        // Position/size the control
        HWND hwndControl = GetDlgItem(m_hwndParent, m_CtrlInfo[n].m_nID);
        MoveWindow(hwndControl, rcControl.left, rcControl.top,
            rcControl.right - rcControl.left,
            rcControl.bottom - rcControl.top, FALSE);
        if (m_CtrlInfo[n].m_fRedraw) {
            InvalidateRect(hwndControl, NULL, FALSE);
        }
        else {
            // Remove the regions occupied by the control's new position
            HRGN hrgnTemp = CreateRectRgnIndirect(&rcControl);
            CombineRgn(hrgnPaint, hrgnPaint, hrgnTemp, RGN_DIFF);
            DeleteObject(hrgnTemp);
            // Make the control repaint itself
            InvalidateRect(hwndControl, NULL, TRUE);
            SendMessage(hwndControl, WM_NCPAINT, 1, 0);
            UpdateWindow(hwndControl);
        }
    }

    // Paint the newly exposed portion of the dialog box's client area
    HDC hdc = GetDC(m_hwndParent);
    HBRUSH hbrColor = CreateSolidBrush(GetSysColor(COLOR_3DFACE));
    FillRgn(hdc, hrgnPaint, hbrColor);
    DeleteObject(hbrColor);
    ReleaseDC(m_hwndParent, hdc);
    DeleteObject(hrgnPaint);
    return(fOk);
}


///////////////////////////////////////////////////////////////////////////////


void CUILayout::PixelFromAnchorPoint(ANCHORPOINT ap,
    int cxParent, int cyParent, PPOINT ppt) {

    ppt->x = ppt->y = 0;

    switch (ap) {
    case AP_TOPMIDDLE:
    case AP_CENTER:
    case AP_BOTTOMMIDDLE:
        ppt->x = cxParent / 2;
        break;

    case AP_TOPRIGHT:
    case AP_MIDDLERIGHT:
    case AP_BOTTOMRIGHT:
        ppt->x = cxParent;
        break;
    }

    switch (ap) {
    case AP_MIDDLELEFT:
    case AP_CENTER:
    case AP_MIDDLERIGHT:
        ppt->y = cyParent / 2;
        break;

    case AP_BOTTOMLEFT:
    case AP_BOTTOMMIDDLE:
    case AP_BOTTOMRIGHT:
        ppt->y = cyParent;
        break;
    }
}

/////////////////// CAutoBuf Template C++ Class Description ///////////////////


/*
The CAutoBuf template C++ class implements type safe buffers that
automatically grow to meet the needs of your code.  Memory is also
automatically freed when the object is destroyed (typically when your
code goes out of frame and it is popped off of the stack).

Examples of use:

// Create a buffer with no explicit data type,
// the buffer grown in increments of a byte
CAutoBuf<PVOID> buf;

// Create a buffer of TCHARs,
// the buffer grows in increments of sizeof(TCHAR)
CAutoBuf<PTSTR, sizeof(TCHAR)> buf;

// Force the buffer to be 10 bytes big
buf = 10;

*/


///////////////////////////////////////////////////////////////////////////////


// This class is only ever used as a base class of the CAutoBuf template class.
// The base class exists so that all instances of the template class share
// a single instance of the common code.
class CAutoBufBase {
public:
    UINT  Size() { return(*(PDWORD)PSize()); }
    UINT  Size(UINT uSize);

    PUINT PSize() {
        AdjustBuffer();
        m_uNewSize = m_uCurrentSize;
        return(&m_uNewSize);
    }
    void  Free() { Reconstruct(); }

protected:
    CAutoBufBase(PBYTE *ppbData, int nMult) {
        m_nMult = nMult;
        m_ppbBuffer = ppbData; // Derived class holds address of buffer to allow
                               // debugger's Quick Watch to work with typed data.
        Reconstruct(TRUE);
    }

    virtual ~CAutoBufBase() { Free(); }

    void Reconstruct(BOOL fFirstTime = FALSE);

    PBYTE Buffer() {
        AdjustBuffer();
        return(*m_ppbBuffer);
    }

private:
    void AdjustBuffer();

private:
    PBYTE* m_ppbBuffer;    // Address of address of data buffer
    int    m_nMult;        // Multiplier (in bytes) used for buffer growth
    UINT   m_uNewSize;     // Requested buffer size (in m_nMult units)
    UINT   m_uCurrentSize; // Actual size (in m_nMult units)
};


///////////////////////////////////////////////////////////////////////////////


template <class TYPE, int MULT = 1>
class CAutoBuf : private CAutoBufBase {
public:
    CAutoBuf() : CAutoBufBase((PBYTE*)&m_pData, MULT) {}
    void Free() { CAutoBufBase::Free(); }

public:
    operator TYPE*() { return(Buffer()); }

    UINT operator=(UINT uSize) { return(CAutoBufBase::Size(uSize)); }
    operator UINT() { return(Size()); }
    operator ULONG() { return(Size()); }

    operator PUINT() { return(PSize()); }
    operator PLONG() { return((PLONG)PSize()); }
    operator PULONG() { return((PULONG)PSize()); }

    operator PBYTE() { return((PBYTE)Buffer()); }
    operator PVOID() { return((PVOID)Buffer()); }

    TYPE& operator[](int nIndex) { return(*(Buffer() + nIndex)); }

private:
    TYPE* Buffer() { return((TYPE*)CAutoBufBase::Buffer()); }

private:
    TYPE* m_pData;
};


///////////////////////////////////////////////////////////////////////////////


#define GROWUNTIL(fail, func)                        \
   do {                                              \
      if ((func) != (fail))                          \
         break;                                      \
   } while ((GetLastError() == ERROR_MORE_DATA) ||   \
            (GetLastError() == ERROR_INSUFFICIENT_BUFFER));


///////////////////////////////////////////////////////////////////////////////


void CAutoBufBase::Reconstruct(BOOL fFirstTime) {

    if (!fFirstTime) {
        if (*m_ppbBuffer != NULL)
            HeapFree(GetProcessHeap(), 0, *m_ppbBuffer);
    }

    *m_ppbBuffer = NULL; // Derived class doesn't point to a data buffer
    m_uNewSize = 0;      // Initially, buffer has no bytes in it
    m_uCurrentSize = 0;  // Initially, buffer has no bytes in it
}


///////////////////////////////////////////////////////////////////////////////


UINT CAutoBufBase::Size(UINT uSize) {

    // Set buffer to desired number of m_nMult bytes.
    if (uSize == 0) {
        Reconstruct();
    }
    else {
        m_uNewSize = uSize;
        AdjustBuffer();
    }
    return(m_uNewSize);
}


///////////////////////////////////////////////////////////////////////////////


void CAutoBufBase::AdjustBuffer() {

    if (m_uCurrentSize < m_uNewSize) {

        // We're growing the buffer
        HANDLE hHeap = GetProcessHeap();

        if (*m_ppbBuffer != NULL) {
            // We already have a buffer, re-size it
            PBYTE pNew = (PBYTE)
                HeapReAlloc(hHeap, 0, *m_ppbBuffer, m_uNewSize * m_nMult);
            if (pNew != NULL) {
                m_uCurrentSize = m_uNewSize;
                *m_ppbBuffer = pNew;
            }
        }
        else {
            // We don't have a buffer, create new one.
            *m_ppbBuffer = (PBYTE)HeapAlloc(hHeap, 0, m_uNewSize * m_nMult);
            if (*m_ppbBuffer != NULL)
                m_uCurrentSize = m_uNewSize;
        }
    }
}


///////////////////////////////////////////////////////////////////////////////

#include "LSAStr.h"

#include "EditTrusteeList.h"


///////////////////////////////////////////////////////////////////////////////


#ifndef UNICODE
#error This module must be compiled natively using Unicode.
#endif


///////////////////////////////////////////////////////////////////////////////


typedef enum TRUSTEE_T {
      User=1, 
      Group
};

HINSTANCE g_hInst;


///////////////////////////////////////////////////////////////////////////////


typedef struct _TrusteeManState {
   // State
   HIMAGELIST m_himage;
   LSA_HANDLE m_hPolicy;
   TCHAR      m_szComputer[256];
   CUILayout  m_UILayout;
} TRUSTEEMANSTATE, *PTRUSTEEMANSTATE;


///////////////////////////////////////////////////////////////////////////////


void ReportError(PTSTR pszFunction, ULONG lErr) {
   CPrintBuf prntBuf;
   prntBuf.Print(TEXT("The Function:  %s\r\n"), pszFunction);
   prntBuf.Print(TEXT("Caused the following error - \r\n"));
   prntBuf.PrintError(lErr);
   MessageBox(NULL, prntBuf, TEXT("TrusteeMan Error"), MB_OK);
}


///////////////////////////////////////////////////////////////////////////////


void GetComputer(HWND hwnd, PTSTR szComputer, ULONG lSize) {
   // Get state info
   PTRUSTEEMANSTATE ptmState = (PTRUSTEEMANSTATE) 
      GetWindowLongPtr(hwnd, DWLP_USER);

   HWND hwndCombo = GetDlgItem(hwnd, IDC_COMPUTER);
   int nIndex = ComboBox_GetCurSel(hwndCombo);
   if ((nIndex == 0) || (ptmState->m_szComputer[0] == 0)) {

      // Local system
      GetComputerName(szComputer, &lSize);

   } else {

      lstrcpyn(szComputer, ptmState->m_szComputer, lSize);      
   }
}


///////////////////////////////////////////////////////////////////////////////


void EnableControls( HWND hwnd ) {

   BOOL fTrusteeSelected = FALSE;
   BOOL fGroupSelected = FALSE;
   BOOL fPrivilegeSelected = FALSE;

   HWND hwndList = GetDlgItem(hwnd, IDL_TRUSTEES);
   int nItem = ListView_GetNextItem(hwndList, -1, LVNI_SELECTED);
   if(nItem!=-1){
      fTrusteeSelected=TRUE;
      
      TCHAR szType[256];
      ListView_GetItemText(hwndList, nItem, 1, szType, chDIMOF(szType));
      fGroupSelected = szType[0]==TEXT('G');
   }
   
   hwndList = GetDlgItem(hwnd, IDL_PRIVILEGES);
   nItem = ListView_GetNextItem(hwndList, -1, LVNI_SELECTED);
   fPrivilegeSelected = nItem != -1;

   EnableWindow(GetDlgItem(hwnd, IDB_REMOVE), fTrusteeSelected);
   EnableWindow(GetDlgItem(hwnd, IDB_EDITMEMBERS), fGroupSelected);
   EnableWindow(GetDlgItem(hwnd, IDB_PRIVILEGED), fPrivilegeSelected);
   EnableWindow(GetDlgItem(hwnd, IDB_GRANT), fPrivilegeSelected);
   EnableWindow(GetDlgItem(hwnd, IDB_REVOKE), fPrivilegeSelected);
}


///////////////////////////////////////////////////////////////////////////////


void PriviligedTrustees(HWND hwndDlg, PTSTR pszPrivilige) {

   LSA_ENUMERATION_INFORMATION* plsaEnum = NULL;

   try { {
      // Get state info
      PTRUSTEEMANSTATE ptmState = (PTRUSTEEMANSTATE) 
         GetWindowLongPtr(hwndDlg, DWLP_USER);

      // Translate the privilege name into an LSA string
      CLSAStr lsastrPriv = pszPrivilige;

      // Find accounts that have the privilege
      ULONG lCount;
      NTSTATUS ntStatus = LsaEnumerateAccountsWithUserRight(ptmState->m_hPolicy, 
         &lsastrPriv, (PVOID*) &plsaEnum, &lCount);
      ULONG lErr = LsaNtStatusToWinError(ntStatus);
      if ((lErr != ERROR_SUCCESS) && (lErr != ERROR_NO_MORE_ITEMS)) {
         ReportError(TEXT("LsaEnumerateAccountsWithUserRight"), lErr);
         plsaEnum = NULL;
         goto leave;
      }

      // If none, that is fine
      if (lErr == ERROR_NO_MORE_ITEMS) {
         plsaEnum = NULL;
         lCount = 0;
      }

      TCHAR szComputer[256];
      GetComputer(hwndDlg, szComputer, chDIMOF(szComputer));

      // Edit existing trustee list and return additions and deletions
      LSA_ENUMERATION_INFORMATION* pinfoTrusteeAdd;
      LSA_ENUMERATION_INFORMATION* pinfoTrusteeRemove;
      int nAddCount;
      int nRemoveCount;
      if (!EditTrusteeList(hwndDlg, szComputer,
         (LOCALGROUP_MEMBERS_INFO_0*) plsaEnum, lCount,
         (LOCALGROUP_MEMBERS_INFO_0**) &pinfoTrusteeAdd, &nAddCount,
         (LOCALGROUP_MEMBERS_INFO_0**) &pinfoTrusteeRemove, &nRemoveCount,
         TEXT("Edit Priviliged Trustee List"))) {
         goto leave;
      }

      // Handle additions
      if (nAddCount > 0) {

         while (nAddCount-- != 0) {

            // Add the privilege to this trustee
            ntStatus = LsaAddAccountRights(ptmState->m_hPolicy,
               pinfoTrusteeAdd[nAddCount].Sid, &lsastrPriv, 1);
            lErr = LsaNtStatusToWinError(ntStatus);
            if (lErr != ERROR_SUCCESS)
               ReportError(TEXT("LsaAddAccountRights"), lErr);
         }
         LocalFree(pinfoTrusteeAdd);
      }

      // Handle deletions
      if (nRemoveCount > 0) {

         while (nRemoveCount-- != 0) {

            // Remove the privilege from this trustee
            ntStatus = LsaRemoveAccountRights(ptmState->m_hPolicy,
               pinfoTrusteeRemove[nRemoveCount].Sid, FALSE, &lsastrPriv, 1);
            lErr = LsaNtStatusToWinError(ntStatus);
            if (lErr != ERROR_SUCCESS)
               ReportError(TEXT("LsaRemoveAccountRights"), lErr);
         }
         LocalFree(pinfoTrusteeRemove);
      }

   } leave:;
   }
   catch (...) {
   }

   // Free the buffer returned by lsaenumerateaccountswithuserright
   if (plsaEnum != NULL)
      LsaFreeMemory(plsaEnum);
}


///////////////////////////////////////////////////////////////////////////////


void GroupMembers(HWND hwndDlg, PTSTR pszGroup) {

   LOCALGROUP_MEMBERS_INFO_0* pinfoCurrent = NULL;

   try { {
      TCHAR szComputer[256];
      GetComputer(hwndDlg, szComputer, chDIMOF(szComputer));

      // Find current group membership information
      ULONG lEntries, lTotalEntries;
      NET_API_STATUS netStatus = NetLocalGroupGetMembers(szComputer,
         pszGroup, 0, (PBYTE*) &pinfoCurrent, MAX_PREFERRED_LENGTH,
         &lEntries, &lTotalEntries, NULL);
      if (netStatus != NERR_Success) {
         ReportError(TEXT("NetLocalGroupGetMembers"), netStatus);
         pinfoCurrent = NULL;
         goto leave;
      }

      // Call the EditTrusteeList function which returns a list of trustees
      // to add and a list to remove from your current trustee list
      LOCALGROUP_MEMBERS_INFO_0* pinfoTrusteeAdd;
      LOCALGROUP_MEMBERS_INFO_0* pinfoTrusteeRemove;
      int nAddCount;
      int nRemoveCount;
      if (!EditTrusteeList(hwndDlg, szComputer, pinfoCurrent, lEntries,
         &pinfoTrusteeAdd, &nAddCount, &pinfoTrusteeRemove, &nRemoveCount,
         TEXT("Edit Member List"))) {
         goto leave;
      }

      // Handle additions
      if (nAddCount > 0) {

         // Add members to the group
         netStatus = NetLocalGroupAddMembers(szComputer, pszGroup, 0,
            (PBYTE) pinfoTrusteeAdd, nAddCount);
         if (netStatus != NERR_Success)
            ReportError(TEXT("NetLocalGroupAddMembers"), NERR_Success);

         LocalFree(pinfoTrusteeAdd);
      }

      // Handle deletions
      if (nRemoveCount > 0) {

         // Delete members from the group
         netStatus = NetLocalGroupDelMembers(szComputer, pszGroup, 0,
            (PBYTE) pinfoTrusteeRemove, nRemoveCount);
         if (netStatus != NERR_Success)
            ReportError(TEXT("NetLocalGroupDelMembers"), NERR_Success);

         LocalFree(pinfoTrusteeRemove);
      }
   } leave:;
   }
   catch (...) {
   }
   
   // Free the buffer returned by NetLocalGroupGetMembers
   if (pinfoCurrent != NULL)
      NetApiBufferFree(pinfoCurrent);
}


///////////////////////////////////////////////////////////////////////////////


void PopulatePrivilegeList(HWND hwndDlg) {

   // Found in "winnt.h" and "ntsecapi.h"
   PTSTR szPrivileges[] = {
      SE_CREATE_TOKEN_NAME,
      SE_ASSIGNPRIMARYTOKEN_NAME,
      SE_LOCK_MEMORY_NAME,
      SE_UNSOLICITED_INPUT_NAME,
      SE_MACHINE_ACCOUNT_NAME,
      SE_INCREASE_QUOTA_NAME,
      SE_TCB_NAME,
      SE_SECURITY_NAME,
      SE_TAKE_OWNERSHIP_NAME,
      SE_LOAD_DRIVER_NAME,
      SE_SYSTEM_PROFILE_NAME,
      SE_SYSTEMTIME_NAME,
      SE_PROF_SINGLE_PROCESS_NAME,
      SE_CREATE_PAGEFILE_NAME,
      SE_CREATE_PERMANENT_NAME,
      SE_UNDOCK_NAME,
      SE_BACKUP_NAME,
      SE_RESTORE_NAME,
      SE_SYNC_AGENT_NAME,
      SE_DEBUG_NAME,
      SE_SHUTDOWN_NAME,
      SE_SYSTEM_ENVIRONMENT_NAME,
      SE_INC_BASE_PRIORITY_NAME,
      SE_CHANGE_NOTIFY_NAME,
      SE_REMOTE_SHUTDOWN_NAME,
      SE_AUDIT_NAME,
      SE_ENABLE_DELEGATION_NAME,
      SE_INTERACTIVE_LOGON_NAME,
      SE_NETWORK_LOGON_NAME,
      SE_BATCH_LOGON_NAME,
      SE_SERVICE_LOGON_NAME,
      SE_DENY_INTERACTIVE_LOGON_NAME,
      SE_DENY_NETWORK_LOGON_NAME,
      SE_DENY_BATCH_LOGON_NAME,
      SE_DENY_SERVICE_LOGON_NAME 
   };

   // Clear the control
   HWND hwndList = GetDlgItem(hwndDlg, IDL_PRIVILEGES);
   ListView_DeleteAllItems(hwndList);

   // Iterate through global array of privileges
   CAutoBuf<TCHAR, sizeof(TCHAR)> szDisplayName;
   int nIndex = chDIMOF(szPrivileges);
   while (nIndex-- != 0) {

      ULONG lLang;
      BOOL fRet;
      do {
         // Find the friendly name of the privilege
         fRet = LookupPrivilegeDisplayName(NULL, szPrivileges[nIndex],
            szDisplayName, szDisplayName, &lLang);
      } while (!fRet && (GetLastError() == ERROR_INSUFFICIENT_BUFFER));
      
      if (!fRet) {
         szDisplayName = 64;  // Set size of buffer to 64 characters
         lstrcpy(szDisplayName,
               TEXT("[Unable to find friendly name for privilege]"));
      }
      
      // Add the privilege to the list control
      LVITEM item = { 0 };
      item.mask = LVIF_TEXT | LVIF_IMAGE;
      item.iItem = 0;
      item.iImage = 4;
      item.pszText = szPrivileges[nIndex];
      int nIndex2 = ListView_InsertItem(hwndList, &item);
      ListView_SetItemText(hwndList, nIndex2, 1, szDisplayName);
   }
}


///////////////////////////////////////////////////////////////////////////////


void ImagePrivilegeList(HWND hwnd, PTSTR pszName, BOOL fAddHistory) {

   // Get state info
   PTRUSTEEMANSTATE ptmState = (PTRUSTEEMANSTATE) 
      GetWindowLongPtr(hwnd, DWLP_USER);

   BOOL fClearMode = FALSE;

   // Get the SID for the user name...
   CAutoBuf<SID> psid;
   if (lstrlen(pszName) > 0) {

      CAutoBuf<TCHAR, sizeof(TCHAR)> szDomain;
      TCHAR szComputer[256];
      SID_NAME_USE sidUse;
      GetComputer(hwnd, szComputer, chDIMOF(szComputer));
      BOOL fRet;
      do {
         // ...using LookupAccountName
         fRet = LookupAccountName(szComputer, pszName, psid, psid, szDomain,
            szDomain, &sidUse);
      } while (!fRet && (GetLastError() == ERROR_INSUFFICIENT_BUFFER));
      
      if (!fRet) {
         ReportError(TEXT("LookupAccountName"), GetLastError());
         // Error case, clear privilege indicators
         fClearMode = TRUE;
      } else {
         // Add convenience history
         HWND hwndCtrl = GetDlgItem(hwnd, IDC_TRUSTEE);
         if (fAddHistory && (ComboBox_FindStringExact(hwndCtrl, 0, pszName)
               == CB_ERR))
            ComboBox_AddString(hwndCtrl, pszName);
      }
   } else {
      // This says that we will be clearing the privilege indicators
      fClearMode = TRUE;
   }

   // If not clear mode, then we get a list of privileges for the trustee
   PLSA_UNICODE_STRING  pustrPrivileges = NULL;
   ULONG                ulCount = 0;
   if (!fClearMode) {

      // Get the privileges for a trustee
      NTSTATUS ntStatus = LsaEnumerateAccountRights(ptmState->m_hPolicy, psid,
         &pustrPrivileges, &ulCount);
      ULONG lErr = LsaNtStatusToWinError(ntStatus);
      if (ERROR_FILE_NOT_FOUND == lErr) {         
         ulCount = 0;      
      } else {         
         if (ERROR_SUCCESS != lErr) {
            ReportError(TEXT("LsaEnumerateAccountRights"), lErr);
            fClearMode = TRUE;
         }
      }
   }

   CLSAStr  lsastrPriv;
   TCHAR    szPriv[256];

   // Now update the list control
   HWND hwndList = GetDlgItem(hwnd, IDL_PRIVILEGES);
   ULONG nIndex = ListView_GetItemCount(hwndList);
   while (nIndex-- != 0) {

      // Not in clear mode? Then compare to find privileges
      int nImage = 0;
      if (!fClearMode) {

         // Get the item text
         ListView_GetItemText(hwndList, nIndex, 0, szPriv, chDIMOF(szPriv));

         ULONG nIndex2 = ulCount;
         BOOL fFound = FALSE;
         while (nIndex2-- != 0) {

            // Use clsastr to ease some of the issues with LSA strings
            lsastrPriv = pustrPrivileges[nIndex2];
            if (lstrcmpi(szPriv, lsastrPriv) == 0) {

               fFound = TRUE;
               break;
            }
         }
         nImage = fFound ? 2 : 3;
      } else nImage = 4;

      // Adjust the item
      LVITEM lvItem = { 0 };
      lvItem.mask = LVIF_IMAGE;
      lvItem.iImage = nImage;
      lvItem.iItem = nIndex;
      lvItem.iSubItem = 0;
      ListView_SetItem(hwndList, &lvItem);
   }
}


///////////////////////////////////////////////////////////////////////////////


void GrantSelectedPrivileges(HWND hwnd, PTSTR pszName, BOOL fGrant) {

   // Get state info
   PTRUSTEEMANSTATE ptmState = (PTRUSTEEMANSTATE) 
      GetWindowLongPtr(hwnd, DWLP_USER);

   // Without this handy class, the LSA_UNICODE_STRING would be tough here
   CLSAStr* plsaString = NULL;

   try { {

      // Give up if the trustee name is empty
      if (lstrlen(pszName) == 0)
         goto leave;

      TCHAR szComputer[256];
      GetComputer(hwnd, szComputer, chDIMOF(szComputer));

      // Get the SID for the account given.  If not, fail
      CAutoBuf<SID> psid;
      SID_NAME_USE sidUse;
      CAutoBuf<TCHAR, sizeof(TCHAR)> szDomain;
      BOOL fRet;
      
      do {
         fRet = LookupAccountName(szComputer, pszName, psid, psid, szDomain,
            szDomain, &sidUse);
      } while (!fRet && (GetLastError() == ERROR_INSUFFICIENT_BUFFER));
      
      if (!fRet) {
         ReportError(TEXT("LookupAccountName"), GetLastError());
         goto leave;
      }


      // How many selected... If zero, exit the function
      HWND hwndList = GetDlgItem(hwnd, IDL_PRIVILEGES);
      int nPrivCount = ListView_GetSelectedCount(hwndList);
      if (nPrivCount == 0)
         goto leave;

      // Create our array of LSA_UNICODE_STRING structures
      plsaString = new CLSAStr[nPrivCount];
      TCHAR szPrivilege[256];
      nPrivCount = 0;
      int nIndex = -1;
      for (;;) {
         // Get the next privilege that is selected
         nIndex = ListView_GetNextItem(hwndList, nIndex, LVNI_SELECTED);
         if (nIndex < 0)
            break;

         // Get its name, and create a LSA string out of it
         ListView_GetItemText(hwndList, nIndex, 0, szPrivilege,
            chDIMOF(szPrivilege));
         plsaString[nPrivCount++] = szPrivilege;
      }

      // If we still don't have any, then leave
      if (nPrivCount == 0)
         goto leave;

      // Add or remove privileges
      NTSTATUS ntStatus;
      if (fGrant)
         ntStatus = LsaAddAccountRights(ptmState->m_hPolicy, psid, plsaString,
            nPrivCount);
      else
         ntStatus = LsaRemoveAccountRights(ptmState->m_hPolicy, psid, FALSE,
            plsaString, nPrivCount);

      // Check errors
      ULONG lErr = LsaNtStatusToWinError(ntStatus);
      if (lErr == ERROR_SUCCESS)
         ImagePrivilegeList(hwnd, pszName, TRUE);
      else
         ReportError(TEXT("LsaAdd / RemoveAccountRights"), lErr);

   } leave:;
   }
   catch (...) {
   }

   // Delete array of LSA strings
   if (plsaString != NULL)
      delete[] plsaString;
}


///////////////////////////////////////////////////////////////////////////////


int AddTrusteeToList(HWND hwndList, PTSTR szText, BOOL fGroup) {

   LVITEM item = { 0 };
   item.mask = LVIF_TEXT | LVIF_IMAGE;
   item.iItem = 0;
   item.iImage = fGroup ? 0 : 1;
   item.pszText =  szText;
   int nIndex = ListView_InsertItem(hwndList, &item);
   ListView_SetItemText(hwndList, nIndex, 1, 
      fGroup ? TEXT("Group") : TEXT("User"));
   return(nIndex);
}


///////////////////////////////////////////////////////////////////////////////


void PopulateTrusteeList(HWND hwndDlg, TCHAR* pszComputer) {

   NET_API_STATUS netStatus;

   HWND hwndList = GetDlgItem(hwndDlg, IDL_TRUSTEES);
   ListView_DeleteAllItems(hwndList);

   // Enumerate local groups of the system, and add to the trustee list
   ULONG lIndex2 = 0;
   ULONG lRetEntries, lTotalEntries;
   ULONG_PTR ulPtr = 0;
   LOCALGROUP_INFO_0* pinfoGroups;
   
   do {
      netStatus = NetLocalGroupEnum(pszComputer, 0, (PBYTE*) &pinfoGroups,
         1000, &lRetEntries, &lTotalEntries, &ulPtr);
      if ((netStatus != ERROR_MORE_DATA) && (netStatus != NERR_Success)) {
         ReportError(TEXT("NetLocalGroupEnum"), netStatus);
         break;
      }

      if (lRetEntries != 0) {
         for (lIndex2 = 0; lIndex2 < lRetEntries; lIndex2++) {
            AddTrusteeToList(hwndList, pinfoGroups[lIndex2].lgrpi0_name, TRUE);
         }
      }
      
      // Free the buffer containing the local groups
      NetApiBufferFree(pinfoGroups);

   } while (netStatus == ERROR_MORE_DATA);

   // Enumerate users of the system and add to the trustee list
   ULONG lIndex = 0;
   NET_DISPLAY_USER* pnetUsers;
   do {
      
      // Because of the potentially many users on a system, this function
      // is more appropriate than NetUserEnum for UI programs.
      // We will return no more than 20000 users with this call in 1 k chunks
      netStatus = NetQueryDisplayInformation(pszComputer, 1, lIndex, 20000,
         1024, &lRetEntries, (PVOID*) &pnetUsers);
      if ((netStatus != ERROR_MORE_DATA) && (netStatus != NERR_Success)) {
         ReportError(TEXT("NetQueryDisplayInformation"), netStatus);
         break;
      }

      for (lIndex2 = 0; lIndex2 < lRetEntries; lIndex2++) {
         AddTrusteeToList(hwndList, pnetUsers[lIndex2].usri1_name, FALSE);
      }
      
      // Start enumeration where we left off
      lIndex = pnetUsers[lIndex2 - 1].usri1_next_index;
      
      // Free the buffer
      NetApiBufferFree(pnetUsers);

   } while (netStatus == ERROR_MORE_DATA);
}


///////////////////////////////////////////////////////////////////////////////


void UpdatePolicy(HWND hwnd) {

   // Get state info
   PTRUSTEEMANSTATE ptmState = (PTRUSTEEMANSTATE) 
      GetWindowLongPtr(hwnd, DWLP_USER);

   // Do we already have a valid policy object?
   if (ptmState->m_hPolicy != NULL) {

      LsaClose(ptmState->m_hPolicy);
      ptmState->m_hPolicy = NULL;
   }
   
   // Get computer name
   TCHAR szName[256];
   //GetComputer(hwnd, szName, chDIMOF(szName));
   HWND hwndCombo = GetDlgItem(hwnd, IDC_COMPUTER);
   int nIndex = ComboBox_GetCurSel(hwndCombo);
   if (nIndex == 0){
        // Local system
      ULONG lSize = chDIMOF(szName);
      GetComputerName(szName, &lSize);
   }else{
      ComboBox_GetText(hwndCombo, szName, chDIMOF(szName));
   }

   // Open a policy good for adjusting privileges and enumerating privileges
   CLSAStr lsastrComputer = szName;
   LSA_OBJECT_ATTRIBUTES lsaOA = { 0 };
   lsaOA.Length = sizeof(lsaOA);
   NTSTATUS ntStatus = LsaOpenPolicy(&lsastrComputer, &lsaOA,
      POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES
      | POLICY_CREATE_ACCOUNT, &ptmState->m_hPolicy);
   ULONG lErr = LsaNtStatusToWinError(ntStatus);
   
   if (lErr != ERROR_SUCCESS) {

      ReportError(TEXT("LsaOpenPolicy"), lErr);
      
      // Revert to local computer
      ComboBox_SetCurSel(GetDlgItem(hwnd, IDC_COMPUTER), 0);
      GetComputer(hwnd, szName, chDIMOF(szName));
      ntStatus = LsaOpenPolicy(NULL, &lsaOA, POLICY_VIEW_LOCAL_INFORMATION
         | POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT,
         &ptmState->m_hPolicy);
      lErr = LsaNtStatusToWinError(ntStatus);
      if (lErr != ERROR_SUCCESS) {
         ReportError(TEXT("LsaOpenPolicy"), lErr);
         MessageBox(hwnd, TEXT("TrusteeMan has no computer system to manage"),
            TEXT("TrusteeMan Notice"), MB_OK);
      }

      ptmState->m_szComputer[0] = 0;

   } else {
      
      // Success, add the computer to the combo box for convenient future use
      if (ComboBox_FindStringExact(GetDlgItem(hwnd, IDC_COMPUTER), 0, szName)
         == CB_ERR)
         ComboBox_AddString(GetDlgItem(hwnd, IDC_COMPUTER), szName);

      lstrcpy(ptmState->m_szComputer, szName);
   }

   // Populate the trustee list for the current system
   PopulateTrusteeList(hwnd, szName);

   // Reset privilege list
   SetDlgItemText(hwnd, IDC_TRUSTEE, TEXT(""));
   ImagePrivilegeList(hwnd, TEXT(""), TRUE);
}


///////////////////////////////////////////////////////////////////////////////


int CALLBACK SortView(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) {

   LPNMLISTVIEW pnmlListView = (LPNMLISTVIEW) lParamSort;
   int          nColumn      = pnmlListView->iSubItem;

   TCHAR szBuffer1[256];
   TCHAR szBuffer2[256];

   // Get the primary column of interest
   HWND hwndList = pnmlListView->hdr.hwndFrom;
   ListView_GetItemText(hwndList, lParam1, nColumn, szBuffer1,
      chDIMOF(szBuffer1));
   ListView_GetItemText(hwndList, lParam2, nColumn, szBuffer2,
      chDIMOF(szBuffer1));

   // Compare strings
   int nSort = lstrcmpi(szBuffer1, szBuffer2);
   if (nSort == 0) {
      // If equal, sort on the secondary column
      int nColumn2 = (nColumn == 1) ? 0 : 1;
      ListView_GetItemText(hwndList, lParam1, nColumn2, szBuffer1,
         chDIMOF(szBuffer1));
      ListView_GetItemText(hwndList, lParam2, nColumn2, szBuffer2,
         chDIMOF(szBuffer1));
      nSort = lstrcmpi(szBuffer1, szBuffer2);
   }
   return(nSort);
}


///////////////////////////////////////////////////////////////////////////////


BOOL AddGroup(HWND hwnd, PTSTR pszName) {

   TCHAR szName[256];
   GetComputer(hwnd, szName, chDIMOF(szName));

   LOCALGROUP_INFO_0 groupInfo = { 0 };
   groupInfo.lgrpi0_name = pszName;

   // Add group
   NET_API_STATUS netStatus = NetLocalGroupAdd(szName, 0, (PBYTE) &groupInfo,
      NULL);
   return(netStatus == NERR_Success);
}


///////////////////////////////////////////////////////////////////////////////


BOOL AddUser(HWND hwnd, PTSTR pszName) {

   // Get computer
   TCHAR szName[256];
   GetComputer(hwnd, szName, chDIMOF(szName));

   // Setup USER_INFO_1 structure
   USER_INFO_1 userInfo = { 0 };
   userInfo.usri1_name = pszName;

   // Trusteeman creates user accounts with a password of "Pass2000"
   userInfo.usri1_password = TEXT("Pass2000");
   userInfo.usri1_comment = TEXT("[Add User Comments Here]");
   userInfo.usri1_home_dir = NULL;
   userInfo.usri1_priv = USER_PRIV_USER;

   // Add the user
   NET_API_STATUS netStatus = NetUserAdd(szName, 1, (PBYTE) &userInfo, NULL);   
   return(netStatus == NERR_Success);
}


///////////////////////////////////////////////////////////////////////////////


BOOL RemoveTrustee(HWND hwnd, PTSTR szTrustee, TRUSTEE_T tType) {

   TCHAR          szComputer[256];
   NET_API_STATUS netStatus = NERR_Success;

   // Get computer name
   GetComputer(hwnd, szComputer, chDIMOF(szComputer));

   switch (tType) {
   case User:  // Delete user
      netStatus =  NetUserDel(szComputer, szTrustee);
      break;
   
   case Group: // Delete group
      netStatus =  NetLocalGroupDel(szComputer, szTrustee);
      break;
   }
   return(netStatus == NERR_Success);
}


///////////////////////////////////////////////////////////////////////////////


BOOL Dlg_OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam) {

   chSETDLGICONS(hwnd, IDI_TRUSTEEMAN);

   // We are using common controls in this sample
   InitCommonControls();

   PTRUSTEEMANSTATE ptmState = new TRUSTEEMANSTATE;
   chASSERT(ptmState != NULL);
   ptmState->m_himage = NULL;
   ptmState->m_hPolicy = NULL;
   ptmState->m_szComputer[0] = 0;
   // Set the pointer to the state structure as user data in the window
   SetWindowLongPtr(hwnd, DWLP_USER, (LONG_PTR) ptmState);

   // Setup resizer control
   ptmState->m_UILayout.Initialize(hwnd);
   ptmState->m_UILayout.AnchorControl(CUILayout::AP_TOPLEFT, CUILayout::AP_BOTTOMMIDDLE, IDL_TRUSTEES, FALSE);
   ptmState->m_UILayout.AnchorControl(CUILayout::AP_TOPMIDDLE, CUILayout::AP_BOTTOMRIGHT, IDL_PRIVILEGES, FALSE);
   ptmState->m_UILayout.AnchorControls(CUILayout::AP_TOPMIDDLE, CUILayout::AP_TOPMIDDLE, FALSE,
      IDS_TRUSTEE, IDC_TRUSTEE, IDB_USETRUSTEE, (UINT) -1);
   ptmState->m_UILayout.AnchorControls(CUILayout::AP_BOTTOMLEFT, CUILayout::AP_BOTTOMLEFT, FALSE,
      IDB_ADDUSER, IDB_ADDGROUP, IDB_REMOVE, IDB_EDITMEMBERS, (UINT) -1);
   ptmState->m_UILayout.AnchorControls(CUILayout::AP_BOTTOMMIDDLE, CUILayout::AP_BOTTOMMIDDLE, FALSE,
      IDB_PRIVILEGED, IDB_GRANT, IDB_REVOKE, (UINT) -1);

   // Set the icons for the graphical grant and revoke buttons
   HWND hwndButton = GetDlgItem(hwnd, IDB_GRANT);
   SendMessage(hwndButton, BM_SETIMAGE, IMAGE_ICON,
      (LPARAM) LoadImage(g_hInst, MAKEINTRESOURCE(IDI_GRANT), IMAGE_ICON, 93,
         16, LR_DEFAULTSIZE));
   hwndButton = GetDlgItem(hwnd, IDB_REVOKE);
   SendMessage(hwndButton, BM_SETIMAGE, IMAGE_ICON,
      (LPARAM) LoadImage(g_hInst, MAKEINTRESOURCE(IDI_REVOKE), IMAGE_ICON, 93,
         16, LR_DEFAULTSIZE));

   // Create image list
   ptmState->m_himage = ImageList_LoadBitmap(g_hInst,
      MAKEINTRESOURCE(IDB_IMAGE), 16, 1, RGB(255, 0, 255));

   // Set image list to the privileges dialog
   HWND hwndList = GetDlgItem(hwnd, IDL_PRIVILEGES);
   ListView_SetImageList(hwndList, ptmState->m_himage, LVSIL_SMALL);

   RECT rect;
   GetClientRect(hwndList, &rect);

   // Add Columns to privilege list control
   LVCOLUMN column = { 0 };
   column.mask = LVCF_TEXT | LVCF_WIDTH;
   column.pszText = TEXT("Privilege Programmatic Name");
   column.cx = rect.right / 2;
   ListView_InsertColumn(hwndList, 0, &column);

   column.mask = LVCF_TEXT | LVCF_WIDTH;
   column.pszText = TEXT("Privilege Friendly Name");
   column.cx = rect.right / 2;
   ListView_InsertColumn(hwndList, 1, &column);

   // Set image list to the trustees list control
   hwndList = GetDlgItem(hwnd, IDL_TRUSTEES);
   ListView_SetImageList(hwndList, ptmState->m_himage, LVSIL_SMALL);

   GetClientRect(hwndList, &rect);

   // Add columns to the trustee list control
   column.mask = LVCF_TEXT | LVCF_WIDTH;
   column.pszText = TEXT("Trustee Type");
   column.cx = 100;
   ListView_InsertColumn(hwndList, 0, &column);

   column.mask = LVCF_TEXT | LVCF_WIDTH;
   column.pszText = TEXT("Trustee Name");
   column.cx = rect.right - 100;
   ListView_InsertColumn(hwndList, 0, &column);

   // Make sure there is at least one option in the computer combo box
   ComboBox_AddString(GetDlgItem(hwnd, IDC_COMPUTER), 
      TEXT("[Local Computer]"));
   ComboBox_SetCurSel(GetDlgItem(hwnd, IDC_COMPUTER), 0);
   // Setup Policy for the current settings
   UpdatePolicy(hwnd);

   // Populate the privilige list control
   PopulatePrivilegeList(hwnd);

   EnableControls(hwnd); 

   return(TRUE);
}


///////////////////////////////////////////////////////////////////////////////


BOOL HandlePrivilegesNotify(HWND hwnd, LPNMHDR pnmhdr) {

   switch (pnmhdr->code) {
   case LVN_ITEMCHANGED:
      EnableControls(hwnd);
      break;
   case LVN_COLUMNCLICK:   // Sort by selected column
      LPNMLISTVIEW pnmlListView = (LPNMLISTVIEW) pnmhdr;
      ListView_SortItemsEx(pnmhdr->hwndFrom, SortView, pnmlListView);
      break;
   }
   return(FALSE);
}


///////////////////////////////////////////////////////////////////////////////


BOOL HandleTrusteesNotify(HWND hwnd, LPNMHDR pnmhdr) {

   BOOL              fReturn = FALSE;
   LPNMLVDISPINFOW   pnmlvDispInfo;
   LPNMLISTVIEW      pnmlListView;

   switch (pnmhdr->code) {
   case LVN_ITEMCHANGED: 
      {
      TCHAR szBuffer[1024];
      pnmlListView = (LPNMLISTVIEW) pnmhdr;
      if (pnmlListView->uNewState != pnmlListView->uOldState) {
         // If selected change current trustee for privileges
         // (Only if it is in the non-editing state)
         if (((pnmlListView->uNewState & LVIS_SELECTED) != 0) && 
             (pnmlListView->lParam == 0)) {
            ListView_GetItemText(pnmhdr->hwndFrom, pnmlListView->iItem, 
               0, szBuffer, chDIMOF(szBuffer));
            ComboBox_SetText(GetDlgItem(hwnd, IDC_TRUSTEE), szBuffer);
            // Update privilege list
            ImagePrivilegeList(hwnd, szBuffer, FALSE);
         }
      }
      EnableControls(hwnd);      
      }
      break;

   case LVN_BEGINLABELEDIT:
      // Deny any label edit user initiated label edits
      pnmlvDispInfo = (LPNMLVDISPINFOW) pnmhdr;
      fReturn = (pnmlvDispInfo->item.lParam == 0);
      break;

   case LVN_ENDLABELEDIT: 
      {
      BOOL     fAdded;

      // Handle end of edit for new trustee
      pnmlvDispInfo = (LPNMLVDISPINFOW) pnmhdr;
      if ((pnmlvDispInfo->item.pszText == NULL) || 
         (pnmlvDispInfo->item.pszText[0] == TEXT('['))) {
         // Clear new item if it is empty or still has the starting text
         fAdded = FALSE;
      } else {
         if (pnmlvDispInfo->item.lParam == Group) {
            fAdded = AddGroup(hwnd, pnmlvDispInfo->item.pszText);
         } else {
            fAdded = AddUser(hwnd, pnmlvDispInfo->item.pszText);            
         }
      }
      // If not, then delete list view entry
      if (fAdded == FALSE) {
         ListView_DeleteItem(pnmlvDispInfo->hdr.hwndFrom, 
            pnmlvDispInfo->item.iItem);
      } else {
         // Otherwise, finish off the item, and set the lparam to zero
         LVITEM lvItem;
         lvItem.mask = LVIF_PARAM | LVIF_STATE;
         lvItem.iItem = pnmlvDispInfo->item.iItem;
         lvItem.iSubItem = 0;
         lvItem.lParam = 0;
         lvItem.state = 0;
         ListView_SetItem(pnmlvDispInfo->hdr.hwndFrom, &lvItem);

         ComboBox_SetText(GetDlgItem(hwnd, IDC_TRUSTEE), 
            pnmlvDispInfo->item.pszText);
         ImagePrivilegeList(hwnd, pnmlvDispInfo->item.pszText, FALSE);

         fReturn = TRUE;
      }
      }
      break;

   case LVN_COLUMNCLICK:   // Sort by selected column
      pnmlListView = (LPNMLISTVIEW) pnmhdr;
      ListView_SortItemsEx(pnmhdr->hwndFrom, SortView, pnmlListView);
      break;
   }
   return(fReturn);
}


///////////////////////////////////////////////////////////////////////////////


BOOL Dlg_OnNotify(HWND hwnd, int idCtrl, LPNMHDR pnmhdr) {

   BOOL fReturn = FALSE;
   switch (idCtrl) {
   case IDL_PRIVILEGES:
      fReturn = HandlePrivilegesNotify(hwnd, pnmhdr);
      break;

   case IDL_TRUSTEES:
      fReturn = HandleTrusteesNotify(hwnd, pnmhdr);
      break;
   }
   return(fReturn);
}


///////////////////////////////////////////////////////////////////////////////


void HandlePrivileged(HWND hwnd) {
   
   HWND hwndList = GetDlgItem(hwnd, IDL_PRIVILEGES);
   int nIndex = ListView_GetNextItem(hwndList, -1, LVNI_SELECTED);
   if (nIndex >= 0) {
      TCHAR szName[256];
      ListView_GetItemText(hwndList, nIndex, 0, szName, chDIMOF(szName));
      PriviligedTrustees(hwnd, szName);
   }
}


///////////////////////////////////////////////////////////////////////////////


void HandleEditMembers(HWND hwnd) {
   HWND hwndList = GetDlgItem(hwnd, IDL_TRUSTEES);
   int nIndex = ListView_GetNextItem(hwndList, -1, LVNI_SELECTED);
   if (nIndex >= 0) {
      TCHAR szName[256];
      TCHAR szType[25];

      // Get the items name and type
      ListView_GetItemText(hwndList, nIndex, 0, szName, chDIMOF(szName));
      ListView_GetItemText(hwndList, nIndex, 1, szType, chDIMOF(szType));
      if (szType[0] == TEXT('G'))  {
         // If it is a group, then edit its members
         GroupMembers(hwnd, szName);
      } else {
         MessageBox(hwnd, TEXT("You can not edit the member list of a user."),
            TEXT("TrusteeMan Notice"), MB_OK);
      }
   }
}


///////////////////////////////////////////////////////////////////////////////


void HandleRemove(HWND hwnd) {
   HWND hwndList = GetDlgItem(hwnd, IDL_TRUSTEES);
   
   // Get the selected item
   int nIndex = ListView_GetNextItem(hwndList, -1, LVNI_SELECTED);
   if (nIndex >= 0) {
      TCHAR szName[256];
      TCHAR szType[25];
      BOOL  fRemoved = FALSE;

      // Get its name and type
      ListView_GetItemText(hwndList, nIndex, 0, szName, chDIMOF(szName));
      ListView_GetItemText(hwndList, nIndex, 1, szType, chDIMOF(szType));
      fRemoved = RemoveTrustee(hwnd, szName, 
         (szType[0] == TEXT('G')) ? Group : User);

      // Delete the actual item from the list control
      if (fRemoved) {
         ListView_DeleteItem(hwndList, nIndex);
         ImagePrivilegeList(hwnd, TEXT(""), FALSE);
      }
   }
}


///////////////////////////////////////////////////////////////////////////////


void HandleAddTrustee(HWND hwnd, TRUSTEE_T tType) {

   if (tType == User) {
      MessageBox(hwnd, TEXT("TrusteeMan creates user accounts with a\n")
         TEXT("password of \"Pass2000.\"  Use the MMC or \n")
         TEXT("another tool to change the password for user \naccounts."), 
         TEXT("TrusteeMan Notice"), MB_OK);
   }

   // ntype 1 == User, ntype 2 == Group
   HWND hwndList = GetDlgItem(hwnd, IDL_TRUSTEES);
   
   // Add a new trustee account to the list box
   PTSTR pszText = (tType == User) ? TEXT("[New User]") : TEXT("[New Group]");
   int nIndex = AddTrusteeToList(hwndList, pszText, tType == Group);
   LVITEM lvItem = { 0 };
   lvItem.mask = LVIF_PARAM;
   
   // When edit finishes, lparam indicates type of trustee to add
   lvItem.lParam = tType;
   lvItem.iItem = nIndex;
   lvItem.iSubItem = 0;
   ListView_SetItem(hwndList, &lvItem);

   // Set focus to list box, and then begin item editing
   SetFocus(hwndList);
   ListView_EditLabel(hwndList, nIndex);
}


///////////////////////////////////////////////////////////////////////////////


void HandleGrantRevoke(HWND hwnd, BOOL fGrant) {
   TCHAR szName[256];
   // Get Trustee name
   GetDlgItemText(hwnd, IDC_TRUSTEE, szName, chDIMOF(szName));

   // Grant or revoke selected privileges for the trustee
   GrantSelectedPrivileges(hwnd, szName, fGrant);
}


///////////////////////////////////////////////////////////////////////////////


void HandleTrustee(HWND hwnd, UINT codeNotify, HWND hwndCtl) {
   switch (codeNotify) {
   case CBN_SELENDOK:
      TCHAR szName[256];
      // Trustee selected from combo box
      int nIndex = ComboBox_GetCurSel(hwndCtl);
      ComboBox_GetLBText(hwndCtl, nIndex, szName);
      ImagePrivilegeList(hwnd, szName, FALSE);
      break;
   }
}


///////////////////////////////////////////////////////////////////////////////


void HandleUpdatePriv(HWND hwnd) {
   TCHAR szName[256];
   GetDlgItemText(hwnd, IDC_TRUSTEE, szName, chDIMOF(szName));
   // Update privilege list for the new trustee
   ImagePrivilegeList(hwnd, szName, TRUE);
}


///////////////////////////////////////////////////////////////////////////////


void HandleComputer(HWND hwnd, UINT codeNotify, HWND hwndCtl) {
   switch (codeNotify) {
   case CBN_SELENDOK:
      TCHAR szName[256];
      // Computer selected from combo box
      int nIndex = ComboBox_GetCurSel(hwndCtl);
      ComboBox_GetLBText(hwndCtl, nIndex, szName);
      SetWindowText(hwndCtl, szName);
      // Use the new computer name
      UpdatePolicy(hwnd);
      break;
   }
}


///////////////////////////////////////////////////////////////////////////////


void Dlg_OnCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify) {

   switch (id) {
   case IDCANCEL:
      {
      // Get state info
      PTRUSTEEMANSTATE ptmState = (PTRUSTEEMANSTATE) 
         GetWindowLongPtr(hwnd, DWLP_USER);

      // Cleanup policy object
      if (ptmState->m_hPolicy != NULL)
         LsaClose(ptmState->m_hPolicy);

      delete ptmState;
      EndDialog(hwnd, id);
      }
      break;

   case IDC_COMPUTER:
      HandleComputer(hwnd, codeNotify, hwndCtl);
      break;

   case IDB_USETRUSTEE:
      HandleUpdatePriv(hwnd);
      break;

   case IDC_TRUSTEE:
      HandleTrustee(hwnd, codeNotify, hwndCtl);
      break;

   case IDB_GRANT:
      HandleGrantRevoke(hwnd, TRUE);
      break;

   case IDB_REVOKE:
      HandleGrantRevoke(hwnd, FALSE);
      break;

   case IDB_USECOMPUTER:
      UpdatePolicy(hwnd);
      break;

   case IDB_ADDGROUP:
      HandleAddTrustee(hwnd, Group);
      break;

   case IDB_ADDUSER:
      HandleAddTrustee(hwnd, User);
      break;

   case IDB_REMOVE:
      HandleRemove(hwnd);
      break;

   case IDB_EDITMEMBERS:
      HandleEditMembers(hwnd);
      break;

   case IDB_PRIVILEGED:
      HandlePrivileged(hwnd);
      break;
   }
}


///////////////////////////////////////////////////////////////////////////////


void Dlg_OnContextMenu(HWND hwnd, HWND hwndContext, UINT xPos, UINT yPos) {

   // Which control are we creating a context menu for
   LONG_PTR lID = GetWindowLongPtr(hwndContext, GWLP_ID);

   // Load that holds the popup menus
   HMENU hMenu = LoadMenu(g_hInst, MAKEINTRESOURCE(IDM_POPUPS));
   HMENU hMenuPopup = GetSubMenu(hMenu, (lID == IDL_TRUSTEES) ? 0 : 1);
   chASSERT(hMenuPopup != NULL);
   TrackPopupMenu(hMenuPopup, TPM_TOPALIGN | TPM_LEFTALIGN | TPM_LEFTBUTTON, 
      xPos, yPos, 0, hwnd, NULL);
}


///////////////////////////////////////////////////////////////////////////////


void Dlg_OnSize(HWND hwnd, UINT state, int cx, int cy) {
   // Get state info
   PTRUSTEEMANSTATE ptmState = (PTRUSTEEMANSTATE) 
      GetWindowLongPtr(hwnd, DWLP_USER);

   // Simply call the adjustcontrols function of our handy resizer class
   ptmState->m_UILayout.AdjustControls(cx, cy);
}


///////////////////////////////////////////////////////////////////////////////


void Dlg_OnGetMinMaxInfo(HWND hwnd, PMINMAXINFO pMinMaxInfo) {

   // Get state info
   PTRUSTEEMANSTATE ptmState = (PTRUSTEEMANSTATE) 
      GetWindowLongPtr(hwnd, DWLP_USER);

   // Just calling another resizer function
   ptmState->m_UILayout.HandleMinMax(pMinMaxInfo);
}


///////////////////////////////////////////////////////////////////////////////


INT_PTR WINAPI Dlg_Proc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {

   switch (uMsg) {
   chHANDLE_DLGMSG(hwnd, WM_INITDIALOG,    Dlg_OnInitDialog);
   chHANDLE_DLGMSG(hwnd, WM_SIZE,          Dlg_OnSize);
   chHANDLE_DLGMSG(hwnd, WM_GETMINMAXINFO, Dlg_OnGetMinMaxInfo);
   chHANDLE_DLGMSG(hwnd, WM_COMMAND,       Dlg_OnCommand);
   chHANDLE_DLGMSG(hwnd, WM_NOTIFY,        Dlg_OnNotify);
   chHANDLE_DLGMSG(hwnd, WM_CONTEXTMENU,   Dlg_OnContextMenu);
   }
   return (FALSE);
}


///////////////////////////////////////////////////////////////////////////////


int WINAPI _tWinMain(HINSTANCE hinstExe, HINSTANCE, PTSTR pszCmdLine, int) {

   g_hInst = hinstExe;
   DialogBox(hinstExe, MAKEINTRESOURCE(IDD_TRUSTEEMAN), NULL, Dlg_Proc);
   return (0);
}


///////////////////////////////// End of File /////////////////////////////////