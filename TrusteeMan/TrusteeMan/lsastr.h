/******************************************************************************
Module:  LSAStr.h
Notices: Copyright (c) 2000 Jeffrey Richter
******************************************************************************/


class CLSAStr : public LSA_UNICODE_STRING {
public:
   CLSAStr() { ResetInstance(TRUE); }
   CLSAStr(PWSTR pstr) {
      ResetInstance(TRUE);
      AssignString(pstr);      
   }
   CLSAStr(LSA_UNICODE_STRING &lsastr) {
      ResetInstance(TRUE);
      AssignLSAStr(&lsastr);      
   }
   CLSAStr(PLSA_UNICODE_STRING plsastr) {
      ResetInstance(TRUE);
      AssignLSAStr(plsastr);      
   }
   CLSAStr(CLSAStr &lsaStr) {
      ResetInstance(TRUE);
      AssignLSAStr(&lsaStr);      
   }

   ~CLSAStr() { ResetInstance(FALSE); }

   operator PWSTR() {return(Buffer); }
   CLSAStr& operator =(LSA_UNICODE_STRING &lsastr) { AssignLSAStr(&lsastr); return *this; }
   CLSAStr& operator =(PLSA_UNICODE_STRING plsastr) { AssignLSAStr(plsastr); return *this; }
   CLSAStr& operator =(PWSTR pstr) { AssignString(pstr); return *this; }

private:
   void ResetInstance(BOOL fConstructing = FALSE) {
      if (!fConstructing && Buffer)
         HeapFree(GetProcessHeap(), 0, Buffer);
      Buffer = NULL;
      Length = MaximumLength = 0;      
   }

   void AssignString(PWSTR pstr) {
      USHORT nLength = (USHORT)(lstrlen(pstr) * sizeof(WCHAR));
      if (AdjustBuffer((USHORT) (nLength + sizeof(WCHAR)))) {
         lstrcpy(Buffer, pstr);
         Length = nLength;         
      }      
   }

   void AssignLSAStr(PLSA_UNICODE_STRING plsastr) {
      if (AdjustBuffer((USHORT) (plsastr->Length + sizeof(WCHAR)))) {
         CopyMemory(Buffer, plsastr->Buffer, plsastr->Length);
         Length = plsastr->Length;
         Buffer[Length / sizeof(WCHAR)] = 0;         
      }
   }

   BOOL AdjustBuffer(USHORT nMax) {
      BOOL fReturn = FALSE;
      if (MaximumLength < nMax) {
         ResetInstance();
         Buffer = (WCHAR*) HeapAlloc(GetProcessHeap(), 0, nMax);
         if (Buffer) {
            MaximumLength = nMax;
            fReturn = TRUE;
         }
      } else fReturn = TRUE;
      return(fReturn);
   }
};


///////////////////////////////// End of File /////////////////////////////////