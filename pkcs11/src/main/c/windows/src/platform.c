#include "platform.h"
#include "pkcs11wrapper.h"
#include <stdlib.h>
#include <windows.h>

CK_ULONG p11_open_lib(P11ModuleHandle* phModule, char* libPath)
{
  HINSTANCE hLib = LoadLibrary(libPath);
  if (hLib == NULL) {
    return CKR_JNI_OPEN_LIB;
  }

  phModule->hLib = hLib;
  return CKR_OK;
}

void *p11_get_lib_symbol(P11ModuleHandle hModule, const char *symbol)
{
  return GetProcAddress(hModule.hLib, symbol);
}

CK_ULONG p11_close_lib(P11ModuleHandle hModule)
{
  FreeLibrary(hModule.hLib);
  return CKR_OK;
}
