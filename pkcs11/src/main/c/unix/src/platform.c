#include "platform.h"
#include "pkcs11wrapper.h"
#include <dlfcn.h>
#include <stdlib.h>

CK_ULONG p11_open_lib(P11ModuleHandle* phModule, char* libPath)
{
  void* hLib = dlopen(libPath, RTLD_LAZY); // RTLD_NOW
  if (hLib == NULL_PTR) {
    return CKR_JNI_OPEN_LIB;
  }

  phModule->hLib = hLib;
  return CKR_OK;
}

void *p11_get_lib_symbol(P11ModuleHandle hModule, const char *symbol)
{
  return dlsym(hModule.hLib, symbol);
}

CK_ULONG p11_close_lib(P11ModuleHandle hModule)
{
  dlclose(hModule.hLib);
  return CKR_OK;
}
