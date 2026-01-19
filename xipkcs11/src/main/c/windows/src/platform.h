/* defines for WIN32 platform */

#ifndef PLATFORM_H_
#define PLATFORM_H_

/* statement according to PKCS11 docu */
#pragma pack(push, cryptoki, 1)

/* definitions according to PKCS#11 docu for Win32 environment */
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType __declspec(dllexport) name
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
/*#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)*/
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)

#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif /* NULL_PTR */

/* to avoid clash with Win32 #define */
#ifdef CreateMutex
#undef CreateMutex
#endif /* CreateMutex */

#include "pkcs11.h"
#include <stdlib.h>

/* statement according to PKCS11 docu */
#pragma pack(pop, cryptoki)

//#include "jni.h"

/* A data structure to hold handle to a PKCS#11 module. */
typedef struct P11ModuleHandle {
  /* the module (DLL) handle */
  HINSTANCE hLib;
} P11ModuleHandle;

#endif // PLATFORM_H
