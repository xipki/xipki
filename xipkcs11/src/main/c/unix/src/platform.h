/* defines for UNIX platforms */

#ifndef PLATFORM_H_
#define PLATFORM_H_

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

/* A data structure to hold handle to a PKCS#11 module. */
typedef struct P11ModuleHandle {
  /* the module handle */
  void* hLib;
} P11ModuleHandle;

#endif // PLATFORM_H
