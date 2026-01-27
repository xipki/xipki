// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.jni;

import static org.xipki.pkcs11.wrapper.jni.PKCS11.ATTRS2_R;
import static org.xipki.pkcs11.wrapper.jni.PKCS11.ATTRS_R;
import static org.xipki.pkcs11.wrapper.jni.PKCS11.DATA2_R;
import static org.xipki.pkcs11.wrapper.jni.PKCS11.DATA_O;
import static org.xipki.pkcs11.wrapper.jni.PKCS11.DATA_R;
import static org.xipki.pkcs11.wrapper.jni.PKCS11.METH_O;
import static org.xipki.pkcs11.wrapper.jni.PKCS11.METH_R;

/**
 * Enumeration of JNI operations for the C_* PKCS#11 functions.
 *
 * @author Lijun Liao (xipki)
 */
public enum JniOperation {

  // v2.x functions
  C_GetAttributeValueX(1),

  C_Initialize        (2),
  C_Finalize          (3),
  C_GetInfo           (4),
  //C_GetFunctionList -- will be used in the native code only
  C_GetSlotList       (5),
  C_GetSlotInfo       (6),
  C_GetTokenInfo      (7),
  C_GetMechanismList  (8),
  C_GetMechanismInfo  (9),
  C_OpenSession       (10),
  C_CloseSession      (11),
  C_CloseAllSessions  (12),
  C_GetSessionInfo    (13),
  C_Login             (14 | DATA_O),
  C_Logout            (15),
  C_CreateObject      (16 | ATTRS_R),
  C_CopyObject        (17 | ATTRS_R),
  C_DestroyObject     (18),
  C_GetAttributeValue (19 | DATA_R),
  C_SetAttributeValue (20 | ATTRS_R),
  C_FindObjectsInit   (21 | ATTRS_R),
  C_FindObjects       (22),
  C_FindObjectsFinal  (23),
  C_DigestInit        (24 | METH_R),
  C_Digest            (25 | DATA_R),
  C_DigestUpdate      (26 | DATA_R),
  C_DigestKey         (27),
  C_DigestFinal       (28),
  C_SignInit          (29 | METH_R),
  C_Sign              (30 | METH_O | DATA_R),
  C_SignUpdate        (31 | DATA_R),
  C_SignFinal         (32 | METH_O),
  C_GenerateKey       (33 | METH_R | ATTRS_R),
  C_GenerateKeyPair   (34 | METH_R | ATTRS_R | ATTRS2_R),

  // version 3.0 functions
  //C_GetInterfaceList, will be used in the native code only
  //C_GetInterface, will be used in the native code only
  C_LoginUser         (35 | DATA_O | DATA2_R),
  C_SessionCancel     (36),

  // v3.2 functions
  C_DecapsulateKey    (37 | METH_R | DATA_R | ATTRS_R);

  // caution: use maximal 16 bits to support 32-bit OS.
  private final int code;

  JniOperation(int code) {
    this.code = code;
  }

  public int getCode() {
    return code;
  }

  public static JniOperation ofCode(int code) {
    for (JniOperation op : JniOperation.values()) {
      if (op.code == code) {
        return op;
      }
    }
    return null;
  }

}
