// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.EncodeList;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11Module;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Represents the CK_EDDSA_PARAMS.
 * <pre>
 * typedef struct CK_EDDSA_PARAMS {
 *    CK_BBOOL     phFlag;
 *    CK_ULONG     ulContextDataLen;
 *    CK_BYTE_PTR  pContextData;
 * }  CK_EDDSA_PARAMS;
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EDDSA_PARAMS extends CkParams {

  private final boolean phFlag;

  private final byte[] context;

  public EDDSA_PARAMS(boolean phFlag, byte[] context) {
    this.phFlag = phFlag;
    this.context = context;
  }

  public boolean phFlag() {
    return phFlag;
  }

  public byte[] context() {
    return context;
  }

  @Override
  public ParamsType type() {
    return ParamsType.EDDSA_PARAMS;
  }

  @Override
  protected void addContent(EncodeList contents) {
    contents.v(phFlag).v(context);
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    return toString(indent, module, "phFlag", phFlag, "pContext", context);
  }

  public static EDDSA_PARAMS decode(
      Arch arch, byte[] encoded, AtomicInteger off)
      throws PKCS11Exception {
    assertType(encoded, off, ParamsType.EDDSA_PARAMS);
    return new EDDSA_PARAMS(encoded[off.getAndIncrement()] != 0,
        readByteArray(arch, encoded, off));
  }

}

