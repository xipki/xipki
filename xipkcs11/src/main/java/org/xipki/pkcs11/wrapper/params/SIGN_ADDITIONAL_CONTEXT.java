// Copyright (c) 2022-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.EncodeList;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.pkcs11.wrapper.PKCS11T;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Represents the CK_SIGN_ADDITIONAL_CONTEXT.
 * <pre>
 * typedef struct CK_SIGN_ADDITIONAL_CONTEXT {
 *    CK_HEDGE_TYPE  hedgeVariant;
 *    CK_BYTE_PTR    pContext;
 *    CK_ULONG       ulContextLen;
 * } CK_SIGN_ADDITIONAL_CONTEXT;
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SIGN_ADDITIONAL_CONTEXT extends CkParams {

  private final long hedgeVariant;

  private final byte[] context;

  public SIGN_ADDITIONAL_CONTEXT(long hedgeVariant, byte[] context) {
    this.hedgeVariant = hedgeVariant;
    this.context = context;
  }

  public long hedgeVariant() {
    return hedgeVariant;
  }

  public byte[] context() {
    return context;
  }

  @Override
  public ParamsType type() {
    return ParamsType.SIGN_ADDITIONAL_CONTEXT;
  }

  @Override
  protected void addContent(EncodeList contents) {
    contents.v(hedgeVariant).v(context);
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    return toString(indent, module,
        "hedgeVariant", PKCS11T.codeToName(Category.CKH_HEDGE, hedgeVariant),
        "pContext", context);
  }

  public static SIGN_ADDITIONAL_CONTEXT decode(
      Arch arch, byte[] encoded, AtomicInteger off)
      throws PKCS11Exception {
    assertType(encoded, off, ParamsType.SIGN_ADDITIONAL_CONTEXT);
    return new SIGN_ADDITIONAL_CONTEXT(
        readLong(arch, encoded, off), readByteArray(arch, encoded, off));
  }

}

