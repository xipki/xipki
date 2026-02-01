// Copyright (c) 2013-2026 xipki. All rights reserved.
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
 * Represents the CK_HASH_SIGN_ADDITIONAL_CONTEXT.
 * <pre>
 * typedef struct CK_HASH_SIGN_ADDITIONAL_CONTEXT {
 *    CK_HEDGE_TYPE      hedgeVariant;
 *    CK_BYTE_PTR        pContext;
 *    CK_ULONG           ulContextLen;
 *    CK_MECHANISM_TYPE  hash;
 * } CK_HASH_SIGN_ADDITIONAL_CONTEXT;
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class HASH_SIGN_ADDITIONAL_CONTEXT extends CkParams {

  private final long hedgeVariant;

  private final byte[] context;

  private final long hash;

  public HASH_SIGN_ADDITIONAL_CONTEXT(
      long hedgeVariant, byte[] context, long hash) {
    this.hedgeVariant = hedgeVariant;
    this.context = context;
    this.hash = hash;
  }

  public long hedgeVariant() {
    return hedgeVariant;
  }

  public byte[] context() {
    return context;
  }

  public long hash() {
    return hash;
  }

  @Override
  public ParamsType type() {
    return ParamsType.HASH_SIGN_ADDITIONAL_CONTEXT;
  }

  @Override
  protected void addContent(EncodeList contents) {
    contents.v(hedgeVariant).v(context).v(hash);
  }

  @Override
  public CkParams vendorCopy(PKCS11Module module) {
    long vendorHash = module.genericToVendorCode(Category.CKM, hash);
    if (hash == vendorHash) {
      return this;
    }
    return new HASH_SIGN_ADDITIONAL_CONTEXT(hedgeVariant, context, vendorHash);
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    return toString(indent, module, "hedgeVariant",
        PKCS11T.codeToName(Category.CKH_HEDGE, hedgeVariant),
        "pContext", context, "hash", PKCS11T.ckmCodeToName(hash));
  }

  public static HASH_SIGN_ADDITIONAL_CONTEXT decode(
      Arch arch, byte[] encoded, AtomicInteger off)
      throws PKCS11Exception {
    assertType(encoded, off, ParamsType.HASH_SIGN_ADDITIONAL_CONTEXT);
    return new HASH_SIGN_ADDITIONAL_CONTEXT(readLong(arch, encoded, off),
        readByteArray(arch, encoded, off), readLong(arch, encoded, off));
  }

}

