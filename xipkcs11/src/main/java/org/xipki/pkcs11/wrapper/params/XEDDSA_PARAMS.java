// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.EncodeList;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11Module;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * <pre>
 * typedef struct CK_XEDDSA_PARAMS {
 *       CK_XEDDSA_HASH_TYPE  hash;
 * } CK_XEDDSA_PARAMS;
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class XEDDSA_PARAMS extends CkParams {

  private final long hash;

  public XEDDSA_PARAMS(long hash) {
    this.hash = hash;
  }

  public long hash() {
    return hash;
  }

  @Override
  public ParamsType type() {
    return ParamsType.XEDDSA_PARAMS;
  }

  @Override
  protected void addContent(EncodeList contents) {
    contents.v(hash);
  }

  @Override
  public CkParams vendorCopy(PKCS11Module module) {
    long vendorHash = module.genericToVendorCode(Category.CKM, hash);
    if (hash == vendorHash) {
      return this;
    }
    return new XEDDSA_PARAMS(vendorHash);
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    return toString(indent, module, "hash", hash);
  }

  public static XEDDSA_PARAMS decode(
      Arch arch, byte[] encoded, AtomicInteger off)
      throws PKCS11Exception {
    assertType(encoded, off, ParamsType.XEDDSA_PARAMS);
    long hash = readLong(arch, encoded, off);
    return new XEDDSA_PARAMS(hash);
  }

}
