// Copyright (c) 2022-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.EncodeList;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.util.codec.Args;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Represents the CK_ECDH1_DERIVE_PARAMS.
 * <pre>
 * typedef struct CK_ECDH1_DERIVE_PARAMS {
 *    CK_EC_KDF_TYPE  kdf;
 *    CK_ULONG        ulSharedDataLen;
 *    CK_BYTE_PTR     pSharedData;
 *    CK_ULONG        ulPublicDataLen;
 *    CK_BYTE_PTR     pPublicData;
 * }  CK_ECDH1_DERIVE_PARAMS;
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ECDH1_DERIVE_PARAMS extends CkParams {

  private final long kdf;

  private final byte[] sharedData;

  private final byte[] publicData;

  /**
   * Create a new ECDH1_DERIVE_PARAMS object with the given
   * attributes.
   *
   * @param kdf
   *        The key derivation function used on the shared secret value.
   *        One of the values defined in KeyDerivationFunctionType.
   * @param sharedData
   *        The data shared between the two parties.
   * @param publicData
   *        The other party's public key value.
   */
  public ECDH1_DERIVE_PARAMS(long kdf, byte[] sharedData, byte[] publicData) {
    this.kdf = kdf;
    this.sharedData = sharedData;
    this.publicData = Args.notNull(publicData, "publicData");
  }

  public long kdf() {
    return kdf;
  }

  public byte[] sharedData() {
    return sharedData;
  }

  public byte[] publicData() {
    return publicData;
  }

  public ECDH1_DERIVE_PARAMS vendorCopy(PKCS11Module module) {
    if (module == null) {
      return this;
    }

    long vendorKdf = module.genericToVendorCode(Category.CKD, kdf);
    if (kdf == vendorKdf) {
      return this;
    }
    return new ECDH1_DERIVE_PARAMS(vendorKdf, sharedData, publicData);
  }

  @Override
  public ParamsType type() {
    return ParamsType.ECDH1_DERIVE_PARAMS;
  }

  @Override
  protected void addContent(EncodeList contents) {
    contents.v(kdf).v(sharedData).v(publicData);
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    return toString(indent, module, "kdf", ckdName(kdf, module),
        "pPublicData", publicData, "pSharedData", sharedData);
  }

  public static ECDH1_DERIVE_PARAMS decode(Arch arch, byte[] encoded, AtomicInteger off)
      throws PKCS11Exception {
    assertType(encoded, off, ParamsType.ECDH1_DERIVE_PARAMS);
    return new ECDH1_DERIVE_PARAMS(readLong(arch, encoded, off),
        readByteArray(arch, encoded, off), // sharedData
        readByteArray(arch, encoded, off)); // publicData
  }

}
