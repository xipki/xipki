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
 * Represents the CK_RSA_PKCS_PSS_PARAMS.
 *
 * <pre>
 * typedef struct CK_RSA_PKCS_PSS_PARAMS {
 *    CK_MECHANISM_TYPE     hashAlg;
 *    CK_RSA_PKCS_MGF_TYPE  mgf;
 *    CK_ULONG              sLen;
 * }  CK_RSA_PKCS_PSS_PARAMS;
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class RSA_PKCS_PSS_PARAMS extends CkParams {

  private final long hashAlg;

  private final long mgf;

  private final int sLen;

  /**
   * Create a new CK_RSA_PKCS_PSS_PARAMS object with the given attributes.
   *
   * @param hashAlg
   *        The message digest algorithm used to calculate the digest of the
   *        encoding parameter.
   * @param mgf
   *        The mask to apply to the encoded block. One of the constants
   *        defined in the MessageGenerationFunctionType interface.
   * @param saltLength
   *        The length of the salt value in octets.
   */
  public RSA_PKCS_PSS_PARAMS(long hashAlg, long mgf, int saltLength) {
    this.hashAlg = hashAlg;
    this.mgf = mgf;
    this.sLen = saltLength;
  }

  public long hashAlg() {
    return hashAlg;
  }

  public long mgf() {
    return mgf;
  }

  public long sLen() {
    return sLen;
  }

  @Override
  public RSA_PKCS_PSS_PARAMS vendorCopy(PKCS11Module module) {
    if (module == null) {
      return this;
    }

    long newHashAlg = module.genericToVendorCode(Category.CKM, hashAlg);
    long newMgf = module.genericToVendorCode(Category.CKG_MGF, mgf);
    return (newHashAlg == hashAlg && newMgf == mgf) ? this
            : new RSA_PKCS_PSS_PARAMS(hashAlg, mgf, sLen);
  }

  @Override
  public ParamsType type() {
    return ParamsType.RSA_PKCS_PSS_PARAMS;
  }

  @Override
  protected void addContent(EncodeList contents) {
    contents.v(hashAlg).v(mgf).v(sLen);
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    return toString(indent, module, "hashAlg", ckmName(hashAlg, module),
       "mgf", mgfName(mgf, module), "sLen", sLen);
  }

  public static RSA_PKCS_PSS_PARAMS decode(
      Arch arch, byte[] encoded, AtomicInteger off)
      throws PKCS11Exception {
    assertType(encoded, off, ParamsType.RSA_PKCS_PSS_PARAMS);
    return new RSA_PKCS_PSS_PARAMS(readLong(arch, encoded, off),
        readLong(arch, encoded, off), readInt(arch, encoded, off));
  }

}
