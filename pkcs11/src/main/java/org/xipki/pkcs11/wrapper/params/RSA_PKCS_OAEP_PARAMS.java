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
 * RSA PKCS OAEP PARAMS.
 *
 * <pre>
 * typedef struct CK_RSA_PKCS_OAEP_PARAMS {
 *    CK_MECHANISM_TYPE             hashAlg;
 *    CK_RSA_PKCS_MGF_TYPE          mgf;
 *    CK_RSA_PKCS_OAEP_SOURCE_TYPE  source;
 *    CK_VOID_PTR                   pSourceData;
 *    CK_ULONG                      ulSourceDataLen;
 * }  CK_RSA_PKCS_OAEP_PARAMS;
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class RSA_PKCS_OAEP_PARAMS extends CkParams {

  private final long hashAlg;

  private final long mgf;

  final long source;

  final byte[] sourceData;

  public RSA_PKCS_OAEP_PARAMS(long hashAlg, long mgf) {
    this(hashAlg, mgf, PKCS11T.CKZ_SALT_SPECIFIED, null);
  }

  /**
   * Create a new RSA_PKCS_OAEP_PARAMS object with the given attributes.
   *
   * @param hashAlg
   *        The message digest algorithm used to calculate the digest of the
   *        encoding parameter.
   * @param mgf
   *        The mask to apply to the encoded block. One of the constants
   *        defined in the MessageGenerationFunctionType interface.
   * @param source
   *        The source of the encoding parameter. One of the constants
   *        defined in the SourceType interface.
   * @param sourceData
   *        The data used as the input for the encoding parameter source.
   */
  public RSA_PKCS_OAEP_PARAMS(long hashAlg, long mgf, long source, byte[] sourceData) {
    this.hashAlg = hashAlg;
    this.mgf = mgf;
    this.source = source;
    this.sourceData = sourceData;
  }

  public long hashAlg() {
    return hashAlg;
  }

  public long mgf() {
    return mgf;
  }

  public long source() {
    return source;
  }

  public byte[] sourceData() {
    return sourceData;
  }

  @Override
  public RSA_PKCS_OAEP_PARAMS vendorCopy(PKCS11Module module) {
    if (module == null) {
      return this;
    }

    long newHashAlg = module.genericToVendorCode(Category.CKM, hashAlg);
    long newMgf = module.genericToVendorCode(Category.CKG_MGF, mgf);
    if (newHashAlg == hashAlg && newMgf == mgf) {
      return this;
    }

    return new RSA_PKCS_OAEP_PARAMS(newHashAlg, newMgf, source, sourceData);
  }

  @Override
  public ParamsType type() {
    return ParamsType.RSA_PKCS_OAEP_PARAMS;
  }

  @Override
  protected void addContent(EncodeList contents) {
    contents.v(hashAlg).v(mgf).v(source).v(sourceData);
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    return toString(indent, module, "hashAlg", ckmName(hashAlg, module),
        "mgf", mgfName(mgf, module), "source", ckzName(source, module), "pSourceData", sourceData);
  }

  public static RSA_PKCS_OAEP_PARAMS decode(Arch arch, byte[] encoded, AtomicInteger off)
      throws PKCS11Exception {
    assertType(encoded, off, ParamsType.RSA_PKCS_OAEP_PARAMS);
    return new RSA_PKCS_OAEP_PARAMS(readLong(arch, encoded, off), // hashAlg
        readLong(arch, encoded, off), // mgf
        readLong(arch, encoded, off), // source
        readByteArray(arch, encoded, off) // sourceData
    );
  }

}
