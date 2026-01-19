// Copyright (c) 2022-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.params;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.EncodeList;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.util.codec.Args;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Represents the CK_GCM_PARAMS.
 * <pre>
 * typedef struct CK_GCM_PARAMS {
 *    CK_BYTE_PTR   pIv;
 *    CK_ULONG      ulIvLen;
 *    CK_ULONG      ulIvBits;
 *    CK_BYTE_PTR   pAAD;
 *    CK_ULONG      ulAADLen;
 *    CK_ULONG      ulTagBits;
 * }  CK_GCM_PARAMS;
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class GCM_PARAMS extends CkParams {

  private final ParamsType type;

  private final byte[] iv;

  private final byte[] AAD;

  private final int tagBits;

  /**
   * Create a new GCM_PARAMS object with the given attributes.
   *
   * @param iv
   *        Initialization vector
   * @param aad
   *        additional authentication data. This data is authenticated but not
   *        encrypted.
   * @param tagBits
   *        length of authentication tag (output following ciphertext) in bits.
   *        (0 - 128) depending on the algorithm implementation within the hsm,
   *        ulTagBits may be any one of the following five values: 128, 120,
   *        112, 104, or 96, may be 64 or 32;
   */
  public GCM_PARAMS(byte[] iv, byte[] aad, int tagBits) {
    this.type = ParamsType.GCM_PARAMS;
    this.iv = Args.notNull(iv, "iv");
    this.AAD = aad;
    this.tagBits = Args.among(tagBits, "tagBits",
        128, 120, 112, 104, 96, 64, 32);
  }

  public byte[] iv() {
    return iv;
  }

  public byte[] AAD() {
    return AAD;
  }

  public long tagBits() {
    return tagBits;
  }

  @Override
  public ParamsType type() {
    return type;
  }

  @Override
  protected void addContent(EncodeList contents) {
    contents.v(iv).v(AAD).v(tagBits);
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    return toString(indent, module, "pIv", iv, "pAAD", AAD,
        "ulTagBits", tagBits);
  }

  public static GCM_PARAMS decode(
      Arch arch, byte[] encoded, AtomicInteger off)
      throws PKCS11Exception {
    assertType(encoded, off, ParamsType.GCM_PARAMS);
    return new GCM_PARAMS(readByteArray(arch, encoded, off),
        readByteArray(arch, encoded, off), readInt(arch, encoded, off));
  }

}

