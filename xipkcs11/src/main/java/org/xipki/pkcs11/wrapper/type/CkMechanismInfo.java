// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.type;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.EncodeList;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.util.codec.Args;

import java.util.concurrent.atomic.AtomicInteger;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * Objects of this class provide information about a certain mechanism that a
 * token implements.
 * <pre>
 * typedef struct CK_MECHANISM_INFO {
 *     CK_ULONG    ulMinKeySize;
 *     CK_ULONG    ulMaxKeySize;
 *     CK_FLAGS    flags;
 * } CK_MECHANISM_INFO;
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class CkMechanismInfo extends AbstractInfo {

  /**
   * The minimum key length supported by this algorithm.
   */
  private final long minKeySize;

  /**
   * The maximum key length supported by this algorithm.
   */
  private final long maxKeySize;

  /**
   * Contains all feature flags of this mechanism info.
   */
  private final long flags;

  /**
   * @param minKeySize
   *          The minimum key length supported by this mechanism.
   * @param maxKeySize
   *          The maximum key length supported by this mechanism.
   * @param flags
   *          The flag bit(s).
   */
  public CkMechanismInfo(long minKeySize, long maxKeySize, long flags) {
    this.minKeySize = minKeySize;
    this.maxKeySize = maxKeySize;
    this.flags = flags;
  }

  /**
   * Get the minimum key length supported by this mechanism.
   *
   * @return The minimum key length supported by this mechanism.
   */
  public long minKeySize() {
    return minKeySize;
  }

  /**
   * Get the maximum key length supported by this mechanism.
   *
   * @return The maximum key length supported by this mechanism.
   */
  public long maxKeySize() {
    return maxKeySize;
  }

  public long flags() {
    return flags;
  }

  public boolean hasFlagBit(long flagMask) {
    return (flags & flagMask) != 0L;
  }

  /**
   * Check, if this mechanism info has those flags set to true, which are set
   * in the given mechanism info. This may be used as a simple check, if some
   * operations are supported.
   * This also checks the key length range, if they are specified in the given
   * mechanism object; i.e. if they are not zero.
   *
   * @param requiredFeatures
   *          The required features.
   * @return True, if the required features are supported.
   */
  public boolean supports(CkMechanismInfo requiredFeatures) {
    Args.notNull(requiredFeatures, "requiredFeatures");

    long requiredMaxKeySize = requiredFeatures.maxKeySize();
    long requiredMinKeySize = requiredFeatures.minKeySize();

    return (requiredMaxKeySize == 0 || requiredMaxKeySize <= maxKeySize)
        && ((requiredMinKeySize == 0 || requiredMinKeySize >= minKeySize)
        && (requiredFeatures.flags & flags) == requiredFeatures.flags);
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    String text = indent + "  Key-Size: [" + minKeySize + ", " + maxKeySize
        + "]\n";

    return text + Functions.toStringFlags(Category.CKF_MECHANISM,
        indent + "  Flags: ", flags,
        CKF_HW, CKF_FIND_OBJECTS,

        CKF_ENCRYPT, CKF_DECRYPT, CKF_DIGEST, CKF_SIGN, CKF_SIGN_RECOVER,
        CKF_VERIFY,  CKF_VERIFY_RECOVER,  CKF_GENERATE, CKF_GENERATE_KEY_PAIR,
        CKF_WRAP,    CKF_UNWRAP,         CKF_DERIVE,

        CKF_EC_F_P, CKF_EC_F_2M, CKF_EC_ECPARAMETERS, CKF_EC_OID,
        CKF_EC_UNCOMPRESS, CKF_EC_COMPRESS, CKF_EC_CURVENAME,
        CKF_ENCAPSULATE, CKF_DECAPSULATE);
  }

  @Override
  protected EncodeList getEncodeList() {
    return new EncodeList().v(minKeySize).v(maxKeySize).v(flags);
  }

  public static CkMechanismInfo decode(Arch arch, byte[] encoded) {
    AtomicInteger off = new AtomicInteger();
    return new CkMechanismInfo(readLong(arch, encoded, off),
        readLong(arch, encoded, off), readLong(arch, encoded, off));
  }

}
