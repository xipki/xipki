// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.type;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.ExtraParams;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.Token;
import org.xipki.pkcs11.wrapper.jni.JniUtil;
import org.xipki.pkcs11.wrapper.params.CkParams;
import org.xipki.pkcs11.wrapper.params.NullParams;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

import static org.xipki.pkcs11.wrapper.Category.CKM;

/**
 * Objects of this class represent a mechanism as defined in PKCS#11. There are
 * constants defined for all mechanisms that PKCS#11 version 2.11 defines.
 *
 * <pre>
 * typedef struct CK_MECHANISM {
 *   CK_MECHANISM_TYPE mechanism;
 *   CK_VOID_PTR       pParameter;
 *   CK_ULONG          ulParameterLen; // in bytes
 * } CK_MECHANISM;
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CkMechanism extends CkType {

  /**
   * The code of the mechanism as defined in PKCS11Constants (or pkcs11t.h
   * likewise).
   */
  private final long mechanism;

  /**
   * The parameters of the mechanism. Not all mechanisms use these parameters.
   */
  private final CkParams parameters;

  private ExtraParams extraParams;

  /**
   * Constructor taking just the mechanism code as defined in PKCS11Constants.
   *
   * @param mechanism
   *          The mechanism code.
   */
  public CkMechanism(long mechanism) {
    this(mechanism, null);
  }

  /**
   * Constructor taking just the mechanism code as defined in PKCS11Constants.
   *
   * @param mechanism The mechanism code.
   * @param parameters The mechanism parameters.
   */
  public CkMechanism(long mechanism, CkParams parameters) {
    this.mechanism = mechanism;
    if (NullParams.INSTANCE.equals(parameters)) {
      this.parameters = null;
    } else {
      this.parameters = parameters;
    }
  }

  public ExtraParams getExtraParams() {
    return extraParams;
  }

  public void setExtraParams(ExtraParams extraParams) {
    this.extraParams = extraParams;
  }

  /**
   * Get the parameters object of this mechanism.
   *
   * @return The parameters of this mechanism. May be null.
   */
  public CkParams getParameters() {
    return parameters;
  }

  /**
   * Get the code of this mechanism as defined in PKCS11Constants (of
   * pkcs11t.h likewise).
   *
   * @return The code of this mechanism.
   */
  public long getMechanism() {
    return mechanism;
  }

  /**
   * Get the name of this mechanism.
   *
   * @return The name of this mechanism.
   */
  public String getCkmName(PKCS11Module module) {
    if (module == null) {
      return PKCS11T.ckmCodeToName(mechanism);
    }

    String name = module.codeToName(CKM, mechanism);
    long code2 = module.genericToVendorCode(CKM, mechanism);
    if (mechanism == code2) {
      return name;
    } else {
      String name2 = module.codeToName(CKM, code2);
      return name + " (native: " + name2 + ")";
    }
  }

  public CkMechanism nativeCopy(Token token) {
    if (token == null) {
      throw new IllegalStateException("token is not set");
    }
    return nativeCopy(token.getSlot().getModule());
  }

  public CkMechanism nativeCopy(PKCS11Module module) {
    if (module == null) {
      return this;
    }

    long newCkm = module.genericToVendorCode(Category.CKM, mechanism);
    CkParams newParams = null;
    if (parameters != null) {
      newParams = parameters.vendorCopy(module);
    }

    if (mechanism == newCkm && parameters == newParams) {
      return this;
    }

    return new CkMechanism(newCkm, newParams);
  }

  public int getEncodedLen(Arch arch) {
    CkParams params = parameters == null ? NullParams.INSTANCE : parameters;
    return arch.longSize() + params.getEncodedLen(arch);
  }

  public byte[] getEncoded(Arch arch) {
    CkParams params = parameters == null ? NullParams.INSTANCE : parameters;
    int len = arch.longSize() + params.getEncodedLen(arch);
    byte[] dest = new byte[len];
    AtomicInteger off = new AtomicInteger();
    JniUtil.writeLong(arch, mechanism, dest, off);
    params.encodeTo(arch, dest, off);
    return dest;
  }

  @Override
  public int hashCode() {
    return Long.hashCode(mechanism) * 31 +
        (parameters == null ? 0 : parameters.hashCode());
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    } else if (!(other instanceof CkMechanism)) {
      return false;
    }

    CkMechanism b = (CkMechanism) other;
    return mechanism == b.mechanism
        && Objects.equals(parameters, b.parameters);
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    return toString(indent, "CK_MECHANISM", module, "mechanism",
        getCkmName(module), "pParameter", parameters);
  }

  public static CkMechanism decode(Arch arch, byte[] encoded)
      throws PKCS11Exception {
    AtomicInteger off = new AtomicInteger();
    long mechanism = JniUtil.readLong(arch, encoded, off);
    CkParams params = CkParams.decodeParams(arch, encoded, off);
    return new CkMechanism(mechanism, params);
  }

}
