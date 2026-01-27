// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.crypt;

import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.params.CkParams;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.OperationType;

/**
 * @author Lijun Liao (xipki)
 */
public class XiMechanism {

  private final XiHsmVendor vendor;

  private final CkMechanism mechanism;

  private final long origCkm;

  public XiMechanism(XiHsmVendor vendor, CkMechanism mechanism, long origCkm) {
    this.vendor = vendor;
    this.mechanism = mechanism;
    this.origCkm = origCkm;
  }

  public XiHsmVendor getVendor() {
    return vendor;
  }

  public CkMechanism getMechanism() {
    return mechanism;
  }

  public long getCkm() {
    return mechanism.getMechanism();
  }

  public CkParams getParameter() {
    return mechanism.getParameters();
  }

  public void assertUpdateSupported(OperationType opType)
      throws HsmException {
    long flagBit =
          (opType == OperationType.DIGEST) ? PKCS11T.CKF_DIGEST
        : (opType == OperationType.SIGN) ? PKCS11T.CKF_SIGN
        : 0;

    if (flagBit == 0) {
      return;
    }

    if (!vendor.supportsMultipart(origCkm, flagBit)) {
      throw new HsmException(PKCS11T.CKR_FUNCTION_NOT_SUPPORTED,
          "C_*Update() for mechanism " +
              vendor.codeToName(Category.CKM, origCkm) + " and purpose " +
              opType + " is not supported");
    }
  }

}
