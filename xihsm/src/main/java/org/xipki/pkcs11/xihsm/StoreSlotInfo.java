// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.type.CkSlotInfo;
import org.xipki.pkcs11.xihsm.mgr.UserVerifier;
import org.xipki.pkcs11.xihsm.util.HsmUtil;
import org.xipki.util.codec.Args;

/**
 * @author Lijun Liao (xipki)
 */
public class StoreSlotInfo {

  private final int slotIndex;

  private final long slotId;

  private final String serialNumber;

  private final CkSlotInfo slotInfo;

  private final UserVerifier userVerifier;

  public StoreSlotInfo(XiHsmVendor vendor, int slotIndex, long slotId,
                       String serialNumber, String description,
                       UserVerifier userVerifier) {
    this.slotIndex = Args.notNegative(slotIndex, "slotIndex");
    this.slotId = slotId;
    this.serialNumber = serialNumber;
    this.userVerifier = Args.notNull(userVerifier, "userVerifier");

    slotInfo = new CkSlotInfo(description, vendor.getManufactureID(),
        PKCS11T.CKF_TOKEN_PRESENT,
        HsmUtil.buildVersion(1, 1),
        HsmUtil.buildVersion(1, 1));
  }

  public int getSlotIndex() {
    return slotIndex;
  }

  public long getSlotId() {
    return slotId;
  }

  public String getSerialNumber() {
    return serialNumber;
  }

  public UserVerifier getUserVerifier() {
    return userVerifier;
  }

  public CkSlotInfo getSlotInfo() {
    return slotInfo;
  }

}
