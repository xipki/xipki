// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.store;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.StoreSlotInfo;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.objects.XiP11Storage;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.util.codec.Args;

/**
 * @author Lijun Liao (xipki)
 */
public abstract class PersistSlot {

  protected final XiHsmVendor vendor;

  protected final StoreSlotInfo slotInfo;

  protected PersistSlot(XiHsmVendor vendor, StoreSlotInfo slotInfo) {
    this.vendor = Args.notNull(vendor, "vendor");
    this.slotInfo = Args.notNull(slotInfo, "slotInfo");
  }

  public PersistObject from(XiTemplate attrs)
      throws HsmException {
    long cku = attrs.removeNonNullLong(XiP11Storage.CKA_XIHSM_CKU);
    long originCode = attrs.removeNonNullLong(XiP11Storage.CKA_XIHSM_ORIGIN);
    Origin origin = Origin.ofCode(originCode);
    long objClass = attrs.removeLong(PKCS11T.CKA_CLASS);
    boolean private_ = attrs.removeBool(PKCS11T.CKA_PRIVATE, false);
    Long l = attrs.removeLong(PKCS11T.CKA_KEY_TYPE);
    long keyType = (l == null) ? -1 : l;
    byte[] id = attrs.removeByteArray(PKCS11T.CKA_ID);
    String label = attrs.removeChars(PKCS11T.CKA_LABEL);

    byte[] encodedAttrs = attrs.encode();
    return new PersistObject(cku, origin, private_, objClass,
            keyType, id, label, encodedAttrs);
  }

}
