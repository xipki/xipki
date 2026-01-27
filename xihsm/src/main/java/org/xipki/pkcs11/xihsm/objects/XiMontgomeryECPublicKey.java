// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.HsmUtil;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_EC_PARAMS;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_EC_POINT;

/**
 * @author Lijun Liao (xipki)
 */
public class XiMontgomeryECPublicKey extends XiECPublicKey {

  public XiMontgomeryECPublicKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, Long keyGenMechanism,
      byte[] ecParams, byte[] ecPoint) {
    super(vendor, cku, newObjectMethod, handle, inToken,
        PKCS11T.CKK_EC_MONTGOMERY, keyGenMechanism, ecParams, ecPoint);
  }

  public static XiMontgomeryECPublicKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod,
      long handle, boolean inToken, XiTemplate attrs, Long keyGenMechanism)
      throws HsmException {
    byte[] ecParams   = attrs.removeNonNullByteArray(CKA_EC_PARAMS);
    byte[] derEcPoint = attrs.removeNonNullByteArray(CKA_EC_POINT);
    byte[] ecPoint = HsmUtil.getOctetStringValue("EC_Point", derEcPoint);

    XiMontgomeryECPublicKey ret = new XiMontgomeryECPublicKey(
        vendor, cku, newObjectMethod,
        handle, inToken, keyGenMechanism, ecParams, ecPoint);
    ret.updateAttributes(loginState, initMethod, attrs);
    return ret;
  }

}
