// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.crypt.WeierstraussCurveEnum;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.HsmUtil;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_EC_PARAMS;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_EC_POINT;

/**
 * @author Lijun Liao (xipki)
 */
public class XiSm2ECPublicKey extends XiWeierstrassECPublicKey {

  public XiSm2ECPublicKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, long keyType,
      Long keyGenMechanism, byte[] ecParams, byte[] ecPoint)
      throws HsmException {
    super(vendor, cku, newObjectMethod, handle, inToken, keyType,
        keyGenMechanism, ecParams, ecPoint);

    if (curve != WeierstraussCurveEnum.SM2) {
      throw new IllegalArgumentException(
          "ecParams is not for the curve SM2P256V1");
    }
  }

  public static XiSm2ECPublicKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod,
      long handle, boolean inToken, XiTemplate attrs, long keyType,
      Long keyGenMechanism) throws HsmException {
    byte[] ecParams   = attrs.removeNonNullByteArray(CKA_EC_PARAMS);
    byte[] derEcPoint = attrs.removeNonNullByteArray(CKA_EC_POINT);
    byte[] ecPoint = HsmUtil.getOctetStringValue("EC_Point", derEcPoint);

    XiSm2ECPublicKey ret = new XiSm2ECPublicKey(vendor, cku, newObjectMethod,
        handle, inToken, keyType, keyGenMechanism, ecParams, ecPoint);
    ret.updateAttributes(loginState, initMethod, attrs);
    return ret;
  }

}
