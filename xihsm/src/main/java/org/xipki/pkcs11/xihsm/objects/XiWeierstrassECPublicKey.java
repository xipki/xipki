// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.bouncycastle.math.ec.ECPoint;
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
import static org.xipki.pkcs11.wrapper.PKCS11T.CKK_EC;

/**
 * @author Lijun Liao (xipki)
 */
public class XiWeierstrassECPublicKey extends XiECPublicKey {

  protected final WeierstraussCurveEnum curve;

  protected final ECPoint publicPoint;

  public XiWeierstrassECPublicKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, long keyType,
      Long keyGenMechanism, byte[] ecParams, byte[] ecPoint)
      throws HsmException {
    super(vendor, cku, newObjectMethod, handle, inToken, keyType,
        keyGenMechanism, ecParams, ecPoint);

    this.curve = WeierstraussCurveEnum.ofEcParamsNonNull(ecParams);
    this.publicPoint = curve.decodePoint(ecPoint);
  }

  public static XiWeierstrassECPublicKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod,
      long handle, boolean inToken, XiTemplate attrs, Long keyGenMechanism)
      throws HsmException {
    byte[] ecParams   = attrs.removeNonNullByteArray(CKA_EC_PARAMS);
    byte[] derEcPoint = attrs.removeNonNullByteArray(CKA_EC_POINT);
    byte[] ecPoint = HsmUtil.getOctetStringValue("EC_Point", derEcPoint);

    XiWeierstrassECPublicKey ret;
    if (WeierstraussCurveEnum.ofEcParams(ecParams)
        == WeierstraussCurveEnum.SM2) {
      ret = new XiSm2ECPublicKey(vendor, cku, newObjectMethod,
          handle, inToken, CKK_EC, keyGenMechanism, ecParams, ecPoint);
    } else {
      ret = new XiWeierstrassECPublicKey(vendor, cku, newObjectMethod,
          handle, inToken, CKK_EC, keyGenMechanism, ecParams, ecPoint);
    }

    ret.updateAttributes(loginState, initMethod, attrs);
    return ret;
  }

}
