// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.params.CkParams;
import org.xipki.pkcs11.wrapper.params.EDDSA_PARAMS;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.crypt.EdwardsCurveEnum;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.HsmUtil;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;

/**
 * @author Lijun Liao (xipki)
 */
public class XiEdwardsECPublicKey extends XiECPublicKey {

  public XiEdwardsECPublicKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, Long keyGenMechanism,
      byte[] ecParams, byte[] ecPoint) {
    super(vendor, cku, newObjectMethod, handle, inToken,
        PKCS11T.CKK_EC_EDWARDS, keyGenMechanism, ecParams, ecPoint);
  }

  public static XiEdwardsECPublicKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod,
      long handle, boolean inToken, XiTemplate attrs, Long keyGenMechanism)
      throws HsmException {
    byte[] ecParams   = attrs.removeNonNullByteArray(
        PKCS11T.CKA_EC_PARAMS);
    byte[] derEcPoint = attrs.removeNonNullByteArray(
        PKCS11T.CKA_EC_POINT);
    byte[] ecPoint = HsmUtil.getOctetStringValue("EC_Point", derEcPoint);

    XiEdwardsECPublicKey ret = new XiEdwardsECPublicKey(
        vendor, cku, newObjectMethod,
        handle, inToken, keyGenMechanism, ecParams, ecPoint);
    ret.updateAttributes(loginState, initMethod, attrs);
    return ret;
  }

  static void checkMechanismParameters(
      EdwardsCurveEnum curve, XiMechanism mechanism)
      throws HsmException {
    if (curve == EdwardsCurveEnum.ED25519) {
      HsmUtil.assertNullParameter(mechanism);
    } else {
      CkParams param = mechanism.getParameter();
      if (!(param instanceof EDDSA_PARAMS)) {
        throw new HsmException(PKCS11T.CKR_MECHANISM_PARAM_INVALID,
            "Mechanism.parameters is not CK_EDDSA_PARAMS");
      }

      EDDSA_PARAMS eddsaParams = (EDDSA_PARAMS) param;
      if (eddsaParams.phFlag()) {
        throw new HsmException(PKCS11T.CKR_MECHANISM_PARAM_INVALID,
            "EDDSA_PARAMS.phFlag != FALSE");
      }

      byte[] context = eddsaParams.context();
      if (context != null && context.length > 0) {
        throw new HsmException(PKCS11T.CKR_MECHANISM_PARAM_INVALID,
            "EDDSA_PARAMS.context is not empty");
      }
    }
  }

}
