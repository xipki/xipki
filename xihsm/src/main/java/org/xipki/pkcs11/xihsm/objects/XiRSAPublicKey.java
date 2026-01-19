// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.attr.XiTemplateChecker;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.util.codec.Args;

import java.math.BigInteger;
import java.util.List;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_MODULUS;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_PUBLIC_EXPONENT;

/**
 * @author Lijun Liao (xipki)
 */
public class XiRSAPublicKey extends XiPublicKey {

  private final BigInteger modulus;

  private final BigInteger publicExponent;

  public XiRSAPublicKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, Long keyGenMechanism,
      BigInteger modulus, BigInteger publicExponent) {
    super(vendor, cku, newObjectMethod, handle, inToken,
        PKCS11T.CKK_RSA, keyGenMechanism);
    this.modulus = Args.notNull(modulus, "modulus");
    this.publicExponent = Args.notNull(publicExponent, "publicExponent");
  }

  @Override
  protected void assertAttributesSettable(XiTemplate attrs)
      throws HsmException {
    XiTemplateChecker.assertRsaPublicKeyAttributesSettable(attrs);
  }

  @Override
  protected void doGetAttributes(
      List<XiAttribute> res, long[] types, boolean withAll)
      throws HsmException {
    super.doGetAttributes(res, types, withAll);
    addAttr(res, types, CKA_MODULUS, modulus);
    addAttr(res, types, CKA_PUBLIC_EXPONENT, publicExponent);
  }

  public static XiRSAPublicKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod,
      long handle, boolean inToken, XiTemplate attrs, Long keyGenMechanism)
      throws HsmException {
    BigInteger modulus = attrs.removeNonNullBigInt(CKA_MODULUS);
    BigInteger publicExponent = attrs.removeNonNullBigInt(CKA_PUBLIC_EXPONENT);
    XiRSAPublicKey ret = new XiRSAPublicKey(vendor, cku, newObjectMethod,
        handle, inToken, keyGenMechanism, modulus, publicExponent);
    ret.updateAttributes(loginState, initMethod, attrs);
    return ret;
  }

}
