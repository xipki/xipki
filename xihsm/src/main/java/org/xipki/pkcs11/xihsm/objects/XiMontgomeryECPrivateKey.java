// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.crypt.MontgomeryCurveEnum;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;

import java.io.IOException;

/**
 * @author Lijun Liao (xipki)
 */
public class XiMontgomeryECPrivateKey extends XiECPrivateKey {

  private final MontgomeryCurveEnum curve;

  public XiMontgomeryECPrivateKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, Long keyGenMechanism,
      byte[] ecParams, byte[] sk) throws HsmException {
    super(vendor, cku, newObjectMethod, handle, inToken,
        PKCS11T.CKK_EC_MONTGOMERY, keyGenMechanism, ecParams, sk);

    this.curve = MontgomeryCurveEnum.ofEcParamsNonNull(ecParams);
  }

  @Override
  public byte[] getEncoded() throws HsmException {
    try {
      return new PrivateKeyInfo(
          new AlgorithmIdentifier(new ASN1ObjectIdentifier(curve.getOid())),
          new DEROctetString(value)).getEncoded();
    } catch (IOException ex) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "error encoding " + getClass().getName(), ex);
    }
  }

  public static XiMontgomeryECPrivateKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod,
      long handle, boolean inToken, XiTemplate attrs, Long keyGenMechanism)
      throws HsmException {
    byte[] ecParams = attrs.removeNonNullByteArray(
        PKCS11T.CKA_EC_PARAMS);
    byte[] value = attrs.removeNonNullByteArray(PKCS11T.CKA_VALUE);

    XiMontgomeryECPrivateKey ret = new XiMontgomeryECPrivateKey(
        vendor, cku, newObjectMethod,
        handle, inToken, keyGenMechanism, ecParams, value);

    ret.updateAttributes(loginState, initMethod, attrs);
    return ret;
  }

}
