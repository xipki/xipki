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
import org.xipki.pkcs11.xihsm.crypt.EdwardsCurveEnum;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;

import java.io.IOException;
import java.security.SecureRandom;

/**
 * @author Lijun Liao (xipki)
 */
public class XiEdwardsECPrivateKey extends XiECPrivateKey {

  private final EdwardsCurveEnum curve;

  public XiEdwardsECPrivateKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, Long keyGenMechanism,
      byte[] ecParams, byte[] sk) throws HsmException {
    super(vendor, cku, newObjectMethod, handle, inToken,
        PKCS11T.CKK_EC_EDWARDS, keyGenMechanism, ecParams, sk);

    this.curve = EdwardsCurveEnum.ofEcParamsNonNull(ecParams);
  }

  public static XiEdwardsECPrivateKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod,
      long handle, boolean inToken, XiTemplate attrs, Long keyGenMechanism)
      throws HsmException {
    byte[] ecParams = attrs.removeNonNullByteArray(
        PKCS11T.CKA_EC_PARAMS);
    byte[] value = attrs.removeNonNullByteArray(PKCS11T.CKA_VALUE);

    XiEdwardsECPrivateKey ret = new XiEdwardsECPrivateKey(
        vendor, cku, newObjectMethod,
        handle, inToken, keyGenMechanism, ecParams, value);
    ret.updateAttributes(loginState, initMethod, attrs);
    return ret;
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

  @Override
  public byte[] sign(XiMechanism mechanism, byte[] data,
                            SecureRandom random)
      throws HsmException {
    if (!isSign()) {
      throw new HsmException(PKCS11T.CKR_KEY_FUNCTION_NOT_PERMITTED,
          "CKA_SIGN != TRUE");
    }

    long ckm = mechanism.getCkm();
    if (ckm != PKCS11T.CKM_EDDSA) {
      throw new HsmException(PKCS11T.CKR_MECHANISM_INVALID,
          "Invalid mechanism " +
              PKCS11T.ckmCodeToName(ckm));
    }

    XiEdwardsECPublicKey.checkMechanismParameters(curve, mechanism);
    return curve.sign(value, data);
  }

}
