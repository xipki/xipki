// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.math.ec.rfc7748.X448;
import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.params.ECDH1_DERIVE_PARAMS;
import org.xipki.pkcs11.wrapper.vendor.VendorEnum;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.crypt.MontgomeryCurveEnum;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;

import java.io.IOException;
import java.util.Arrays;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_VALUE_LEN;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKD_NULL;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKR_ATTRIBUTE_VALUE_INVALID;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKR_FUNCTION_FAILED;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKR_MECHANISM_INVALID;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKR_MECHANISM_PARAM_INVALID;

/**
 * Xi Montgomery ECPrivate Key.
 *
 * @author Lijun Liao (xipki)
 */
public class XiMontgomeryECPrivateKey extends XiECPrivateKey {

  private final MontgomeryCurveEnum curve;

  public XiMontgomeryECPrivateKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod, long handle, boolean inToken,
      Long keyGenMechanism, byte[] ecParams, byte[] sk) throws HsmException {
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

  @Override
  public byte[] deriveKey(XiMechanism mechanism, XiTemplate template) throws HsmException {
    if (!isDerive()) {
      throw new HsmException(PKCS11T.CKR_KEY_FUNCTION_NOT_PERMITTED, "CKA_DERIVE != TRUE");
    }

    long ckm = mechanism.getCkm();
    Object params = mechanism.getParameter();
    if (ckm == PKCS11T.CKM_ECDH1_DERIVE) {
      int valueLen = template.removeNonNullInt(CKA_VALUE_LEN);
      if (!(valueLen >= 1 && valueLen <= curve.getPublicKeySize())) {
        throw new HsmException(CKR_ATTRIBUTE_VALUE_INVALID, "invalid CKA_VALUE_LEN " + valueLen);
      }

      if (!(params instanceof ECDH1_DERIVE_PARAMS)) {
        throw new HsmException(CKR_MECHANISM_PARAM_INVALID,
            "params not allowed: " + params.getClass().getName());
      }

      if (vendor.getVendorEnum() == VendorEnum.CLOUDHSM) {
        throw new HsmException(CKR_FUNCTION_FAILED, "simulate CloudHSM's behavior");
      }

      ECDH1_DERIVE_PARAMS p = (ECDH1_DERIVE_PARAMS) params;
      long kdf = p.kdf();
      if (kdf != CKD_NULL) {
        throw new HsmException(CKR_MECHANISM_PARAM_INVALID,
            "parameter.kdf not allowed: " + PKCS11T.codeToName(Category.CKD, kdf));
      }

      byte[] sharedData = p.sharedData();
      if (!(sharedData == null || sharedData.length == 0)) {
        throw new HsmException(CKR_MECHANISM_PARAM_INVALID, "parameter.sharedData != NULL");
      }

      int size = curve.getPublicKeySize();
      byte[] publicData = p.publicData();
      if (publicData.length != size) {
        throw new HsmException(CKR_MECHANISM_PARAM_INVALID, "invalid parameters.publicData");
      }

      byte[] bytes = new byte[curve.getPublicKeySize()];
      if (curve == MontgomeryCurveEnum.X25519) {
        X25519.calculateAgreement(value, 0, publicData, 0, bytes, 0);
      } else {
        X448.calculateAgreement(value, 0, publicData, 0, bytes, 0);
      }

      return valueLen == bytes.length ? bytes
          : Arrays.copyOfRange(bytes, bytes.length - valueLen, bytes.length);
    } else {
      throw new HsmException(CKR_MECHANISM_INVALID,
          "Mechanism " + PKCS11T.ckmCodeToName(ckm) + " is not supported");
    }
  }

  public static XiMontgomeryECPrivateKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod, LoginState loginState,
      ObjectInitMethod initMethod, long handle, boolean inToken, XiTemplate attrs,
      Long keyGenMechanism) throws HsmException {
    byte[] ecParams = attrs.removeNonNullByteArray(PKCS11T.CKA_EC_PARAMS);
    byte[] value = attrs.removeNonNullByteArray(PKCS11T.CKA_VALUE);

    XiMontgomeryECPrivateKey ret = new XiMontgomeryECPrivateKey(
        vendor, cku, newObjectMethod, handle, inToken, keyGenMechanism, ecParams, value);

    ret.updateAttributes(loginState, initMethod, attrs);
    return ret;
  }

}
