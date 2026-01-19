// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;

import java.util.List;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * @author Lijun Liao (xipki)
 */
public abstract class XiPrivateKey extends XiPrivateOrSecretKey {

  /**
   * DER-encoding of the key subject name.
   * <p/>
   * May be modified after object is created with a C_SetAttributeValue call,
   * or in the process of copying object with a C_CopyObject call. However, it
   * is possible that a particular token may not permit modification of the
   * attribute during the course of a C_CopyObject call.
   */
  private byte[] subject;

  /**
   * CK_TRUE if key supports signatures where the data can be recovered from
   * the signature.
   * <p/>
   * May be modified after object is created with a C_SetAttributeValue call,
   * or in the process of copying object with a C_CopyObject call. However, it
   * is possible that a particular token may not permit modification of the
   * attribute during the course of a C_CopyObject call.
   * <p/>
   * Default value is token-specific, and may depend on the values of other
   * attributes.
   */
  private Boolean signRecover;

  /**
   * If CK_TRUE, the user has to supply the PIN for each use (sign or decrypt)
   * with the key. Default is CK_FALSE.
   */
  private Boolean alwaysAuthenticate;

  private Boolean decapsulate;

  /**
   * DER-encoding of the SubjectPublicKeyInfo for the associated public key
   * (MAY be empty; DEFAULT derived from the underlying private key data; MAY
   * be manually set for specific key types; if set; MUST be consistent with
   * the underlying private key data).
   */
  private byte[] publicKeyInfo;

  public XiPrivateKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, long keyType, Long keyGenMechanism) {
    super(vendor, cku, newObjectMethod, handle, inToken,
        CKO_PRIVATE_KEY, keyType, keyGenMechanism);
  }

  public boolean isDecapsulate() {
    return boolValue(decapsulate, false);
  }

  @Override
  protected void doGetAttributes(List<XiAttribute> res, long[] types,
                                 boolean withAll) throws HsmException {
    super.doGetAttributes(res, types, withAll);
    addAttr(res, types, CKA_SUBJECT, subject);
    addAttr(res, types, CKA_SIGN_RECOVER, signRecover);
    addAttr(res, types, CKA_DECAPSULATE, decapsulate);
    addAttr(res, types, CKA_ALWAYS_AUTHENTICATE, alwaysAuthenticate);
    addAttr(res, types, CKA_PUBLIC_KEY_INFO, publicKeyInfo);
  }

  @Override
  protected void doSetAttributes(
      LoginState loginState, ObjectInitMethod initMethod, XiTemplate attrs)
      throws HsmException {
    super.doSetAttributes(loginState, initMethod, attrs);

    this.signRecover = attrs.removeBool(CKA_SIGN_RECOVER);
    this.decapsulate = attrs.removeBool(CKA_DECAPSULATE);
    this.subject = attrs.removeByteArray(CKA_SUBJECT);

    Boolean attrB = attrs.removeBool(CKA_ALWAYS_AUTHENTICATE);
    if (attrB != null) {
      if (attrB) {
        throw new HsmException(CKR_ATTRIBUTE_VALUE_INVALID,
            "CKR_ATTRIBUTE_VALUE_INVALID=TRUE is not supported");
      }
      this.alwaysAuthenticate = false;
    }

    this.publicKeyInfo = attrs.removeByteArray(CKA_PUBLIC_KEY_INFO);
  }

  public byte[] decapsulateKey(
        XiMechanism mechanism, byte[] encapsulatedKey)
      throws HsmException {
    throw new HsmException(CKR_KEY_FUNCTION_NOT_PERMITTED,
        getClass() + " does not support C_DecapsulateKey");
  }

  public static XiPrivateKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod,
      long handle, boolean inToken, XiTemplate attrs, long keyType,
      Long keyGenMechanism) throws HsmException {
    if (keyType == CKK_RSA) {
      return XiRSAPrivateKey.newInstance(vendor, cku, newObjectMethod,
          loginState, initMethod, handle, inToken, attrs, keyGenMechanism);
    } else if (keyType == CKK_EC_EDWARDS) {
      return XiEdwardsECPrivateKey.newInstance(vendor, cku, newObjectMethod,
          loginState, initMethod, handle, inToken, attrs, keyGenMechanism);
    } else if (keyType == CKK_EC_MONTGOMERY) {
      return XiMontgomeryECPrivateKey.newInstance(vendor, cku, newObjectMethod,
          loginState, initMethod, handle, inToken, attrs, keyGenMechanism);
    } else if (keyType == CKK_EC) {
      return XiWeierstrassECPrivateKey.newInstance(vendor, cku, newObjectMethod,
          loginState, initMethod, handle, inToken, attrs, keyGenMechanism);
    } else if (keyType == PKCS11T.CKK_VENDOR_SM2) {
      return XiSm2ECPrivateKey.newInstance(vendor, cku, newObjectMethod,
          loginState, initMethod, handle, inToken, attrs, keyGenMechanism);
    } else if (keyType == CKK_ML_DSA) {
      return XiMLDSAPrivateKey.newInstance(vendor, cku, newObjectMethod,
          loginState, initMethod, handle, inToken, attrs, keyGenMechanism);
    } else if (keyType == CKK_ML_KEM) {
      return XiMLKEMPrivateKey.newInstance(vendor, cku, newObjectMethod,
          loginState, initMethod, handle, inToken, attrs, keyGenMechanism);
    } else {
      throw new HsmException(CKR_GENERAL_ERROR,
          "unsupported public key type " +
              PKCS11T.ckkCodeToName(keyType));
    }
  }

}
