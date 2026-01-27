// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;

import java.util.List;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * @author Lijun Liao (xipki)
 */
public abstract class XiPublicKey extends XiKey implements XiPublicOrSecretKey {

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
   * CK_TRUE if key supports encryption.
   * <p>
   * May be modified after an object is created with a C_SetAttributeValue call,
   * or in the process of copying an object with a C_CopyObject call. However,
   * it is possible that a particular token may not permit modification of the
   * attribute during the course of a C_CopyObject call.
   * <p>
   * The default value is token-specific, and may depend on the values of other
   * attributes.
   */
  protected Boolean encrypt;

  protected Boolean encapsulate;

  /**
   * CK_TRUE if key supports verification where the signature is an appendix to
   * the data.
   * <p>
   * May be modified after an object is created with a C_SetAttributeValue call,
   * or in the process of copying object with a C_CopyObject call. However, it
   * is possible that a particular token may not permit modification of the
   * attribute during the course of a C_CopyObject call.
   * <p>
   * Default value is token-specific, and may depend on the values of other
   * attributes.
   */
  protected Boolean verify;

  /**
   * CK_TRUE if key supports verification where the data is recovered from the
   * signature
   * <p>
   * May be modified after an object is created with a C_SetAttributeValue call,
   * or in the process of copying object with a C_CopyObject call. However, it
   * is possible that a particular token may not permit modification of the
   * attribute during the course of a C_CopyObject call.
   * <p>
   * The default value is token-specific, and may depend on the values of other
   * attributes.
   */
  private Boolean verifyRecover;

  /**
   * CK_TRUE if key supports wrapping (i.e., can be used to wrap other keys)
   * <p>
   * May be modified after object is created with a C_SetAttributeValue call,
   * or in the process of copying object with a C_CopyObject call. However, it
   * is possible that a particular token may not permit modification of the
   * attribute during the course of a C_CopyObject call.
   * <p>
   * The default value is token-specific, and may depend on the values of other
   * attributes.
   */
  protected Boolean wrap;

  /**
   * The key can be trusted for the application that it was created.
   * <p>
   * The wrapping key can be used to wrap keys with CKA_WRAP_WITH_TRUSTED set
   * to CK_TRUE.
   * <p>
   * Can only be set to CK_TRUE by the SO user.
   */
  protected Boolean trusted;

  /**
   * For wrapping keys. The attribute template to match against any keys
   * wrapped using this wrapping key. Keys that do not match cannot be wrapped.
   * The number of attributes in the array is the ulValueLen component of the
   * attribute divided by the size of CK_ATTRIBUTE.
   */
  protected XiTemplate wrapTemplate;

  protected XiTemplate encapsulateTemplate;

  /**
   * DER-encoding of the SubjectPublicKeyInfo for this public key. (May be
   * empty, DEFAULT derived from the underlying public key data)
   */
  protected byte[] publicKeyInfo;

  public XiPublicKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, long keyType, Long keyGenMechanism) {
    super(vendor, cku, newObjectMethod, handle, inToken, CKO_PUBLIC_KEY,
        keyType, keyGenMechanism);
  }

  public boolean isVerify() {
    return verify != null && verify;
  }

  public boolean isEncrypt() {
    return encrypt != null && encrypt;
  }

  public boolean isEncapsulate() {
    return encapsulate != null && encapsulate;
  }

  public boolean isWrap() {
    return wrap != null && wrap;
  }

  @Override
  public boolean isTrusted() {
    return trusted != null && trusted;
  }

  @Override
  public XiTemplate getWrapTemplate() {
    return wrapTemplate;
  }

  public XiTemplate getEncapsulateTemplate() {
    return encapsulateTemplate;
  }

  @Override
  protected boolean isDefaultPrivate() {
    return false;
  }

  @Override
  protected void doGetAttributes(List<XiAttribute> res, long[] types,
                                 boolean withAll)
      throws HsmException {
    super.doGetAttributes(res, types, withAll);
    addAttr(res, types, CKA_SUBJECT,         subject);
    addAttr(res, types, CKA_ENCRYPT,         encrypt);
    addAttr(res, types, CKA_ENCAPSULATE,     encapsulate);
    addAttr(res, types, CKA_VERIFY,          verify);
    addAttr(res, types, CKA_VERIFY_RECOVER,  verifyRecover);
    addAttr(res, types, CKA_WRAP,            wrap);
    addAttr(res, types, CKA_TRUSTED,         trusted);
    addAttr(res, types, CKA_WRAP_TEMPLATE,   wrapTemplate);
    addAttr(res, types, CKA_ENCAPSULATE_TEMPLATE,   encapsulateTemplate);
    addAttr(res, types, CKA_PUBLIC_KEY_INFO, publicKeyInfo);
  }

  @Override
  protected void doSetAttributes(
      LoginState loginState, ObjectInitMethod initMethod, XiTemplate attrs)
      throws HsmException {
    super.doSetAttributes(loginState, initMethod, attrs);

    subject       = attrs.removeByteArray(CKA_SUBJECT);
    encrypt       = attrs.removeBool(CKA_ENCRYPT);
    encapsulate   = attrs.removeBool(CKA_ENCAPSULATE);
    verify        = attrs.removeBool(CKA_VERIFY);
    verifyRecover = attrs.removeBool(CKA_VERIFY_RECOVER);
    wrap          = attrs.removeBool(CKA_WRAP);
    wrapTemplate  = attrs.removeTemplate(CKA_WRAP_TEMPLATE);
    encapsulateTemplate  = attrs.removeTemplate(CKA_ENCAPSULATE_TEMPLATE);
    publicKeyInfo = attrs.removeByteArray(CKA_PUBLIC_KEY_INFO);

    Boolean attrB = attrs.removeBool(CKA_TRUSTED);
    if (attrB != null) {
      if (initMethod == ObjectInitMethod.UPDATE) {
        loginState.assertLoggedIn(CKU_SO);
      }
      this.trusted = attrB;
    }
  }

  public static XiPublicKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod,
      long handle, boolean inToken, XiTemplate attrs, long keyType,
      Long keyGenMechanism) throws HsmException {
    if (keyType == CKK_RSA) {
      return XiRSAPublicKey.newInstance(vendor, cku, newObjectMethod,
          loginState, initMethod, handle, inToken, attrs, keyGenMechanism);
    } else if (keyType == CKK_EC_EDWARDS) {
      return XiEdwardsECPublicKey.newInstance(vendor, cku, newObjectMethod,
          loginState, initMethod, handle, inToken, attrs, keyGenMechanism);
    } else if (keyType == CKK_EC_MONTGOMERY) {
      return XiMontgomeryECPublicKey.newInstance(vendor, cku, newObjectMethod,
          loginState, initMethod, handle, inToken, attrs, keyGenMechanism);
    } else if (keyType == CKK_EC) {
      return XiWeierstrassECPublicKey.newInstance(vendor, cku, newObjectMethod,
          loginState, initMethod, handle, inToken, attrs, keyGenMechanism);
    } else if (keyType == PKCS11T.CKK_VENDOR_SM2) {
      return XiSm2ECPublicKey.newInstance(vendor, cku, newObjectMethod,
          loginState, initMethod, handle, inToken, attrs, keyGenMechanism);
    } else if (keyType == CKK_ML_DSA) {
      return XiMLDSAPublicKey.newInstance(vendor, cku, newObjectMethod,
          loginState, initMethod, handle, inToken, attrs, keyGenMechanism);
    } else if (keyType == CKK_ML_KEM) {
      return XiMLKEMPublicKey.newInstance(vendor, cku, newObjectMethod,
          loginState, initMethod, handle, inToken, attrs, keyGenMechanism);
    } else {
      throw new HsmException(CKR_GENERAL_ERROR,
          "unsupported public key type " +
              PKCS11T.ckkCodeToName(keyType));
    }
  }

}
