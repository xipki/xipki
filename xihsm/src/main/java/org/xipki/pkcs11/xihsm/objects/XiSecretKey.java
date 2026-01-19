// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.vendor.VendorEnum;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.attr.XiTemplateChecker;
import org.xipki.pkcs11.xihsm.crypt.HashAlgo;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.util.codec.Args;

import java.security.SecureRandom;
import java.util.List;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * @author Lijun Liao (xipki)
 */
public class XiSecretKey extends XiPrivateOrSecretKey
    implements XiPublicOrSecretKey {

  private final byte[] value;

  /**
   * CK_TRUE if key supports encryption.
   * <p/>
   * May be modified after object is created with a C_SetAttributeValue call,
   * or in the process of copying object with a C_CopyObject call. However, it
   * is possible that a particular token may not permit modification of the
   * attribute during the course of a C_CopyObject call.
   * <p/>
   * Default value is token-specific, and may depend on the values of other
   * attributes.
   */
  protected Boolean encrypt;

  /**
   * CK_TRUE if key supports verification (i.e., of authentication codes) where
   * the signature is an appendix to the data.
   * <p/>
   * May be modified after the object is created with a C_SetAttributeValue
   * call, or in the process of copying the object with a C_CopyObject call.
   * However, it is possible that a particular token may not permit
   * modification of the attribute during the process of a C_CopyObject call.
   * <p/>
   * The default value is token-specific, and may depend on the values of other
   * attributes.
   */
  protected Boolean verify;

  /**
   * CK_TRUE if key supports wrapping (i.e., can be used to wrap other keys).
   * <p/>
   * May be modified after the object is created with a C_SetAttributeValue
   * call, or in the process of copying the object with a C_CopyObject call.
   * However, it is possible that a particular token may not permit
   * modification of the attribute during the process of a C_CopyObject call.
   * <p/>
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

  /**
   * Key checksum
   */
  private byte[] checkValue;

  public XiSecretKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, long keyType,
      Long keyGenMechanism, byte[] value) {
    super(vendor, cku, newObjectMethod, handle, inToken,
        CKO_SECRET_KEY, keyType, keyGenMechanism);
    this.value = Args.notNull(value, "value");
  }

  public boolean isVerify() {
    return boolValue(verify, false);
  }

  public boolean isEncrypt() {
    return boolValue(encrypt, false);
  }

  public boolean isWrap() {
    return boolValue(wrap, false);
  }

  public boolean isTrusted() {
    return trusted != null && trusted;
  }

  public byte[] getValue() {
    return value;
  }

  @Override
  public XiTemplate getWrapTemplate() {
    return wrapTemplate;
  }

  @Override
  public byte[] getEncoded() {
    return value;
  }

  @Override
  protected void assertAttributesSettable(XiTemplate attrs)
      throws HsmException {
    XiTemplateChecker.assertSecretKeyAttributesSettable(attrs);
  }

  @Override
  protected void doSetAttributes(
      LoginState loginState, ObjectInitMethod initMethod, XiTemplate attrs)
      throws HsmException {
    super.doSetAttributes(loginState, initMethod, attrs);

    encrypt = attrs.removeBool(CKA_ENCRYPT);
    verify  = attrs.removeBool(CKA_VERIFY);
    wrap    = attrs.removeBool(CKA_WRAP);
    trusted = attrs.removeBool(CKA_TRUSTED);
    checkValue = attrs.removeByteArray(CKA_CHECK_VALUE);
    wrapTemplate = attrs.removeTemplate(CKA_WRAP_TEMPLATE);
  }

  @Override
  public byte[] sign(XiMechanism mechanism, byte[] data,
                            SecureRandom random)
      throws HsmException {
    if (!isSign()) {
      throw new HsmException(PKCS11T.CKR_KEY_FUNCTION_NOT_PERMITTED,
          "CKA_SIGN != TRUE");
    }

    return computeMac(mechanism, data);
  }

  private byte[] computeMac(XiMechanism mechanism, byte[] data)
      throws HsmException {
    long ckm = mechanism.getCkm();
    if (ckm == CKM_SHA_1_HMAC
        || ckm == CKM_SHA224_HMAC
        || ckm == CKM_SHA256_HMAC
        || ckm == CKM_SHA384_HMAC
        || ckm == CKM_SHA512_HMAC) {
      HashAlgo ha = (ckm == CKM_SHA256_HMAC) ? HashAlgo.SHA256
          : (ckm == CKM_SHA384_HMAC) ? HashAlgo.SHA384
          : HashAlgo.SHA512;

      HMac mac = new HMac(ha.createDigest());
      mac.init(new KeyParameter(value));
      mac.update(data, 0, data.length);

      byte[] macValue = new byte[mac.getMacSize()];
      mac.doFinal(macValue, 0);
      return macValue;
    }

    throw new HsmException(CKR_MECHANISM_INVALID,
        "unsupported mechanism " + PKCS11T.ckmCodeToName(ckm));
  }

  @Override
  protected void doGetAttributes(
      List<XiAttribute> res, long[] types, boolean withAll)
      throws HsmException {
    super.doGetAttributes(res, types, withAll);

    addAttr(res, types, CKA_ENCRYPT,   encrypt);
    addAttr(res, types, CKA_WRAP,      wrap);
    addAttr(res, types, CKA_VERIFY,    verify);
    addAttr(res, types, CKA_TRUSTED,   trusted);
    addAttr(res, types, CKA_CHECK_VALUE, checkValue);
    addAttr(res, types, CKA_WRAP_TEMPLATE, wrapTemplate);

    int vLen = value.length;
    if (!withAll) {
      if (vendor.getVendorEnum() == VendorEnum.SOFTHSM) {
        vLen = 0;
      }
    }
    addAttr(res, types, CKA_VALUE_LEN, vLen);

    if (withAll || !isSensitive()) {
      addAttr(res, types, CKA_VALUE, value);
    }
  }

  public static XiSecretKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod,
      long handle, boolean inToken, XiTemplate attrs, long keyType,
      Long keyGenMechanism) throws HsmException {
    byte[] value = attrs.removeNonNullByteArray(CKA_VALUE);
    attrs.removeAttributes(CKA_VALUE_LEN);
    XiSecretKey secretKey = new XiSecretKey(vendor, cku, newObjectMethod,
        handle, inToken, keyType, keyGenMechanism, value);
    secretKey.updateAttributes(loginState, initMethod, attrs);
    return secretKey;
  }

}
