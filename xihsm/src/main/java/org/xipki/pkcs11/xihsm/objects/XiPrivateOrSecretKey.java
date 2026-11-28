// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;

import java.security.SecureRandom;
import java.util.List;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * Xi Private Or Secret Key.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class XiPrivateOrSecretKey extends XiKey {

  /**
   * CK_TRUE if key supports decryption.
   * <p/>
   * May be modified after object is created with a C_SetAttributeValue call,
   * or in the process of copying object with a C_CopyObject call. However, it
   * is possible that a particular token may not permit modification of the
   * attribute during the course of a C_CopyObject call.
   * <p/>
   * Default value is token-specific, and may depend on the values of other
   * attributes.
   */
  private Boolean decrypt;

  /**
   * CK_TRUE if key is extractable and can be wrapped.
   * <p/>
   * May be modified after object is created with a C_SetAttributeValue call,
   * or in the process of copying object with a C_CopyObject call. However, it
   * is possible that a particular token may not permit modification of the
   * attribute during the course of a C_CopyObject call.
   * <p/>
   * Default value is token-specific, and may depend on the values of other
   * attributes.
   * <p/>
   * Attribute cannot be changed once set to CK_FALSE. It becomes a read only
   * attribute.
   */
  private Boolean extractable;

  /**
   * CK_TRUE if key is sensitive.
   * <p/>
   * May be modified after object is created with a C_SetAttributeValue call,
   * or in the process of copying object with a C_CopyObject call. However, it
   * is possible that a particular token may not permit modification of the
   * attribute during the course of a C_CopyObject call.
   * <p/>
   * Default value is token-specific, and may depend on the values of other
   * attributes.
   * <p/>
   * Attribute cannot be changed once set to CK_TRUE. It becomes a read only
   * attribute.
   */
  private Boolean sensitive;

  /**
   * CK_TRUE if key supports signatures where the signature is an appendix to
   * the data.
   * <p/>
   * May be modified after object is created with a C_SetAttributeValue call,
   * or in the process of copying object with a C_CopyObject call. However, it
   * is possible that a particular token may not permit modification of the
   * attribute during the course of a C_CopyObject call.
   * <p/>
   * Default value is token-specific, and may depend on the values of other
   * attributes.
   */
  private Boolean sign;

  /**
   * CK_TRUE if key supports unwrapping (i.e., can be used to unwrap other
   * keys).
   * <p/>
   * May be modified after object is created with a C_SetAttributeValue call,
   * or in the process of copying object with a C_CopyObject call. However, it
   * is possible that a particular token may not permit modification of the
   * attribute during the course of a C_CopyObject call.
   * <p/>
   * Default value is token-specific, and may depend on the values of other
   * attributes.
   */
  private Boolean unwrap;

  /**
   * CK_TRUE if the key can only be wrapped with a wrapping key that has
   * CKA_TRUSTED set to CK_TRUE. Default is CK_FALSE.
   * <p>
   * Attribute cannot be changed once set to CK_TRUE. It becomes a read only
   * attribute.
   */
  private Boolean wrapWithTrusted;

  /**
   * CK_TRUE if key has always had the CKA_SENSITIVE attribute set to CK_TRUE.
   * <p>
   * MUST not be specified when object is created with C_CreateObject.
   * <p>
   * MUST not be specified when object is generated with C_GenerateKey or
   * C_GenerateKeyPair.
   * <p>
   * MUST not be specified when object is unwrapped with C_UnwrapKey.
   */
  private Boolean alwaysSensitive;

  /**
   * CK_TRUE if key has never had the CKA_EXTRACTABLE attribute set to CK_TRUE.
   * <p>
   * MUST not be specified when object is created with C_CreateObject.
   * <p>
   * MUST not be specified when object is generated with C_GenerateKey or
   * C_GenerateKeyPair.
   * <p>
   * MUST not be specified when object is unwrapped with C_UnwrapKey.
   */
  private Boolean neverExtractable;

  /**
   * For wrapping keys. The attribute template to apply to any keys unwrapped
   * using this wrapping key. Any user supplied template is applied after this
   * template as if the object has already been created. The number of
   * attributes in the array is the ulValueLen component of the attribute
   * divided by the size of CK_ATTRIBUTE.
   */
  private XiTemplate unwrapTemplate;

  private XiTemplate deriveTemplate;

  public XiPrivateOrSecretKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod, long handle,
      boolean inToken, long objectClass, long keyType, Long keyGenMechanism) {
    super(vendor, cku, newObjectMethod, handle, inToken, objectClass, keyType, keyGenMechanism);
  }

  public abstract byte[] getEncoded() throws HsmException;

  public boolean isSign() {
    return boolValue(sign, false);
  }

  public boolean isDecrypt() {
    return boolValue(decrypt, false);
  }

  public boolean isUnwrap() {
    return boolValue(unwrap, false);
  }

  public boolean isSensitive() {
    return boolValue(sensitive, true);
  }

  public boolean isExtractable() {
    return boolValue(extractable, false);
  }

  public boolean isWrapWithTrusted() {
    return boolValue(wrapWithTrusted, false);
  }

  public XiTemplate getUnwrapTemplate() {
    return unwrapTemplate;
  }

  public XiTemplate getDeriveTemplate() {
    return deriveTemplate;
  }

  public byte[] sign(XiMechanism mechanism, byte[] data, SecureRandom random) throws HsmException {
    throw new HsmException(CKR_KEY_FUNCTION_NOT_PERMITTED, getClass() + " does not support C_Sign");
  }

  public byte[] deriveKey(XiMechanism mechanism, XiTemplate template) throws HsmException {
    throw new HsmException(CKR_KEY_FUNCTION_NOT_PERMITTED,
        getClass().getName() + " does not support C_DeriveKey");
  }

  public byte[] decrypt(XiMechanism mechanism, byte[] encryptedData) throws HsmException {
    throw new HsmException(CKR_KEY_FUNCTION_NOT_PERMITTED,
        getClass() + " does not support C_Decrypt");
  }

  @Override
  protected boolean isDefaultPrivate() {
    return true;
  }

  @Override
  protected void doGetAttributes(List<XiAttribute> res, long[] types, boolean withAll)
      throws HsmException {
    super.doGetAttributes(res, types, withAll);

    addAttr(res, types, CKA_DECRYPT,     decrypt);
    addAttr(res, types, CKA_EXTRACTABLE, extractable);
    addAttr(res, types, CKA_SENSITIVE,   sensitive);
    addAttr(res, types, CKA_SIGN,        sign);
    addAttr(res, types, CKA_UNWRAP,      unwrap);
    addAttr(res, types, CKA_WRAP_WITH_TRUSTED, wrapWithTrusted);
    // PKCS#11: for a key generated on the token, CKA_ALWAYS_SENSITIVE is its CKA_SENSITIVE and
    // CKA_NEVER_EXTRACTABLE the negation of its CKA_EXTRACTABLE; for keys whose value was known
    // outside the token (created, unwrapped), both are CK_FALSE. The attributes are always
    // present. A stored value (e.g. set to CK_FALSE when CKA_SENSITIVE was changed) wins.
    // The derived values are only returned to queries (types != null), not stored in the
    // encoding of the object (types == null), where they would be read-only on restore.
    boolean generated = newObjectMethod == Origin.GENERATE;
    boolean derive = types != null;
    addAttr(res, types, CKA_ALWAYS_SENSITIVE, (alwaysSensitive != null || !derive)
        ? alwaysSensitive : Boolean.valueOf(generated && isSensitive()));
    addAttr(res, types, CKA_NEVER_EXTRACTABLE, (neverExtractable != null || !derive)
        ? neverExtractable : Boolean.valueOf(generated && !isExtractable()));
    addAttr(res, types, CKA_UNWRAP_TEMPLATE,   unwrapTemplate);
    addAttr(res, types, CKA_DERIVE_TEMPLATE,   deriveTemplate);
  }

  @Override
  protected void doSetAttributes(
      LoginState loginState, ObjectInitMethod initMethod, XiTemplate attrs) throws HsmException {
    super.doSetAttributes(loginState, initMethod, attrs);

    decrypt = attrs.removeBool(CKA_DECRYPT);

    // CKA_EXTRACTABLE
    // PKCS#11: CKA_EXTRACTABLE may be changed from TRUE to FALSE, but not back
    Boolean attrB = attrs.removeBool(CKA_EXTRACTABLE);
    if (attrB != null) {
      assertNotFalseToTrue(initMethod, CKA_EXTRACTABLE, attrB, isExtractable());
      this.extractable = attrB;
    }

    // CKA_SENSITIVE
    // PKCS#11: CKA_SENSITIVE may be changed from FALSE to TRUE, but not back
    attrB = attrs.removeBool(CKA_SENSITIVE);
    if (attrB != null) {
      assertNotTrueToFalse(initMethod, CKA_SENSITIVE, attrB, isSensitive());
      this.sensitive = attrB;
    }

    sign = attrs.removeBool(CKA_SIGN);

    // CKA_UNWRAP
    unwrap = attrs.removeBool(CKA_UNWRAP);

    // CKA_WRAP_WITH_TRUSTED
    attrB = attrs.removeBool(CKA_WRAP_WITH_TRUSTED);
    if (attrB != null) {
      assertNotTrueToFalse(initMethod, CKA_WRAP_WITH_TRUSTED, attrB, isWrapWithTrusted());
      this.wrapWithTrusted = attrB;
    }

    // read-only for the caller (see assertAttributesSettable), set internally and on RESTORE
    attrB = attrs.removeBool(CKA_ALWAYS_SENSITIVE);
    if (attrB != null) {
      this.alwaysSensitive = attrB;
    } else {
      if (!boolValue(sensitive, true)) {
        alwaysSensitive = false;
      }
    }

    // read-only for the caller (see assertAttributesSettable), set internally and on RESTORE
    attrB = attrs.removeBool(CKA_NEVER_EXTRACTABLE);
    if (attrB != null) {
      this.neverExtractable = attrB;
    } else {
      if (boolValue(extractable, false)) {
        neverExtractable = false;
      }
    }

    this.unwrapTemplate = attrs.removeTemplate(CKA_UNWRAP_TEMPLATE);
    this.deriveTemplate = attrs.removeTemplate(CKA_DERIVE_TEMPLATE);
  }

}
