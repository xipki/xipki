// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.HsmUtil;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.asn1.Asn1Util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * @author Lijun Liao (xipki)
 */
public abstract class XiP11Storage extends XiP11Object {

  public static final long CKA_XIHSM_CKU = 0x1_FFFF_FFFFL;

  public static final long CKA_XIHSM_ORIGIN = 0x1_FFFF_FFFEL;

  /**
   * CK_TRUE if the object is a token object; CK_FALSE if the object is a#
   * session object. Default is CK_FALSE.
   */
  protected final boolean inToken;

  /**
   * CK_TRUE if object is a private object; CK_FALSE if object is a public
   * object. Default value is token-specific, and may depend on the values of
   * other attributes of the object.
   */
  protected Boolean private_;

  /**
   * CK_TRUE if object can be modified Default is CK_TRUE.
   */
  protected Boolean modifiable;

  /**
   * CK_TRUE if object can be copied using C_CopyObject. Defaults to CK_TRUE.
   * Can't be set to TRUE once it is set to FALSE.
   */
  protected Boolean copyable;

  /**
   * CK_TRUE if the object can be destroyed using C_DestroyObject.
   * Default is CK_TRUE.
   */
  protected Boolean destroyable;

  /**
   * RFC2279 string, Description of the object (default empty).
   */
  protected String label;

  protected final XiHsmVendor vendor;

  protected final long cku;

  protected final Origin newObjectMethod;

  public XiP11Storage(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, long objectClass) {
    super(handle, objectClass);

    this.vendor = Args.notNull(vendor, "vendor");
    this.cku = cku;
    this.newObjectMethod = Args.notNull(newObjectMethod, "newObjectMethod");
    this.inToken = inToken;
  }

  public long getHandle() {
    return handle;
  }

  public boolean isModifiable() {
    return boolValue(modifiable, true);
  }

  public boolean isDestroyable() {
    return boolValue(destroyable, true);
  }

  public boolean isVisibleForCku(LoginState loginState) {
    boolean isPrivate = (private_ != null) ? private_ : isDefaultPrivate();
    if (!isPrivate) {
      return true;
    }

    Long loginCku = loginState.getUserType();
    if (!(loginState.isLoggedIn() && loginCku != null)) {
      return false;
    }

    return vendor.isPrivateObjectVisibleToOther() || (cku == loginCku);
  }

  protected static void addAttr(
      List<XiAttribute> res, long[] types, long type, Object value)
      throws HsmException {
    if (value == null) {
      return;
    }

    if (types == null || HsmUtil.contains(types, type)) {
      if (type == CKA_EC_POINT) {
        value = Asn1Util.toOctetString((byte[]) value);
      }

      for (XiAttribute attr : res) {
        if (attr.getType() == type) {
          throw new HsmException(CKR_GENERAL_ERROR,
              "duplicated attribute " + PKCS11T.ckaCodeToName(type)
          );
        }
      }

      res.add(XiAttribute.ofObject(type, value));
    }
  }

  protected abstract void assertAttributesSettable(XiTemplate attrs)
      throws HsmException;

  protected abstract boolean isDefaultPrivate();

  protected void doSetAttributes(
      LoginState loginState, ObjectInitMethod initMethod, XiTemplate attrs)
      throws HsmException {
    // CKA_PRIVATE
    Boolean b = attrs.removeBool(CKA_PRIVATE);
    if (b != null) {
      assertNotTrueToFalse(initMethod, CKA_PRIVATE, b,
          boolValue(private_, isDefaultPrivate()));
      this.private_ = b;
    }

    // CKA_COPYABLE
    b = attrs.removeBool(CKA_COPYABLE);
    if (b != null) {
      assertNotFalseToTrue(initMethod, CKA_COPYABLE, b,
          boolValue(this.copyable, true));
      this.copyable = b;
    }

    // CKA_DESTROYABLE
    b = attrs.removeBool(CKA_DESTROYABLE);
    if (b != null) {
      assertNotFalseToTrue(initMethod, CKA_DESTROYABLE, b,
          boolValue(this.destroyable, true));
      this.destroyable = b;
    }

    this.label = attrs.removeChars(CKA_LABEL);

    // CKA_MODIFIABLE
    b = attrs.removeBool(CKA_MODIFIABLE);
    if (b != null) {
      assertNotFalseToTrue(initMethod, CKA_MODIFIABLE, b,
          boolValue(this.modifiable, true));
      this.modifiable = b;
    }
  }

  protected void doGetAttributes(
      List<XiAttribute> res, long[] types, boolean withAll)
      throws HsmException {
    addAttr(res, types, CKA_TOKEN,       inToken);
    addAttr(res, types, CKA_CLASS,       objectClass);
    addAttr(res, types, CKA_PRIVATE,     private_);
    addAttr(res, types, CKA_MODIFIABLE,  modifiable);
    addAttr(res, types, CKA_COPYABLE,    copyable);
    addAttr(res, types, CKA_DESTROYABLE, destroyable);
    addAttr(res, types, CKA_LABEL,       label);

    if (withAll) {
      addAttr(res, types, CKA_XIHSM_CKU, cku);
      addAttr(res, types, CKA_XIHSM_ORIGIN, newObjectMethod.getCode());
    }
  }

  public boolean match(XiTemplate template) {
    long[] requiredTypes = template.getTypes();
    List<XiAttribute> attrs = new ArrayList<>(requiredTypes.length);
    try {
      doGetAttributes(attrs, requiredTypes, false);
    } catch (HsmException e) {
      return false;
    }

    if (attrs.size() != requiredTypes.length) {
      return false;
    }

    return template.match(new XiTemplate(attrs));
  }

  public final void updateAttributes(
      LoginState loginState, ObjectInitMethod initMethod, XiTemplate attrs)
      throws HsmException {
    assertAttributesSettable(attrs);

    if (modifiable != null && !modifiable) {
      throw new HsmException(CKR_ACTION_PROHIBITED,
          "The object is not modifiable");
    }

    doSetAttributes(loginState, initMethod, attrs);

    if (attrs.getSize() > 0) {
      throw new HsmException(CKR_ATTRIBUTE_TYPE_INVALID,
          "Attribute of types are not allowed: " +
          Arrays.toString(attrs.getTextTypes()));
    }
  }

  public XiTemplate getAllAttributes() throws HsmException {
    List<XiAttribute> res = new LinkedList<>();
    doGetAttributes(res, null, true);
    return new XiTemplate(res);
  }

  public XiTemplate getAttributes(long[] types) throws HsmException {
    List<XiAttribute> res = new LinkedList<>();
    doGetAttributes(res, types, false);
    return new XiTemplate(res);
  }

  public byte[] encode() throws HsmException {
    XiTemplate attrs = getAllAttributes();
    return attrs.encode();
  }

  protected static boolean boolValue(Boolean b, boolean default_) {
    return b == null ? default_ : b;
  }

  /**
   * cannot set from TRUE to FALSE
   */
  protected static void assertNotTrueToFalse(
      ObjectInitMethod initMethod, long cka, boolean newValue, boolean oldValue)
      throws HsmException {
    if (initMethod == ObjectInitMethod.UPDATE && oldValue && !newValue) {
      throw new HsmException(CKR_ATTRIBUTE_VALUE_INVALID,
          "Cannot set " + PKCS11T.ckaCodeToName(cka) +
              " to FALSE");
    }
  }

  /**
   * cannot set from FALSE to TRUE
   */
  protected static void assertNotFalseToTrue(
      ObjectInitMethod initMethod, long cka, boolean newValue, boolean oldValue)
      throws HsmException {
    if (initMethod == ObjectInitMethod.UPDATE && !oldValue && newValue) {
      throw new HsmException(CKR_ATTRIBUTE_VALUE_INVALID,
          "Cannot set " + PKCS11T.ckaCodeToName(cka) +
              " to TRUE");
    }
  }

  public static XiP11Storage decode(
      XiHsmVendor vendor, long handle, byte[] encoded) throws HsmException {
    return fromAttributes(vendor, null, ObjectInitMethod.RESTORE,
        handle, XiTemplate.decode(encoded));
  }

  public static XiP11Storage fromAttributes(
      XiHsmVendor vendor, long handle, XiTemplate attrs) throws HsmException {
   return fromAttributes(vendor, null, ObjectInitMethod.RESTORE,
       handle, attrs);
  }

  public static XiP11Storage fromAttributes(
      XiHsmVendor vendor, LoginState loginState, ObjectInitMethod initMethod,
      long handle, XiTemplate attrs) throws HsmException {
    long objClass = attrs.removeNonNullLong(CKA_CLASS);
    long cku = attrs.removeNonNullLong(CKA_XIHSM_CKU);

    long newObjectMethodCode = attrs.removeLong(CKA_XIHSM_ORIGIN);
    Origin newObjectMethod =
        Origin.ofCode(newObjectMethodCode);

    Boolean b = attrs.removeBool(CKA_TOKEN);
    boolean inToken = b != null && b;

    if (!(objClass == CKO_SECRET_KEY || objClass == CKO_PUBLIC_KEY
        || objClass == CKO_PRIVATE_KEY)) {
      throw new HsmException(CKR_GENERAL_ERROR,
          "can not construct a PKCS#11 object of class " +
              PKCS11T.ckoCodeToName(objClass));
    }

    long keyType = attrs.removeNonNullLong(CKA_KEY_TYPE);
    Long keyGenMechanism = attrs.removeLong(CKA_KEY_GEN_MECHANISM);

    if (objClass == CKO_SECRET_KEY) {
      return XiSecretKey.newInstance(vendor, cku, newObjectMethod,
          loginState, initMethod, handle, inToken, attrs, keyType,
          keyGenMechanism);
    } else if (objClass == CKO_PUBLIC_KEY) {
      return XiPublicKey.newInstance(vendor, cku, newObjectMethod,
          loginState, initMethod, handle, inToken, attrs, keyType,
          keyGenMechanism);
    } else { // if (objClass == CKO_PRIVATE_KEY) {
      return XiPrivateKey.newInstance(vendor, cku, newObjectMethod,
          loginState, initMethod, handle, inToken, attrs, keyType,
          keyGenMechanism);
    }
  }

}
