// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.store;

import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.Hex;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_CLASS;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_ID;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_KEY_TYPE;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_LABEL;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_PRIVATE;

/**
 * Persist Object.
 *
 * @author Lijun Liao (xipki)
 */
public class PersistObject implements JsonEncodable {

  private static final int V1 = 1;

  private final long cku;

  private final Origin origin;

  private final boolean private_;

  private final long objectClass;

  private final long keyType;

  private final byte[] id;

  private final String label;

  private final XiTemplate attrs;

  public PersistObject(long cku, Origin origin, boolean private_, long objectClass,
                      long keyType, byte[] id, String label, XiTemplate attrs) {
    this.cku = cku;
    this.origin = Args.notNull(origin, "origin");
    this.private_ = private_;
    this.objectClass = objectClass;
    this.keyType = keyType;
    this.id = id;
    this.label = label;
    this.attrs = Args.notNull(attrs, "attrs");
  }

  public long getCku() {
    return cku;
  }

  public Origin getOrigin() {
    return origin;
  }

  public boolean isPrivate_() {
    return private_;
  }

  public long getObjectClass() {
    return objectClass;
  }

  public long getKeyType() {
    return keyType;
  }

  public byte[] getId() {
    return id;
  }

  public String getLabel() {
    return label;
  }

  public XiTemplate getAttrs() {
    return attrs;
  }

  @Override
  public JsonMap toCodec() {
    JsonMap map = new JsonMap();
    map.put("version", V1);
    map.put("cku", PKCS11T.ckuCodeToName(cku));
    map.put("origin", origin.name());
    map.put("private", private_);
    map.put("class", PKCS11T.ckoCodeToName(objectClass));

    map.put("keyType", PKCS11T.ckkCodeToName(keyType));
    if (id != null) {
      map.put("id", Hex.encode(id));
    }

    if (label != null) {
      map.put("label", label);
    }

    if (attrs != null) {
      map.put("attrs", attrs);
    }

    return map;
  }

  public boolean isVisibleForCku(XiHsmVendor vendor, LoginState loginState) {
    if (!private_) {
      return true;
    }

    Long loginCku = loginState.getUserType();
    if (!(loginState.isLoggedIn() && loginCku != null)) {
      return false;
    }

    return vendor.isPrivateObjectVisibleToOther() || (cku == loginCku);
  }

  public boolean match(XiTemplate criteria) throws HsmException {
    return toAttributes().match(criteria);
  }

  public XiTemplate toAttributes() throws HsmException {
    try {
      XiTemplate attrs = XiTemplate.decode(this.attrs.toCodec());
      attrs.add(XiAttribute.ofLong(XiAttribute.CKA_XIHSM_CKU, cku));
      attrs.add(XiAttribute.ofLong(XiAttribute.CKA_XIHSM_ORIGIN, origin.getCode()));
      attrs.add(XiAttribute.ofBool(CKA_PRIVATE, private_));
      attrs.add(XiAttribute.ofLong(CKA_CLASS, objectClass));
      if (keyType != -1) {
        attrs.add(XiAttribute.ofLong(CKA_KEY_TYPE, keyType));
      }

      if (id != null) {
        attrs.add(XiAttribute.ofByteArray(CKA_ID, id));
      }

      if (label != null) {
        attrs.add(XiAttribute.ofChars(CKA_LABEL, label));
      }

      return attrs;
    } catch (RuntimeException e) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR, "error decoding PersistObject", e);
    }
  }

  public static PersistObject decode(byte[] encoded) throws HsmException {
    try {
      return decode(JsonParser.parseMap(encoded, false));
    } catch (CodecException e) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR, "error decoding PersistObject", e);
    }
  }

  public static PersistObject decode(JsonMap jMap) throws HsmException {
    try {
      int version = jMap.getInt("version");
      if (version != V1) {
        throw new HsmException(PKCS11T.CKR_GENERAL_ERROR, "invalid version " + version);
      }

      long cku = PKCS11T.nonnullNameToCode(Category.CKU, jMap.getNnString("cku"));
      Origin origin = Origin.valueOf(jMap.getNnString("origin"));
      boolean private_ = jMap.getNnBool("private");
      long objClass = PKCS11T.nonnullNameToCode(Category.CKO, jMap.getNnString("class"));
      long keyType  = PKCS11T.nonnullNameToCode(Category.CKK, jMap.getNnString("keyType"));
      String str = jMap.getString("id");
      byte[] id = (str == null) ? null : Hex.decode(str);
      String label = jMap.getString("label");
      XiTemplate attrs = XiTemplate.decode(jMap.getNnMap("attrs"));

      return new PersistObject(cku, origin, private_, objClass, keyType, id, label, attrs);
    } catch (CodecException e) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR, "error decoding PersistObject", e);
    }
  }

}
