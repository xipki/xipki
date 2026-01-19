// Copyright (c) 2023 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.store;

import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.objects.XiP11Storage;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.cbor.CborDecoder;
import org.xipki.util.codec.cbor.CborEncodable;
import org.xipki.util.codec.cbor.CborEncoder;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_CLASS;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_ID;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_KEY_TYPE;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_LABEL;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_PRIVATE;

/**
 * @author Lijun Liao (xipki)
 */
public class PersistObject implements CborEncodable {

  private static final int V1 = 1;

  private final long cku;

  private final Origin origin;

  private final boolean private_;

  private final long objectClass;

  private final long keyType;

  private final byte[] id;

  private final String label;

  private final byte[] attrs;

  public PersistObject(long cku, Origin origin, boolean private_,
                       long objectClass, long keyType, byte[] id, String label,
                       byte[] attrs) {
    this.cku = cku;
    this.origin = Args.notNull(origin, "origin");
    this.private_ = private_;
    this.objectClass = objectClass;
    this.keyType = keyType;
    this.id = id;
    this.label = label;
    this.attrs = Args.notEmptyBytes(attrs, "attrs");
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

  public byte[] getAttrs() {
    return attrs;
  }

  @Override
  public void encode(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(9);
    encoder.writeInt(V1);
    encoder.writeLong(cku);
    encoder.writeLong(origin.getCode());
    encoder.writeBoolean(private_);
    encoder.writeLong(objectClass);
    encoder.writeLong(keyType);
    encoder.writeByteString(id);
    encoder.writeTextString(label);
    encoder.writeByteString(attrs);
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

  public XiTemplate toAttributes()
      throws HsmException {
    XiTemplate attrs = XiTemplate.decode(this.attrs);
    attrs.add(XiAttribute.ofLong(
        XiP11Storage.CKA_XIHSM_CKU, cku));
    attrs.add(XiAttribute.ofLong(
        XiP11Storage.CKA_XIHSM_ORIGIN, origin.getCode()));
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
  }

  public static PersistObject decode(byte[] encoded)
      throws CodecException {
    return decode(new CborDecoder(encoded));
  }

  public static PersistObject decode(CborDecoder decoder)
      throws CodecException {
    decoder.readArrayLength(9);
    int version = decoder.readInt();
    if (version != V1) {
      throw new CodecException("invalid version " + version);
    }

    return new PersistObject(
        decoder.readLong(), // cku
        Origin.ofCode(decoder.readLong()), // origin
        decoder.readBoolean(),
        decoder.readLong(),
        decoder.readLong(),
        decoder.readByteString(),
        decoder.readTextString(),
        decoder.readByteString());
  }

}
