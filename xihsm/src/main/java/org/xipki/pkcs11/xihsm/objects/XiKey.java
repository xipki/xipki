// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiDate;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;

import java.util.List;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_ALLOWED_MECHANISMS;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_DERIVE;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_END_DATE;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_ID;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_KEY_GEN_MECHANISM;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_KEY_TYPE;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_LOCAL;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKA_START_DATE;

/**
 * @author Lijun Liao (xipki)
 */
public abstract class XiKey extends XiP11Storage {

  /**
   * Type of key.
   * <p/>
   * MUST be specified when the object is created with C_CreateObject.
   * <p/>
   * MUST be specified when the object is unwrapped with C_UnwrapKey.
   */
  protected final long keyType;

  /**
   * Identifier of the mechanism used to generate the key material.
   * <p>
   * MUST not be specified when object is created with C_CreateObject.
   * <p>
   * MUST not be specified when object is generated with C_GenerateKey or
   * C_GenerateKeyPair.
   * <p>
   * MUST not be specified when object is unwrapped with C_UnwrapKey.
   * <p>
   * The CKA_KEY_GEN_MECHANISM attribute identifies the key generation
   * mechanism used to generate the key material. It contains a valid value
   * only if the CKA_LOCAL attribute has the value CK_TRUE. If CKA_LOCAL has
   * the value CK_FALSE, the value of the attribute is
   * CK_UNAVAILABLE_INFORMATION.
   */
  private final Long keyGenMechanism;

  /**
   * Key identifier for key (default empty)
   * <p/>
   * The CKA_ID field is intended to distinguish among multiple keys. In the
   * case of public and private keys, this field assists in handling multiple
   * keys held by the same subject; the key identifier for a public key and its
   * corresponding private key should be the same. The key identifier should
   * also be the same as for the corresponding certificate, if one exists.
   * Cryptoki does not enforce these associations, however. (See Section 4.6
   * for further commentary.)
   * <p/>
   * In the case of secret keys, the meaning of the CKA_ID attribute is up to
   * the application.
   * <p/>
   * May be modified after object is created with a C_SetAttributeValue call,
   * or in the process of copying object with a C_CopyObject call. However,
   * it is possible that a particular token may not permit modification of the
   * attribute during the course of a C_CopyObject call.
   */
  private byte[] id;

  /**
   * Start date for the key (default empty).
   * <p/>
   * Note that the CKA_START_DATE and CKA_END_DATE attributes are for reference
   * only; Cryptoki does not attach any special meaning to them. In particular,
   * it does not restrict usage of a key according to the dates; doing this is
   * up to the application.
   * <p/>
   * May be modified after object is created with a C_SetAttributeValue call,
   * or in the process of copying object with a C_CopyObject call. However,
   * it is possible that a particular token may not permit modification of the
   * attribute during the course of a C_CopyObject call.
   */
  private XiDate startDate;

  /**
   * End date for the key (default empty).
   * <p/>
   * Note that the CKA_START_DATE and CKA_END_DATE attributes are for reference
   * only; Cryptoki does not attach any special meaning to them. In particular,
   * it does not restrict usage of a key according to the dates; doing this is
   * up to the application.
   * <p/>
   * May be modified after object is created with a C_SetAttributeValue call,
   * or in the process of copying object with a C_CopyObject call. However,
   * it is possible that a particular token may not permit modification of the
   * attribute during the course of a C_CopyObject call.
   */
  private XiDate endDate;

  /**
   * CK_TRUE if key supports key derivation (i.e., if other keys can be derived
   * from this one (default CK_FALSE)
   * <p/>
   * May be modified after object is created with a C_SetAttributeValue call,
   * or in the process of copying object with a C_CopyObject call. However,
   * it is possible that a particular token may not permit modification of the
   * attribute during the course of a C_CopyObject call.
   */
  private Boolean derive;

  /**
   * CK_TRUE only if key was either
   * <ul>
   *  <li>generated locally (i.e., on the token) with a C_GenerateKey or
   *    C_GenerateKeyPair call</li>
   *  <li>created with a C_CopyObject call as a copy of a key which had its
   *    CKA_LOCAL attribute set to CK_TRUE</li>
   * </ul>
   *
   * MUST not be specified when object is created with C_CreateObject.
   * <p>
   * MUST not be specified when object is generated with C_GenerateKey or
   * C_GenerateKeyPair.
   * <p>
   * MUST not be specified when object is unwrapped with C_UnwrapKey.
   */
  private Boolean local;

  /**
   * A list of mechanisms allowed to be used with this key. The number of
   * mechanisms in the array is the ulValueLen component of the attribute
   * divided by the size of CK_MECHANISM_TYPE.
   */
  private long[] allowedMechanisms;

  public XiKey(XiHsmVendor vendor, long cku, Origin newObjectMethod,
               long handle, boolean inToken, long objectClass, long keyType,
               Long keyGenMechanism) {
    super(vendor, cku, newObjectMethod, handle, inToken, objectClass);
    this.keyType = keyType;
    this.keyGenMechanism = keyGenMechanism;
  }

  public long getKeyType() {
    return keyType;
  }

  public boolean isDerive() {
    return boolValue(derive, false);
  }

  @Override
  protected void doGetAttributes(
      List<XiAttribute> res, long[] types, boolean withAll)
      throws HsmException {
    super.doGetAttributes(res, types, withAll);
    addAttr(res, types, CKA_KEY_TYPE,   keyType);
    addAttr(res, types, CKA_ID,         id);
    addAttr(res, types, CKA_START_DATE, startDate);
    addAttr(res, types, CKA_END_DATE,   endDate);
    addAttr(res, types, CKA_DERIVE,     derive);
    addAttr(res, types, CKA_LOCAL,      local);
    addAttr(res, types, CKA_KEY_GEN_MECHANISM,  keyGenMechanism);
    addAttr(res, types, CKA_ALLOWED_MECHANISMS, allowedMechanisms);
  }

  @Override
  protected void doSetAttributes(
      LoginState loginState, ObjectInitMethod initMethod, XiTemplate attrs)
      throws HsmException {
    super.doSetAttributes(loginState, initMethod, attrs);

    this.id        = attrs.removeByteArray(CKA_ID);
    this.startDate = attrs.removeDate(CKA_START_DATE);
    this.endDate   = attrs.removeDate(CKA_END_DATE);
    this.derive    = attrs.removeBool(CKA_DERIVE);
    this.local     = attrs.removeBool(CKA_LOCAL);
    this.allowedMechanisms = attrs.removeLongArray(CKA_ALLOWED_MECHANISMS);
  }
}
