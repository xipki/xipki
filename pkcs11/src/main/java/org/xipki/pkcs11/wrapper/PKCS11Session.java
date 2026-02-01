// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.attrs.AttributeTypes;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.type.CkMechanism;

import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * @author Lijun Liao (xipki)
 */
class PKCS11Session {

  private enum OP {
    DIGEST, SIGN
  }

  private static final Logger LOG =
      LoggerFactory.getLogger(PKCS11Session.class);

  private final Session session;

  private final PKCS11Token slot;

  private final int maxMessageSize;

  PKCS11Session(Session session, PKCS11Token slot, int maxMessageSize) {
    this.session = session;
    this.slot = slot;
    this.maxMessageSize = Math.min(maxMessageSize, slot.getMaxMessageSize());
  }

  long getSessionState() throws PKCS11Exception {
    return session.getSessionInfo().getState();
  }

  boolean isRecoverable() {
    return session.isRecoverable();
  }

  /* ***************************************
   * PKCS#11 V2.x Functions
   * ***************************************/

  void close() throws PKCS11Exception {
    session.closeSession();
  }

  void login() throws TokenException {
    session.login();
    LOG.info("login CKU_USER");
  }

  void loginSo(byte[] pin) throws TokenException {
    session.login(CKU_SO, pin == null ? new byte[0] : pin);
    LOG.info("login CKU_SO");
  }

  void logout() throws TokenException {
    session.logout();
    LOG.info("logout");
  }

  long importObject(Template template) throws TokenException {
    return session.importObject(template);
  }

  long importPrivateKey(
      PrivateKeyChoice privateKey, PublicKeyChoice publicKey,
      Template template)
      throws InvalidKeySpecException, TokenException {
    return session.importPrivateKey(privateKey, publicKey, template);
  }

  long importPublicKey(
      PublicKeyChoice publicKey, Template template)
      throws InvalidKeySpecException, TokenException {
    return session.importPublicKey(publicKey, template);
  }

  PKCS11KeyPair importKeyPair(
      PrivateKeyChoice privateKey, PublicKeyChoice publicKey,
      KeyPairTemplate template)
      throws InvalidKeySpecException, TokenException {
    return session.importKeyPair(privateKey, publicKey, template);
  }

  long copyObject(long hSourceObject, Template template)
      throws TokenException {
    return session.copyObject(hSourceObject, template);
  }

  void setAttributeValues(
      long hObjectToUpdate, Template template)
      throws TokenException {
    session.setAttributeValues(hObjectToUpdate, template);
  }

  void destroyObject(long hObject) throws TokenException {
    session.destroyObject(hObject);
  }

  List<Long> destroyObjects(List<Long> hObjects) {
    List<Long> hDestroyeds = new ArrayList<>(hObjects.size());
    for (long hObject : hObjects) {
      try {
        session.destroyObject(hObject);
        hDestroyeds.add(hObject);
      } catch (PKCS11Exception e) {
        LOG.warn("error destroying object {}: {}",
            hObject, e.getMessage());
      }
    }

    return hDestroyeds;
  }

  byte[] generateUniqueId(Template template, int idLength, Random random)
      throws TokenException {
    byte[] keyId = new byte[idLength];
    template.id(keyId);

    int tries = 0;
    while (tries++ < 256) {
      random.nextBytes(keyId);
      if (session.findObjectsSingle(template, 1).length == 0) {
        return keyId;
      }
    }

    throw new TokenException("could not generate unique ID.");
  }

  PKCS11Key getKey(Template criteria) throws TokenException {
    PKCS11KeyId keyId = getKeyId(criteria);
    return (keyId == null) ? null : getKey(keyId);
  }

  PKCS11Key getKey(PKCS11KeyId keyId) throws TokenException {
    PKCS11KeyId.KeyIdType type = keyId.type();
    long keyType = keyId.getKeyType();

    AttributeTypes ckaTypes = new AttributeTypes();

    if (type == PKCS11KeyId.KeyIdType.SECRET_KEY
        || type == PKCS11KeyId.KeyIdType.PRIVATE_KEY
        || type == PKCS11KeyId.KeyIdType.KEYPAIR) {
      ckaTypes.extractable().neverExtractable().private_().decrypt()
          .sign().unwrap().wrapWithTrusted().sensitive().alwaysSensitive();

      if (type == PKCS11KeyId.KeyIdType.SECRET_KEY) {
        ckaTypes.encrypt().trusted().verify().wrap().valueLen();
      } else {
        ckaTypes.alwaysAuthenticate().signRecover();

        if (keyType == CKK_RSA) {
          ckaTypes.modulus().publicExponent();
        } else if (keyType == CKK_EC || keyType == CKK_EC_EDWARDS
            || keyType == CKK_EC_MONTGOMERY || keyType == CKK_VENDOR_SM2) {
          ckaTypes.ecParams().ecPoint();
        } else if (keyType == CKK_DSA) {
          ckaTypes.prime().subprime().base();
        } else if (keyType == CKK_ML_DSA || keyType == CKK_ML_KEM
          || keyType == CKK_SLH_DSA) {
          ckaTypes.parameterSet();
        }
      }
    } else { // if (objClass == CKO_PUBLIC_KEY) {
      ckaTypes.encrypt().trusted().verify().verifyRecover().wrap();
      if (keyType == CKK_RSA) {
        ckaTypes.modulus().publicExponent();
      } else if (keyType == CKK_EC || keyType == CKK_EC_EDWARDS
          || keyType == CKK_EC_MONTGOMERY || keyType == CKK_VENDOR_SM2) {
        ckaTypes.ecParams().ecPoint();
      } else if (keyType == CKK_DSA) {
        ckaTypes.prime().subprime().base();
      } else if (keyType == CKK_ML_DSA || keyType == CKK_ML_KEM
        || keyType == CKK_SLH_DSA) {
        ckaTypes.parameterSet();
      }
    }

    Template attrs = session.getAttrValues(keyId.getHandle(), ckaTypes);
    // read EC_POINT from the public key
    if (type == PKCS11KeyId.KeyIdType.KEYPAIR) {
      if (keyType == CKK_EC || keyType == CKK_EC_EDWARDS
          || keyType == CKK_EC_MONTGOMERY || keyType == CKK_VENDOR_SM2) {
        if (attrs.ecPoint() == null) {
          Template pubAttrs = session.getAttrValues(
              keyId.getPublicKeyHandle(), new AttributeTypes().ecPoint());
          byte[] ecPoint = pubAttrs.ecPoint();
          if (ecPoint != null) {
            attrs.ecPoint(pubAttrs.ecPoint());
          }
        }
      }
    }

    return new PKCS11Key(keyId, attrs);
  }

  /**
   * Gets the {@link PKCS11KeyId} of a key satisfying the given criteria.
   *
   * @param criteria The criteria. At one of the CKA_ID and CKA_LABEL must be
   *                 set.
   * @return {@link PKCS11KeyId} of a key satisfying the given criteria
   * @throws TokenException If executing operation fails.
   */
  PKCS11KeyId getKeyId(Template criteria) throws TokenException {
    byte[] id = criteria.id();
    String label = criteria.label();
    if ((id == null || id.length == 0) && (label == null || label.isEmpty())) {
      return null;
    }

    Long oClass = criteria.class_();
    if (oClass != null) {
      // CKA_CLASS is set in criteria
      if (!(CKO_PRIVATE_KEY == oClass || CKO_PUBLIC_KEY == oClass
          || CKO_SECRET_KEY == oClass)) {
        return null;
      }

      long[] handles = session.findObjectsSingle(criteria, 2);
      if (handles.length == 0) {
        return null;
      } else if (handles.length > 1) {
        throw new TokenException(
            "found more than 1 key for the criteria " + criteria);
      } else {
        return getKeyIdByHandle(handles[0]);
      }
    }

    // CKA_CLASS is not set in criteria
    oClass = CKO_PRIVATE_KEY;
    long[] handles = session.findObjectsSingle(criteria.class_(oClass), 2);
    if (handles.length == 0) {
      oClass = CKO_SECRET_KEY;
      handles = session.findObjectsSingle(criteria.class_(oClass), 2);

      if (handles.length == 0) {
        oClass = CKO_PUBLIC_KEY;
        handles = session.findObjectsSingle(criteria.class_(oClass), 2);
      }
    }

    if (handles.length == 0) {
      return null;
    } else if (handles.length > 1) {
      throw new TokenException(("found more than 1 key of " +
          ckoCodeToName(oClass) + " for the criteria " +
          criteria.class_(null)));
    } else {
      return getKeyIdByHandle(handles[0]);
    }
  }

  private PKCS11KeyId getKeyIdByHandle(long hKey) throws TokenException {
    Template attrs = session.getAttrValues(hKey,
        new AttributeTypes().class_().keyType().id().label());
    Long oClass = attrs.class_();
    Long keyType = attrs.keyType();
    if (oClass == null || keyType == null) {
      return null;
    }

    byte[] id = attrs.id();
    if (oClass == CKO_PRIVATE_KEY) {
      // find the public key
      long[] pubKeyHandles = session.findObjectsSingle(
          Template.newPublicKey(keyType).id(id), 2);

      Long pubKeyHandle = null;
      if (pubKeyHandles.length == 1) {
        pubKeyHandle = pubKeyHandles[0];
      } else if (pubKeyHandles.length > 1) {
        LOG.warn("found more than 1 public key for the private " +
            "key {}, ignore them.", hKey);
      }

      PKCS11KeyId.KeyIdType type = (pubKeyHandle == null)
          ? PKCS11KeyId.KeyIdType.PRIVATE_KEY : PKCS11KeyId.KeyIdType.KEYPAIR;
      PKCS11KeyId ret = new PKCS11KeyId(type, hKey, keyType, id, attrs.label());
      ret.setPublicKeyHandle(pubKeyHandle);
      return ret;
    } else if (oClass == CKO_SECRET_KEY) {
      return new PKCS11KeyId(PKCS11KeyId.KeyIdType.SECRET_KEY,
          hKey, keyType, id, attrs.label());
    } else if (oClass == CKO_PUBLIC_KEY) {
      return new PKCS11KeyId(PKCS11KeyId.KeyIdType.PUBLIC_KEY,
          hKey, keyType, id, attrs.label());
    } else {
      throw new TokenException("invalid key class " +
          ckoCodeToName(oClass));
    }
  }

  long[] findObjects(Template template, int maxObjectCount)
      throws TokenException {
    return session.findObjectsSingle(template, maxObjectCount);
  }

  byte[] digest(CkMechanism mechanism, byte[] data) throws TokenException {
    int len = data.length;
    boolean useMulti = len > maxMessageSize
            && slot.supportsMultipart(mechanism, CKF_DIGEST);

    if (!useMulti) {
      return session.digestSingle(mechanism, data);
    } else {
      opInit(OP.DIGEST, session, mechanism, 0);
      byte[] digest;
      try {
        for (int ofs = 0; ofs < len; ofs += maxMessageSize) {
          session.signUpdate(data, ofs, Math.min(maxMessageSize, len - ofs));
        }
      } finally {
        digest = session.digestFinal();
      }
      return digest;
    }
  }

  byte[] digestKey(CkMechanism mechanism, byte[] prefix,
                   long hKey, byte[] suffix)
      throws TokenException {
    opInit(OP.DIGEST, session, mechanism, 0);
    byte[] digest;
    try {
      if (prefix != null) {
        session.digestUpdate(prefix);
      }
      session.digestKey(hKey);
      if (suffix != null) {
        session.digestUpdate(suffix);
      }
    } finally {
      digest = session.digestFinal();
    }
    return digest;
  }

  byte[] sign(CkMechanism mechanism, long hKey, byte[] data, int maxSize)
      throws TokenException {
    int len = data.length;
    boolean useMulti = len > maxMessageSize
            && slot.supportsMultipart(mechanism, CKF_SIGN);

    byte[] sig;
    if (!useMulti) {
      sig = session.signSingle(mechanism, hKey, data, maxSize);
    } else {
      opInit(OP.SIGN, session, mechanism, hKey);

      try {
        for (int ofs = 0; ofs < len; ofs += maxMessageSize) {
          session.signUpdate(data, ofs, Math.min(maxMessageSize, len - ofs));
        }
      } finally {
        sig = session.signFinal(maxSize);
      }
    }

    return sig;
  }

  long generateKey(CkMechanism mechanism, Template template)
      throws TokenException {
    return session.generateKey(mechanism, template);
  }

  PKCS11KeyPair generateKeyPair(
      CkMechanism mechanism, KeyPairTemplate template)
      throws TokenException {
    return session.generateKeyPair(mechanism, template);
  }

  /**
   * Gets give attributes for the given object handle.
   *
   * @param hObject
   *        the object handle.
   * @param attributeTypes
   *        types of attributes to be read.
   * @return attributes for the given object handle.
   * @throws TokenException
   *         if getting attributes failed.
   */
  Template getAttrValues(long hObject, AttributeTypes attributeTypes)
      throws TokenException {
    return session.getAttrValues(hObject, attributeTypes);
  }

  Template getDefaultAttrValues(long hObject)
      throws TokenException {
    return session.getDefaultAttrValues(hObject);
  }

  private void opInit(OP op, Session session, CkMechanism mechanism,
                      long hKey)
      throws TokenException {
    switch (op) {
      case SIGN:
        session.signInit(mechanism, hKey);
        break;
      case DIGEST:
        session.digestInit(mechanism);
        break;
      default:
        throw new IllegalStateException("unknown OP " + op);
    }
  }

  /* ***************************************
   * PKCS#11 V3.0 Functions
   * ***************************************/
  void loginSo(byte[] userName, byte[] pin)
      throws TokenException {
    session.loginUser(CKU_SO, userName, pin == null ? new byte[0] : pin);
    LOG.info("login CKU_SO with userName");
  }

  /**
   * terminates active session based operations.
   *
   * @throws PKCS11Exception If terminating operations failed
   */
  void sessionCancel(long flags) throws PKCS11Exception {
    session.sessionCancel(flags);
  }

  /* ***************************************
   * PKCS#11 V3.2 Functions
   * ***************************************/

  long decapsulateKey(CkMechanism mechanism, long hPrivateKey,
                      byte[] encapsulatedKey, Template template)
      throws TokenException {
    return session.decapsulateKey(mechanism, hPrivateKey,
        encapsulatedKey, template);
  }

}
