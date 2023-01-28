/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security.pkcs11;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.*;
import org.xipki.security.EdECConstants;
import org.xipki.security.pkcs11.P11ModuleConf.P11MechanismFilter;
import org.xipki.security.pkcs11.P11ModuleConf.P11NewObjectConf;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.concurrent.ConcurrentBag;
import org.xipki.util.concurrent.ConcurrentBagEntry;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.xipki.pkcs11.AttributeVector.*;
import static org.xipki.pkcs11.PKCS11Constants.*;
import static org.xipki.security.pkcs11.NativeP11SlotUtil.*;
import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.positive;
import static org.xipki.util.CollectionUtil.isEmpty;
import static org.xipki.util.CollectionUtil.isNotEmpty;

/**
 * {@link P11Slot} based on the ipkcs11wrapper or jpkcs11wrapper.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
class NativeP11Slot extends P11Slot {

  public static final AlgorithmIdentifier ALGID_RSA = new AlgorithmIdentifier(
      PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);

  private static final Logger LOG = LoggerFactory.getLogger(NativeP11Slot.class);

  private static final long DEFAULT_MAX_COUNT_SESSION = 32;

  private final int maxMessageSize;

  private Slot slot;

  private final long userType;

  private List<char[]> password;

  private final int maxSessionCount;

  private final long timeOutWaitNewSession = 10000; // maximal wait for 10 second

  private final AtomicLong countSessions = new AtomicLong(0);

  private final SecureRandom random = new SecureRandom();

  private final ConcurrentBag<ConcurrentBagEntry<Session>> sessions = new ConcurrentBag<>();

  private final long rsaKeyPairGenMech;

  private String libDesc;

  NativeP11Slot(String moduleName, P11SlotId slotId, Slot slot, boolean readOnly, long userType,
                List<char[]> password, int maxMessageSize, P11MechanismFilter mechanismFilter,
                P11NewObjectConf newObjectConf, Integer numSessions, List<Long> secretKeyTypes, List<Long> keyPairTypes)
      throws TokenException {
    super(moduleName, slotId, readOnly, secretKeyTypes, keyPairTypes, newObjectConf);

    this.slot = notNull(slot, "slot");
    this.maxMessageSize = positive(maxMessageSize, "maxMessageSize");

    this.userType = userType;
    this.password = password;

    boolean successful = false;

    ModuleInfo moduleInfo = slot.getModule().getInfo();
    libDesc = moduleInfo.getLibraryDescription();
    if (libDesc == null) {
      libDesc = "";
    }

    initMechanisms(getSupportedMechanisms(), mechanismFilter);

    try {
      Session session = openSession();

      firstLogin(session, password);

      Token token = this.slot.getToken();

      long maxSessionCount2 = token.getTokenInfo().getMaxSessionCount();

      maxSessionCount2 = (maxSessionCount2 <= 0) ? DEFAULT_MAX_COUNT_SESSION
          : (maxSessionCount2 < 3) ? 1 : maxSessionCount2 - 2; // 2 sessions as buffer, they may be used elsewhere.

      if (numSessions != null) {
        maxSessionCount2 = Math.min(numSessions, maxSessionCount2);
      }

      this.maxSessionCount = (int) maxSessionCount2;
      LOG.info("maxSessionCount: {}", this.maxSessionCount);

      sessions.add(new ConcurrentBagEntry<>(session));

      rsaKeyPairGenMech = supportsMechanism(CKM_RSA_X9_31_KEY_PAIR_GEN)
          ? CKM_RSA_X9_31_KEY_PAIR_GEN : CKM_RSA_PKCS_KEY_PAIR_GEN;

      successful = true;
    } finally {
      if (!successful) {
        close();
      }
    }
  } // constructor

  private long[] getSupportedMechanisms() throws TokenException {
    long[] mechanisms = slot.getToken().getMechanismList();

    List<Long> newList = new ArrayList<>(mechanisms.length);

    StringBuilder ignoreMechs = new StringBuilder();
    boolean smartcard = libDesc.toLowerCase().contains("smartcard");
    for (long code : mechanisms) {
      if (smartcard) {
        if (code == CKM_ECDSA_SHA1     || code == CKM_ECDSA_SHA224   || code == CKM_ECDSA_SHA256 ||
            code == CKM_ECDSA_SHA384   || code == CKM_ECDSA_SHA512   || code == CKM_ECDSA_SHA3_224 ||
            code == CKM_ECDSA_SHA3_256 || code == CKM_ECDSA_SHA3_384 || code == CKM_ECDSA_SHA3_512) {
          ignoreMechs.append(ckmCodeToName(code)).append(", ");
        } else {
          newList.add(code);
        }
      } else {
        newList.add(code);
      }
    }

    if (ignoreMechs.length() > 0) {
      LOG.info("Ignore mechanisms in smartcard-based HSM: {}", ignoreMechs.substring(0, ignoreMechs.length() - 2));
    }

    if (ignoreMechs.length() == 0) {
      return mechanisms;
    } else {
      long[] ret = new long[newList.size()];
      int i = 0;
      for (Long mech : newList) {
        ret[i++] = mech;
      }
      return ret;
    }
  } // method getSupportedMechanisms()

  @Override
  public final void close() {
    if (slot != null) {
      try {
        LOG.info("close all sessions on token: {}", slot.getSlotID());

        for (ConcurrentBagEntry<Session> session : sessions.values()) {
          session.value().closeSession();
        }
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "could not slot.getToken().closeAllSessions()");
      }

      slot = null;
    }

    // clear the session pool
    sessions.close();
    countSessions.lazySet(0);
  } // method close

  byte[] digestSecretKey(long mech, NativeP11Identity identity) throws TokenException {
    if (!identity.isSecretKey()) {
      throw new TokenException("digestSecretKey could not be applied to non-SecretKey");
    }

    long keyHandle = notNull(identity, "identity").getId().getKeyId().getHandle();
    assertMechanismSupported(mech);

    if (LOG.isTraceEnabled()) {
      LOG.debug("digest (init, digestKey, then finish) secret key {}", identity.getId());
    }

    int digestLen = (CKM_SHA_1 == mech) ? 20
        : (CKM_SHA224 == mech || CKM_SHA3_224 == mech) ? 28
        : (CKM_SHA256 == mech || CKM_SHA3_256 == mech) ? 32
        : (CKM_SHA384 == mech || CKM_SHA3_384 == mech) ? 48
        : (CKM_SHA512 == mech || CKM_SHA3_512 == mech) ? 64 : -1;

    if (digestLen == -1) throw new TokenException("unsupported mechanism " + mech);

    ConcurrentBagEntry<Session> session0 = borrowSession();
    Mechanism mechanismObj = new Mechanism(mech);

    try {
      Session session = session0.value();
      try {
        return NativeP11SlotUtil.digestKey(session, digestLen, mechanismObj, keyHandle);
      } catch (PKCS11Exception ex) {
        if (ex.getErrorCode() != CKR_USER_NOT_LOGGED_IN) {
          throw ex;
        }

        LOG.info("digestKey ended with ERROR CKR_USER_NOT_LOGGED_IN, login and then retry it");
        // force the login
        forceLogin(session);
        return NativeP11SlotUtil.digestKey(session, digestLen, mechanismObj, keyHandle);
      }
    } finally {
      sessions.requite(session0);
    }
  } // method digestKey

  byte[] sign(long mech, P11Params parameters, byte[] content, NativeP11Identity identity) throws TokenException {
    notNull(content, "content");
    assertMechanismSupported(mech);

    Mechanism mechanismObj = getMechanism(mech, parameters);
    long signingKeyHandle = identity.getId().getKeyId().getHandle();

    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return sign0(session, mechanismObj, content, signingKeyHandle);
    } catch (PKCS11Exception ex) {
      if (ex.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        LOG.info("sign ended with ERROR CKR_USER_NOT_LOGGED_IN, login and then retry it");
        // force the login
        forceLogin(session);
        return sign0(session, mechanismObj, content, signingKeyHandle);
      } else {
        throw ex;
      }
    } finally {
      sessions.requite(session0);
    }
  } // method sign

  private byte[] sign0(Session session, Mechanism mechanism, byte[] content, long signingKeyHandle)
      throws PKCS11Exception {
    int len = content.length;

    byte[] sigvalue;
    if (len <= maxMessageSize) {
      sigvalue = singleSign(session, mechanism, content, signingKeyHandle);
    } else {
      LOG.debug("sign (init, update, then finish)");
      session.signInit(mechanism, signingKeyHandle);

      for (int i = 0; i < len; i += maxMessageSize) {
        int blockLen = Math.min(maxMessageSize, len - i);
        session.signUpdate(content, i, blockLen);
      }

      sigvalue = session.signFinal();
    }

    return sigvalue;
  } // method sign0

  private byte[] singleSign(Session session, Mechanism mechanism, byte[] content, long signingKeyHandle)
      throws PKCS11Exception {
    LOG.debug("single sign");
    session.signInit(mechanism, signingKeyHandle);
    return session.sign(content);
  } // method singleSign

  private Session openSession() throws TokenException {
    Session session = slot.getToken().openSession(!isReadOnly());
    countSessions.incrementAndGet();
    return session;
  } // method openSession

  private ConcurrentBagEntry<Session> borrowSession() throws TokenException {
    ConcurrentBagEntry<Session> session = null;
    synchronized (sessions) {
      if (countSessions.get() < maxSessionCount) {
        try {
          session = sessions.borrow(1, TimeUnit.NANOSECONDS);
        } catch (InterruptedException ex) {
        }

        if (session == null) {
          // create new session
          sessions.add(new ConcurrentBagEntry<>(openSession()));
        }
      }
    }

    if (session == null) {
      try {
        session = sessions.borrow(timeOutWaitNewSession, TimeUnit.MILLISECONDS);
      } catch (InterruptedException ex) {
      }
    }

    if (session == null) {
      throw new TokenException("no idle session");
    }

    login(session.value());
    return session;
  } // method borrowSession

  private void firstLogin(Session session, List<char[]> password) throws TokenException {
    try {
      boolean isProtectedAuthenticationPath = session.getToken().getTokenInfo().isProtectedAuthenticationPath();

      if (isProtectedAuthenticationPath || isEmpty(password)) {
        LOG.info("verify on PKCS11Module with PROTECTED_AUTHENTICATION_PATH");
        singleLogin(session, userType, null);
      } else {
        LOG.info("verify on PKCS11Module with PIN");
        for (char[] singlePwd : password) {
          singleLogin(session, userType, singlePwd);
        }
        this.password = password;
      }
    } catch (PKCS11Exception ex) {
      if (ex.getErrorCode() != CKR_USER_ALREADY_LOGGED_IN) {
        throw ex;
      }
    }
  } // method firstLogin

  private void login(Session session) throws TokenException {
    boolean isSessionLoggedIn = checkSessionLoggedIn(session, userType);
    if (isSessionLoggedIn) {
      return;
    }

    boolean loginRequired;
    try {
      loginRequired = session.getToken().getTokenInfo().isLoginRequired();
    } catch (PKCS11Exception ex) {
      LogUtil.error(LOG, ex, "could not check isLoginRequired of token");
      loginRequired = true;
    }

    LOG.debug("loginRequired: {}", loginRequired);
    if (!loginRequired) {
      return;
    }

    if (isEmpty(password)) {
      singleLogin(session, userType, null);
    } else {
      for (char[] singlePwd : password) {
        singleLogin(session, userType, singlePwd);
      }
    }
  } // method login

  private void forceLogin(Session session) throws TokenException {
    if (isEmpty(password)) {
      LOG.info("verify on PKCS11Module with NULL PIN");
      singleLogin(session, userType, null);
    } else {
      LOG.info("verify on PKCS11Module with PIN");
      for (char[] singlePwd : password) {
        singleLogin(session, userType, singlePwd);
      }
    }
  } // method forceLogin

  @Override
  public P11Identity getIdentity(P11IdentityId identityId) throws TokenException {
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();
      long handle = identityId.getKeyId().getHandle();

      AttributeVector attrs = session.getAttrValues(handle, CKA_CLASS, CKA_KEY_TYPE);
      long keyType = attrs.keyType();
      long objClass = attrs.class_();
      NativeP11Identity p11Identity = new NativeP11Identity(this, identityId);
      if (objClass == CKO_PRIVATE_KEY) {
        if (keyType == CKK_RSA) {
          attrs = session.getAttrValues(handle, CKA_MODULUS, CKA_PUBLIC_EXPONENT);
          p11Identity.setRsaMParameters(attrs.modulus(), attrs.publicExponent());
        } else if (keyType == CKK_DSA) {
          p11Identity.setDsaQ(session.getBigIntAttrValue(handle, CKA_SUBPRIME));
        } else if (keyType == CKK_EC || keyType == CKK_VENDOR_SM2
            || keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
          byte[] ecParams = session.getByteArrayAttrValue(handle, CKA_EC_PARAMS);
          ASN1ObjectIdentifier curveId = detectCurveOid(ecParams);

          // try the public key
          if (curveId == null && identityId.getPublicKeyHandle() != null) {
            ecParams = session.getByteArrayAttrValue(identityId.getPublicKeyHandle(), CKA_EC_PARAMS);
            curveId = detectCurveOid(ecParams);
          }

          if (curveId != null) {
            p11Identity.setEcParams(curveId);
          }
        } else {
          throw new IllegalStateException("unknown key type " + ckkCodeToName(keyType));
        }
      } else {
        // should not reach here
        throw new IllegalStateException("unknown object class " + ckoCodeToName(objClass));
      }

      return p11Identity;
    } finally {
      sessions.requite(bagEntry);
    }
  }

  @Override
  protected PublicKey getPublicKey(P11Identity identity) throws TokenException {
    Long publicKeyHandle = identity.getId().getPublicKeyHandle();
    if (publicKeyHandle == null) {
      return null;
    }

    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      long keyType = identity.getKeyType();
      Session session = bagEntry.value();
      if (keyType == CKK_RSA) {
        return buildRSAKey(identity.getRsaModulus(), identity.getRsaPublicExponent());
      } else if (keyType == CKK_DSA) {
        BigInteger q = identity.getDsaQ();
        AttributeVector attrs = session.getAttrValues(publicKeyHandle, CKA_PRIME, CKA_VALUE, CKA_BASE);
        DSAPublicKeySpec keySpec = new DSAPublicKeySpec(
            new BigInteger(1, attrs.value()), attrs.prime(), q, attrs.base());
        try {
          return KeyUtil.generateDSAPublicKey(keySpec);
        } catch (InvalidKeySpecException ex) {
          throw new TokenException(ex.getMessage(), ex);
        }
      } else if (keyType == CKK_EC || keyType == CKK_VENDOR_SM2
          || keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
        byte[] ecPoint = session.getByteArrayAttrValue(publicKeyHandle, CKA_EC_POINT);
        ASN1ObjectIdentifier curveOid = identity.getEcParams();
        byte[] encodedPoint = DEROctetString.getInstance(ecPoint).getOctets();

        if (keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
          if (keyType == CKK_EC_EDWARDS) {
            if (!EdECConstants.isEdwardsCurve(curveOid)) {
              throw new TokenException("unknown Edwards curve OID " + curveOid);
            }
          } else {
            if (!EdECConstants.isMontgomeryCurve(curveOid)) {
              throw new TokenException("unknown Montgomery curve OID " + curveOid);
            }
          }
          SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(curveOid), encodedPoint);
          try {
            return KeyUtil.generatePublicKey(pkInfo);
          } catch (InvalidKeySpecException ex) {
            throw new TokenException(ex.getMessage(), ex);
          }
        } else {
          try {
            return KeyUtil.createECPublicKey(curveOid, encodedPoint);
          } catch (InvalidKeySpecException ex) {
            throw new TokenException(ex.getMessage(), ex);
          }
        }
      } else {
        throw new TokenException("unknown key type " + ckkCodeToName(keyType));
      }
    } finally {
      sessions.requite(bagEntry);
    }
  }

  @Override
  public boolean objectExistsByIdLabel(byte[] id, String label) throws TokenException {
    if ((id == null || id.length == 0) && StringUtil.isBlank(label)) {
      return false;
    }

    AttributeVector template = new AttributeVector();
    if (id != null && id.length > 0) {
      template.id(id);
    }

    if (!StringUtil.isBlank(label)) {
      template.label(label);
    }

    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();
      return !getObjects(session, template, 1).isEmpty();
    } finally {
      sessions.requite(bagEntry);
    }
  }

  @Override
  public long[] destroyObjectsByHandle(long[] handles) {
    ConcurrentBagEntry<Session> bagEntry = null;
    List<Long> destroyedHandles = new ArrayList<>(handles.length);
    try {
      bagEntry = borrowSession();
      for (long handle : handles) {
        try {
          bagEntry.value().destroyObject(handle);
          destroyedHandles.add(handle);
        } catch (PKCS11Exception e) {
          LOG.warn("error destroying object with handle " + handle + ": " + e.getMessage());
        }
      }
    } catch (TokenException e) {
      LogUtil.warn(LOG, e, "error borrowSession()");
    } finally {
      if (bagEntry != null) {
        sessions.requite(bagEntry);
      }
    }

    if (handles.length == destroyedHandles.size()) {
      return new long[0];
    }

    long[] failedHandles = new long[handles.length - destroyedHandles.size()];
    int index = 0;
    for (long handle : handles) {
      if (!destroyedHandles.contains(handle)) {
        failedHandles[index++] = handle;
      }
    }
    return failedHandles;
  }

  @Override
  public int destroyObjectsByIdLabel(byte[] id, String label) throws TokenException {
    if ((id == null || id.length == 0) && StringUtil.isBlank(label)) {
      throw new IllegalArgumentException("at least one of id and label may not be null");
    }

    AttributeVector template = new AttributeVector();
    if (id != null && id.length > 0) {
      template.id(id);
    }

    if (label != null && !label.isEmpty()) {
      template.label(label);
    }

    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      String objIdDesc = getDescription(id, label);
      return removeObjects0(bagEntry.value(), template, "objects " + objIdDesc);
    } finally {
      sessions.requite(bagEntry);
    }
  } // method removeObjects

  @Override
  protected P11IdentityId doGenerateSecretKey(long keyType, Integer keysize, P11NewKeyControl control)
      throws TokenException {
    if (keysize != null && keysize % 8 != 0) {
      throw new IllegalArgumentException("keysize is not multiple of 8: " + keysize);
    }

    boolean hasValueLen = true;
    long mech;
    if (CKK_AES == keyType) {
      mech = CKM_AES_KEY_GEN;
    } else if (CKK_DES3 == keyType) {
      mech = CKM_DES3_KEY_GEN;
      hasValueLen = false;
    } else if (CKK_GENERIC_SECRET == keyType) {
      mech = CKM_GENERIC_SECRET_KEY_GEN;
    } else if (CKK_SHA_1_HMAC == keyType || CKK_SHA224_HMAC   == keyType || CKK_SHA256_HMAC == keyType
        || CKK_SHA384_HMAC   == keyType  || CKK_SHA512_HMAC   == keyType || CKK_SHA3_224_HMAC == keyType
        || CKK_SHA3_256_HMAC == keyType  || CKK_SHA3_384_HMAC == keyType || CKK_SHA3_512_HMAC == keyType) {
      mech = CKM_GENERIC_SECRET_KEY_GEN;
    } else {
      throw new IllegalArgumentException("unsupported key type 0x" + codeToName(Category.CKK, keyType));
    }

    assertMechanismSupported(mech);

    String label;
    if (newObjectConf.isIgnoreLabel()) {
      if (control.getLabel() != null) {
        LOG.warn("label is set, but ignored: '{}'", control.getLabel());
      }
      label = null;
    } else {
      label = control.getLabel();
    }

    byte[] id = control.getId();

    AttributeVector template = newSecretKey(keyType);
    NativeP11SlotUtil.setKeyAttributes(control, template, label);
    if (hasValueLen) {
      if (keysize == null) {
        throw new IllegalArgumentException("keysize must not be null");
      }
      template.valueLen(keysize / 8);
    }

    Mechanism mechanism = new Mechanism(mech);
    long keyHandle;
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();
      if (label != null && labelExists(session, label)) {
        throw new IllegalArgumentException("label " + control.getLabel() + " exists, please specify another one");
      }

      if (id == null) {
        id = generateId(session);
      }

      template.id(id);
      keyHandle = session.generateKey(mechanism, template);
      label = session.getCkaLabel(keyHandle);

      return new P11IdentityId(slotId, new P11ObjectId(keyHandle, CKO_SECRET_KEY, keyType, id, label), null);
    } finally {
      sessions.requite(bagEntry);
    }
  } // method generateSecretKey0

  @Override
  protected P11IdentityId doImportSecretKey(long keyType, byte[] keyValue, P11NewKeyControl control)
      throws TokenException {
    AttributeVector template = newSecretKey(keyType);
    String label;
    if (newObjectConf.isIgnoreLabel()) {
      if (control.getLabel() != null) {
        LOG.warn("label is set, but ignored: '{}'", control.getLabel());
      }
      label = null;
    } else {
      label = control.getLabel();
    }

    NativeP11SlotUtil.setKeyAttributes(control, template, label);
    template.value(keyValue);

    long keyHandle;
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();
      if (label != null && labelExists(session, label)) {
        throw new IllegalArgumentException("label " + control.getLabel() + " exists, please specify another one");
      }

      byte[] id = control.getId();
      if (id == null) {
        id = generateId(session);
      }

      template.id(id);
      keyHandle = session.createObject(template);

      try {
        label = session.getCkaLabel(keyHandle);
      } catch (PKCS11Exception e) {
      }

      return new P11IdentityId(slotId, new P11ObjectId(keyHandle, CKO_SECRET_KEY, keyType, id, label), null);
    } finally {
      sessions.requite(bagEntry);
    }
  } // method importSecretKey0

  @Override
  protected P11IdentityId doGenerateRSAKeypair(int keysize, BigInteger publicExponent, P11NewKeyControl control)
      throws TokenException {
    AttributeVector privateKey = newPrivateKey(CKK_RSA);
    AttributeVector publicKey = newPublicKey(CKK_RSA).modulusBits(keysize);
    if (publicExponent != null) {
      publicKey.publicExponent(publicExponent);
    }
    setKeyAttributes(control, publicKey, privateKey, newObjectConf);

    return doGenerateKeyPair(rsaKeyPairGenMech, control.getId(), privateKey, publicKey);
  } // method generateRSAKeypair0

  @Override
  protected PrivateKeyInfo doGenerateRSAKeypairOtf(int keysize, BigInteger publicExponent)
      throws TokenException {
    AttributeVector publicKeyTemplate = newPublicKey(CKK_RSA).modulusBits(keysize);
    if (publicExponent != null) {
      publicKeyTemplate.publicExponent(publicExponent);
    }

    AttributeVector privateKeyTemplate = newPrivateKey(CKK_RSA);
    setPrivateKeyAttrsOtf(privateKeyTemplate);

    long mech = rsaKeyPairGenMech;
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();

      PKCS11KeyPair keypair = null;
      try {
        keypair = session.generateKeyPair(new Mechanism(mech), publicKeyTemplate, privateKeyTemplate);
        AttributeVector attrs = session.getAttrValues(keypair.getPrivateKey(), CKA_MODULUS, CKA_PUBLIC_EXPONENT,
            CKA_PRIVATE_EXPONENT, CKA_PRIME_1, CKA_PRIME_2, CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT);

        return new PrivateKeyInfo(ALGID_RSA,
            new org.bouncycastle.asn1.pkcs.RSAPrivateKey(
                attrs.modulus(), attrs.publicExponent(), attrs.privateExponent(),
                attrs.prime1(), attrs.prime2(), attrs.exponent1(), attrs.exponent2(), attrs.coefficient()));

      } catch (PKCS11Exception | IOException ex) {
        throw new TokenException("could not generate keypair " + ckmCodeToName(mech), ex);
      } finally {
        destroyKeyPairQuietly(session, keypair);
      }
    } finally {
      sessions.requite(bagEntry);
    }
  } // method generateRSAKeypairOtf0

  @Override
  protected P11IdentityId doGenerateDSAKeypair(BigInteger p, BigInteger q, BigInteger g, P11NewKeyControl control)
      throws TokenException {
    AttributeVector privateKey = newDSAPrivateKey();
    AttributeVector publicKey = newDSAPublicKey().prime(p).subprime(q).base(g);
    setKeyAttributes(control, publicKey, privateKey, newObjectConf);

    return doGenerateKeyPair(CKM_DSA_KEY_PAIR_GEN, control.getId(), privateKey, publicKey);
  }

  @Override
  protected PrivateKeyInfo generateDSAKeypairOtf0(BigInteger p, BigInteger q, BigInteger g) throws TokenException {
    AttributeVector priKeyTemplate = newDSAPrivateKey();
    setPrivateKeyAttrsOtf(priKeyTemplate);

    AttributeVector pubKeyTemplate = newDSAPublicKey().prime(p).subprime(q).base(g);

    long mech = CKM_DSA_KEY_PAIR_GEN;
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();

      PKCS11KeyPair keypair = null;
      try {
        DSAParameter parameter = new DSAParameter(p, q, g);
        AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, parameter);

        keypair = session.generateKeyPair(new Mechanism(mech), pubKeyTemplate, priKeyTemplate);
        long skHandle = keypair.getPrivateKey();
        long pkHandle = keypair.getPublicKey();

        BigInteger p11PublicKeyValue = session.getBigIntAttrValue(pkHandle, CKA_VALUE);
        BigInteger p11PrivateKeyValue = session.getBigIntAttrValue(skHandle, CKA_VALUE);

        byte[] publicKey = new ASN1Integer(p11PublicKeyValue).getEncoded(); // y

        return new PrivateKeyInfo(algId, new ASN1Integer(p11PrivateKeyValue), null, publicKey);
      } catch (PKCS11Exception | IOException ex) {
        throw new TokenException("could not generate keypair " + ckmCodeToName(mech), ex);
      } finally {
        destroyKeyPairQuietly(session, keypair);
      }
    } finally {
      sessions.requite(bagEntry);
    }
  }

  @Override
  protected P11IdentityId doGenerateECEdwardsKeypair(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws TokenException {
    AttributeVector privKeyTemplate = newPrivateKey(CKK_EC_EDWARDS);
    AttributeVector pubKeyTemplate = newPublicKey(CKK_EC_EDWARDS);
    setKeyAttributes(control, pubKeyTemplate, privKeyTemplate, newObjectConf);
    byte[] encodedCurveId;
    try {
      encodedCurveId = curveId.getEncoded();
    } catch (IOException ex) {
      throw new TokenException(ex.getMessage(), ex);
    }
    pubKeyTemplate.ecParams(encodedCurveId);
    return doGenerateKeyPair(CKM_EC_EDWARDS_KEY_PAIR_GEN, control.getId(), privKeyTemplate, pubKeyTemplate);
  } // method generateECEdwardsKeypair0

  @Override
  protected PrivateKeyInfo doGenerateECEdwardsKeypairOtf(ASN1ObjectIdentifier curveId) throws TokenException {
    return doGenerateECKeypairOtf(CKK_EC_EDWARDS, CKM_EC_EDWARDS_KEY_PAIR_GEN, curveId);
  }

  @Override
  protected P11IdentityId doGenerateECMontgomeryKeypair(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws TokenException {
    AttributeVector privateKey = newPrivateKey(CKK_EC_MONTGOMERY);
    AttributeVector publicKey = newPublicKey(CKK_EC_MONTGOMERY);
    setKeyAttributes(control, publicKey, privateKey, newObjectConf);
    try {
      publicKey.ecParams(curveId.getEncoded());
    } catch (IOException ex) {
      throw new TokenException(ex.getMessage(), ex);
    }

    return doGenerateKeyPair(CKM_EC_MONTGOMERY_KEY_PAIR_GEN, control.getId(), privateKey, publicKey);
  } // method generateECMontgomeryKeypair0

  @Override
  protected PrivateKeyInfo doGenerateECMontgomeryKeypairOtf(ASN1ObjectIdentifier curveId) throws TokenException {
    return doGenerateECKeypairOtf(CKK_EC_MONTGOMERY, CKM_EC_MONTGOMERY_KEY_PAIR_GEN, curveId);
  }

  @Override
  protected P11IdentityId doGenerateECKeypair(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws TokenException {
    AttributeVector privateKey = newPrivateKey(CKK_EC);
    AttributeVector publicKey = newPublicKey(CKK_EC);
    setKeyAttributes(control, publicKey, privateKey, newObjectConf);
    byte[] encodedCurveId;
    try {
      encodedCurveId = curveId.getEncoded();
    } catch (IOException ex) {
      throw new TokenException(ex.getMessage(), ex);
    }

    publicKey.ecParams(encodedCurveId);
    return doGenerateKeyPair(CKM_EC_KEY_PAIR_GEN, control.getId(), privateKey, publicKey);
  } // method generateECKeypair0

  @Override
  protected PrivateKeyInfo doGenerateECKeypairOtf(ASN1ObjectIdentifier curveId) throws TokenException {
    return doGenerateECKeypairOtf(CKK_EC, CKM_EC_KEY_PAIR_GEN, curveId);
  }

  private PrivateKeyInfo doGenerateECKeypairOtf(long keyType, long mech, ASN1ObjectIdentifier curveId)
      throws TokenException {
    if (keyType == CKK_VENDOR_SM2) {
      if (!GMObjectIdentifiers.sm2p256v1.equals(curveId)) {
        throw new TokenException("keyType and curveId do not match.");
      }
    }

    AttributeVector privateKeyTemplate = newPrivateKey(keyType);
    setPrivateKeyAttrsOtf(privateKeyTemplate);

    AttributeVector publicKeyTemplate = newPublicKey(keyType);
    try {
      publicKeyTemplate.ecParams(curveId.getEncoded());
    } catch (IOException ex) {
      throw new TokenException(ex.getMessage(), ex);
    }

    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();

      PKCS11KeyPair keypair = null;
      try {
        keypair = session.generateKeyPair(new Mechanism(mech), publicKeyTemplate, privateKeyTemplate);

        byte[] ecPoint = session.getByteArrayAttrValue(keypair.getPublicKey(), CKA_EC_POINT);
        byte[] encodedPublicPoint = DEROctetString.getInstance(ecPoint).getOctets();

        byte[] privValue = session.getByteArrayAttrValue(keypair.getPrivateKey(), CKA_VALUE);

        if (CKK_EC_EDWARDS == keyType || CKK_EC_MONTGOMERY == keyType) {
          AlgorithmIdentifier algId = new AlgorithmIdentifier(curveId);
          return new PrivateKeyInfo(algId, new DEROctetString(privValue), null, encodedPublicPoint);
        } else {
          AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curveId);

          if (encodedPublicPoint[0] != 4) {
            throw new TokenException("EcPoint does not start with 0x04");
          }

          int orderBigLen = (encodedPublicPoint.length - 1) / 2 * 8;
          return new PrivateKeyInfo(algId,
              new org.bouncycastle.asn1.sec.ECPrivateKey(orderBigLen,
                  new BigInteger(1, privValue), new DERBitString(encodedPublicPoint), null));
        }
      } catch (PKCS11Exception | IOException ex) {
        throw new TokenException("could not generate keypair " + ckmCodeToName(mech), ex);
      } finally {
        destroyKeyPairQuietly(session, keypair);
      }
    } finally {
      sessions.requite(bagEntry);
    }

  }

  @Override
  protected P11IdentityId doGenerateSM2Keypair(P11NewKeyControl control) throws TokenException {
    long ckm = CKM_VENDOR_SM2_KEY_PAIR_GEN;
    if (supportsMechanism(ckm)) {
      AttributeVector privateKey = newPrivateKey(CKK_VENDOR_SM2);
      AttributeVector publicKey = newPublicKey(CKK_VENDOR_SM2);
      publicKey.ecParams(Hex.decode("06082A811CCF5501822D"));
      setKeyAttributes(control, publicKey, privateKey, newObjectConf);

      return doGenerateKeyPair(ckm, control.getId(), privateKey, publicKey);
    } else {
      return doGenerateECKeypair(GMObjectIdentifiers.sm2p256v1, control);
    }
  } // method generateSM2Keypair0

  @Override
  protected PrivateKeyInfo doGenerateSM2KeypairOtf() throws TokenException {
    long ckm = CKM_VENDOR_SM2_KEY_PAIR_GEN;

    return supportsMechanism(ckm)
        ? doGenerateECKeypairOtf(CKK_VENDOR_SM2, ckm, GMObjectIdentifiers.sm2p256v1)
        : doGenerateECKeypairOtf(GMObjectIdentifiers.sm2p256v1);
  }

  private P11IdentityId doGenerateKeyPair(
      long mech, byte[] id, AttributeVector privateKeyTemplate, AttributeVector publicKeyTemplate)
      throws TokenException {
    long keyType = privateKeyTemplate.keyType();
    String label = privateKeyTemplate.label();

    boolean succ = false;

    try {
      PKCS11KeyPair keypair;
      ConcurrentBagEntry<Session> bagEntry = borrowSession();
      try {
        Session session = bagEntry.value();
        if (label != null && labelExists(session, label)) {
          throw new IllegalArgumentException("label " + label + " exists, please specify another one");
        }

        if (id == null) {
          id = generateId(session);
        }

        privateKeyTemplate.id(id);
        publicKeyTemplate.id(id);

        try {
          keypair = session.generateKeyPair(new Mechanism(mech), publicKeyTemplate, privateKeyTemplate);
        } catch (PKCS11Exception ex) {
          throw new TokenException("could not generate keypair " + ckmCodeToName(mech), ex);
        }

        P11IdentityId ret = new P11IdentityId(slotId,
            new P11ObjectId(keypair.getPrivateKey(), CKO_PRIVATE_KEY, keyType, id, label), keypair.getPublicKey());
        succ = true;
        return ret;
      } finally {
        sessions.requite(bagEntry);
      }
    } finally {
      if (!succ && (id != null)) {
        try {
          destroyObjectsByIdLabel(id, label);
        } catch (Throwable th) {
          LogUtil.error(LOG, th, "could not remove objects");
        }
      }
    }
  }

  @Override
  public P11IdentityId getIdentityId(byte[] keyId, String keyLabel) throws TokenException {
    if ((keyId == null || keyId.length == 0) && StringUtil.isBlank(keyLabel)) {
      return null;
    }

    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();

      if (keyId == null) {
        AttributeVector template = new AttributeVector().label(keyLabel);

        long objClass = CKO_PRIVATE_KEY;
        List<Long> objHandles = getObjects(session, template.class_(objClass), 2);
        if (objHandles.isEmpty()) {
          objClass = CKO_SECRET_KEY;
          objHandles = getObjects(session, template.class_(objClass), 2);
        }

        if (objHandles.isEmpty()) {
          return null;
        } else if (objHandles.size() > 1) {
          throw new TokenException("found more than 1 " + ckkCodeToName(objClass).substring(4) +
              " with label=" + keyLabel);
        }

        long keyHandle = objHandles.get(0);
        AttributeVector attrs = session.getAttrValues(keyHandle, CKA_ID, CKA_KEY_TYPE);
        long keyType = attrs.keyType();
        keyId = attrs.id();

        P11ObjectId secretOrPrivKeyId = new P11ObjectId(keyHandle, objClass, keyType, keyId, keyLabel);

        Long publicKeyHandle = null;
        if (objClass == CKO_PRIVATE_KEY) {
          if (keyId == null) {
            List<Long> handles = getObjects(session, AttributeVector.newPublicKey().label(keyLabel), 2);
            if (handles.size() > 1) {
              LOG.warn("found more than 1 public key with label={}, ignore them", keyLabel);
            } else if (handles.size() == 1){
              publicKeyHandle = handles.get(0);
            }
          } else {
            List<Long> handles = getObjects(session, AttributeVector.newPublicKey().id(keyId), 2);
            if (handles.size() > 1) {
              LOG.warn("found more than 1 public key with id={}, ignore them", Hex.encode(keyId));
            } else if (handles.size() == 1){
              publicKeyHandle = handles.get(0);
            }
          }
        }

        return new P11IdentityId(slotId, secretOrPrivKeyId, publicKeyHandle);
      } else {
        // keyId != null
        AttributeVector template = new AttributeVector().id(keyId);
        if (keyLabel != null) {
          template.label(keyLabel);
        }

        long objClass = CKO_PRIVATE_KEY;
        List<Long> objHandles = getObjects(session, template.class_(objClass), 2);
        if (objHandles.isEmpty()) {
          objClass = CKO_SECRET_KEY;
          objHandles = getObjects(session, template.class_(objClass), 2);
        }

        if (objHandles.isEmpty()) {
          return null;
        } else if (objHandles.size() > 1) {
          throw new TokenException("found more than 1 " + ckoCodeToName(objClass).substring(4) +
              " with " + getDescription(keyId, keyLabel));
        }

        long keyHandle = objHandles.get(0);
        AttributeVector attrs;
        if (keyLabel == null) {
          attrs = session.getAttrValues(keyHandle, CKA_KEY_TYPE, CKA_LABEL);
          keyLabel = attrs.label();
        } else {
          attrs = session.getAttrValues(keyHandle, CKA_KEY_TYPE);
        }

        P11ObjectId secretOrPrivKeyId = new P11ObjectId(keyHandle, objClass, attrs.keyType(), keyId, keyLabel);

        Long publicKeyHandle = null;
        if (objClass == CKO_PRIVATE_KEY) {
          objHandles = getObjects(session, AttributeVector.newPublicKey().id(keyId), 2);

          if (objHandles.isEmpty()) {
            LOG.warn("found no public key with ID {}.", hex(keyId));
          } else if (objHandles.size() > 1) {
            LOG.warn("found more than 1 public key with ID {}, ignore them", hex(keyId));
          } else {
            publicKeyHandle = objHandles.get(0);
          }
        }

        return new P11IdentityId(slotId, secretOrPrivKeyId, publicKeyHandle);
      }
    } finally {
      sessions.requite(bagEntry);
    }
  }

  @Override
  public void showDetails(OutputStream stream, boolean verbose) throws IOException {
    String tokenInfo;
    try {
      tokenInfo = slot.getToken().getTokenInfo().toString("  ");
    } catch (PKCS11Exception ex) {
      tokenInfo = "  ERROR";
    }

    String slotInfo;
    try {
      slotInfo = slot.getSlotInfo().toString("  ");
    } catch (PKCS11Exception ex) {
      slotInfo = "  ERROR";
    }

    stream.write(("\nToken information:\n" + tokenInfo).getBytes(StandardCharsets.UTF_8));

    stream.write(("\n\nSlot information:\n" + slotInfo).getBytes(StandardCharsets.UTF_8));
    stream.write('\n');

    if (verbose) {
      printSupportedMechanism(stream);
    }

    stream.write("\nList of objects:\n".getBytes(StandardCharsets.UTF_8));

    ConcurrentBagEntry<Session> session0;
    try {
      session0 = borrowSession();
    } catch (TokenException e) {
      throw new RuntimeException(e);
    }

    try {
      Session session = session0.value();
      session.findObjectsInit(null);

      // get handles of all objects
      List<Long> allHandles = new LinkedList<>();
      long[] handles;
      try {
        do {
          handles = session.findObjects(10);
          for (long handle : handles) {
            allHandles.add(handle);
          }
        } while (handles.length >= 10);
      } finally {
        session.findObjectsFinal();
      }

      int no = 0;
      for (long handle : allHandles) {
        String objectText = objectToString(session, handle);

        String text;
        try {
          text = formatNumber(++no, 3) + ". " + objectText;
        } catch (Exception ex) {
          text = formatNumber(no, 3) + ". " + "Error reading object with handle " + handle;
          LOG.debug(text, ex);
        }

        stream.write(("  " + text + "\n").getBytes(StandardCharsets.UTF_8));
        if (no % 10 == 0) {
          stream.flush();
        }
      }
    } catch (PKCS11Exception e) {
      String message = "error finding objects: " + e.getMessage();
      stream.write(message.getBytes(StandardCharsets.UTF_8));
      LogUtil.warn(LOG, e, message);
    } finally {
      sessions.requite(session0);
    }

    stream.flush();
  }

  private String objectToString(Session session, long handle)
      throws PKCS11Exception {
    AttributeVector attrs = session.getAttrValues(handle, CKA_ID, CKA_LABEL, CKA_CLASS);
    long objClass = attrs.class_();
    byte[] id = attrs.id();
    String label = attrs.label();

    String keySpec = null;
    if (objClass == CKO_PRIVATE_KEY || objClass == CKO_PUBLIC_KEY || objClass == CKO_SECRET_KEY) {
      long keyType = session.getCkaKeyType(handle);

      if (objClass == CKO_SECRET_KEY) {
        int valueLen;
        if (keyType == CKK_DES3) {
          valueLen = 24;
        } else {
          Integer len = session.getIntAttrValue(handle, CKA_VALUE_LEN);
          valueLen = (len == null) ? 0 : len;
        }

        keySpec = ckkCodeToName(keyType).substring(4) + "/" + (valueLen * 8);
      } else {
        if (keyType == CKK_RSA) {
          BigInteger modulus = session.getBigIntAttrValue(handle, CKA_MODULUS);
          keySpec = "RSA/" + (modulus == null ? "<N/A>" : modulus.bitLength());
        } else if (keyType == CKK_EC || keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
          byte[] ecParams = session.getByteArrayAttrValue(handle, CKA_EC_PARAMS);
          String curveName = null;
          if (ecParams == null) {
            curveName = "<N/A>";
          } else  {
            ASN1ObjectIdentifier curveOid = detectCurveOid(ecParams);
            if (curveOid != null) {
              curveName = AlgorithmUtil.getCurveName(curveOid);
              if (curveName == null) {
                curveName = curveOid.getId();
              }
            }

            if (curveName == null) {
              curveName = "0x" + hex(ecParams);
            }
          }

          keySpec = ckkCodeToName(keyType).substring(4) + "/" + curveName;
        } else if (keyType == CKK_VENDOR_SM2) {
          keySpec = "SM2";
        } else if (keyType == CKK_DSA) {
          BigInteger prime = session.getBigIntAttrValue(handle, CKA_PRIME);
          keySpec = "DSA/" + ((prime == null) ? 0 : prime.bitLength());
        } else {
          keySpec = ckkCodeToName(keyType).substring(4);
        }
      }
    }

    String text = "handle=" + handle + ", id=" + (id == null ? "<N/A>" : hex(id)) +
        ", label=" + (label == null ? "<N/A>" : label) + ", " + ckoCodeToName(objClass).substring(4);
    if (keySpec != null) {
      text += ": " + keySpec;
    }

    return text;
  }

  private byte[] generateId(Session session) throws TokenException {

    while (true) {
      byte[] keyId = new byte[newObjectConf.getIdLength()];
      random.nextBytes(keyId);

      AttributeVector template = new AttributeVector().id(keyId);
      if (isEmpty(getObjects(session, template, 1))) {
        return keyId;
      }
    }
  }

  private boolean labelExists(Session session, String keyLabel) throws TokenException {
    notNull(keyLabel, "keyLabel");
    AttributeVector template = new AttributeVector().label(keyLabel);
    return !isEmpty(getObjects(session, template, 1));
  } // method labelExists

  static void setKeyAttributes(P11NewKeyControl control, AttributeVector publicKey,
                        AttributeVector privateKey, P11NewObjectConf newObjectConf) {
    if (privateKey != null) {
      privateKey.private_(true).token(true);
      if (newObjectConf.isIgnoreLabel()) {
        if (control.getLabel() != null) {
          LOG.warn("label is set, but ignored: '{}'", control.getLabel());
        }
      } else {
        privateKey.label(control.getLabel());
      }

      if (control.getExtractable() != null) {
        privateKey.extractable(control.getExtractable());
      }

      if (control.getSensitive() != null) {
        privateKey.sensitive(control.getSensitive());
      }

      Set<P11KeyUsage> usages = control.getUsages();
      if (isNotEmpty(usages)) {
        for (P11KeyUsage usage : usages) {
          privateKey.attr(usage.getAttributeType(), true);
        }
      } else {
        long keyType = privateKey.keyType();
        // if not set
        if (keyType == CKK_EC || keyType == CKK_RSA || keyType == CKK_DSA) {
          privateKey.sign(true);
        }

        if (keyType == CKK_VENDOR_SM2) {
          privateKey.sign(true);
        }

        if (keyType == CKK_RSA) {
          privateKey.unwrap(true).decrypt(true);
        }
      }
    }

    if (publicKey != null) {
      publicKey.verify(true).token(true);
      if (!newObjectConf.isIgnoreLabel()) {
        publicKey.label(control.getLabel());
      }
    }
  } // method setKeyAttributes

  private static void setPrivateKeyAttrsOtf(AttributeVector privateKeyTemplate) {
    privateKeyTemplate.sensitive(false).extractable(true).token(false);
  }

  private static void destroyKeyPairQuietly(Session session, PKCS11KeyPair keypair) {
    if (keypair != null) {
      try {
        session.destroyObject(keypair.getPrivateKey());
      } catch (PKCS11Exception ex) {
        LogUtil.warn(LOG, ex, "error destroying private key " + keypair.getPrivateKey());
      }

      try {
        session.destroyObject(keypair.getPublicKey());
      } catch (PKCS11Exception ex) {
        LogUtil.warn(LOG, ex, "error destroying public key " + keypair.getPublicKey());
      }
    }
  }

  private static ASN1ObjectIdentifier detectCurveOid(byte[] ecParams) {
    if (ecParams[0] == 0x06 && (0xFF & ecParams[1]) == ecParams.length - 2) {
      try {
        return ASN1ObjectIdentifier.getInstance(ecParams);
      } catch (Exception e) {
        return null;
      }
    } else {
      return null;
    }
  }

}
