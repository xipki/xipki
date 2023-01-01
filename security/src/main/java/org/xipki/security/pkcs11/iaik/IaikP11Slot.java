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

package org.xipki.security.pkcs11.iaik;

import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.objects.*;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.*;
import org.xipki.security.pkcs11.P11ModuleConf.P11MechanismFilter;
import org.xipki.security.pkcs11.P11ModuleConf.P11NewObjectConf;
import org.xipki.security.util.SignerUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.concurrent.ConcurrentBag;
import org.xipki.util.concurrent.ConcurrentBagEntry;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static iaik.pkcs.pkcs11.wrapper.PKCS11Constants.*;
import static org.xipki.security.pkcs11.iaik.IaikP11SlotUtil.*;
import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.positive;
import static org.xipki.util.CollectionUtil.isEmpty;
import static org.xipki.util.CollectionUtil.isNotEmpty;

/**
 * {@link P11Slot} based on the IAIK PKCS#11 wrapper.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
class IaikP11Slot extends P11Slot {

  public static final AlgorithmIdentifier ALGID_RSA = new AlgorithmIdentifier(
      PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);

  private static final Logger LOG = LoggerFactory.getLogger(IaikP11Slot.class);

  private static final long DEFAULT_MAX_COUNT_SESSION = 32;

  private final int maxMessageSize;

  private Slot slot;

  private final long userType;

  private List<char[]> password;

  private final int maxSessionCount;

  private final boolean supportCert;

  private final long timeOutWaitNewSession = 10000; // maximal wait for 10 second

  private final AtomicLong countSessions = new AtomicLong(0);

  private final SecureRandom random = new SecureRandom();

  private final P11NewObjectConf newObjectConf;

  private final ConcurrentBag<ConcurrentBagEntry<Session>> sessions = new ConcurrentBag<>();

  private final long rsaKeyPairGenMech;

  private String libDesc;

  private boolean omitDateAttrsInCertObject;

  IaikP11Slot(String moduleName, P11SlotIdentifier slotId, Slot slot, boolean readOnly, long userType,
              List<char[]> password, int maxMessageSize, P11MechanismFilter mechanismFilter,
              P11NewObjectConf newObjectConf, Integer numSessions, List<Long> secretKeyTypes, List<Long> keyPairTypes)
      throws P11TokenException {
    super(moduleName, slotId, readOnly, mechanismFilter, numSessions, secretKeyTypes, keyPairTypes);

    this.newObjectConf = notNull(newObjectConf, "newObjectConf");
    this.slot = notNull(slot, "slot");
    this.maxMessageSize = positive(maxMessageSize, "maxMessageSize");

    this.userType = userType;
    this.password = password;

    boolean successful = false;

    try {
      Info moduleInfo = slot.getModule().getInfo();
      libDesc = moduleInfo.getLibraryDescription();
      if (libDesc == null) {
        libDesc = "";
      }
    } catch (TokenException ex) {
      LogUtil.error(LOG, ex, "Module.getInfo()");
      throw new P11TokenException("could not get Module Info: " + ex.getMessage(), ex);
    }

    try {
      Session session;
      try {
        // SO (Security Officer) cannot login in READ-ONLY session
        session = openSession();
      } catch (P11TokenException ex) {
        LogUtil.error(LOG, ex, "openSession");
        throw ex;
      }

      try {
        firstLogin(session, password);
      } catch (P11TokenException ex) {
        LogUtil.error(LOG, ex, "firstLogin");
        throw ex;
      }

      Token token;
      try {
        token = this.slot.getToken();
      } catch (TokenException ex) {
        throw new P11TokenException("could not getToken: " + ex.getMessage(), ex);
      }

      long maxSessionCount2;
      try {
        maxSessionCount2 = token.getTokenInfo().getMaxSessionCount();
      } catch (TokenException ex) {
        throw new P11TokenException("could not get tokenInfo: " + ex.getMessage(), ex);
      }

      if (maxSessionCount2 <= 0) {
        maxSessionCount2 = DEFAULT_MAX_COUNT_SESSION;
      } else {
        // 2 sessions as buffer, they may be used elsewhere.
        maxSessionCount2 = (maxSessionCount2 < 3) ? 1 : maxSessionCount2 - 2;
      }

      if (numSessions != null) {
        maxSessionCount2 = Math.min(numSessions, maxSessionCount2);
      }

      this.maxSessionCount = (int) maxSessionCount2;
      LOG.info("maxSessionCount: {}", this.maxSessionCount);

      // test whether supports X.509 certificates
      boolean supports = true;
      try {
        session.findObjectsInit(newX509Cert());
        session.findObjectsFinal();
      } catch (Exception ex) {
        supports = false;
      }
      this.supportCert = supports;
      LOG.info("support certificates: {}", this.supportCert);

      sessions.add(new ConcurrentBagEntry<>(session));
      refresh();

      rsaKeyPairGenMech = supportsMechanism(CKM_RSA_X9_31_KEY_PAIR_GEN)
          ? CKM_RSA_X9_31_KEY_PAIR_GEN : CKM_RSA_PKCS_KEY_PAIR_GEN;

      successful = true;
    } finally {
      if (!successful) {
        close();
      }
    }
  } // constructor

  Slot getSlot() {
    return slot;
  }

  @Override
  protected P11SlotRefreshResult refresh0() throws P11TokenException {
    Mechanism[] mechanisms;
    try {
      mechanisms = slot.getToken().getMechanismList();
    } catch (TokenException ex) {
      throw new P11TokenException("could not getMechanismList: " + ex.getMessage(), ex);
    }

    P11SlotRefreshResult ret = new P11SlotRefreshResult();

    if (mechanisms != null) {
      StringBuilder ignoreMechs = new StringBuilder();
      boolean smartcard = libDesc.toLowerCase().contains("smartcard");
      for (Mechanism mech : mechanisms) {
        long code = mech.getMechanismCode();
        if (smartcard) {
          if (code == CKM_ECDSA_SHA1     || code == CKM_ECDSA_SHA224   || code == CKM_ECDSA_SHA256 ||
              code == CKM_ECDSA_SHA384   || code == CKM_ECDSA_SHA512   || code == CKM_ECDSA_SHA3_224 ||
              code == CKM_ECDSA_SHA3_256 || code == CKM_ECDSA_SHA3_384 || code == CKM_ECDSA_SHA3_512) {
            ignoreMechs.append(Functions.ckmCodeToName(code)).append(", ");
          } else {
            ret.addMechanism(code);
          }
        } else {
          ret.addMechanism(code);
        }
      }

      if (ignoreMechs.length() > 0) {
        LOG.info("Ignore mechanisms in smartcard-based HSM: {}", ignoreMechs.substring(0, ignoreMechs.length() - 2));
      }
    }

    ConcurrentBagEntry<Session> bagEntry = borrowSession();

    try {
      Session session = bagEntry.value();
      // secret keys
      List<Long> hSecretKeys;
      if (secretKeyTypes == null) {
        hSecretKeys = getObjects(session, Attribute.getInstance(CKA_CLASS, CKO_SECRET_KEY));
      } else if (secretKeyTypes.isEmpty()) {
        hSecretKeys = Collections.emptyList();
      } else {
        hSecretKeys = new LinkedList<>();
        for (Long keyType : secretKeyTypes) {
          hSecretKeys.addAll(getObjects(session, newSecretKey(keyType)));
        }
      }

      LOG.info("found {} secret keys", hSecretKeys.size());
      int count = 0;
      for (Long hSecretKey : hSecretKeys) {
        if (analyseSingleSecretKey(session, hSecretKey, ret)) {
          count++;
        }
      }
      LOG.info("accepted {} secret keys", count);

      if (supportCert) {
        // first get the list of all CA certificates
        List<Long> hP11Certs = getAllCertificateObjects(session);
        LOG.info("found {} X.509 certificates", hP11Certs.size());

        count = 0;
        for (long hP11Cert : hP11Certs) {
          ByteArrayAttribute idAttr = new ByteArrayAttribute(CKA_ID);
          CharArrayAttribute labelAttr = new CharArrayAttribute(CKA_LABEL);
          ByteArrayAttribute valueAttr = new ByteArrayAttribute(CKA_VALUE);

          try {
            session.getAttributeValues(hP11Cert, idAttr, labelAttr, valueAttr);
          } catch (TokenException ex) {
            LogUtil.warn(LOG, ex, "Error reading attributes of X.509 certificate with handle " + hP11Cert);
            continue;
          }

          byte[] id = idAttr.getByteArrayValue();
          String label = labelAttr.getStringValue();
          if (id == null || id.length == 0) {
            LOG.warn("ignored X.509 certificate with ID: null and label: " + label);
          } else {
            ret.addCertificate(new P11ObjectIdentifier(id, label), parseCert(valueAttr.getByteArrayValue()));
            count++;
          }
        }

        LOG.info("accepted {} X.509 certificates", count);
      }

      List<Long> hPrivKeys;
      if (keyPairTypes == null) {
        hPrivKeys = getObjects(session, Attribute.getInstance(CKA_CLASS, CKO_PRIVATE_KEY));
      } else if (keyPairTypes.isEmpty()) {
        hPrivKeys = Collections.emptyList();
      } else {
        hPrivKeys = new LinkedList<>();
        for (long keyType : keyPairTypes) {
          List<Long> handles = getObjects(session, newPrivateKey(keyType));
          hPrivKeys.addAll(handles);
        }
      }

      LOG.info("found {} private keys", hPrivKeys.size());
      count = 0;
      for (Long hPrivKey : hPrivKeys) {
        if (analyseSinglePrivateKey(session, hPrivKey, ret)) {
          count++;
        }
      }
      LOG.info("accepted {} private keys", count);

      return ret;
    } finally {
      sessions.requite(bagEntry);
    }
  } // method refresh0

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

  private boolean analyseSingleSecretKey(Session session, long hSecretKey, P11SlotRefreshResult refreshResult) {
    ByteArrayAttribute idAttr = new ByteArrayAttribute(CKA_ID);
    CharArrayAttribute labelAttr = new CharArrayAttribute(CKA_LABEL);
    LongAttribute keyTypeAttr = new LongAttribute(CKA_KEY_TYPE);

    try {
      session.getAttributeValues(hSecretKey, idAttr, labelAttr, keyTypeAttr);
    } catch (PKCS11Exception ex) {
      LOG.warn("error reading attributes of secret key {}", hSecretKey);
      return false;
    }

    byte[] id = idAttr.getByteArrayValue();
    String label = labelAttr.getStringValue();

    if ((id == null || id.length == 0) && StringUtil.isBlank(label)) {
      LOG.warn("ignored secret key with ID: null and label: " + label);
      return false;
    }

    long keyType = keyTypeAttr.getLongValue();

    int keyBitLen;
    if (keyType == CKK_DES3) {
      keyBitLen = 192;
    } else {
      try {
        keyBitLen = 8 * session.getLongAttributeValue(hSecretKey, CKA_VALUE_LEN).intValue();
      } catch (PKCS11Exception ex) {
        LOG.warn("error reading attributes of secret key {}", hSecretKey);
        return false;
      }
    }

    IaikP11Identity identity = new IaikP11Identity(this,
        new P11IdentityId(slotId, new P11ObjectIdentifier(id, label)), hSecretKey, keyType, keyBitLen);
    refreshResult.addIdentity(identity);
    return true;
  } // method analyseSingleKey

  private boolean analyseSinglePrivateKey(
      Session session, long hPrivKey, P11SlotRefreshResult refreshResult) {
    ByteArrayAttribute idAttr = new ByteArrayAttribute(CKA_ID);
    CharArrayAttribute labelAttr = new CharArrayAttribute(CKA_LABEL);
    LongAttribute keyTypeAttr = new LongAttribute(CKA_KEY_TYPE);

    try {
      session.getAttributeValues(hPrivKey, keyTypeAttr, idAttr, labelAttr);
    } catch (PKCS11Exception ex) {
      LOG.warn("error reading attributes of private key {}", hPrivKey);
      return false;
    }

    byte[] id = idAttr.getByteArrayValue();
    String label = labelAttr.getStringValue();
    long keyType = keyTypeAttr.getLongValue();

    int idLen = id == null ? 0 : id.length;
    String name = "id " + (idLen == 0 ? "" : hex(id)) + " and label " + label;
    String keyTypeName = Functions.ckkCodeToName(keyType);

    if (idLen == 0) {
      if (keyType == CKK_RSA) {
        if (StringUtil.isBlank(label)) {
          // We do not need id to identify the public key and certificate.
          // The public key can be constructed from the private key
          LOG.warn("ignored {} private key with ID: null and label: {}", keyTypeName, label);
        }
      } else{
        LOG.warn("ignored {] private key with ID: null and label: {}", keyTypeName, label);
        return false;
      }
    }

    try {
      String pubKeyLabel = null;
      Long hPubKey = idLen == 0 ? null : getKeyObjectForId(session, CKO_PUBLIC_KEY, keyType, id);
      if (hPubKey != null) {
        pubKeyLabel = readLabel(session, hPubKey);
      }

      String certLabel = null;
      java.security.PublicKey pubKey = null;
      X509Cert cert = idLen == 0 ? null : refreshResult.getCertForId(id);

      if (cert != null) {
        certLabel = refreshResult.getCertLabelForId(id);
        pubKey = cert.getPublicKey();
      } else if (hPubKey != null) {
        pubKey = generatePublicKey(session, hPubKey, keyType);
      } else {
        if (keyType == CKK_RSA) {
          pubKey = generatePublicKey(session, hPrivKey, keyType);
        }

        if (pubKey == null) {
          LOG.info("neither certificate nor public key for the {} key ({}) is available",
              keyTypeName, name);
          return false;
        }
      }

      X509Cert[] certs = (cert == null) ? null : new X509Cert[]{cert};
      P11IdentityId p11Id = new P11IdentityId(slotId, new P11ObjectIdentifier(id, label),
          pubKey != null, pubKeyLabel, cert != null, certLabel);
      refreshResult.addIdentity(new IaikP11Identity(this, p11Id, hPrivKey, keyType, pubKey, certs));
      return true;
    } catch (XiSecurityException ex) {
      LogUtil.error(LOG, ex, "XiSecurityException while initializing private key with " + name);
    } catch (Throwable th) {
      LOG.error("unexpected exception while initializing private key with " + name, th);
    }

    return false;
  } // method analyseSingleKey

  byte[] digestSecretKey(long mech, IaikP11Identity identity) throws P11TokenException {
    if (!identity.isSecretKey()) {
      throw new P11TokenException("digestSecretKey could not be applied to non-SecretKey");
    }

    long keyHandle = notNull(identity, "identity").getSigningKeyHandle();
    assertMechanismSupported(mech);

    if (LOG.isTraceEnabled()) {
      LOG.debug("digest (init, digestKey, then finish) secret key {}", identity.getId());
    }

    int digestLen;
    if (CKM_SHA_1 == mech) {
      digestLen = 20;
    } else if (CKM_SHA224 == mech || CKM_SHA3_224 == mech) {
      digestLen = 28;
    } else if (CKM_SHA256 == mech || CKM_SHA3_256 == mech) {
      digestLen = 32;
    } else if (CKM_SHA384 == mech || CKM_SHA3_384 == mech) {
      digestLen = 48;
    } else if (CKM_SHA512 == mech || CKM_SHA3_512 == mech) {
      digestLen = 64;
    } else {
      throw new P11TokenException("unsupported mechanism " + mech);
    }

    ConcurrentBagEntry<Session> session0 = borrowSession();
    Mechanism mechanismObj = Mechanism.get(mech);

    try {
      Session session = session0.value();
      try {
        return IaikP11SlotUtil.digestKey(session, digestLen, mechanismObj, keyHandle);
      } catch (PKCS11Exception ex) {
        if (ex.getErrorCode() != CKR_USER_NOT_LOGGED_IN) {
          throw new P11TokenException(ex.getMessage(), ex);
        }

        LOG.info("digestKey ended with ERROR CKR_USER_NOT_LOGGED_IN, login and then retry it");
        // force the login
        forceLogin(session);
        try {
          return IaikP11SlotUtil.digestKey(session, digestLen, mechanismObj, keyHandle);
        } catch (TokenException ex2) {
          throw new P11TokenException(ex2.getMessage(), ex2);
        }
      } catch (TokenException ex) {
        throw new P11TokenException(ex.getMessage(), ex);
      }
    } finally {
      sessions.requite(session0);
    }
  } // method digestKey

  byte[] sign(long mech, P11Params parameters, byte[] content, IaikP11Identity identity)
      throws P11TokenException {
    notNull(content, "content");
    assertMechanismSupported(mech);

    int expectedSignatureLen;
    if (mech == CKM_SHA_1_HMAC) {
      expectedSignatureLen = 20;
    } else if (mech == CKM_SHA224_HMAC || mech == CKM_SHA3_224) {
      expectedSignatureLen = 28;
    } else if (mech == CKM_SHA256_HMAC || mech == CKM_SHA3_256) {
      expectedSignatureLen = 32;
    } else if (mech == CKM_SHA384_HMAC || mech == CKM_SHA3_384) {
      expectedSignatureLen = 48;
    } else if (mech == CKM_SHA512_HMAC || mech == CKM_SHA3_512) {
      expectedSignatureLen = 64;
    } else {
      expectedSignatureLen = identity.getExpectedSignatureLen();
    }

    Mechanism mechanismObj = getMechanism(mech, parameters);
    long signingKeyHandle = identity.getSigningKeyHandle();

    ConcurrentBagEntry<Session> session0 = borrowSession();
    try {
      Session session = session0.value();
      try {
        return sign0(session, expectedSignatureLen, mechanismObj, content, signingKeyHandle, identity.getKeyType());
      } catch (PKCS11Exception ex) {
        if (ex.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
          LOG.info("sign ended with ERROR CKR_USER_NOT_LOGGED_IN, login and then retry it");
          // force the login
          forceLogin(session);
          return sign0(session, expectedSignatureLen, mechanismObj, content, signingKeyHandle, identity.getKeyType());
        } else {
          throw ex;
        }
      } finally {
        sessions.requite(session0);
      }
    } catch (TokenException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
  } // method sign

  private byte[] sign0(Session session, int expectedSignatureLen, Mechanism mechanism,
                       byte[] content, long signingKeyHandle, long keyType)
      throws TokenException {
    boolean weierstrausKey = CKK_EC == keyType || CKK_VENDOR_SM2 == keyType;

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

      // Some HSM vendor return not the EC plain signature (r || s), but the X.962 encoded one.
      // So we need to increase the expectedSignatureLen
      int maxSignatureLen = weierstrausKey ? expectedSignatureLen + 20 : expectedSignatureLen;
      sigvalue = session.signFinal(maxSignatureLen);
    }

    if (sigvalue.length > expectedSignatureLen) {
      if (sigvalue[0] == 0x30) {
        try {
          sigvalue = SignerUtil.dsaSigX962ToPlain(sigvalue, expectedSignatureLen * 4);
        } catch (XiSecurityException e) {
          LOG.error(String.format("ERROR: sigvalue (%d): %s", sigvalue.length, Hex.toHexString(sigvalue)), e);
          throw new TokenException(e);
        } catch (RuntimeException e) {
          LOG.error(String.format("ERROR: sigvalue (%d): %s", sigvalue.length, Hex.toHexString(sigvalue)), e);
          throw e;
        }
      }
    }

    return sigvalue;
  } // method sign0

  private byte[] singleSign(Session session, Mechanism mechanism, byte[] content, long signingKeyHandle)
      throws TokenException {
    LOG.debug("single sign");
    session.signInit(mechanism, signingKeyHandle);
    return session.sign(content);
  } // method singleSign

  private Session openSession() throws P11TokenException {
    Session session;
    try {
      session = slot.getToken().openSession(!isReadOnly());
    } catch (TokenException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    countSessions.incrementAndGet();
    return session;
  } // method openSession

  private ConcurrentBagEntry<Session> borrowSession() throws P11TokenException {
    for (int i = 0; i < Math.min(DEFAULT_MAX_COUNT_SESSION, maxSessionCount); i++) {
      try {
        return borrowSession0();
      } catch (P11TokenException ex) {
        Throwable cause = ex.getCause();
        if (cause instanceof PKCS11Exception) {
          long ckr = ((PKCS11Exception) cause).getErrorCode();
          if (ckr == CKR_SESSION_HANDLE_INVALID || ckr == CKR_SESSION_CLOSED) {
            break;
          }
        }
      }
    }
    throw new P11TokenException("could not borrow valid session");
  } // method borrowSession

  private ConcurrentBagEntry<Session> borrowSession0() throws P11TokenException {
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
      throw new P11TokenException("no idle session");
    }

    login(session.value());
    return session;
  } // method borrowSession

  private void firstLogin(Session session, List<char[]> password) throws P11TokenException {
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
      if (ex.getErrorCode() != PKCS11Constants.CKR_USER_ALREADY_LOGGED_IN) {
        throw new P11TokenException(ex.getMessage(), ex);
      }
    } catch (TokenException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
  } // method firstLogin

  private void login(Session session) throws P11TokenException {
    boolean isSessionLoggedIn = checkSessionLoggedIn(session, userType);
    if (isSessionLoggedIn) {
      return;
    }

    boolean loginRequired;
    try {
      loginRequired = session.getToken().getTokenInfo().isLoginRequired();
    } catch (TokenException ex) {
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

  private void forceLogin(Session session) throws P11TokenException {
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

  private Long getKeyObjectForId(Session session, long keyClass, Long keyType, byte[] keyId)
      throws P11TokenException {
    return getKeyObject(session, keyClass, keyType, keyId, true, null);
  }

  private Long getKeyObject(Session session, long keyClass, Long keyType, byte[] keyId, char[] keyLabel)
      throws P11TokenException {
    return getKeyObject(session, keyClass, keyType, keyId, false, keyLabel);
  }

  private Long getKeyObject(Session session, long keyClass, Long keyType,
                           byte[] keyId, boolean ignoreLabel, char[] keyLabel)
      throws P11TokenException {
    AttributeVector template = new AttributeVector().class_(keyClass).id(notNull(keyId, "keyId"));
    if (keyType != null) {
      template.keyType(keyType);
    }

    if (!ignoreLabel) {
      template.label(keyLabel);
    }

    List<Long> tmpObjects = getObjects(session, template, 2);
    if (isEmpty(tmpObjects)) {
      return null;
    }

    int size = tmpObjects.size();
    if (size > 1) {
      LOG.warn("found {} public key identified by {}, use the first one", size, getDescription(keyId, keyLabel));
    }

    return tmpObjects.get(0);
  } // method getKeyObject

  @Override
  public int removeObjectsForId(byte[] id) throws P11TokenException {
    return removeObjects(id, true, null);
  }

  @Override
  public int removeObjectsForLabel(String label) throws P11TokenException {
    return removeObjects(null, false, notNull(label, "label").toCharArray());
  }

  @Override
  public int removeObjects(byte[] id, String label) throws P11TokenException {
    return removeObjects(id, false, (label == null) ? null : label.toCharArray());
  }

  private int removeObjects(byte[] id, boolean ignoreLabel, char[] label) throws P11TokenException {
    if (ignoreLabel) {
      label = null;
    }
    boolean labelBlank = label == null || label.length == 0;
    if ((id == null || id.length == 0) && labelBlank) {
      throw new IllegalArgumentException("at least one of id and label may not be null");
    }

    AttributeVector template = new AttributeVector();
    if (id != null && id.length > 0) {
      template.id(id);
    }

    if (!ignoreLabel) {
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
  protected void removeCerts0(P11ObjectIdentifier objectId) throws P11TokenException {
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();
      List<Long> existingCerts = getCertificateObjects(session, objectId.getId(), objectId.getLabelChars());
      if (existingCerts == null || existingCerts.isEmpty()) {
        LOG.warn("could not find certificates " + objectId);
        return;
      }

      for (Long certHandle : existingCerts) {
        destroyObject(session, certHandle, "");
      }
    } finally {
      sessions.requite(bagEntry);
    }
  } // method removeCerts0

  @Override
  protected P11ObjectIdentifier addCert0(X509Cert cert, P11NewObjectControl control)
      throws P11TokenException {
    ConcurrentBagEntry<Session> bagEntry = borrowSession();

    try {
      Session session = bagEntry.value();
      // get a local copy
      boolean omit = omitDateAttrsInCertObject;
      AttributeVector newCertTemp = createPkcs11Template(session, cert, control, omit);
      long newCertHandle;
      try {
        newCertHandle = session.createObject(newCertTemp);
      } catch (PKCS11Exception ex) {
         long errCode = ex.getErrorCode();
         if (!omit && CKR_TEMPLATE_INCONSISTENT == errCode) {
           // some HSMs like NFAST does not like the attributes CKA_START_DATE and CKA_END_DATE, try without them.
           newCertTemp = createPkcs11Template(session, cert, control, true);
           newCertHandle = session.createObject(newCertTemp);
           omitDateAttrsInCertObject = true;
           LOG.warn("The HSM does not accept certificate object with attributes "
               + "CKA_START_DATE and CKA_END_DATE, ignore them");
         } else {
           throw ex;
         }
      }

      byte[] id = newCertTemp.getAttributeByteArrayValue(CKA_ID);
      String label = newCertTemp.getAttributeStringValue(CKA_LABEL);
      return new P11ObjectIdentifier(id, label);
    } catch (TokenException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    } finally {
      sessions.requite(bagEntry);
    }
  } // method addCert0

  @Override
  protected P11Identity generateSecretKey0(long keyType, int keysize, P11NewKeyControl control)
      throws P11TokenException {
    if (keysize % 8 != 0) {
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
    } else if (CKK_SHA_1_HMAC == keyType || CKK_SHA224_HMAC == keyType   || CKK_SHA256_HMAC == keyType
        || CKK_SHA384_HMAC == keyType    || CKK_SHA512_HMAC == keyType   || CKK_SHA3_224_HMAC == keyType
        || CKK_SHA3_256_HMAC == keyType  || CKK_SHA3_384_HMAC == keyType || CKK_SHA3_512_HMAC == keyType) {
      mech = CKM_GENERIC_SECRET_KEY_GEN;
    } else {
      throw new IllegalArgumentException("unsupported key type 0x" + Functions.toFullHex((int)keyType));
    }

    assertMechanismSupported(mech);

    char[] labelChars;
    if (newObjectConf.isIgnoreLabel()) {
      if (control.getLabel() != null) {
        LOG.warn("label is set, but ignored: '{}'", control.getLabel());
      }
      labelChars = null;
    } else {
      labelChars = control.getLabel().toCharArray();
    }

    byte[] id = control.getId();

    AttributeVector template = newSecretKey(keyType);
    IaikP11SlotUtil.setKeyAttributes(control, template, labelChars);
    if (hasValueLen) {
      template.valueLen(keysize / 8);
    }

    Mechanism mechanism = Mechanism.get(mech);
    long keyHandle;
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();
      if (labelChars != null && labelExists(session, labelChars)) {
        throw new IllegalArgumentException("label " + control.getLabel() + " exists, please specify another one");
      }

      if (id == null) {
        id = generateId(session);
      }

      template.id(id);

      try {
        keyHandle = session.generateKey(mechanism, template);
      } catch (TokenException ex) {
        throw new P11TokenException("could not generate generic secret key using " + mechanism.getName(), ex);
      }

      String label = null;
      try {
        label = session.getCharAttributeStringValue(keyHandle, CKA_LABEL);
      } catch (PKCS11Exception e) {
        throw new P11TokenException(e);
      }

      P11ObjectIdentifier objId = new P11ObjectIdentifier(id, label);
      P11IdentityId entityId = new P11IdentityId(slotId, objId);

      return new IaikP11Identity(this, entityId, keyHandle, keyType, keysize);
    } finally {
      sessions.requite(bagEntry);
    }
  } // method generateSecretKey0

  @Override
  protected P11Identity importSecretKey0(long keyType, byte[] keyValue, P11NewKeyControl control)
      throws P11TokenException {
    AttributeVector template = newSecretKey(keyType);
    char[] labelChars;
    if (newObjectConf.isIgnoreLabel()) {
      if (control.getLabel() != null) {
        LOG.warn("label is set, but ignored: '{}'", control.getLabel());
      }
      labelChars = null;
    } else {
      labelChars = control.getLabel().toCharArray();
    }

    IaikP11SlotUtil.setKeyAttributes(control, template, labelChars);
    template.value(keyValue);

    long keyHandle;
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();
      if (labelChars != null && labelExists(session, labelChars)) {
        throw new IllegalArgumentException("label " + control.getLabel() + " exists, please specify another one");
      }

      byte[] id = control.getId();
      if (id == null) {
        id = generateId(session);
      }

      template.id(id);

      try {
        keyHandle = session.createObject(template);
      } catch (TokenException ex) {
        throw new P11TokenException("could not create secret key", ex);
      }

      String label = null;
      try {
        label = session.getCharAttributeStringValue(keyHandle, CKA_LABEL);
      } catch (PKCS11Exception e) {
      }

      P11ObjectIdentifier objId = new P11ObjectIdentifier(id, label);
      P11IdentityId entityId = new P11IdentityId(slotId, objId);

      return new IaikP11Identity(this, entityId, keyHandle, keyType, keyValue.length * 8);
    } finally {
      sessions.requite(bagEntry);
    }
  } // method importSecretKey0

  @Override
  protected P11Identity generateRSAKeypair0(int keysize, BigInteger publicExponent, P11NewKeyControl control)
      throws P11TokenException {
    AttributeVector privateKey = newPrivateKey(CKK_RSA);
    AttributeVector publicKey = newPublicKey(CKK_RSA).modulusBits(keysize);
    if (publicExponent != null) {
      publicKey.publicExponent(publicExponent);
    }
    setKeyAttributes(control, publicKey, privateKey, newObjectConf);

    return generateKeyPair(rsaKeyPairGenMech, control.getId(), privateKey, publicKey);
  } // method generateRSAKeypair0

  @Override
  protected PrivateKeyInfo generateRSAKeypairOtf0(int keysize, BigInteger publicExponent)
      throws P11TokenException {
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

      KeyPair keypair = null;
      try {
        keypair = session.generateKeyPair(Mechanism.get(mech), publicKeyTemplate, privateKeyTemplate);
        BigInteger[] attrValues = session.getByteArrayAttributeBigIntValues(keypair.getPrivateKey(),
            CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKA_PRIVATE_EXPONENT,
            CKA_PRIME_1, CKA_PRIME_2, CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT);

        return new PrivateKeyInfo(ALGID_RSA,
            new org.bouncycastle.asn1.pkcs.RSAPrivateKey(
                attrValues[0], attrValues[1], attrValues[2], attrValues[3],
                attrValues[4], attrValues[5], attrValues[6], attrValues[7]));

      } catch (TokenException | IOException ex) {
        throw new P11TokenException("could not generate keypair " + Functions.ckmCodeToName(mech), ex);
      } finally {
        destroyKeyPairQuietly(session, keypair);
      }
    } finally {
      sessions.requite(bagEntry);
    }
  } // method generateRSAKeypairOtf0

  @Override
  protected P11Identity generateDSAKeypair0(BigInteger p, BigInteger q, BigInteger g, P11NewKeyControl control)
      throws P11TokenException {
    AttributeVector privateKey = newPrivateKey(CKK_DSA);
    AttributeVector publicKey = newPublicKey(CKK_DSA).prime(p).subprime(q).base(g);
    setKeyAttributes(control, publicKey, privateKey, newObjectConf);

    return generateKeyPair(CKM_DSA_KEY_PAIR_GEN, control.getId(), privateKey, publicKey);
  } // method generateDSAKeypair0

  @Override
  protected PrivateKeyInfo generateDSAKeypairOtf0(BigInteger p, BigInteger q, BigInteger g)
      throws P11TokenException {
    AttributeVector priKeyTemplate = newPrivateKey(CKK_DSA);
    setPrivateKeyAttrsOtf(priKeyTemplate);

    AttributeVector pubKeyTemplate = newPublicKey(CKK_DSA).prime(p).subprime(q).base(g);

    long mech = CKM_DSA_KEY_PAIR_GEN;
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();

      KeyPair keypair = null;
      try {
        DSAParameter parameter = new DSAParameter(p, q, g);
        AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, parameter);

        keypair = session.generateKeyPair(Mechanism.get(mech), pubKeyTemplate, priKeyTemplate);
        long skHandle = keypair.getPrivateKey();
        long pkHandle = keypair.getPublicKey();

        BigInteger p11PublicKeyValue = session.getByteArrayAttributeBigIntValue(pkHandle, CKA_VALUE);
        BigInteger p11PrivateKeyValue = session.getByteArrayAttributeBigIntValue(skHandle, CKA_VALUE);

        byte[] publicKey = new ASN1Integer(p11PublicKeyValue).getEncoded(); // y

        return new PrivateKeyInfo(algId, new ASN1Integer(p11PrivateKeyValue), null, publicKey);
      } catch (TokenException | IOException ex) {
        throw new P11TokenException("could not generate keypair " + Functions.ckmCodeToName(mech), ex);
      } finally {
        destroyKeyPairQuietly(session, keypair);
      }
    } finally {
      sessions.requite(bagEntry);
    }
  } // method generateDSAKeypairOtf0

  @Override
  protected P11Identity generateECEdwardsKeypair0(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws P11TokenException {
    AttributeVector privKeyTemplate = newPrivateKey(CKK_EC_EDWARDS);
    AttributeVector pubKeyTemplate = newPublicKey(CKK_EC_EDWARDS);
    setKeyAttributes(control, pubKeyTemplate, privKeyTemplate, newObjectConf);
    byte[] encodedCurveId;
    try {
      encodedCurveId = curveId.getEncoded();
    } catch (IOException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    pubKeyTemplate.ecParams(encodedCurveId);
    return generateKeyPair(CKM_EC_EDWARDS_KEY_PAIR_GEN, control.getId(), privKeyTemplate, pubKeyTemplate);
  } // method generateECEdwardsKeypair0

  @Override
  protected PrivateKeyInfo generateECEdwardsKeypairOtf0(ASN1ObjectIdentifier curveId)
      throws P11TokenException {
    return generateECKeypairOtf0(CKK_EC_EDWARDS, CKM_EC_EDWARDS_KEY_PAIR_GEN, curveId);
  }

  @Override
  protected P11Identity generateECMontgomeryKeypair0(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws P11TokenException {
    AttributeVector privateKey = newPrivateKey(CKK_EC_MONTGOMERY);
    AttributeVector publicKey = newPublicKey(CKK_EC_MONTGOMERY);
    setKeyAttributes(control, publicKey, privateKey, newObjectConf);
    try {
      publicKey.ecParams(curveId.getEncoded());
    } catch (IOException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }

    return generateKeyPair(CKM_EC_MONTGOMERY_KEY_PAIR_GEN, control.getId(), privateKey, publicKey);
  } // method generateECMontgomeryKeypair0

  @Override
  protected PrivateKeyInfo generateECMontgomeryKeypairOtf0(ASN1ObjectIdentifier curveId)
      throws P11TokenException {
    return generateECKeypairOtf0(CKK_EC_MONTGOMERY, CKM_EC_MONTGOMERY_KEY_PAIR_GEN, curveId);
  }

  @Override
  protected P11Identity generateECKeypair0(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws P11TokenException {
    AttributeVector privateKey = newPrivateKey(CKK_EC);
    AttributeVector publicKey = newPublicKey(CKK_EC);
    setKeyAttributes(control, publicKey, privateKey, newObjectConf);
    byte[] encodedCurveId;
    try {
      encodedCurveId = curveId.getEncoded();
    } catch (IOException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }

    publicKey.ecParams(encodedCurveId);
    return generateKeyPair(CKM_EC_KEY_PAIR_GEN, control.getId(), privateKey, publicKey);
  } // method generateECKeypair0

  @Override
  protected PrivateKeyInfo generateECKeypairOtf0(ASN1ObjectIdentifier curveId) throws P11TokenException {
    return generateECKeypairOtf0(CKK_EC, CKM_EC_KEY_PAIR_GEN, curveId);
  }

  private PrivateKeyInfo generateECKeypairOtf0(long keyType, long mech, ASN1ObjectIdentifier curveId)
      throws P11TokenException {
    if (keyType == CKK_VENDOR_SM2) {
      if (!GMObjectIdentifiers.sm2p256v1.equals(curveId)) {
        throw new P11TokenException("keyType and curveId do not match.");
      }
    }

    AttributeVector privateKeyTemplate = newPrivateKey(keyType);
    setPrivateKeyAttrsOtf(privateKeyTemplate);

    AttributeVector publicKeyTemplate = newPublicKey(keyType);
    try {
      publicKeyTemplate.ecParams(curveId.getEncoded());
    } catch (IOException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }

    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();

      KeyPair keypair = null;
      try {
        keypair = session.generateKeyPair(Mechanism.get(mech), publicKeyTemplate, privateKeyTemplate);

        byte[] ecPoint = session.getByteArrayAttributeValue(keypair.getPublicKey(), CKA_EC_POINT);
        byte[] privValue = session.getByteArrayAttributeValue(keypair.getPrivateKey(), CKA_VALUE);

        if (CKK_EC_EDWARDS == keyType || CKK_EC_MONTGOMERY == keyType) {
          AlgorithmIdentifier algId = new AlgorithmIdentifier(curveId);
          byte[] encodedPublicPoint = ASN1OctetString.getInstance(ecPoint).getOctets();
          return new PrivateKeyInfo(algId, new DEROctetString(privValue), null, encodedPublicPoint);
        } else {
          AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curveId);

          byte[] encodedPublicPoint = ASN1OctetString.getInstance(ecPoint).getOctets();
          if (encodedPublicPoint[0] != 4) {
            throw new P11TokenException("EcPoint does not start with 0x04");
          }

          int orderBigLen = (encodedPublicPoint.length - 1) / 2 * 8;
          return new PrivateKeyInfo(algId,
              new org.bouncycastle.asn1.sec.ECPrivateKey(orderBigLen,
                  new BigInteger(1, privValue), new DERBitString(encodedPublicPoint), null));
        }
      } catch (TokenException | IOException ex) {
        throw new P11TokenException("could not generate keypair " + Functions.ckmCodeToName(mech), ex);
      } finally {
        destroyKeyPairQuietly(session, keypair);
      }
    } finally {
      sessions.requite(bagEntry);
    }

  }

  @Override
  protected P11Identity generateSM2Keypair0(P11NewKeyControl control) throws P11TokenException {
    long ckm = CKM_VENDOR_SM2_KEY_PAIR_GEN;
    if (supportsMechanism(ckm)) {
      AttributeVector privateKey = newPrivateKey(CKK_VENDOR_SM2);
      AttributeVector publicKey = newPublicKey(CKK_VENDOR_SM2);
      publicKey.ecParams(Hex.decode("06082A811CCF5501822D"));
      setKeyAttributes(control, publicKey, privateKey, newObjectConf);

      return generateKeyPair(ckm, control.getId(), privateKey, publicKey);
    } else {
      return generateECKeypair0(GMObjectIdentifiers.sm2p256v1, control);
    }
  } // method generateSM2Keypair0

  @Override
  protected PrivateKeyInfo generateSM2KeypairOtf0() throws P11TokenException {
    long ckm = CKM_VENDOR_SM2_KEY_PAIR_GEN;
    if (supportsMechanism(ckm)) {
      return generateECKeypairOtf0(CKK_VENDOR_SM2, ckm, GMObjectIdentifiers.sm2p256v1);
    } else {
      return generateECKeypairOtf0(GMObjectIdentifiers.sm2p256v1);
    }
  }

  private P11Identity generateKeyPair(
      long mech, byte[] id, AttributeVector privateKeyTemplate, AttributeVector publicKeyTemplate)
      throws P11TokenException {
    long keyType = privateKeyTemplate.getAttributeLongValue(CKA_KEY_TYPE);
    char[] labelChars = privateKeyTemplate.getAttributeCharArrayValue(CKA_LABEL);

    boolean succ = false;

    try {
      KeyPair keypair;
      ConcurrentBagEntry<Session> bagEntry = borrowSession();
      try {
        Session session = bagEntry.value();
        if (labelChars != null && labelExists(session, labelChars)) {
          throw new IllegalArgumentException("label " + new String(labelChars) + " exists, please specify another one");
        }

        if (id == null) {
          id = generateId(session);
        }

        privateKeyTemplate.id(id);
        publicKeyTemplate.id(id);

        try {
          keypair = session.generateKeyPair(Mechanism.get(mech), publicKeyTemplate, privateKeyTemplate);
        } catch (TokenException ex) {
          throw new P11TokenException("could not generate keypair " + Functions.ckmCodeToName(mech), ex);
        }

        String pubKeyLabel;

        try {
          labelChars = session.getCharAttributeValue(keypair.getPrivateKey(), CKA_LABEL);
          if (labelChars == null) {
            throw new P11TokenException("Label of the generated PrivateKey is not set");
          }

          pubKeyLabel = session.getCharAttributeStringValue(keypair.getPublicKey(), CKA_LABEL);
        } catch (PKCS11Exception ex) {
          throw new P11TokenException("error getting attribute CKA_LABEL", ex);
        }

        P11ObjectIdentifier objId = new P11ObjectIdentifier(id, new String(labelChars));
        java.security.PublicKey jcePublicKey;
        try {
          jcePublicKey = generatePublicKey(session, keypair.getPublicKey(), keyType);
        } catch (XiSecurityException ex) {
          throw new P11TokenException("could not generate public key " + objId, ex);
        }

        Long privKey2 = getKeyObject(session, CKO_PRIVATE_KEY, null, id, labelChars);
        if (privKey2 == null) {
          throw new P11TokenException("could not read the generated private key");
        }

        // certificate: some vendors generate also certificate
        String certLabel = null;
        X509Cert[] certs = null;

        if (supportCert) {
          Long cert2 = getCertificateObject(session, id, null);
          if (cert2 != null) {
            CharArrayAttribute labelAttr = new CharArrayAttribute(CKA_LABEL);
            ByteArrayAttribute valueAttr = new ByteArrayAttribute(CKA_VALUE);
            try {
              session.getAttributeValues(cert2, labelAttr, valueAttr);
            } catch (PKCS11Exception e) {
              throw new P11TokenException("could not get attributes", e);
            }

            certLabel = labelAttr.getStringValue();
            certs = new X509Cert[1];
            try {
              certs[0] = X509Util.parseCert(valueAttr.getByteArrayValue());
            } catch (CertificateException ex) {
              throw new P11TokenException("could not parse certificate", ex);
            }
          }
        }

        P11IdentityId entityId = new P11IdentityId(slotId, objId, true, pubKeyLabel, certs != null, certLabel);
        IaikP11Identity ret = new IaikP11Identity(this, entityId, privKey2, keyType, jcePublicKey, certs);
        succ = true;
        return ret;
      } finally {
        sessions.requite(bagEntry);
      }
    } finally {
      if (!succ && (id != null)) {
        try {
          removeObjects(id, false, labelChars);
        } catch (Throwable th) {
          LogUtil.error(LOG, th, "could not remove objects");
        }
      }
    }
  } // method generateKeyPair

  private AttributeVector createPkcs11Template(
      Session session, X509Cert cert, P11NewObjectControl control, boolean omitDateAttrs)
      throws P11TokenException {
    byte[] id = control.getId();
    if (id == null) {
      id = generateId(session);
    }

    AttributeVector newCertTemp = new AttributeVector().id(id).token(true).certificateType(CKC_X_509);

    if (newObjectConf.isIgnoreLabel()) {
      if (control.getLabel() != null) {
        LOG.warn("label is set, but ignored: '{}'", control.getLabel());
      }
    } else {
      newCertTemp.label(control.getLabel());
    }

    Set<Long> setCertAttributes = newObjectConf.getSetCertObjectAttributes();

    try {
      if (setCertAttributes.contains(CKA_SUBJECT)) {
        newCertTemp.subject(cert.getSubject().getEncoded());
      }

      if (setCertAttributes.contains(CKA_ISSUER)) {
        newCertTemp.issuer(cert.getIssuer().getEncoded());
      }
    } catch (IOException ex) {
      throw new P11TokenException("error encoding certificate: " + ex.getMessage(), ex);
    }

    if (setCertAttributes.contains(CKA_SERIAL_NUMBER)) {
      newCertTemp.serialNumber(Util.unsignedBigIntergerToByteArray(cert.getSerialNumber()));
    }

    if (!omitDateAttrs) {
      if (setCertAttributes.contains(CKA_START_DATE)) {
        newCertTemp.startDate(cert.getNotBefore());
      }

      if (setCertAttributes.contains(CKA_END_DATE)) {
        newCertTemp.endDate(cert.getNotAfter());
      }
    }

    return newCertTemp;
  } // method createPkcs11Template

  @Override
  protected void updateCertificate0(P11ObjectIdentifier keyId, X509Cert newCert)
      throws P11TokenException {
    try {
      removeCerts(keyId);
    } catch (P11UnknownEntityException ex) {
      // certificates do not exist, do nothing
    }

    try {
      Thread.sleep(1000);
    } catch (InterruptedException ex) {
    }

    addCert0(newCert, new P11NewObjectControl(keyId.getId(), keyId.getLabel()));
  } // method updateCertificate0

  @Override
  protected void removeIdentity0(P11IdentityId identityId) throws P11TokenException {
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();
      P11ObjectIdentifier keyId = identityId.getKeyId();
      byte[] id = keyId.getId();
      char[] label = keyId.getLabelChars();
      Long secretKey = getKeyObject(session, CKO_SECRET_KEY, null, id, label);
      destroyObject(session, secretKey, "secret key " + keyId);

      Long privKey = getKeyObject(session, CKO_PRIVATE_KEY, null, id, label);
      destroyObject(session, privKey, "private key " + keyId);

      P11ObjectIdentifier pubKeyId = identityId.getPublicKeyId();
      if (pubKeyId != null) {
        Long pubKey = getKeyObject(session, CKO_PUBLIC_KEY, null, pubKeyId.getId(), pubKeyId.getLabelChars());
        destroyObject(session, pubKey, "public key " + keyId);
      }

      P11ObjectIdentifier certId = identityId.getCertId();
      if (certId != null) {
        List<Long> certs = getCertificateObjects(session, certId.getId(), certId.getLabelChars());
        if (certs != null && !certs.isEmpty()) {
          for (Long cert : certs) {
            destroyObject(session, cert, "certificate " + certId);
          }
        }
      }
    } finally {
      sessions.requite(bagEntry);
    }
  } // method removeIdentity0

  private byte[] generateId(Session session) throws P11TokenException {
    while (true) {
      byte[] keyId = new byte[newObjectConf.getIdLength()];
      random.nextBytes(keyId);
      // clear the first bit
      keyId[0] = (byte) (0x7F & keyId[0]);

      if (existsIdentityForId(keyId) || existsCertForId(keyId)) {
        continue;
      }

      AttributeVector template = new AttributeVector().id(keyId);
      if (isEmpty(getObjects(session, template, 1))) {
        return keyId;
      }
    }
  }

  private boolean labelExists(Session session, char[] keyLabel) throws P11TokenException {
    notNull(keyLabel, "keyLabel");

    String strLabel = new String(keyLabel);
    if (existsIdentityForLabel(strLabel) || existsCertForLabel(strLabel)) {
      return true;
    }

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
        long keyType = privateKey.getAttributeLongValue(CKA_KEY_TYPE);
        // if not set
        if (keyType == PKCS11Constants.CKK_EC || keyType == PKCS11Constants.CKK_RSA
            || keyType == PKCS11Constants.CKK_DSA) {
          privateKey.sign(true);
        }

        if (keyType == CKK_VENDOR_SM2) {
          privateKey.sign(true);
        }

        if (keyType == PKCS11Constants.CKK_RSA) {
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

  private static void destroyKeyPairQuietly(Session session, KeyPair keypair) {
    if (keypair != null) {
      try {
        session.destroyObject(keypair.getPrivateKey());
      } catch (TokenException ex) {
        LogUtil.warn(LOG, ex, "error destroying private key " + keypair.getPrivateKey());
      }

      try {
        session.destroyObject(keypair.getPublicKey());
      } catch (TokenException ex) {
        LogUtil.warn(LOG, ex, "error destroying public key " + keypair.getPublicKey());
      }
    }
  }

  private static void destroyObject(Session session, Long hObject, String objectDesc)
      throws P11TokenException {
    if (hObject != null) {
      try {
        session.destroyObject(hObject);
      } catch (TokenException ex) {
        String msg = "could not destroy " + objectDesc;
        LogUtil.error(LOG, ex, msg);
        throw new P11TokenException(msg);
      }
    }
  }

}
