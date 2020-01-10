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

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.EdECConstants;
import org.xipki.security.X509Cert;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.P11Identity;
import org.xipki.security.pkcs11.P11IdentityId;
import org.xipki.security.pkcs11.P11ModuleConf.P11MechanismFilter;
import org.xipki.security.pkcs11.P11ModuleConf.P11NewObjectConf;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Params;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.security.pkcs11.P11TokenException;
import org.xipki.security.pkcs11.P11UnknownEntityException;
import org.xipki.security.pkcs11.iaik.IaikP11Module.Vendor;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.concurrent.ConcurrentBag;
import org.xipki.util.concurrent.ConcurrentBagEntry;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.SessionInfo;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.State;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.Util;
import iaik.pkcs.pkcs11.objects.Attribute;
import iaik.pkcs.pkcs11.objects.Certificate.CertificateType;
import iaik.pkcs.pkcs11.objects.DSAPrivateKey;
import iaik.pkcs.pkcs11.objects.DSAPublicKey;
import iaik.pkcs.pkcs11.objects.ECPrivateKey;
import iaik.pkcs.pkcs11.objects.ECPublicKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.Key.KeyType;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PKCS11Object;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.objects.SecretKey;
import iaik.pkcs.pkcs11.objects.Storage;
import iaik.pkcs.pkcs11.objects.ValuedSecretKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.parameters.OpaqueParameters;
import iaik.pkcs.pkcs11.parameters.Parameters;
import iaik.pkcs.pkcs11.parameters.RSAPkcsPssParameters;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

/**
 * {@link P11Slot} based on the IAIK PKCS#11 wrapper.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
class IaikP11Slot extends P11Slot {

  private static final Logger LOG = LoggerFactory.getLogger(IaikP11Slot.class);

  private static final long DEFAULT_MAX_COUNT_SESSION = 32;

  private final int maxMessageSize;

  private Slot slot;

  private final String userTypeText;

  private final long userType;

  private List<char[]> password;

  private int maxSessionCount;

  private long timeOutWaitNewSession = 10000; // maximal wait for 10 second

  private final AtomicLong countSessions = new AtomicLong(0);

  private final SecureRandom random = new SecureRandom();

  private final P11NewObjectConf newObjectConf;

  private final ConcurrentBag<ConcurrentBagEntry<Session>> sessions = new ConcurrentBag<>();

  private final Vendor vendor;

  IaikP11Slot(String moduleName, P11SlotIdentifier slotId, Slot slot, boolean readOnly,
      long userType, List<char[]> password, int maxMessageSize, P11MechanismFilter mechanismFilter,
      P11NewObjectConf newObjectConf, Vendor vendor) throws P11TokenException {
    super(moduleName, slotId, readOnly, mechanismFilter);

    this.newObjectConf = Args.notNull(newObjectConf, "newObjectConf");
    this.slot = Args.notNull(slot, "slot");
    this.maxMessageSize = Args.positive(maxMessageSize, "maxMessageSize");
    this.vendor = Args.notNull(vendor,"vendo r");

    this.userType = userType;
    if (userType == PKCS11Constants.CKU_SO) {
      userTypeText = "CKU_SO";
    } else if (userType == PKCS11Constants.CKU_USER) {
      userTypeText = "CKU_USER";
    } else if (userType == PKCS11Constants.CKU_CONTEXT_SPECIFIC) {
      userTypeText = "CKU_CONTEXT_SPECIFIC";
    } else {
      userTypeText = "VENDOR_" + userType;
    }

    this.password = password;

    boolean successful = false;

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

      if (maxSessionCount2 == 0) {
        maxSessionCount2 = DEFAULT_MAX_COUNT_SESSION;
      } else {
        // 2 sessions as buffer, they may be used elsewhere.
        maxSessionCount2 = (maxSessionCount2 < 3) ? 1 : maxSessionCount2 - 2;
      }
      this.maxSessionCount = (int) maxSessionCount2;
      LOG.info("maxSessionCount: {}", this.maxSessionCount);

      sessions.add(new ConcurrentBagEntry<Session>(session));
      refresh();
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
      for (Mechanism mech : mechanisms) {
        ret.addMechanism(mech.getMechanismCode());
      }
    }

    ConcurrentBagEntry<Session> bagEntry = borrowSession();

    try {
      Session session = bagEntry.value();
      // secret keys
      List<SecretKey> secretKeys = getAllSecretKeyObjects(session);
      for (SecretKey secKey : secretKeys) {
        byte[] keyId = secKey.getId().getByteArrayValue();
        if (keyId == null || keyId.length == 0) {
          continue;
        }

        analyseSingleKey(secKey, ret);
      }

      // first get the list of all CA certificates
      List<X509PublicKeyCertificate> p11Certs = getAllCertificateObjects(session);
      for (X509PublicKeyCertificate p11Cert : p11Certs) {
        byte[] id = p11Cert.getId().getByteArrayValue();
        char[] label = p11Cert.getLabel().getCharArrayValue();
        if (id != null && label != null) {
          P11ObjectIdentifier objId = new P11ObjectIdentifier(id, new String(label));
          ret.addCertificate(objId, parseCert(p11Cert));
        }
      }

      List<PrivateKey> privKeys = getAllPrivateObjects(session);

      for (PrivateKey privKey : privKeys) {
        byte[] keyId = privKey.getId().getByteArrayValue();

        try {
          analyseSingleKey(session, privKey, ret);
        } catch (XiSecurityException ex) {
          LogUtil.error(LOG, ex, "XiSecurityException while initializing private key "
              + "with id " + hex(keyId));
          continue;
        } catch (Throwable th) {
          String label = "";
          if (privKey.getLabel() != null) {
            label = new String(privKey.getLabel().getCharArrayValue());
          }
          LOG.error("unexpected exception while initializing private key with id "
              + hex(keyId) + " and label " + label, th);
          continue;
        }
      }

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

  private void analyseSingleKey(SecretKey secretKey, P11SlotRefreshResult refreshResult) {
    byte[] id = secretKey.getId().getByteArrayValue();
    char[] label = secretKey.getLabel().getCharArrayValue();
    if (id == null || label == null) {
      return;
    }

    P11ObjectIdentifier objectId = new P11ObjectIdentifier(id, new String(label));

    IaikP11Identity identity = new IaikP11Identity(this,
        new P11IdentityId(slotId, objectId, null, null), secretKey);
    refreshResult.addIdentity(identity);
  } // method analyseSingleKey

  private void analyseSingleKey(Session session, PrivateKey privKey,
      P11SlotRefreshResult refreshResult) throws P11TokenException, XiSecurityException {
    byte[] id = privKey.getId().getByteArrayValue();
    char[] label = privKey.getLabel().getCharArrayValue();
    if (id == null || label == null) {
      return;
    }

    String pubKeyLabel = null;
    PublicKey p11PublicKey = getPublicKeyObject(session, id, null);
    if (p11PublicKey != null) {
      pubKeyLabel = new String(p11PublicKey.getLabel().getCharArrayValue());
    }

    String certLabel = null;
    java.security.PublicKey pubKey = null;
    X509Cert cert = refreshResult.getCertForId(id);

    if (cert != null) {
      certLabel = refreshResult.getCertLabelForId(id);
      pubKey = cert.getCert().getPublicKey();
    } else if (p11PublicKey != null) {
      pubKey = generatePublicKey(p11PublicKey);
    } else {
      LOG.info("neither certificate nor public key for the key (" + hex(id) + " is available");
      return;
    }

    P11ObjectIdentifier objectId = new P11ObjectIdentifier(id, new String(label));

    X509Certificate[] certs = (cert == null) ? null : new X509Certificate[]{cert.getCert()};
    IaikP11Identity identity = new IaikP11Identity(this,
        new P11IdentityId(slotId, objectId, pubKeyLabel, certLabel), privKey, pubKey, certs);
    refreshResult.addIdentity(identity);
  } // method analyseSingleKey

  byte[] digestKey(long mechanism, IaikP11Identity identity) throws P11TokenException {
    Args.notNull(identity, "identity");
    assertMechanismSupported(mechanism);
    Key key = identity.getSigningKey();
    if (!(key instanceof SecretKey)) {
      throw new P11TokenException("digestSecretKey could not be applied to non-SecretKey");
    }

    if (LOG.isTraceEnabled()) {
      LOG.debug("digest (init, digestKey, then finish)\n{}", key);
    }

    int digestLen;
    if (PKCS11Constants.CKM_SHA_1 == mechanism) {
      digestLen = 20;
    } else if (PKCS11Constants.CKM_SHA224 == mechanism
        || PKCS11Constants.CKM_SHA3_224 == mechanism) {
      digestLen = 28;
    } else if (PKCS11Constants.CKM_SHA256 == mechanism
        || PKCS11Constants.CKM_SHA3_256 == mechanism) {
      digestLen = 32;
    } else if (PKCS11Constants.CKM_SHA384 == mechanism
        || PKCS11Constants.CKM_SHA3_384 == mechanism) {
      digestLen = 48;
    } else if (PKCS11Constants.CKM_SHA512 == mechanism
        || PKCS11Constants.CKM_SHA3_512 == mechanism) {
      digestLen = 64;
    } else {
      throw new P11TokenException("unsupported mechnism " + mechanism);
    }

    ConcurrentBagEntry<Session> session0 = borrowSession();
    Mechanism mechanismObj = Mechanism.get(mechanism);

    try {
      Session session = session0.value();
      try {
        return digestKey0(session, digestLen, mechanismObj, (SecretKey) key);
      } catch (PKCS11Exception ex) {
        if (ex.getErrorCode() != PKCS11Constants.CKR_USER_NOT_LOGGED_IN) {
          throw new P11TokenException(ex.getMessage(), ex);
        }

        LOG.info("digestKey ended with ERROR CKR_USER_NOT_LOGGED_IN, login and then retry it");
        // force the login
        forceLogin(session);
        try {
          return digestKey0(session, digestLen, mechanismObj, (SecretKey) key);
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

  private byte[] digestKey0(Session session, int digestLen, Mechanism mechanism, SecretKey key)
      throws TokenException {
    session.digestInit(mechanism);
    session.digestKey(key);
    byte[] digest = new byte[digestLen];
    session.digestFinal(digest, 0, digestLen);
    return digest;
  } // method digestKey0

  byte[] sign(long mechanism, P11Params parameters, byte[] content, IaikP11Identity identity)
      throws P11TokenException {
    Args.notNull(content, "content");
    assertMechanismSupported(mechanism);

    int expectedSignatureLen;
    if (mechanism == PKCS11Constants.CKM_SHA_1_HMAC) {
      expectedSignatureLen = 20;
    } else if (mechanism == PKCS11Constants.CKM_SHA224_HMAC
        || mechanism == PKCS11Constants.CKM_SHA3_224) {
      expectedSignatureLen = 28;
    } else if (mechanism == PKCS11Constants.CKM_SHA256_HMAC
        || mechanism == PKCS11Constants.CKM_SHA3_256) {
      expectedSignatureLen = 32;
    } else if (mechanism == PKCS11Constants.CKM_SHA384_HMAC
        || mechanism == PKCS11Constants.CKM_SHA3_384) {
      expectedSignatureLen = 48;
    } else if (mechanism == PKCS11Constants.CKM_SHA512_HMAC
        || mechanism == PKCS11Constants.CKM_SHA3_512) {
      expectedSignatureLen = 64;
    } else if (mechanism == PKCS11Constants.CKM_VENDOR_SM2
        || mechanism == PKCS11Constants.CKM_VENDOR_SM2_SM3) {
      expectedSignatureLen = 32;
    } else {
      expectedSignatureLen = identity.getExpectedSignatureLen();
    }

    Mechanism mechanismObj = getMechanism(mechanism, parameters);
    Key signingKey = identity.getSigningKey();

    ConcurrentBagEntry<Session> session0 = borrowSession();
    try {
      Session session = session0.value();
      try {
        return sign0(session, expectedSignatureLen, mechanismObj, content, signingKey);
      } catch (PKCS11Exception ex) {
        long errorCode = ex.getErrorCode();
        if (errorCode == PKCS11Constants.CKR_USER_NOT_LOGGED_IN) {
          LOG.info("sign ended with ERROR CKR_USER_NOT_LOGGED_IN, login and then retry it");
          // force the login
          forceLogin(session);
          return sign0(session, expectedSignatureLen, mechanismObj, content, signingKey);
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
      byte[] content, Key signingKey) throws TokenException {
    int len = content.length;

    if (len <= maxMessageSize) {
      return singleSign(session, mechanism, content, signingKey);
    }

    LOG.debug("sign (init, update, then finish)");

    session.signInit(mechanism, signingKey);

    for (int i = 0; i < len; i += maxMessageSize) {
      int blockLen = Math.min(maxMessageSize, len - i);
      session.signUpdate(content, i, blockLen);
    }

    return session.signFinal(expectedSignatureLen);
  } // method sign0

  private byte[] singleSign(Session session, Mechanism mechanism, byte[] content,
      Key signingKey) throws TokenException {
    LOG.debug("single sign");
    session.signInit(mechanism, signingKey);
    byte[] signature = session.sign(content);
    return signature;
  } // method singleSign

  private static Mechanism getMechanism(long mechanism, P11Params parameters)
      throws P11TokenException {
    Mechanism ret = Mechanism.get(mechanism);
    if (parameters == null) {
      return ret;
    }

    Parameters paramObj;
    if (parameters instanceof P11Params.P11RSAPkcsPssParams) {
      P11Params.P11RSAPkcsPssParams param = (P11Params.P11RSAPkcsPssParams) parameters;
      paramObj = new RSAPkcsPssParameters(param.getHashAlgorithm(),
          param.getMaskGenerationFunction(), param.getSaltLength());
    } else if (parameters instanceof P11Params.P11ByteArrayParams) {
      paramObj = new OpaqueParameters(((P11Params.P11ByteArrayParams) parameters).getBytes());
    } else if (parameters instanceof P11Params.P11IVParams) {
      paramObj = new InitializationVectorParameters(((P11Params.P11IVParams) parameters).getIV());
    } else {
      throw new P11TokenException("unknown P11Parameters " + parameters.getClass().getName());
    }

    if (paramObj != null) {
      ret.setParameters(paramObj);
    }

    return ret;
  } // method getMechanism

  private Session openSession() throws P11TokenException {
    Session session;
    try {
      boolean rw = !isReadOnly();
      session = slot.getToken().openSession(Token.SessionType.SERIAL_SESSION, rw, null, null);
    } catch (TokenException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    countSessions.incrementAndGet();
    return session;
  } // method openSession

  private ConcurrentBagEntry<Session> borrowSession() throws P11TokenException {
    ConcurrentBagEntry<Session> session = null;
    synchronized (sessions) {
      if (countSessions.get() < maxSessionCount) {
        try {
          session = sessions.borrow(1, TimeUnit.NANOSECONDS);
        } catch (InterruptedException ex) { // CHECKSTYLE:SKIP
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
      } catch (InterruptedException ex) { // CHECKSTYLE:SKIP
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
      boolean isProtectedAuthenticationPath =
          session.getToken().getTokenInfo().isProtectedAuthenticationPath();

      if (isProtectedAuthenticationPath || CollectionUtil.isEmpty(password)) {
        LOG.info("verify on PKCS11Module with PROTECTED_AUTHENTICATION_PATH");
        singleLogin(session, null);
      } else {
        LOG.info("verify on PKCS11Module with PIN");
        for (char[] singlePwd : password) {
          singleLogin(session, singlePwd);
        }
        this.password = password;
      }
    } catch (PKCS11Exception ex) {
      // 0x100: user already logged in
      if (ex.getErrorCode() != 0x100) {
        throw new P11TokenException(ex.getMessage(), ex);
      }
    } catch (TokenException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
  } // method firstLogin

  private void login(Session session) throws P11TokenException {
    boolean isSessionLoggedIn = checkSessionLoggedIn(session);
    if (isSessionLoggedIn) {
      return;
    }

    boolean loginRequired;
    try {
      loginRequired = session.getToken().getTokenInfo().isLoginRequired();
    } catch (TokenException ex) {
      LogUtil.error(LOG, ex, "could not check whether LoginRequired of token");
      loginRequired = true;
    }

    LOG.debug("loginRequired: {}", loginRequired);
    if (!loginRequired) {
      return;
    }

    if (CollectionUtil.isEmpty(password)) {
      singleLogin(session, null);
    } else {
      for (char[] singlePwd : password) {
        singleLogin(session, singlePwd);
      }
    }
  } // method login

  private void forceLogin(Session session) throws P11TokenException {
    if (CollectionUtil.isEmpty(password)) {
      LOG.info("verify on PKCS11Module with NULL PIN");
      singleLogin(session, null);
    } else {
      LOG.info("verify on PKCS11Module with PIN");
      for (char[] singlePwd : password) {
        singleLogin(session, singlePwd);
      }
    }
  } // method forceLogin

  private void singleLogin(Session session, char[] pin) throws P11TokenException {
    char[] tmpPin = pin;
    // some driver does not accept null PIN
    if (pin == null) {
      tmpPin = new char[]{};
    }

    try {
      session.login(userType, tmpPin);
      LOG.info("login successful as user " + userTypeText);
    } catch (TokenException ex) {
      // 0x100: user already logged in
      if (ex instanceof PKCS11Exception && ((PKCS11Exception) ex).getErrorCode() == 0x100) {
        LOG.info("user already logged in");
      } else {
        LOG.info("login failed as user " + userTypeText);
        throw new P11TokenException(
            "login failed as user " + userTypeText + ": " + ex.getMessage(), ex);
      }
    }
  } // method singleLogin

  private List<PrivateKey> getAllPrivateObjects(Session session) throws P11TokenException {
    PrivateKey template = new PrivateKey();
    List<Storage> tmpObjects = getObjects(session, template);
    if (CollectionUtil.isEmpty(tmpObjects)) {
      return Collections.emptyList();
    }

    final int n = tmpObjects.size();
    LOG.info("found {} private keys", n);

    List<PrivateKey> privateKeys = new ArrayList<>(n);
    for (Storage tmpObject : tmpObjects) {
      privateKeys.add((PrivateKey) tmpObject);
    }

    return privateKeys;
  } // method getAllPrivateObjects

  private List<SecretKey> getAllSecretKeyObjects(Session session) throws P11TokenException {
    SecretKey template = new SecretKey();
    List<Storage> tmpObjects = getObjects(session, template);
    if (CollectionUtil.isEmpty(tmpObjects)) {
      return Collections.emptyList();
    }

    final int n = tmpObjects.size();
    LOG.info("found {} private keys", n);

    List<SecretKey> keys = new ArrayList<>(n);
    for (Storage tmpObject : tmpObjects) {
      keys.add((SecretKey) tmpObject);
    }

    return keys;
  } // method getAllSecretKeyObjects

  private SecretKey getSecretKeyObject(Session session, byte[] keyId, char[] keyLabel)
      throws P11TokenException {
    return (SecretKey) getKeyObject(session, new SecretKey(), keyId, keyLabel);
  }

  private PrivateKey getPrivateKeyObject(Session session, byte[] keyId, char[] keyLabel)
      throws P11TokenException {
    return (PrivateKey) getKeyObject(session, new PrivateKey(), keyId, keyLabel);
  }

  private PublicKey getPublicKeyObject(Session session, byte[] keyId, char[] keyLabel)
      throws P11TokenException {
    return (PublicKey) getKeyObject(session, new PublicKey(), keyId, keyLabel);
  }

  private Key getKeyObject(Session session, Key template, byte[] keyId, char[] keyLabel)
      throws P11TokenException {
    if (keyId != null) {
      template.getId().setByteArrayValue(keyId);
    }
    if (keyLabel != null) {
      template.getLabel().setCharArrayValue(keyLabel);
    }

    List<Storage> tmpObjects = getObjects(session, template, 2);
    if (CollectionUtil.isEmpty(tmpObjects)) {
      return null;
    }
    int size = tmpObjects.size();
    if (size > 1) {
      LOG.warn("found {} public key identified by {}, use the first one", size,
          getDescription(keyId, keyLabel));
    }

    return (Key) tmpObjects.get(0);
  } // method getKeyObject

  private X509PublicKeyCertificate getCertificateObject(Session session, byte[] keyId,
      char[] keyLabel) throws P11TokenException {
    X509PublicKeyCertificate template = new X509PublicKeyCertificate();
    if (keyId != null) {
      template.getId().setByteArrayValue(keyId);
    }
    if (keyLabel != null) {
      template.getLabel().setCharArrayValue(keyLabel);
    }

    List<Storage> tmpObjects = getObjects(session, template, 2);

    if (CollectionUtil.isEmpty(tmpObjects)) {
      LOG.info("found no certificate identified by {}", getDescription(keyId, keyLabel));
      return null;
    }

    int size = tmpObjects.size();
    if (size > 1) {
      LOG.warn("found {} public key identified by {}, use the first one", size,
          getDescription(keyId, keyLabel));
    }

    return (X509PublicKeyCertificate) tmpObjects.get(0);
  } // method getCertificateObject

  private boolean checkSessionLoggedIn(Session session) throws P11TokenException {
    SessionInfo info;
    try {
      info = session.getSessionInfo();
    } catch (TokenException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    if (LOG.isTraceEnabled()) {
      LOG.debug("SessionInfo: {}", info);
    }

    State state = info.getState();
    long deviceError = info.getDeviceError();

    LOG.debug("to be verified PKCS11Module: state = {}, deviceError: {}", state, deviceError);
    if (deviceError != 0) {
      LOG.error("deviceError {}", deviceError);
      return false;
    }

    boolean sessionLoggedIn;
    if (userType == PKCS11Constants.CKU_SO) {
      sessionLoggedIn = state.equals(State.RW_SO_FUNCTIONS);
    } else {
      sessionLoggedIn = state.equals(State.RW_USER_FUNCTIONS)
          || state.equals(State.RO_USER_FUNCTIONS);
    }

    LOG.debug("sessionLoggedIn: {}", sessionLoggedIn);
    return sessionLoggedIn;
  } // method checkSessionLoggedIn

  private static List<Storage> getObjects(Session session, Storage template)
      throws P11TokenException {
    return getObjects(session, template, 9999);
  }

  private static List<Storage> getObjects(Session session, Storage template, int maxNo)
      throws P11TokenException {
    List<Storage> objList = new LinkedList<>();

    try {
      session.findObjectsInit(template);

      while (objList.size() < maxNo) {
        PKCS11Object[] foundObjects = session.findObjects(1);
        if (foundObjects == null || foundObjects.length == 0) {
          break;
        }

        for (PKCS11Object object : foundObjects) {
          logPkcs11ObjectAttributes("found object: ", object);
          objList.add((Storage) object);
        }
      }
    } catch (TokenException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    } finally {
      try {
        session.findObjectsFinal();
      } catch (Exception ex) {
        LogUtil.error(LOG, ex, "session.findObjectsFinal() failed");
      }
    }

    return objList;
  } // method getObjects

  private static java.security.PublicKey generatePublicKey(PublicKey p11Key)
      throws XiSecurityException {
    if (p11Key instanceof RSAPublicKey) {
      RSAPublicKey rsaP11Key = (RSAPublicKey) p11Key;
      byte[] expBytes = rsaP11Key.getPublicExponent().getByteArrayValue();
      BigInteger exp = new BigInteger(1, expBytes);

      byte[] modBytes = rsaP11Key.getModulus().getByteArrayValue();
      BigInteger mod = new BigInteger(1, modBytes);
      RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
      try {
        return KeyUtil.generateRSAPublicKey(keySpec);
      } catch (InvalidKeySpecException ex) {
        throw new XiSecurityException(ex.getMessage(), ex);
      }
    } else if (p11Key instanceof DSAPublicKey) {
      DSAPublicKey dsaP11Key = (DSAPublicKey) p11Key;

      BigInteger prime = new BigInteger(1, dsaP11Key.getPrime().getByteArrayValue()); // p
      BigInteger subPrime = new BigInteger(1,
          dsaP11Key.getSubprime().getByteArrayValue()); // q
      BigInteger base = new BigInteger(1, dsaP11Key.getBase().getByteArrayValue()); // g
      BigInteger value = new BigInteger(1, dsaP11Key.getValue().getByteArrayValue()); // y
      DSAPublicKeySpec keySpec = new DSAPublicKeySpec(value, prime, subPrime, base);
      try {
        return KeyUtil.generateDSAPublicKey(keySpec);
      } catch (InvalidKeySpecException ex) {
        throw new XiSecurityException(ex.getMessage(), ex);
      }
    } else if (p11Key instanceof ECPublicKey) {
      ECPublicKey ecP11Key = (ECPublicKey) p11Key;
      long keyType = ecP11Key.getKeyType().getLongValue().longValue();
      byte[] ecParameters = ecP11Key.getEcdsaParams().getByteArrayValue();
      byte[] encodedPoint = DEROctetString.getInstance(
          ecP11Key.getEcPoint().getByteArrayValue()).getOctets();

      if (keyType == KeyType.EC_EDWARDS || keyType == KeyType.EC_MONTGOMERY) {
        ASN1ObjectIdentifier algOid = ASN1ObjectIdentifier.getInstance(ecParameters);
        if (keyType == KeyType.EC_EDWARDS) {
          if (!EdECConstants.isEdwardsCurve(algOid)) {
            throw new XiSecurityException("unknown Edwards curve OID " + algOid);
          }
        } else {
          if (!EdECConstants.isMontgomeryCurve(algOid)) {
            throw new XiSecurityException("unknown Montgomery curve OID " + algOid);
          }
        }
        SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(algOid),
            encodedPoint);
        try {
          return KeyUtil.generatePublicKey(pkInfo);
        } catch (InvalidKeySpecException ex) {
          throw new XiSecurityException(ex.getMessage(), ex);
        }
      } else {
        try {
          return KeyUtil.createECPublicKey(ecParameters, encodedPoint);
        } catch (InvalidKeySpecException ex) {
          throw new XiSecurityException(ex.getMessage(), ex);
        }
      }
    } else {
      throw new XiSecurityException("unknown publicKey class " + p11Key.getClass().getName());
    }
  } // method generatePublicKey

  private static X509Cert parseCert(X509PublicKeyCertificate p11Cert) throws P11TokenException {
    try {
      byte[] encoded = p11Cert.getValue().getByteArrayValue();
      return new X509Cert(X509Util.parseCert(encoded), encoded);
    } catch (CertificateException ex) {
      throw new P11TokenException("could not parse certificate: " + ex.getMessage(), ex);
    }
  } // method parseCert

  private List<X509PublicKeyCertificate> getAllCertificateObjects(Session session)
      throws P11TokenException {
    X509PublicKeyCertificate template = new X509PublicKeyCertificate();
    List<Storage> tmpObjects = getObjects(session, template);

    List<X509PublicKeyCertificate> certs = new ArrayList<>(tmpObjects.size());
    for (PKCS11Object tmpObject : tmpObjects) {
      X509PublicKeyCertificate cert = (X509PublicKeyCertificate) tmpObject;
      certs.add(cert);
    }
    return certs;
  } // method getAllCertificateObjects

  @Override
  public int removeObjects(byte[] id, String label) throws P11TokenException {
    return removeObjects(id, (label == null) ? null : label.toCharArray());
  }

  private int removeObjects(byte[] id, char[] label) throws P11TokenException {
    boolean labelNotBlank = (label != null && label.length != 0);
    if ((id == null || id.length == 0) && !labelNotBlank) {
      throw new IllegalArgumentException("at least one of id and label may not be null");
    }

    Key keyTemplate = new Key();
    if (id != null && id.length > 0) {
      keyTemplate.getId().setByteArrayValue(id);
    }
    if (labelNotBlank) {
      keyTemplate.getLabel().setCharArrayValue(label);
    }

    String objIdDesc = getDescription(id, label);
    int num = removeObjects(keyTemplate, "keys " + objIdDesc);

    X509PublicKeyCertificate certTemplate = new X509PublicKeyCertificate();
    if (id != null && id.length > 0) {
      certTemplate.getId().setByteArrayValue(id);
    }
    if (labelNotBlank) {
      certTemplate.getLabel().setCharArrayValue(label);
    }

    num += removeObjects(certTemplate, "certificates" + objIdDesc);
    return num;
  } // method removeObjects

  private int removeObjects(Storage template, String desc) throws P11TokenException {
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();
      List<Storage> objects = getObjects(session, template);
      for (Storage obj : objects) {
        if (vendor == Vendor.YUBIKEY) {
          if (obj instanceof X509PublicKeyCertificate) {
            throw new P11TokenException("cannot delete certificates in Yubikey token");
          } else if (obj instanceof PrivateKey
              || obj instanceof PublicKey) {
            // do nothing: In yubikey, the triple (private key, public key, certificate) will be
            // deleted only be deleting the certificate.
          }
        }

        session.destroyObject(obj);
      }
      return objects.size();
    } catch (TokenException ex) {
      LogUtil.error(LOG, ex, "could not remove " + desc);
      throw new P11TokenException(ex.getMessage(), ex);
    } finally {
      sessions.requite(bagEntry);
    }
  } // method removeObjects

  @Override
  protected void removeCerts0(P11ObjectIdentifier objectId) throws P11TokenException {
    if (vendor == Vendor.YUBIKEY) {
      throw new P11TokenException("Unsupported operation removeCerts() in yubikey token");
    }

    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();
      X509PublicKeyCertificate[] existingCerts = getCertificateObjects(session, objectId.getId(),
          objectId.getLabelChars());
      if (existingCerts == null || existingCerts.length == 0) {
        LOG.warn("could not find certificates " + objectId);
        return;
      }

      for (X509PublicKeyCertificate cert : existingCerts) {
        session.destroyObject(cert);
      }
    } catch (TokenException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    } finally {
      sessions.requite(bagEntry);
    }
  } // method removeCerts0

  @Override
  protected P11ObjectIdentifier addCert0(X509Certificate cert, P11NewObjectControl control)
      throws P11TokenException {
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();
      X509PublicKeyCertificate newCertTemp =
          createPkcs11Template(session, new X509Cert(cert), control);
      X509PublicKeyCertificate newCert =
          (X509PublicKeyCertificate) session.createObject(newCertTemp);

      return new P11ObjectIdentifier(newCert.getId().getByteArrayValue(),
          new String(newCert.getLabel().getCharArrayValue()));
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

    long mech;
    if (PKCS11Constants.CKK_AES == keyType) {
      mech = PKCS11Constants.CKM_AES_KEY_GEN;
    } else if (PKCS11Constants.CKK_DES3 == keyType) {
      mech = PKCS11Constants.CKM_DES3_KEY_GEN;
    } else if (PKCS11Constants.CKK_GENERIC_SECRET == keyType) {
      mech = PKCS11Constants.CKM_GENERIC_SECRET_KEY_GEN;
    } else if (PKCS11Constants.CKK_SHA_1_HMAC == keyType
        || PKCS11Constants.CKK_SHA224_HMAC == keyType
        || PKCS11Constants.CKK_SHA256_HMAC == keyType
        || PKCS11Constants.CKK_SHA384_HMAC == keyType
        || PKCS11Constants.CKK_SHA512_HMAC == keyType
        || PKCS11Constants.CKK_SHA3_224_HMAC == keyType
        || PKCS11Constants.CKK_SHA3_256_HMAC == keyType
        || PKCS11Constants.CKK_SHA3_384_HMAC == keyType
        || PKCS11Constants.CKK_SHA3_512_HMAC == keyType) {
      mech = PKCS11Constants.CKM_GENERIC_SECRET_KEY_GEN;
    } else {
      throw new IllegalArgumentException(
          "unsupported key type 0x" + Functions.toFullHex((int)keyType));
    }

    assertMechanismSupported(mech);

    char[] labelChars = newObjectConf.isIgnoreLabel() ? null : control.getLabel().toCharArray();
    byte[] id = control.getId();

    ValuedSecretKey template = new ValuedSecretKey(keyType);

    template.getToken().setBooleanValue(true);
    if (labelChars != null) {
      template.getLabel().setCharArrayValue(labelChars);
    }

    if (control.getExtractable() != null) {
      template.getExtractable().setBooleanValue(control.getExtractable());
    }

    if (control.getSensitive() != null) {
      template.getSensitive().setBooleanValue(control.getSensitive());
    }

    Set<P11KeyUsage> usages = control.getUsages();
    // CHECKSTYLE:SKIP
    final Boolean TRUE = Boolean.TRUE;
    if (CollectionUtil.isNotEmpty(usages)) {
      for (P11KeyUsage usage : usages) {
        switch (usage) {
          case DECRYPT:
            template.getDecrypt().setBooleanValue(TRUE);
            break;
          case DERIVE:
            template.getDerive().setBooleanValue(TRUE);
            break;
          case SIGN:
            template.getSign().setBooleanValue(TRUE);
            break;
          case UNWRAP:
            template.getUnwrap().setBooleanValue(TRUE);
            break;
          default:
            break;
        }
      }
    }

    template.getValueLen().setLongValue((long) (keysize / 8));

    Mechanism mechanism = Mechanism.get(mech);
    SecretKey key;
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();
      if (labelChars != null && labelExists(session, labelChars)) {
        throw new IllegalArgumentException(
            "label " + control.getLabel() + " exists, please specify another one");
      }

      if (id == null) {
        id = generateId(session);
      }

      template.getId().setByteArrayValue(id);

      try {
        key = (SecretKey) session.generateKey(mechanism, template);
      } catch (TokenException ex) {
        throw new P11TokenException("could not generate generic secret key using "
            + mechanism.getName(), ex);
      }

      labelChars = key.getLabel().getCharArrayValue();

      P11ObjectIdentifier objId = new P11ObjectIdentifier(id, new String(labelChars));
      P11IdentityId entityId = new P11IdentityId(slotId, objId, null, null);

      return new IaikP11Identity(this, entityId, key);
    } finally {
      sessions.requite(bagEntry);
    }
  } // method generateSecretKey0

  @Override
  protected P11Identity importSecretKey0(long keyType, byte[] keyValue, P11NewKeyControl control)
      throws P11TokenException {

    ValuedSecretKey template = new ValuedSecretKey(keyType);
    template.getToken().setBooleanValue(true);

    char[] labelChars = newObjectConf.isIgnoreLabel() ? null : control.getLabel().toCharArray();
    if (labelChars != null) {
      template.getLabel().setCharArrayValue(labelChars);
    }

    if (control.getExtractable() != null) {
      template.getExtractable().setBooleanValue(control.getExtractable());
    }

    if (control.getSensitive() != null) {
      template.getSensitive().setBooleanValue(control.getSensitive());
    }

    template.getValue().setByteArrayValue(keyValue);

    Set<P11KeyUsage> usages = control.getUsages();
    // CHECKSTYLE:SKIP
    final Boolean TRUE = Boolean.TRUE;
    if (CollectionUtil.isNotEmpty(usages)) {
      for (P11KeyUsage usage : usages) {
        switch (usage) {
          case DECRYPT:
            template.getDecrypt().setBooleanValue(TRUE);
            break;
          case DERIVE:
            template.getDerive().setBooleanValue(TRUE);
            break;
          case SIGN:
            template.getSign().setBooleanValue(TRUE);
            break;
          case UNWRAP:
            template.getUnwrap().setBooleanValue(TRUE);
            break;
          default:
            break;
        }
      }
    }

    SecretKey key;
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();
      if (labelChars != null && labelExists(session, labelChars)) {
        throw new IllegalArgumentException(
            "label " + control.getLabel() + " exists, please specify another one");
      }

      byte[] id = control.getId();
      if (id == null) {
        id = generateId(session);
      }

      if (id != null) {
        template.getId().setByteArrayValue(id);
      }

      try {
        key = (SecretKey) session.createObject(template);
      } catch (TokenException ex) {
        throw new P11TokenException("could not create secret key", ex);
      }

      labelChars = key.getLabel().getCharArrayValue();

      P11ObjectIdentifier objId = new P11ObjectIdentifier(id, new String(labelChars));
      P11IdentityId entityId = new P11IdentityId(slotId, objId, null, null);

      return new IaikP11Identity(this, entityId, key);
    } finally {
      sessions.requite(bagEntry);
    }
  } // method importSecretKey0

  @Override
  protected P11Identity generateRSAKeypair0(int keysize, BigInteger publicExponent,
      P11NewKeyControl control) throws P11TokenException {
    long mech = PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;
    assertMechanismSupported(mech);

    RSAPrivateKey privateKey = new RSAPrivateKey();
    RSAPublicKey publicKey = new RSAPublicKey();
    setKeyAttributes(control, publicKey, privateKey);

    publicKey.getModulusBits().setLongValue((long) keysize);
    if (publicExponent != null) {
      publicKey.getPublicExponent().setByteArrayValue(publicExponent.toByteArray());
    }

    return generateKeyPair(mech, control.getId(), privateKey, publicKey);
  } // method generateRSAKeypair0

  @Override
  // CHECKSTYLE:SKIP
  protected P11Identity generateDSAKeypair0(BigInteger p, BigInteger q, BigInteger g,
      P11NewKeyControl control) throws P11TokenException {
    long mech = PKCS11Constants.CKM_DSA_KEY_PAIR_GEN;
    assertMechanismSupported(mech);

    DSAPrivateKey privateKey = new DSAPrivateKey();
    DSAPublicKey publicKey = new DSAPublicKey();
    setKeyAttributes(control, publicKey, privateKey);

    publicKey.getPrime().setByteArrayValue(Util.unsignedBigIntergerToByteArray(p));
    publicKey.getSubprime().setByteArrayValue(Util.unsignedBigIntergerToByteArray(q));
    publicKey.getBase().setByteArrayValue(Util.unsignedBigIntergerToByteArray(g));
    return generateKeyPair(mech, control.getId(), privateKey, publicKey);
  } // method generateDSAKeypair0

  @Override
  protected P11Identity generateECEdwardsKeypair0(ASN1ObjectIdentifier curveId,
      P11NewKeyControl control) throws P11TokenException {
    long mech = PKCS11Constants.CKM_EC_EDWARDS_KEY_PAIR_GEN;
    assertMechanismSupported(mech);

    ECPrivateKey privateKey = new ECPrivateKey(KeyType.EC_EDWARDS);
    ECPublicKey publicKey = new ECPublicKey(KeyType.EC_EDWARDS);
    setKeyAttributes(control, publicKey, privateKey);
    byte[] encodedCurveId;
    try {
      encodedCurveId = curveId.getEncoded();
    } catch (IOException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    publicKey.getEcdsaParams().setByteArrayValue(encodedCurveId);
    return generateKeyPair(mech, control.getId(), privateKey, publicKey);
  } // method generateECEdwardsKeypair0

  @Override
  protected P11Identity generateECMontgomeryKeypair0(ASN1ObjectIdentifier curveId,
      P11NewKeyControl control) throws P11TokenException {
    long mech = PKCS11Constants.CKM_EC_MONTGOMERY_KEY_PAIR_GEN;
    assertMechanismSupported(mech);

    ECPrivateKey privateKey = new ECPrivateKey(KeyType.EC_MONTGOMERY);
    ECPublicKey publicKey = new ECPublicKey(KeyType.EC_MONTGOMERY);
    setKeyAttributes(control, publicKey, privateKey);
    byte[] encodedCurveId;
    try {
      encodedCurveId = curveId.getEncoded();
    } catch (IOException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    publicKey.getEcdsaParams().setByteArrayValue(encodedCurveId);
    return generateKeyPair(mech, control.getId(), privateKey, publicKey);
  } // method generateECMontgomeryKeypair0

  @Override
  protected P11Identity generateECKeypair0(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws P11TokenException {
    long mech = PKCS11Constants.CKM_EC_KEY_PAIR_GEN;
    assertMechanismSupported(mech);

    ECPrivateKey privateKey = new ECPrivateKey();
    ECPublicKey publicKey = new ECPublicKey();
    setKeyAttributes(control, publicKey, privateKey);
    byte[] encodedCurveId;
    try {
      encodedCurveId = curveId.getEncoded();
    } catch (IOException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    try {
      publicKey.getEcdsaParams().setByteArrayValue(encodedCurveId);
      return generateKeyPair(mech, control.getId(), privateKey, publicKey);
    } catch (P11TokenException ex) {
      X9ECParameters ecParams = ECNamedCurveTable.getByOID(curveId);
      if (ecParams == null) {
        throw new IllegalArgumentException("could not get X9ECParameters for curve "
            + curveId.getId());
      }

      try {
        publicKey.getEcdsaParams().setByteArrayValue(ecParams.getEncoded());
      } catch (IOException ex2) {
        throw new P11TokenException(ex.getMessage(), ex);
      }
      return generateKeyPair(mech, control.getId(), privateKey, publicKey);
    }
  } // method generateECKeypair0

  @Override
  protected P11Identity generateSM2Keypair0(P11NewKeyControl control) throws P11TokenException {
    long mech = PKCS11Constants.CKM_VENDOR_SM2_KEY_PAIR_GEN;
    assertMechanismSupported(mech);

    ECPrivateKey privateKey = new ECPrivateKey(KeyType.VENDOR_SM2);
    ECPublicKey publicKey = new ECPublicKey(KeyType.VENDOR_SM2);
    setKeyAttributes(control, publicKey, privateKey);
    return generateKeyPair(mech, control.getId(), privateKey, publicKey);
  } // method generateSM2Keypair0

  private P11Identity generateKeyPair(long mech, byte[] id, PrivateKey privateKeyTemplate,
      PublicKey publicKeyTemplate) throws P11TokenException {
    char[] labelChars = null;
    if (privateKeyTemplate.getLabel() != null) {
      labelChars = privateKeyTemplate.getLabel().getCharArrayValue();
    }

    boolean succ = false;

    try {
      KeyPair keypair;
      ConcurrentBagEntry<Session> bagEntry = borrowSession();
      try {
        Session session = bagEntry.value();
        if (labelChars != null && labelExists(session, labelChars)) {
          throw new IllegalArgumentException(
              "label " + new String(labelChars) + " exists, please specify another one");
        }

        if (id == null) {
          id = generateId(session);
        }

        privateKeyTemplate.getId().setByteArrayValue(id);
        publicKeyTemplate.getId().setByteArrayValue(id);

        try {
          keypair = session.generateKeyPair(Mechanism.get(mech),
              publicKeyTemplate, privateKeyTemplate);

          labelChars = keypair.getPrivateKey().getLabel().getCharArrayValue();
        } catch (TokenException ex) {
          throw new P11TokenException("could not generate keypair "
              + Functions.mechanismCodeToString(mech), ex);
        }

        // CHECKSTYLE:SKIP
        String publicKeyLabel = new String(keypair.getPublicKey().getLabel().getCharArrayValue());

        P11ObjectIdentifier objId = new P11ObjectIdentifier(id, new String(labelChars));
        java.security.PublicKey jcePublicKey;
        try {
          jcePublicKey = generatePublicKey(keypair.getPublicKey());
        } catch (XiSecurityException ex) {
          throw new P11TokenException("could not generate public key " + objId, ex);
        }

        PrivateKey privateKey2 = getPrivateKeyObject(session, id, labelChars);
        if (privateKey2 == null) {
          throw new P11TokenException("could not read the generated private key");
        }

        // certificate: some vendors like yubico generate also certificate
        X509PublicKeyCertificate cert2 = getCertificateObject(session, id, null);
        String certLabel = null;
        X509Certificate[] certs = null;
        if (cert2 != null) {
          certLabel = new String(cert2.getLabel().getCharArrayValue());
          certs = new X509Certificate[1];
          try {
            certs[0] = X509Util.parseCert(cert2.getValue().getByteArrayValue());
          } catch (CertificateException ex) {
            throw new P11TokenException("coult not parse certifcate", ex);
          }
        }

        P11IdentityId entityId = new P11IdentityId(slotId, objId, publicKeyLabel, certLabel);
        IaikP11Identity ret = new IaikP11Identity(this, entityId, privateKey2, jcePublicKey, certs);
        succ = true;
        return ret;
      } finally {
        sessions.requite(bagEntry);
      }
    } finally {
      if (!succ && (id != null || labelChars != null)) {
        try {
          removeObjects(id, labelChars);
        } catch (Throwable th) {
          LogUtil.error(LOG, th, "could not remove objects");
        }
      }
    }
  } // method generateKeyPair

  private X509PublicKeyCertificate createPkcs11Template(Session session, X509Cert cert,
      P11NewObjectControl control) throws P11TokenException {
    X509PublicKeyCertificate newCertTemp = new X509PublicKeyCertificate();
    byte[] id = control.getId();
    if (id == null) {
      id = generateId(session);
    }

    newCertTemp.getId().setByteArrayValue(id);

    if (!newObjectConf.isIgnoreLabel()) {
      newCertTemp.getLabel().setCharArrayValue(control.getLabel().toCharArray());
    }

    newCertTemp.getToken().setBooleanValue(true);
    newCertTemp.getCertificateType().setLongValue(CertificateType.X_509_PUBLIC_KEY);

    Set<Long> setCertAttributes = newObjectConf.getSetCertObjectAttributes();
    if (setCertAttributes.contains(PKCS11Constants.CKA_SUBJECT)) {
      newCertTemp.getSubject().setByteArrayValue(
          cert.getCert().getSubjectX500Principal().getEncoded());
    }

    if (setCertAttributes.contains(PKCS11Constants.CKA_ISSUER)) {
      newCertTemp.getIssuer().setByteArrayValue(
          cert.getCert().getIssuerX500Principal().getEncoded());
    }

    if (setCertAttributes.contains(PKCS11Constants.CKA_SERIAL_NUMBER)) {
      newCertTemp.getSerialNumber().setByteArrayValue(
          cert.getCert().getSerialNumber().toByteArray());
    }

    if (setCertAttributes.contains(PKCS11Constants.CKA_START_DATE)) {
      newCertTemp.getStartDate().setDateValue(cert.getCert().getNotBefore());
    }

    if (setCertAttributes.contains(PKCS11Constants.CKA_END_DATE)) {
      newCertTemp.getStartDate().setDateValue(cert.getCert().getNotAfter());
    }

    newCertTemp.getValue().setByteArrayValue(cert.getEncodedCert());
    return newCertTemp;
  } // method createPkcs11Template

  private void setKeyAttributes(P11NewKeyControl control,
      PublicKey publicKey, PrivateKey privateKey) {
    if (privateKey != null) {
      privateKey.getToken().setBooleanValue(true);
      if (!newObjectConf.isIgnoreLabel()) {
        privateKey.getLabel().setCharArrayValue(control.getLabel().toCharArray());
      }
      privateKey.getPrivate().setBooleanValue(true);

      if (control.getExtractable() != null) {
        privateKey.getExtractable().setBooleanValue(control.getExtractable());
      }

      if (control.getSensitive() != null) {
        privateKey.getSensitive().setBooleanValue(control.getSensitive());
      }

      Set<P11KeyUsage> usages = control.getUsages();
      // CHECKSTYLE:SKIP
      final Boolean TRUE = Boolean.TRUE;
      if (CollectionUtil.isNotEmpty(usages)) {
        for (P11KeyUsage usage : usages) {
          switch (usage) {
            case DECRYPT:
              privateKey.getDecrypt().setBooleanValue(TRUE);
              break;
            case DERIVE:
              privateKey.getDerive().setBooleanValue(TRUE);
              break;
            case SIGN:
              privateKey.getSign().setBooleanValue(TRUE);
              break;
            case SIGN_RECOVER:
              privateKey.getSignRecover().setBooleanValue(TRUE);
              break;
            case UNWRAP:
              privateKey.getUnwrap().setBooleanValue(TRUE);
              break;
            default:
              break;
          }
        }
      } else {
        long keyType = privateKey.getKeyType().getLongValue().longValue();
        // if not set
        if (keyType == PKCS11Constants.CKK_EC
            || keyType == PKCS11Constants.CKK_RSA
            || keyType == PKCS11Constants.CKK_DSA
            || keyType == PKCS11Constants.CKK_VENDOR_SM2) {
          privateKey.getSign().setBooleanValue(TRUE);
        }

        if (keyType == PKCS11Constants.CKK_RSA) {
          privateKey.getUnwrap().setBooleanValue(TRUE);
          privateKey.getDecrypt().setBooleanValue(TRUE);
        }
      }
    }

    if (publicKey != null) {
      publicKey.getToken().setBooleanValue(true);
      if (!newObjectConf.isIgnoreLabel()) {
        publicKey.getLabel().setCharArrayValue(control.getLabel().toCharArray());
      }
      publicKey.getVerify().setBooleanValue(true);
    }
  } // method setKeyAttributes

  @Override
  protected void updateCertificate0(P11ObjectIdentifier keyId, X509Certificate newCert)
      throws P11TokenException {
    try {
      removeCerts(keyId);
    } catch (P11UnknownEntityException ex) {
      // CHECKSTYLE: certificates do not exist, do nothing
    }

    try {
      Thread.sleep(1000);
    } catch (InterruptedException ex) {
      // CHECKSTYLE:SKIP
    }

    P11NewObjectControl control = new P11NewObjectControl(keyId.getId(), keyId.getLabel());
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();
      X509PublicKeyCertificate newCertTemp =
          createPkcs11Template(session, new X509Cert(newCert), control);
      session.createObject(newCertTemp);
    } catch (TokenException ex) {
      throw new P11TokenException("could not createObject: " + ex.getMessage(), ex);
    } finally {
      sessions.requite(bagEntry);
    }
  } // method updateCertificate0

  private X509PublicKeyCertificate[] getCertificateObjects(Session session, byte[] keyId,
      char[] keyLabel) throws P11TokenException {
    X509PublicKeyCertificate template = new X509PublicKeyCertificate();
    if (keyId != null) {
      template.getId().setByteArrayValue(keyId);
    }
    if (keyLabel != null) {
      template.getLabel().setCharArrayValue(keyLabel);
    }

    List<Storage> tmpObjects = getObjects(session, template);

    if (CollectionUtil.isEmpty(tmpObjects)) {
      LOG.info("found no certificate identified by {}", getDescription(keyId, keyLabel));
      return null;
    }

    int size = tmpObjects.size();
    X509PublicKeyCertificate[] certs = new X509PublicKeyCertificate[size];
    for (int i = 0; i < size; i++) {
      certs[i] = (X509PublicKeyCertificate) tmpObjects.get(i);
    }
    return certs;
  } // method getCertificateObjects

  @Override
  protected void removeIdentity0(P11IdentityId identityId) throws P11TokenException {
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();
      P11ObjectIdentifier keyId = identityId.getKeyId();
      byte[] id = keyId.getId();
      char[] label = keyId.getLabelChars();
      SecretKey secretKey = getSecretKeyObject(session, id, label);
      if (secretKey != null) {
        try {
          session.destroyObject(secretKey);
        } catch (TokenException ex) {
          String msg = "could not delete secret key " + keyId;
          LogUtil.error(LOG, ex, msg);
          throw new P11TokenException(msg);
        }
      }

      if (vendor != Vendor.YUBIKEY) {
        // Yubico: deletion of certificate implies the deletion of key pairs.
        PrivateKey privKey = getPrivateKeyObject(session, id, label);
        if (privKey != null) {
          try {
            session.destroyObject(privKey);
          } catch (TokenException ex) {
            String msg = "could not delete private key " + keyId;
            LogUtil.error(LOG, ex, msg);
            throw new P11TokenException(msg);
          }
        }

        P11ObjectIdentifier pubKeyId = identityId.getPublicKeyId();
        if (pubKeyId != null) {
          PublicKey pubKey = getPublicKeyObject(session,
              pubKeyId.getId(), pubKeyId.getLabelChars());
          if (pubKey != null) {
            try {
              session.destroyObject(pubKey);
            } catch (TokenException ex) {
              String msg = "could not delete public key " + pubKeyId;
              LogUtil.error(LOG, ex, msg);
              throw new P11TokenException(msg);
            }
          }
        }
      }

      P11ObjectIdentifier certId = identityId.getCertId();
      if (certId != null) {
        X509PublicKeyCertificate[] certs =
            getCertificateObjects(session, certId.getId(), certId.getLabelChars());
        if (certs != null && certs.length > 0) {
          for (int i = 0; i < certs.length; i++) {
            try {
              session.destroyObject(certs[i]);
            } catch (TokenException ex) {
              String msg = "could not delete certificate " + certId;
              LogUtil.error(LOG, ex, msg);
              throw new P11TokenException(msg);
            }
          }
        }
      }
    } finally {
      sessions.requite(bagEntry);
    }
  } // method removeIdentity0

  private byte[] generateId(Session session) throws P11TokenException {
    byte[] keyId = null;
    do {
      keyId = new byte[newObjectConf.getIdLength()];
      random.nextBytes(keyId);
    } while (idExists(session, keyId));

    return keyId;
  }

  private boolean idExists(Session session, byte[] id) throws P11TokenException {
    if (existsIdentityForId(id) || existsCertForId(id)) {
      return true;
    }

    Key key = new Key();
    key.getId().setByteArrayValue(id);

    Object[] objects;
    try {
      session.findObjectsInit(key);
      objects = session.findObjects(1);
      if (objects.length > 0) {
        return true;
      }
    } catch (TokenException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    } finally {
      try {
        session.findObjectsFinal();
      } catch (TokenException ex) {
        LogUtil.error(LOG, ex, "session.findObjectsFinal() failed");
      }
    }

    X509PublicKeyCertificate cert = new X509PublicKeyCertificate();
    cert.getId().setByteArrayValue(id);

    try {
      session.findObjectsInit(cert);
      objects = session.findObjects(1);
    } catch (TokenException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    } finally {
      try {
        session.findObjectsFinal();
      } catch (TokenException ex) {
        LogUtil.error(LOG, ex, "session.findObjectsFinal() failed");
      }
    }

    return objects.length > 0;
  } // method idExists

  private static boolean labelExists(Session session, char[] keyLabel) throws P11TokenException {
    Args.notNull(keyLabel, "keyLabel");
    Key key = new Key();
    key.getLabel().setCharArrayValue(keyLabel);

    Object[] objects;
    try {
      session.findObjectsInit(key);
      objects = session.findObjects(1);
      if (objects.length > 0) {
        return true;
      }
    } catch (TokenException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    } finally {
      try {
        session.findObjectsFinal();
      } catch (TokenException ex) {
        LogUtil.error(LOG, ex, "session.findObjectsFinal() failed");
      }
    }

    X509PublicKeyCertificate cert = new X509PublicKeyCertificate();
    cert.getLabel().setCharArrayValue(keyLabel);

    try {
      session.findObjectsInit(cert);
      objects = session.findObjects(1);
    } catch (TokenException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    } finally {
      try {
        session.findObjectsFinal();
      } catch (TokenException ex) {
        LogUtil.error(LOG, ex, "session.findObjectsFinal() failed");
      }
    }

    return objects.length > 0;
  } // method labelExists

  private static void logPkcs11ObjectAttributes(String prefix, PKCS11Object p11Object) {
    if (!LOG.isDebugEnabled()) {
      return;
    }

    Hashtable<Long, Attribute> table = p11Object.getAttributeTable();
    StringBuilder sb = new StringBuilder();
    if (prefix != null) {
      sb.append(prefix);
    }

    Enumeration<Long> keys = table.keys();
    while (keys.hasMoreElements()) {
      Attribute attr = p11Object.getAttribute(keys.nextElement());
      sb.append("\n  ").append(attr.toString(true));
    }

    LOG.debug(sb.toString());
  } // method logPkcs11ObjectAttributes

}
