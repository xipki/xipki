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

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.objects.*;
import iaik.pkcs.pkcs11.objects.Certificate.CertificateType;
import iaik.pkcs.pkcs11.objects.Key.KeyType;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
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

  private final long timeOutWaitNewSession = 10000; // maximal wait for 10 second

  private final AtomicLong countSessions = new AtomicLong(0);

  private final SecureRandom random = new SecureRandom();

  private final P11NewObjectConf newObjectConf;

  private final ConcurrentBag<ConcurrentBagEntry<Session>> sessions = new ConcurrentBag<>();

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

      sessions.add(new ConcurrentBagEntry<>(session));
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
      StringBuilder ignoreMechs = new StringBuilder();
      boolean smartcard = libDesc.toLowerCase().contains("smartcard");
      for (Mechanism mech : mechanisms) {
        long code = mech.getMechanismCode();
        if (smartcard) {
          if (code == CKM_ECDSA_SHA1     || code == CKM_ECDSA_SHA224   || code == CKM_ECDSA_SHA256 ||
              code == CKM_ECDSA_SHA384   || code == CKM_ECDSA_SHA512   || code == CKM_ECDSA_SHA3_224 ||
              code == CKM_ECDSA_SHA3_256 || code == CKM_ECDSA_SHA3_384 || code == CKM_ECDSA_SHA3_512) {
            ignoreMechs.append(Functions.getMechanismDescription(code)).append(", ");
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
      List<Storage> secretKeys;
      if (secretKeyTypes == null) {
        secretKeys = getObjects(session, new SecretKey());
      } else if (secretKeyTypes.isEmpty()) {
        secretKeys = Collections.emptyList();
      } else {
        secretKeys = new LinkedList<>();
        for (Long keyType : secretKeyTypes) {
          secretKeys.addAll(getObjects(session, new ValuedSecretKey(keyType)));
        }
      }

      LOG.info("found {} secret keys", secretKeys.size());
      int count = 0;
      for (Storage secretKey : secretKeys) {
        if (secretKey instanceof SecretKey) {
          if (analyseSingleSecretKey((SecretKey) secretKey, ret)) {
            count++;
          }
        }
      }
      LOG.info("accepted {} secret keys", count);

      // first get the list of all CA certificates
      List<X509PublicKeyCertificate> p11Certs = getAllCertificateObjects(session);
      LOG.info("found {} X.509 certificates", p11Certs.size());

      count = 0;
      for (X509PublicKeyCertificate p11Cert : p11Certs) {
        byte[] id = value(p11Cert.getId());
        String label = valueStr(p11Cert.getLabel());
        if (id == null || id.length == 0) {
          LOG.warn("ignored X.509 certificate with ID: null and label: " + label);
        } else {
          ret.addCertificate(new P11ObjectIdentifier(id, label), parseCert(p11Cert));
          count++;
        }
      }

      LOG.info("accepted {} X.509 certificates", count);

      List<Storage> privKeys;
      if (keyPairTypes == null) {
        PrivateKey template = new PrivateKey();
        privKeys = getObjects(session, template);
      } else if (keyPairTypes.isEmpty()) {
        privKeys = Collections.emptyList();
      } else {
        privKeys = new LinkedList<>();
        for (long keyType : keyPairTypes) {
          PrivateKey template;

          if (keyType == KeyType.RSA) {
            template = new RSAPrivateKey();
          } else if (keyType == KeyType.DSA) {
            template = new DSAPrivateKey();
          } else if (keyType == KeyType.EC) {
            template = new ECPrivateKey();
          } else if (keyType == KeyType.VENDOR_SM2) {
            template = ECPrivateKey.newSM2PrivateKey(slot.getModule());
          } else if (keyType == KeyType.EC_EDWARDS) {
            template = new ECPrivateKey(KeyType.EC_EDWARDS);
          } else if (keyType == KeyType.EC_MONTGOMERY) {
            template = new ECPrivateKey(KeyType.EC_MONTGOMERY);
          } else {
            LOG.error("unknown KeyPair keyType " + keyType);
            continue;
          }

          privKeys.addAll(getObjects(session, template));
        }
      }

      LOG.info("found {} private keys", privKeys.size());
      count = 0;
      for (Storage privKey : privKeys) {
        if (privKey instanceof PrivateKey) {
          if (analyseSinglePrivateKey(session, (PrivateKey) privKey, ret)) {
            count++;
          }
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

  private boolean analyseSingleSecretKey(SecretKey secretKey, P11SlotRefreshResult refreshResult) {
    byte[] id = value(secretKey.getId());
    String label = valueStr(secretKey.getLabel());

    if (id == null || id.length == 0) {
      LOG.warn("ignored secret key with ID: null and label: " + label);
      return false;
    }

    IaikP11Identity identity = new IaikP11Identity(this,
        new P11IdentityId(slotId, new P11ObjectIdentifier(id, label)), secretKey);
    refreshResult.addIdentity(identity);
    return true;
  } // method analyseSingleKey

  private boolean analyseSinglePrivateKey(Session session, PrivateKey privKey, P11SlotRefreshResult refreshResult) {
    byte[] id = value(privKey.getId());
    String label = valueStr(privKey.getLabel());

    if (id == null || id.length == 0) {
      LOG.warn("ignored private key with ID: null and label: " + label);
      return false;
    }

    try {
      String pubKeyLabel = null;
      PublicKey p11PublicKey = (PublicKey) getKeyObjectForId(session, new PublicKey(), id);
      if (p11PublicKey != null) {
        pubKeyLabel = valueStr(p11PublicKey.getLabel());
      }

      String certLabel = null;
      java.security.PublicKey pubKey = null;
      X509Cert cert = refreshResult.getCertForId(id);

      if (cert != null) {
        certLabel = refreshResult.getCertLabelForId(id);
        pubKey = cert.getPublicKey();
      } else if (p11PublicKey != null) {
        pubKey = generatePublicKey(p11PublicKey);
      } else {
        if (privKey instanceof RSAPrivateKey) {
          RSAPrivateKey p11RsaSk = (RSAPrivateKey) privKey;
          if (p11RsaSk.getPublicExponent() != null && p11RsaSk.getModulus() == null) {
            pubKey = buildRSAKey(new BigInteger(1, value(p11RsaSk.getModulus())),
                new BigInteger(1, value(p11RsaSk.getPublicExponent())));
          }
        }

        if (pubKey == null) {
          LOG.info("neither certificate nor public key for the key (" + hex(id) + " is available");
          return false;
        }
      }

      X509Cert[] certs = (cert == null) ? null : new X509Cert[]{cert};
      P11IdentityId p11Id = new P11IdentityId(slotId, new P11ObjectIdentifier(id, label),
          pubKey != null, pubKeyLabel, cert != null, certLabel);
      refreshResult.addIdentity(new IaikP11Identity(this, p11Id, privKey, pubKey, certs));
      return true;
    } catch (XiSecurityException ex) {
      LogUtil.error(LOG, ex, "XiSecurityException while initializing private key with id " + hex(id));
    } catch (Throwable th) {
      LOG.error("unexpected exception while initializing private key with id "
          + hex(id) + " and label " + label, th);
    }

    return false;
  } // method analyseSingleKey

  byte[] digestSecretKey(long mech, IaikP11Identity identity) throws P11TokenException {
    Key key = notNull(identity, "identity").getSigningKey();
    assertMechanismSupported(mech);
    if (!(key instanceof SecretKey)) {
      throw new P11TokenException("digestSecretKey could not be applied to non-SecretKey");
    }

    if (LOG.isTraceEnabled()) {
      LOG.debug("digest (init, digestKey, then finish)\n{}", key);
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
      throw new P11TokenException("unsupported mechnism " + mech);
    }

    ConcurrentBagEntry<Session> session0 = borrowSession();
    Mechanism mechanismObj = Mechanism.get(mech);

    try {
      Session session = session0.value();
      try {
        return IaikP11SlotUtil.digestKey(session, digestLen, mechanismObj, (SecretKey) key);
      } catch (PKCS11Exception ex) {
        if (ex.getErrorCode() != CKR_USER_NOT_LOGGED_IN) {
          throw new P11TokenException(ex.getMessage(), ex);
        }

        LOG.info("digestKey ended with ERROR CKR_USER_NOT_LOGGED_IN, login and then retry it");
        // force the login
        forceLogin(session);
        try {
          return IaikP11SlotUtil.digestKey(session, digestLen, mechanismObj, (SecretKey) key);
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
    Key signingKey = identity.getSigningKey();

    ConcurrentBagEntry<Session> session0 = borrowSession();
    try {
      Session session = session0.value();
      try {
        return sign0(session, expectedSignatureLen, mechanismObj, content, signingKey);
      } catch (PKCS11Exception ex) {
        if (ex.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
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

  private byte[] sign0(Session session, int expectedSignatureLen, Mechanism mechanism, byte[] content, Key signingKey)
      throws TokenException {
    long keytype = signingKey.getKeyType().getLongValue();
    boolean weierstrausKey = KeyType.EC == keytype || KeyType.VENDOR_SM2 == keytype;

    int len = content.length;

    byte[] sigvalue;
    if (len <= maxMessageSize) {
      sigvalue = singleSign(session, mechanism, content, signingKey);
    } else {
      LOG.debug("sign (init, update, then finish)");
      session.signInit(mechanism, signingKey);

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

  private byte[] singleSign(Session session, Mechanism mechanism, byte[] content, Key signingKey)
      throws TokenException {
    LOG.debug("single sign");
    session.signInit(mechanism, signingKey);
    return session.sign(content);
  } // method singleSign

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
      // 0x100: user already logged in
      if (ex.getErrorCode() != 0x100) {
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

  private Key getKeyObjectForId(Session session, Key template, byte[] keyId)
      throws P11TokenException {
    return getKeyObject(session, template, keyId, true, null);
  }

  private Key getKeyObject(Session session, Key template, byte[] keyId, char[] keyLabel)
      throws P11TokenException {
    return getKeyObject(session, template, keyId, false, keyLabel);
  }

  private Key getKeyObject(Session session, Key template, byte[] keyId, boolean ignoreLabel, char[] keyLabel)
      throws P11TokenException {
    template.getId().setByteArrayValue(notNull(keyId, "keyId"));
    if (!ignoreLabel) {
      template.getLabel().setCharArrayValue(keyLabel);
    }

    List<Storage> tmpObjects = getObjects(session, template, 2);
    if (isEmpty(tmpObjects)) {
      return null;
    }

    int size = tmpObjects.size();
    if (size > 1) {
      LOG.warn("found {} public key identified by {}, use the first one", size, getDescription(keyId, keyLabel));
    }

    return (Key) tmpObjects.get(0);
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

    Key keyTemplate = new Key();
    if (id != null && id.length > 0) {
      keyTemplate.getId().setByteArrayValue(id);
    }

    if (!ignoreLabel) {
      keyTemplate.getLabel().setCharArrayValue(label);
    }

    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();
      String objIdDesc = getDescription(id, label);
      int num = removeObjects0(session, keyTemplate, "keys " + objIdDesc);

      X509PublicKeyCertificate certTemplate = new X509PublicKeyCertificate();
      if (id != null && id.length > 0) {
        certTemplate.getId().setByteArrayValue(id);
      }
      if (!ignoreLabel) {
        certTemplate.getLabel().setCharArrayValue(label);
      }

      num += removeObjects0(session, certTemplate, "certificates " + objIdDesc);
      return num;
    } finally {
      sessions.requite(bagEntry);
    }
  } // method removeObjects

  @Override
  protected void removeCerts0(P11ObjectIdentifier objectId) throws P11TokenException {
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
  protected P11ObjectIdentifier addCert0(X509Cert cert, P11NewObjectControl control)
      throws P11TokenException {
    ConcurrentBagEntry<Session> bagEntry = borrowSession();

    try {
      Session session = bagEntry.value();
      // get a local copy
      boolean omit = omitDateAttrsInCertObject;
      X509PublicKeyCertificate newCertTemp = createPkcs11Template(session, cert, control, omit);
      X509PublicKeyCertificate newCert;
      try {
        newCert = (X509PublicKeyCertificate) session.createObject(newCertTemp);
      } catch (PKCS11Exception ex) {
         long errCode = ex.getErrorCode();
         if (!omit && CKR_TEMPLATE_INCONSISTENT == errCode) {
           // some HSMs like NFAST does not like the attributes CKA_START_DATE and CKA_END_DATE, try without them.
           newCertTemp = createPkcs11Template(session, cert, control, true);
           newCert = (X509PublicKeyCertificate) session.createObject(newCertTemp);
           omitDateAttrsInCertObject = true;
           LOG.warn("The HSM does not accept certificate object with attributes "
               + "CKA_START_DATE and CKA_END_DATE, ignore them");
         } else {
           throw ex;
         }
      }

      return new P11ObjectIdentifier(value(newCert.getId()), valueStr(newCert.getLabel()));
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
    if (CKK_AES == keyType) {
      mech = CKM_AES_KEY_GEN;
    } else if (CKK_DES3 == keyType) {
      mech = CKM_DES3_KEY_GEN;
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

    ValuedSecretKey template = new ValuedSecretKey(keyType);
    IaikP11SlotUtil.setKeyAttributes(control, template, labelChars);
    template.getValueLen().setLongValue((long) (keysize / 8));

    Mechanism mechanism = Mechanism.get(mech);
    SecretKey key;
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();
      if (labelChars != null && labelExists(session, labelChars)) {
        throw new IllegalArgumentException("label " + control.getLabel() + " exists, please specify another one");
      }

      if (id == null) {
        id = generateId(session);
      }

      template.getId().setByteArrayValue(id);

      try {
        key = (SecretKey) session.generateKey(mechanism, template);
      } catch (TokenException ex) {
        throw new P11TokenException("could not generate generic secret key using " + mechanism.getName(), ex);
      }

      P11ObjectIdentifier objId = new P11ObjectIdentifier(id, valueStr(key.getLabel()));
      P11IdentityId entityId = new P11IdentityId(slotId, objId);

      return new IaikP11Identity(this, entityId, key);
    } finally {
      sessions.requite(bagEntry);
    }
  } // method generateSecretKey0

  @Override
  protected P11Identity importSecretKey0(long keyType, byte[] keyValue, P11NewKeyControl control)
      throws P11TokenException {
    ValuedSecretKey template = new ValuedSecretKey(keyType);
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
    template.getValue().setByteArrayValue(keyValue);

    SecretKey key;
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

      template.getId().setByteArrayValue(id);

      try {
        key = (SecretKey) session.createObject(template);
      } catch (TokenException ex) {
        throw new P11TokenException("could not create secret key", ex);
      }

      P11ObjectIdentifier objId = new P11ObjectIdentifier(id, valueStr(key.getLabel()));
      P11IdentityId entityId = new P11IdentityId(slotId, objId);

      return new IaikP11Identity(this, entityId, key);
    } finally {
      sessions.requite(bagEntry);
    }
  } // method importSecretKey0

  @Override
  protected P11Identity generateRSAKeypair0(int keysize, BigInteger publicExponent, P11NewKeyControl control)
      throws P11TokenException {
    RSAPrivateKey privateKey = new RSAPrivateKey();
    RSAPublicKey publicKey = new RSAPublicKey();
    setKeyAttributes(control, publicKey, privateKey, newObjectConf);

    publicKey.getModulusBits().setLongValue((long) keysize);
    publicKey.getPublicExponent().setByteArrayValue(publicExponent.toByteArray());

    return generateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN, control.getId(), privateKey, publicKey);
  } // method generateRSAKeypair0

  @Override
  protected PrivateKeyInfo generateRSAKeypairOtf0(int keysize, BigInteger publicExponent)
      throws P11TokenException {
    RSAPublicKey publicKeyTemplate = new RSAPublicKey();
    publicKeyTemplate.getModulusBits().setLongValue((long) keysize);
    publicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponent.toByteArray());

    RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();
    setPrivateKeyAttrsOtf(privateKeyTemplate);

    long mech = CKM_RSA_PKCS_KEY_PAIR_GEN;
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();

      KeyPair keypair = null;
      try {
        keypair = session.generateKeyPair(Mechanism.get(mech), publicKeyTemplate, privateKeyTemplate);
        RSAPrivateKey sk = (RSAPrivateKey) keypair.getPrivateKey();

        return new PrivateKeyInfo(ALGID_RSA,
            new org.bouncycastle.asn1.pkcs.RSAPrivateKey(
                toBigInt(sk.getModulus()),   toBigInt(sk.getPublicExponent()), toBigInt(sk.getPrivateExponent()),
                toBigInt(sk.getPrime1()),    toBigInt(sk.getPrime2()),         toBigInt(sk.getExponent1()),
                toBigInt(sk.getExponent2()), toBigInt(sk.getCoefficient())));

      } catch (TokenException | IOException ex) {
        throw new P11TokenException("could not generate keypair " + Functions.mechanismCodeToString(mech), ex);
      } finally {
        if (keypair != null) {
          destroyObject(session, keypair.getPrivateKey());
          destroyObject(session, keypair.getPublicKey());
        }
      }
    } finally {
      sessions.requite(bagEntry);
    }
  } // method generateRSAKeypairOtf0

  @Override
  protected P11Identity generateDSAKeypair0(BigInteger p, BigInteger q, BigInteger g, P11NewKeyControl control)
      throws P11TokenException {
    DSAPrivateKey privateKey = new DSAPrivateKey();
    DSAPublicKey publicKey = new DSAPublicKey();
    setKeyAttributes(control, publicKey, privateKey, newObjectConf);

    publicKey.getPrime().setByteArrayValue(Util.unsignedBigIntergerToByteArray(p));
    publicKey.getSubprime().setByteArrayValue(Util.unsignedBigIntergerToByteArray(q));
    publicKey.getBase().setByteArrayValue(Util.unsignedBigIntergerToByteArray(g));

    return generateKeyPair(CKM_DSA_KEY_PAIR_GEN, control.getId(), privateKey, publicKey);
  } // method generateDSAKeypair0

  @Override
  protected PrivateKeyInfo generateDSAKeypairOtf0(BigInteger p, BigInteger q, BigInteger g)
      throws P11TokenException {
    DSAPublicKey publicKeyTemplate = new DSAPublicKey();
    publicKeyTemplate.getPrime().setByteArrayValue(Util.unsignedBigIntergerToByteArray(p));
    publicKeyTemplate.getSubprime().setByteArrayValue(Util.unsignedBigIntergerToByteArray(q));
    publicKeyTemplate.getBase().setByteArrayValue(Util.unsignedBigIntergerToByteArray(g));

    DSAPrivateKey privateKeyTemplate = new DSAPrivateKey();
    setPrivateKeyAttrsOtf(privateKeyTemplate);

    long mech = CKM_DSA_KEY_PAIR_GEN;
    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();

      KeyPair keypair = null;
      try {
        DSAParameter parameter = new DSAParameter(p, q, g);
        AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, parameter);

        keypair = session.generateKeyPair(Mechanism.get(mech),
            publicKeyTemplate, privateKeyTemplate);
        DSAPrivateKey sk = (DSAPrivateKey) keypair.getPrivateKey();
        DSAPublicKey pk = (DSAPublicKey) keypair.getPublicKey();

        BigInteger value = toBigInt(pk.getValue()); // y
        byte[] publicKey = new ASN1Integer(value).getEncoded();

        return new PrivateKeyInfo(algId, new ASN1Integer(toBigInt(sk.getValue())), null, publicKey);
      } catch (TokenException | IOException ex) {
        throw new P11TokenException("could not generate keypair " + Functions.mechanismCodeToString(mech), ex);
      } finally {
        if (keypair != null) {
          destroyObject(session, keypair.getPrivateKey());
          destroyObject(session, keypair.getPublicKey());
        }
      }
    } finally {
      sessions.requite(bagEntry);
    }
  } // method generateDSAKeypairOtf0

  @Override
  protected P11Identity generateECEdwardsKeypair0(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws P11TokenException {
    ECPrivateKey privateKey = new ECPrivateKey(KeyType.EC_EDWARDS);
    ECPublicKey publicKey = new ECPublicKey(KeyType.EC_EDWARDS);
    setKeyAttributes(control, publicKey, privateKey, newObjectConf);
    byte[] encodedCurveId;
    try {
      encodedCurveId = curveId.getEncoded();
    } catch (IOException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    publicKey.getEcdsaParams().setByteArrayValue(encodedCurveId);
    return generateKeyPair(CKM_EC_EDWARDS_KEY_PAIR_GEN, control.getId(), privateKey, publicKey);
  } // method generateECEdwardsKeypair0

  @Override
  protected PrivateKeyInfo generateECEdwardsKeypairOtf0(ASN1ObjectIdentifier curveId)
      throws P11TokenException {
    return generateECKeypairOtf0(KeyType.EC_EDWARDS, CKM_EC_EDWARDS_KEY_PAIR_GEN, curveId);
  }

  @Override
  protected P11Identity generateECMontgomeryKeypair0(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws P11TokenException {
    ECPrivateKey privateKey = new ECPrivateKey(KeyType.EC_MONTGOMERY);
    ECPublicKey publicKey = new ECPublicKey(KeyType.EC_MONTGOMERY);
    setKeyAttributes(control, publicKey, privateKey, newObjectConf);
    try {
      publicKey.getEcdsaParams().setByteArrayValue(curveId.getEncoded());
    } catch (IOException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }

    return generateKeyPair(CKM_EC_MONTGOMERY_KEY_PAIR_GEN, control.getId(), privateKey, publicKey);
  } // method generateECMontgomeryKeypair0

  @Override
  protected PrivateKeyInfo generateECMontgomeryKeypairOtf0(ASN1ObjectIdentifier curveId)
      throws P11TokenException {
    return generateECKeypairOtf0(KeyType.EC_MONTGOMERY, CKM_EC_MONTGOMERY_KEY_PAIR_GEN, curveId);
  }

  @Override
  protected P11Identity generateECKeypair0(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws P11TokenException {
    ECPrivateKey privateKey = new ECPrivateKey();
    ECPublicKey publicKey = new ECPublicKey();
    setKeyAttributes(control, publicKey, privateKey, newObjectConf);
    byte[] encodedCurveId;
    try {
      encodedCurveId = curveId.getEncoded();
    } catch (IOException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }

    long mech = CKM_EC_KEY_PAIR_GEN;
    try {
      publicKey.getEcdsaParams().setByteArrayValue(encodedCurveId);
      return generateKeyPair(mech, control.getId(), privateKey, publicKey);
    } catch (P11TokenException ex) {
      X9ECParameters ecParams = ECNamedCurveTable.getByOID(curveId);
      if (ecParams == null) {
        throw new IllegalArgumentException("got no X9ECParameters for curve " + curveId.getId());
      }

      try {
        publicKey.getEcdsaParams().setByteArrayValue(ecParams.getEncoded());
      } catch (IOException ex2) {
        throw new P11TokenException(ex2.getMessage(), ex2);
      }
      return generateKeyPair(mech, control.getId(), privateKey, publicKey);
    }
  } // method generateECKeypair0

  @Override
  protected PrivateKeyInfo generateECKeypairOtf0(ASN1ObjectIdentifier curveId) throws P11TokenException {
    return generateECKeypairOtf0(KeyType.EC, CKM_EC_KEY_PAIR_GEN, curveId);
  }

  private PrivateKeyInfo generateECKeypairOtf0(long keyType, long mech, ASN1ObjectIdentifier curveId)
      throws P11TokenException {
    ECPrivateKey privateKeyTemplate;
    ECPublicKey publicKeyTemplate;

    if (keyType == KeyType.VENDOR_SM2) {
      if (!GMObjectIdentifiers.sm2p256v1.equals(curveId)) {
        throw new P11TokenException("keyType and curveId do not match.");
      }

      privateKeyTemplate = ECPrivateKey.newSM2PrivateKey(slot.getModule());
      publicKeyTemplate  = ECPublicKey.newSM2PublicKey(slot.getModule());
    } else {
      privateKeyTemplate = new ECPrivateKey(keyType);
      publicKeyTemplate  = new ECPublicKey(keyType);
    }

    try {
      publicKeyTemplate.getEcdsaParams().setByteArrayValue(curveId.getEncoded());
    } catch (IOException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }

    setPrivateKeyAttrsOtf(privateKeyTemplate);

    ConcurrentBagEntry<Session> bagEntry = borrowSession();
    try {
      Session session = bagEntry.value();

      KeyPair keypair = null;
      try {
        keypair = session.generateKeyPair(Mechanism.get(mech), publicKeyTemplate, privateKeyTemplate);
        ECPrivateKey sk = (ECPrivateKey) keypair.getPrivateKey();
        ECPublicKey pk = (ECPublicKey) keypair.getPublicKey();

        if (KeyType.EC_EDWARDS == keyType || KeyType.EC_MONTGOMERY == keyType) {
          AlgorithmIdentifier algId = new AlgorithmIdentifier(curveId);
          byte[] encodedPublicPoint = ASN1OctetString.getInstance(pk.getEcPoint().getByteArrayValue()).getOctets();
          byte[] privValue = sk.getValue().getByteArrayValue();
          return new PrivateKeyInfo(algId, new DEROctetString(privValue), null, encodedPublicPoint);
        } else {
          AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curveId);

          byte[] encodedPublicPoint =
              ASN1OctetString.getInstance(pk.getEcPoint().getByteArrayValue()).getOctets();
          if (encodedPublicPoint[0] != 4) {
            throw new P11TokenException("EcPoint does not start with 0x04");
          }

          int orderBigLen = (encodedPublicPoint.length - 1) / 2 * 8;
          return new PrivateKeyInfo(algId,
              new org.bouncycastle.asn1.sec.ECPrivateKey(orderBigLen,
                  new BigInteger(1, sk.getValue().getByteArrayValue()),
                  new DERBitString(encodedPublicPoint), null));
        }
      } catch (TokenException | IOException ex) {
        throw new P11TokenException("could not generate keypair " + Functions.mechanismCodeToString(mech), ex);
      } finally {
        if (keypair != null) {
          destroyObject(session, keypair.getPrivateKey());
          destroyObject(session, keypair.getPublicKey());
        }
      }
    } finally {
      sessions.requite(bagEntry);
    }

  }

  @Override
  protected P11Identity generateSM2Keypair0(P11NewKeyControl control) throws P11TokenException {
    long ckm = CKM_VENDOR_SM2_KEY_PAIR_GEN;
    if (supportsMechanism(ckm)) {
      ECPrivateKey privateKey = ECPrivateKey.newSM2PrivateKey(slot.getModule());
      ECPublicKey publicKey = ECPublicKey.newSM2PublicKey(slot.getModule());
      publicKey.getEcdsaParams().setByteArrayValue(Hex.decode("06082A811CCF5501822D"));
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
      return generateECKeypairOtf0(KeyType.VENDOR_SM2, ckm, GMObjectIdentifiers.sm2p256v1);
    } else {
      return generateECKeypairOtf0(GMObjectIdentifiers.sm2p256v1);
    }
  }

  private P11Identity generateKeyPair(long mech, byte[] id, PrivateKey privateKeyTemplate, PublicKey publicKeyTemplate)
      throws P11TokenException {
    char[] labelChars = value(privateKeyTemplate.getLabel());

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

        privateKeyTemplate.getId().setByteArrayValue(id);
        publicKeyTemplate.getId().setByteArrayValue(id);

        try {
          keypair = session.generateKeyPair(Mechanism.get(mech), publicKeyTemplate, privateKeyTemplate);
          labelChars = value(keypair.getPrivateKey().getLabel());
        } catch (TokenException ex) {
          throw new P11TokenException("could not generate keypair " + Functions.mechanismCodeToString(mech), ex);
        }

        if (labelChars == null) {
          throw new P11TokenException("Label of the generated PrivateKey is not set");
        }

        String pubKeyLabel = valueStr(keypair.getPublicKey().getLabel());

        P11ObjectIdentifier objId = new P11ObjectIdentifier(id, new String(labelChars));
        java.security.PublicKey jcePublicKey;
        try {
          jcePublicKey = generatePublicKey(keypair.getPublicKey());
        } catch (XiSecurityException ex) {
          throw new P11TokenException("could not generate public key " + objId, ex);
        }

        PrivateKey privKey2 = (PrivateKey) getKeyObject(session, new PrivateKey(), id, labelChars);
        if (privKey2 == null) {
          throw new P11TokenException("could not read the generated private key");
        }

        // certificate: some vendors generate also certificate
        X509PublicKeyCertificate cert2 = getCertificateObject(session, id, null);
        String certLabel = null;
        X509Cert[] certs = null;
        if (cert2 != null) {
          certLabel = valueStr(cert2.getLabel());
          certs = new X509Cert[1];
          try {
            certs[0] = X509Util.parseCert(value(cert2.getValue()));
          } catch (CertificateException ex) {
            throw new P11TokenException("could not parse certifcate", ex);
          }
        }

        P11IdentityId entityId = new P11IdentityId(slotId, objId, true, pubKeyLabel, certs != null, certLabel);
        IaikP11Identity ret = new IaikP11Identity(this, entityId, privKey2, jcePublicKey, certs);
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

  private X509PublicKeyCertificate createPkcs11Template(
      Session session, X509Cert cert, P11NewObjectControl control, boolean omitDateAttrs)
      throws P11TokenException {
    X509PublicKeyCertificate newCertTemp = new X509PublicKeyCertificate();
    byte[] id = control.getId();
    if (id == null) {
      id = generateId(session);
    }

    newCertTemp.getId().setByteArrayValue(id);

    if (newObjectConf.isIgnoreLabel()) {
      if (control.getLabel() != null) {
        LOG.warn("label is set, but ignored: '{}'", control.getLabel());
      }
    } else {
      newCertTemp.getLabel().setCharArrayValue(control.getLabel().toCharArray());
    }

    newCertTemp.getToken().setBooleanValue(true);
    newCertTemp.getCertificateType().setLongValue(CertificateType.X_509_PUBLIC_KEY);

    Set<Long> setCertAttributes = newObjectConf.getSetCertObjectAttributes();

    try {
      if (setCertAttributes.contains(CKA_SUBJECT)) {
        newCertTemp.getSubject().setByteArrayValue(cert.getSubject().getEncoded());
      }

      if (setCertAttributes.contains(CKA_ISSUER)) {
        newCertTemp.getIssuer().setByteArrayValue(cert.getIssuer().getEncoded());
      }
    } catch (IOException ex) {
      throw new P11TokenException("error encoding certificate: " + ex.getMessage(), ex);
    }

    if (setCertAttributes.contains(CKA_SERIAL_NUMBER)) {
      newCertTemp.getSerialNumber().setByteArrayValue(cert.getSerialNumber().toByteArray());
    }

    if (!omitDateAttrs) {
      if (setCertAttributes.contains(CKA_START_DATE)) {
        newCertTemp.getStartDate().setDateValue(cert.getNotBefore());
      }

      if (setCertAttributes.contains(CKA_END_DATE)) {
        newCertTemp.getStartDate().setDateValue(cert.getNotAfter());
      }
    }

    newCertTemp.getValue().setByteArrayValue(cert.getEncoded());
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
      SecretKey secretKey = (SecretKey) getKeyObject(session, new SecretKey(), id, label);
      if (secretKey != null) {
        try {
          session.destroyObject(secretKey);
        } catch (TokenException ex) {
          String msg = "could not delete secret key " + keyId;
          LogUtil.error(LOG, ex, msg);
          throw new P11TokenException(msg);
        }
      }

      PrivateKey privKey = (PrivateKey) getKeyObject(session, new PrivateKey(), id, label);

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
        PublicKey pubKey =
            (PublicKey) getKeyObject(session, new PublicKey(), pubKeyId.getId(), pubKeyId.getLabelChars());
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

      P11ObjectIdentifier certId = identityId.getCertId();
      if (certId != null) {
        X509PublicKeyCertificate[] certs = getCertificateObjects(session, certId.getId(), certId.getLabelChars());
        if (certs != null && certs.length > 0) {
          for (X509PublicKeyCertificate cert : certs) {
            try {
              session.destroyObject(cert);
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
    while (true) {
      byte[] keyId = new byte[newObjectConf.getIdLength()];
      random.nextBytes(keyId);
      // clear the first bit
      keyId[0] = (byte) (0x7F & keyId[0]);

      if (existsIdentityForId(keyId) || existsCertForId(keyId)) {
        continue;
      }

      Key key = new Key();
      key.getId().setByteArrayValue(keyId);
      if (!isEmpty(getObjects(session, key, 1))) {
        continue;
      }

      X509PublicKeyCertificate cert = new X509PublicKeyCertificate();
      cert.getId().setByteArrayValue(keyId);
      if (!isEmpty(getObjects(session, cert, 1))) {
        continue;
      }

      return keyId;
    }
  }

  private boolean labelExists(Session session, char[] keyLabel) throws P11TokenException {
    notNull(keyLabel, "keyLabel");

    String strLabel = new String(keyLabel);
    if (existsIdentityForLabel(strLabel) || existsCertForLabel(strLabel)) {
      return true;
    }

    Key key = new Key();
    key.getLabel().setCharArrayValue(keyLabel);
    if (!isEmpty(getObjects(session, key, 1))) {
      return true;
    }

    X509PublicKeyCertificate cert = new X509PublicKeyCertificate();
    cert.getLabel().setCharArrayValue(keyLabel);
    return !isEmpty(getObjects(session, cert, 1));
  } // method labelExists

  void setKeyAttributes(
      P11NewKeyControl control, PublicKey publicKey, PrivateKey privateKey, P11NewObjectConf newObjectConf) {
    if (privateKey != null) {
      privateKey.getToken().setBooleanValue(true);
      if (newObjectConf.isIgnoreLabel()) {
        if (control.getLabel() != null) {
          LOG.warn("label is set, but ignored: '{}'", control.getLabel());
        }
      } else {
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
      final Boolean TRUE = Boolean.TRUE;
      if (isNotEmpty(usages)) {
        for (P11KeyUsage usage : usages) {
          if (usage == P11KeyUsage.DECRYPT) {
            privateKey.getDecrypt().setBooleanValue(TRUE);
          } else if (usage == P11KeyUsage.DERIVE) {
            privateKey.getDerive().setBooleanValue(TRUE);
          } else if (usage == P11KeyUsage.SIGN) {
            privateKey.getSign().setBooleanValue(TRUE);
          } else if (usage == P11KeyUsage.SIGN_RECOVER) {
            privateKey.getSignRecover().setBooleanValue(TRUE);
          } else if (usage == P11KeyUsage.UNWRAP) {
            privateKey.getUnwrap().setBooleanValue(TRUE);
          }
        }
      } else {
        long keyType = privateKey.getKeyType().getLongValue();
        // if not set
        if (keyType == PKCS11Constants.CKK_EC || keyType == PKCS11Constants.CKK_RSA
            || keyType == PKCS11Constants.CKK_DSA) {
          privateKey.getSign().setBooleanValue(TRUE);
        }

        if (slot.getModule().getVendorCodeConverter() != null) {
          if (keyType == slot.getModule().getVendorCodeConverter().genericToVendorCKK(CKK_VENDOR_SM2)) {
            privateKey.getSign().setBooleanValue(TRUE);
          }
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

  private static void setPrivateKeyAttrsOtf(PrivateKey privateKeyTemplate) {
    privateKeyTemplate.getToken().setBooleanValue(false);
    privateKeyTemplate.getSensitive().setBooleanValue(false);
    privateKeyTemplate.getExtractable().setBooleanValue(true);
  }

  private static void destroyObject(Session session, PKCS11Object object) {
    try {
      session.destroyObject(object);
    } catch (TokenException ex) {
      LogUtil.warn(LOG, ex, "error destroying object");
    }
  }

  private static BigInteger toBigInt(ByteArrayAttribute attr) {
    return new BigInteger(1, attr.getByteArrayValue());
  }

}
