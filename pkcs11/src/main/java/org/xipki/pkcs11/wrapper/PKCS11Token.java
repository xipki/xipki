// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.attrs.AttributeTypes;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.jni.PKCS11;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairType;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeySpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11SecretKeySpec;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.pkcs11.wrapper.type.CkMechanismInfo;
import org.xipki.pkcs11.wrapper.type.CkTokenInfo;
import org.xipki.util.codec.Args;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * This is a PKCS#11 token with session management.
 *
 * @author xipki
 */
public class PKCS11Token {

  private static final int idLen = 8;

  private static final Logger LOG = LoggerFactory.getLogger(PKCS11Token.class);

  private static final Clock clock = Clock.systemUTC();

  private int maxMessageSize = 2048;

  private final Token token;

  private final Map<Long, CkMechanismInfo> mechanisms = new HashMap<>();

  private final SessionAuth auth;

  private final int maxSessionCount;

  private final boolean readOnly;

  private long timeOutWaitNewSessionMs = 10000; // maximal wait for 10 second

  private final AtomicInteger countSessions = new AtomicInteger(0);

  private final BlockingQueue<PKCS11Session> sessions;

  private final SecureRandom random = new SecureRandom();

  /**
   * The simple constructor.
   *
   * @param token    The token
   * @param readOnly True if this token is read only, false if read-write.
   * @param pin      The PIN of user type CKU_USER. May be null.
   * @throws TokenException If accessing the PKCS#11 device failed.
   */
  public PKCS11Token(Token token, boolean readOnly, String pin)
      throws TokenException {
    this(token, readOnly, CKU_USER, null,
        (pin == null ? null : Collections.singletonList(pin)), null);
  }

  /**
   * The simple constructor.
   *
   * @param token       The token
   * @param readOnly    True if this token is read only, false if read-write.
   * @param pin         The PIN of user type CKU_USER. May be null.
   * @param numSessions Number of sessions. May be null.
   * @throws TokenException If accessing the PKCS#11 device failed.
   */
  public PKCS11Token(Token token, boolean readOnly, String pin,
                     Integer numSessions) throws TokenException {
    this(token, readOnly, CKU_USER, null,
        (pin == null ? null : Collections.singletonList(pin)), numSessions);
  }

  public PKCS11Token(Token token, boolean readOnly, byte[] pin,
                     Integer numSessions) throws TokenException {
    this(token, readOnly, pin == null ? null : new String(pin), numSessions);
  }

  /**
   * The advanced constructor.
   *
   * @param token       The token
   * @param readOnly    True if this token is read only, false if read-write.
   * @param userType    The user type. In general, it is CKU_USER.
   * @param userName    The user-name. In general, it is null.
   * @param pins        The PINs. May be null and empty list.
   * @param numSessions Number of sessions. May be null.
   * @throws TokenException If accessing the PKCS#11 device failed.
   */
  public PKCS11Token(Token token, boolean readOnly, long userType,
                     String userName, List<String> pins, Integer numSessions)
      throws TokenException {
    this.token = Objects.requireNonNull(token, "token shall not be null");
    this.readOnly = readOnly;
    this.auth = userName == null
        ? SessionAuth.ofLogin(userType, pins)
        : SessionAuth.ofLoginUser(userType, userName, pins);

    CkTokenInfo tokenInfo = token.getTokenInfo();
    long lc = tokenInfo.maxSessionCount();
    int tokenMaxSessionCount = lc > Integer.MAX_VALUE ? Integer.MAX_VALUE
        : (int) lc;

    //this.isProtectedAuthenticationPath =
    //    tokenInfo.isProtectedAuthenticationPath();

    int maxNumSessions;
    if (numSessions == null) {
      maxNumSessions = (tokenMaxSessionCount < 1) ? 32
          : Math.min(32, tokenMaxSessionCount);
    } else {
      if (tokenMaxSessionCount < 1) {
        maxNumSessions = numSessions;
      } else {
        maxNumSessions = Math.min(numSessions, tokenMaxSessionCount);
      }
    }

    for (long mech : token.getMechanismList()) {
      try {
        mechanisms.put(mech, token.getMechanismInfo(mech));
      } catch (Exception e) {
        LOG.warn("error getMechanism for {} (0x{}): {}",
            token.getSlot().getModule().codeToName(Category.CKM, mech),
            Functions.toFullHex(mech), e.getMessage());
      }
    }

    this.sessions = new ArrayBlockingQueue<>(maxNumSessions);
    // login
    for (int i = 0; i < maxNumSessions; i++) {
      try {
        sessions.add(openSession(i == 0, true));
      } catch (Exception e) {
        LOG.warn("error openSession i={}", i, e);
        break;
      }
    }

    this.maxSessionCount = sessions.size();
    LOG.info("tokenMaxSessionCount={}, maxSessionCount={}",
        tokenMaxSessionCount, this.maxSessionCount);
    if (this.maxSessionCount == 0) {
      LOG.error("could not open any session");
    }
  }

  public PKCS11Module getModule() {
    return token.getSlot().getModule();
  }

  public void setTimeOutWaitNewSession(int timeOutWaitNewSessionMs) {
    if (timeOutWaitNewSessionMs < 1000) {
      throw new IllegalArgumentException(
          "timeOutWaitNewSessionMs is not greater than 999");
    }
    this.timeOutWaitNewSessionMs = timeOutWaitNewSessionMs;
    LOG.info("timeOutWaitNewSession = {} milli-seconds",
        timeOutWaitNewSessionMs);
  }

  /**
   * Sets the maximal message size sent to the PKCS#11 device in one command.
   *
   * @param maxMessageSize the maximal message size in bytes.
   */
  public void setMaxMessageSize(int maxMessageSize) {
    if (maxMessageSize < 256) {
      throw new IllegalArgumentException(
          "maxMessageSize too small, at least 256 is required: " +
              maxMessageSize);
    }
    this.maxMessageSize = maxMessageSize;
  }

  public Set<Long> getMechanisms() {
    return Collections.unmodifiableSet(mechanisms.keySet());
  }

  /**
   * Gets the {@link CkMechanismInfo} for given mechanism code.
   *
   * @param mechanism The mechanism code.
   * @return the {@link CkMechanismInfo}.
   */
  public CkMechanismInfo getMechanismInfo(long mechanism) {
    return mechanisms.get(mechanism);
  }

  /**
   * Returns whether the mechanism for given purpose is supported.
   *
   * @param mechanism The mechanism.
   * @param flagBit
   *        The purpose. Valid values are (could be extended in the future
   *        PKCS#11 version):
   *        {@link PKCS11T#CKF_SIGN},
   *        {@link PKCS11T#CKF_VERIFY},
   *        {@link PKCS11T#CKF_SIGN_RECOVER},
   *        {@link PKCS11T#CKF_VERIFY_RECOVER},
   *        {@link PKCS11T#CKF_ENCRYPT},
   *        {@link PKCS11T#CKF_DECRYPT},
   *        {@link PKCS11T#CKF_DERIVE},
   *        {@link PKCS11T#CKF_DIGEST},
   *        {@link PKCS11T#CKF_UNWRAP},
   *        {@link PKCS11T#CKF_WRAP}.
   * @return whether the mechanism with given flag bit is supported.
   */
  public boolean supportsMechanism(long mechanism, long flagBit) {
    CkMechanismInfo info = mechanisms.get(mechanism);
    return info != null && info.hasFlagBit(flagBit);
  }

  public int getMaxMessageSize() {
    return getModule().getMaxFrameSize();
  }

  public boolean supportsMultipart(long mechanism, long flagBit) {
    return getModule().supportsMultipart(mechanism, flagBit);
  }

  public boolean supportsMultipart(CkMechanism mechanism, long flagBit) {
    return supportsMultipart(mechanism.getMechanism(), flagBit);
  }

  public byte[] prepareGcmIv() {
    return getModule().prepareGcmIv(random);
  }

  /* ***************************************
   * PKCS#11 V2.x Functions
   * ***************************************/

  public void closeAllSessions() {
    if (token != null) {
      try {
        LOG.info("close all sessions on token: {}", token.getTokenInfo());

        for (PKCS11Session session : sessions) {
          session.close();
        }
      } catch (Throwable th) {
        LOG.error("error closing sessions, {}", th.getMessage());
      }
    }

    // clear the session pool
    sessions.clear();
    countSessions.lazySet(0);
  }

  /**
   * Get the token (slot) identifier of this token.
   *
   * @return the slot identifier of this token.
   */
  public long getTokenId() {
    return token.getTokenID();
  }

  /**
   * Get the token that created this Session object.
   *
   * @return The token.
   */
  public Token getToken() {
    return token;
  }

  public String getModuleInfo() throws TokenException {
    return token.getSlot().getModule().getInfo().toString();
  }

  /**
   * Returns whether this token is read-only.
   *
   * @return true if read-only, false if read-write.
   */
  public boolean isReadOnly() {
    return readOnly;
  }

  /**
   * Login this session as CKU_SO (Security Officer).
   *
   * @param pin      PIN.
   * @throws TokenException If logging in the session fails.
   */
  public void loginSo(byte[] pin) throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      session.loginSo(pin);
    } finally {
      requiteSession(session);
    }
  }

  /**
   * Login this session as CKU_SO (Security Officer).
   *
   * @param userName Username of user type CKU_SO.
   * @param pin      PIN.
   * @throws TokenException If logging in the session fails.
   */
  public void loginSo(byte[] userName, byte[] pin)
      throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      session.loginSo(userName, pin);
    } finally {
      requiteSession(session);
    }
  }

  /**
   * Logs out this session.
   *
   * @throws TokenException If logging out the session fails.
   */
  public void logout() throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      session.logout();
    } finally {
      requiteSession(session);
    }
  }

  /**
   * Logs out the CKU_SO session.
   *
   * @throws TokenException If logging out the session fails.
   */
  public void logoutSo() throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      long state = session.getSessionState();
      if (state == CKS_RW_SO_FUNCTIONS) {
        session.logout();
        LOG.info("logged out CKU_SO");
      }
    } finally {
      requiteSession(session);
    }
  }

  /**
   * Create a new object on the token (or in the session). The application must
   * provide a template that holds enough information to create a certain
   * object. For instance, if the application wants to create a new DES key
   * object it creates a new instance of the AttributesTemplate class to serve
   * as a template. The application must set all attributes of this new object
   * which are required for the creation of such an object on the token. Then
   * it passes this DESSecretKey object to this method to create the object on
   * the token. Example:
   *
   * <pre>
   * AttributesTemplate desKeyTemplate =
   *     AttributesTemplate.newSecretKey(CKK_DES3);
   * // the key type is set by the DESSecretKey's constructor, so you need not
   * // do it
   * desKeyTemplate.value(myDesKeyValueAs8BytesLongByteArray)
   *   .token(true)
   *   .private(true);
   *   .encrypt(true);
   *   .decrypt(true);
   *
   * ...
   *
   * long theCreatedDESKeyObjectHandle =
   *     userSession.createObject(desKeyTemplate);
   * </pre>
   * <p>
   * Refer to the PKCS#11 standard to find out what attributes must be set for
   * certain types of objects to create them on the token.
   *
   * @param template
   *        The template object that holds all values that the new object on
   *        the token should contain.
   * @return A new PKCS#11 Object that serves holds all the (readable)
   *         attributes of the object on the token. In contrast to the
   *         templateObject, this object might have certain attributes set to
   *         token-dependent default-values.
   * @throws TokenException
   *         If the creation of the new object fails. If it fails, the no new
   *         object was created on the token.
   */
  public long importObject(Template template) throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      return session.importObject(template);
    } finally {
      requiteSession(session);
    }
  }

  public long importPublicKey(byte[] publicKey, PKCS11KeyPairSpec spec)
      throws InvalidKeySpecException, TokenException {
    return importPublicKey(new PublicKeyChoice(publicKey), spec);
  }

  public long importPublicKey(PublicKey publicKey, PKCS11KeyPairSpec spec)
      throws InvalidKeySpecException, TokenException {
    return importPublicKey(new PublicKeyChoice(publicKey), spec);
  }

  public long importPublicKey(PublicKeyChoice publicKey, PKCS11KeyPairSpec spec)
      throws InvalidKeySpecException, TokenException {
    PKCS11Session session = borrowSession();
    try {
      fillTemplate(false, session, spec);
      return session.importPublicKey(publicKey,
          spec.toPublicKeyAttributeVector());
    } finally {
      requiteSession(session);
    }
  }

  public long importPrivateKey(
      byte[] pkcs8PrivateKey, byte[] publicKey, PKCS11KeyPairSpec spec)
      throws InvalidKeySpecException, TokenException {
    Args.notNull(pkcs8PrivateKey, "pkcs8PrivateKey");

    return importPrivateKey(
        new PrivateKeyChoice(pkcs8PrivateKey),
        publicKey == null ? null : new PublicKeyChoice(publicKey),
        spec);
  }

  public long importPrivateKey(
      PrivateKey privateKey, PublicKey publicKey, PKCS11KeyPairSpec spec)
      throws InvalidKeySpecException, TokenException {
    Args.notNull(privateKey, "privateKey");

    return importPrivateKey(
        new PrivateKeyChoice(privateKey),
        publicKey == null ? null : new PublicKeyChoice(publicKey), spec);
  }

  public long importPrivateKey(
      PrivateKeyChoice privateKey, PublicKeyChoice publicKey,
      PKCS11KeyPairSpec spec)
      throws InvalidKeySpecException, TokenException {
    Args.notNull(privateKey, "privateKey");

    PKCS11Session session = borrowSession();
    try {
      fillTemplate(true, session, spec);
      return session.importPrivateKey(privateKey, publicKey,
          spec.toPrivateKeyAttributeVector());
    } finally {
      requiteSession(session);
    }
  }

  public PKCS11KeyPair importKeyPair(
      byte[] pkcs8PrivateKey, byte[] publicKey, PKCS11KeyPairSpec spec)
      throws InvalidKeySpecException, TokenException {
    Args.notNull(pkcs8PrivateKey, "pkcs8PrivateKey");
    Args.notNull(publicKey, "publicKey");

    return importKeyPair(
        new PrivateKeyChoice(pkcs8PrivateKey),
        new PublicKeyChoice(publicKey),
        spec);
  }

  public PKCS11KeyPair importKeyPair(
      PrivateKey privateKey, PublicKey publicKey, PKCS11KeyPairSpec spec)
      throws InvalidKeySpecException, TokenException {
    Args.notNull(privateKey, "privateKey");
    Args.notNull(publicKey, "publicKey");

    return importKeyPair(
        new PrivateKeyChoice(privateKey),
        new PublicKeyChoice(publicKey),
        spec);
  }

  public PKCS11KeyPair importKeyPair(
      PrivateKeyChoice privateKey, PublicKeyChoice publicKey,
      PKCS11KeyPairSpec spec) throws InvalidKeySpecException, TokenException {
    Args.notNull(privateKey, "privateKey");
    Args.notNull(publicKey, "publicKey");

    PKCS11Session session = borrowSession();
    try {
      fillTemplate(session, spec);

      return session.importKeyPair(privateKey, publicKey,
          spec.toKeyPairTemplate());
    } finally {
      requiteSession(session);
    }
  }

  /**
   * Copy an existing object. The source object and a template object are
   * given. Any value set in the template object will override the
   * corresponding value from the source object, when the new object is
   * created. See the PKCS#11 standard for details.
   *
   * @param hObject
   *        The source object of the copy operation.
   * @param template
   *        A template object whose attribute values are used for the new
   *        object; i.e. they have higher priority than the attribute values
   *        from the source object. May be null; in that case the new object
   *        is just a one-to-one copy of the sourceObject.
   * @return The new object that is created by copying the source object and
   *         setting attributes to the values given by the template.
   * @throws TokenException If copying the object fails for some reason.
   */
  public long copyObject(long hObject, Template template)
      throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      return session.copyObject(hObject, template);
    } finally {
      requiteSession(session);
    }
  }

  /**
   * Gets all present attributes of the given template object and writes them
   * to the object to update on the token (or in the session). Both parameters
   * may refer to the same Java object. This is possible, because this method
   * only needs the object handle of the objectToUpdate, and gets the
   * attributes to set from the template. This means, an application can get
   * the object using createObject of findObject, then modify attributes of
   * this Java object and then call this method passing this object as both
   * parameters. This will update the object on the token to the values as
   * modified in the Java object.
   *
   * @param hObject
   *        The attributes of this object get updated.
   * @param template
   *        This method gets all present attributes of this template object
   *        and set this attributes at the objectToUpdate.
   * @throws TokenException
   *         If updating the attributes fails. All or no attributes are
   *         updated.
   */
  public void setAttributeValues(long hObject, Template template)
      throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      session.setAttributeValues(hObject, template);
    } finally {
      requiteSession(session);
    }
  }

  /**
   * Destroy a certain object on the token (or in the session). Give the object
   * that you want to destroy. This method uses only the internal object handle
   * of the given object to identify the object.
   *
   * @param hObject The object handle that should be destroyed.
   * @throws TokenException If the object could not be destroyed.
   */
  public void destroyObject(long hObject) throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      session.destroyObject(hObject);
    } finally {
      requiteSession(session);
    }
  }

  /**
   * Destroy a certain object on the token (or in the session). Give the object
   * that you want to destroy. This method uses only the internal object handle
   * of the given object to identify the object.
   *
   * @param hObjects The object handles that should be destroyed.
   * @return objects that have been destroyed.
   * @throws TokenException If could not get a valid session.
   */
  public long[] destroyObjects(long... hObjects) throws TokenException {
    List<Long> list = new ArrayList<>(hObjects.length);
    for (long handle : hObjects) {
      list.add(handle);
    }

    List<Long> destroyedHandles = destroyObjects(list);
    long[] ret = new long[destroyedHandles.size()];
    for (int i = 0; i < ret.length; i++) {
      ret[i] = destroyedHandles.get(i);
    }
    return ret;
  }

  public List<Long> destroyObjects(List<Long> hObjects)
      throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      return session.destroyObjects(hObjects);
    } finally {
      requiteSession(session);
    }
  }

  public void destroyKey(PKCS11KeyId keyId) throws TokenException {
    if (keyId.getPublicKeyHandle() != null) {
      destroyObjects(keyId.getPublicKeyHandle(), keyId.getHandle());
    } else {
      destroyObject(keyId.getHandle());
    }
  }

  /**
   * Generate a unique CKA_ID.
   *
   * @param template The search criteria for the uniqueness.
   * @param idLength Length of the CKA_ID.
   * @return the unique CKA_ID.
   * @throws TokenException If executing operation fails.
   */
  public byte[] generateUniqueId(
      Template template, int idLength)
      throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      return session.generateUniqueId(template, idLength, random);
    } finally {
      requiteSession(session);
    }
  }

  private byte[] generateUniqueId(
      PKCS11Session session, Template template, int idLength)
      throws TokenException {
    if (template != null && template.id() != null) {
      throw new IllegalArgumentException("template shall not have CKA_ID");
    }

    if (template == null) {
      template = new Template();
    }

    return session.generateUniqueId(template, idLength, random);
  }

  /**
   * Gets the {@link PKCS11Key} identified by the given {@link PKCS11KeyId}.
   *
   * @param keyId The key identifier.
   * @return {@link PKCS11Key} identified by the given {@link PKCS11KeyId}.
   * @throws TokenException If executing operation fails.
   */
  public PKCS11Key getKey(PKCS11KeyId keyId) throws TokenException {
    if (keyId == null) {
      return null;
    }

    PKCS11Session session = borrowSession();
    try {
      return session.getKey(keyId);
    } finally {
      requiteSession(session);
    }
  }

  /**
   * Gets the {@link PKCS11Key} of a key satisfying the given criteria.
   *
   * @param criteria
   *        The criteria. At one of the CKA_ID and CKA_LABEL must be set.
   * @return {@link PKCS11Key} of a key satisfying the given criteria
   * @throws TokenException If executing operation fails.
   */
  public PKCS11Key getKey(Template criteria) throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      return session.getKey(criteria);
    } finally {
      requiteSession(session);
    }
  }

  /**
   * Gets the {@link PKCS11KeyId} of a key satisfying the given criteria.
   *
   * @param criteria
   *        The criteria. At one of the CKA_ID and CKA_LABEL must be set.
   * @return {@link PKCS11KeyId} of a key satisfying the given criteria
   * @throws TokenException If executing operation fails.
   */
  public PKCS11KeyId getKeyId(Template criteria) throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      return session.getKeyId(criteria);
    } finally {
      requiteSession(session);
    }
  }

  /**
   * Finds all objects that match the template.
   *
   * @param template
   *        The object that serves as a template for searching. If this object
   *        is null, the find operation will find all objects that this session
   *        can see. Notice, that only a user session will see private objects.
   * @return An array of found objects. The maximum size of this array is
   *         maxObjectCount, the minimum length is 0. Never returns null.
   * @throws TokenException if finding objects failed.
   */
  public long[] findAllObjects(Template template) throws TokenException {
    return findObjects(template, Integer.MAX_VALUE);
  }

  /**
   * Finds objects that match the template.
   *
   * @param template
   *        The object that serves as a template for searching. If this object
   *        is null, the find operation will find all objects that this session
   *        can see. Notice, that only a user session will see private objects.
   * @param maxObjectCount
   *        Specifies how many objects to return with this call.
   * @return An array of found objects. The maximum size of this array is
   *         maxObjectCount, the minimum length is 0. Never returns null.
   * @throws TokenException if finding objects failed.
   */
  public long[] findObjects(Template template, int maxObjectCount)
      throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      return findObjects(session, template, maxObjectCount);
    } finally {
      requiteSession(session);
    }
  }

  private long[] findObjects(PKCS11Session session,
                             Template template, int maxObjectCount)
      throws TokenException {
    return session.findObjects(template, maxObjectCount);
  }

  /**
   * Digests the given data with the mechanism.
   *
   * @param mechanism
   *        The mechanism to use
   * @param data
   *        the to-be-digested data
   * @return the message digest. Never returns {@code null}.
   * @throws TokenException If digesting the data failed.
   */
  public byte[] digest(CkMechanism mechanism, byte[] data)
      throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      return session.digest(mechanism, data);
    } finally {
      requiteSession(session);
    }
  }

  /**
   * Digests the given key with the mechanism:
   *   Hash(prefix || key || suffix).
   *
   * @param mechanism
   *        The mechanism to use.
   * @param hKey
   *        handle of the to-be-digested key.
   * @return the message digest. Never returns {@code null}.
   * @throws TokenException
   *         If digesting the data failed.
   */
  public byte[] digestKey(CkMechanism mechanism, long hKey)
      throws TokenException {
    return digestKey(mechanism, null, hKey, null);
  }

  /**
   * Digests the given key with the mechanism:
   *   Hash(prefix || key || suffix).
   *
   * @param mechanism
   *        The mechanism to use.
   * @param prefix
   *        The data inputted to the hash algorithm before
   *        the key data. May be null
   * @param hKey
   *        handle of the to-be-digested key.
   * @param suffix
   *        The data inputted to the hash algorithm after
   *        the key data. May be null.
   * @return the message digest. Never returns {@code null}.
   * @throws TokenException
   *         If digesting the data failed.
   */
  public byte[] digestKey(CkMechanism mechanism,
                          byte[] prefix, long hKey, byte[] suffix)
      throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      return session.digestKey(mechanism, prefix, hKey, suffix);
    } finally {
      requiteSession(session);
    }
  }

  public byte[] sign(CkMechanism mechanism, long hKey, byte[] data)
      throws TokenException {
    return sign(mechanism, hKey, data, PKCS11.MAX_SIZE_NULL);
  }

  /**
   * Signs the given data with the key and mechanism.
   *
   * @param mechanism
   *        The mechanism to use.
   * @param hKey
   *        The signing key to use.
   * @param data
   *        The data to sign.
   * @return The signed data. Never returns {@code null}.
   * @throws TokenException
   *         If signing the data failed.
   */
  public byte[] sign(CkMechanism mechanism, long hKey, byte[] data, int maxSize)
      throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      return session.sign(mechanism, hKey, data, maxSize);
    } finally {
      requiteSession(session);
    }
  }

  /**
   * Generate a new secret key or a set of domain parameters. It uses the set
   * attributes of the template for setting the attributes of the new key
   * object. As mechanism the application can use a constant of the Mechanism
   * class.
   *
   * @param spec
   *        The template for the new key or domain parameters.
   * @return The newly generated secret key or domain parameters.
   * @throws TokenException
   *         If generating a new secret key or domain parameters failed.
   */
  public PKCS11KeyId generateKey(PKCS11SecretKeySpec spec)
      throws TokenException {
    if (spec.keyType() == null) {
      throw new IllegalArgumentException("CKA_KEY_TYPE is not set");
    }

    long keyType = spec.keyType();

    PKCS11Session session = borrowSession();
    long hKey;
    try {
      fillTemplate(session, spec);
      CkMechanism mechanism = getGenerateKeyCkm(keyType);

      hKey = session.generateKey(mechanism, spec.toTemplate());
    } finally {
      requiteSession(session);
    }

    PKCS11KeyId keyId = new PKCS11KeyId(PKCS11KeyId.KeyIdType.SECRET_KEY,
        hKey, keyType, spec.id(), spec.label());

    LOG.info("generated secret key {}", keyId);
    return keyId;
  }

  /**
   * Imports secret key object in the PKCS#11 token. The key itself will not be
   * generated within the PKCS#11 token.
   *
   * @param keyValue Key value. Must not be {@code null}.
   * @param spec
   *        Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#11 token.
   * @throws TokenException if PKCS#11 token exception occurs.
   */
  public PKCS11KeyId importSecretKey(
      byte[] keyValue, PKCS11SecretKeySpec spec)
      throws TokenException {
    PKCS11Session session = borrowSession();
    long hKey;
    try {
      fillTemplate(session, spec);

      Template attrs = spec.toTemplate();
      attrs.value(keyValue);

      hKey = session.importObject(attrs);
    } finally {
      requiteSession(session);
    }

    PKCS11KeyId keyId = new PKCS11KeyId(PKCS11KeyId.KeyIdType.SECRET_KEY,
        hKey, spec.keyType(), spec.id(), spec.label());

    LOG.info("created secret key {}", keyId);
    return keyId;
  }

  public boolean canGenerateKeyPair(PKCS11KeyPairType keyPairType) {
    CkMechanism mechanism;
    try {
      mechanism = getGenerateKeyPairCkm(keyPairType);
    } catch (TokenException e) {
      return false;
    }
    return supportsMechanism(mechanism.getMechanism(),
        CKF_GENERATE_KEY_PAIR);
  }

  private CkMechanism getGenerateKeyPairCkm(PKCS11KeyPairType keyPairType)
      throws TokenException {
    CkMechanism mechanism = keyPairType.getGenerateMechanism();
    if (mechanism.getMechanism() == CKM_RSA_PKCS_KEY_PAIR_GEN) {
      if (supportsMechanism(CKM_RSA_X9_31_KEY_PAIR_GEN,
              CKF_GENERATE_KEY_PAIR)) {
        mechanism = new CkMechanism(CKM_RSA_X9_31_KEY_PAIR_GEN,
            mechanism.getParameters());
      }
    }

    return mechanism;
  }

  public boolean canGenerateKey(long keyType) {
    CkMechanism mechanism;
    try {
      mechanism = getGenerateKeyCkm(keyType);
    } catch (TokenException e) {
      return false;
    }
    return supportsMechanism(mechanism.getMechanism(), CKF_GENERATE);
  }

  private CkMechanism getGenerateKeyCkm(long keyType) throws TokenException {
    long ckm;
    if (keyType == CKK_AES) {
      ckm = CKM_AES_KEY_GEN;
    } else if (keyType == CKK_GENERIC_SECRET) {
      ckm = CKM_GENERIC_SECRET_KEY_GEN;
    } else if (keyType == CKK_VENDOR_SM4) {
      ckm = CKM_VENDOR_SM4_KEY_GEN;
    } else if (keyType == CKK_CHACHA20) {
      ckm = CKM_CHACHA20_KEY_GEN;
    } else {
      if (keyType == CKK_SHA_1_HMAC) {
        ckm = CKM_SHA_1_KEY_GEN;
      } else if (keyType == CKK_SHA224_HMAC) {
        ckm = CKM_SHA224_KEY_GEN;
      } else if (keyType == CKK_SHA256_HMAC) {
        ckm = CKM_SHA256_KEY_GEN;
      } else if (keyType == CKK_SHA384_HMAC) {
        ckm = CKM_SHA384_KEY_GEN;
      } else if (keyType == CKK_SHA512_HMAC) {
        ckm = CKM_SHA512_KEY_GEN;
      } else if (keyType == CKK_SHA3_224_HMAC) {
        ckm = CKM_SHA3_224_KEY_GEN;
      } else if (keyType == CKK_SHA3_256_HMAC) {
        ckm = CKM_SHA3_256_KEY_GEN;
      } else if (keyType == CKK_SHA3_384_HMAC) {
        ckm = CKM_SHA3_384_KEY_GEN;
      } else if (keyType == CKK_SHA3_512_HMAC) {
        ckm = CKM_SHA3_512_KEY_GEN;
      } else {
        throw new TokenException("unknown key tye " + ckkCodeToName(keyType));
      }
    }
    return new CkMechanism(ckm);
  }

  /**
   * Generate a new public key - private key key-pair and use the set
   * attributes of the template objects for setting the attributes of the new
   * public key and private key objects. As mechanism the application can use
   * a constant of the Mechanism class.
   *
   * @param spec
   *        The template for the new keypair.
   * @return The newly generated key-pair.
   * @throws TokenException
   *         If generating a new key-pair failed.
   */
  public PKCS11KeyId generateKeyPair(PKCS11KeyPairSpec spec)
      throws TokenException {
    PKCS11Session session = borrowSession();
    PKCS11KeyPair handlePair;
    try {
      fillTemplate(session, spec);
      CkMechanism mechanism = getGenerateKeyPairCkm(spec.keyPairType());
      handlePair = session.generateKeyPair(mechanism, spec.toKeyPairTemplate());
    } finally {
      requiteSession(session);
    }

    KeyPairTemplate template = spec.toKeyPairTemplate();
    PKCS11KeyId ret = new PKCS11KeyId(PKCS11KeyId.KeyIdType.KEYPAIR,
        handlePair.getPrivateKey(), template.privateKey().keyType(),
        template.id(), template.publicKey().label());
    ret.setPublicKeyHandle(handlePair.getPublicKey());
    return ret;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  @Override
  public String toString() {
    return "\nMaximal session count: " + maxSessionCount +
        "\nNew session timeout: " + timeOutWaitNewSessionMs + " ms" +
        "\nRead only: " + readOnly +
        "\nToken: " + token;
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
  public Template getAttrValues(long hObject, AttributeTypes attributeTypes)
      throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      return session.getAttrValues(hObject, attributeTypes);
    } finally {
      requiteSession(session);
    }
  }

  /**
   * Gets all attributes for the given object handle.
   * @param hObject
   *        the object handle.
   * @return all attributes for the given object handle.
   * @throws TokenException
   *         if getting attributes failed.
   */
  public Template getDefaultAttrValues(long hObject)
      throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      return session.getDefaultAttrValues(hObject);
    } finally {
      requiteSession(session);
    }
  }

  void requiteSession(PKCS11Session session) {
    if (session.isRecoverable()) {
      sessions.add(session);
    } else {
      countSessions.decrementAndGet();
    }
  }

  PKCS11Session borrowSession() throws TokenException {
    if (maxSessionCount < 1) {
      throw new TokenException("could not open any session");
    }

    long start = clock.millis();

    try {
      PKCS11Session session = sessions.poll();
      if (session == null) {
        int num = countSessions.get();
        if (num < maxSessionCount) {
          session = openSession(false, false);
        }
      }

      if (session == null) {
        try {
          session = sessions.poll(timeOutWaitNewSessionMs,
              TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
        }
      }

      if (session == null) {
        throw new TokenException("found no idle session");
      }

      return session;
    } finally {
      if (LOG.isDebugEnabled()) {
        LOG.debug("borrowing session took {}ms",
            clock.millis() - start);
      }
    }
  }

  private PKCS11Session openSession(boolean login, boolean init)
      throws PKCS11Exception {
    long start = clock.millis();
    if (!init) {
      LOG.debug("openSession, #sessions={}, #maxSessions={}",
          countSessions.get(), maxSessionCount);
    }
    Session session = null;
    try {
      session = token.openSession(!readOnly, auth);
      if (login || !session.isLoggedIn()) {
        session.login();
      }
      countSessions.incrementAndGet();
    } catch (PKCS11Exception e) {
      LOG.warn("error opening session", e);
      throw e;
    } finally {
      LOG.info("openSession with hSession {} took {}ms",
          session == null ? "NULL" :  session.getSessionHandle(),
          clock.millis() - start);
    }

    return new PKCS11Session(session, this, maxMessageSize);
  }

  public void destroyKeyPairQuietly(PKCS11KeyPair keypair) {
    if (keypair == null) {
      return;
    }

    try {
      destroyObject(keypair.getPrivateKey());
    } catch (TokenException ex) {
      LOG.warn("error destroying private key {}", keypair.getPrivateKey(), ex);
    }

    try {
      destroyObject(keypair.getPublicKey());
    } catch (TokenException ex) {
      LOG.warn("error destroying public key {}", keypair.getPublicKey(), ex);
    }
  }

  public void destroyKeyQuietly(PKCS11KeyId keyId) {
    if (keyId == null) {
      return;
    }

    long hKey = keyId.getHandle();

    if (keyId.getType() == PKCS11KeyId.KeyIdType.KEYPAIR) {
      destroyKeyPairQuietly(new PKCS11KeyPair(
          keyId.getPublicKeyHandle(), hKey));
      return;
    }

    try {
      destroyObject(hKey);
    } catch (TokenException ex) {
      LOG.warn("error destroying key {}", hKey, ex);
    }
  }

  public boolean objectExistsByIdLabel(byte[] id, String label)
      throws TokenException {
    if ((id == null || id.length == 0) && Args.isBlank(label)) {
      return false;
    }

    Template template = new Template();
    if (id != null && id.length > 0) {
      template.id(id);
    }

    if (Args.isNotBlank(label)) {
      template.label(label);
    }

    return !getObjects(template, 1).isEmpty();
  }

  /**
   * Remove objects.
   *
   * @param id    ID of the objects to be deleted. At least one of id and
   *              label may not be {@code null}.
   * @param label Label of the objects to be deleted
   * @return how many objects have been deleted
   * @throws TokenException If PKCS#11 error happens.
   */
  public int destroyObjectsByIdLabel(byte[] id, String label)
      throws TokenException {
    if ((id == null || id.length == 0) && Args.isBlank(label)) {
      throw new IllegalArgumentException(
          "at least one of id and label may not be null");
    }

    Template template = new Template();
    if (id != null && id.length > 0) {
      template.id(id);
    }

    if (Args.isNotBlank(label)) {
      template.label(label);
    }

    return removeObjects0(template,
        "objects " + getDescription(id, label));
  }

  public boolean labelExists(String keyLabel) throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      return labelExists(session, keyLabel);
    } finally {
      requiteSession(session);
    }
  }

  private boolean labelExists(PKCS11Session session, String keyLabel)
      throws TokenException {
    Args.notNull(keyLabel, "keyLabel");
    Template template = new Template().label(keyLabel);
    return !getObjects(session, template, 1).isEmpty();
  } // method labelExists

  private boolean labelExists(PKCS11Session session, long objClass,
                              String keyLabel)
      throws TokenException {
    Args.notNull(keyLabel, "keyLabel");
    Template template = new Template().class_(objClass)
        .label(keyLabel);
    return !getObjects(session, template, 1).isEmpty();
  } // method labelExists

  public PKCS11Key getKey(byte[] keyId, String keyLabel) throws TokenException {
    return getKey(null, keyId, keyLabel);
  }

  public PKCS11Key getKey(Long objClass,
                          byte[] keyId, String keyLabel) throws TokenException {
    boolean isLabelBlank = Args.isBlank(keyLabel);
    if ((keyId == null || keyId.length == 0) && isLabelBlank) {
      return null;
    }
    return getKey(toAttributeVector(objClass, keyId, keyLabel));
  }

  public PKCS11KeyId getKeyId(byte[] keyId, String keyLabel)
      throws TokenException {
    return getKeyId(null, keyId, keyLabel);
  }

  public PKCS11KeyId getKeyId(Long objClass, byte[] keyId, String keyLabel)
      throws TokenException {
    if ((keyId == null || keyId.length == 0) && Args.isBlank(keyLabel)) {
      return null;
    }
    return getKeyId(toAttributeVector(objClass, keyId, keyLabel));
  }

  private static Template toAttributeVector(
      Long objClass, byte[] id, String label) {
    Template attrs = new Template();
    if (id != null && id.length > 0) {
      attrs.id(id);
    }

    if (!Args.isNotBlank(label)) {
      attrs.label(label);
    }

    if (objClass != null) {
      attrs.class_(objClass);
    }

    return attrs;
  }

  public List<Long> getObjects(Template template, int maxNo)
      throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      return getObjects(session, template, maxNo);
    } finally {
      requiteSession(session);
    }
  }

  /* ***************************************
   * PKCS#11 V3.0 Functions
   * ***************************************/

  public void loginUser()
      throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      session.login();
    } finally {
      requiteSession(session);
    }
  }

  /* ***************************************
   * PKCS#11 V3.2 Functions
   * ***************************************/

  /**
   * Decapsulate the given encapsulated key with the private key using
   * the given mechanism. The application passes a template to set
   * certain attributes of the decapsulated key. This creates a key object
   * after decapsulating the key and returns an object representing this key.
   *
   * @param mechanism
   *        The mechanism to use for decapsulating the key.
   * @param hPrivateKey
   *        The key to use for decapsulating.
   * @param encapsulatedKey
   *        The encrypted key to unwrap (decrypt).
   * @param keySpec
   *        The template for creating the new key object.
   * @return A key object representing the newly created key object.
   * @throws TokenException
   *         If unwrapping the key or creating a new key object failed.
   */
  public long decapsulateKey(CkMechanism mechanism, long hPrivateKey,
                             byte[] encapsulatedKey, PKCS11KeySpec keySpec)
      throws TokenException {
    PKCS11Session session = borrowSession();
    try {
      Template template;
      if (keySpec instanceof PKCS11SecretKeySpec) {
        fillTemplate(session, (PKCS11SecretKeySpec) keySpec);
        template = ((PKCS11SecretKeySpec) keySpec).toTemplate();
      } else {
        throw new TokenException("unknown keyTemplate " +
            keySpec.getClass().getName());
      }

      return session.decapsulateKey(mechanism, hPrivateKey,
          encapsulatedKey, template);
    } finally {
      requiteSession(session);
    }
  }

  /* ***************************************
   * Helper Functions
   * ***************************************/

  private List<Long> getObjects(PKCS11Session session,
                                Template template, int maxNo)
      throws TokenException {
    List<Long> objList = new LinkedList<>();

    long[] objHandles = findObjects(session, template, maxNo);
    for (long hObject : objHandles) {
      objList.add(hObject);
    }

    return objList;
  }

  private int removeObjects0(Template template, String desc)
      throws TokenException {
    try {
      List<Long> objects = getObjects(template, 9999);
      return destroyObjects(objects).size();
    } catch (TokenException ex) {
      throw new TokenException(
          "could not remove " + desc + ": " + ex.getMessage(), ex);
    }
  }

  private void fillTemplate(PKCS11Session session, PKCS11SecretKeySpec spec)
      throws TokenException {
    String label = spec.label();
    byte[] id = spec.id();

    if (label != null && labelExists(label)) {
      throw new IllegalArgumentException("label " + label
          + " exists, please specify another one");
    }

    if (id == null && spec.generateId()) {
      spec.id(this.generateUniqueId(session, null, idLen));
    }
  }

  private void fillTemplate(PKCS11Session session, PKCS11KeyPairSpec spec)
      throws TokenException {
    // CKA_LABEL
    String label = spec.label();
    if (label != null) {
      if (labelExists(session, label)) {
        throw new IllegalArgumentException("label " + label
            + " exists, please specify another one");
      }
    }

    String pubKeyLabel = spec.publicKeyLabel();
    if (pubKeyLabel != null) {
      if (labelExists(session, pubKeyLabel)) {
        throw new IllegalArgumentException("label " + pubKeyLabel
            + " exists, please specify another one");
      }
    }

    // CKA_ID
    if (spec.id() == null && spec.generateId()) {
      spec.id(generateUniqueId(session, null, idLen));
    }
  }

  private void fillTemplate(boolean forPrivateKey, PKCS11Session session,
                            PKCS11KeyPairSpec spec)
      throws TokenException {
    // CKA_LABEL
    String label = forPrivateKey ? spec.label() : spec.labelForPublicKey();
    long objClass = forPrivateKey ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
    if (label != null) {
      if (labelExists(session, objClass, label)) {
        throw new IllegalArgumentException("label " + label +
            " with CKO_CLASS=" + PKCS11T.ckoCodeToName(objClass) +
            " exists, please specify another one");
      }
    }

    // CKA_ID
    if (spec.id() == null && spec.generateId()) {
      spec.id(generateUniqueId(session, null, idLen));
    }
  }

  private static String getDescription(byte[] keyId, String keyLabel) {
    return "id " + (keyId == null ? "<null>" : Functions.toHex(keyId)) +
        " and label " + keyLabel;
  }

}
