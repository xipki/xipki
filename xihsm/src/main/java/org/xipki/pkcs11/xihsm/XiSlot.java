// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.type.CkMechanismInfo;
import org.xipki.pkcs11.wrapper.type.CkSlotInfo;
import org.xipki.pkcs11.wrapper.type.CkTokenInfo;
import org.xipki.pkcs11.wrapper.type.CkVersion;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;
import org.xipki.pkcs11.xihsm.mgr.UserVerifier;
import org.xipki.pkcs11.xihsm.objects.XiKey;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.HsmUtil;
import org.xipki.util.codec.Args;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * @author Lijun Liao (xipki)
 */
public class XiSlot {

  private final int index;

  private final long slotId;

  private final CkSlotInfo slotInfo;

  private final CkTokenInfo tokenInfo;

  private static final int maxSessionCount = 256;

  private final ConcurrentHashMap<Long, XiSession> sessions =
      new ConcurrentHashMap<>();

  private final LoginState loginState;

  private final AtomicLong nextSessionHandle;

  private final Backend store;

  private final XiHsmVendor vendor;

  public XiSlot(XiHsmVendor vendor, Backend store, String manufacturerID,
                int index, long slotId, AtomicLong nextSessionHandle,
                UserVerifier userVerifier) {
    this.vendor = vendor;
    this.store = store;
    this.loginState = new LoginState(userVerifier);
    this.index = Args.notNegative(index, "index");
    this.slotId = slotId;
    this.slotInfo  = buildSlotInfo (manufacturerID, slotId);
    this.tokenInfo = buildTokenInfo(manufacturerID, slotId);
    this.nextSessionHandle =
        Args.notNull(nextSessionHandle, "nextSessionHandle");
  }

  XiHsmVendor getVendor() {
    return vendor;
  }

  /**
   * <pre>
   *    typedef struct CK_SLOT_INFO {
   *      CK_UTF8CHAR  slotDescription[64];
   *      CK_UTF8CHAR  manufacturerID[32];
   *      CK_FLAGS     flags;
   *      CK_VERSION   hardwareVersion;
   *      CK_VERSION   firmwareVersion;
   *    } CK_SLOT_INFO;
   * </pre>
   */
  private static CkSlotInfo buildSlotInfo(String manufacturerID, long slotId) {
    return new CkSlotInfo("xipki xihsm slot " + slotId,
        manufacturerID, PKCS11T.CKF_TOKEN_PRESENT, HsmUtil.buildVersion(1, 0),
        HsmUtil.buildVersion(1, 0));
  }

  /**
   * <pre>
   * typedef struct CK_TOKEN_INFO {
   *     CK_UTF8CHAR  label[32];
   *     CK_UTF8CHAR  manufacturerID[32];
   *     CK_UTF8CHAR  model[16];
   *     CK_CHAR      serialNumber[16];
   *     CK_FLAGS     flags;
   *     CK_ULONG     ulMaxSessionCount;
   *     CK_ULONG     ulSessionCount;
   *     CK_ULONG     ulMaxRwSessionCount;
   *     CK_ULONG     ulRwSessionCount;
   *     CK_ULONG     ulMaxPinLen;
   *     CK_ULONG     ulMinPinLen;
   *     CK_ULONG     ulTotalPublicMemory;
   *     CK_ULONG     ulFreePublicMemory;
   *     CK_ULONG     ulTotalPrivateMemory;
   *     CK_ULONG     ulFreePrivateMemory;
   *     CK_VERSION   hardwareVersion;
   *     CK_VERSION   firmwareVersion;
   *     CK_CHAR      utcTime[16];
   *                  -- YYYYMMDDhhmmss00
   * } CK_TOKEN_INFO;
   * </pre>
   */
  private static CkTokenInfo buildTokenInfo(
      String manufacturerID, long slotId) {
    String label = "token " + slotId;
    String model = manufacturerID + " G1";
    String serialNumber = "G1-123456";
    long flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED |
        CKF_CLOCK_ON_TOKEN | CKF_TOKEN_INITIALIZED;
    long sessionCount       = 0;
    long maxRwSessionCount  = maxSessionCount;
    long rwSessionCount     = 0;
    long maxPinLen          = 32;
    long minPinLen          = 4;
    long totalPublicMemory  = CK_UNAVAILABLE_INFORMATION;
    long freePublicMemory   = CK_UNAVAILABLE_INFORMATION;
    long totalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    long freePrivateMemory  = CK_UNAVAILABLE_INFORMATION;
    CkVersion hardwareVersion = HsmUtil.buildVersion(1, 0);
    CkVersion firmwareVersion = HsmUtil.buildVersion(1, 0);
    String utcTime          = buildTokenUtcTime();

    return new CkTokenInfo(label, manufacturerID, model, serialNumber, flags,
        maxSessionCount, sessionCount, maxRwSessionCount, rwSessionCount,
        maxPinLen, minPinLen, totalPublicMemory, freePublicMemory,
        totalPrivateMemory, freePrivateMemory,
        hardwareVersion, firmwareVersion, utcTime);
  }

  // YYYYMMDDhhmmss00
  private static String buildTokenUtcTime() {
    ZonedDateTime c = ZonedDateTime.ofInstant(Instant.now(), ZoneId.of("UTC"));
    return prepend0(4, c.getYear())
        + prepend0(2, c.getMonthValue())
        + prepend0(2, c.getDayOfMonth())
        + prepend0(2, c.getHour())
        + prepend0(2, c.getMinute())
        + prepend0(2, c.getSecond())
        + "00";
  }

  private static String prepend0(int size, int v) {
    String text = Integer.toString(v);
    if (text.length() < size) {
      char[] cs = new char[size - text.length()];
      Arrays.fill(cs, '0');
      return new String(cs) + text;
    } else {
      return text;
    }
  }

  public void close() {
    loginState.logoutIfLoggedIn();
  }

  public SecureRandom getRandom() {
    return store.getRandom();
  }

  public int getIndex() {
    return index;
  }

  public long getSlotId() {
    return slotId;
  }

  public CkSlotInfo C_GetSlotInfo() {
    return slotInfo;
  }

  public CkTokenInfo C_GetTokenInfo() {
    long sessionCount = sessions.size();
    int rwCount = 0;
    for (XiSession session : sessions.values()) {
      if (session.isRw()) {
        rwCount++;
      }
    }
    long rwSessionCount = rwCount;
    String utcTime = buildTokenUtcTime();

    return new CkTokenInfo(tokenInfo.label(), tokenInfo.manufacturerID(),
        tokenInfo.model(), tokenInfo.serialNumber(), tokenInfo.getFlags(),
        maxSessionCount, sessionCount,
        tokenInfo.maxRwSessionCount(), rwSessionCount,
        tokenInfo.maxPinLen(), tokenInfo.minPinLen(),
        tokenInfo.totalPublicMemory(), tokenInfo.freePublicMemory(),
        tokenInfo.totalPrivateMemory(), tokenInfo.freePrivateMemory(),
        tokenInfo.hardwareVersion(), tokenInfo.firmwareVersion(), utcTime);
  }

  public long[] C_GetMechanismList() {
    return getVendor().getCkms();
  }

  public CkMechanismInfo C_GetMechanismInfo(long type)
      throws HsmException {
    CkMechanismInfo info = getVendor().getMechanismInfo(type);
    if (info != null) {
      return info;
    }
    throw new HsmException(CKR_MECHANISM_INVALID,
        "Mechanism " + ckmCodeToName(type) +
        " is not supported");
  }

  public LoginState loginState() {
    return loginState;
  }

  public LoginState loginState(long hSession) throws HsmException {
    return loginState;
  }

  public long C_OpenSession(long flags) throws HsmException {
    if ((flags & CKF_SERIAL_SESSION) == 0) {
      throw new HsmException(CKR_SESSION_PARALLEL_NOT_SUPPORTED, null);
    }

    boolean rw = (flags & CKF_RW_SESSION) != 0;

    long hSession = nextSessionHandle.incrementAndGet();
    XiSession session = new XiSession(hSession, this, rw);
    sessions.put(hSession, session);
    return hSession;
  }

  public XiSession getSession(long hSession) throws HsmException {
    XiSession session = sessions.get(hSession);
    if (session == null) {
      throw new HsmException(CKR_SESSION_HANDLE_INVALID,
          "invalid hSession " + hSession);
    }
    return session;
  }

  public void removeSession(long hSession) {
    sessions.remove(hSession);
  }

  public List<Long> C_CloseAllSessions() throws HsmException {
    try {
      for (XiSession session : sessions.values()) {
        session.close();
      }

      Enumeration<Long> handleSet = sessions.keys();
      List<Long> handleList = new LinkedList<>();
      while (handleSet.hasMoreElements()) {
        handleList.add(handleSet.nextElement());
      }

      store.destroyAllSessionObjects(slotId);
      return handleList;
    } finally {
      sessions.clear();
    }
  }

  public void C_DestroyObject(long hSession, boolean sessionRw, long hObject)
      throws HsmException {
    store.destroyObject(sessionRw, slotId, hObject, loginState(hSession));
  }

  public long[] findObjects(long hSession, XiTemplate template)
      throws HsmException {
    return store.findObjects(slotId, loginState(hSession), template);
  }

  public long[] C_GenerateKeyPair(
      long hSession, boolean sessionRw, XiMechanism mechanism,
      XiTemplate publicKeyTemplate, XiTemplate privateKeyTemplate)
      throws HsmException {
    return store.C_GenerateKeyPair(loginState(hSession), sessionRw, slotId,
        mechanism, publicKeyTemplate, privateKeyTemplate);

  }

  public long C_GenerateKey(
      long hSession, boolean sessionRw, XiMechanism pMechanism,
      XiTemplate template)
      throws HsmException {
    return store.C_GenerateKey(loginState(hSession), sessionRw, slotId,
        pMechanism, template);
  }

  public long C_CreateObject(
      long hSession, boolean sessionRw, XiTemplate attrs)
      throws HsmException {
    return store.C_CreateObject(vendor, loginState(hSession),
        sessionRw, slotId, attrs);
  }

  public Template C_GetAttributeValue(
      long hSession, long hObject, long[] attrTypes)
      throws HsmException {
    return store.C_GetAttributeValue(slotId, hObject,
        loginState(hSession), attrTypes);
  }

  public void C_SetAttributeValue(
      long hSession, boolean sessionRw, long hObject, XiTemplate template)
      throws HsmException {
    store.C_SetAttributeValue(loginState(hSession), sessionRw, slotId,
        hObject, template);
  }

  public XiKey getKey(long hSession, long hKey) throws HsmException {
    return store.getKey(slotId, hKey, loginState(hSession));
  }

}
