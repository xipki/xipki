// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.type.CkMechanismInfo;
import org.xipki.pkcs11.wrapper.type.CkSlotInfo;
import org.xipki.pkcs11.wrapper.type.CkTokenInfo;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.crypt.EdwardsCurveEnum;
import org.xipki.pkcs11.xihsm.crypt.MontgomeryCurveEnum;
import org.xipki.pkcs11.xihsm.crypt.WeierstraussCurveEnum;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;
import org.xipki.pkcs11.xihsm.objects.*;
import org.xipki.pkcs11.xihsm.store.FilePersistStore;
import org.xipki.pkcs11.xihsm.store.MemPersistStore;
import org.xipki.pkcs11.xihsm.store.PersistStore;
import org.xipki.pkcs11.xihsm.store.Store;
import org.xipki.pkcs11.xihsm.store.VolatileStore;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.HsmUtil;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.pkcs11.xihsm.util.StorageMode;
import org.xipki.util.codec.Args;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.misc.StringUtil;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;
import static org.xipki.pkcs11.xihsm.util.XiConstants.P11MldsaVariant;
import static org.xipki.pkcs11.xihsm.util.XiConstants.P11MlkemVariant;

/**
 * @author Lijun Liao (xipki)
 */
public class Backend {

  private static final Logger LOG = LoggerFactory.getLogger(Backend.class);

  public static final long MAX_TOKEN_HANDLE = 0x00FF_FFFFL;

  public static final long MIN_VOLATILE_HANDLE = MAX_TOKEN_HANDLE + 1;

  public static final long MAX_VOLATILE_HANDLE = 0xFFFF_FFFFL;

  private static final SecureRandom rnd = new SecureRandom();

  private final PersistStore persistStore;

  private final VolatileStore volatileStore;

  private final XiHsmVendor vendor;

  private final Map<Long, XiSlot> slotMap = new HashMap<>();

  private final Map<Long, XiSession> sessionMap = new ConcurrentHashMap<>();

  public Backend(XiHsmVendor vendor, StorageMode storageMode,
                 ConfPairs confPairs) throws HsmException {
    Args.notNull(storageMode, "storageMode");
    Args.notNull(confPairs, "confPairs");
    this.vendor = Args.notNull(vendor, "vendor");

    if (storageMode == StorageMode.mem) {
      persistStore = new MemPersistStore(vendor);
    } else {
      String tenant = confPairs.removePair("tenant");
      if (StringUtil.isBlank(tenant)) {
        tenant = "default";
      }

      String basedir = confPairs.removePair("basedir");
      if (StringUtil.isBlank(basedir)) {
        basedir = null;
      }

      persistStore = new FilePersistStore(vendor, tenant, basedir);
    }

    volatileStore = new VolatileStore(persistStore.getSlotIds());

    StoreSlotInfo[] slotInfos = persistStore.getSlotInfos();
    for (StoreSlotInfo info : slotInfos) {
      long slotId = info.getSlotId();
      CkSlotInfo ckInfo = info.getSlotInfo();
      XiSlot slot = new XiSlot(vendor, this, ckInfo.manufacturerID(),
          info.getSlotIndex(), slotId, new AtomicLong(1),
          info.getUserVerifier());
      slotMap.put(slotId, slot);
    }
  }

  private static PKCS11Exception logAndGet(String method, HsmException e) {
    LOG.warn("{}: {}", method, e.getMessage());
    LOG.debug(method, e);
    return e.toPKCS11Exception();
  }

  private XiSlot getSlot(long slotId) throws PKCS11Exception {
    XiSlot slot = slotMap.get(slotId);
    if (slot != null) {
      return slot;
    }

    throw new PKCS11Exception(CKR_SLOT_ID_INVALID);
  }

  public SecureRandom getRandom() {
    return rnd;
  }

  public CkSlotInfo C_GetSlotInfo(long slotID) throws PKCS11Exception {
    return getSlot(slotID).C_GetSlotInfo();
  }

  public CkTokenInfo C_GetTokenInfo(long slotID) throws PKCS11Exception {
    return getSlot(slotID).C_GetTokenInfo();
  }

  public long[] C_GetMechanismList(long slotID) throws PKCS11Exception {
    return getSlot(slotID).C_GetMechanismList();
  }

  public CkMechanismInfo C_GetMechanismInfo(long slotID, long type)
      throws PKCS11Exception {
    try {
      return getSlot(slotID).C_GetMechanismInfo(type);
    } catch (HsmException e) {
      throw logAndGet("C_GetMechanismInfo", e);
    }
  }

  public long C_OpenSession(long slotID, long flags)
      throws PKCS11Exception {
    XiSlot slot = getSlot(slotID);
    try {
      long hSession = slot.C_OpenSession(flags);
      XiSession session = slot.getSession(hSession);
      sessionMap.put(hSession, session);
      return hSession;
    } catch (HsmException e) {
      throw logAndGet("C_OpenSession", e);
    }
  }

  public void C_CloseSession(long hSession) throws PKCS11Exception {
    XiSession session = sessionMap.remove(hSession);
    if (session == null) {
      throw new PKCS11Exception(CKR_SESSION_HANDLE_INVALID);
    }
    session.C_CloseSession();
  }

  public void C_CloseAllSessions(long slotID) throws PKCS11Exception {
    try {
      List<Long> hSessions = getSlot(slotID).C_CloseAllSessions();
      for (long hSession : hSessions) {
        sessionMap.remove(hSession);
      }
      getSlot(slotID).C_CloseAllSessions();
    } catch (HsmException e) {
      throw logAndGet("C_CloseAllSessions", e);
    }
  }

  private Store store(boolean token) {
    return token ? persistStore : volatileStore;
  }

  public long[] findObjects(long slotId, LoginState loginState,
                            XiTemplate criteria)
      throws HsmException {
    List<Long> handles = new LinkedList<>();
    Boolean inToken = criteria.removeBool(CKA_TOKEN);
    if (inToken != null) {
      store(inToken).findObjects(handles, slotId, loginState, criteria);
    } else {
      volatileStore.findObjects(handles, slotId, loginState, criteria);
      persistStore.findObjects(handles, slotId, loginState, criteria);
    }

    Collections.sort(handles);
    return HsmUtil.listToLongs(handles);
  }

  public void destroyObject(long slotId, long hObject, boolean sessionRw,
                            LoginState loginState)
    throws HsmException {
    boolean persist = isPersistHandle(hObject);
    if (isPersistHandle(hObject)) {
      if (!sessionRw) {
        throw new HsmException(CKR_SESSION_READ_ONLY);
      }
    }

    store(persist).destroyObject(slotId, hObject, loginState);
  }

  public void destroyAllSessionObjects(long slotId) throws HsmException {
    volatileStore.destroyAllObjects(slotId);
  }

  private static boolean isPersistHandle(long handle) {
    return handle < MIN_VOLATILE_HANDLE;
  }

  public long[] C_GenerateKeyPair(
      LoginState loginState, boolean sessionRw, long slotId,
      XiMechanism mechanism, XiTemplate pkAttrs, XiTemplate skAttrs)
      throws HsmException {
    long keyType = pkAttrs.removeNonNullLong(CKA_KEY_TYPE);

    long ckm = mechanism.getCkm();
    // remove the CKA_CLASS
    pkAttrs.removeAttributes(CKA_CLASS);

    skAttrs.removeAttributes(CKA_CLASS, CKA_TOKEN, CKA_EC_PARAMS,
        CKA_MODULUS_BITS, CKA_KEY_TYPE);

    boolean inToken = checkInToken(sessionRw, pkAttrs);
    Store store = store(inToken);

    XiPrivateKey privateKey;
    XiPublicKey publicKey;

    long[] handles;

    ObjectInitMethod initMethod = ObjectInitMethod.NEW;
    long cku = loginState.getUserType();
    Origin newObjectMethod = Origin.GENERATE;

    try {
      if (ckm == CKM_RSA_X9_31_KEY_PAIR_GEN
          || ckm == CKM_RSA_PKCS_KEY_PAIR_GEN) {
        if (keyType != CKK_RSA) {
          throw new HsmException(CKR_TEMPLATE_INCONSISTENT,
              "Key is not RSA");
        }

        int modulusBitSize = pkAttrs.removeNonNullInt(CKA_MODULUS_BITS);

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(modulusBitSize, rnd);
        KeyPair keyPair = kpGen.generateKeyPair();

        RSAPrivateCrtKey sk = (RSAPrivateCrtKey) keyPair.getPrivate();
        java.security.interfaces.RSAPublicKey pk =
            (java.security.interfaces.RSAPublicKey) keyPair.getPublic();

        BigInteger modulus = pk.getModulus();
        BigInteger publicExponent = pk.getPublicExponent();

        handles = store.nextKeyPairHandles(slotId);

        publicKey = new XiRSAPublicKey(vendor, cku, newObjectMethod,
            handles[0], inToken, ckm, modulus, publicExponent);

        privateKey = new XiRSAPrivateKey(vendor, cku, newObjectMethod,
            handles[1], inToken, ckm, modulus,
            publicExponent, sk.getPrivateExponent(),
            sk.getPrimeP(), sk.getPrimeQ(),
            sk.getPrimeExponentP(), sk.getPrimeExponentQ(),
            sk.getCrtCoefficient());
      } else if (ckm == CKM_EC_KEY_PAIR_GEN
          || ckm == CKM_VENDOR_SM2_KEY_PAIR_GEN) {
        if (ckm == CKM_VENDOR_SM2_KEY_PAIR_GEN) {
          if (keyType != CKK_VENDOR_SM2) {
            throw new HsmException(CKR_TEMPLATE_INCONSISTENT,
                "The key is not SM2: " +
                    PKCS11T.ckkCodeToName(keyType));
          }
        } else {
          if (keyType != CKK_VENDOR_SM2 && keyType != CKK_EC) {
            throw new HsmException(
                CKR_TEMPLATE_INCONSISTENT, "The key is not EC");
          }
        }

        WeierstraussCurveEnum curve;
        if (keyType == CKK_VENDOR_SM2) {
          curve = WeierstraussCurveEnum.SM2;

          byte[] ecParams = pkAttrs.removeByteArray(
              PKCS11T.CKA_EC_PARAMS);
          if (ecParams != null) {
            if (WeierstraussCurveEnum.SM2 !=
                WeierstraussCurveEnum.ofEcParams(ecParams)) {
              throw new HsmException(
                  PKCS11T.CKR_TEMPLATE_INCONSISTENT,
                  "The key is not SM2");
            }
          }
        } else {
          byte[] ecParams = pkAttrs.removeNonNullByteArray(CKA_EC_PARAMS);
          curve = WeierstraussCurveEnum.ofEcParamsNonNull(ecParams);
        }

        byte[][] keypair = curve.generateKeyPair(rnd);
        byte[] sk      = keypair[0];
        byte[] ecPoint = keypair[1];

        handles = store.nextKeyPairHandles(slotId);

        byte[] ecParams = curve.getEncodedOid();

        if (curve == WeierstraussCurveEnum.SM2) {
          publicKey  = new XiSm2ECPublicKey(vendor, cku, newObjectMethod,
              handles[0], inToken, keyType, ckm, ecParams, ecPoint);
          privateKey = new XiSm2ECPrivateKey(vendor, cku, newObjectMethod,
              handles[1], inToken, keyType, ckm, ecParams, sk, ecPoint);
        } else {
          publicKey  = new XiWeierstrassECPublicKey(
              vendor, cku, newObjectMethod,
              handles[0], inToken, keyType, ckm, ecParams, ecPoint);
          privateKey = new XiWeierstrassECPrivateKey(
              vendor, cku, newObjectMethod,
              handles[1], inToken, keyType, ckm, ecParams, sk);
        }
      } else if (ckm == CKM_EC_EDWARDS_KEY_PAIR_GEN) {
        if (keyType != CKK_EC_EDWARDS) {
          throw new HsmException(CKR_TEMPLATE_INCONSISTENT,
              "The key is not EC-Edwards");
        }

        if (mechanism.getParameter() != null) {
          throw new HsmException(CKR_MECHANISM_PARAM_INVALID,
              "Mechanism.parameters != NULL");
        }

        byte[] ecParams = pkAttrs.removeNonNullByteArray(CKA_EC_PARAMS);
        EdwardsCurveEnum curveEnum =
            EdwardsCurveEnum.ofEcParamsNonNull(ecParams);
        byte[][] keypair = curveEnum.generateKeyPair(rnd);

        handles = store.nextKeyPairHandles(slotId);
        publicKey = new XiEdwardsECPublicKey(vendor, cku, newObjectMethod,
            handles[0], inToken, ckm, ecParams, keypair[1]);
        privateKey = new XiEdwardsECPrivateKey(vendor, cku, newObjectMethod,
            handles[1], inToken, ckm, ecParams, keypair[0]);
      } else if (ckm == CKM_EC_MONTGOMERY_KEY_PAIR_GEN) {
        if (keyType != CKK_EC_MONTGOMERY) {
          throw new HsmException(CKR_TEMPLATE_INCONSISTENT,
              "The key is not EC-Montgomery");
        }

        if (mechanism.getParameter() != null) {
          throw new HsmException(CKR_MECHANISM_PARAM_INVALID,
              "Mechanism.parameters != NULL");
        }

        byte[] ecParams = pkAttrs.removeByteArray(CKA_EC_PARAMS);
        MontgomeryCurveEnum curveEnum =
            MontgomeryCurveEnum.ofEcParamsNonNull(ecParams);
        byte[][] keypair = curveEnum.generateKeyPair(rnd);

        handles = store.nextKeyPairHandles(slotId);
        publicKey = new XiMontgomeryECPublicKey(vendor, cku, newObjectMethod,
            handles[0], inToken, ckm, ecParams, keypair[1]);
        privateKey = new XiMontgomeryECPrivateKey(vendor, cku, newObjectMethod,
            handles[1], inToken, ckm, ecParams, keypair[0]);
      } else if (ckm == CKM_ML_DSA_KEY_PAIR_GEN) {
        long variantCode = pkAttrs.removeNonNullLong(CKA_PARAMETER_SET);
        P11MldsaVariant variant = P11MldsaVariant.ofCode(variantCode);
        skAttrs.removeAttributes(CKA_PARAMETER_SET);
        KeyPair keyPair = variant.generateKeyPair();
        byte[] sk = PrivateKeyInfo.getInstance(
            keyPair.getPrivate().getEncoded()).getPrivateKey().getOctets();
        byte[] pk = SubjectPublicKeyInfo.getInstance(
            keyPair.getPublic().getEncoded()).getPublicKeyData().getBytes();

        handles = store.nextKeyPairHandles(slotId);
        publicKey  = new XiMLDSAPublicKey(vendor, cku, newObjectMethod,
            handles[0], inToken, ckm, variant, pk);
        privateKey = new XiMLDSAPrivateKey(vendor, cku, newObjectMethod,
            handles[1], inToken, ckm, variant, sk);
      } else if (ckm == CKM_ML_KEM_KEY_PAIR_GEN) {
        long variantCode = pkAttrs.removeNonNullLong(CKA_PARAMETER_SET);
        skAttrs.removeAttributes(CKA_PARAMETER_SET);
        P11MlkemVariant variant = P11MlkemVariant.ofCode(variantCode);

        MLKEMKeyPairGenerator kpGen = new MLKEMKeyPairGenerator();
        MLKEMKeyGenerationParameters params = new MLKEMKeyGenerationParameters(
            getRandom(), XiMLKEMPublicKey.getParams(variant));
        kpGen.init(params);
        AsymmetricCipherKeyPair keyPair = kpGen.generateKeyPair();
        MLKEMPublicKeyParameters pkParams =
            (MLKEMPublicKeyParameters) keyPair.getPublic();
        MLKEMPrivateKeyParameters skParams =
            (MLKEMPrivateKeyParameters) keyPair.getPrivate();

        handles = store.nextKeyPairHandles(slotId);
        publicKey  = new XiMLKEMPublicKey(vendor, cku, newObjectMethod,
            handles[0], inToken, ckm, variant, pkParams.getEncoded());
        privateKey = new XiMLKEMPrivateKey(vendor, cku, newObjectMethod,
            handles[1], inToken, ckm, variant, skParams.getEncoded());
      } else {
        throw new HsmException(CKR_MECHANISM_INVALID,
            "unsupported mechanism " +
                PKCS11T.codeToName(Category.CKF_MECHANISM, ckm));
      }
    } catch (GeneralSecurityException | RuntimeException e) {
      throw new HsmException(CKR_GENERAL_ERROR,
          "error generating keypair", e);
    }

    publicKey.updateAttributes(loginState, initMethod, pkAttrs);
    privateKey.updateAttributes(loginState, initMethod, skAttrs);

    store.addObject(slotId, publicKey);
    boolean succ = false;
    try {
      store.addObject(slotId, privateKey);
      succ = true;
    } finally {
      if (!succ) {
        store.destroyObject(slotId, publicKey.getHandle(), loginState);
      }
    }

    return handles;
  }

  public long C_GenerateKey(
      LoginState loginState, boolean sessionRw, long slotId,
      XiMechanism mechanism, XiTemplate template)
      throws HsmException {
    long keyType = template.removeNonNullLong(CKA_KEY_TYPE);

    template.removeAttributes(CKA_CLASS);
    boolean inToken = checkInToken(sessionRw, template);

    int valueLen;
    if (keyType == CKK_AES) {
      valueLen = template.removeNonNullInt(CKA_VALUE_LEN);

      if (!(valueLen == 16 || valueLen == 24 || valueLen == 32)) {
        throw new HsmException(CKR_TEMPLATE_INCONSISTENT,
            "invalid CKA_VALUE_LEN " + valueLen);
      }
    } else if (keyType == CKK_DES3 || keyType == CKK_VENDOR_SM4) {
      Integer i = template.removeInt(CKA_VALUE_LEN);
      valueLen = (keyType == CKK_DES3) ? 24 : 16;
      if (i != null) {
        if (valueLen != i) {
          throw new HsmException(CKR_TEMPLATE_INCONSISTENT,
              "CKA_VALUE_LEN != " + valueLen);
        }
      }
    } else {
      valueLen = template.removeNonNullInt(CKA_VALUE_LEN);
    }

    byte[] value = new byte[valueLen];
    rnd.nextBytes(value);

    Store store = store(inToken);
    long handle = store.nextObjectHandle(slotId);

    XiSecretKey secretKey = new XiSecretKey(
        vendor, loginState.getUserType(), Origin.GENERATE,
        handle, inToken, keyType, mechanism.getCkm(), value);
    secretKey.updateAttributes(loginState, ObjectInitMethod.NEW, template);

    store.addObject(slotId, secretKey);
    return handle;
  }

  public long C_CreateObject(
      XiHsmVendor vendor, LoginState loginState, boolean sessionRw,
      long slotId, XiTemplate attributes) throws HsmException {
    boolean inToken = checkInToken(sessionRw, attributes);
    Store storage = store(inToken);
    long handle = storage.nextObjectHandle(slotId);

    attributes.add(XiAttribute.ofBool(CKA_TOKEN, inToken));
    attributes.add(XiAttribute.ofLong(
        XiP11Storage.CKA_XIHSM_CKU, loginState.getUserType()));
    attributes.add(XiAttribute.ofLong(
        XiP11Storage.CKA_XIHSM_ORIGIN,
        Origin.CREATE_OBJECT.getCode()));

    // CKA_TOKEN will be used here
    XiP11Storage obj = XiP11Storage.fromAttributes(
        vendor, loginState, ObjectInitMethod.NEW, handle, attributes);
    storage.addObject(slotId, obj);
    return handle;
  }

  public Template C_GetAttributeValue(
      long slotId, long hObject, LoginState loginState, long[] types)
      throws HsmException {
    XiP11Storage obj = getStorageForHandle(hObject)
        .getObject(slotId, hObject, loginState);

    return obj.getAttributes(types).toCkAttributeArray();
  }

  public void C_SetAttributeValue(
      LoginState loginState, boolean sessionRw, long slotId, long hObject,
      XiTemplate template) throws HsmException {
    Store storage = getStorageForHandle(sessionRw, hObject, sessionRw);
    storage.updateObject(slotId, hObject, loginState, template);
  }

  public XiKey getKey(long slotId, long hKey, LoginState loginState)
      throws HsmException {
    Store storage = store(isPersistHandle(hKey));
    XiP11Storage obj = storage.getObject(slotId, hKey, loginState);
    if (!(obj instanceof XiKey)) {
      throw new HsmException(CKR_OBJECT_HANDLE_INVALID);
    }

    return (XiKey) obj;
  }

  public void destroyObject(boolean sessionRw, long slotId, long hObject,
                            LoginState loginState)
      throws HsmException {
    Store storage = getStorageForHandle(sessionRw, hObject, true);
    storage.destroyObject(slotId, hObject, loginState);
  }

  private static boolean checkInToken(boolean sessionRw, XiTemplate attrs)
      throws HsmException {
    Boolean b = attrs.removeBool(CKA_TOKEN);
    boolean inToken = b != null && b;
    if (inToken) {
      if (!sessionRw) {
        throw new HsmException(CKR_SESSION_READ_ONLY, null);
      }
    }
    return inToken;
  }

  public long[] getSlotIds() {
    return persistStore.getSlotIds();
  }

  XiSession getSession(long hSession) throws PKCS11Exception {
    XiSession session = sessionMap.get(hSession);
    if (session == null) {
      throw new PKCS11Exception(CKR_SESSION_HANDLE_INVALID);
    }

    return session;
  }

  public void close() {
    for (XiSession session : sessionMap.values()) {
      session.close();
    }

    for (XiSlot slot : slotMap.values()) {
      slot.close();
    }

    slotMap.clear();
    sessionMap.clear();

    persistStore.close();
  }

  private Store getStorageForHandle(long hObject) throws HsmException {
    return getStorageForHandle(false, hObject, false);
  }

  private Store getStorageForHandle(
      boolean sessionRw, long hObject, boolean forWrite)
      throws HsmException {
    boolean token = isPersistHandle(hObject);
    if (token && forWrite && !sessionRw) {
      throw new HsmException(CKR_SESSION_READ_ONLY, null);
    }

    return store(token);
  }

}
