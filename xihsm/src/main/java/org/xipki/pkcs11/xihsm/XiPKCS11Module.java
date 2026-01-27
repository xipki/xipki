// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.attrs.Attribute;
import org.xipki.pkcs11.wrapper.attrs.LongArrayAttribute;
import org.xipki.pkcs11.wrapper.attrs.LongAttribute;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.params.CkParams;
import org.xipki.pkcs11.wrapper.type.CkInfo;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.pkcs11.wrapper.type.CkMechanismInfo;
import org.xipki.pkcs11.wrapper.type.CkSessionInfo;
import org.xipki.pkcs11.wrapper.type.CkSlotInfo;
import org.xipki.pkcs11.wrapper.type.CkTokenInfo;
import org.xipki.pkcs11.wrapper.type.CkVersion;
import org.xipki.pkcs11.wrapper.vendor.SpecialBehaviour;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.StorageMode;
import org.xipki.util.codec.Args;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.misc.StringUtil;

import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * @author Lijun Liao (xipki)
 */
public class XiPKCS11Module {

  private static final Logger LOG =
      LoggerFactory.getLogger(XiPKCS11Module.class);

  private static final CkVersion V3_0 = new CkVersion((byte) 3, (byte) 0);
  private static final CkVersion V3_2 = new CkVersion((byte) 3, (byte) 2);

  private final AtomicBoolean initialized = new AtomicBoolean(false);

  private String modulePath;

  private CkInfo info;

  private Backend backend;

  private XiHsmVendor vendor;

  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    String version = StringUtil.getBundleVersion(XiPKCS11Module.class);
    LOG.info("xihsm version {}", version);
  }

  CkInfo getCkInfo() {
    return info;
  }

  void initModule(String modulePath) throws PKCS11Exception {
    this.modulePath = Args.notNull(modulePath, "modulePath");

    StorageMode storageMode;
    ConfPairs confPairs;
    String vendorName = null;

    if (modulePath.isEmpty()) {
      storageMode = StorageMode.mem;
      confPairs = new ConfPairs();
    } else {
      int sepIndex = modulePath.indexOf(':');

      String modeStr;
      if (sepIndex == -1) {
        modeStr = modulePath;
        confPairs = new ConfPairs();
      } else {
        modeStr = modulePath.substring(0, sepIndex);
        String confStr = modulePath.substring(sepIndex + 1);
        confPairs = new ConfPairs(confStr);
      }

      storageMode = StorageMode.valueOf(modeStr);
      vendorName = confPairs.removePair("vendor");
    }

    if (StringUtil.isBlank(vendorName)) {
      vendorName = "xihsm";
    }

    try {
      this.vendor = XiHsmVendor.getInstance(vendorName);
    } catch (Exception e) {
      LOG.error("error initializing vendor configuration", e);
      throw new PKCS11Exception(CKR_DEVICE_ERROR);
    }

    info = new CkInfo(vendor.getCryptokiVersion(),
        vendor.getManufactureID(), 0, vendor.getLibraryDescription(),
        vendor.getLibraryVersion());

    try {
      this.backend = new Backend(vendor, storageMode, confPairs);
    } catch (HsmException e) {
      LOG.error("could not initialize XiPKCS11", e);
      throw new PKCS11Exception(CKR_DEVICE_ERROR);
    }
  }

  public void closeModule() {
    backend.close();
  }

  public String toString() {
    return "modulePath: " + modulePath;
  }

  private static PKCS11Exception logAndGet(String method, HsmException e) {
    LOG.warn("{}: {}", method, e.getMessage());
    LOG.debug(method, e);
    return e.toPKCS11Exception();
  }

  public void C_Initialize(long flags)
      throws PKCS11Exception {
    synchronized (initialized) {
      if (initialized.get()) {
        throw new PKCS11Exception(CKR_CRYPTOKI_ALREADY_INITIALIZED);
      }

      initialized.set(true);
    }
  }

  private void assertInitialized() throws PKCS11Exception {
    if (!initialized.get()) {
      throw new PKCS11Exception(CKR_CRYPTOKI_NOT_INITIALIZED);
    }
  }

  public void C_Finalize() throws PKCS11Exception {
    initialized.set(false);
  }

  public CkInfo C_GetInfo() throws PKCS11Exception {
    assertInitialized();
    return info;
  }

  public long[] C_GetSlotList(boolean tokenPresentOnly) throws PKCS11Exception {
    assertInitialized();
    return backend.getSlotIds();
  }

  public CkSlotInfo C_GetSlotInfo(long slotID) throws PKCS11Exception {
    return backend.C_GetSlotInfo(slotID);
  }

  public CkTokenInfo C_GetTokenInfo(long slotID) throws PKCS11Exception {
    return backend.C_GetTokenInfo(slotID);
  }

  public long[] C_GetMechanismList(long slotID) throws PKCS11Exception {
    return backend.C_GetMechanismList(slotID);
  }

  public CkMechanismInfo C_GetMechanismInfo(long slotID, long type)
      throws PKCS11Exception {
    return backend.C_GetMechanismInfo(slotID, type);
  }

  public long C_OpenSession(long slotID, long flags)
      throws PKCS11Exception {
    assertInitialized();
    return backend.C_OpenSession(slotID, flags);
  }

  public void C_CloseSession(long hSession) throws PKCS11Exception {
    assertInitialized();
    backend.C_CloseSession(hSession);
  }

  public void C_CloseAllSessions(long slotID) throws PKCS11Exception {
    backend.C_CloseAllSessions(slotID);
  }

  public CkSessionInfo C_GetSessionInfo(long hSession)
      throws PKCS11Exception {
    try {
      return session(hSession).C_GetSessionInfo();
    } catch (HsmException e) {
      throw logAndGet("C_GetSessionInfo", e);
    }
  }

  public void C_SessionCancel(long hSession, long flags)
      throws PKCS11Exception {
    try {
      vendor.assertCryptokiVersionSupported(V3_0);
      session(hSession).C_SessionCancel(flags);
    } catch (HsmException e) {
      throw logAndGet("C_SessionCancel", e);
    }
  }

  public void C_Login(long hSession, long userType, byte[] pin)
      throws PKCS11Exception {
    try {
      XiSession session = session(hSession);
      session.C_Login(userType, pin);
    } catch (HsmException e) {
      throw logAndGet("C_Login", e);
    }
  }

  public void C_Logout(long hSession) throws PKCS11Exception {
    try {
      XiSession session = session(hSession);
      session.C_Logout();
    } catch (HsmException e) {
      throw logAndGet("C_Logout", e);
    }
  }

  public long C_CreateObject(long hSession, Template template)
      throws PKCS11Exception {
    try {
      XiTemplate attrs = vendorToGenericCka2(
          FunctionEnum.CREATE_OBJECT, template, null);
      long objClass = attrs.getNonNullLong(CKA_CLASS);

      if (objClass == CKO_PRIVATE_KEY) {
        checkPrivateKeyECPoint(attrs);
      }

      Long keyType = attrs.getLong(CKA_KEY_TYPE);
      if (keyType != null && !vendor.supportsCkk(keyType)) {
        throw new HsmException(CKR_KEY_TYPE_INCONSISTENT,
            "key type " + ckkCodeToName(keyType) + " is not supported");
      }

      return session(hSession).C_CreateObject(attrs);
    } catch (HsmException e) {
      throw logAndGet("C_CreateObject", e);
    }
  }

  public void C_DestroyObject(long hSession, long hObject)
      throws PKCS11Exception {
    try {
      session(hSession).C_DestroyObject(hObject);
    } catch (HsmException e) {
      throw logAndGet("C_DestroyObject", e);
    }
  }

  public Template C_GetAttributeValue(
      long hSession, long hObject, long[] attrTypes)
      throws PKCS11Exception {
    try {
      Template template = session(hSession).C_GetAttributeValue(
          hObject, attrTypes);
      genericToVendorCka(template);
      return template;
    } catch (HsmException e) {
      throw logAndGet("C_GetAttributeValue", e);
    }
  }

  public void C_SetAttributeValue(long hSession, long hObject,
                                  Template template)
      throws PKCS11Exception {
    try {
      XiTemplate template2 = vendorToGenericCka2(
          FunctionEnum.SET_ATTRIBUTE_VALUES, template, null);
      session(hSession).C_SetAttributeValue(hObject, template2);
    } catch (HsmException e) {
      throw logAndGet("C_SetAttributeValue", e);
    }
  }

  public void C_FindObjectsInit(long hSession, Template template)
      throws PKCS11Exception {
    try {
      vendorToGenericCka(template, true);
      session(hSession)
          .C_FindObjectsInit(XiTemplate.fromCkAttributes(template));
    } catch (HsmException e) {
      throw logAndGet("C_FindObjectsInit", e);
    }
  }

  public long[] C_FindObjects(long hSession, int maxObjectCount)
      throws PKCS11Exception {
    try {
      return session(hSession).C_FindObjects(maxObjectCount);
    } catch (HsmException e) {
      throw logAndGet("C_FindObjects", e);
    }
  }

  public void C_FindObjectsFinal(long hSession) throws PKCS11Exception {
    try {
      session(hSession).C_FindObjectsFinal();
    } catch (HsmException e) {
      throw logAndGet("C_FindObjectsFinal", e);
    }
  }

  public void C_DigestInit(long hSession, CkMechanism mechanism)
      throws PKCS11Exception {
    try {
      XiMechanism xiMech = vendorToGenericCkm(mechanism, CKF_DIGEST);
      session(hSession).C_DigestInit(xiMech);
    } catch (HsmException e) {
      throw logAndGet("C_DigestInit", e);
    }
  }

  public byte[] C_Digest(long hSession, byte[] data) throws PKCS11Exception {
    try {
      vendor.assertFrameSize(data.length);
      return session(hSession).C_Digest(data);
    } catch (HsmException e) {
      throw logAndGet("C_Digest", e);
    }
  }

  public void C_DigestUpdate(long hSession, byte[] part)
      throws PKCS11Exception {
    try {
      vendor.assertFrameSize(part.length);
      session(hSession).C_DigestUpdate(part);
    } catch (HsmException e) {
      throw logAndGet("C_DigestUpdate", e);
    }
  }

  public void C_DigestKey(long hSession, long hKey) throws PKCS11Exception {
    try {
      session(hSession).C_DigestKey(hKey);
    } catch (HsmException e) {
      throw logAndGet("C_DigestKey", e);
    }
  }

  public byte[] C_DigestFinal(long hSession) throws PKCS11Exception {
    try {
      return session(hSession).C_DigestFinal();
    } catch (HsmException e) {
      throw logAndGet("C_DigestFinal", e);
    }
  }

  public void C_SignInit(long hSession, CkMechanism mechanism, long hKey)
      throws PKCS11Exception {
    try {
      XiMechanism xiMech = vendorToGenericCkm(mechanism, CKF_SIGN);
      session(hSession).C_SignInit(xiMech, hKey);
    } catch (HsmException e) {
      throw logAndGet("C_SignInit", e);
    }
  }

  public byte[] C_Sign(long hSession, byte[] data)
      throws PKCS11Exception {
    try {
      vendor.assertFrameSize(data.length);
      return session(hSession).C_Sign(data);
    } catch (HsmException e) {
      throw logAndGet("C_Sign", e);
    }
}

  public void C_SignUpdate(long hSession, byte[] part) throws PKCS11Exception {
    try {
      vendor.assertFrameSize(part.length);
      session(hSession).C_SignUpdate(part);
    } catch (HsmException e) {
      throw logAndGet("C_SignUpdate", e);
    }
  }

  public byte[] C_SignFinal(long hSession) throws PKCS11Exception {
    try {
      return session(hSession).C_SignFinal();
    } catch (HsmException e) {
      throw logAndGet("C_SignFinal", e);
    }
  }

  public long[] C_GenerateKeyPair(
      long hSession, CkMechanism mechanism,
      Template publicKeyTemplate, Template privateKeyTemplate)
      throws PKCS11Exception {
    try {
      XiMechanism xiMech = vendorToGenericCkm(mechanism, CKF_GENERATE_KEY_PAIR);
      XiTemplate priTemplate = vendorToGenericCka2(
          FunctionEnum.GENERATE_KEY_PAIR, privateKeyTemplate, CKO_PRIVATE_KEY);
      XiTemplate pubTemplate = vendorToGenericCka2(
          FunctionEnum.GENERATE_KEY_PAIR, publicKeyTemplate,  CKO_PUBLIC_KEY);

      return session(hSession)
          .C_GenerateKeyPair(xiMech, pubTemplate, priTemplate);
    } catch (HsmException e) {
      throw logAndGet("C_GenerateKeyPair", e);
    }
  }

  public long C_GenerateKey(long hSession, CkMechanism mechanism,
                            Template template)
      throws PKCS11Exception {
    try {
      XiMechanism xiMech = vendorToGenericCkm(mechanism, CKF_GENERATE);
      XiTemplate template2 = vendorToGenericCka2(
          FunctionEnum.GENERATE_KEY, template, CKO_SECRET_KEY);
      return session(hSession).C_GenerateKey(xiMech, template2);
    } catch (HsmException e) {
      throw logAndGet("C_GenerateKey", e);
    }
  }

  private XiSession session(long hSession) throws PKCS11Exception {
    assertInitialized();
    return backend.getSession(hSession);
  }

  public void C_LoginUser(long hSession, long userType, byte[] pin,
                          byte[] username)
      throws PKCS11Exception {
    throw new PKCS11Exception(CKR_FUNCTION_NOT_SUPPORTED);
  }

  public long C_CopyObject(
      long hSession, long hObject, Template template)
      throws PKCS11Exception {
    throw new PKCS11Exception(CKR_FUNCTION_NOT_SUPPORTED);
  }

  public long C_DecapsulateKey(
      long hSession, CkMechanism mechanism, long hPrivateKey,
      byte[] cipherText, Template template)
      throws PKCS11Exception {
    try {
      vendor.assertCryptokiVersionSupported(V3_2);
      XiMechanism xiMech = vendorToGenericCkm(mechanism, CKF_ENCAPSULATE);
      XiTemplate template2 = vendorToGenericCka2(
          FunctionEnum.ENCAPSULATE_KEY, template, null);

      return session(hSession).C_DecapsulateKey(xiMech, hPrivateKey,
          cipherText, template2);
    } catch (HsmException e) {
      throw logAndGet("C_GenerateRandom", e);
    }
  }

  private XiMechanism vendorToGenericCkm(CkMechanism mechanism, long flagBit)
      throws HsmException {
    long ckm = mechanism.getMechanism();
    vendor.assertCkmSupported(ckm, flagBit);

    long newCkm = vendor.vendorToGenericCode(Category.CKM, ckm);
    CkParams parameter = mechanism.getParameters();

    CkMechanism newMech;
    if (newCkm == ckm && (parameter == mechanism.getParameters())) {
      newMech = mechanism;
    } else {
      newMech = new CkMechanism(newCkm, parameter);
    }

    return new XiMechanism(vendor, newMech, ckm);
  }

  private void checkCkaSensitive(long objClass, Boolean sensitive)
      throws HsmException {
    if (!(objClass == CKO_PRIVATE_KEY || objClass == CKO_SECRET_KEY)) {
      return;
    }

    if (!(sensitive != null && !sensitive)) {
      return;
    }
  }

  private XiTemplate vendorToGenericCka2(
      FunctionEnum functionEnum, Template ckAttrs, Long objClass)
      throws HsmException {
    vendorToGenericCka(ckAttrs, false);
    XiTemplate attrs = XiTemplate.fromCkAttributes(ckAttrs);

    if (objClass == null) {
      objClass = attrs.getLong(CKA_CLASS);
    }

    if (objClass == null) {
      return attrs;
    }

    // CKA_SENSITIVE
    checkCkaSensitive(objClass, attrs.getBool(CKA_SENSITIVE));

    return attrs;
  }

  private void vendorToGenericCka(Template ckAttrs, boolean forFindObjects)
      throws HsmException {
    if (ckAttrs == null) {
      return;
    }

    for (Attribute ckAttr : ckAttrs.attributes()) {
      if (ckAttr.isNullValue()) {
        continue;
      }

      long cka = ckAttr.type();
      Object value = ckAttr.value();
      if (cka == CKA_KEY_TYPE) {
        long keyType = (long) value;
        if (!forFindObjects) {
          vendor.assertCkkSupported(keyType);
        }

        long genericKeyType = vendor.vendorToGenericCode(Category.CKK, keyType);
        if (genericKeyType != keyType) {
          ((LongAttribute) ckAttr).setValue(genericKeyType);
        }
      }
    }
  }

  private void checkPrivateKeyECPoint(XiTemplate attrs) throws HsmException {
    Long keyType = attrs.getLong(CKA_KEY_TYPE);
    if (keyType == null) {
      return;
    }

    boolean withEcPoint = attrs.getByteArray(CKA_EC_POINT) != null;
    if (withEcPoint) {
      return;
    }

    boolean needEcPoint = false;
    if (keyType == CKK_EC) {
      needEcPoint = vendor.hasSpecialBehaviour(
          SpecialBehaviour.EC_PRIVATEKEY_ECPOINT);
    } else if (keyType == CKK_VENDOR_SM2) {
      needEcPoint = vendor.hasSpecialBehaviour(
          SpecialBehaviour.SM2_PRIVATEKEY_ECPOINT);
    }

    if (needEcPoint) {
      throw new HsmException(CKR_TEMPLATE_INCOMPLETE,
          "CKA_EC_POINT is not present");
    }
  }

  private void genericToVendorCka(Template attrs) {
    for (Attribute attr : attrs.attributes()) {
      if (attr.isNullValue()) {
        continue;
      }

      long cka = attr.type();
      if (cka == CKA_KEY_GEN_MECHANISM) {
        long genericCkm = ((LongAttribute) attr).getValue();
        long vendorCkm = vendor.genericToVendorCode(Category.CKM, genericCkm);
        if (genericCkm != vendorCkm) {
          ((LongAttribute) attr).setValue(vendorCkm);
        }
        return;
      } else if (cka == CKA_ALLOWED_MECHANISMS) {
        long[] ckms = ((LongArrayAttribute) attr).getValue();
        for (int i = 0; i < ckms.length; i++) {
          ckms[i] = vendor.genericToVendorCode(Category.CKM, ckms[i]);
        }
        ((LongArrayAttribute) attr).setValue(ckms);
      }
    }
  }

  private enum FunctionEnum {
    CREATE_OBJECT,
    DERIVE_KEY,
    GENERATE_KEY_PAIR,
    GENERATE_KEY,
    SET_ATTRIBUTE_VALUES,
    UNWRAP_KEY,
    ENCAPSULATE_KEY,
    DECAPSULATE_KEY
  }

}
