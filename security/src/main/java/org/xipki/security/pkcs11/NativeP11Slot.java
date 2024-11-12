// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.AttributeVector;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.KeyPairTemplate;
import org.xipki.pkcs11.wrapper.Mechanism;
import org.xipki.pkcs11.wrapper.MechanismInfo;
import org.xipki.pkcs11.wrapper.ModuleInfo;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11Key;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11KeyPair;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.SlotInfo;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.TokenInfo;
import org.xipki.pkcs11.wrapper.params.ExtraParams;
import org.xipki.security.EdECConstants;
import org.xipki.security.pkcs11.P11ModuleConf.P11MechanismFilter;
import org.xipki.security.pkcs11.P11ModuleConf.P11NewObjectConf;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_BASE;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_CLASS;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_COEFFICIENT;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_EC_PARAMS;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_EC_POINT;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_EXPONENT_1;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_EXPONENT_2;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_ID;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_KEY_TYPE;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_LABEL;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_MODULUS;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_PRIME;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_PRIME_1;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_PRIME_2;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_PRIVATE_EXPONENT;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_PUBLIC_EXPONENT;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_SUBPRIME;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_VALUE;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKA_VALUE_LEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKF_DIGEST;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKF_GENERATE;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKF_GENERATE_KEY_PAIR;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKF_SIGN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_AES;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_DES3;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_DSA;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_EC;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_EC_EDWARDS;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_EC_MONTGOMERY;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_GENERIC_SECRET;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_RSA;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_SHA224_HMAC;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_SHA256_HMAC;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_SHA384_HMAC;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_SHA3_224_HMAC;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_SHA3_256_HMAC;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_SHA3_384_HMAC;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_SHA3_512_HMAC;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_SHA512_HMAC;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_SHA_1_HMAC;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_VENDOR_SM2;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_AES_KEY_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_DES3_KEY_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_DSA_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_ECDSA_SHA1;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_ECDSA_SHA224;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_ECDSA_SHA256;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_ECDSA_SHA384;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_ECDSA_SHA3_224;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_ECDSA_SHA3_256;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_ECDSA_SHA3_384;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_ECDSA_SHA3_512;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_ECDSA_SHA512;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_EC_EDWARDS_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_EC_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_EC_MONTGOMERY_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_GENERIC_SECRET_KEY_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_RSA_X9_31_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_VENDOR_SM2_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKO_PRIVATE_KEY;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKO_PUBLIC_KEY;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKO_SECRET_KEY;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.Category;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.ckkCodeToName;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.ckmCodeToName;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.ckoCodeToName;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.codeToName;

/**
 * {@link P11Slot} based on the ipkcs11wrapper or jpkcs11wrapper.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */
class NativeP11Slot extends P11Slot {

  public static final AlgorithmIdentifier ALGID_RSA = new AlgorithmIdentifier(
      PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);

  private static final Logger LOG = LoggerFactory.getLogger(NativeP11Slot.class);

  private final PKCS11Token token;

  private final TokenInfo tokenInfo;

  private final SlotInfo slotInfo;

  private final SecureRandom random = new SecureRandom();

  private final long rsaKeyPairGenMech;

  private String libDesc;

  NativeP11Slot(String moduleName, P11SlotId slotId, PKCS11Token token, P11MechanismFilter mechanismFilter,
                P11NewObjectConf newObjectConf, List<Long> secretKeyTypes, List<Long> keyPairTypes)
      throws TokenException {
    super(moduleName, slotId, token.isReadOnly(), secretKeyTypes, keyPairTypes, newObjectConf);
    if (slotId.getId() != token.getTokenId()) {
      throw new IllegalArgumentException("slotId != token.getTokenId");
    }

    this.token = Args.notNull(token, "slot");

    ModuleInfo moduleInfo = token.getModule().getInfo();
    libDesc = moduleInfo.getLibraryDescription();
    if (libDesc == null) {
      libDesc = "";
    }

    initMechanisms(getSupportedMechanisms(), mechanismFilter);
    rsaKeyPairGenMech = supportsMechanism(CKM_RSA_X9_31_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR)
        ? CKM_RSA_X9_31_KEY_PAIR_GEN : CKM_RSA_PKCS_KEY_PAIR_GEN;

    TokenInfo ti = null;
    try {
      ti = token.getToken().getTokenInfo();
    } catch (TokenException e) {
      LOG.warn("error getting tokenInfo", e);
    }
    tokenInfo = ti;

    SlotInfo si = null;
    try {
      si = token.getToken().getSlot().getSlotInfo();
    } catch (TokenException e) {
      LOG.warn("error getting slotInfo", e);
    }
    slotInfo = si;
  } // constructor

  AttributeVector getAttrValues(long objectHandle, long... attrTypes) throws TokenException {
    return token.getAttrValues(objectHandle, attrTypes);
  }

  private Map<Long, MechanismInfo> getSupportedMechanisms() {
    Set<Long> mechanisms = token.getMechanisms();

    List<Long> newList = new ArrayList<>(mechanisms.size());

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

    Map<Long, MechanismInfo> ret = new HashMap<>(newList.size() * 5 / 4);
    for (Long mech : newList) {
      MechanismInfo info = token.getMechanismInfo(mech);
      if (info == null) {
        LOG.warn("found not MechanismInfo for " + ckmCodeToName(mech) + ", ignore it");
      } else {
        ret.put(mech, info);
      }
    }
    return ret;
  } // method getSupportedMechanisms()

  @Override
  protected PKCS11Module getPKCS11Module() {
    return token.getModule();
  }

  @Override
  protected String mechanismCodeToName(long code) {
    return token.getModule().codeToName(Category.CKM, code);
  }

  @Override
  public boolean supportsMechanism(long mechanism, long flagBit) {
    MechanismInfo info = mechanisms.get(mechanism);
    if (info == null) {
      long genericCode = token.getModule().vendorToGenericCode(Category.CKM, mechanism);
      if (genericCode != mechanism) {
        info = mechanisms.get(mechanism);
      }
    }
    return info != null && info.hasFlagBit(flagBit);
  }

  @Override
  public final void close() {
    token.closeAllSessions();
  }

  @Override
  public byte[] digestSecretKey(long mech, long handle) throws TokenException {
    assertMechanismSupported(mech, CKF_DIGEST);
    return token.digestKey(new Mechanism(mech), handle);
  }

  @Override
  public byte[] sign(long mechanism, P11Params params, ExtraParams extraParams,
                     long keyHandle, byte[] content) throws TokenException {
    Args.notNull(content, "content");
    assertMechanismSupported(mechanism, CKF_SIGN);
    Mechanism mech = (params == null) ? new Mechanism(mechanism) : params.toMechanism(mechanism, extraParams);
    return token.sign(mech, keyHandle, content);
  }

  @Override
  public P11Key getKey(PKCS11KeyId keyId) throws TokenException {
    PKCS11Key pkcs11Key = token.getKey(keyId);
    return (pkcs11Key == null) ? null : toIdentity(pkcs11Key);
  }

  @Override
  public P11Key getKey(byte[] keyId, String keyLabel) throws TokenException {
    if ((keyId == null || keyId.length == 0) && StringUtil.isBlank(keyLabel)) {
      return null;
    }

    AttributeVector criteria = new AttributeVector();
    if (keyId != null && keyId.length > 0) {
      criteria.id(keyId);
    }
    if (StringUtil.isNotBlank(keyLabel)) {
      criteria.label(keyLabel);
    }

    PKCS11Key pkcs11Key = token.getKey(criteria);
    return (pkcs11Key == null) ? null : toIdentity(pkcs11Key);
  }

  @Override
  public PKCS11KeyId getKeyId(byte[] keyId, String keyLabel) throws TokenException {
    if ((keyId == null || keyId.length == 0) && StringUtil.isBlank(keyLabel)) {
      return null;
    }

    AttributeVector criteria = new AttributeVector();
    if (keyId != null && keyId.length > 0) {
      criteria.id(keyId);
    }
    if (StringUtil.isNotBlank(keyLabel)) {
      criteria.label(keyLabel);
    }

    PKCS11KeyId objectId = token.getKeyId(criteria);
    if (objectId == null) {
      return null;
    }

    long objClass = objectId.getObjectCLass();
    if (objClass != CKO_PRIVATE_KEY && objClass != CKO_SECRET_KEY) {
      throw new TokenException("could not find private key or secret key for " + getDescription(keyId, keyLabel));
    }

    return objectId;
  }

  private P11Key toIdentity(PKCS11Key pkcs11Key) throws TokenException {
    PKCS11KeyId keyId = pkcs11Key.id();
    NativeP11Key p11Identity = new NativeP11Key(this, keyId);

    long objClass = keyId.getObjectCLass();
    long keyType = keyId.getKeyType();
    if (objClass == CKO_PRIVATE_KEY) {
      if (keyType == CKK_RSA) {
        p11Identity.setRsaMParameters(pkcs11Key.rsaModulus(), pkcs11Key.rsaPublicExponent());
      } else if (keyType == CKK_DSA) {
        p11Identity.setDsaParameters(pkcs11Key.dsaPrime(), pkcs11Key.dsaSubprime(), pkcs11Key.dsaBase());
      } else if (keyType == CKK_EC || keyType == CKK_VENDOR_SM2
          || keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
        ASN1ObjectIdentifier curveId = detectCurveOid(pkcs11Key.ecParams());
        // try the public key
        if (curveId == null && keyId.getPublicKeyHandle() != null) {
          byte[] ecParams = token.getAttrValues(keyId.getPublicKeyHandle(), CKA_EC_PARAMS).ecParams();
          curveId = detectCurveOid(ecParams);
        }

        if (curveId != null) {
          p11Identity.setEcParams(curveId);
        }
      } else {
        throw new IllegalStateException("unknown key type " + ckkCodeToName(keyType));
      }
    } else if (objClass == CKO_SECRET_KEY) {
      // do nothing
    } else {
      // should not reach here
      throw new IllegalStateException("unknown object class " + ckoCodeToName(objClass));
    }

    return p11Identity.sign(pkcs11Key.sign());
  }

  @Override
  public PublicKey getPublicKey(long handle) throws TokenException {
    AttributeVector attrs = getAttrValues(handle, CKA_KEY_TYPE, CKA_CLASS);
    Long objClass = attrs.class_();
    Long keyType = attrs.keyType();
    boolean valid = objClass != null && keyType != null;
    if (valid) {
      valid = objClass == CKO_PUBLIC_KEY;
    }

    if (!valid) {
      throw new TokenException("object with " +  handle + " is not a public key");
    }

    if (keyType == CKK_RSA) {
      attrs = getAttrValues(handle, CKA_MODULUS, CKA_PUBLIC_EXPONENT);
      try {
        return KeyUtil.generateRSAPublicKey(
            new RSAPublicKeySpec(attrs.modulus(), attrs.publicExponent()));
      } catch (InvalidKeySpecException ex) {
        throw new TokenException(ex.getMessage(), ex);
      }
    } else if (keyType == CKK_DSA) {
      attrs = token.getAttrValues(handle, CKA_VALUE, CKA_PRIME, CKA_SUBPRIME, CKA_BASE);
      DSAPublicKeySpec keySpec = new DSAPublicKeySpec(
          new BigInteger(1, attrs.value()), attrs.prime(), attrs.subprime(), attrs.base());
      try {
        return KeyUtil.generateDSAPublicKey(keySpec);
      } catch (InvalidKeySpecException ex) {
        throw new TokenException(ex.getMessage(), ex);
      }
    } else if (keyType == CKK_EC || keyType == CKK_VENDOR_SM2
        || keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
      ASN1ObjectIdentifier curveOid;
      if (keyType == CKK_VENDOR_SM2) {
        attrs = getAttrValues(handle, CKA_EC_POINT);
        curveOid = GMObjectIdentifiers.sm2p256v1;
      } else {
        attrs = getAttrValues(handle, CKA_EC_POINT, CKA_EC_PARAMS);
        curveOid = ASN1ObjectIdentifier.getInstance(attrs.ecParams());
      }

      byte[] ecPoint = attrs.ecPoint();

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
        SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(curveOid), ecPoint);
        try {
          return KeyUtil.generatePublicKey(pkInfo);
        } catch (InvalidKeySpecException ex) {
          throw new TokenException(ex.getMessage(), ex);
        }
      } else {
        try {
          return KeyUtil.createECPublicKey(curveOid, ecPoint);
        } catch (InvalidKeySpecException ex) {
          throw new TokenException(ex.getMessage(), ex);
        }
      }
    } else {
      throw new TokenException("unknown key type " + ckkCodeToName(keyType));
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

    return !getObjects(template, 1).isEmpty();
  }

  @Override
  public int destroyAllObjects() {
    try {
      long[] handles = token.findAllObjects(null);
      return token.destroyObjects(handles).length;
    } catch (TokenException e) {
      LogUtil.warn(LOG, e, "error destroyAllObjects()");
      return 0;
    }
  }

  @Override
  public long[] destroyObjectsByHandle(long[] handles) {
    List<Long> handleList = new ArrayList<>(handles.length);
    for (long handle : handles) {
      handleList.add(handle);
    }

    List<Long> destroyedHandles;
    try {
      destroyedHandles = token.destroyObjects(handleList);
    } catch (TokenException e) {
      // only thrown if we could not borrow an active session.
      return handles;
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

      return removeObjects0(template, "objects " + getDescription(id, label));
  }

  @Override
  protected PKCS11KeyId doGenerateSecretKey(long keyType, Integer keysize, P11NewKeyControl control)
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
    } else if (CKK_SHA_1_HMAC == keyType || CKK_SHA224_HMAC   == keyType || CKK_SHA256_HMAC   == keyType
        || CKK_SHA384_HMAC    == keyType || CKK_SHA512_HMAC   == keyType || CKK_SHA3_224_HMAC == keyType
        || CKK_SHA3_256_HMAC  == keyType || CKK_SHA3_384_HMAC == keyType || CKK_SHA3_512_HMAC == keyType) {
      mech = CKM_GENERIC_SECRET_KEY_GEN;
    } else {
      throw new IllegalArgumentException("unsupported key type 0x" + codeToName(Category.CKK, keyType));
    }

    assertMechanismSupported(mech, CKF_GENERATE);

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

    AttributeVector template = AttributeVector.newSecretKey(keyType);
    setKeyAttributes(control, template, label);
    if (hasValueLen) {
      if (keysize == null) {
        throw new IllegalArgumentException("keysize must not be null");
      }
      template.valueLen(keysize / 8);
    }

    Mechanism mechanism = new Mechanism(mech);
    long keyHandle;
    if (label != null && labelExists(label)) {
      throw new IllegalArgumentException("label " + control.getLabel() + " exists, please specify another one");
    }

    if (id == null) {
      id = generateId();
    }

    keyHandle = token.generateKey(mechanism, template.id(id));
    label = token.getAttrValues(keyHandle, CKA_LABEL).label();

    return new PKCS11KeyId(keyHandle, CKO_SECRET_KEY, keyType, id, label);
  }

  @Override
  protected PKCS11KeyId doImportSecretKey(long keyType, byte[] keyValue, P11NewKeyControl control)
      throws TokenException {
    AttributeVector template = AttributeVector.newSecretKey(keyType);
    String label;
    if (newObjectConf.isIgnoreLabel()) {
      if (control.getLabel() != null) {
        LOG.warn("label is set, but ignored: '{}'", control.getLabel());
      }
      label = null;
    } else {
      label = control.getLabel();
    }

    setKeyAttributes(control, template, label);

    if (label != null && labelExists(label)) {
      throw new IllegalArgumentException("label " + control.getLabel() + " exists, please specify another one");
    }

    byte[] id = control.getId();
    if (id == null) {
      id = generateId();
    }

    long keyHandle = token.createObject(template.value(keyValue).id(id));

    try {
      label = token.getAttrValues(keyHandle, CKA_LABEL).label();
    } catch (PKCS11Exception e) {
    }

    return new PKCS11KeyId(keyHandle, CKO_SECRET_KEY, keyType, id, label);
  }

  @Override
  protected PKCS11KeyId doGenerateRSAKeypair(int keysize, BigInteger publicExponent, P11NewKeyControl control)
      throws TokenException {
    KeyPairTemplate template = new KeyPairTemplate(CKK_RSA);
    template.publicKey().modulusBits(keysize);
    if (publicExponent != null) {
      template.publicKey().publicExponent(publicExponent);
    }
    setKeyPairAttributes(control, template, newObjectConf);

    return doGenerateKeyPair(rsaKeyPairGenMech, control.getId(), template);
  }

  @Override
  protected PrivateKeyInfo doGenerateRSAKeypairOtf(int keysize, BigInteger publicExponent) throws TokenException {
    KeyPairTemplate template = new KeyPairTemplate(CKK_RSA);
    template.publicKey().modulusBits(keysize);
    if (publicExponent != null) {
      template.publicKey().publicExponent(publicExponent);
    }

    setPrivateKeyAttrsOtf(template.privateKey());

    long mech = rsaKeyPairGenMech;
    PKCS11KeyPair keypair = null;
    try {
      keypair = token.generateKeyPair(new Mechanism(mech), template);
      AttributeVector attrs = token.getAttrValues(keypair.getPrivateKey(), CKA_MODULUS, CKA_PUBLIC_EXPONENT,
          CKA_PRIVATE_EXPONENT, CKA_PRIME_1, CKA_PRIME_2, CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT);

      return new PrivateKeyInfo(ALGID_RSA,
          new org.bouncycastle.asn1.pkcs.RSAPrivateKey(
              attrs.modulus(), attrs.publicExponent(), attrs.privateExponent(),
              attrs.prime1(), attrs.prime2(), attrs.exponent1(), attrs.exponent2(), attrs.coefficient()));

    } catch (PKCS11Exception | IOException ex) {
      throw new TokenException("could not generate keypair " + ckmCodeToName(mech), ex);
    } finally {
      destroyKeyPairQuietly(keypair);
    }
  } // method generateRSAKeypairOtf0

  @Override
  protected PKCS11KeyId doGenerateDSAKeypair(BigInteger p, BigInteger q, BigInteger g, P11NewKeyControl control)
      throws TokenException {
    KeyPairTemplate template = new KeyPairTemplate(CKK_DSA);
    template.publicKey().prime(p).subprime(q).base(g);
    setKeyPairAttributes(control, template, newObjectConf);

    return doGenerateKeyPair(CKM_DSA_KEY_PAIR_GEN, control.getId(), template);
  }

  @Override
  protected PrivateKeyInfo generateDSAKeypairOtf0(BigInteger p, BigInteger q, BigInteger g) throws TokenException {
    KeyPairTemplate template = new KeyPairTemplate(CKK_DSA);
    setPrivateKeyAttrsOtf(template.privateKey());

    template.publicKey().prime(p).subprime(q).base(g);

    long mech = CKM_DSA_KEY_PAIR_GEN;
    PKCS11KeyPair keypair = null;
    try {
      DSAParameter parameter = new DSAParameter(p, q, g);
      AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, parameter);

      keypair = token.generateKeyPair(new Mechanism(mech), template);
      long skHandle = keypair.getPrivateKey();
      long pkHandle = keypair.getPublicKey();

      BigInteger p11PublicKeyValue  = new BigInteger(1, token.getAttrValues(pkHandle, CKA_VALUE).value());
      BigInteger p11PrivateKeyValue = new BigInteger(1, token.getAttrValues(skHandle, CKA_VALUE).value());

      byte[] publicKey = new ASN1Integer(p11PublicKeyValue).getEncoded(); // y

      return new PrivateKeyInfo(algId, new ASN1Integer(p11PrivateKeyValue), null, publicKey);
    } catch (PKCS11Exception | IOException ex) {
      throw new TokenException("could not generate keypair " + ckmCodeToName(mech), ex);
    } finally {
      destroyKeyPairQuietly( keypair);
    }
  }

  @Override
  protected PKCS11KeyId doGenerateECEdwardsKeypair(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws TokenException {
    KeyPairTemplate template = new KeyPairTemplate(CKK_EC_EDWARDS);
    setKeyPairAttributes(control, template, newObjectConf);
    byte[] encodedCurveId;
    try {
      encodedCurveId = curveId.getEncoded();
    } catch (IOException ex) {
      throw new TokenException(ex.getMessage(), ex);
    }
    template.publicKey().ecParams(encodedCurveId);
    return doGenerateKeyPair(CKM_EC_EDWARDS_KEY_PAIR_GEN, control.getId(), template);
  }

  @Override
  protected PrivateKeyInfo doGenerateECEdwardsKeypairOtf(ASN1ObjectIdentifier curveId) throws TokenException {
    return doGenerateECKeypairOtf(CKK_EC_EDWARDS, CKM_EC_EDWARDS_KEY_PAIR_GEN, curveId);
  }

  @Override
  protected PKCS11KeyId doGenerateECMontgomeryKeypair(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws TokenException {
    KeyPairTemplate template = new KeyPairTemplate(CKK_EC_MONTGOMERY);
    setKeyPairAttributes(control, template, newObjectConf);
    try {
      template.publicKey().ecParams(curveId.getEncoded());
    } catch (IOException ex) {
      throw new TokenException(ex.getMessage(), ex);
    }

    return doGenerateKeyPair(CKM_EC_MONTGOMERY_KEY_PAIR_GEN, control.getId(), template);
  }

  @Override
  protected PrivateKeyInfo doGenerateECMontgomeryKeypairOtf(ASN1ObjectIdentifier curveId) throws TokenException {
    return doGenerateECKeypairOtf(CKK_EC_MONTGOMERY, CKM_EC_MONTGOMERY_KEY_PAIR_GEN, curveId);
  }

  @Override
  protected PKCS11KeyId doGenerateECKeypair(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws TokenException {
    KeyPairTemplate template = new KeyPairTemplate(CKK_EC);
    setKeyPairAttributes(control, template, newObjectConf);
    byte[] encodedCurveId;
    try {
      encodedCurveId = curveId.getEncoded();
    } catch (IOException ex) {
      throw new TokenException(ex.getMessage(), ex);
    }

    template.publicKey().ecParams(encodedCurveId);
    return doGenerateKeyPair(CKM_EC_KEY_PAIR_GEN, control.getId(), template);
  }

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

    KeyPairTemplate template = new KeyPairTemplate(keyType);
    setPrivateKeyAttrsOtf(template.privateKey());

    byte[] ecParams;
    try {
      ecParams = curveId.getEncoded();
    } catch (IOException ex) {
      throw new TokenException(ex.getMessage(), ex);
    }
    template.publicKey().ecParams(ecParams);

    PKCS11KeyPair keypair = null;
    try {
      keypair = token.generateKeyPair(new Mechanism(mech), template);
      byte[] ecPoint = token.getAttrValues(keypair.getPublicKey(), CKA_EC_POINT).ecPoint();
      byte[] privValue = token.getAttrValues(keypair.getPrivateKey(), CKA_VALUE).value();

      if (CKK_EC_EDWARDS == keyType || CKK_EC_MONTGOMERY == keyType) {
        AlgorithmIdentifier algId = new AlgorithmIdentifier(curveId);
        return new PrivateKeyInfo(algId, new DEROctetString(privValue), null, ecPoint);
      } else {
        AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curveId);

        if (ecPoint[0] != 4) {
          throw new TokenException("EcPoint does not start with 0x04");
        }

        Integer orderBitLen = Functions.getCurveOrderBitLength(ecParams);
        if (orderBitLen == null) {
          throw new TokenException("unknown curve " + curveId.getId());
        }
        return new PrivateKeyInfo(algId, new org.bouncycastle.asn1.sec.ECPrivateKey(orderBitLen,
                new BigInteger(1, privValue), new DERBitString(ecPoint), null));
      }
    } catch (PKCS11Exception | IOException ex) {
      throw new TokenException("could not generate keypair " + ckmCodeToName(mech), ex);
    } finally {
      destroyKeyPairQuietly(keypair);
    }
  }

  @Override
  protected PKCS11KeyId doGenerateSM2Keypair(P11NewKeyControl control) throws TokenException {
    long ckm = CKM_VENDOR_SM2_KEY_PAIR_GEN;
    if (supportsMechanism(ckm, CKF_GENERATE_KEY_PAIR)) {
      KeyPairTemplate template = new KeyPairTemplate(CKK_VENDOR_SM2);
      template.publicKey().ecParams(Hex.decode("06082A811CCF5501822D"));
      setKeyPairAttributes(control, template, newObjectConf);

      return doGenerateKeyPair(ckm, control.getId(), template);
    } else {
      return doGenerateECKeypair(GMObjectIdentifiers.sm2p256v1, control);
    }
  }

  @Override
  protected PrivateKeyInfo doGenerateSM2KeypairOtf() throws TokenException {
    long ckm = CKM_VENDOR_SM2_KEY_PAIR_GEN;

    return supportsMechanism(ckm, CKF_GENERATE_KEY_PAIR)
        ? doGenerateECKeypairOtf(CKK_VENDOR_SM2, ckm, GMObjectIdentifiers.sm2p256v1)
        : doGenerateECKeypairOtf(GMObjectIdentifiers.sm2p256v1);
  }

  private PKCS11KeyId doGenerateKeyPair(long mech, byte[] id, KeyPairTemplate template) throws TokenException {
    long keyType = template.privateKey().keyType();
    String label = template.privateKey().label();

    boolean succ = false;

    try {
      if (label != null && labelExists(label)) {
        throw new IllegalArgumentException("label " + label + " exists, please specify another one");
      }

      if (id == null) {
        id = generateId();
      }

      template.id(id);

      PKCS11KeyPair keypair;
      try {
        keypair = token.generateKeyPair(new Mechanism(mech), template);
      } catch (PKCS11Exception ex) {
        if (mech == CKM_EC_KEY_PAIR_GEN) {
          // Named Curve is not supported, use explicit curve parameters.
          ASN1ObjectIdentifier curveId = ASN1ObjectIdentifier.getInstance(template.publicKey().ecParams());
          X9ECParameters ecParams = ECNamedCurveTable.getByOID(curveId);
          if (ecParams == null) {
            throw ex;
          }

          try {
            template.publicKey().ecParams(ecParams.getEncoded());
          } catch (IOException ex2) {
            throw ex;
          }
          keypair = token.generateKeyPair(new Mechanism(mech), template);
        } else {
          throw new TokenException("could not generate keypair " + ckmCodeToName(mech), ex);
        }
      }

      PKCS11KeyId objectId = new PKCS11KeyId(keypair.getPrivateKey(), CKO_PRIVATE_KEY, keyType, id, label);
      objectId.setPublicKeyHandle(keypair.getPublicKey());
      succ = true;
      return objectId;
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

  /**
   * The specified stream remains open after this method returns.
   */
  @Override
  public void showDetails(OutputStream stream, Long objectHandle, boolean verbose) throws IOException {
    String tokenInfo = (this.tokenInfo == null) ? "ERROR" : this.tokenInfo.toString("  ");
    String slotInfo  = (this.slotInfo  == null) ? "ERROR" : this.slotInfo .toString("  ");

    stream.write(("\nToken information:\n" + tokenInfo).getBytes(StandardCharsets.UTF_8));
    stream.write(("\n\nSlot information:\n" + slotInfo).getBytes(StandardCharsets.UTF_8));
    stream.write('\n');

    if (verbose) {
      printSupportedMechanism(stream);
    }

    try {
      if (objectHandle != null) {
        stream.write(("\nDetails of object with handle " + objectHandle +
            "\n").getBytes(StandardCharsets.UTF_8));
        AttributeVector attrs = token.getDefaultAttrValues(objectHandle);
        stream.write(attrs.toString(false, "  ").getBytes(StandardCharsets.UTF_8));
      } else {
        stream.write("\nList of objects:\n".getBytes(StandardCharsets.UTF_8));
        long[] handles = token.findObjects(null, 9999);
        int i = 0;

        for (long handle : handles) {
          i++;

          String text;
          try {
            String objectText = objectToString(handle);
            text = StringUtil.formatAccount(i, 3) + ". " + objectText;
          } catch (Exception ex) {
            text = StringUtil.formatAccount(i, 3) + ". " + "Error reading object with handle " + handle;
            LOG.debug(text, ex);
          }

          stream.write(("  " + text + "\n").getBytes(StandardCharsets.UTF_8));
          if ((i) % 10 == 0) {
            stream.flush();
          }
        }
      }
    } catch (TokenException e) {
      String message = "  error: " + e.getMessage();
      stream.write(message.getBytes(StandardCharsets.UTF_8));
      LogUtil.warn(LOG, e, message);
    }

    stream.flush();
  }

  private String objectToString(long handle) throws TokenException {
    AttributeVector attrs = token.getAttrValues(handle, CKA_ID, CKA_LABEL, CKA_CLASS);
    long objClass = Optional.ofNullable(attrs.class_()).orElseThrow(
        () -> new TokenException("CKA_CLASS is not present."));

    byte[] id = attrs.id();
    String label = attrs.label();

    String keySpec = null;
    if (objClass == CKO_PRIVATE_KEY || objClass == CKO_PUBLIC_KEY || objClass == CKO_SECRET_KEY) {
      long keyType = token.getAttrValues(handle, CKA_KEY_TYPE).keyType();

      if (objClass == CKO_SECRET_KEY) {
        int valueLen;
        if (keyType == CKK_DES3) {
          valueLen = 24;
        } else {
          Integer len = token.getAttrValues(handle, CKA_VALUE_LEN).valueLen();
          valueLen = (len == null) ? 0 : len;
        }

        keySpec = ckkCodeToName(keyType).substring(4) + "/" + (valueLen * 8);
      } else {
        if (keyType == CKK_RSA) {
          BigInteger modulus = token.getAttrValues(handle, CKA_MODULUS).modulus();
          keySpec = "RSA/" + (modulus == null ? "<N/A>" : modulus.bitLength());
        } else if (keyType == CKK_EC || keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
          byte[] ecParams = token.getAttrValues(handle, CKA_EC_PARAMS).ecParams();
          String curveName;
          if (ecParams == null) {
            curveName = "<N/A>";
          } else  {
            curveName = Functions.getCurveName(ecParams);
            if (curveName == null) {
              curveName = "0x" + hex(ecParams);
            }
          }

          keySpec = ckkCodeToName(keyType).substring(4) + "/" + curveName;
        } else if (keyType == CKK_VENDOR_SM2) {
          keySpec = "SM2";
        } else if (keyType == CKK_DSA) {
          BigInteger prime = token.getAttrValues(handle, CKA_PRIME).prime();
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

  private byte[] generateId() throws TokenException {
    return token.generateUniqueId(null, newObjectConf.getIdLength(), random);
  }

  private boolean labelExists(String keyLabel) throws TokenException {
    Args.notNull(keyLabel, "keyLabel");
    AttributeVector template = new AttributeVector().label(keyLabel);
    return CollectionUtil.isNotEmpty(getObjects(template, 1));
  } // method labelExists

  private static void setPrivateKeyAttrsOtf(AttributeVector privateKeyTemplate) {
    privateKeyTemplate.sensitive(false).extractable(true).token(false);
  }

  private void destroyKeyPairQuietly(PKCS11KeyPair keypair) {
    if (keypair == null) {
      return;
    }

    try {
      token.destroyObject(keypair.getPrivateKey());
    } catch (TokenException ex) {
      LogUtil.warn(LOG, ex, "error destroying private key " + keypair.getPrivateKey());
    }

    try {
      token.destroyObject(keypair.getPublicKey());
    } catch (TokenException ex) {
      LogUtil.warn(LOG, ex, "error destroying public key " + keypair.getPublicKey());
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

  private List<Long> getObjects(AttributeVector template) throws TokenException {
    return getObjects(template, 9999);
  }

  private List<Long> getObjects(AttributeVector template, int maxNo) throws TokenException {
    List<Long> objList = new LinkedList<>();

    long[] objHandles = token.findObjects(template, maxNo);
    for (long hObject : objHandles) {
      objList.add(hObject);
    }

    return objList;
  }

  private int removeObjects0(AttributeVector template, String desc) throws TokenException {
    try {
      List<Long> objects = getObjects(template);
      return token.destroyObjects(objects).size();
    } catch (TokenException ex) {
      LogUtil.error(LOG, ex, "could not remove " + desc);
      throw new TokenException(ex.getMessage(), ex);
    }
  }

  private void setKeyPairAttributes(P11NewKeyControl control, KeyPairTemplate template,
                                   P11ModuleConf.P11NewObjectConf newObjectConf) {
    template.token(true);

    template.privateKey().private_(true);
    if (newObjectConf.isIgnoreLabel()) {
      if (control.getLabel() != null) {
        LOG.warn("label is set, but ignored: '{}'", control.getLabel());
      }
    } else {
      template.labels(control.getLabel());
    }

    if (control.getExtractable() != null) {
      template.privateKey().extractable(control.getExtractable());
    }

    if (control.getSensitive() != null) {
      template.privateKey().sensitive(control.getSensitive());
    }

    Set<P11KeyUsage> usages = control.getUsages();
    if (CollectionUtil.isNotEmpty(usages)) {
      for (P11KeyUsage usage : usages) {
        switch (usage) {
          case DECRYPT:
            template.decryptEncrypt(true);
            break;
          case DERIVE:
            template.derive(true);
            break;
          case SIGN:
            template.signVerify(true);
            break;
          case SIGN_RECOVER:
            template.signVerifyRecover(true);
            break;
          case UNWRAP:
            template.unwrapWrap(true);
            break;
          default:
            throw new IllegalStateException("unknown P11KeyUsage");
        }
      }
    } else {
      long keyType = template.privateKey().keyType();
      // if not set
      if (keyType == CKK_EC || keyType == CKK_RSA || keyType == CKK_DSA || keyType == CKK_VENDOR_SM2) {
        template.signVerify(true);
      }

      if (keyType == CKK_RSA) {
        template.unwrapWrap(true).decryptEncrypt(true);
      }
    }
  }

  private void setKeyAttributes(P11NewKeyControl control, AttributeVector template, String label) {
    template.token(true);
    if (label != null) {
      template.label(label);
    }

    if (control.getExtractable() != null) {
      template.extractable(control.getExtractable());
    }

    if (control.getSensitive() != null) {
      template.sensitive(control.getSensitive());
    }

    Set<P11KeyUsage> usages = control.getUsages();
    if (CollectionUtil.isNotEmpty(usages)) {
      for (P11KeyUsage usage : usages) {
        switch (usage) {
          case DECRYPT:
            template.decrypt(true).encrypt(true);
            break;
          case DERIVE:
            template.derive(true);
            break;
          case SIGN:
            template.sign(true).verify(true);
            break;
          case SIGN_RECOVER:
            template.signRecover(true).verifyRecover(true);
            break;
          case UNWRAP:
            template.unwrap(true).wrap(true);
            break;
          default:
            throw new IllegalStateException("unknown P11KeyUsage");
        }
      }
    }
  }

}
