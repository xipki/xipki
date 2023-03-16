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
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.*;
import org.xipki.pkcs11.wrapper.params.*;
import org.xipki.security.EdECConstants;
import org.xipki.security.pkcs11.P11ModuleConf.P11MechanismFilter;
import org.xipki.security.pkcs11.P11ModuleConf.P11NewObjectConf;
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
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.xipki.pkcs11.wrapper.AttributeVector.newSecretKey;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;
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

  private static final Clock clock = Clock.systemUTC();

  private PKCS11Token token;

  private final SecureRandom random = new SecureRandom();

  private long rsaKeyPairGenMech;

  private String libDesc;

  NativeP11Slot(String moduleName, P11SlotId slotId, PKCS11Token token, P11MechanismFilter mechanismFilter,
                P11NewObjectConf newObjectConf, List<Long> secretKeyTypes, List<Long> keyPairTypes)
      throws TokenException {
    super(moduleName, slotId, token.isReadOnly(), secretKeyTypes, keyPairTypes, newObjectConf);

    this.token = notNull(token, "slot");

    ModuleInfo moduleInfo = token.getToken().getSlot().getModule().getInfo();
    libDesc = moduleInfo.getLibraryDescription();
    if (libDesc == null) {
      libDesc = "";
    }

    initMechanisms(getSupportedMechanisms(), mechanismFilter);
    rsaKeyPairGenMech = supportsMechanism(CKM_RSA_X9_31_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR)
        ? CKM_RSA_X9_31_KEY_PAIR_GEN : CKM_RSA_PKCS_KEY_PAIR_GEN;
  } // constructor

  private Map<Long, MechanismInfo> getSupportedMechanisms() throws TokenException {
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
  public final void close() {
    token.closeAllSessions();
  }

  byte[] digestSecretKey(long mech, NativeP11Identity identity) throws TokenException {
    if (!identity.isSecretKey()) {
      throw new TokenException("digestSecretKey could not be applied to non-SecretKey");
    }

    long keyHandle = notNull(identity, "identity").getId().getKeyId().getHandle();
    assertMechanismSupported(mech, CKF_DIGEST);

    return token.digestKey(new Mechanism(mech), keyHandle);
  }

  byte[] sign(long mech, P11Params parameters, byte[] content, NativeP11Identity identity) throws TokenException {
    notNull(content, "content");
    assertMechanismSupported(mech, CKF_SIGN);

    long signingKeyHandle = identity.getId().getKeyId().getHandle();
    return token.sign(getMechanism(mech, parameters, identity), signingKeyHandle, content);
  }

  @Override
  public P11Identity getIdentity(P11IdentityId identityId) throws TokenException {
    long handle = identityId.getKeyId().getHandle();

    AttributeVector attrs = token.getAttrValues(handle, CKA_CLASS, CKA_KEY_TYPE);
    long keyType = attrs.keyType();
    long objClass = attrs.class_();
    NativeP11Identity p11Identity = new NativeP11Identity(this, identityId);
    if (objClass == CKO_PRIVATE_KEY) {
      if (keyType == CKK_RSA) {
        attrs = token.getAttrValues(handle, CKA_MODULUS, CKA_PUBLIC_EXPONENT);
        p11Identity.setRsaMParameters(attrs.modulus(), attrs.publicExponent());
      } else if (keyType == CKK_DSA) {
        p11Identity.setDsaQ(token.getAttrValues(handle, CKA_SUBPRIME).subprime());
      } else if (keyType == CKK_EC || keyType == CKK_VENDOR_SM2
          || keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
        byte[] ecParams = token.getAttrValues(handle, CKA_EC_PARAMS).ecParams();
        ASN1ObjectIdentifier curveId = detectCurveOid(ecParams);

        // try the public key
        if (curveId == null && identityId.getPublicKeyHandle() != null) {
          ecParams = token.getAttrValues(identityId.getPublicKeyHandle(), CKA_EC_PARAMS).ecParams();
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

    return p11Identity.sign(token.getAttrValues(handle, CKA_SIGN).sign());
  }

  @Override
  protected PublicKey getPublicKey(P11Identity identity) throws TokenException {
    Long publicKeyHandle = identity.getId().getPublicKeyHandle();
    if (publicKeyHandle == null) {
      return null;
    }

    long keyType = identity.getKeyType();
    if (keyType == CKK_RSA) {
      return buildRSAKey(identity.getRsaModulus(), identity.getRsaPublicExponent());
    } else if (keyType == CKK_DSA) {
      BigInteger q = identity.getDsaQ();
      AttributeVector attrs = token.getAttrValues(publicKeyHandle, CKA_PRIME, CKA_VALUE, CKA_BASE);
      DSAPublicKeySpec keySpec = new DSAPublicKeySpec(
          new BigInteger(1, attrs.value()), attrs.prime(), q, attrs.base());
      try {
        return KeyUtil.generateDSAPublicKey(keySpec);
      } catch (InvalidKeySpecException ex) {
        throw new TokenException(ex.getMessage(), ex);
      }
    } else if (keyType == CKK_EC || keyType == CKK_VENDOR_SM2
        || keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
      byte[] ecPoint = token.getAttrValues(publicKeyHandle, CKA_EC_POINT).ecPoint();
      ASN1ObjectIdentifier curveOid = identity.getEcParams();

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
      List<Long> handles = getObjects(null, 9999);
      return token.destroyObjects(handles).size();
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

    List<Long> destroyedHandles = null;
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

    AttributeVector template = newSecretKey(keyType);
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

    template.id(id);
    keyHandle = token.generateKey(mechanism, template);
    label = token.getAttrValues(keyHandle, CKA_LABEL).label();

    return new P11IdentityId(slotId, new P11ObjectId(keyHandle, CKO_SECRET_KEY, keyType, id, label), null);
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

    setKeyAttributes(control, template, label);
    template.value(keyValue);

    if (label != null && labelExists(label)) {
      throw new IllegalArgumentException("label " + control.getLabel() + " exists, please specify another one");
    }

    byte[] id = control.getId();
    if (id == null) {
      id = generateId();
    }

    template.id(id);
    long keyHandle = token.createObject(template);

    try {
      label = token.getAttrValues(keyHandle, CKA_LABEL).label();
    } catch (PKCS11Exception e) {
    }

    return new P11IdentityId(slotId, new P11ObjectId(keyHandle, CKO_SECRET_KEY, keyType, id, label), null);
  } // method importSecretKey0

  @Override
  protected P11IdentityId doGenerateRSAKeypair(int keysize, BigInteger publicExponent, P11NewKeyControl control)
      throws TokenException {
    KeyPairTemplate template = new KeyPairTemplate(CKK_RSA);
    template.publicKey().modulusBits(keysize);
    if (publicExponent != null) {
      template.publicKey().publicExponent(publicExponent);
    }
    setKeyPairAttributes(control, template, newObjectConf);

    return doGenerateKeyPair(rsaKeyPairGenMech, control.getId(), template);
  } // method generateRSAKeypair0

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
  protected P11IdentityId doGenerateDSAKeypair(BigInteger p, BigInteger q, BigInteger g, P11NewKeyControl control)
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
  protected P11IdentityId doGenerateECEdwardsKeypair(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
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
  } // method generateECEdwardsKeypair0

  @Override
  protected PrivateKeyInfo doGenerateECEdwardsKeypairOtf(ASN1ObjectIdentifier curveId) throws TokenException {
    return doGenerateECKeypairOtf(CKK_EC_EDWARDS, CKM_EC_EDWARDS_KEY_PAIR_GEN, curveId);
  }

  @Override
  protected P11IdentityId doGenerateECMontgomeryKeypair(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws TokenException {
    KeyPairTemplate template = new KeyPairTemplate(CKK_EC_MONTGOMERY);
    setKeyPairAttributes(control, template, newObjectConf);
    try {
      template.publicKey().ecParams(curveId.getEncoded());
    } catch (IOException ex) {
      throw new TokenException(ex.getMessage(), ex);
    }

    return doGenerateKeyPair(CKM_EC_MONTGOMERY_KEY_PAIR_GEN, control.getId(), template);
  } // method generateECMontgomeryKeypair0

  @Override
  protected PrivateKeyInfo doGenerateECMontgomeryKeypairOtf(ASN1ObjectIdentifier curveId) throws TokenException {
    return doGenerateECKeypairOtf(CKK_EC_MONTGOMERY, CKM_EC_MONTGOMERY_KEY_PAIR_GEN, curveId);
  }

  @Override
  protected P11IdentityId doGenerateECKeypair(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
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
  protected P11IdentityId doGenerateSM2Keypair(P11NewKeyControl control) throws TokenException {
    long ckm = CKM_VENDOR_SM2_KEY_PAIR_GEN;
    if (supportsMechanism(ckm, CKF_GENERATE_KEY_PAIR)) {
      KeyPairTemplate template = new KeyPairTemplate(CKK_VENDOR_SM2);
      template.publicKey().ecParams(Hex.decode("06082A811CCF5501822D"));
      setKeyPairAttributes(control, template, newObjectConf);

      return doGenerateKeyPair(ckm, control.getId(), template);
    } else {
      return doGenerateECKeypair(GMObjectIdentifiers.sm2p256v1, control);
    }
  } // method generateSM2Keypair0

  @Override
  protected PrivateKeyInfo doGenerateSM2KeypairOtf() throws TokenException {
    long ckm = CKM_VENDOR_SM2_KEY_PAIR_GEN;

    return supportsMechanism(ckm, CKF_GENERATE_KEY_PAIR)
        ? doGenerateECKeypairOtf(CKK_VENDOR_SM2, ckm, GMObjectIdentifiers.sm2p256v1)
        : doGenerateECKeypairOtf(GMObjectIdentifiers.sm2p256v1);
  }

  private P11IdentityId doGenerateKeyPair(long mech, byte[] id, KeyPairTemplate template)
      throws TokenException {
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

        P11IdentityId ret = new P11IdentityId(slotId,
            new P11ObjectId(keypair.getPrivateKey(), CKO_PRIVATE_KEY, keyType, id, label), keypair.getPublicKey());
        succ = true;
        return ret;
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

    if (keyId == null) {
      AttributeVector template = new AttributeVector().label(keyLabel);

      long objClass = CKO_PRIVATE_KEY;
      List<Long> objHandles = getObjects(template.class_(objClass), 2);
      if (objHandles.isEmpty()) {
        objClass = CKO_SECRET_KEY;
        objHandles = getObjects(template.class_(objClass), 2);
      }

      if (objHandles.isEmpty()) {
        return null;
      } else if (objHandles.size() > 1) {
        throw new TokenException("found more than 1 " + ckkCodeToName(objClass).substring(4) +
            " with label=" + keyLabel);
      }

      long keyHandle = objHandles.get(0);
      AttributeVector attrs = token.getAttrValues(keyHandle, CKA_ID, CKA_KEY_TYPE);
      long keyType = attrs.keyType();
      keyId = attrs.id();

      P11ObjectId secretOrPrivKeyId = new P11ObjectId(keyHandle, objClass, keyType, keyId, keyLabel);

      Long publicKeyHandle = null;
      if (objClass == CKO_PRIVATE_KEY) {
        if (keyId == null) {
          List<Long> handles = getObjects(AttributeVector.newPublicKey().label(keyLabel), 2);
          if (handles.size() > 1) {
            LOG.warn("found more than 1 public key with label={}, ignore them", keyLabel);
          } else if (handles.size() == 1){
            publicKeyHandle = handles.get(0);
          }
        } else {
          List<Long> handles = getObjects(AttributeVector.newPublicKey().id(keyId), 2);
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
      List<Long> objHandles = getObjects(template.class_(objClass), 2);
      if (objHandles.isEmpty()) {
        objClass = CKO_SECRET_KEY;
        objHandles = getObjects(template.class_(objClass), 2);
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
        attrs = token.getAttrValues(keyHandle, CKA_KEY_TYPE, CKA_LABEL);
        keyLabel = attrs.label();
      } else {
        attrs = token.getAttrValues(keyHandle, CKA_KEY_TYPE);
      }

      P11ObjectId secretOrPrivKeyId = new P11ObjectId(keyHandle, objClass, attrs.keyType(), keyId, keyLabel);

      Long publicKeyHandle = null;
      if (objClass == CKO_PRIVATE_KEY) {
        objHandles = getObjects(AttributeVector.newPublicKey().id(keyId), 2);

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
  }

  @Override
  public void showDetails(OutputStream stream, Long objectHandle, boolean verbose) throws IOException {
    Token underlyingToken = token.getToken();
    String tokenInfo;
    try {
      tokenInfo = underlyingToken.getTokenInfo().toString("  ");
    } catch (PKCS11Exception ex) {
      tokenInfo = "  ERROR";
    }

    String slotInfo;
    try {
      slotInfo = underlyingToken.getSlot().getSlotInfo().toString("  ");
    } catch (PKCS11Exception ex) {
      slotInfo = "  ERROR";
    }

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
          String objectText = objectToString(handle);

          String text;
          try {
            text = formatNumber(i, 3) + ". " + objectText;
          } catch (Exception ex) {
            text = formatNumber(i, 3) + ". " + "Error reading object with handle " + handle;
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
    long objClass = attrs.class_();
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
          String curveName = null;
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
    while (true) {
      byte[] keyId = new byte[newObjectConf.getIdLength()];
      random.nextBytes(keyId);

      AttributeVector template = new AttributeVector().id(keyId);
      if (isEmpty(getObjects(template, 1))) {
        return keyId;
      }
    }
  }

  private boolean labelExists(String keyLabel) throws TokenException {
    notNull(keyLabel, "keyLabel");
    AttributeVector template = new AttributeVector().label(keyLabel);
    return !isEmpty(getObjects(template, 1));
  } // method labelExists

  private static void setPrivateKeyAttrsOtf(AttributeVector privateKeyTemplate) {
    privateKeyTemplate.sensitive(false).extractable(true).token(false);
  }

  private void destroyKeyPairQuietly(PKCS11KeyPair keypair) {
    if (keypair != null) {
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

  private Mechanism getMechanism(long mechanism, P11Params parameters, P11Identity identity) throws TokenException {
    if (parameters == null) {
      return new Mechanism(mechanism);
    }

    CkParams paramObj;
    if (parameters instanceof P11Params.P11RSAPkcsPssParams) {
      P11Params.P11RSAPkcsPssParams param = (P11Params.P11RSAPkcsPssParams) parameters;
      paramObj = new RSA_PKCS_PSS_PARAMS(param.getHashAlgorithm(),
          param.getMaskGenerationFunction(), param.getSaltLength());
    } else if (parameters instanceof P11Params.P11ByteArrayParams) {
      paramObj = new ByteArrayParams(((P11Params.P11ByteArrayParams) parameters).getBytes());
    } else {
      throw new TokenException("unknown P11Parameters " + parameters.getClass().getName());
    }

    if (identity.getEcOrderBitSize() != null) {
      paramObj = new CkParamsWithExtra(paramObj, new ExtraParams().ecOrderBitSize(identity.getEcOrderBitSize()));
    }

    return new Mechanism(mechanism, paramObj);
  } // method getMechanism

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
  } // method getObjects

  private RSAPublicKey buildRSAKey(BigInteger mod, BigInteger exp) throws TokenException {
    try {
      return KeyUtil.generateRSAPublicKey(new RSAPublicKeySpec(mod, exp));
    } catch (InvalidKeySpecException ex) {
      throw new TokenException(ex.getMessage(), ex);
    }
  }

  private int removeObjects0(AttributeVector template, String desc) throws TokenException {
    try {
      List<Long> objects = getObjects(template);
      return token.destroyObjects(objects).size();
    } catch (TokenException ex) {
      LogUtil.error(LOG, ex, "could not remove " + desc);
      throw new TokenException(ex.getMessage(), ex);
    }
  } // method removeObjects

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
    if (isNotEmpty(usages)) {
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
  } // method setKeyAttributes

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
    if (isNotEmpty(usages)) {
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
