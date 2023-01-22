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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.EdECConstants;
import org.xipki.security.pkcs11.P11ModuleConf.P11MechanismFilter;
import org.xipki.security.pkcs11.P11ModuleConf.P11NewObjectConf;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.DSAParameterCache;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.Hex;
import org.xipki.util.StringUtil;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.*;

import static org.xipki.pkcs11.PKCS11Constants.*;
import static org.xipki.util.Args.*;
import static org.xipki.util.StringUtil.concat;

/**
 * PKCS#11 slot.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P11Slot implements Closeable {

  public static class P11NewObjectControl {

    private final byte[] id;

    private final String label;

    public P11NewObjectControl(byte[] id, String label) {
      this.id = id;
      this.label = notBlank(label, "label");
    }

    public byte[] getId() {
      return id;
    }

    public String getLabel() {
      return label;
    }

  } // class P11NewObjectControl

  public enum P11KeyUsage {
    DECRYPT(CKA_DECRYPT),
    DERIVE(CKA_DERIVE),
    SIGN(CKA_SIGN),
    SIGN_RECOVER(CKA_SIGN_RECOVER),
    UNWRAP(CKA_UNWRAP);

    private final long attributeType;

    private P11KeyUsage(long attributeType) {
      this.attributeType = attributeType;
    }

    public long getAttributeType() {
      return attributeType;
    }

  } // class P11KeyUsage

  public static class P11NewKeyControl extends P11NewObjectControl {

    private Boolean extractable;

    private Boolean sensitive;

    private Set<P11KeyUsage> usages;

    public P11NewKeyControl(byte[] id, String label) {
      super(id, label);
    }

    public Boolean getExtractable() {
      return extractable;
    }

    public void setExtractable(Boolean extractable) {
      this.extractable = extractable;
    }

    public Boolean getSensitive() {
      return sensitive;
    }

    public void setSensitive(Boolean sensitive) {
      this.sensitive = sensitive;
    }

    public Set<P11KeyUsage> getUsages() {
      if (usages == null) {
        usages = new HashSet<>();
      }
      return usages;
    }

    public void setUsages(Set<P11KeyUsage> usages) {
      this.usages = usages;
    }

  } // class P11NewKeyControl

  private static final Logger LOG = LoggerFactory.getLogger(P11Slot.class);

  protected final String moduleName;

  protected final P11SlotIdentifier slotId;

  private final boolean readOnly;

  private final SecureRandom random = new SecureRandom();

  private final Set<Long> mechanisms = new HashSet<>();

  protected final Integer numSessions;
  protected final List<Long> secretKeyTypes;
  protected final List<Long> keyPairTypes;

  protected final P11NewObjectConf newObjectConf;

  protected P11Slot(
      String moduleName, P11SlotIdentifier slotId, boolean readOnly,
      Integer numSessions, List<Long> secretKeyTypes, List<Long> keyPairTypes, P11NewObjectConf newObjectConf)
      throws P11TokenException {
    this.newObjectConf = notNull(newObjectConf, "newObjectConf");
    this.moduleName = notBlank(moduleName, "moduleName");
    this.slotId = notNull(slotId, "slotId");
    this.readOnly = readOnly;
    this.numSessions = numSessions;
    this.secretKeyTypes = secretKeyTypes;
    this.keyPairTypes = keyPairTypes;
  }

  /**
   * Returns the hex representation of the bytes.
   *
   * @param bytes Data to be encoded. Must not be {@code null}.
   * @return the hex representation of the bytes.
   */
  protected static String hex(byte[] bytes) {
    return Hex.encode(bytes);
  }

  /**
   * Returns the hex representation of the bytes.
   *
   * @param hex Data to be decoded. Must not be {@code null}.
   * @return the hex representation of the bytes.
   */
  protected static byte[] decodeHex(String hex) {
    return Hex.decode(hex);
  }

  public static String getDescription(byte[] keyId, String keyLabel) {
    return concat("id ", (keyId == null ? "null" : hex(keyId)), " and label ", keyLabel);
  }

  public abstract P11IdentityId getIdentityId(byte[] keyId, String keyLabel) throws P11TokenException;

  public abstract P11Identity getIdentity(P11IdentityId identityId) throws P11TokenException;

  /**
   * Remove objects.
   *
   * @param id    Id of the objects to be deleted. At least one of id and label may not be {@code null}.
   * @param label Label of the objects to be deleted
   * @return how many objects have been deleted
   * @throws P11TokenException If PKCS#11 error happens.
   */
  public abstract int removeObjects(byte[] id, String label) throws P11TokenException;

  protected abstract boolean objectExistsForIdOrLabel(byte[] id, String label) throws P11TokenException;

  /**
   * Removes the key (private key, public key, and secret key) associated with
   * the given identifier {@code objectId}.
   *
   * @param identityId Identity identifier. Must not be {@code null}.
   * @throws P11TokenException if PKCS#11 token exception occurs.
   */
  public abstract void removeIdentity(P11IdentityId identityId) throws P11TokenException;

  /**
   * Generates a secret key in the PKCS#11 token.
   *
   * @param keyType key type
   * @param keysize key size
   * @param control Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#11 token.
   * @throws P11TokenException if PKCS#11 token exception occurs.
   */
  protected abstract P11IdentityId doGenerateSecretKey(long keyType, Integer keysize, P11NewKeyControl control)
      throws P11TokenException;

  /**
   * Imports secret key object in the PKCS#11 token. The key itself will not be generated
   * within the PKCS#11 token.
   *
   * @param keyType  key type.
   * @param keyValue Key value. Must not be {@code null}.
   * @param control  Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws P11TokenException if PKCS#11 token exception occurs.
   */
  protected abstract P11IdentityId doImportSecretKey(long keyType, byte[] keyValue, P11NewKeyControl control)
      throws P11TokenException;

  /**
   * Generates a DSA keypair on-the-fly.
   *
   * @param p       p of DSA. Must not be {@code null}.
   * @param q       q of DSA. Must not be {@code null}.
   * @param g       g of DSA. Must not be {@code null}.
   * @param control Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws P11TokenException if PKCS#11 token exception occurs.
   */
  protected abstract P11IdentityId doGenerateDSAKeypair(
      BigInteger p, BigInteger q, BigInteger g, P11NewKeyControl control)
      throws P11TokenException;

  /**
   * Generates an EC Edwards keypair.
   *
   * @param curveId Object Identifier of the curve. Must not be {@code null}.
   * @param control Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws P11TokenException if PKCS#11 token exception occurs.
   */
  protected abstract P11IdentityId doGenerateECEdwardsKeypair(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws P11TokenException;

  /**
   * Generates an EC Edwards keypair on-the-fly.
   *
   * @param curveId Object Identifier of the curve. Must not be {@code null}.
   * @return the ASN.1 keypair.
   * @throws P11TokenException if PKCS#11 token exception occurs.
   */
  protected abstract PrivateKeyInfo doGenerateECEdwardsKeypairOtf(ASN1ObjectIdentifier curveId)
      throws P11TokenException;

  /**
   * Generates an EC Montgomery keypair.
   *
   * @param curveId Object Identifier of the curve. Must not be {@code null}.
   * @param control Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws P11TokenException if PKCS#11 token exception occurs.
   */
  protected abstract P11IdentityId doGenerateECMontgomeryKeypair(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws P11TokenException;

  /**
   * Generates an EC Montgomery keypair on-the-fly.
   *
   * @param curveId Object Identifier of the curve. Must not be {@code null}.
   * @return the ASN.1 keypair.
   * @throws P11TokenException if PKCS#11 token exception occurs.
   */
  protected abstract PrivateKeyInfo doGenerateECMontgomeryKeypairOtf(ASN1ObjectIdentifier curveId)
      throws P11TokenException;

  /**
   * Generates an EC keypair.
   *
   * @param curveId Object identifier of the EC curve. Must not be {@code null}.
   * @param control Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws P11TokenException if PKCS#11 token exception occurs.
   */
  protected abstract P11IdentityId doGenerateECKeypair(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws P11TokenException;

  /**
   * Generates an EC keypair over-the-air.
   *
   * @param curveId Object identifier of the EC curve. Must not be {@code null}.
   * @return the ASN.1 encoded keypair.
   * @throws P11TokenException if PKCS#11 token exception occurs.
   */
  protected abstract PrivateKeyInfo doGenerateECKeypairOtf(ASN1ObjectIdentifier curveId)
      throws P11TokenException;

  /**
   * Generates an SM2p256v1 keypair.
   *
   * @param control Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws P11TokenException if PKCS#11 token exception occurs.
   */
  protected abstract P11IdentityId doGenerateSM2Keypair(P11NewKeyControl control)
      throws P11TokenException;

  /**
   * Generates an SM2p256v1 keypair on-the-fly.
   *
   * @return the ASN.1 encoded keypair.
   * @throws P11TokenException if PKCS#11 token exception occurs.
   */
  protected abstract PrivateKeyInfo doGenerateSM2KeypairOtf() throws P11TokenException;

  /**
   * Generates an RSA keypair.
   *
   * @param keysize        key size in bit
   * @param publicExponent RSA public exponent. Could be {@code null}.
   * @param control        Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws P11TokenException if PKCS#11 token exception occurs.
   */
  protected abstract P11IdentityId doGenerateRSAKeypair(
      int keysize, BigInteger publicExponent, P11NewKeyControl control)
      throws P11TokenException;

  protected abstract void printObjects(OutputStream stream, boolean verbose) throws IOException;

  @Override
  public abstract void close();

  protected void initMechanisms(long[] supportedMechanisms, P11MechanismFilter mechanismFilter)
      throws P11TokenException {
    mechanisms.clear();

    List<Long> ignoreMechs = new ArrayList<>();

    for (long mech : supportedMechanisms) {
      if (mechanismFilter.isMechanismPermitted(slotId, mech)) {
        mechanisms.add(mech);
      } else {
        ignoreMechs.add(mech);
      }
    }

    if (LOG.isInfoEnabled()) {
      StringBuilder sb = new StringBuilder();
      sb.append("initialized module ").append(moduleName).append(", slot ").append(slotId);

      sb.append("\nsupported mechanisms:\n");
      List<Long> sortedMechs = new ArrayList<>(mechanisms);
      Collections.sort(sortedMechs);
      for (Long mech : sortedMechs) {
        sb.append("\t").append(ckmCodeToName(mech)).append("\n");
      }

      sb.append("\nsupported by device but ignored mechanisms:\n");
      if (ignoreMechs.isEmpty()) {
        sb.append("\tNONE\n");
      } else {
        Collections.sort(ignoreMechs);
        for (Long mech : ignoreMechs) {
          sb.append("\t").append(ckmCodeToName(mech)).append("\n");
        }
      }
      LOG.info(sb.toString());
    }
  }

  public Set<Long> getMechanisms() {
    return Collections.unmodifiableSet(mechanisms);
  }

  public boolean supportsMechanism(long mechanism) {
    return mechanisms.contains(mechanism);
  }

  public void assertMechanismSupported(long mechanism) throws P11UnsupportedMechanismException {
    if (!mechanisms.contains(mechanism)) {
      throw new P11UnsupportedMechanismException(mechanism, slotId);
    }
  }

  public String getModuleName() {
    return moduleName;
  }

  public P11SlotIdentifier getSlotId() {
    return slotId;
  }

  public boolean isReadOnly() {
    return readOnly;
  }

  protected void assertNoObjects(byte[] id, String label) throws P11TokenException {
    if (id == null && label == null) {
      return;
    }

    if (objectExistsForIdOrLabel(id, label)) {
      throw new P11DuplicateEntityException("Objects with " + getDescription(id, label) + " already exists");
    }
  }

  /**
   * Remove objects.
   *
   * @param id Id of the objects to be deleted.
   * @return how many objects have been deleted
   * @throws P11TokenException If PKCS#11 error happens.
   */
  public int removeObjectsForId(byte[] id) throws P11TokenException {
    return removeObjects(id, null);
  }

  /**
   * Remove objects.
   *
   * @param label Label of the objects to be deleted
   * @return how many objects have been deleted
   * @throws P11TokenException If PKCS#11 error happens.
   */
  public int removeObjectsForLabel(String label) throws P11TokenException {
    return removeObjects(null, label);
  }

  /**
   * Generates a secret key in the PKCS#11 token.
   *
   * @param keyType
   *          Key type
   * @param keysize
   *          Key size in bit
   * @param control
   *          Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the identity within the PKCS#11 token.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public P11IdentityId generateSecretKey(long keyType, Integer keysize, P11NewKeyControl control)
      throws P11TokenException {
    assertWritable("generateSecretKey");
    notNull(control, "control");
    assertNoObjects(control.getId(), control.getLabel());
    assertSecretKeyAllowed(keyType);

    if (keysize == null) {
      if (keyType != CKK_DES3) {
        throw new IllegalArgumentException(
            "keysize is required for key " + ckkCodeToName(keyType) + " but is not specified");
      }
    }

    P11IdentityId keyId = doGenerateSecretKey(keyType, keysize, control);
    LOG.info("generated secret key {}", keyId);
    return keyId;
  }

  /**
   * Imports secret key object in the PKCS#11 token. The key itself will not be generated
   * within the PKCS#11 token.
   *
   * @param keyType
   *          Key type
   * @param keyValue
   *          Key value. Must not be {@code null}.
   * @param control
   *          Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#11 token.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public P11IdentityId importSecretKey(long keyType, byte[] keyValue, P11NewKeyControl control)
      throws P11TokenException {
    notNull(control, "control");
    assertWritable("createSecretKey");
    assertNoObjects(control.getId(), control.getLabel());
    assertSecretKeyAllowed(keyType);

    P11IdentityId keyId = doImportSecretKey(keyType, keyValue, control);
    LOG.info("created secret key {}", keyId);
    return keyId;
  }

  private void assertSecretKeyAllowed(long keyType) throws P11TokenException {
    if (secretKeyTypes == null) {
      return;
    }

    if (!secretKeyTypes.contains(keyType)) {
      throw new P11TokenException("secret key type 0x" + Long.toHexString(keyType) + "unsupported");
    }
  }

  /**
   * Generates an RSA keypair on the fly.
   *
   * @param keysize
   *          key size in bit
   * @param publicExponent
   *          RSA public exponent. Could be {@code null}.
   * @return the ASN.1 keypair.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public PrivateKeyInfo generateRSAKeypairOtf(int keysize, BigInteger publicExponent)
      throws P11TokenException {
    min(keysize, "keysize", 1024);
    if (keysize % 1024 != 0) {
      throw new IllegalArgumentException("key size is not multiple of 1024: " + keysize);
    }

    if (!(supportsMechanism(CKM_RSA_X9_31_KEY_PAIR_GEN) || supportsMechanism(CKM_RSA_PKCS_KEY_PAIR_GEN))) {
      throw new P11UnsupportedMechanismException(buildOrMechanismsUnsupportedMessage(
          CKM_RSA_X9_31_KEY_PAIR_GEN, CKM_RSA_PKCS_KEY_PAIR_GEN));
    }

    return doGenerateRSAKeypairOtf(keysize, publicExponent == null ? RSAKeyGenParameterSpec.F4 : publicExponent);
  }

  protected abstract PrivateKeyInfo doGenerateRSAKeypairOtf(int keysize, BigInteger publicExponent)
      throws P11TokenException;

  /**
   * Generates an RSA keypair.
   *
   * @param keysize
   *          key size in bit
   * @param publicExponent
   *          RSA public exponent. Could be {@code null}.
   * @param control
   *          Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the identity within the PKCS#P11 token.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public P11IdentityId generateRSAKeypair(int keysize, BigInteger publicExponent, P11NewKeyControl control)
      throws P11TokenException {
    min(keysize, "keysize", 1024);
    if (keysize % 1024 != 0) {
      throw new IllegalArgumentException("key size is not multiple of 1024: " + keysize);
    }
    assertCanGenKeypair("generateRSAKeypair", control, CKK_RSA,
        CKM_RSA_X9_31_KEY_PAIR_GEN, CKM_RSA_PKCS_KEY_PAIR_GEN);
    P11IdentityId keyId = doGenerateRSAKeypair(keysize,
        publicExponent == null ? RSAKeyGenParameterSpec.F4 : publicExponent, control);
    LOG.info("generated RSA keypair {}", keyId);
    return keyId;
  }

  /**
   * Generates a DSA keypair on-the-fly.
   *
   * @param p
   *          p of DSA. Must not be {@code null}.
   * @param q
   *          q of DSA. Must not be {@code null}.
   * @param g
   *          g of DSA. Must not be {@code null}.
   * @return the ASN.1 keypair.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public PrivateKeyInfo generateDSAKeypairOtf(BigInteger p, BigInteger q, BigInteger g) throws P11TokenException {
    notNull(p, "p");
    notNull(q, "q");
    notNull(g, "g");

    assertMechanismSupported(CKM_DSA_KEY_PAIR_GEN);
    return generateDSAKeypairOtf0(p, q, g);
  }

  protected abstract PrivateKeyInfo generateDSAKeypairOtf0(BigInteger p, BigInteger q, BigInteger g)
      throws P11TokenException;

  /**
   * Generates a DSA keypair.
   *
   * @param plength
   *          bit length of P
   * @param qlength
   *          bit length of Q
   * @param control
   *          Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the identity within the PKCS#P11 token.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public P11IdentityId generateDSAKeypair(int plength, int qlength, P11NewKeyControl control)
      throws P11TokenException {
    min(plength, "plength", 1024);
    if (plength % 1024 != 0) {
      throw new IllegalArgumentException("key size is not multiple of 1024: " + plength);
    }
    DSAParameterSpec dsaParams = DSAParameterCache.getDSAParameterSpec(plength, qlength, random);
    return generateDSAKeypair(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG(), control);
  }

  /**
   * Generates a DSA keypair.
   *
   * @param p
   *          p of DSA. Must not be {@code null}.
   * @param q
   *          q of DSA. Must not be {@code null}.
   * @param g
   *          g of DSA. Must not be {@code null}.
   * @param control
   *          Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the identity within the PKCS#P11 token.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public P11IdentityId generateDSAKeypair(BigInteger p, BigInteger q, BigInteger g, P11NewKeyControl control)
      throws P11TokenException {
    assertCanGenKeypair("generateDSAKeypair", control, CKK_DSA, CKM_DSA_KEY_PAIR_GEN);
    P11IdentityId keyId = doGenerateDSAKeypair(notNull(p, "p"), notNull(q, "q"), notNull(g, "g"), control);
    LOG.info("generated DSA keypair {}", keyId);
    return keyId;
  }

  /**
   * Generates an EC keypair on-the-fly.
   *
   * @param curveOid
   *         Object identifier of the EC curve. Must not be {@code null}.
   * @return the ASN.1 keypair.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public PrivateKeyInfo generateECKeypairOtf(ASN1ObjectIdentifier curveOid) throws P11TokenException {
    notNull(curveOid, "curveOid");

    if (EdECConstants.isEdwardsCurve(curveOid)) {
      assertMechanismSupported(CKM_EC_EDWARDS_KEY_PAIR_GEN);
      return doGenerateECEdwardsKeypairOtf(curveOid);
    } else if (EdECConstants.isMontgomeryCurve(curveOid)) {
      assertMechanismSupported(CKM_EC_MONTGOMERY_KEY_PAIR_GEN);
      return doGenerateECMontgomeryKeypairOtf(curveOid);
    } else {
      assertMechanismSupported(CKM_EC_KEY_PAIR_GEN);
      return doGenerateECKeypairOtf(curveOid);
    }
  }

  /**
   * Generates an EC keypair.
   *
   * @param curveOid
   *         Object identifier of the EC curve. Must not be {@code null}.
   * @param control
   *          Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the identity within the PKCS#P11 token.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public P11IdentityId generateECKeypair(ASN1ObjectIdentifier curveOid, P11NewKeyControl control)
      throws P11TokenException {
    notNull(curveOid, "curveOid");

    P11IdentityId keyId;
    if (EdECConstants.isEdwardsCurve(curveOid)) {
      assertCanGenKeypair("generateECKeypair", control, CKK_EC_EDWARDS, CKM_EC_EDWARDS_KEY_PAIR_GEN);
      keyId = doGenerateECEdwardsKeypair(curveOid, control);
    } else if (EdECConstants.isMontgomeryCurve(curveOid)) {
      assertCanGenKeypair("generateECKeypair", control, CKK_EC_MONTGOMERY, CKM_EC_MONTGOMERY_KEY_PAIR_GEN);
      keyId = doGenerateECMontgomeryKeypair(curveOid, control);
    } else {
      assertCanGenKeypair("generateECKeypair", control, CKK_EC, CKM_EC_KEY_PAIR_GEN);
      keyId = doGenerateECKeypair(curveOid, control);
    }

    LOG.info("generated EC keypair {} {}", keyId);
    return keyId;
  }

  /**
   * Generates an SM2 keypair on the fly.
   *
   * @return the ASN.1 keypair.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public PrivateKeyInfo generateSM2KeypairOtf() throws P11TokenException {
    assertMechanismSupported(CKM_VENDOR_SM2_KEY_PAIR_GEN);
    return doGenerateSM2KeypairOtf();
  }

  /**
   * Generates an SM2 keypair.
   *
   * @param control
   *          Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the identity within the PKCS#P11 token.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public P11IdentityId generateSM2Keypair(P11NewKeyControl control) throws P11TokenException {
    assertCanGenKeypair("generateSM2Keypair", control, CKK_VENDOR_SM2, CKM_VENDOR_SM2_KEY_PAIR_GEN);
    P11IdentityId keyId = doGenerateSM2Keypair(control);
    LOG.info("generated SM2 keypair {}", keyId);
    return keyId;
  }

  private void assertCanGenKeypair(String methodName, P11NewKeyControl control, long keyType, long... orMechanisms)
      throws P11TokenException {
    notNull(control, "control");
    assertWritable(methodName);
    if (orMechanisms.length < 2) {
      assertMechanismSupported(orMechanisms[0]);
    } else {
      boolean mechSupported = false;
      for (long mechanism : orMechanisms) {
        if (supportsMechanism(mechanism)) {
          mechSupported = true;
          break;
        }
      }

      if (!mechSupported) {
        throw new P11UnsupportedMechanismException(buildOrMechanismsUnsupportedMessage(orMechanisms));
      }
    }

    assertNoObjects(control.getId(), control.getLabel());

    if (keyPairTypes == null) {
      return;
    }

    if (!keyPairTypes.contains(keyType)) {
      LOG.error("Keypair of key type 0x{} unsupported", Long.toHexString(keyType));
      throw new P11UnsupportedMechanismException(buildOrMechanismsUnsupportedMessage(orMechanisms));
    }
  }

  private String buildOrMechanismsUnsupportedMessage(long... mechanisms) {
    StringBuilder sb = new StringBuilder("none of mechanisms [");
    for (long mechanism : mechanisms) {
      sb.append(ckmCodeToName(mechanism)).append(", ");
    }
    sb.deleteCharAt(sb.length() - 1);
    sb.append("] is not supported by PKCS11 slot ").append(slotId);
    return sb.toString();
  }

  /**
   * Writes the token details to the given {@code stream}.
   * @param stream
   *          Output stream. Must not be {@code null}.
   * @param verbose
   *          Whether to show the details verbosely.
   * @throws IOException
   *         if IO error occurs.
   */
  public void showDetails(OutputStream stream, boolean verbose) throws IOException {
    notNull(stream, "stream");

    StringBuilder sb = new StringBuilder();
    if (verbose) {
      sb.append("\nSupported mechanisms:\n");
      List<Long> sortedMechs = new ArrayList<>(mechanisms);
      int no = 0;
      Collections.sort(sortedMechs);
      for (Long mech : sortedMechs) {
        sb.append("  ").append(++no).append(". ").append(ckmCodeToName(mech)).append("\n");
      }
    }
    sb.append("List of objects:\n");

    stream.write(sb.toString().getBytes(StandardCharsets.UTF_8));

    printObjects(stream, verbose);
  }

  protected void assertWritable(String operationName) throws P11PermissionException {
    if (readOnly) {
      throw new P11PermissionException("Writable operation " + operationName + " is not permitted");
    }
  }

  private static String getAlgorithmDesc(PublicKey publicKey) {
    String algo = publicKey.getAlgorithm();

    if (publicKey instanceof ECPublicKey) {
      String curveName = "UNKNOWN";
      ECParameterSpec paramSpec = ((ECPublicKey) publicKey).getParams();
      ASN1ObjectIdentifier curveOid = KeyUtil.detectCurveOid(paramSpec);
      if (curveOid != null) {
        String name = AlgorithmUtil.getCurveName(curveOid);
        curveName = name == null ? curveOid.getId() : name;
      }
      algo += "/" + curveName;
    } else if (publicKey instanceof RSAPublicKey) {
      int keylen = ((RSAPublicKey) publicKey).getModulus().bitLength();
      algo += "/" + keylen;
    } else if (publicKey instanceof DSAPublicKey) {
      int keylen = ((DSAPublicKey) publicKey).getParams().getP().bitLength();
      algo += "/" + keylen;
    }

    return algo;
  }

  private List<P11ObjectId> getSortedObjectIds(Set<P11ObjectId> sets) {
    List<P11ObjectId> ids = new ArrayList<>(sets);
    Collections.sort(ids);
    return ids;
  }

}
