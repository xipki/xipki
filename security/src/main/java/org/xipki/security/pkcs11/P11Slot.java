// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.MechanismInfo;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.params.ExtraParams;
import org.xipki.security.EdECConstants;
import org.xipki.security.pkcs11.P11ModuleConf.P11MechanismFilter;
import org.xipki.security.pkcs11.P11ModuleConf.P11NewObjectConf;
import org.xipki.security.util.DSAParameterCache;
import org.xipki.util.Args;
import org.xipki.util.Hex;
import org.xipki.util.StringUtil;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.DSAParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKF_GENERATE_KEY_PAIR;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_DES3;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_DSA;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_EC;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_EC_EDWARDS;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_EC_MONTGOMERY;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_RSA;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKK_VENDOR_SM2;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_DSA_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_EC_EDWARDS_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_EC_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_EC_MONTGOMERY_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_RSA_X9_31_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.CKM_VENDOR_SM2_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.Category;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.ckkCodeToName;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.ckmCodeToName;
import static org.xipki.pkcs11.wrapper.PKCS11Constants.codeToName;

/**
 * PKCS#11 slot.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public abstract class P11Slot implements Closeable {

  public static class P11NewObjectControl {

    private final byte[] id;

    private final String label;

    public P11NewObjectControl(byte[] id, String label) {
      this.id = id;
      this.label = Args.notBlank(label, "label");
    }

    public byte[] getId() {
      return id;
    }

    public String getLabel() {
      return label;
    }

  } // class P11NewObjectControl

  public enum P11KeyUsage {
    DECRYPT,
    DERIVE,
    SIGN,
    SIGN_RECOVER,
    UNWRAP
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

  protected final P11SlotId slotId;

  private final boolean readOnly;

  private final SecureRandom random = new SecureRandom();

  protected final Map<Long, MechanismInfo> mechanisms = new HashMap<>();

  protected final List<Long> secretKeyTypes;
  protected final List<Long> keyPairTypes;

  protected final P11NewObjectConf newObjectConf;

  protected P11Slot(
      String moduleName, P11SlotId slotId, boolean readOnly,
      List<Long> secretKeyTypes, List<Long> keyPairTypes, P11NewObjectConf newObjectConf) {
    this.newObjectConf = Args.notNull(newObjectConf, "newObjectConf");
    this.moduleName = Args.notBlank(moduleName, "moduleName");
    this.slotId = Args.notNull(slotId, "slotId");
    this.readOnly = readOnly;
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

  protected static String getDescription(byte[] keyId, String keyLabel) {
    return StringUtil.concat("id ", (keyId == null ? "null" : hex(keyId)), " and label ", keyLabel);
  }

  public abstract PKCS11KeyId getKeyId(byte[] keyId, String keyLabel) throws TokenException;

  public abstract byte[] sign(long mechanism, P11Params params, ExtraParams extraParams,
                              long keyHandle, byte[] content) throws TokenException;

  public abstract P11Key getKey(PKCS11KeyId keyId) throws TokenException;

  public abstract P11Key getKey(byte[] keyId, String keyLabel) throws TokenException;

  public abstract PublicKey getPublicKey(long handle) throws TokenException;

  /**
   * Destroys objects.
   * @param handles handles of objects to be destroyed.
   * @return handles of objects which could not been destroyed.
   */
  public abstract long[] destroyObjectsByHandle(long... handles);

  /**
   * !!!DANGEROUS OPERATION!!! Destroys all objects.
   * @return number of destroyed objects.
   */
  public abstract int destroyAllObjects();

  /**
   * Remove objects.
   *
   * @param id    ID of the objects to be deleted. At least one of id and label may not be {@code null}.
   * @param label Label of the objects to be deleted
   * @return how many objects have been deleted
   * @throws TokenException If PKCS#11 error happens.
   */
  public abstract int destroyObjectsByIdLabel(byte[] id, String label) throws TokenException;

  public abstract byte[] digestSecretKey(long mechanism, long objectHandle) throws TokenException;

  public abstract boolean objectExistsByIdLabel(byte[] id, String label) throws TokenException;

  protected String mechanismCodeToName(long code) {
    return ckmCodeToName(code);
  }

  /**
   * Generates a secret key in the PKCS#11 token.
   *
   * @param keyType key type
   * @param keysize key size
   * @param control Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#11 token.
   * @throws TokenException if PKCS#11 token exception occurs.
   */
  protected abstract PKCS11KeyId doGenerateSecretKey(long keyType, Integer keysize, P11NewKeyControl control)
      throws TokenException;

  /**
   * Imports secret key object in the PKCS#11 token. The key itself will not be generated
   * within the PKCS#11 token.
   *
   * @param keyType  key type.
   * @param keyValue Key value. Must not be {@code null}.
   * @param control  Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws TokenException if PKCS#11 token exception occurs.
   */
  protected abstract PKCS11KeyId doImportSecretKey(long keyType, byte[] keyValue, P11NewKeyControl control)
      throws TokenException;

  /**
   * Generates a DSA keypair on-the-fly.
   *
   * @param p       p of DSA. Must not be {@code null}.
   * @param q       q of DSA. Must not be {@code null}.
   * @param g       g of DSA. Must not be {@code null}.
   * @param control Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws TokenException if PKCS#11 token exception occurs.
   */
  protected abstract PKCS11KeyId doGenerateDSAKeypair(
      BigInteger p, BigInteger q, BigInteger g, P11NewKeyControl control) throws TokenException;

  /**
   * Generates an EC Edwards keypair.
   *
   * @param curveId Object Identifier of the curve. Must not be {@code null}.
   * @param control Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws TokenException if PKCS#11 token exception occurs.
   */
  protected abstract PKCS11KeyId doGenerateECEdwardsKeypair(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws TokenException;

  /**
   * Generates an EC Edwards keypair on-the-fly.
   *
   * @param curveId Object Identifier of the curve. Must not be {@code null}.
   * @return the ASN.1 keypair.
   * @throws TokenException if PKCS#11 token exception occurs.
   */
  protected abstract PrivateKeyInfo doGenerateECEdwardsKeypairOtf(ASN1ObjectIdentifier curveId)
      throws TokenException;

  /**
   * Generates an EC Montgomery keypair.
   *
   * @param curveId Object Identifier of the curve. Must not be {@code null}.
   * @param control Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws TokenException if PKCS#11 token exception occurs.
   */
  protected abstract PKCS11KeyId doGenerateECMontgomeryKeypair(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws TokenException;

  /**
   * Generates an EC Montgomery keypair on-the-fly.
   *
   * @param curveId Object Identifier of the curve. Must not be {@code null}.
   * @return the ASN.1 keypair.
   * @throws TokenException if PKCS#11 token exception occurs.
   */
  protected abstract PrivateKeyInfo doGenerateECMontgomeryKeypairOtf(ASN1ObjectIdentifier curveId)
      throws TokenException;

  /**
   * Generates an EC keypair.
   *
   * @param curveId Object identifier of the EC curve. Must not be {@code null}.
   * @param control Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws TokenException if PKCS#11 token exception occurs.
   */
  protected abstract PKCS11KeyId doGenerateECKeypair(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws TokenException;

  /**
   * Generates an EC keypair over-the-air.
   *
   * @param curveId Object identifier of the EC curve. Must not be {@code null}.
   * @return the ASN.1 encoded keypair.
   * @throws TokenException if PKCS#11 token exception occurs.
   */
  protected abstract PrivateKeyInfo doGenerateECKeypairOtf(ASN1ObjectIdentifier curveId) throws TokenException;

  /**
   * Generates an SM2p256v1 keypair.
   *
   * @param control Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws TokenException if PKCS#11 token exception occurs.
   */
  protected abstract PKCS11KeyId doGenerateSM2Keypair(P11NewKeyControl control) throws TokenException;

  /**
   * Generates an SM2p256v1 keypair on-the-fly.
   *
   * @return the ASN.1 encoded keypair.
   * @throws TokenException if PKCS#11 token exception occurs.
   */
  protected abstract PrivateKeyInfo doGenerateSM2KeypairOtf() throws TokenException;

  /**
   * Generates an RSA keypair.
   *
   * @param keysize        key size in bit
   * @param publicExponent RSA public exponent. Could be {@code null}.
   * @param control        Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws TokenException if PKCS#11 token exception occurs.
   */
  protected abstract PKCS11KeyId doGenerateRSAKeypair(
      int keysize, BigInteger publicExponent, P11NewKeyControl control) throws TokenException;

  /**
   * Writes the token details to the given {@code stream}.
   * The specified stream remains open after this method returns.
   * @param stream
   *          Output stream. Must not be {@code null}.
   * @param verbose
   *          Whether to show the details verbosely.
   * @param objectHandle
   *          If present, only details of this object will be shown.
   * @throws IOException
   *         if IO error occurs.
   */
  public abstract void showDetails(OutputStream stream, Long objectHandle, boolean verbose) throws IOException;

  protected PKCS11Module getPKCS11Module() {
    return null;
  }

  @Override
  public abstract void close();

  protected void initMechanisms(Map<Long, MechanismInfo> supportedMechanisms, P11MechanismFilter mechanismFilter) {
    mechanisms.clear();

    List<Long> ignoreMechs = new ArrayList<>();
    PKCS11Module pkcs11Module = getPKCS11Module();

    for (Map.Entry<Long, MechanismInfo> entry : supportedMechanisms.entrySet()) {
      long mech = entry.getKey();
      if (mechanismFilter.isMechanismPermitted(slotId, mech, pkcs11Module)) {
        mechanisms.put(mech, entry.getValue());
      } else {
        ignoreMechs.add(mech);
      }
    }
    Collections.sort(ignoreMechs);

    if (LOG.isInfoEnabled()) {
      StringBuilder sb = new StringBuilder();
      sb.append("initialized module ").append(moduleName).append(", slot ").append(slotId);

      sb.append("\nsupported mechanisms:\n");
      if (mechanisms.isEmpty()) {
        sb.append("  NONE\n");
      } else {
        printMechanisms(sb, mechanisms);
      }

      sb.append("\nsupported by device but ignored mechanisms:\n");
      if (ignoreMechs.isEmpty()) {
        sb.append("  NONE\n");
      } else {
        for (Long mech : ignoreMechs) {
          sb.append("\n  ").append(mechanismCodeToName(mech));
        }
      }
      LOG.info(sb.toString());
    }
  }

  private void printMechanisms(StringBuilder sb, Map<Long, MechanismInfo> mechanisms) {
    List<Long> sortedMechs = new ArrayList<>(mechanisms.keySet());
    Collections.sort(sortedMechs);

    for (Long mech : sortedMechs) {
      sb.append("  ").append(mechanismCodeToName(mech)).append("(0x").append(Functions.toFullHex(mech)).append(")\n")
          .append(mechanisms.get(mech).toString("  ")).append("\n");
    }
  }

  public Map<Long, MechanismInfo> getMechanisms() {
    return Collections.unmodifiableMap(mechanisms);
  }

  public boolean supportsMechanism(long mechanism, long flagBit) {
    MechanismInfo info = mechanisms.get(mechanism);
    return info != null && info.hasFlagBit(flagBit);
  }

  public void assertMechanismSupported(long mechanism, long flagBit) throws TokenException {
    if (!supportsMechanism(mechanism, flagBit)) {
      throw new TokenException("mechanism " + mechanismCodeToName(mechanism) + " for "
          + codeToName(Category.CKF_MECHANISM, flagBit) + " is not supported by PKCS11 slot " + slotId);
    }
  }

  public String getModuleName() {
    return moduleName;
  }

  public P11SlotId getSlotId() {
    return slotId;
  }

  public boolean isReadOnly() {
    return readOnly;
  }

  protected void assertNoObjects(byte[] id, String label) throws TokenException {
    if (id == null && label == null) {
      return;
    }

    if (objectExistsByIdLabel(id, label)) {
      throw new TokenException("Objects with " + getDescription(id, label) + " already exists");
    }
  }

  /**
   * Remove objects.
   *
   * @param id ID of the objects to be deleted.
   * @return how many objects have been deleted
   * @throws TokenException If PKCS#11 error happens.
   */
  public int destroyObjectsById(byte[] id) throws TokenException {
    return destroyObjectsByIdLabel(id, null);
  }

  /**
   * Remove objects.
   *
   * @param label Label of the objects to be deleted
   * @return how many objects have been deleted
   * @throws TokenException If PKCS#11 error happens.
   */
  public int destroyObjectsByLabel(String label) throws TokenException {
    return destroyObjectsByIdLabel(null, label);
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
   * @return the identifier of the key within the PKCS#11 token.
   * @throws TokenException
   *         if PKCS#11 token exception occurs.
   */
  public PKCS11KeyId generateSecretKey(long keyType, Integer keysize, P11NewKeyControl control)
      throws TokenException {
    assertWritable("generateSecretKey");
    assertNoObjects(Args.notNull(control, "control").getId(), control.getLabel());
    assertSecretKeyAllowed(keyType);

    if (keysize == null) {
      if (keyType != CKK_DES3) {
        throw new IllegalArgumentException(
            "keysize is required for key " + ckkCodeToName(keyType) + " but is not specified");
      }
    }

    PKCS11KeyId keyId = doGenerateSecretKey(keyType, keysize, control);
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
   * @throws TokenException
   *         if PKCS#11 token exception occurs.
   */
  public PKCS11KeyId importSecretKey(long keyType, byte[] keyValue, P11NewKeyControl control) throws TokenException {
    assertWritable("createSecretKey");
    assertNoObjects(Args.notNull(control, "control").getId(), control.getLabel());
    assertSecretKeyAllowed(keyType);

    PKCS11KeyId keyId = doImportSecretKey(keyType, keyValue, control);
    LOG.info("created secret key {}", keyId);
    return keyId;
  }

  private void assertSecretKeyAllowed(long keyType) throws TokenException {
    if (secretKeyTypes == null) {
      return;
    }

    if (!secretKeyTypes.contains(keyType)) {
      throw new TokenException("secret key type 0x" + Long.toHexString(keyType) + "unsupported");
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
   * @throws TokenException
   *         if PKCS#11 token exception occurs.
   */
  public PrivateKeyInfo generateRSAKeypairOtf(int keysize, BigInteger publicExponent) throws TokenException {
    Args.min(keysize, "keysize", 1024);
    if (keysize % 1024 != 0) {
      throw new IllegalArgumentException("key size is not multiple of 1024: " + keysize);
    }

    if (!(supportsMechanism(CKM_RSA_X9_31_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR)
        || supportsMechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR))) {
      throw new TokenException(buildOrMechanismsUnsupportedMessage(
          CKM_RSA_X9_31_KEY_PAIR_GEN, CKM_RSA_PKCS_KEY_PAIR_GEN));
    }

    return doGenerateRSAKeypairOtf(keysize, publicExponent == null ? RSAKeyGenParameterSpec.F4 : publicExponent);
  }

  protected abstract PrivateKeyInfo doGenerateRSAKeypairOtf(int keysize, BigInteger publicExponent)
      throws TokenException;

  /**
   * Generates an RSA keypair.
   *
   * @param keysize
   *          key size in bit
   * @param publicExponent
   *          RSA public exponent. Could be {@code null}.
   * @param control
   *          Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws TokenException
   *         if PKCS#11 token exception occurs.
   */
  public PKCS11KeyId generateRSAKeypair(int keysize, BigInteger publicExponent, P11NewKeyControl control)
      throws TokenException {
    if (Args.min(keysize, "keysize", 1024) % 1024 != 0) {
      throw new IllegalArgumentException("key size is not multiple of 1024: " + keysize);
    }
    assertCanGenKeypair("generateRSAKeypair", control, CKK_RSA,
        CKM_RSA_X9_31_KEY_PAIR_GEN, CKM_RSA_PKCS_KEY_PAIR_GEN);
    PKCS11KeyId keyId = doGenerateRSAKeypair(keysize,
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
   * @throws TokenException
   *         if PKCS#11 token exception occurs.
   */
  public PrivateKeyInfo generateDSAKeypairOtf(BigInteger p, BigInteger q, BigInteger g) throws TokenException {
    assertMechanismSupported(CKM_DSA_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR);
    return generateDSAKeypairOtf0(Args.notNull(p, "p"), Args.notNull(q, "q"), Args.notNull(g, "g"));
  }

  protected abstract PrivateKeyInfo generateDSAKeypairOtf0(BigInteger p, BigInteger q, BigInteger g)
      throws TokenException;

  /**
   * Generates a DSA keypair.
   *
   * @param plength
   *          The bit length of P
   * @param qlength
   *          The bit length of Q
   * @param control
   *          The control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws TokenException
   *         if PKCS#11 token exception occurs.
   */
  public PKCS11KeyId generateDSAKeypair(int plength, int qlength, P11NewKeyControl control) throws TokenException {
    if (Args.min(plength, "plength", 1024) % 1024 != 0) {
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
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws TokenException
   *         if PKCS#11 token exception occurs.
   */
  public PKCS11KeyId generateDSAKeypair(BigInteger p, BigInteger q, BigInteger g, P11NewKeyControl control)
      throws TokenException {
    assertCanGenKeypair("generateDSAKeypair", control, CKK_DSA, CKM_DSA_KEY_PAIR_GEN);
    PKCS11KeyId keyId = doGenerateDSAKeypair(
        Args.notNull(p, "p"),
        Args.notNull(q, "q"),
        Args.notNull(g, "g"),
        control);
    LOG.info("generated DSA keypair {}", keyId);
    return keyId;
  }

  /**
   * Generates an EC keypair on-the-fly.
   *
   * @param curveOid
   *         Object identifier of the EC curve. Must not be {@code null}.
   * @return the ASN.1 keypair.
   * @throws TokenException
   *         if PKCS#11 token exception occurs.
   */
  public PrivateKeyInfo generateECKeypairOtf(ASN1ObjectIdentifier curveOid) throws TokenException {
    if (EdECConstants.isEdwardsCurve(Args.notNull(curveOid, "curveOid"))) {
      assertMechanismSupported(CKM_EC_EDWARDS_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR);
      return doGenerateECEdwardsKeypairOtf(curveOid);
    } else if (EdECConstants.isMontgomeryCurve(curveOid)) {
      assertMechanismSupported(CKM_EC_MONTGOMERY_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR);
      return doGenerateECMontgomeryKeypairOtf(curveOid);
    } else {
      assertMechanismSupported(CKM_EC_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR);
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
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws TokenException
   *         if PKCS#11 token exception occurs.
   */
  public PKCS11KeyId generateECKeypair(ASN1ObjectIdentifier curveOid, P11NewKeyControl control) throws TokenException {
    PKCS11KeyId keyId;
    if (EdECConstants.isEdwardsCurve(Args.notNull(curveOid, "curveOid"))) {
      assertCanGenKeypair("generateECKeypair", control, CKK_EC_EDWARDS, CKM_EC_EDWARDS_KEY_PAIR_GEN);
      keyId = doGenerateECEdwardsKeypair(curveOid, control);
    } else if (EdECConstants.isMontgomeryCurve(curveOid)) {
      assertCanGenKeypair("generateECKeypair", control, CKK_EC_MONTGOMERY, CKM_EC_MONTGOMERY_KEY_PAIR_GEN);
      keyId = doGenerateECMontgomeryKeypair(curveOid, control);
    } else {
      assertCanGenKeypair("generateECKeypair", control, CKK_EC, CKM_EC_KEY_PAIR_GEN);
      keyId = doGenerateECKeypair(curveOid, control);
    }

    LOG.info("generated EC keypair {}", keyId);
    return keyId;
  }

  /**
   * Generates an SM2 keypair on the fly.
   *
   * @return the ASN.1 keypair.
   * @throws TokenException
   *         if PKCS#11 token exception occurs.
   */
  public PrivateKeyInfo generateSM2KeypairOtf() throws TokenException {
    assertMechanismSupported(CKM_VENDOR_SM2_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR);
    return doGenerateSM2KeypairOtf();
  }

  /**
   * Generates an SM2 keypair.
   *
   * @param control
   *          Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws TokenException
   *         if PKCS#11 token exception occurs.
   */
  public PKCS11KeyId generateSM2Keypair(P11NewKeyControl control) throws TokenException {
    assertCanGenKeypair("generateSM2Keypair", control, CKK_VENDOR_SM2, CKM_VENDOR_SM2_KEY_PAIR_GEN);
    PKCS11KeyId keyId = doGenerateSM2Keypair(control);
    LOG.info("generated SM2 keypair {}", keyId);
    return keyId;
  }

  private void assertCanGenKeypair(String methodName, P11NewKeyControl control, long keyType, long... orMechanisms)
      throws TokenException {
    assertWritable(methodName);
    if (orMechanisms.length < 2) {
      assertMechanismSupported(orMechanisms[0], CKF_GENERATE_KEY_PAIR);
    } else {
      boolean mechSupported = false;
      for (long mechanism : orMechanisms) {
        if (supportsMechanism(mechanism, CKF_GENERATE_KEY_PAIR)) {
          mechSupported = true;
          break;
        }
      }

      if (!mechSupported) {
        throw new TokenException(buildOrMechanismsUnsupportedMessage(orMechanisms));
      }
    }

    assertNoObjects(Args.notNull(control, "control").getId(), control.getLabel());

    if (keyPairTypes == null) {
      return;
    }

    if (!keyPairTypes.contains(keyType)) {
      LOG.error("Keypair of key type 0x{} unsupported", Long.toHexString(keyType));
      throw new TokenException(buildOrMechanismsUnsupportedMessage(orMechanisms));
    }
  }

  private String buildOrMechanismsUnsupportedMessage(long... mechanisms) {
    StringBuilder sb = new StringBuilder("none of mechanisms [");
    for (long mechanism : mechanisms) {
      sb.append(mechanismCodeToName(mechanism)).append(", ");
    }
    sb.deleteCharAt(sb.length() - 1);
    sb.append("] is supported by PKCS11 slot ").append(slotId);
    return sb.toString();
  }

  /**
   * Print supported mechanism to the specified output stream.
   * The specified stream remains open after this method returns.
   * @param stream the output stream.
   * @throws IOException if IO-error occurs while writing to the output stream.
   */
  protected void printSupportedMechanism(OutputStream stream) throws IOException {
    Args.notNull(stream, "stream");

    StringBuilder sb = new StringBuilder();
    sb.append("\nSupported mechanisms:\n");
    printMechanisms(sb, mechanisms);
    stream.write(sb.toString().getBytes(StandardCharsets.UTF_8));
  }

  protected void assertWritable(String operationName) throws TokenException {
    if (readOnly) {
      throw new TokenException("Writable operation " + operationName + " is not permitted");
    }
  }

}
