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

import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.EdECConstants;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.pkcs11.P11ModuleConf.P11MechanismFilter;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.DSAParameterCache;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.Hex;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

import static org.xipki.util.Args.*;
import static org.xipki.util.StringUtil.concat;
import static org.xipki.util.StringUtil.toUtf8Bytes;

/**
 * PKCS#11 slot.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P11Slot implements Closeable {

  public static class P11SlotRefreshResult {

    private final Map<P11ObjectIdentifier, P11Identity> identities = new HashMap<>();

    private final Map<P11ObjectIdentifier, X509Cert> certificates = new HashMap<>();

    private final Set<Long> mechanisms = new HashSet<>();

    public P11SlotRefreshResult() {
    }

    public Map<P11ObjectIdentifier, P11Identity> getIdentities() {
      return identities;
    }

    public Map<P11ObjectIdentifier, X509Cert> getCertificates() {
      return certificates;
    }

    public Set<Long> getMechanisms() {
      return mechanisms;
    }

    public void addIdentity(P11Identity identity) {
      notNull(identity, "identity");
      this.identities.put(identity.getId().getKeyId(), identity);
    }

    public void addMechanism(long mechanism) {
      this.mechanisms.add(mechanism);
    }

    public void addCertificate(P11ObjectIdentifier objectId, X509Cert certificate) {
      notNull(objectId, "objectId");
      notNull(certificate, "certificate");
      this.certificates.put(objectId, certificate);
    }

    /**
     * Returns the certificate of the given identifier {@code id}.
     * @param id
     *          Identifier. Must not be {@code null}.
     * @return the certificate of the given identifier.
     */
    public X509Cert getCertForId(byte[] id) {
      for (Entry<P11ObjectIdentifier, X509Cert> entry : certificates.entrySet()) {
        P11ObjectIdentifier objId = entry.getKey();
        if (objId.matchesId(id)) {
          return entry.getValue();
        }
      }
      return null;
    }

    /**
     * Returns the PKCS#11 label for certificate of the given {@code id}.
     * @param id
     *          Identifier. Must not be {@code null}.
     * @return the label.
     */
    public String getCertLabelForId(byte[] id) {
      for (P11ObjectIdentifier objId : certificates.keySet()) {
        if (objId.matchesId(id)) {
          return objId.getLabel();
        }
      }
      return null;
    }

  } // class P11SlotRefreshResult

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

  protected final P11SlotIdentifier slotId;

  private final boolean readOnly;

  private final SecureRandom random = new SecureRandom();

  private final ConcurrentHashMap<P11ObjectIdentifier, P11Identity> identities = new ConcurrentHashMap<>();

  private final ConcurrentHashMap<P11ObjectIdentifier, X509Cert> certificates = new ConcurrentHashMap<>();

  private final Set<Long> mechanisms = new HashSet<>();

  private final P11MechanismFilter mechanismFilter;

  protected final Integer numSessions;
  protected final List<Long> secretKeyTypes;
  protected final List<Long> keyPairTypes;

  protected P11Slot(
      String moduleName, P11SlotIdentifier slotId, boolean readOnly, P11MechanismFilter mechanismFilter,
      Integer numSessions, List<Long> secretKeyTypes, List<Long> keyPairTypes)
      throws P11TokenException {
    this.mechanismFilter = notNull(mechanismFilter, "mechanismFilter");
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
   * @param bytes
   *          Data to be encoded. Must not be {@code null}.
   * @return the hex representation of the bytes.
   */
  protected static String hex(byte[] bytes) {
    return Hex.encode(bytes);
  }

  /**
   * Returns the hex representation of the bytes.
   *
   * @param hex
   *          Data to be decoded. Must not be {@code null}.
   * @return the hex representation of the bytes.
   */
  protected static byte[] decodeHex(String hex) {
    return Hex.decode(hex);
  }

  public static String getDescription(byte[] keyId, char[] keyLabel) {
    return concat("id ", (keyId == null ? "null" : hex(keyId)), " and label ",
        (keyLabel == null ? "null" : new String(keyLabel)));
  }

  public static String getDescription(byte[] keyId, String keyLabel) {
    return concat("id ", (keyId == null ? "null" : hex(keyId)), " and label ", keyLabel);
  }

  /**
   * Updates the certificate associated with the given {@code objectId} with the given certificate
   * {@code newCert}.
   *
   * @param keyId
   *          Object identifier of the private key. Must not be {@code null}.
   * @param newCert
   *          Certificate to be added. Must not be {@code null}.
   * @throws CertificateException
   *         if process with certificate fails.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  protected abstract void updateCertificate0(P11ObjectIdentifier keyId, X509Cert newCert)
      throws P11TokenException, CertificateException;

  /**
   * Removes the key (private key, public key, secret key, and certificates) associated with
   * the given identifier {@code objectId}.
   *
   * @param identityId
   *          Identity identifier. Must not be {@code null}.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  protected abstract void removeIdentity0(P11IdentityId identityId)
      throws P11TokenException;

  /**
   * Adds the certificate to the PKCS#11 token under the given identifier {@code objectId}.
   *
   * @param cert
   *          Certificate to be added. Must not be {@code null}.
   * @param control
   *          Control of the object creation process. Must not be {@code null}.
   * @return the PKCS#11 identifier of the added certificate.
   * @throws CertificateException
   *         if process with certificate fails.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  protected abstract P11ObjectIdentifier addCert0(X509Cert cert, P11NewObjectControl control)
      throws P11TokenException, CertificateException;

  /**
   * Generates a secret key in the PKCS#11 token.
   *
   * @param keyType
   *          key type
   * @param keysize
   *          key size
   * @param control
   *          Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#11 token.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  protected abstract P11Identity generateSecretKey0(long keyType, int keysize, P11NewKeyControl control)
      throws P11TokenException;

  /**
   * Imports secret key object in the PKCS#11 token. The key itself will not be generated
   * within the PKCS#11 token.
   *
   * @param keyType
   *          key type.
   * @param keyValue
   *          Key value. Must not be {@code null}.
   * @param control
   *          Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  protected abstract P11Identity importSecretKey0(long keyType, byte[] keyValue, P11NewKeyControl control)
      throws P11TokenException;

  /**
   * Generates a DSA keypair on-the-fly.
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
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  protected abstract P11Identity generateDSAKeypair0(BigInteger p, BigInteger q, BigInteger g, P11NewKeyControl control)
      throws P11TokenException;

  /**
   * Generates an EC Edwards keypair.
   *
   * @param curveId
   *         Object Identifier of the curve. Must not be {@code null}.
   * @param control
   *          Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  protected abstract P11Identity generateECEdwardsKeypair0(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws P11TokenException;

  /**
   * Generates an EC Edwards keypair on-the-fly.
   *
   * @param curveId
   *         Object Identifier of the curve. Must not be {@code null}.
   * @return the ASN.1 keypair.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  protected abstract PrivateKeyInfo generateECEdwardsKeypairOtf0(ASN1ObjectIdentifier curveId)
      throws P11TokenException;

  /**
   * Generates an EC Montgomery keypair.
   *
   * @param curveId
   *         Object Identifier of the curve. Must not be {@code null}.
   * @param control
   *          Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  protected abstract P11Identity generateECMontgomeryKeypair0(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws P11TokenException;

  /**
   * Generates an EC Montgomery keypair on-the-fly.
   *
   * @param curveId
   *         Object Identifier of the curve. Must not be {@code null}.
   * @return the ASN.1 keypair.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  protected abstract PrivateKeyInfo generateECMontgomeryKeypairOtf0(ASN1ObjectIdentifier curveId)
      throws P11TokenException;

  /**
   * Generates an EC keypair.
   *
   * @param curveId
   *         Object identifier of the EC curve. Must not be {@code null}.
   * @param control
   *          Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  protected abstract P11Identity generateECKeypair0(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws P11TokenException;

  /**
   * Generates an EC keypair over-the-air.
   *
   * @param curveId
   *         Object identifier of the EC curve. Must not be {@code null}.
   * @return the ASN.1 encoded keypair.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  protected abstract PrivateKeyInfo generateECKeypairOtf0(ASN1ObjectIdentifier curveId)
      throws P11TokenException;

  /**
   * Generates an SM2p256v1 keypair.
   *
   * @param control
   *          Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  protected abstract P11Identity generateSM2Keypair0(P11NewKeyControl control)
      throws P11TokenException;

  /**
   * Generates an SM2p256v1 keypair on-the-fly.
   *
   * @return the ASN.1 encoded keypair.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  protected abstract PrivateKeyInfo generateSM2KeypairOtf0()
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
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  protected abstract P11Identity generateRSAKeypair0(int keysize, BigInteger publicExponent, P11NewKeyControl control)
      throws P11TokenException;

  protected abstract P11SlotRefreshResult refresh0()
      throws P11TokenException;

  protected abstract void removeCerts0(P11ObjectIdentifier objectId)
      throws P11TokenException;

  @Override
  public abstract void close();

  /**
   * Remove objects.
   *
   * @param id
   *         Id of the objects to be deleted. At least one of id and label may not be {@code null}.
   * @param label
   *         Label of the objects to be deleted
   * @return how many objects have been deleted
   * @throws P11TokenException
   *           If PKCS#11 error happens.
   */
  public abstract int removeObjects(byte[] id, String label)
      throws P11TokenException;

  /**
   * Gets certificate with the given identifier {@code id}.
   * @param id
   *          Identifier of the certificate. Must not be {@code null}.
   * @return certificate with the given identifier.
   */
  public X509Cert getCertForId(byte[] id) {
    for (P11ObjectIdentifier objId : certificates.keySet()) {
      if (objId.matchesId(id)) {
        return certificates.get(objId);
      }
    }
    return null;
  } // method getCertForId

  /**
   * Gets certificate with the given identifier {@code id}.
   * @param objectId
   *          Identifier of the certificate. Must not be {@code null}.
   * @return certificate with the given identifier.
   */
  public X509Cert getCert(P11ObjectIdentifier objectId) {
    return certificates.get(objectId);
  }

  private void updateCaCertsOfIdentities() {
    for (P11Identity identity : identities.values()) {
      updateCaCertsOfIdentity(identity);
    }
  }

  private void updateCaCertsOfIdentity(P11Identity identity) {
    X509Cert[] certchain = identity.certificateChain();
    if (certchain == null || certchain.length == 0) {
      return;
    }

    X509Cert[] newCertchain = buildCertPath(certchain[0]);
    if (!Arrays.equals(certchain, newCertchain)) {
      try {
        identity.setCertificates(newCertchain);
      } catch (P11TokenException ex) {
        LOG.warn("could not set certificates for identity {}", identity.getId());
      }
    }
  } // method updateCaCertsOfIdentity

  private X509Cert[] buildCertPath(X509Cert cert) {
    List<X509Cert> certs = new LinkedList<>();
    X509Cert cur = cert;
    while (cur != null) {
      certs.add(cur);
      cur = getIssuerForCert(cur);
    }
    return certs.toArray(new X509Cert[0]);
  } // method buildCertPath

  private X509Cert getIssuerForCert(X509Cert cert) {
    try {
      if (cert.isSelfSigned()) {
        return null;
      }

      for (X509Cert cert2 : certificates.values()) {
        if (cert2 == cert) {
          continue;
        }

        if (X509Util.issues(cert2, cert)) {
          return cert2;
        }
      }
    } catch (CertificateEncodingException ex) {
      LOG.warn("invalid encoding of certificate {}", ex.getMessage());
    }
    return null;
  } // method getIssuerForCert

  public void refresh()
      throws P11TokenException {
    P11SlotRefreshResult res = refresh0();

    mechanisms.clear();
    certificates.clear();
    identities.clear();

    List<Long> ignoreMechs = new ArrayList<>();

    for (Long mech : res.getMechanisms()) {
      if (mechanismFilter.isMechanismPermitted(slotId, mech)) {
        mechanisms.add(mech);
      } else {
        ignoreMechs.add(mech);
      }
    }
    certificates.putAll(res.getCertificates());
    identities.putAll(res.getIdentities());

    updateCaCertsOfIdentities();

    if (LOG.isInfoEnabled()) {
      StringBuilder sb = new StringBuilder();
      sb.append("initialized module ").append(moduleName).append(", slot ").append(slotId);

      sb.append("\nsupported mechanisms:\n");
      List<Long> sortedMechs = new ArrayList<>(mechanisms);
      Collections.sort(sortedMechs);
      for (Long mech : sortedMechs) {
        sb.append("\t").append(Functions.getMechanismDescription(mech)).append("\n");
      }

      sb.append("\nsupported by device but ignored mechanisms:\n");
      if (ignoreMechs.isEmpty()) {
        sb.append("\tNONE\n");
      } else {
        Collections.sort(ignoreMechs);
        for (Long mech : ignoreMechs) {
          sb.append("\t").append(Functions.getMechanismDescription(mech)).append("\n");
        }
      }

      List<P11ObjectIdentifier> ids = getSortedObjectIds(certificates.keySet());
      sb.append(ids.size()).append(" certificates:\n");
      for (P11ObjectIdentifier objectId : ids) {
        X509Cert entity = certificates.get(objectId);
        sb.append("\t").append(objectId);
        sb.append(", subject='").append(entity.getSubjectText()).append("'\n");
      }

      ids = getSortedObjectIds(identities.keySet());
      sb.append(ids.size()).append(" identities:\n");
      for (P11ObjectIdentifier objectId : ids) {
        P11Identity identity = identities.get(objectId);
        sb.append("\t").append(objectId);

        PublicKey publicKey = identity.getPublicKey();
        if (publicKey != null) {
          String algo = getAlgorithmDesc(publicKey);
          sb.append(", algo=").append(algo);
          if (identity.getCertificate() != null) {
            String subject = identity.getCertificate().getSubjectText();
            sb.append(", subject='").append(subject).append("'");
          }
        } else {
          sb.append(", algo=<symmetric>");
        }
        sb.append("\n");
      }

      LOG.info(sb.toString());
    }
  } // method refresh

  protected void addIdentity(P11Identity identity)
      throws P11DuplicateEntityException {
    if (!slotId.equals(identity.getId().getSlotId())) {
      throw new IllegalArgumentException("invalid identity");
    }

    P11ObjectIdentifier keyId = identity.getId().getKeyId();
    if (hasIdentity(keyId)) {
      throw new P11DuplicateEntityException(slotId, keyId);
    }

    identities.put(keyId, identity);
    updateCaCertsOfIdentity(identity);
  } // method addIdentity

  public boolean hasIdentity(P11ObjectIdentifier keyId) {
    return identities.containsKey(keyId);
  }

  public Set<Long> getMechanisms() {
    return Collections.unmodifiableSet(mechanisms);
  }

  public boolean supportsMechanism(long mechanism) {
    return mechanisms.contains(mechanism);
  }

  public void assertMechanismSupported(long mechanism)
      throws P11UnsupportedMechanismException {
    if (!mechanisms.contains(mechanism)) {
      throw new P11UnsupportedMechanismException(mechanism, slotId);
    }
  }

  public Set<P11ObjectIdentifier> getIdentityKeyIds() {
    return Collections.unmodifiableSet(identities.keySet());
  }

  public Set<P11ObjectIdentifier> getCertIds() {
    return Collections.unmodifiableSet(certificates.keySet());
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

  public P11Identity getIdentity(P11ObjectIdentifier keyId)
      throws P11UnknownEntityException {
    P11Identity ident = identities.get(keyId);
    if (ident == null) {
      throw new P11UnknownEntityException(slotId, keyId);
    }
    return ident;
  }

  protected void assertNoIdentityAndCert(byte[] id, String label)
      throws P11DuplicateEntityException {
    if (id == null && label == null) {
      return;
    }

    Set<P11ObjectIdentifier> objectIds = new HashSet<>(identities.keySet());
    objectIds.addAll(certificates.keySet());

    for (P11ObjectIdentifier objectId : objectIds) {
      boolean matchId = id != null && objectId.matchesId(id);
      boolean matchLabel = label != null && label.equals(objectId.getLabel());

      if (matchId || matchLabel) {
        StringBuilder sb = new StringBuilder("Identity or Certificate with ");
        if (matchId) {
          sb.append("id=0x").append(Hex.encodeUpper(id));
          if (matchLabel) {
            sb.append(" and ");
          }
        }

        if (matchLabel) {
          sb.append("label=").append(label);
        }

        sb.append(" already exists");
        throw new P11DuplicateEntityException(sb.toString());
      }
    }
  } // method assertNoIdentityAndCert

  public P11ObjectIdentifier getObjectId(byte[] id, String label) {
    if (id == null && label == null) {
      return null;
    }

    for (P11ObjectIdentifier objectId : identities.keySet()) {
      boolean match = true;
      if (id != null) {
        match = objectId.matchesId(id);
      }

      if (label != null) {
        match = label.equals(objectId.getLabel());
      }

      if (match) {
        return objectId;
      }
    }

    for (P11ObjectIdentifier objectId : certificates.keySet()) {
      boolean match = true;
      if (id != null) {
        match = objectId.matchesId(id);
      }

      if (label != null) {
        match = label.equals(objectId.getLabel());
      }

      if (match) {
        return objectId;
      }
    }

    return null;
  } // method getObjectId

  public P11IdentityId getIdentityId(byte[] keyId, String keyLabel) {
    if (keyId == null && keyLabel == null) {
      return null;
    }

    for (P11ObjectIdentifier objectId : identities.keySet()) {
      boolean match = true;
      if (keyId != null) {
        match = objectId.matchesId(keyId);
      }

      if (keyLabel != null) {
        match = keyLabel.equals(objectId.getLabel());
      }

      if (match) {
        return identities.get(objectId).getId();
      }
    }

    return null;
  } // method getIdentityId

  /**
   * Exports the certificate of the given identifier {@code objectId}.
   *
   * @param objectId
   *          Object identifier. Must not be {@code null}.
   * @return the exported certificate
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public X509Cert exportCert(P11ObjectIdentifier objectId)
      throws P11TokenException {
    notNull(objectId, "objectId");
    try {
      return getIdentity(objectId).getCertificate();
    } catch (P11UnknownEntityException ex) {
    }

    X509Cert cert = certificates.get(objectId);
    if (cert == null) {
      throw new P11UnknownEntityException(slotId, objectId);
    }
    return cert;
  } // method exportCert

  /**
   * Remove certificates.
   *
   * @param objectId
   *          Object identifier. Must not be {@code null}.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public void removeCerts(P11ObjectIdentifier objectId)
      throws P11TokenException {
    notNull(objectId, "objectId");
    assertWritable("removeCerts");

    P11ObjectIdentifier keyId = null;
    for (P11ObjectIdentifier m : identities.keySet()) {
      P11Identity identity = identities.get(m);
      if (objectId.equals(identity.getId().getCertId())) {
        keyId = m;
        break;
      }
    }

    if (keyId != null) {
      certificates.remove(objectId);
      identities.get(keyId).setCertificates(null);
    } else if (certificates.containsKey(objectId)) {
      certificates.remove(objectId);
    } else {
      throw new P11UnknownEntityException(slotId, objectId);
    }

    updateCaCertsOfIdentities();
    removeCerts0(objectId);
  } // method removeCerts

  /**
   * Removes the key (private key, public key, secret key, and certificates) associated with
   * the given identifier {@code objectId}.
   *
   * @param identityId
   *          Identity identifier. Must not be {@code null}.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public void removeIdentity(P11IdentityId identityId)
      throws P11TokenException {
    notNull(identityId, "identityId");
    assertWritable("removeIdentity");
    P11ObjectIdentifier keyId = identityId.getKeyId();
    if (identities.containsKey(keyId)) {
      if (identityId.getCertId() != null) {
        certificates.remove(identityId.getCertId());
      }
      identities.get(keyId).setCertificates(null);
      identities.remove(keyId);
      updateCaCertsOfIdentities();
    }

    removeIdentity0(identityId);
  } // method removeIdentity

  /**
   * Removes the key (private key, public key, secret key, and certificates) associated with
   * the given identifier {@code objectId}.
   *
   * @param keyId
   *          Key identifier. Must not be {@code null}.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public void removeIdentityByKeyId(P11ObjectIdentifier keyId)
      throws P11TokenException {
    notNull(keyId, "keyId");
    assertWritable("removeIdentityByKeyId");

    P11IdentityId entityId;
    if (identities.containsKey(keyId)) {
      entityId = identities.get(keyId).getId();
      if (entityId.getCertId() != null) {
        certificates.remove(entityId.getCertId());
      }
      identities.get(keyId).setCertificates(null);
      identities.remove(keyId);
      updateCaCertsOfIdentities();

      removeIdentity0(entityId);
    }

  } // method removeIdentityByKeyId

  /**
   * Adds the certificate to the PKCS#11 token under the given identifier {@code objectId}.
   *
   * @param cert
   *          Certificate to be added. Must not be {@code null}.
   * @param control
   *          Control of the object creation process. Must not be {@code null}.
   * @return the identifier of the newly added certificate.
   * @throws CertificateException
   *         if process with certificate fails.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public P11ObjectIdentifier addCert(X509Cert cert, P11NewObjectControl control)
      throws P11TokenException, CertificateException {
    notNull(cert, "cert");
    notNull(control, "control");
    assertWritable("addCert");

    if (control.getLabel() == null) {
      String cn = cert.getCommonName();
      control = new P11NewObjectControl(control.getId(), generateLabel(cn));
    }

    P11ObjectIdentifier objectId = addCert0(cert, control);
    certificates.put(objectId, cert);
    updateCaCertsOfIdentities();
    LOG.info("added certificate {}", objectId);
    return objectId;
  } // method addCert

  protected String generateLabel(String label) {
    String tmpLabel = label;
    int idx = 0;
    while (true) {
      boolean duplicated = false;
      for (P11ObjectIdentifier objectId : identities.keySet()) {
        P11IdentityId identityId = identities.get(objectId).getId();
        P11ObjectIdentifier pubKeyId = identityId.getPublicKeyId();
        P11ObjectIdentifier certId = identityId.getCertId();

        if (label.equals(objectId.getLabel())
            || (pubKeyId != null && label.equals(pubKeyId.getLabel())
            || (certId != null && label.equals(certId.getLabel())))) {
          duplicated = true;
          break;
        }
      }

      if (!duplicated) {
        for (P11ObjectIdentifier objectId : certificates.keySet()) {
          if (objectId.getLabel().equals(label)) {
            duplicated = true;
            break;
          }
        }
      }

      if (!duplicated) {
        return tmpLabel;
      }

      idx++;
      tmpLabel = label + "-" + idx;
    }
  } // method generateLabel

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
  public P11IdentityId generateSecretKey(long keyType, int keysize, P11NewKeyControl control)
      throws P11TokenException {
    assertWritable("generateSecretKey");
    notNull(control, "control");
    assertNoIdentityAndCert(control.getId(), control.getLabel());
    assertSecretKeyAllowed(keyType);

    P11Identity identity = generateSecretKey0(keyType, keysize, control);
    addIdentity(identity);

    P11IdentityId id = identity.getId();
    LOG.info("generated secret key {}", id);
    return id;
  } // method generateSecretKey

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
  public P11ObjectIdentifier importSecretKey(long keyType, byte[] keyValue, P11NewKeyControl control)
      throws P11TokenException {
    notNull(control, "control");
    assertWritable("createSecretKey");
    assertNoIdentityAndCert(control.getId(), control.getLabel());
    assertSecretKeyAllowed(keyType);

    P11Identity identity = importSecretKey0(keyType, keyValue, control);
    addIdentity(identity);

    P11ObjectIdentifier objId = identity.getId().getKeyId();
    LOG.info("created secret key {}", objId);
    return objId;
  } // method importSecretKey

  private void assertSecretKeyAllowed(long keyType)
      throws P11TokenException {
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

    assertMechanismSupported(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
    return generateRSAKeypairOtf0(keysize, publicExponent);
  }

  protected abstract PrivateKeyInfo generateRSAKeypairOtf0(int keysize, BigInteger publicExponent)
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
    assertCanGenKeypair("generateRSAKeypair", PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN, control);
    BigInteger tmpPublicExponent = publicExponent;
    if (tmpPublicExponent == null) {
      tmpPublicExponent = BigInteger.valueOf(65537);
    }

    P11Identity identity = generateRSAKeypair0(keysize, tmpPublicExponent, control);
    addIdentity(identity);
    P11IdentityId id = identity.getId();
    LOG.info("generated RSA keypair {}", id);
    return id;
  } // method generateRSAKeypair

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
  public PrivateKeyInfo generateDSAKeypairOtf(BigInteger p, BigInteger q, BigInteger g)
      throws P11TokenException {
    notNull(p, "p");
    notNull(q, "q");
    notNull(g, "g");
    assertMechanismSupported(PKCS11Constants.CKM_DSA_KEY_PAIR_GEN);
    return generateDSAKeypairOtf0(p, q, g);
  } // method generateDSAKeypairOtf

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
  } // method generateDSAKeypair

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
    notNull(p, "p");
    notNull(q, "q");
    notNull(g, "g");
    assertCanGenKeypair("generateDSAKeypair", PKCS11Constants.CKM_DSA_KEY_PAIR_GEN, control);
    P11Identity identity = generateDSAKeypair0(p, q, g, control);
    addIdentity(identity);
    P11IdentityId id = identity.getId();
    LOG.info("generated DSA keypair {}", id);
    return id;
  } // method generateDSAKeypair

  /**
   * Generates an EC keypair on-the-fly.
   *
   * @param curveOid
   *         Object identifier of the EC curve. Must not be {@code null}.
   * @return the ASN.1 keypair.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public PrivateKeyInfo generateECKeypairOtf(ASN1ObjectIdentifier curveOid)
      throws P11TokenException {
    notNull(curveOid, "curveOid");

    if (EdECConstants.isEdwardsCurve(curveOid)) {
      assertMechanismSupported(PKCS11Constants.CKM_EC_EDWARDS_KEY_PAIR_GEN);
      return generateECEdwardsKeypairOtf0(curveOid);
    } else if (EdECConstants.isMontgomeryCurve(curveOid)) {
      assertMechanismSupported(PKCS11Constants.CKM_EC_MONTGOMERY_KEY_PAIR_GEN);
      return generateECMontgomeryKeypairOtf0(curveOid);
    } else {
      assertMechanismSupported(PKCS11Constants.CKM_EC_KEY_PAIR_GEN);
      return generateECKeypairOtf0(curveOid);
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

    P11Identity identity;
    if (EdECConstants.isEdwardsCurve(curveOid)) {
      assertCanGenKeypair("generateECKeypair", PKCS11Constants.CKM_EC_EDWARDS_KEY_PAIR_GEN,
          control);
      identity = generateECEdwardsKeypair0(curveOid, control);
    } else if (EdECConstants.isMontgomeryCurve(curveOid)) {
      assertCanGenKeypair("generateECKeypair", PKCS11Constants.CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
          control);
      identity = generateECMontgomeryKeypair0(curveOid, control);
    } else {
      assertCanGenKeypair("generateECKeypair", PKCS11Constants.CKM_EC_KEY_PAIR_GEN, control);
      identity = generateECKeypair0(curveOid, control);
    }

    addIdentity(identity);
    P11IdentityId id = identity.getId();
    LOG.info("generated EC keypair {}", id);
    return id;
  } // method generateECKeypair

  /**
   * Generates an SM2 keypair on the fly.
   *
   * @return the ASN.1 keypair.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public PrivateKeyInfo generateSM2KeypairOtf()
      throws P11TokenException {
    assertMechanismSupported(PKCS11Constants.CKM_VENDOR_SM2_KEY_PAIR_GEN);
    return generateSM2KeypairOtf0();
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
  public P11IdentityId generateSM2Keypair(P11NewKeyControl control)
      throws P11TokenException {
    assertCanGenKeypair("generateSM2Keypair", PKCS11Constants.CKM_VENDOR_SM2_KEY_PAIR_GEN, control);
    P11Identity identity = generateSM2Keypair0(control);
    addIdentity(identity);
    P11IdentityId id = identity.getId();
    LOG.info("generated SM2 keypair {}", id);
    return id;
  } // method generateSM2Keypair

  private void assertCanGenKeypair(String methodName, long mechanism, P11NewKeyControl control)
      throws P11UnsupportedMechanismException, P11PermissionException, P11DuplicateEntityException {
    notNull(control, "control");
    assertWritable(methodName);
    assertMechanismSupported(mechanism);
    assertNoIdentityAndCert(control.getId(), control.getLabel());

    if (keyPairTypes == null) {
      return;
    }

    long keyType;
    if (PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN == mechanism) {
      keyType = PKCS11Constants.CKK_RSA;
    } else if (PKCS11Constants.CKM_EC_KEY_PAIR_GEN == mechanism) {
      keyType = PKCS11Constants.CKK_EC;
    } else if (PKCS11Constants.CKM_EC_EDWARDS_KEY_PAIR_GEN == mechanism) {
      keyType = PKCS11Constants.CKK_EC_EDWARDS;
    } else if (PKCS11Constants.CKM_EC_MONTGOMERY_KEY_PAIR_GEN == mechanism) {
      keyType = PKCS11Constants.CKK_EC_MONTGOMERY;
    } else if (PKCS11Constants.CKM_DSA_KEY_PAIR_GEN == mechanism) {
      keyType = PKCS11Constants.CKK_DSA;
    } else if (PKCS11Constants.CKM_VENDOR_SM2_KEY_PAIR_GEN == mechanism) {
      keyType = PKCS11Constants.CKK_VENDOR_SM2;
    } else {
      throw new IllegalStateException("unknown KeyPair generation mechanism " + mechanism);
    }

    if (!keyPairTypes.contains(keyType)) {
      LOG.error("Keypair of key type 0x{} unsupported", Long.toHexString(keyType));
      throw new P11UnsupportedMechanismException(mechanism, slotId);
    }
  } // method assertCanGenKeypair

  /**
   * Updates the certificate associated with the given ID {@code keyId} with the given certificate
   * {@code newCert}.
   *
   * @param keyId
   *          Object identifier of the private key. Must not be {@code null}.
   * @param newCert
   *          Certificate to be added. Must not be {@code null}.
   * @throws CertificateException
   *         if process with certificate fails.
   * @throws P11TokenException
   *         if PKCS#11 token exception occurs.
   */
  public void updateCertificate(P11ObjectIdentifier keyId, X509Cert newCert)
      throws P11TokenException, CertificateException {
    notNull(keyId, "keyId");
    notNull(newCert, "newCert");
    assertWritable("updateCertificate");

    P11Identity identity = identities.get(keyId);
    if (identity == null) {
      throw new P11UnknownEntityException("could not find private key " + keyId);
    }

    java.security.PublicKey pk = identity.getPublicKey();
    java.security.PublicKey newPk = newCert.getPublicKey();
    if (!pk.equals(newPk)) {
      throw new P11TokenException("the given certificate is not for key " + keyId);
    }

    updateCertificate0(keyId, newCert);

    certificates.put(keyId, newCert);

    P11IdentityId identityId = identity.getId();
    identityId.setCertLabel(keyId.getLabel());
    identity.setCertificates(new X509Cert[]{newCert});
    updateCaCertsOfIdentities();
    LOG.info("updated certificate for key {}", keyId);
  } // method updateCertificate

  /**
   * Writes the token details to the given {@code stream}.
   * @param stream
   *          Output stream. Must not be {@code null}.
   * @param verbose
   *          Whether to show the details verbosely.
   * @throws IOException
   *         if IO error occurs.
   */
  public void showDetails(OutputStream stream, boolean verbose)
      throws IOException {
    notNull(stream, "stream");

    List<P11ObjectIdentifier> sortedKeyIds = getSortedObjectIds(identities.keySet());
    int size = sortedKeyIds.size();

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < size; i++) {
      P11ObjectIdentifier keyId = sortedKeyIds.get(i);
      P11Identity identity = identities.get(keyId);

      String label = keyId.getLabel();
      sb.append("\t").append(i + 1).append(". ").append(label);
      sb.append(" (").append("id: ").append(keyId.getIdHex());
      P11IdentityId identityId = identity.getId();
      P11ObjectIdentifier certId = identityId.getCertId();
      if (certId != null && !certId.equals(keyId)) {
        sb.append(", certificate label: ").append(identityId.getCertId().getLabel());
      }

      P11ObjectIdentifier pubKeyId = identityId.getPublicKeyId();
      if (pubKeyId != null && !pubKeyId.equals(keyId)) {
        sb.append(", publicKey label: ").append(pubKeyId.getLabel());
      }

      sb.append(")\n");

      if (identity.getPublicKey() != null) {
        String algo = getAlgorithmDesc(identity.getPublicKey());
        sb.append("\t\tAlgorithm: ").append(algo).append("\n");
        X509Cert[] certs = identity.certificateChain();
        if (certs == null || certs.length == 0) {
          sb.append("\t\tCertificate: NONE\n");
        } else {
          for (int j = 0; j < certs.length; j++) {
            formatString(j, verbose, sb, certs[j]);
          }
        }
      } else {
        sb.append("\t\tSymmetric key\n");
      }
    }

    sortedKeyIds.clear();
    for (P11ObjectIdentifier objectId : certificates.keySet()) {
      if (!identities.containsKey(objectId)) {
        sortedKeyIds.add(objectId);
      }
    }

    Collections.sort(sortedKeyIds);

    if (!sortedKeyIds.isEmpty()) {
      Collections.sort(sortedKeyIds);
      size = sortedKeyIds.size();
      for (int i = 0; i < size; i++) {
        P11ObjectIdentifier objectId = sortedKeyIds.get(i);
        sb.append("\tCert-").append(i + 1).append(". ").append(objectId.getLabel());
        sb.append(" (").append("id: ").append(objectId.getIdHex())
          .append(", label: ").append(objectId.getLabel()).append(")\n");
        formatString(null, verbose, sb, certificates.get(objectId));
      }
    }

    if (sb.length() > 0) {
      stream.write(toUtf8Bytes(sb.toString()));
    }
  } // method showDetails

  protected void assertWritable(String operationName)
      throws P11PermissionException {
    if (readOnly) {
      throw new P11PermissionException("Writable operation " + operationName + " is not permitted");
    }
  } // method assertWritable

  protected boolean existsIdentityForId(byte[] id) {
    for (P11ObjectIdentifier objectId : identities.keySet()) {
      if (objectId.matchesId(id)) {
        return true;
      }
    }

    return false;
  } // method existsIdentityForId

  protected boolean existsIdentityForLabel(String label) {
    for (P11ObjectIdentifier objectId : identities.keySet()) {
      if (objectId.matchesLabel(label)) {
        return true;
      }
    }

    return false;
  } // method existsIdentityForLabel

  protected boolean existsCertForId(byte[] id) {
    for (P11ObjectIdentifier objectId : certificates.keySet()) {
      if (objectId.matchesId(id)) {
        return true;
      }
    }

    return false;
  } // method existsCertForId

  protected boolean existsCertForLabel(String label) {
    for (P11ObjectIdentifier objectId : certificates.keySet()) {
      if (objectId.matchesLabel(label)) {
        return true;
      }
    }

    return false;
  } // method existsCertForLabel

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

  private static void formatString(Integer index, boolean verbose, StringBuilder sb,
      X509Cert cert) {
    String subject = cert.getSubjectText();
    sb.append("\t\tCertificate");
    if (index != null) {
      sb.append("[").append(index).append("]");
    }
    sb.append(": ");

    if (!verbose) {
      sb.append(subject).append("\n");
      return;
    }

    sb.append("\n\t\t\tSubject: ").append(subject);

    sb.append("\n\t\t\tIssuer: ").append(cert.getIssuerText());
    sb.append("\n\t\t\tSerial: ").append(cert.getSerialNumberHex());
    sb.append("\n\t\t\tStart time: ").append(cert.getNotBefore());
    sb.append("\n\t\t\tEnd time: ").append(cert.getNotAfter());
    sb.append("\n\t\t\tSHA1 Sum: ");
    sb.append(HashAlgo.SHA1.hexHash(cert.getEncoded()));
    sb.append("\n");
  } // method formatString

  private List<P11ObjectIdentifier> getSortedObjectIds(Set<P11ObjectIdentifier> sets) {
    List<P11ObjectIdentifier> ids = new ArrayList<>(sets);
    Collections.sort(ids);
    return ids;
  } // method getSortedObjectIds

}
