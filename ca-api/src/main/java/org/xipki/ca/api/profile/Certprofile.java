// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.profile.ctrl.*;
import org.xipki.security.KeySpec;
import org.xipki.security.SignAlgo;
import org.xipki.security.exception.BadCertTemplateException;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.exception.CertprofileException;
import org.xipki.util.extra.misc.SubjectKeyIdentifierControl;
import org.xipki.util.extra.type.Validity;

import java.io.Closeable;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Defines how the certificate looks like. All Certprofile classes must extend
 * this class.
 *
 * @author Lijun Liao (xipki)
 *
 */

public abstract class Certprofile implements Closeable {

  protected Certprofile() {
  }

  @Override
  public void close() {
  }

  public ValidityMode getNotAfterMode() {
    return ValidityMode.BY_CA;
  }

  public List<SignAlgo> getSignatureAlgorithms() {
    return null;
  }

  /**
   * Get the SubjectControl.
   *
   * @return the SubjectControl, may not be <code>null</code>.
   */
  public abstract SubjectControl getSubjectControl();

  protected abstract void verifySubjectDnOccurrence(X500Name requestedSubject)
      throws BadCertTemplateException;

  public AuthorityInfoAccessControl getAiaControl() {
    return null;
  }

  public abstract CertificatePolicies getCertificatePolicies();

  public abstract Set<GeneralNameTag> getSubjectAltNameModes();

  public Set<ExtKeyUsageControl> getExtendedKeyUsages() {
    return null;
  }

  public Map<ASN1ObjectIdentifier, Set<GeneralNameTag>>
      getSubjectInfoAccessModes() {
    return null;
  }

  public abstract ExtensionsControl getExtensionsControl();

  /**
   * Initializes this object.
   *
   * @param data
   *          Configuration. Could be {@code null}.
   * @throws CertprofileException
   *         if error during the initialization occurs.
   */
  public abstract void initialize(String data) throws CertprofileException;

  public abstract CertLevel getCertLevel();

  public CertDomain getCertDomain() {
    return CertDomain.RFC5280;
  }

  public KeypairGenControl getKeypairGenControl() {
    return KeypairGenControl.FORBIDDEN;
  }

  public abstract PublicKeyControl getPublicKeyControl();

  public abstract Set<KeySingleUsage> getKeyUsage(KeySpec keySpec);

  public Integer getPathLenBasicConstraint() {
    return null;
  }

  /**
   * Checks and gets the granted NotBefore.
   *
   * @param requestedNotBefore
   *          Requested NotBefore. Could be {@code null}.
   * @return the granted NotBefore.
   */
  public Instant getNotBefore(Instant requestedNotBefore) {
    Instant now = Instant.now();
    return (requestedNotBefore != null && requestedNotBefore.isAfter(now))
            ? requestedNotBefore : now;
  }

  public abstract Validity getValidity();

  /**
   * As in RFC5280:
   * <p>
   *    To indicate that a certificate has no well-defined expiration date,
   *    the notAfter SHOULD be assigned the GeneralizedTime value of
   *    99991231235959Z.
   *
   * @return true to use the fixed value 99991231235959Z in notAfter, false
   *   as in defined in {@link #getValidity()}.
   */
  public boolean hasNoWellDefinedExpirationDate() {
    return false;
  }

  /**
   * Checks the public key. If the check passes, returns the canonicalized
   * public key.
   *
   * @param publicKey
   *          Requested public key. Must not be {@code null}.
   * @return the granted public key.
   * @throws BadCertTemplateException
   *         if the publicKey does not have correct format or is not permitted.
   */
  public SubjectPublicKeyInfo checkPublicKey(SubjectPublicKeyInfo publicKey)
      throws BadCertTemplateException {
    Args.notNull(publicKey, "publicKey");

    KeySpec keySpec = KeySpec.ofPublicKey(publicKey);
    if (keySpec == null) {
      throw new BadCertTemplateException("unknown type of subject public key");
    }

    if (!getPublicKeyControl().allowsPublicKey(keySpec)) {
      throw new BadCertTemplateException("key type " + keySpec
          + " is not permitted");
    }

    return publicKey;
  } // method checkPublicKey

  /**
   * Checks the requested subject. If the check passes, returns the
   * canonicalized subject.
   *
   * @param requestedSubject
   *          Requested subject. Must not be {@code null}.
   * @return the granted subject
   * @throws BadCertTemplateException
   *         if the subject is not permitted.
   * @throws CertprofileException
   *         if error occurs.
   */
  public SubjectInfo getSubject(X500Name requestedSubject)
      throws CertprofileException, BadCertTemplateException {
    Args.notNull(requestedSubject, "requestedSubject");
    verifySubjectDnOccurrence(requestedSubject);

    if (getCertLevel() == CertLevel.CROSS) {
      return new SubjectInfo(requestedSubject, null);
    }

    return ProfileUtil.getSubject(requestedSubject, getSubjectControl());
  }

  /**
   * Checks the requested extensions and returns the canonicalized ones.
   *
   * @param extensionsToProcess
   *          IDs of extensions to be processed. This list shall not be changed.
   * @param requestedSubject
   *          Requested subject. Must not be {@code null}.
   * @param grantedSubject
   *          Granted subject. Must not be {@code null}.
   * @param requestedExtensions
   *          Requested extensions. Could be {@code null}.
   * @param notBefore
   *          NotBefore. Must not be {@code null}.
   * @param notAfter
   *          NotAfter. Must not be {@code null}.
   * @param caInfo
   *          CA information.
   * @return extensions of the certificate to be issued.
   * @throws BadCertTemplateException
   *         if at least one of extension is not permitted.
   * @throws CertprofileException
   *         if error occurs.
   */
  public abstract ExtensionValues getExtensions(
      List<ASN1ObjectIdentifier> extensionsToProcess,
      X500Name requestedSubject, X500Name grantedSubject,
      Map<ASN1ObjectIdentifier, Extension> requestedExtensions,
      Instant notBefore, Instant notAfter, PublicCaInfo caInfo)
          throws CertprofileException, BadCertTemplateException;

  /**
   * Returns maximal size in bytes of the certificate.
   *
   * @return maximal size in bytes of the certificate, 0 or negative value
   *         indicates accepting all sizes.
   */
  public int getMaxCertSize() {
    return 0;
  }

  public byte[] getSubjectKeyIdentifier(
      SubjectPublicKeyInfo subjectPublicKeyInfo)
      throws CertprofileException {
    SubjectKeyIdentifierControl control = getSubjectKeyIdentifierControl();
    if (control == null) {
      control = new SubjectKeyIdentifierControl();
    }

    byte[] keyData = subjectPublicKeyInfo.getPublicKeyData().getOctets();
    return control.computeKeyIdentifier(keyData);
  }

  protected SubjectKeyIdentifierControl getSubjectKeyIdentifierControl() {
    return null;
  }

}
