// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.CertificatePolicies;
import org.xipki.pkix.asn1.x509.Extension;
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.profile.ctrl.*;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.exception.BadCertTemplateException;
import org.xipki.ca.api.CertprofileException;
import org.xipki.ca.api.SubjectKeyIdentifierControl;
import org.xipki.pkix.util.conf.Validity;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Certificate profile definition.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class Certprofile {

  protected Certprofile() {
  }

  public ValidityMode notAfterMode() {
    return ValidityMode.BY_CA;
  }

  public List<SignAlgo> signatureAlgorithms() {
    return null;
  }

  /**
   * Get the SubjectControl.
   *
   * @return the SubjectControl, may not be <code>null</code>.
   */
  public abstract SubjectControl subjectControl();

  protected abstract void verifySubjectDnOccurrence(X500Name requestedSubject)
      throws BadCertTemplateException;

  public AuthorityInfoAccessControl aiaControl() {
    return null;
  }

  public abstract CertificatePolicies certificatePolicies();

  public abstract Set<GeneralNameTag> subjectAltNameModes();

  public Set<ExtKeyUsageControl> extendedKeyUsages() {
    return null;
  }

  public Map<Asn1Oid, Set<GeneralNameTag>> subjectInfoAccessModes() {
    return null;
  }

  public abstract ExtensionsControl extensionsControl();

  /**
   * Initializes this object.
   *
   * @param data
   *          Configuration. Could be {@code null}.
   * @throws CertprofileException
   *         if error during the initialization occurs.
   */
  public abstract void initialize(String data) throws CertprofileException;

  public abstract CertLevel certLevel();

  public CertDomain certDomain() {
    return CertDomain.RFC5280;
  }

  public KeypairGenControl keypairGenControl() {
    return KeypairGenControl.FORBIDDEN;
  }

  public abstract PublicKeyControl publicKeyControl();

  public abstract Set<KeySingleUsage> keyUsage(KeySpec keySpec);

  public Integer pathLenBasicConstraint() {
    return null;
  }

  /**
   * Checks and gets the granted NotBefore.
   *
   * @param requestedNotBefore
   *          Requested NotBefore. Could be {@code null}.
   * @return the granted NotBefore.
   */
  public Instant notBefore(Instant requestedNotBefore) {
    Instant now = Instant.now();
    return (requestedNotBefore != null && requestedNotBefore.isAfter(now))
            ? requestedNotBefore : now;
  }

  public abstract Validity validity();

  /**
   * As in RFC5280:
   * <p>
   *    To indicate that a certificate has no well-defined expiration date,
   *    the notAfter SHOULD be assigned the GeneralizedTime value of
   *    99991231235959Z.
   *
   * @return true to use the fixed value 99991231235959Z in notAfter, false
   *   as in defined in {@link #validity()}.
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

    KeySpec keySpec = null;
    try {
      keySpec = KeySpec.ofPublicKey(publicKey);
    } catch (CodecException e) {
      throw new BadCertTemplateException("malformed public key", e);
    }
    if (keySpec == null) {
      throw new BadCertTemplateException("unknown type of subject public key");
    }

    if (!publicKeyControl().allowsPublicKey(keySpec)) {
      throw new BadCertTemplateException("key type " + keySpec + " is not permitted");
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
  public SubjectInfo subject(X500Name requestedSubject) throws BadCertTemplateException {
    Args.notNull(requestedSubject, "requestedSubject");
    verifySubjectDnOccurrence(requestedSubject);

    if (certLevel() == CertLevel.CROSS) {
      return new SubjectInfo(requestedSubject, null);
    }

    return ProfileUtil.getSubject(requestedSubject, subjectControl());
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
      List<Asn1Oid> extensionsToProcess,
      X500Name requestedSubject, X500Name grantedSubject,
      Map<Asn1Oid, Extension> requestedExtensions,
      Instant notBefore, Instant notAfter, PublicCaInfo caInfo)
      throws CertprofileException, BadCertTemplateException;

  /**
   * Returns maximal size in bytes of the certificate.
   *
   * @return maximal size in bytes of the certificate, 0 or negative value
   *         indicates accepting all sizes.
   */
  public int maxCertSize() {
    return 0;
  }

  public byte[] subjectKeyIdentifier(SubjectPublicKeyInfo subjectPublicKeyInfo) {
    SubjectKeyIdentifierControl control = subjectKeyIdentifierControl();
    if (control == null) {
      control = new SubjectKeyIdentifierControl();
    }

    byte[] keyData = subjectPublicKeyInfo.subjectPublicKey();
    return control.computeKeyIdentifier(keyData);
  }

  protected SubjectKeyIdentifierControl subjectKeyIdentifierControl() {
    return null;
  }

}
