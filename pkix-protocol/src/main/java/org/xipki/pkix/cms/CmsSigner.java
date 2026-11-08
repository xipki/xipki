// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cms;

import org.xipki.pkix.asn1.cms.Attributes;
import org.xipki.pkix.asn1.cms.CMSAlgorithmProtection;
import org.xipki.pkix.asn1.cms.IssuerAndSerialNumber;
import org.xipki.pkix.asn1.cms.SignerInfo;
import org.xipki.pkix.asn1.x509.Attribute;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.pkix.asn1.x509.Extension;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.crypto.ContentVerifier;
import org.xipki.codec.crypto.ContentVerifierProvider;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.oid.CmsOIDs;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.util.exception.PkixException;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;

/**
 * A signer (SignerInfo) of the CMS SignedData.
 *
 * @author Lijun Liao (xipki)
 */
public class CmsSigner {

  private final SignerInfo info;

  private final Asn1Oid contentType;

  private final byte[] content;

  CmsSigner(SignerInfo info, Asn1Oid contentType, byte[] content) {
    this.info = info;
    this.contentType = contentType;
    this.content = content;
  }

  public SignerInfo toASN1Structure() {
    return info;
  }

  public AlgorithmIdentifier getDigestAlgorithm() {
    return info.getDigestAlgorithm();
  }

  public AlgorithmIdentifier getSignatureAlgorithm() {
    return info.getSignatureAlgorithm();
  }

  public Attributes getSignedAttributes() {
    return info.getSignedAttributes();
  }

  public Attributes getUnsignedAttributes() {
    return info.getUnsignedAttributes();
  }

  /**
   * Returns whether the given certificate is identified by the SID of this signer.
   * @param cert the certificate.
   * @return true if the certificate is identified by the SID, false otherwise.
   */
  public boolean matches(Certificate cert) {
    return matches(info.getSID().getIssuerAndSerialNumber(),
        info.getSID().subjectKeyIdentifier(), cert);
  }

  static boolean matches(IssuerAndSerialNumber isn, byte[] ski, Certificate cert) {
    if (isn != null) {
      return isn.getName().equals(cert.getIssuer())
          && isn.serialNumber().equals(cert.serialNumber());
    }

    if (ski != null) {
      Extension ext = cert.getExtension(ExtensionOIDs.subjectKeyIdentifier);
      return ext != null && Arrays.equals(ski, ext.subjectKeyIdentifier());
    }

    return false;
  }

  /**
   * Verifies the signature and the signed attributes (RFC 5652, section 5.6).
   *
   * @param verifierProvider the provider of the signature verifier. If it has an associated
   *        certificate, the certificate must be valid at the signing-time.
   * @return true if the signature is valid, false otherwise.
   * @throws PkixException if the signer cannot be processed or a signed attribute is invalid.
   */
  public boolean verify(ContentVerifierProvider verifierProvider) throws PkixException {
    Args.notNull(verifierProvider, "verifierProvider");

    Attributes signedAttrs = info.getSignedAttributes();
    Attributes unsignedAttrs = info.getUnsignedAttributes();

    for (Asn1Oid type : new Asn1Oid[]{CmsOIDs.contentType, CmsOIDs.messageDigest,
        CmsOIDs.signingTime, CmsOIDs.cmsAlgorithmProtect}) {
      if (unsignedAttrs != null && unsignedAttrs.hasAttribute(type)) {
        throw new PkixException("attribute " + type.getId() + " MUST NOT be unsigned");
      }
    }

    byte[] toBeVerified;
    if (signedAttrs == null) {
      if (content == null) {
        throw new PkixException("data not encapsulated in signature");
      }
      toBeVerified = content;
    } else {
      if (signedAttrs.hasAttribute(CmsOIDs.counterSignature)) {
        throw new PkixException("a countersignature attribute MUST NOT be a signed attribute");
      }

      // content-type
      Attribute attr = onlySignedAttribute(CmsOIDs.contentType);
      if (attr == null) {
        throw new PkixException("the content-type signed attribute is absent");
      }
      if (!attr.getCmsContentType().equals(contentType)) {
        throw new PkixException("content-type attribute value does not match eContentType");
      }

      // message-digest
      attr = onlySignedAttribute(CmsOIDs.messageDigest);
      if (attr == null) {
        throw new PkixException("the message-digest signed attribute is absent");
      }
      // as in BouncyCastle, the absent content is treated as empty content.
      byte[] digest = CmsCrypto.digest(info.getDigestAlgorithm(),
          content == null ? new byte[0] : content);
      if (!MessageDigest.isEqual(digest, attr.messageDigest())) {
        throw new PkixException("message-digest attribute value does not match calculated value");
      }

      // cmsAlgorithmProtect (RFC 6211)
      attr = onlySignedAttribute(CmsOIDs.cmsAlgorithmProtect);
      if (attr != null) {
        CMSAlgorithmProtection algProtect = attr.getCmsAlgorithmProtection();
        if (!algProtect.getDigestAlgorithm().isEquivalent(info.getDigestAlgorithm())) {
          throw new PkixException("CMS algorithm protection check failed for digestAlgorithm");
        }
        if (!algProtect.getSignatureAlgorithm().isEquivalent(info.getSignatureAlgorithm())) {
          throw new PkixException("CMS algorithm protection check failed for signatureAlgorithm");
        }
      }

      // signing-time
      attr = onlySignedAttribute(CmsOIDs.signingTime);
      if (attr != null && verifierProvider.hasAssociatedCertificate()) {
        Instant signingTime = attr.signingTime();
        if (!verifierProvider.isAssociatedCertificateValidOn(signingTime)) {
          throw new PkixException("verifier not valid at signingTime");
        }
      }

      toBeVerified = signedAttrs.getEncoded();
    }

    AlgorithmIdentifier sigAlg = CmsCrypto.signatureAlgorithm(
        info.getDigestAlgorithm(), info.getSignatureAlgorithm());
    try {
      ContentVerifier verifier = verifierProvider.get(sigAlg);
      return verifier.atomicVerify(toBeVerified, info.signature());
    } catch (Exception e) {
      throw new PkixException("could not verify signature: " + e.getMessage(), e);
    }
  }

  private Attribute onlySignedAttribute(Asn1Oid type) throws PkixException {
    try {
      return info.getSignedAttributes().getOnlyAttribute(type);
    } catch (CodecException e) {
      throw new PkixException("signed attribute " + type.getId() + " is present more than once");
    }
  }

}
