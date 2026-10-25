// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client.test;

import org.xipki.codec.asn1.Asn1PrintableString;
import org.xipki.codec.asn1.GenerationException;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.pkix.asn1.pkcs10.CertificationRequest;
import org.xipki.pkix.asn1.util.ContentSigner;
import org.xipki.pkix.asn1.x500.DirectoryString;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.Attribute;
import org.xipki.pkix.asn1.x509.BasicConstraints;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.pkix.asn1.x509.Extension;
import org.xipki.pkix.asn1.x509.Extensions;
import org.xipki.pkix.asn1.x509.KeyUsage;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.sign.SignatureSigner;
import org.xipki.pkix.util.KeyUtil;
import org.xipki.pkix.util.misc.CollectionUtil;
import org.xipki.pkix.util.misc.StringUtil;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * Utility class.
 *
 * @author Lijun Liao (xipki)
 */

public class MyUtil {

  public static X509Cert issueSubCaCert(
      PrivateKey rcaKey, X500Name issuer, SubjectPublicKeyInfo pubKeyInfo,
      X500Name subject, BigInteger serialNumber, Instant startTime) throws GenerationException {
    Instant notAfter = startTime.plus(3650, ChronoUnit.DAYS);
    Certificate.V3CertBuilder certGenerator = new Certificate.V3CertBuilder(
        issuer, serialNumber, startTime, notAfter, subject, pubKeyInfo);
    KeyUsage ku = new KeyUsage(KeyUsage.keyCertSign, KeyUsage.cRLSign);
    try {
      certGenerator.addExtension(Extension.ofKeyUsage(true, ku));
      BasicConstraints bc = new BasicConstraints(0);
      certGenerator.addExtension(Extension.ofBasicConstraints(true, bc));
      ContentSigner contentSigner = SignatureSigner.newContentSigner(
          SignAlgo.getInstance(rcaKey), rcaKey);
      return new X509Cert(certGenerator.build(contentSigner));
    } catch (CodecException | NoSuchAlgorithmException | XiSecurityException ex) {
      throw new GenerationException(ex.getMessage(), ex);
    }
  } // method issueSubCaCert

  public static CertificationRequest generateRequest(
      PrivateKey privateKey, SubjectPublicKeyInfo subjectPublicKeyInfo,
      X500Name subjectDn, String challengePassword, List<Extension> extensions)
          throws GenerationException {
    Args.notNull(privateKey, "privateKey");
    Args.notNull(subjectPublicKeyInfo, "subjectPublicKeyInfo");
    Args.notNull(subjectDn, "subjectDn");

    CertificationRequest.CsrBuilder csrBuilder =
        new CertificationRequest.CsrBuilder(subjectDn, subjectPublicKeyInfo);

    if (StringUtil.isNotBlank(challengePassword)) {
      csrBuilder.setAttribute(Attribute.ofChallengePassword(
          new DirectoryString(new Asn1PrintableString(challengePassword))));
    }

    if (CollectionUtil.isNotEmpty(extensions)) {
      csrBuilder.setAttribute(Attribute.ofExtensionRequest(new Extensions(extensions)));
    }

    ContentSigner contentSigner;
    try {
      contentSigner = SignatureSigner.newContentSigner(
          SignAlgo.getInstance(privateKey), privateKey);
    } catch (NoSuchAlgorithmException | XiSecurityException ex) {
      throw new GenerationException(ex.getMessage(), ex);
    }
    try {
      return csrBuilder.build(contentSigner);
    } catch (SignatureException e) {
      throw new GenerationException(e.getMessage(), e);
    }
  } // method generateRequest

  public static X509Cert generateSelfsignedCert(
      CertificationRequest csr, PrivateKey identityKey)
      throws CertificateException, GenerationException, CodecException {
    return generateSelfsignedCert(
        Args.notNull(csr, "csr").getCertificationRequestInfo().getSubject(),
        csr.getSubjectPKInfo(), identityKey);
  }

  public static X509Cert generateSelfsignedCert(
      X500Name subjectDn, SubjectPublicKeyInfo pubKeyInfo, PrivateKey identityKey)
      throws CertificateException, GenerationException, CodecException {
    Args.notNull(subjectDn, "subjectDn");
    Args.notNull(pubKeyInfo, "pubKeyInfo");
    Args.notNull(identityKey, "identityKey");

    Instant notBefore = Instant.now().minus(5, ChronoUnit.MINUTES);
    Instant notAfter = notBefore.plus(30, ChronoUnit.DAYS);

    Certificate.V3CertBuilder certGenerator = new Certificate.V3CertBuilder(
        subjectDn, BigInteger.ONE, notBefore, notAfter, subjectDn, pubKeyInfo);

    KeyUsage ku = new KeyUsage(KeyUsage.digitalSignature, KeyUsage.dataEncipherment,
        KeyUsage.keyAgreement, KeyUsage.keyEncipherment);

    try {
      certGenerator.addExtension(Extension.ofKeyUsage(true, ku));
    } catch (GenerationException ex) {
      throw new CertificateException(
          "could not generate self-signed certificate: " + ex.getMessage(), ex);
    }

    ContentSigner contentSigner;
    try {
      contentSigner = SignatureSigner.newContentSigner(
          SignAlgo.getInstance(identityKey), identityKey);
    } catch (XiSecurityException | NoSuchAlgorithmException ex) {
      throw new CertificateException("error while creating signer", ex);
    }

    return new X509Cert(certGenerator.build(contentSigner));
  } // method generateSelfsignedCert

  public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(PublicKey publicKey)
      throws InvalidKeyException {
    return KeyUtil.createSubjectPublicKeyInfo(publicKey);
  } // method createSubjectPublicKeyInfo

}
