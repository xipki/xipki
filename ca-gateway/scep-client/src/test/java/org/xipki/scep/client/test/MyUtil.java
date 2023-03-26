// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client.test;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.xipki.scep.util.ScepUtil;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.StringUtil;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Utility class.
 *
 * @author Lijun Liao (xipki)
 */

public class MyUtil {

  public static X509Cert issueSubCaCert(
      PrivateKey rcaKey, X500Name issuer, SubjectPublicKeyInfo pubKeyInfo, X500Name subject,
      BigInteger serialNumber, Instant startTime)
      throws OperatorCreationException {
    Instant notAfter = startTime.plus(3650, ChronoUnit.DAYS);
    X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(issuer, serialNumber,
        Date.from(startTime), Date.from(notAfter), subject, pubKeyInfo);
    X509KeyUsage ku = new X509KeyUsage(X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign);
    try {
      certGenerator.addExtension(Extension.keyUsage, true, ku);
      BasicConstraints bc = new BasicConstraints(0);
      certGenerator.addExtension(Extension.basicConstraints, true, bc);
      String signatureAlgorithm = ScepUtil.getSignatureAlgName(rcaKey, HashAlgo.SHA256);
      ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(rcaKey);
      return new X509Cert(certGenerator.build(contentSigner));
    } catch (CertIOException | NoSuchAlgorithmException ex) {
      throw new OperatorCreationException(ex.getMessage(), ex);
    }
  } // method issueSubCaCert

  public static PKCS10CertificationRequest generateRequest(
      PrivateKey privatekey, SubjectPublicKeyInfo subjectPublicKeyInfo, X500Name subjectDn,
      String challengePassword, List<Extension> extensions)
      throws OperatorCreationException {
    Args.notNull(privatekey, "privatekey");
    Args.notNull(subjectPublicKeyInfo, "subjectPublicKeyInfo");
    Args.notNull(subjectDn, "subjectDn");

    Map<ASN1ObjectIdentifier, ASN1Encodable> attributes = new HashMap<>();

    if (StringUtil.isNotBlank(challengePassword)) {
      attributes.put(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, new DERPrintableString(challengePassword));
    }

    if (CollectionUtil.isNotEmpty(extensions)) {
      attributes.put(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
          new Extensions(extensions.toArray(new Extension[0])));
    }

    PKCS10CertificationRequestBuilder csrBuilder =
        new PKCS10CertificationRequestBuilder(subjectDn, subjectPublicKeyInfo);

    for (ASN1ObjectIdentifier attrType : attributes.keySet()) {
      csrBuilder.addAttribute(attrType, attributes.get(attrType));
    }

    String sigAlgName;
    try {
      sigAlgName = ScepUtil.getSignatureAlgName(privatekey, HashAlgo.SHA1);
    } catch (NoSuchAlgorithmException ex) {
      throw new OperatorCreationException(ex.getMessage(), ex);
    }

    ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlgName).setProvider("BC").build(privatekey);
    return csrBuilder.build(contentSigner);
  } // method generateRequest

  public static X509Cert generateSelfsignedCert(CertificationRequest csr, PrivateKey identityKey)
      throws CertificateException {
    return generateSelfsignedCert(Args.notNull(csr, "csr").getCertificationRequestInfo().getSubject(),
        csr.getCertificationRequestInfo().getSubjectPublicKeyInfo(), identityKey);
  }

  public static X509Cert generateSelfsignedCert(
      X500Name subjectDn, SubjectPublicKeyInfo pubKeyInfo, PrivateKey identityKey)
      throws CertificateException {
    Args.notNull(subjectDn, "subjectDn");
    Args.notNull(pubKeyInfo, "pubKeyInfo");
    Args.notNull(identityKey, "identityKey");

    Instant notBefore = Instant.now().minus(5, ChronoUnit.MINUTES);
    Instant notAfter = notBefore.plus(30, ChronoUnit.DAYS);

    X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(subjectDn, BigInteger.ONE,
        Date.from(notBefore), Date.from(notAfter), subjectDn, pubKeyInfo);

    X509KeyUsage ku = new X509KeyUsage(X509KeyUsage.digitalSignature
        | X509KeyUsage.dataEncipherment | X509KeyUsage.keyAgreement | X509KeyUsage.keyEncipherment);
    try {
      certGenerator.addExtension(Extension.keyUsage, true, ku);
    } catch (CertIOException ex) {
      throw new CertificateException("could not generate self-signed certificate: " + ex.getMessage(), ex);
    }

    ContentSigner contentSigner;
    try {
      String sigAlgorithm = ScepUtil.getSignatureAlgName(identityKey, HashAlgo.SHA1);
      contentSigner = new JcaContentSignerBuilder(sigAlgorithm).setProvider("BC").build(identityKey);
    } catch (OperatorCreationException | NoSuchAlgorithmException ex) {
      throw new CertificateException("error while creating signer", ex);
    }

    return new X509Cert(certGenerator.build(contentSigner));
  } // method generateSelfsignedCert

  public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(PublicKey publicKey)
      throws InvalidKeyException {
    return KeyUtil.createSubjectPublicKeyInfo(publicKey);
  } // method createSubjectPublicKeyInfo

}
