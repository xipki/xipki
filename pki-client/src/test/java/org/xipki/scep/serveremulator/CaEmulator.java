// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.serveremulator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.pkix.asn1.pkcs10.CertificationRequest;
import org.xipki.pkix.asn1.util.ContentSigner;
import org.xipki.pkix.asn1.util.ContentVerifierProvider;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.BasicConstraints;
import org.xipki.pkix.asn1.x509.CRLReason;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.pkix.asn1.x509.CertificateList;
import org.xipki.pkix.asn1.x509.Extension;
import org.xipki.pkix.asn1.x509.KeyUsage;
import org.xipki.codec.util.Args;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.sign.SignatureSigner;
import org.xipki.pkix.util.KeyUtil;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * CA emulator.
 *
 * @author Lijun Liao (xipki)
 */

public class CaEmulator {

  private static final Logger LOG = LoggerFactory.getLogger(CaEmulator.class);

  private final PrivateKey caKey;

  private final X509Cert caCert;

  private final X500Name caSubject;

  private final byte[] caCertBytes;

  private final boolean generateCrl;

  private final Map<BigInteger, X509Cert> serialCertMap = new HashMap<>();

  private final Map<X500Name, X509Cert> reqSubjectCertMap = new HashMap<>();

  private final AtomicLong serialNumber = new AtomicLong(2);

  private final AtomicLong crlNumber = new AtomicLong(2);

  public CaEmulator(PrivateKey caKey, X509Cert caCert, boolean generateCrl) {
    this.caKey = Args.notNull(caKey, "caKey");
    this.caCert = Args.notNull(caCert, "caCert");
    this.caSubject = caCert.subject();
    this.generateCrl = generateCrl;
    this.caCertBytes = caCert.getEncoded();
  }

  public PrivateKey caKey() {
    return caKey;
  }

  public X509Cert caCert() {
    return caCert;
  }

  public byte[] caCertBytes() {
    return Arrays.copyOf(caCertBytes, caCertBytes.length);
  }

  public boolean isGenerateCrl() {
    return generateCrl;
  }

  public X509Cert generateCert(CertificationRequest csr) throws Exception {
    if (!verifyPop(csr)) {
      throw new Exception("CSR invalid");
    }
    return generateCert(csr.getSubjectPKInfo(), csr.getSubject());
  }

  public X509Cert generateCert(SubjectPublicKeyInfo pubKeyInfo, X500Name subjectDn)
      throws Exception {
    return generateCert(pubKeyInfo, subjectDn, Instant.now().minus(10, ChronoUnit.MINUTES));
  }

  public X509Cert generateCert(
      SubjectPublicKeyInfo pubKeyInfo, X500Name subjectDn, Instant notBefore)
      throws Exception {
    return generateCert(pubKeyInfo, subjectDn, notBefore,
        new KeyUsage(KeyUsage.digitalSignature, KeyUsage.dataEncipherment,
            KeyUsage.keyAgreement, KeyUsage.keyEncipherment));
  }

  public X509Cert generateCert(
      SubjectPublicKeyInfo pubKeyInfo, X500Name subjectDn, Instant notBefore, KeyUsage ku)
      throws Exception {
    Args.notNull(pubKeyInfo, "pubKeyInfo");
    Args.notNull(subjectDn, "subjectDn");
    Args.notNull(notBefore, "notBefore");

    Instant notAfter = notBefore.plus(730, ChronoUnit.DAYS);
    BigInteger tmpSerialNumber = BigInteger.valueOf(serialNumber.getAndAdd(1));
    Certificate.V3CertBuilder certGenerator = new Certificate.V3CertBuilder(
        caSubject, tmpSerialNumber, notBefore, notAfter, subjectDn, pubKeyInfo);

    certGenerator.addExtension(Extension.ofKeyUsage(true, ku));
    BasicConstraints bc = new BasicConstraints(false);
    certGenerator.addExtension(Extension.ofBasicConstraints(true, bc));

    ContentSigner contentSigner = SignatureSigner.newContentSigner(
        SignAlgo.getInstance(caKey), caKey);
    X509Cert cert = new X509Cert(certGenerator.build(contentSigner));

    serialCertMap.put(tmpSerialNumber, cert);
    reqSubjectCertMap.put(subjectDn, cert);
    return cert;
  } // method generateCert

  public X509Cert getCert(X500Name issuer, BigInteger serialNumber) {
    if (!caSubject.equals(issuer)) {
      return null;
    }

    return serialCertMap.get(serialNumber);
  }

  public X509Cert pollCert(X500Name issuer, X500Name subject) {
    if (!caSubject.equals(Args.notNull(issuer, "issuer"))) {
      return null;
    }

    return reqSubjectCertMap.get(Args.notNull(subject, "subject"));
  }

  public synchronized CertificateList getCrl(X500Name issuer, BigInteger serialNumber)
      throws Exception {
    Instant thisUpdate = Instant.now();
    CertificateList.V2CRLBuilder crlBuilder =
        new CertificateList.V2CRLBuilder(caSubject, thisUpdate);
    Instant nextUpdate = thisUpdate.plus(30, ChronoUnit.DAYS);
    crlBuilder.setNextUpdate(nextUpdate);
    Instant caStartTime = caCert.notBefore();
    Instant revocationTime = caStartTime.plus(1, ChronoUnit.MILLIS);
    if (revocationTime.isAfter(thisUpdate)) {
      revocationTime = caStartTime;
    }
    crlBuilder.addCRLEntry(BigInteger.valueOf(2), revocationTime, CRLReason.keyCompromise);
    crlBuilder.addExtension(Extension.ofCRLNumber(false, crlNumber.getAndAdd(1)));

    ContentSigner contentSigner = SignatureSigner.newContentSigner(
        SignAlgo.getInstance(caKey), caKey);
    return crlBuilder.build(contentSigner);
  } // method getCrl

  private boolean verifyPop(CertificationRequest csr) {
    Args.notNull(csr, "csr");
    try {
      SubjectPublicKeyInfo pkInfo = csr.getSubjectPKInfo();
      PublicKey pk = generatePublicKey(pkInfo);

      ContentVerifierProvider cvp = getContentVerifierProvider(pk);
      return csr.isSignatureValid(cvp);
    } catch (InvalidKeyException | SignatureException | InvalidKeySpecException ex) {
      LOG.error("could not validate POP of CSR", ex);
      return false;
    }
  } // method verifyPop

  public ContentVerifierProvider getContentVerifierProvider(PublicKey publicKey)
      throws InvalidKeyException {
    return KeyUtil.getContentVerifierProvider(publicKey);
  } // method getContentVerifierProvider

  private static PublicKey generatePublicKey(SubjectPublicKeyInfo pkInfo)
      throws InvalidKeySpecException {
    Args.notNull(pkInfo, "pkInfo");

    X509EncodedKeySpec keyspec = new X509EncodedKeySpec(pkInfo.getEncoded());
    Asn1Oid aid = pkInfo.getAlgorithm().getAlgorithm();

    String algorithm;
    if (AlgorithmOIDs.id_rsaEncryption.equals(aid)) {
      algorithm = "RSA";
    } else if (AlgorithmOIDs.id_ecPublicKey.equals(aid)) {
      algorithm = "EC";
    } else {
      throw new InvalidKeySpecException("unsupported key algorithm: " + aid);
    }

    KeyFactory kf;
    try {
      kf = CryptoApiFactory.get().newKeyFactory(algorithm);
    } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
      throw new InvalidKeySpecException("could not find KeyFactory for "
          + algorithm + ": " + ex.getMessage());
    }

    return kf.generatePublic(keyspec);
  } // method generatePublicKey

}
