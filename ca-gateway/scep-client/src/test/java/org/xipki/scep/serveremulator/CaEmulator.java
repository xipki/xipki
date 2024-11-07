// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.serveremulator;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcDSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcECContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.scep.util.ScepUtil;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
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

  private static final DefaultDigestAlgorithmIdentifierFinder DFLT_DIGESTALG_IDENTIFIER_FINDER =
      new DefaultDigestAlgorithmIdentifierFinder();

  private static final Map<String, BcContentVerifierProviderBuilder> VERIFIER_PROVIDER_BUILDER = new HashMap<>();

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
    this.caSubject = caCert.getSubject();
    this.generateCrl = generateCrl;
    this.caCertBytes = caCert.getEncoded();
  }

  public PrivateKey getCaKey() {
    return caKey;
  }

  public X509Cert getCaCert() {
    return caCert;
  }

  public byte[] getCaCertBytes() {
    return Arrays.copyOf(caCertBytes, caCertBytes.length);
  }

  public boolean isGenerateCrl() {
    return generateCrl;
  }

  public X509Cert generateCert(CertificationRequest csr) throws Exception {
    if (!verifyPop(csr)) {
      throw new Exception("CSR invalid");
    }
    CertificationRequestInfo reqInfo = csr.getCertificationRequestInfo();
    return generateCert(reqInfo.getSubjectPublicKeyInfo(), reqInfo.getSubject());
  }

  public X509Cert generateCert(SubjectPublicKeyInfo pubKeyInfo, X500Name subjectDn)
      throws Exception {
    return generateCert(pubKeyInfo, subjectDn, Instant.now().minus(10, ChronoUnit.MINUTES));
  }

  public X509Cert generateCert(SubjectPublicKeyInfo pubKeyInfo, X500Name subjectDn, Instant notBefore)
      throws Exception {
    Args.notNull(pubKeyInfo, "pubKeyInfo");
    Args.notNull(subjectDn, "subjectDn");
    Args.notNull(notBefore, "notBefore");

    Instant notAfter = notBefore.plus(730, ChronoUnit.DAYS);
    BigInteger tmpSerialNumber = BigInteger.valueOf(serialNumber.getAndAdd(1));
    X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(caSubject, tmpSerialNumber,
        Date.from(notBefore), Date.from(notAfter), subjectDn, pubKeyInfo);

    X509KeyUsage ku = new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.dataEncipherment
        | X509KeyUsage.keyAgreement | X509KeyUsage.keyEncipherment);
    certGenerator.addExtension(Extension.keyUsage, true, ku);
    BasicConstraints bc = new BasicConstraints(false);
    certGenerator.addExtension(Extension.basicConstraints, true, bc);

    String signatureAlgorithm = ScepUtil.getSignatureAlgName(caKey, HashAlgo.SHA256);
    ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(caKey);
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
    X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(caSubject, Date.from(thisUpdate));
    Instant nextUpdate = thisUpdate.plus(30, ChronoUnit.DAYS);
    crlBuilder.setNextUpdate(Date.from(nextUpdate));
    Instant caStartTime = caCert.getNotBefore();
    Instant revocationTime = caStartTime.plus(1, ChronoUnit.MILLIS);
    if (revocationTime.isAfter(thisUpdate)) {
      revocationTime = caStartTime;
    }
    crlBuilder.addCRLEntry(BigInteger.valueOf(2), Date.from(revocationTime), CRLReason.keyCompromise);
    crlBuilder.addExtension(Extension.cRLNumber, false, new ASN1Integer(crlNumber.getAndAdd(1)));

    String signatureAlgorithm = ScepUtil.getSignatureAlgName(caKey, HashAlgo.SHA256);
    ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(caKey);
    X509CRLHolder crl = crlBuilder.build(contentSigner);
    return crl.toASN1Structure();
  } // method getCrl

  private boolean verifyPop(CertificationRequest csr) {
    Args.notNull(csr, "csr");
    try {
      PKCS10CertificationRequest p10Req = new PKCS10CertificationRequest(csr);
      SubjectPublicKeyInfo pkInfo = p10Req.getSubjectPublicKeyInfo();
      PublicKey pk = generatePublicKey(pkInfo);

      ContentVerifierProvider cvp = getContentVerifierProvider(pk);
      return p10Req.isSignatureValid(cvp);
    } catch (InvalidKeyException | PKCSException | InvalidKeySpecException ex) {
      LOG.error("could not validate POP of CSR", ex);
      return false;
    }
  } // method verifyPop

  public ContentVerifierProvider getContentVerifierProvider(PublicKey publicKey)
      throws InvalidKeyException {
    Args.notNull(publicKey, "publicKey");

    String keyAlg = publicKey.getAlgorithm().toUpperCase();
    if ("EC".equals(keyAlg)) {
      keyAlg = "ECDSA";
    }

    BcContentVerifierProviderBuilder builder = VERIFIER_PROVIDER_BUILDER.get(keyAlg);
    if (builder == null) {
      if ("RSA".equals(keyAlg)) {
        builder = new BcRSAContentVerifierProviderBuilder(DFLT_DIGESTALG_IDENTIFIER_FINDER);
      } else if ("DSA".equals(keyAlg)) {
        builder = new BcDSAContentVerifierProviderBuilder(DFLT_DIGESTALG_IDENTIFIER_FINDER);
      } else if ("ECDSA".equals(keyAlg)) {
        builder = new BcECContentVerifierProviderBuilder(DFLT_DIGESTALG_IDENTIFIER_FINDER);
      } else {
        throw new InvalidKeyException("unknown key algorithm of the public key " + keyAlg);
      }
      VERIFIER_PROVIDER_BUILDER.put(keyAlg, builder);
    }

    AsymmetricKeyParameter keyParam = generatePublicKeyParameter(publicKey);
    try {
      return builder.build(keyParam);
    } catch (OperatorCreationException ex) {
      throw new InvalidKeyException("could not build ContentVerifierProvider: " + ex.getMessage(), ex);
    }
  } // method getContentVerifierProvider

  private static PublicKey generatePublicKey(SubjectPublicKeyInfo pkInfo) throws InvalidKeySpecException {
    Args.notNull(pkInfo, "pkInfo");

    X509EncodedKeySpec keyspec;
    try {
      keyspec = new X509EncodedKeySpec(pkInfo.getEncoded());
    } catch (IOException ex) {
      throw new InvalidKeySpecException(ex.getMessage(), ex);
    }
    ASN1ObjectIdentifier aid = pkInfo.getAlgorithm().getAlgorithm();

    String algorithm;
    if (PKCSObjectIdentifiers.rsaEncryption.equals(aid)) {
      algorithm = "RSA";
    } else if (X9ObjectIdentifiers.id_dsa.equals(aid)) {
      algorithm = "DSA";
    } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(aid)) {
      algorithm = "EC";
    } else {
      throw new InvalidKeySpecException("unsupported key algorithm: " + aid);
    }

    KeyFactory kf;
    try {
      kf = KeyFactory.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      throw new InvalidKeySpecException("could not find KeyFactory for " + algorithm + ": " + ex.getMessage());
    }

    return kf.generatePublic(keyspec);
  } // method generatePublicKey

  private static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key) throws InvalidKeyException {
    Args.notNull(key, "key");

    if (key instanceof RSAPublicKey) {
      RSAPublicKey rsaKey = (RSAPublicKey) key;
      return new RSAKeyParameters(false, rsaKey.getModulus(), rsaKey.getPublicExponent());
    } else if (key instanceof ECPublicKey) {
      return ECUtil.generatePublicKeyParameter(key);
    } else if (key instanceof DSAPublicKey) {
      return DSAUtil.generatePublicKeyParameter(key);
    } else {
      throw new InvalidKeyException("unknown key " + key.getClass().getName());
    }
  } // method generatePublicKeyParameter

}
