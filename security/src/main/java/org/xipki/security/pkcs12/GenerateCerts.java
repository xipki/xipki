// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.util.IPAddress;
import org.xipki.security.EdECConstants;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.CollectionUtil;
import org.xipki.util.IoUtil;
import org.xipki.util.JSON;
import org.xipki.util.PemEncoder;
import org.xipki.util.StringUtil;
import org.xipki.util.ValidableConf;
import org.xipki.util.Validity;
import org.xipki.util.exception.InvalidConfException;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Generate keypairs and certificates.
 *
 * @author Lijun Liao (xipki)
 */

public class GenerateCerts {

  private static class Conf extends ValidableConf {
    private List<KeyCertConf> keycerts;
    private List<CertStore> certstores;

    public void setKeycerts(List<KeyCertConf> keycerts) {
      this.keycerts = keycerts;
    }

    public void setCertstores(List<CertStore> certstores) {
      this.certstores = certstores;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(keycerts, "keycerts");
      validate(keycerts);
      if (certstores != null) {
        validate(certstores);
      }

      Set<String> caKeyCertNames = new HashSet<>();
      Set<String> keyCertNames = new HashSet<>();
      for (KeyCertConf m : keycerts) {
        String name = m.name;
        if ("certstore".equalsIgnoreCase(name)) {
          throw new InvalidConfException("name 'keystore' is reserved and can not be used");
        }

        if (keyCertNames.contains(name)) {
          throw new InvalidConfException("Duplicated name " + name);
        }
        keyCertNames.add(name);

        if ("CA".equalsIgnoreCase((m.certType))) {
          caKeyCertNames.add(name);
        } else if (m.getIssuerName() != null) {
          if (!caKeyCertNames.contains(m.getIssuerName())) {
            throw new InvalidConfException("Unknown issuer '" + m.getIssuerName() + "'");
          }
        }
      }

      if (certstores == null) {
        return;
      }

      Set<String> keystoreNames = new HashSet<>();
      for (CertStore m : certstores) {
        String name = m.name;
        if (keystoreNames.contains(name)) {
          throw new InvalidConfException("Duplicated certstore name " + name);
        }
        keystoreNames.add(name);

        for (String certName : m.keyCertNames) {
          if (!keyCertNames.contains(certName)) {
            throw new InvalidConfException("Unknown keycert name " + certName);
          }
        }
      }
    }

  }

  private static class CertStore extends ValidableConf {
    private String name;
    private String p12Password;
    private List<String> keyCertNames;

    public void setName(String name) {
      this.name = name;
    }

    public void setP12Password(String p12Password) {
      this.p12Password = p12Password;
    }

    public void setKeyCertNames(List<String> keyCertNames) {
      this.keyCertNames = keyCertNames;
    }

    @Override
    public void validate() throws InvalidConfException {
      notBlank(name, "name");
      notBlank(p12Password, "p12Password");
      if (CollectionUtil.isEmpty(keyCertNames)) {
        throw new InvalidConfException("keyCertNames is not se");
      }
    }
  }

  private static class KeyCertConf extends ValidableConf {
    private String name;
    private String issuerName;
    // RSA: RSA/<key size>
    // EC: EC/<curve name>, curve names are P256, P384, P521, BP256, BP384 and BP512.
    // ED25519, ED448
    // DSA: DSA/2048, DSA/3072
    private String keyType;
    // CA, TLS-SERVER, TLS-CLIENT, TLSs
    private String certType;
    private String subject;
    private String validity;
    private String p12Password;

    public void setName(String name) {
      this.name = name;
    }

    public void setKeyType(String keyType) {
      this.keyType = keyType;
    }

    public void setCertType(String certType) {
      this.certType = certType;
    }

    public void setSubject(String subject) {
      this.subject = subject;
    }

    public void setValidity(String validity) {
      this.validity = validity;
    }

    public void setP12Password(String p12Password) {
      this.p12Password = p12Password;
    }

    public String getIssuerName() {
      return issuerName;
    }

    public void setIssuerName(String issuerName) {
      this.issuerName = issuerName;
    }

    @Override
    public void validate() throws InvalidConfException {
      notBlank(name, "name");
      notBlank(keyType, "keyType");
      notBlank(subject, "subject");
      notBlank(validity, "validity");
      notBlank(p12Password, "p12Password");
      if ("CA".equalsIgnoreCase(certType) && issuerName != null) {
        throw new InvalidConfException("CA shall not have non-null issuerName");
      }
    }

  }

  private static class KeyStoreAndCert {
    private final byte[] keystoreBytes;

    private final X509Cert cert;

    public KeyStoreAndCert(byte[] keystoreBytes, X509Cert cert) {
      this.keystoreBytes = keystoreBytes;
      this.cert = cert;
    }
  }

  private static final SecureRandom random = new SecureRandom();

  public static void main(String[] args) {
    boolean argsValid = args != null && args.length == 2;
    if (argsValid) {
      argsValid = StringUtil.isNotBlank(args[0]) && StringUtil.isNotBlank(args[1]);
    }

    if (!argsValid) {
      printUsage();
      return;
    }

    String confFile = args[0];
    String targetDir = args[1];
    try {
      generateKeyCerts(confFile, targetDir);
    } catch (Exception ex) {
      System.out.println("error: " + ex.getMessage());
    }
  }

  private static void printUsage() {
    System.out.println("Usage:");
    System.out.println("  java " + GenerateCerts.class.getName() + " <conf file> <target dir>");
  }

  private static void generateKeyCerts(String confFile, String targetDirPath) throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    File targetDir = new File(targetDirPath);
    if (targetDir.exists()) {
      if (!targetDir.isDirectory()) {
        throw new InvalidConfException("The path " + targetDirPath + " is not a directory.");
      }
    }

    Conf conf = JSON.parseConf(Path.of(confFile), Conf.class);
    conf.validate();

    Map<String, X509Cert> nameCertMap = new HashMap<>();
    Map<String, P12KeyGenerator.KeyAndCertPair> caKeyAndCertPairMap = new HashMap<>();
    Set<String> namesOfGeneratedKeyCerts = new HashSet<>();

    for (KeyCertConf keyCertConf : conf.keycerts) {
      String name = keyCertConf.name;
      boolean isCA = "CA".equalsIgnoreCase(keyCertConf.certType);

      File baseDir = new File(targetDir, isCA ? "CA-" + name : name);
      if (baseDir.exists()) {
         X509Cert cert = X509Util.parseCert(new File(baseDir, name + "-cert.pem"));
         nameCertMap.put(name, cert);
         if (isCA) {
           PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(
               X509Util.toDerEncoded(IoUtil.read(new File(baseDir, name + "-key.pem"))));
           PrivateKey privateKey = KeyUtil.generatePrivateKey(pkInfo);
           caKeyAndCertPairMap.put(name, new P12KeyGenerator.KeyAndCertPair(cert, privateKey));
         }
        System.out.println("keypair and certificate for " + name + " already exist, skipping it");
         continue;
      }

      System.out.println("Start generating key and self-signed certificates of " + name);
      P12KeyGenerator.KeyPairWithSubjectPublicKeyInfo keyPairInfo = generateKeyPair(keyCertConf.keyType);
      SubjectPublicKeyInfo subjectPublicKeyInfo = keyPairInfo.getSubjectPublicKeyInfo();
      KeyPair keyPair = keyPairInfo.getKeypair();

      char[] password = keyCertConf.p12Password.toCharArray();
      KeystoreGenerationParameters genParams = new KeystoreGenerationParameters(password);
      Validity validity = Validity.getInstance(keyCertConf.validity);
      X500Name subject = new X500Name(keyCertConf.subject);
      String certType = keyCertConf.certType;

      KeyStoreAndCert keyStoreAndCert;

      if (keyCertConf.getIssuerName() == null) {
        ContentSigner contentSigner = P12KeyGenerator.getContentSigner(keyPair.getPrivate(), keyPair.getPublic());
        keyStoreAndCert = generateSelfSignedCertificate(certType, contentSigner,
            keyPair.getPrivate(), subjectPublicKeyInfo, genParams, subject, validity);
      } else {
        P12KeyGenerator.KeyAndCertPair caKeyCertPair = caKeyAndCertPairMap.get(keyCertConf.getIssuerName());
        if (caKeyCertPair == null) {
          throw new InvalidConfException("unknown CA " + keyCertConf.getIssuerName());
        }
        ContentSigner contentSigner = P12KeyGenerator.getContentSigner(
            caKeyCertPair.getKey(), caKeyCertPair.getCert().getPublicKey());
        keyStoreAndCert = generateCertificate(certType, contentSigner, caKeyCertPair.getCert(),
            keyPair.getPrivate(), subjectPublicKeyInfo, genParams, subject, validity);
      }

      X509Cert cert = keyStoreAndCert.cert;
      nameCertMap.put(name, cert);

      if (isCA) {
        caKeyAndCertPairMap.put(name, new P12KeyGenerator.KeyAndCertPair(cert, keyPair.getPrivate()));
      }

      byte[] certBytes = cert.getEncoded();
      IoUtil.save(new File(baseDir, name + "-cert.pem"),
          PemEncoder.encode(certBytes, PemEncoder.PemLabel.CERTIFICATE));

      IoUtil.save(new File(baseDir, name + ".p12"), keyStoreAndCert.keystoreBytes);
      byte[] keyBytes = keyPair.getPrivate().getEncoded();
      IoUtil.save(new File(baseDir, name + "-key.pem"),
          PemEncoder.encode(keyBytes, PemEncoder.PemLabel.PRIVATE_KEY));

      System.out.println("Finished generating key and self-signed certificates of " + name);
      namesOfGeneratedKeyCerts.add(name);
    }

    if (conf.certstores != null) {
      File baseDir = new File(targetDir, "certstore");
      baseDir.mkdirs();

      for (CertStore certKeystore : conf.certstores) {
        String name = certKeystore.name;
        // check whether any certificate is newly generated.
        boolean containsNewGeneratedCerts = false;
        for (String certName : certKeystore.keyCertNames) {
          if (namesOfGeneratedKeyCerts.contains(certName)) {
            containsNewGeneratedCerts = true;
            break;
          }
        }

        if (!containsNewGeneratedCerts) {
          System.out.println("No change to certificate keystore " + name + ", skipping it");
          continue;
        }

        KeyStore certP12Ks = KeyUtil.getOutKeyStore("PKCS12");
        certP12Ks.load(null, null);

        List<X509Cert> certs = new ArrayList<>(certKeystore.keyCertNames.size());

        for (String certName : certKeystore.keyCertNames) {
          X509Cert cert = nameCertMap.get(certName);
          certs.add(cert);
          certP12Ks.setCertificateEntry(certName, cert.toJceCert());
        }

        try (OutputStream out = new FileOutputStream(new File(baseDir, name + "-certstore.p12"))) {
          certP12Ks.store(out, certKeystore.p12Password.toCharArray());
        }

        IoUtil.save(new File(baseDir, name + "-certstore.pem"),
            X509Util.encodeCertificates(certs.toArray(new X509Cert[0])).getBytes(StandardCharsets.UTF_8));
      }
    }

  }

  private static P12KeyGenerator.KeyPairWithSubjectPublicKeyInfo generateKeyPair(String keyType) throws Exception {
    keyType = keyType.toUpperCase(Locale.ROOT);
    if (keyType.startsWith("RSA")) {
      int keySize = Integer.parseUnsignedInt(keyType, "RSA/".length(), keyType.length(), 10);
      if (keySize > 2047 && keySize % 1024 == 0) {
        return P12KeyGenerator.genRSAKeypair(keySize, null, null);
      } else {
        throw new InvalidConfException("invalid keyType '" + keyType + "'");
      }
    } else if (keyType.startsWith("EC")) {
      String curveName = keyType.substring("EC/".length());
      ASN1ObjectIdentifier curveOid = AlgorithmUtil.getCurveOidForCurveNameOrOid(curveName);
      if (curveOid == null) {
        throw new InvalidConfException("invalid keyType '" + keyType + "'");
      }
      return P12KeyGenerator.genECKeypair(curveOid, null);
    } else if ("ED25519".equals(keyType)) {
      return P12KeyGenerator.genEdECKeypair(EdECConstants.id_ED25519, null);
    } else if ("ED448".equals(keyType)) {
      return P12KeyGenerator.genEdECKeypair(EdECConstants.id_ED448, null);
    } else if (keyType.startsWith("DSA")) {
      int plength = Integer.parseUnsignedInt(keyType, "DSA/".length(), keyType.length(), 10);
      if (plength == 2048 || plength == 3072) {
        int qlength = 256;
        return P12KeyGenerator.genDSAKeypair(plength, qlength, null);
      } else {
        throw new InvalidConfException("invalid keyType '" + keyType + "'");
      }
    } else {
      throw new InvalidConfException("invalid keyType '" + keyType + "'");
    }
  }

  private static KeyStoreAndCert generateSelfSignedCertificate(
      String certType, ContentSigner signer,
      PrivateKey privateKey, SubjectPublicKeyInfo subjectPublicKeyInfo,
      KeystoreGenerationParameters params, X500Name subject, Validity validity)
      throws Exception {
    return generateCertificate(certType, signer, null, privateKey, subjectPublicKeyInfo, params, subject, validity);
  }

  private static KeyStoreAndCert generateCertificate(
      String certType, ContentSigner signer, X509Cert issuerCert,
      PrivateKey privateKey, SubjectPublicKeyInfo subjectPublicKeyInfo,
      KeystoreGenerationParameters params, X500Name subject, Validity validity)
      throws Exception {
    certType = certType.toUpperCase(Locale.ROOT);

    Instant notBefore = Instant.now().minus(10, ChronoUnit.MINUTES); // 10 minutes past
    Instant notAfter = validity.add(notBefore);

    BigInteger serialNumber;
    X500Name issuer;
    if (issuerCert == null) {
      serialNumber = BigInteger.ONE;
      issuer = subject;
    } else {
      if (notAfter.isAfter(issuerCert.getNotAfter())) {
        notAfter = issuerCert.getNotAfter();
      }
      serialNumber = new BigInteger(72, random);
      issuer = issuerCert.getSubject();
    }

    // Generate keystore
    X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(issuer, serialNumber,
        Date.from(notBefore), Date.from(notAfter), subject, subjectPublicKeyInfo);

    if (issuerCert != null) {
      certGenerator.addExtension(Extension.authorityKeyIdentifier, false,
          new AuthorityKeyIdentifier(issuerCert.getSubjectKeyId()));
    }

    byte[] encodedSpki = subjectPublicKeyInfo.getPublicKeyData().getBytes();
    byte[] skiValue = HashAlgo.SHA1.hash(encodedSpki);
    certGenerator.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(skiValue));

    boolean isCA = "CA".equalsIgnoreCase(certType);
    BasicConstraints basicConstraints = isCA ? new BasicConstraints(0) : new BasicConstraints(false);
    certGenerator.addExtension(Extension.basicConstraints, true, basicConstraints);

    KeyUsage keyUsage = isCA
        ? new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
        : new KeyUsage(KeyUsage.digitalSignature);
    certGenerator.addExtension(Extension.keyUsage, true, keyUsage);

    if ("TLS-SERVER".equals(certType) || "TLS-CLIENT".equals(certType) || "TLS".equals(certType)) {
      List<KeyPurposeId> purposeIds = new LinkedList<>();
      if ("TLS-SERVER".equals(certType) || "TLS".equals(certType)) {
        purposeIds.add(KeyPurposeId.id_kp_serverAuth);
        String commonName = X509Util.getCommonName(subject);
        GeneralName generalName;
        if (IPAddress.isValid(commonName)) {
          generalName = new GeneralName(GeneralName.iPAddress, commonName);
        } else {
          generalName = new GeneralName(GeneralName.dNSName, commonName);
        }
        certGenerator.addExtension(Extension.subjectAlternativeName, false,
            new GeneralNames(new GeneralName[]{generalName}));
      }

      if ("TLS-CLIENT".equals(certType) || "TLS".equals(certType)) {
        purposeIds.add(KeyPurposeId.id_kp_clientAuth);
      }

      certGenerator.addExtension(Extension.extendedKeyUsage, false,
          new ExtendedKeyUsage(purposeIds.toArray(new KeyPurposeId[0])));
    }

    P12KeyGenerator.KeyAndCertPair identity = new P12KeyGenerator.KeyAndCertPair(
        new X509Cert(certGenerator.build(signer)), privateKey);

    KeyStore ks = KeyUtil.getOutKeyStore("PKCS12");
    ks.load(null, params.getPassword());

    ks.setKeyEntry("main", privateKey, params.getPassword(),
        new java.security.cert.Certificate[]{identity.getCert().toJceCert()});

    ByteArrayOutputStream ksStream = new ByteArrayOutputStream();
    try {
      ks.store(ksStream, params.getPassword());
    } finally {
      ksStream.flush();
    }

    return new KeyStoreAndCert(ksStream.toByteArray(), identity.getCert());
  }

}
