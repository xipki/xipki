// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.security.util;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.util.IPAddress;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.xipki.security.HashAlgo;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;
import org.xipki.security.X509Cert;
import org.xipki.security.pkcs12.KeyPairWithSubjectPublicKeyInfo;
import org.xipki.security.pkcs12.KeystoreGenerationParameters;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.misc.PemEncoder;
import org.xipki.util.extra.type.Validity;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.xipki.util.codec.Args.notEmpty;

/**
 * Generate keypairs and certificates.
 *
 * @author Lijun Liao (xipki)
 */

public class GenerateCerts {

  private static class Conf {

    private final List<SecretKeyConf> secretkeys;
    private final List<KeyCertConf> keycerts;
    private final List<KeyCertConf2> keycerts2;
    private final List<CertStore> certstores;

    public Conf(List<SecretKeyConf> secretkeys, List<KeyCertConf> keycerts,
                List<KeyCertConf2>  keycerts2,  List<CertStore>   certstores) {
      this.secretkeys = (secretkeys == null) ? Collections.emptyList()
          : secretkeys;
      this.keycerts = (keycerts == null) ? Collections.emptyList()
          : keycerts;
      this.keycerts2 = (keycerts2 == null) ? Collections.emptyList()
          : keycerts2;
      this.certstores = (certstores == null) ? Collections.emptyList()
          : certstores;
      validate();
    }

    private void validate() {
      Set<String> caKeyCertNames = new HashSet<>();
      Set<String> keyCertNames = new HashSet<>();

      for (KeyCertConf m : this.keycerts) {
        String name = m.name;
        if ("certstore".equalsIgnoreCase(name)) {
          throw new IllegalArgumentException(
              "Name 'keystore' is reserved and can not be used");
        }

        if (keyCertNames.contains(name)) {
          throw new IllegalArgumentException("Duplicated name " + name);
        }
        keyCertNames.add(name);

        if ("CA".equalsIgnoreCase((m.certType))) {
          caKeyCertNames.add(name);
        } else if (m.issuerName != null) {
          if (!caKeyCertNames.contains(m.issuerName)) {
            throw new IllegalArgumentException(
                "Unknown issuer '" + m.issuerName + "'");
          }
        }
      }

      for (KeyCertConf2 m : this.keycerts2) {
        String name = m.name;
        if ("certstore".equalsIgnoreCase(name)) {
          throw new IllegalArgumentException(
              "Name 'keystore' is reserved and can not be used");
        }

        if (keyCertNames.contains(name)) {
          throw new IllegalArgumentException("Duplicated name " + name);
        }
        keyCertNames.add(name);

        if (m.getIssuerName() != null) {
          if (!caKeyCertNames.contains(m.getIssuerName())) {
            throw new IllegalArgumentException(
                "Unknown issuer '" + m.getIssuerName() + "'");
          }
        }
      }

      Set<String> keystoreNameSet = new HashSet<>();
      if (certstores != null) {
        for (CertStore m : certstores) {
          String name = m.name;
          if (keystoreNameSet.contains(name)) {
            throw new IllegalArgumentException(
                "Duplicated certstore name " + name);
          }
          keystoreNameSet.add(name);

          for (String certName : m.keyCertNames) {
            if (!keyCertNames.contains(certName)) {
              throw new IllegalArgumentException(
                  "Unknown keycert name " + certName);
            }
          }
        }
      }

      if (secretkeys != null && secretkeys.size() > 1) {
        Set<String> keystoreNames = new HashSet<>();
        for (SecretKeyConf m : secretkeys) {
          if (keystoreNames.contains(m.name)) {
            throw new IllegalArgumentException(
                "Duplicated secretkey name " + m.name);
          }
          keystoreNames.add(m.name);
        }
      }
    }

    public static Conf parse(JsonMap json) throws CodecException {
      JsonList list = json.getList("secretkeys");
      List<SecretKeyConf> secretkeys = (list == null) ? null
          : SecretKeyConf.parseList(list);

      list = json.getList("keycerts");
      List<KeyCertConf> keycerts = (list == null) ? null
          : KeyCertConf.parseList(list);

      list = json.getList("keycerts2");
      List<KeyCertConf2> keycerts2 = (list == null) ? null
          : KeyCertConf2.parseList(list);

      list = json.getList("certstores");
      List<CertStore> cerstores = (list == null) ? null
          : CertStore.parseList(list);

      return new Conf(secretkeys, keycerts, keycerts2, cerstores);
    }

  }

  private static class CertStore {

    private final String name;

    private final String p12Password;

    private final List<String> keyCertNames;

    public CertStore(String name, String p12Password,
                     List<String> keyCertNames) {
      this.name = Args.notBlank(name, "name");
      this.p12Password = Args.notBlank(p12Password, "p12Password");
      this.keyCertNames = notEmpty(keyCertNames, "keyCertNames");
    }

    public static CertStore parse(JsonMap json) throws CodecException {
      return new CertStore(json.getNnString("name"),
          json.getString("p12Password"),
          json.getStringList("keyCertNames"));
    }

    public static List<CertStore> parseList(JsonList json)
        throws CodecException {
      List<CertStore> ret = new ArrayList<>(json.size());
      for (JsonMap m : json.toMapList()) {
        ret.add(parse(m));
      }
      return ret;
    }

  }

  private static class KeyCertConf {

    private final String name;
    private final String issuerName;
    private final String keyType;
    // CA, TLS-SERVER, TLS-CLIENT, TLS, EE
    private final String certType;
    private final String subject;
    private final String validity;
    private final String p12Password;

    public KeyCertConf(String name, String issuerName, String keyType,
                       String certType, String subject, String validity,
                       String p12Password) {
      this.name = Args.notBlank(name, "name");
      this.keyType = Args.notBlank(keyType, "keyType");
      this.certType = Args.notBlank(certType, "certType");
      this.subject = Args.notBlank(subject, "subject");
      this.validity = Args.notBlank(validity, "validity");
      this.p12Password = Args.notBlank(p12Password, "p12Password");
      this.issuerName = issuerName;

      if ("CA".equalsIgnoreCase(certType) && issuerName != null) {
        throw new IllegalArgumentException(
            "CA shall not have non-null issuerName");
      }
    }

    public static KeyCertConf parse(JsonMap json) throws CodecException {
      return new KeyCertConf(
          json.getString("name"),
          json.getString("issuerName"),
          json.getString("keyType"),
          json.getString("certType"),
          json.getString("subject"),
          json.getString("validity"),
          json.getString("p12Password"));
    }

    public static List<KeyCertConf> parseList(JsonList json)
        throws CodecException {
      List<KeyCertConf> ret = new ArrayList<>(json.size());
      for (JsonMap m : json.toMapList()) {
        ret.add(parse(m));
      }
      return ret;
    }

  }

  private static class KeyCertConf2 {

    private final String name;
    private final String issuerName;
    private final String p12Password;
    private final List<SingleKeyCert> entries;

    public KeyCertConf2(String name, String issuerName, String p12Password,
                        List<SingleKeyCert> entries) {
      this.name = Args.notBlank(name, "name");
      this.issuerName = issuerName;
      this.p12Password = Args.notBlank(p12Password, "p12Password");
      this.entries = notEmpty(entries, "entries");
    }

    public String getIssuerName() {
      return issuerName;
    }

    public static KeyCertConf2 parse(JsonMap json) throws CodecException {
      JsonList list = json.getList("entries");
      List<SingleKeyCert> entries = null;
      if (list != null) {
        entries = SingleKeyCert.parseList(list);
      }

      return new KeyCertConf2(json.getString("name"),
          json.getString("issuerName"),
          json.getString("p12Password"),
          entries);
    }

    public static List<KeyCertConf2> parseList(JsonList json)
        throws CodecException {
      List<KeyCertConf2> ret = new ArrayList<>(json.size());
      for (JsonMap m : json.toMapList()) {
        ret.add(parse(m));
      }
      return ret;
    }

  }

  private static class SingleKeyCert {

    private final String keyType;
    // TLS-SERVER, TLS-CLIENT, TLS, EE
    private final String certType;
    private final String subject;
    private final String validity;

    public SingleKeyCert(String keyType, String certType,
                         String subject, String validity) {
      this.keyType = Args.notBlank(keyType, "keyType");
      this.certType = certType;
      this.subject = Args.notBlank(subject, "subject");
      this.validity = Args.notBlank(validity, "validity");
      if ("CA".equalsIgnoreCase(certType)) {
        throw new IllegalArgumentException("certType CA is not allowed");
      }
    }

    public static SingleKeyCert parse(JsonMap json) throws CodecException {
      return new SingleKeyCert(
          json.getString("keyType"),
          json.getString("certType"),
          json.getString("subject"),
          json.getString("validity"));
    }

    public static List<SingleKeyCert> parseList(JsonList json)
        throws CodecException {
      List<SingleKeyCert> ret = new ArrayList<>(json.size());
      for (JsonMap m : json.toMapList()) {
        ret.add(parse(m));
      }
      return ret;
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

  private static class SecretKeyEntry {

    // AES/128, AES/192, AES/256
    private final String keyType;
    private final String alias;

    public SecretKeyEntry(String keyType, String alias) {
      this.keyType = Args.notBlank(keyType, "keyType");
      this.alias = Args.notBlank(alias, "alias");
    }

    public String getKeyType() {
      return keyType;
    }

    public String getAlias() {
      return alias;
    }

    public static SecretKeyEntry parse(JsonMap json) throws CodecException {
      return new SecretKeyEntry(
          json.getString("keyType"), json.getString("alias"));
    }

    public static List<SecretKeyEntry> parseList(JsonList json)
        throws CodecException {
      List<SecretKeyEntry> ret = new ArrayList<>(json.size());
      for (JsonMap m : json.toMapList()) {
        ret.add(parse(m));
      }
      return ret;
    }

  }

  private static class SecretKeyConf {
    private final String name;
    private final String password;
    private final List<SecretKeyEntry> keys;

    public SecretKeyConf(String name, String password,
                         List<SecretKeyEntry> keys) {
      this.name = Args.notBlank(name, "name");
      this.password = Args.notBlank(password, "p12Password");
      this.keys = Args.notEmpty(keys, "keys");
      if (keys.size() > 1) {
        List<String> aliases = new ArrayList<>(keys.size());
        for (SecretKeyEntry entry : keys) {
          String alias = entry.alias;
          if (aliases.contains(alias)) {
            throw new IllegalArgumentException("duplicated alias " + alias);
          }
          aliases.add(alias);
        }
      }

    }

    public static SecretKeyConf parse(JsonMap json) throws CodecException {
      JsonList list = json.getList("keys");

      List<SecretKeyEntry> keys = null;
      if (list != null) {
        keys = SecretKeyEntry.parseList(list);
      }

      return new SecretKeyConf(json.getString("name"),
          json.getString("password"), keys);
    }

    public static List<SecretKeyConf> parseList(JsonList json)
        throws CodecException {
      List<SecretKeyConf> ret = new ArrayList<>(json.size());
      for (JsonMap m : json.toMapList()) {
        ret.add(parse(m));
      }
      return ret;
    }

    public String getName() {
      return name;
    }

    public String getPassword() {
      return password;
    }

    public List<SecretKeyEntry> getKeys() {
      return keys;
    }

  }

  private static final SecureRandom random = new SecureRandom();

  public static void main(String[] args) {
    boolean argsValid = args != null && args.length == 2;
    if (argsValid) {
      argsValid = StringUtil.isNotBlank(args[0]) &&
                  StringUtil.isNotBlank(args[1]);
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
      ex.printStackTrace();
      System.out.println("error: " + ex.getMessage());
    }
  }

  private static void printUsage() {
    System.out.println("Usage:");
    System.out.println("  java " + GenerateCerts.class.getName() +
        " <conf file> <target dir>");
  }

  private static void generateKeyCerts(String confFile, String targetDirPath)
      throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(KeyUtil.newBouncyCastleProvider());
    }

    File targetDir = new File(targetDirPath);
    if (targetDir.exists()) {
      if (!targetDir.isDirectory()) {
        throw new InvalidConfException("The path " + targetDirPath +
            " is not a directory.");
      }
    }

    JsonMap root = JsonParser.parseMap(Paths.get(confFile), true);
    Conf conf = Conf.parse(root);
    conf.validate();

    Map<String, X509Cert[]>  nameCertMap = new HashMap<>();
    Map<String, KeyWithCert> caKeyAndCertPairMap = new HashMap<>();
    Set<String> namesOfGeneratedKeyCerts = new HashSet<>();

    if (conf.secretkeys != null) {
      File baseDir = new File(targetDir, "secretkeys");
      baseDir.mkdirs();

      for (SecretKeyConf skConf : conf.secretkeys) {
        char[] password = skConf.password.toCharArray();
        KeyStore ks = KeyUtil.getOutKeyStore("JCEKS");
        ks.load(null, null);
        for (SecretKeyEntry entry : skConf.getKeys()) {
          SecretKey key = generateSecretKey(entry.keyType);
          ks.setKeyEntry(entry.alias, key, password, null);
        }

        try (OutputStream out = new FileOutputStream(
            new File(baseDir, skConf.name + ".jceks"))) {
          ks.store(out, password);
        }
      }
    }

    for (KeyCertConf keyCertConf : conf.keycerts) {
      String name = keyCertConf.name;
      boolean isCA = "CA".equalsIgnoreCase(keyCertConf.certType);

      File baseDir = new File(targetDir, isCA ? "CA-" + name : name);
      if (baseDir.exists()) {
        X509Cert cert = X509Util.parseCert(
            new File(baseDir, name + "-cert.pem"));
        nameCertMap.put(name, new X509Cert[]{cert});

        PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(
            X509Util.toDerEncoded(IoUtil.read(
                new File(baseDir, name + "-key.pem"))));
        PrivateKey privateKey = KeyUtil.getPrivateKey(pkInfo);

        if (isCA) {
          caKeyAndCertPairMap.put(name, new KeyWithCert(cert, privateKey));
        }

        System.out.println("keypair and certificate for " + name +
            " already exist, skipping it");
        continue;
      }

      System.out.println("Start generating key and certificates of " + name);
      KeySpec keySpec = KeySpec.ofKeySpec(keyCertConf.keyType);

      KeyPairWithSubjectPublicKeyInfo keyPairInfo =
          KeyUtil.generateKeypair2(keySpec, null);

      SubjectPublicKeyInfo subjectPublicKeyInfo =
          keyPairInfo.getSubjectPublicKeyInfo();

      KeyPair keyPair = keyPairInfo.getKeypair();

      char[] password = keyCertConf.p12Password.toCharArray();
      KeystoreGenerationParameters genParams =
          new KeystoreGenerationParameters(password);

      Validity validity = Validity.getInstance(keyCertConf.validity);
      X500Name subject = new X500Name(keyCertConf.subject);
      String certType = keyCertConf.certType;

      KeyStoreAndCert keyStoreAndCert;

      if (keyCertConf.issuerName == null) {
        ContentSigner contentSigner = KeyUtil.getContentSigner(
            keyPair.getPrivate(), keyPair.getPublic(), random);

        keyStoreAndCert = generateSelfSignedCertificate(certType,
            contentSigner, keyPair.getPrivate(), subjectPublicKeyInfo,
            genParams, subject, validity);
      } else {
        KeyWithCert caKeyCertPair =
            caKeyAndCertPairMap.get(keyCertConf.issuerName);
        if (caKeyCertPair == null) {
          throw new InvalidConfException(
              "unknown CA " + keyCertConf.issuerName);
        }
        ContentSigner contentSigner = KeyUtil.getContentSigner(
            caKeyCertPair.getKey(), caKeyCertPair.getCert().getPublicKey(),
            random);
        keyStoreAndCert = generateCertificate(certType, contentSigner,
            caKeyCertPair.getCert(), keyPair.getPrivate(),
            subjectPublicKeyInfo, genParams, subject, validity);
      }

      X509Cert cert = keyStoreAndCert.cert;
      nameCertMap.put(name, new X509Cert[]{cert});

      if (isCA) {
        caKeyAndCertPairMap.put(name,
            new KeyWithCert(cert, keyPair.getPrivate()));
      }

      byte[] certBytes = cert.getEncoded();
      IoUtil.save(new File(baseDir, name + "-cert.pem"),
          PemEncoder.encode(certBytes, PemEncoder.PemLabel.CERTIFICATE));

      IoUtil.save(new File(baseDir, name + ".p12"),
          keyStoreAndCert.keystoreBytes);
      byte[] keyBytes = keyPair.getPrivate().getEncoded();
      IoUtil.save(new File(baseDir, name + "-key.pem"),
          PemEncoder.encode(keyBytes, PemEncoder.PemLabel.PRIVATE_KEY));

      System.out.println("Finished generating key and certificates of " + name);
      namesOfGeneratedKeyCerts.add(name);
    }

    for (KeyCertConf2 keyCertConf : conf.keycerts2) {
      String name = keyCertConf.name;

      File baseDir = new File(targetDir, name);
      if (baseDir.exists()) {
        List<X509Cert> certs0 = X509Util.parseCerts(
            new File(baseDir, name + "-certs.pem"));

        List<PrivateKey> keys = new LinkedList<>();
        try (PemReader pemReader = new PemReader(new FileReader(
            new File(baseDir, name + "-keys.pem")))) {
          while (true) {
            PemObject pemObject = pemReader.readPemObject();
            if (pemObject == null) {
              break;
            }

            PrivateKeyInfo pkInfo =
                PrivateKeyInfo.getInstance(pemObject.getContent());
            keys.add(KeyUtil.getPrivateKey(pkInfo));
          }
        }

        if (certs0.size() != keys.size()) {
          throw new InvalidConfException(
              "number of existing certificate (" + certs0.size() +
              ") != number of existing keys (" + keys.size() + ") for " + name);
        }

        nameCertMap.put(name, certs0.toArray(new X509Cert[0]));

        System.out.println("keypair and certificate for " + name +
            " already exist, skipping it");
        continue;
      }

      System.out.println("Start generating key and certificates of " + name);
      char[] password = keyCertConf.p12Password.toCharArray();
      KeystoreGenerationParameters genParams =
          new KeystoreGenerationParameters(password);

      int size = keyCertConf.entries.size();
      X509Cert[] thisCerts = new X509Cert[size];
      PrivateKey[] thisKeys = new PrivateKey[size];

      int index = 0;
      for (SingleKeyCert entry : keyCertConf.entries) {
        KeySpec keySpec = KeySpec.ofKeySpec(entry.keyType);

        KeyPairWithSubjectPublicKeyInfo keyPairInfo =
            KeyUtil.generateKeypair2(keySpec, null);

        SubjectPublicKeyInfo subjectPublicKeyInfo =
            keyPairInfo.getSubjectPublicKeyInfo();
        KeyPair keyPair = keyPairInfo.getKeypair();

        Validity validity = Validity.getInstance(entry.validity);
        X500Name subject = new X500Name(entry.subject);
        String certType = entry.certType;

        KeyStoreAndCert keyStoreAndCert;

        if (keyCertConf.getIssuerName() == null) {
          ContentSigner contentSigner = KeyUtil.getContentSigner(
              keyPair.getPrivate(), keyPair.getPublic(), random, true);

          keyStoreAndCert = generateSelfSignedCertificate(certType,
              contentSigner, keyPair.getPrivate(), subjectPublicKeyInfo,
              genParams, subject, validity);
        } else {
          KeyWithCert caKeyCertPair =
              caKeyAndCertPairMap.get(keyCertConf.getIssuerName());
          if (caKeyCertPair == null) {
            throw new InvalidConfException(
                "unknown CA " + keyCertConf.getIssuerName());
          }
          ContentSigner contentSigner =
              KeyUtil.getContentSigner(caKeyCertPair.getKey(),
              caKeyCertPair.getCert().getPublicKey(), random);
          keyStoreAndCert = generateCertificate(certType, contentSigner,
              caKeyCertPair.getCert(), keyPair.getPrivate(),
              subjectPublicKeyInfo, genParams, subject, validity);
        }

        X509Cert cert = keyStoreAndCert.cert;
        thisCerts[index] = cert;
        thisKeys[index] = keyPairInfo.getKeypair().getPrivate();
        index++;
      }

      nameCertMap.put(name, thisCerts);

      IoUtil.save(new File(baseDir, name + "-certs.pem"),
          Objects.requireNonNull(X509Util.encodeCertificates(thisCerts))
              .getBytes(StandardCharsets.UTF_8));

      KeyStore ks = KeyUtil.getOutKeyStore("PKCS12");
      ks.load(null, null);

      for (int i = 0; i < size; i++) {
        ks.setKeyEntry(name + "-" + (i + 1), thisKeys[i],
            password, new Certificate[]{thisCerts[i].toJceCert()});
      }

      try (OutputStream keystoreOs = new FileOutputStream(
          new File(baseDir, name + ".p12"))) {
        ks.store(keystoreOs, password);
      }

      ByteArrayOutputStream pemKeyStreams = new ByteArrayOutputStream();
      for (int i = 0; i < size; i++) {
        pemKeyStreams.write(PemEncoder.encode(thisKeys[i].getEncoded(),
            PemEncoder.PemLabel.PRIVATE_KEY));
      }

      IoUtil.save(new File(baseDir, name + "-keys.pem"),
          pemKeyStreams.toByteArray());

      System.out.println("Finished generating key and certificates of " + name);
      namesOfGeneratedKeyCerts.add(name);
    }

    if (conf.certstores != null) {
      File baseDir = new File(targetDir, "certstore");
      baseDir.mkdirs();

      for (CertStore certstore : conf.certstores) {
        String name = certstore.name;
        // check whether any certificate is newly generated.
        boolean containsNewGeneratedCerts = false;
        for (String certName : certstore.keyCertNames) {
          if (namesOfGeneratedKeyCerts.contains(certName)) {
            containsNewGeneratedCerts = true;
            break;
          }
        }

        if (!containsNewGeneratedCerts) {
          System.out.println("No change to certificate keystore " +
              name + ", skipping it");
          continue;
        }

        KeyStore certP12Ks = KeyUtil.getOutKeyStore("PKCS12");
        certP12Ks.load(null, null);

        List<X509Cert> certs = new ArrayList<>(certstore.keyCertNames.size());

        for (String certName : certstore.keyCertNames) {
          X509Cert[] certs0 = nameCertMap.get(certName);
          certs.addAll(Arrays.asList(certs0));

          certP12Ks.setCertificateEntry(certName, certs0[0].toJceCert());
          if (certs0.length > 1) {
            for (int i = 1; i < certs0.length; i++) {
              certP12Ks.setCertificateEntry(certName + "-" + i,
                  certs0[i].toJceCert());
            }
          }
        }

        try (OutputStream out = new FileOutputStream(
            new File(baseDir, name + "-certstore.p12"))) {
          certP12Ks.store(out, certstore.p12Password.toCharArray());
        }

        IoUtil.save(new File(baseDir, name + "-certstore.pem"),
            X509Util.encodeCertificates(certs.toArray(new X509Cert[0]))
                .getBytes(StandardCharsets.UTF_8));
      }
    }

  }

  private static KeyStoreAndCert generateSelfSignedCertificate(
      String certType, ContentSigner signer,
      PrivateKey privateKey, SubjectPublicKeyInfo subjectPublicKeyInfo,
      KeystoreGenerationParameters params, X500Name subject, Validity validity)
      throws Exception {
    return generateCertificate(certType, signer, null, privateKey,
        subjectPublicKeyInfo, params, subject, validity);
  }

  private static KeyStoreAndCert generateCertificate(
      String certType, ContentSigner signer, X509Cert issuerCert,
      PrivateKey privateKey, SubjectPublicKeyInfo subjectPublicKeyInfo,
      KeystoreGenerationParameters params, X500Name subject, Validity validity)
      throws Exception {
    certType = certType.toUpperCase(Locale.ROOT);

    // 10 minutes past
    Instant notBefore = Instant.now().minus(10, ChronoUnit.MINUTES);
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
    X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(
        issuer, serialNumber, Date.from(notBefore),
        Date.from(notAfter), subject, subjectPublicKeyInfo);

    if (issuerCert != null) {
      certGenerator.addExtension(OIDs.Extn.authorityKeyIdentifier, false,
          new AuthorityKeyIdentifier(issuerCert.getSubjectKeyId()));
    }

    byte[] encodedSpki = subjectPublicKeyInfo.getPublicKeyData().getBytes();
    byte[] skiValue = HashAlgo.SHA1.hash(encodedSpki);
    certGenerator.addExtension(OIDs.Extn.subjectKeyIdentifier, false,
        new SubjectKeyIdentifier(skiValue));

    boolean isCA = "CA".equalsIgnoreCase(certType);
    BasicConstraints basicConstraints = isCA ? new BasicConstraints(0)
        : new BasicConstraints(false);
    certGenerator.addExtension(OIDs.Extn.basicConstraints,
        true, basicConstraints);

    KeyUsage keyUsage = isCA
        ? new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
        : new KeyUsage(KeyUsage.digitalSignature);
    certGenerator.addExtension(OIDs.Extn.keyUsage, true, keyUsage);

    if ("TLS-SERVER".equals(certType) ||
        "TLS-CLIENT".equals(certType) ||
        "TLS".equals(certType)) {
      List<KeyPurposeId> purposeIds = new LinkedList<>();
      if ("TLS-SERVER".equals(certType) || "TLS".equals(certType)) {
        purposeIds.add(KeyPurposeId.id_kp_serverAuth);
        String commonName = X509Util.getCommonName(subject);
        if (commonName == null) {
          throw new InvalidConfException(
              "common name of a TLS certificate must not be null");
        }

        GeneralName generalName;
        if (IPAddress.isValid(commonName)) {
          generalName = new GeneralName(GeneralName.iPAddress, commonName);
        } else {
          generalName = new GeneralName(GeneralName.dNSName, commonName);
        }
        certGenerator.addExtension(OIDs.Extn.subjectAlternativeName,
            false, new GeneralNames(new GeneralName[]{generalName}));
      }

      if ("TLS-CLIENT".equals(certType) || "TLS".equals(certType)) {
        purposeIds.add(KeyPurposeId.id_kp_clientAuth);
      }

      certGenerator.addExtension(OIDs.Extn.extendedKeyUsage, false,
          new ExtendedKeyUsage(purposeIds.toArray(new KeyPurposeId[0])));
    }

    KeyWithCert identity = new KeyWithCert(
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

  private static SecretKey generateSecretKey(String keyType) throws Exception {
    keyType = keyType.toUpperCase(Locale.ROOT);
    if (keyType.startsWith("AES")) {
      int keySize = Integer.parseUnsignedInt(keyType, "AES/".length(),
          keyType.length(), 10);
      if (keySize != 128 && keySize != 192 && keySize != 256) {
        throw new InvalidConfException("invalid keyType '" + keyType + "'");
      }

      byte[] keyValue = new byte[keySize / 8];
      random.nextBytes(keyValue);
      return new SecretKeySpec(keyValue, "AES");
    } else {
      throw new InvalidConfException("invalid keyType '" + keyType + "'");
    }
  }

  /**
   * @author Lijun Liao (xipki)
   */
  private static class KeyWithCert {

    private final X509Cert cert;

    private final PrivateKey key;

    public KeyWithCert(X509Cert cert, PrivateKey key) {
      this.key = key;
      this.cert = cert;
    }

    public X509Cert getCert() {
      return cert;
    }

    public PrivateKey getKey() {
      return key;
    }
  }
}
