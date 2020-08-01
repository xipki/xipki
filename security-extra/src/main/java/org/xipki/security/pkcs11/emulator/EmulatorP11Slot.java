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

package org.xipki.security.pkcs11.emulator;

import static org.xipki.util.Args.notBlank;
import static org.xipki.util.Args.notNull;
import static org.xipki.util.Args.positive;
import static org.xipki.util.IoUtil.read;
import static org.xipki.util.IoUtil.save;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.EdECConstants;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.pkcs11.P11Identity;
import org.xipki.security.pkcs11.P11IdentityId;
import org.xipki.security.pkcs11.P11ModuleConf.P11MechanismFilter;
import org.xipki.security.pkcs11.P11ModuleConf.P11NewObjectConf;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.security.pkcs11.P11TokenException;
import org.xipki.security.pkcs11.P11UnknownEntityException;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;

import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * {@link P11Slot} for PKCS#11 emulator.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class EmulatorP11Slot extends P11Slot {

  private static class InfoFilenameFilter implements FilenameFilter {

    @Override
    public boolean accept(File dir, String name) {
      return name.endsWith(INFO_FILE_SUFFIX);
    }

  } // class InfoFilenameFilter

  private static final Logger LOG = LoggerFactory.getLogger(EmulatorP11Slot.class);

  // slotinfo
  private static final String FILE_SLOTINFO = "slot.info";
  private static final String PROP_NAMED_CURVE_SUPPORTED = "namedCurveSupported";

  private static final String DIR_PRIV_KEY = "privkey";
  private static final String DIR_PUB_KEY = "pubkey";
  private static final String DIR_SEC_KEY = "seckey";
  private static final String DIR_CERT = "cert";

  private static final String INFO_FILE_SUFFIX = ".info";
  private static final String VALUE_FILE_SUFFIX = ".value";

  private static final String PROP_ID = "id";
  private static final String PROP_LABEL = "label";
  private static final String PROP_SHA1SUM = "sha1";

  private static final String PROP_ALGORITHM = "algorithm";

  // RSA
  private static final String PROP_RSA_MODUS = "modus";
  private static final String PROP_RSA_PUBLIC_EXPONENT = "publicExponent";

  // DSA
  private static final String PROP_DSA_PRIME = "prime"; // p
  private static final String PROP_DSA_SUBPRIME = "subprime"; // q
  private static final String PROP_DSA_BASE = "base"; // g
  private static final String PROP_DSA_VALUE = "value"; // y

  // EC
  private static final String PROP_EC_ECDSA_PARAMS = "ecdsaParams";
  private static final String PROP_EC_EC_POINT = "ecPoint";

  private static final long[] supportedMechs = new long[]{
    PKCS11Constants.CKM_DSA_KEY_PAIR_GEN,
    PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN,
    PKCS11Constants.CKM_EC_KEY_PAIR_GEN,
    PKCS11Constants.CKM_EC_EDWARDS_KEY_PAIR_GEN,
    PKCS11Constants.CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    PKCS11Constants.CKM_GENERIC_SECRET_KEY_GEN,

    // Digest
    PKCS11Constants.CKM_SHA_1,
    PKCS11Constants.CKM_SHA224,
    PKCS11Constants.CKM_SHA256,
    PKCS11Constants.CKM_SHA384,
    PKCS11Constants.CKM_SHA512,
    PKCS11Constants.CKM_SHA3_224,
    PKCS11Constants.CKM_SHA3_256,
    PKCS11Constants.CKM_SHA3_384,
    PKCS11Constants.CKM_SHA3_512,

    // HMAC
    PKCS11Constants.CKM_SHA_1_HMAC,
    PKCS11Constants.CKM_SHA224_HMAC,
    PKCS11Constants.CKM_SHA256_HMAC,
    PKCS11Constants.CKM_SHA384_HMAC,
    PKCS11Constants.CKM_SHA512_HMAC,
    PKCS11Constants.CKM_SHA3_224_HMAC,
    PKCS11Constants.CKM_SHA3_256_HMAC,
    PKCS11Constants.CKM_SHA3_384_HMAC,
    PKCS11Constants.CKM_SHA3_512_HMAC,

    PKCS11Constants.CKM_RSA_X_509,

    PKCS11Constants.CKM_RSA_PKCS,
    PKCS11Constants.CKM_SHA1_RSA_PKCS,
    PKCS11Constants.CKM_SHA224_RSA_PKCS,
    PKCS11Constants.CKM_SHA256_RSA_PKCS,
    PKCS11Constants.CKM_SHA384_RSA_PKCS,
    PKCS11Constants.CKM_SHA512_RSA_PKCS,
    PKCS11Constants.CKM_SHA3_224_RSA_PKCS,
    PKCS11Constants.CKM_SHA3_256_RSA_PKCS,
    PKCS11Constants.CKM_SHA3_384_RSA_PKCS,
    PKCS11Constants.CKM_SHA3_512_RSA_PKCS,

    PKCS11Constants.CKM_RSA_PKCS_PSS,
    PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS,
    PKCS11Constants.CKM_SHA224_RSA_PKCS_PSS,
    PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS,
    PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS,
    PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS,
    PKCS11Constants.CKM_SHA3_224_RSA_PKCS_PSS,
    PKCS11Constants.CKM_SHA3_256_RSA_PKCS_PSS,
    PKCS11Constants.CKM_SHA3_384_RSA_PKCS_PSS,
    PKCS11Constants.CKM_SHA3_512_RSA_PKCS_PSS,

    PKCS11Constants.CKM_DSA,
    PKCS11Constants.CKM_DSA_SHA1,
    PKCS11Constants.CKM_DSA_SHA224,
    PKCS11Constants.CKM_DSA_SHA256,
    PKCS11Constants.CKM_DSA_SHA384,
    PKCS11Constants.CKM_DSA_SHA512,
    PKCS11Constants.CKM_DSA_SHA3_224,
    PKCS11Constants.CKM_DSA_SHA3_256,
    PKCS11Constants.CKM_DSA_SHA3_384,
    PKCS11Constants.CKM_DSA_SHA3_512,

    PKCS11Constants.CKM_ECDSA,
    PKCS11Constants.CKM_ECDSA_SHA1,
    PKCS11Constants.CKM_ECDSA_SHA224,
    PKCS11Constants.CKM_ECDSA_SHA256,
    PKCS11Constants.CKM_ECDSA_SHA384,
    PKCS11Constants.CKM_ECDSA_SHA512,
    PKCS11Constants.CKM_ECDSA_SHA3_224,
    PKCS11Constants.CKM_ECDSA_SHA3_256,
    PKCS11Constants.CKM_ECDSA_SHA3_384,
    PKCS11Constants.CKM_ECDSA_SHA3_512,

    PKCS11Constants.CKM_EDDSA,

    // SM2
    PKCS11Constants.CKM_VENDOR_SM2_KEY_PAIR_GEN,
    PKCS11Constants.CKM_VENDOR_SM2_SM3,
    PKCS11Constants.CKM_VENDOR_SM2}; // method static

  private static final FilenameFilter INFO_FILENAME_FILTER = new InfoFilenameFilter();

  private final boolean namedCurveSupported;

  private final File slotDir;

  private final File privKeyDir;

  private final File pubKeyDir;

  private final File secKeyDir;

  private final File certDir;

  private final char[] password;

  private final PrivateKeyCryptor privateKeyCryptor;

  private final SecureRandom random = new SecureRandom();

  private final int maxSessions;

  private final P11NewObjectConf newObjectConf;

  EmulatorP11Slot(String moduleName, File slotDir, P11SlotIdentifier slotId, boolean readOnly,
      char[] password, PrivateKeyCryptor privateKeyCryptor, P11MechanismFilter mechanismFilter,
      P11NewObjectConf newObjectConf, int maxSessions) throws P11TokenException {
    super(moduleName, slotId, readOnly, mechanismFilter);

    this.newObjectConf = notNull(newObjectConf, "newObjectConf");
    this.slotDir = notNull(slotDir, "slotDir");
    this.password = notNull(password, "password");
    this.privateKeyCryptor = notNull(privateKeyCryptor, "privateKeyCryptor");
    this.maxSessions = positive(maxSessions, "maxSessions");

    this.privKeyDir = new File(slotDir, DIR_PRIV_KEY);
    if (!this.privKeyDir.exists()) {
      this.privKeyDir.mkdirs();
    }

    this.pubKeyDir = new File(slotDir, DIR_PUB_KEY);
    if (!this.pubKeyDir.exists()) {
      this.pubKeyDir.mkdirs();
    }

    this.secKeyDir = new File(slotDir, DIR_SEC_KEY);
    if (!this.secKeyDir.exists()) {
      this.secKeyDir.mkdirs();
    }

    this.certDir = new File(slotDir, DIR_CERT);
    if (!this.certDir.exists()) {
      this.certDir.mkdirs();
    }

    File slotInfoFile = new File(slotDir, FILE_SLOTINFO);
    if (slotInfoFile.exists()) {
      Properties props = loadProperties(slotInfoFile);
      this.namedCurveSupported = Boolean.parseBoolean(
          props.getProperty(PROP_NAMED_CURVE_SUPPORTED, "true"));
    } else {
      this.namedCurveSupported = true;
    }

    refresh();
  } // constructor

  @Override
  protected P11SlotRefreshResult refresh0() throws P11TokenException {
    P11SlotRefreshResult ret = new P11SlotRefreshResult();
    for (long mech : supportedMechs) {
      ret.addMechanism(mech);
    }

    // Secret Keys
    File[] secKeyInfoFiles = secKeyDir.listFiles(INFO_FILENAME_FILTER);

    if (secKeyInfoFiles != null && secKeyInfoFiles.length != 0) {
      for (File secKeyInfoFile : secKeyInfoFiles) {
        byte[] id = getKeyIdFromInfoFilename(secKeyInfoFile.getName());
        String hexId = hex(id);

        try {
          Properties props = loadProperties(secKeyInfoFile);
          String label = props.getProperty(PROP_LABEL);

          P11ObjectIdentifier p11ObjId = new P11ObjectIdentifier(id, label);
          byte[] encodedValue = read(new File(secKeyDir, hexId + VALUE_FILE_SUFFIX));

          KeyStore ks = KeyStore.getInstance("JCEKS");
          ks.load(new ByteArrayInputStream(encodedValue), password);
          SecretKey key = null;
          Enumeration<String> aliases = ks.aliases();
          while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) {
              key = (SecretKey) ks.getKey(alias, password);
              break;
            }
          }

          EmulatorP11Identity identity = new EmulatorP11Identity(this,
              new P11IdentityId(slotId, p11ObjId, null, null), key, maxSessions, random);
          LOG.info("added PKCS#11 secret key {}", p11ObjId);
          ret.addIdentity(identity);
        } catch (ClassCastException ex) {
          LogUtil.warn(LOG, ex,"InvalidKeyException while initializing key with key-id " + hexId);
          continue;
        } catch (Throwable th) {
          LOG.error("unexpected exception while initializing key with key-id " + hexId, th);
          continue;
        }
      }
    }

    // Certificates
    File[] certInfoFiles = certDir.listFiles(INFO_FILENAME_FILTER);
    if (certInfoFiles != null) {
      for (File infoFile : certInfoFiles) {
        byte[] id = getKeyIdFromInfoFilename(infoFile.getName());
        Properties props = loadProperties(infoFile);
        String label = props.getProperty(PROP_LABEL);
        P11ObjectIdentifier objId = new P11ObjectIdentifier(id, label);
        try {
          X509Cert cert = readCertificate(id);
          ret.addCertificate(objId, cert);
        } catch (CertificateException | IOException ex) {
          LOG.warn("could not parse certificate " + objId);
        }
      }
    }

    // Private / Public keys
    File[] privKeyInfoFiles = privKeyDir.listFiles(INFO_FILENAME_FILTER);

    if (privKeyInfoFiles != null && privKeyInfoFiles.length != 0) {
      for (File privKeyInfoFile : privKeyInfoFiles) {
        byte[] id = getKeyIdFromInfoFilename(privKeyInfoFile.getName());
        String hexId = hex(id);

        try {
          Properties props = loadProperties(privKeyInfoFile);
          String label = props.getProperty(PROP_LABEL);
          if (label == null) {
            continue;
          }

          P11ObjectIdentifier p11ObjId = new P11ObjectIdentifier(id, label);
          X509Cert cert = ret.getCertForId(id);
          java.security.PublicKey publicKey = (cert == null) ? readPublicKey(id)
              : cert.getPublicKey();

          if (publicKey == null) {
            LOG.warn("Neither public key nor certificate is associated with private key {}",
                p11ObjId);
            continue;
          }

          byte[] encodedValue = read(new File(privKeyDir, hexId + VALUE_FILE_SUFFIX));

          PKCS8EncryptedPrivateKeyInfo epki = new PKCS8EncryptedPrivateKeyInfo(encodedValue);
          PrivateKey privateKey = privateKeyCryptor.decrypt(epki);

          X509Cert[] certs = (cert == null) ? null : new X509Cert[]{cert};

          EmulatorP11Identity identity = new EmulatorP11Identity(this,
              new P11IdentityId(slotId, p11ObjId, label, label), privateKey, publicKey, certs,
                  maxSessions, random);
          LOG.info("added PKCS#11 key {}", p11ObjId);
          ret.addIdentity(identity);
        } catch (InvalidKeyException ex) {
          LogUtil.warn(LOG, ex,"InvalidKeyException while initializing key with key-id " + hexId);
          continue;
        } catch (Throwable th) {
          LOG.error("unexpected exception while initializing key with key-id " + hexId, th);
          continue;
        }
      }
    }

    return ret;
  } // method refresh0

  File slotDir() {
    return slotDir;
  }

  private PublicKey readPublicKey(byte[] keyId) throws P11TokenException {
    String hexKeyId = hex(keyId);
    File pubKeyFile = new File(pubKeyDir, hexKeyId + INFO_FILE_SUFFIX);
    Properties props = loadProperties(pubKeyFile);

    String algorithm = props.getProperty(PROP_ALGORITHM);
    if (PKCSObjectIdentifiers.rsaEncryption.getId().equals(algorithm)) {
      BigInteger exp = new BigInteger(1, decodeHex(props.getProperty(PROP_RSA_PUBLIC_EXPONENT)));
      BigInteger mod = new BigInteger(1, decodeHex(props.getProperty(PROP_RSA_MODUS)));

      RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
      try {
        return KeyUtil.generateRSAPublicKey(keySpec);
      } catch (InvalidKeySpecException ex) {
        throw new P11TokenException(ex.getMessage(), ex);
      }
    } else if (X9ObjectIdentifiers.id_dsa.getId().equals(algorithm)) {
      BigInteger prime = new BigInteger(1, decodeHex(props.getProperty(PROP_DSA_PRIME))); // p
      BigInteger subPrime = new BigInteger(1, decodeHex(props.getProperty(PROP_DSA_SUBPRIME))); // q
      BigInteger base = new BigInteger(1, decodeHex(props.getProperty(PROP_DSA_BASE))); // g
      BigInteger value = new BigInteger(1, decodeHex(props.getProperty(PROP_DSA_VALUE))); // y

      DSAPublicKeySpec keySpec = new DSAPublicKeySpec(value, prime, subPrime, base);
      try {
        return KeyUtil.generateDSAPublicKey(keySpec);
      } catch (InvalidKeySpecException ex) {
        throw new P11TokenException(ex.getMessage(), ex);
      }
    } else if (X9ObjectIdentifiers.id_ecPublicKey.getId().equals(algorithm)) {
      byte[] ecdsaParams = decodeHex(props.getProperty(PROP_EC_ECDSA_PARAMS));
      byte[] asn1EncodedPoint = decodeHex(props.getProperty(PROP_EC_EC_POINT));
      byte[] ecPoint = DEROctetString.getInstance(asn1EncodedPoint).getOctets();
      try {
        return KeyUtil.createECPublicKey(ecdsaParams, ecPoint);
      } catch (InvalidKeySpecException ex) {
        throw new P11TokenException(ex.getMessage(), ex);
      }
    } else if (EdECConstants.id_X25519.getId().equals(algorithm)
        || EdECConstants.id_ED25519.getId().equals(algorithm)
        || EdECConstants.id_X448.getId().equals(algorithm)
        || EdECConstants.id_ED448.getId().equals(algorithm)) {
      byte[] encodedPoint = decodeHex(props.getProperty(PROP_EC_EC_POINT));
      SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(
          new AlgorithmIdentifier(new ASN1ObjectIdentifier(algorithm)), encodedPoint);
      try {
        return KeyUtil.generatePublicKey(pkInfo);
      } catch (InvalidKeySpecException ex) {
        throw new P11TokenException("error  key algorithm " + algorithm);
      }
    } else {
      throw new P11TokenException("unknown key algorithm " + algorithm);
    }
  } // method readPublicKey

  private X509Cert readCertificate(byte[] keyId) throws CertificateException, IOException {
    byte[] encoded = read(new File(certDir, hex(keyId) + VALUE_FILE_SUFFIX));
    return X509Util.parseCert(encoded);
  }

  private Properties loadProperties(File file) throws P11TokenException {
    try {
      try (InputStream stream = Files.newInputStream(file.toPath())) {
        Properties props = new Properties();
        props.load(stream);
        return props;
      }
    } catch (IOException ex) {
      throw new P11TokenException("could not load properties from the file " + file.getPath(), ex);
    }
  }

  private static byte[] getKeyIdFromInfoFilename(String fileName) {
    return decodeHex(fileName.substring(0, fileName.length() - INFO_FILE_SUFFIX.length()));
  }

  @Override
  public void close() {
    LOG.info("close slot " + slotId);
  }

  private boolean removePkcs11Cert(P11ObjectIdentifier objectId) throws P11TokenException {
    return removePkcs11Entry(certDir, objectId);
  }

  private boolean removePkcs11Entry(File dir, P11ObjectIdentifier objectId)
      throws P11TokenException {
    byte[] id = objectId.getId();
    String label = objectId.getLabel();
    if (id != null) {
      String hextId = hex(id);
      File infoFile = new File(dir, hextId + INFO_FILE_SUFFIX);
      if (!infoFile.exists()) {
        return false;
      }

      if (StringUtil.isBlank(label)) {
        return deletePkcs11Entry(dir, id);
      } else {
        Properties props = loadProperties(infoFile);

        return label.equals(props.getProperty("label")) ? deletePkcs11Entry(dir, id) : false;
      }
    }

    // id is null, delete all entries with the specified label
    boolean deleted = false;
    File[] infoFiles = dir.listFiles(INFO_FILENAME_FILTER);
    if (infoFiles != null) {
      for (File infoFile : infoFiles) {
        if (!infoFile.isFile()) {
          continue;
        }

        Properties props = loadProperties(infoFile);
        if (label.equals(props.getProperty("label"))) {
          if (deletePkcs11Entry(dir, getKeyIdFromInfoFilename(infoFile.getName()))) {
            deleted = true;
          }
        }
      }
    }

    return deleted;
  } // method removePkcs11Entry

  private static boolean deletePkcs11Entry(File dir, byte[] objectId) {
    String hextId = hex(objectId);
    File infoFile = new File(dir, hextId + INFO_FILE_SUFFIX);
    boolean b1 = true;
    if (infoFile.exists()) {
      b1 = infoFile.delete();
    }

    File valueFile = new File(dir, hextId + VALUE_FILE_SUFFIX);
    boolean b2 = true;
    if (valueFile.exists()) {
      b2 = valueFile.delete();
    }

    return b1 || b2;
  } // method deletePkcs11Entry

  private int deletePkcs11Entry(File dir, byte[] id, String label) throws P11TokenException {
    if (StringUtil.isBlank(label)) {
      return deletePkcs11Entry(dir, id) ? 1 : 0;
    }

    if (id != null && id.length > 0) {
      String hextId = hex(id);
      File infoFile = new File(dir, hextId + INFO_FILE_SUFFIX);
      if (!infoFile.exists()) {
        return 0;
      }

      Properties props = loadProperties(infoFile);
      if (!label.equals(props.get(PROP_LABEL))) {
        return 0;
      }

      return deletePkcs11Entry(dir, id) ? 1 : 0;
    }

    File[] infoFiles = dir.listFiles(INFO_FILENAME_FILTER);
    if (infoFiles == null || infoFiles.length == 0) {
      return 0;
    }

    List<byte[]> ids = new LinkedList<>();

    for (File infoFile : infoFiles) {
      Properties props = loadProperties(infoFile);
      if (label.equals(props.getProperty(PROP_LABEL))) {
        ids.add(getKeyIdFromInfoFilename(infoFile.getName()));
      }
    }

    if (ids.isEmpty()) {
      return 0;
    }

    for (byte[] m : ids) {
      deletePkcs11Entry(dir, m);
    }
    return ids.size();
  } // method deletePkcs11Entry

  private String savePkcs11SecretKey(byte[] id, String label, SecretKey secretKey)
      throws P11TokenException {
    byte[] encrytedValue;
    try {
      KeyStore ks = KeyStore.getInstance("JCEKS");
      ks.load(null, password);
      ks.setKeyEntry("main", secretKey, password, null);
      ByteArrayOutputStream outStream = new ByteArrayOutputStream();
      ks.store(outStream, password);
      outStream.flush();
      encrytedValue = outStream.toByteArray();
    } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | IOException ex) {
      throw new P11TokenException(ex.getClass().getName() + ": " + ex.getMessage(), ex);
    }

    savePkcs11Entry(secKeyDir, id, label, encrytedValue);

    return label;
  } // method savePkcs11SecretKey

  private String savePkcs11PrivateKey(byte[] id, String label, PrivateKey privateKey)
      throws P11TokenException {
    PKCS8EncryptedPrivateKeyInfo encryptedPrivKeyInfo = privateKeyCryptor.encrypt(privateKey);
    byte[] encoded;
    try {
      encoded = encryptedPrivKeyInfo.getEncoded();
    } catch (IOException ex) {
      LogUtil.error(LOG, ex);
      throw new P11TokenException("could not encode PrivateKey");
    }

    savePkcs11Entry(privKeyDir, id, label, encoded);
    return label;
  } // method savePkcs11PrivateKey

  private String savePkcs11PublicKey(byte[] id, String label, PublicKey publicKey)
      throws P11TokenException {
    String hexId = hex(id);
    StringBuilder sb = new StringBuilder(100);
    sb.append(PROP_ID).append('=').append(hexId).append('\n');
    sb.append(PROP_LABEL).append('=').append(label).append('\n');

    if (publicKey instanceof RSAPublicKey) {
      sb.append(PROP_ALGORITHM).append('=')
        .append(PKCSObjectIdentifiers.rsaEncryption.getId()).append('\n');

      RSAPublicKey rsaKey = (RSAPublicKey) publicKey;
      sb.append(PROP_RSA_MODUS).append('=')
        .append(hex(rsaKey.getModulus().toByteArray())).append('\n');

      sb.append(PROP_RSA_PUBLIC_EXPONENT).append('=')
        .append(hex(rsaKey.getPublicExponent().toByteArray())).append('\n');
    } else if (publicKey instanceof DSAPublicKey) {
      sb.append(PROP_ALGORITHM).append('=')
        .append(X9ObjectIdentifiers.id_dsa.getId()).append('\n');

      DSAPublicKey dsaKey = (DSAPublicKey) publicKey;
      sb.append(PROP_DSA_PRIME).append('=')
        .append(hex(dsaKey.getParams().getP().toByteArray())).append('\n');

      sb.append(PROP_DSA_SUBPRIME).append('=')
        .append(hex(dsaKey.getParams().getQ().toByteArray())).append('\n');

      sb.append(PROP_DSA_BASE).append('=')
        .append(hex(dsaKey.getParams().getG().toByteArray())).append('\n');

      sb.append(PROP_DSA_VALUE).append('=')
        .append(hex(dsaKey.getY().toByteArray())).append('\n');
    } else if (publicKey instanceof ECPublicKey) {
      sb.append(PROP_ALGORITHM).append('=')
        .append(X9ObjectIdentifiers.id_ecPublicKey.getId()).append('\n');

      ECPublicKey ecKey = (ECPublicKey) publicKey;
      ECParameterSpec paramSpec = ecKey.getParams();

      // ecdsaParams
      org.bouncycastle.jce.spec.ECParameterSpec bcParamSpec = EC5Util.convertSpec(paramSpec);
      ASN1ObjectIdentifier curveOid = ECUtil.getNamedCurveOid(bcParamSpec);
      if (curveOid == null) {
        throw new P11TokenException("EC public key is not of namedCurve");
      }

      byte[] encodedParams;
      try {
        if (namedCurveSupported) {
          encodedParams = curveOid.getEncoded();
        } else {
          encodedParams = ECNamedCurveTable.getByOID(curveOid).getEncoded();
        }
      } catch (IOException | NullPointerException ex) {
        throw new P11TokenException(ex.getMessage(), ex);
      }

      sb.append(PROP_EC_ECDSA_PARAMS).append('=').append(hex(encodedParams)).append('\n');

      // EC point
      java.security.spec.ECPoint pointW = ecKey.getW();
      int keysize = (paramSpec.getOrder().bitLength() + 7) / 8;
      byte[] ecPoint = new byte[1 + keysize * 2];
      ecPoint[0] = 4; // uncompressed
      bigIntToBytes("Wx", pointW.getAffineX(), ecPoint, 1, keysize);
      bigIntToBytes("Wy", pointW.getAffineY(), ecPoint, 1 + keysize, keysize);

      byte[] encodedEcPoint;
      try {
        encodedEcPoint = new DEROctetString(ecPoint).getEncoded();
      } catch (IOException ex) {
        throw new P11TokenException("could not ASN.1 encode the ECPoint");
      }
      sb.append(PROP_EC_EC_POINT).append('=').append(hex(encodedEcPoint)).append('\n');
    } else if (publicKey instanceof EdDSAKey || publicKey instanceof XDHKey) {
      String algorithm = publicKey.getAlgorithm();
      ASN1ObjectIdentifier curveOid = EdECConstants.getCurveOid(algorithm);
      if (curveOid == null) {
        throw new P11TokenException("Invalid EdDSA key algorithm " + algorithm);
      }
      sb.append(PROP_ALGORITHM).append('=').append(curveOid.getId()).append('\n');

      byte[] encodedParams;
      try {
        encodedParams = curveOid.getEncoded();
      } catch (IOException | NullPointerException ex) {
        throw new P11TokenException(ex.getMessage(), ex);
      }

      sb.append(PROP_EC_ECDSA_PARAMS).append('=').append(hex(encodedParams)).append('\n');

      // EC point
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
      byte[] encodedEcPoint = spki.getPublicKeyData().getOctets();
      sb.append(PROP_EC_EC_POINT).append('=').append(hex(encodedEcPoint)).append('\n');
    } else {
      throw new IllegalArgumentException(
          "unsupported public key " + publicKey.getClass().getName());
    }

    try {
      save(new File(pubKeyDir, hexId + INFO_FILE_SUFFIX),
          StringUtil.toUtf8Bytes(sb.toString()));
    } catch (IOException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }

    return label;
  } // method savePkcs11PublicKey

  private static void bigIntToBytes(String numName, BigInteger num, byte[] dest, int destPos,
      int length) throws P11TokenException {
    if (num.signum() != 1) {
      throw new P11TokenException(numName + " is not positive");
    }
    byte[] bytes = num.toByteArray();
    if (bytes.length == length) {
      System.arraycopy(bytes, 0, dest, destPos, length);
    } else if (bytes.length < length) {
      System.arraycopy(bytes, 0, dest, destPos + length - bytes.length, bytes.length);
    } else {
      System.arraycopy(bytes, bytes.length - length, dest, destPos, length);
    }
  }

  private void savePkcs11Cert(byte[] id, String label, X509Cert cert)
      throws P11TokenException, CertificateException {
    savePkcs11Entry(certDir, id, label, cert.getEncoded());
  }

  private void savePkcs11Entry(File dir, byte[] id, String label, byte[] value)
      throws P11TokenException {
    notNull(dir, "dir");
    notNull(id, "id");
    notBlank(label, "label");
    notNull(value, "value");

    String hexId = hex(id);

    String str = StringUtil.concat(PROP_ID, "=", hexId, "\n", PROP_LABEL, "=", label, "\n",
        PROP_SHA1SUM, "=", HashAlgo.SHA1.hexHash(value), "\n");

    try {
      save(new File(dir, hexId + INFO_FILE_SUFFIX), StringUtil.toUtf8Bytes(str));
      save(new File(dir, hexId + VALUE_FILE_SUFFIX), value);
    } catch (IOException ex) {
      throw new P11TokenException("could not save certificate");
    }
  } // method savePkcs11Entry

  @Override
  public int removeObjects(byte[] id, String label) throws P11TokenException {
    if ((id == null || id.length == 0) && StringUtil.isBlank(label)) {
      throw new IllegalArgumentException("at least one of id and label may not be null");
    }

    int num = deletePkcs11Entry(privKeyDir, id, label);
    num += deletePkcs11Entry(pubKeyDir, id, label);
    num += deletePkcs11Entry(certDir, id, label);
    num += deletePkcs11Entry(secKeyDir, id, label);
    return num;
  } // method removeObjects

  @Override
  protected void removeIdentity0(P11IdentityId identityId) throws P11TokenException {
    P11ObjectIdentifier keyId = identityId.getKeyId();

    boolean b1 = true;
    if (identityId.getCertId() != null) {
      removePkcs11Entry(certDir, identityId.getCertId());
    }

    boolean b2 = removePkcs11Entry(privKeyDir, keyId);

    boolean b3 = true;
    if (identityId.getPublicKeyId() != null) {
      b3 = removePkcs11Entry(pubKeyDir, identityId.getPublicKeyId());
    }

    boolean b4 = removePkcs11Entry(secKeyDir, keyId);
    if (! (b1 || b2 || b3 || b4)) {
      throw new P11UnknownEntityException(slotId, keyId);
    }
  } // method removeIdentity0

  @Override
  protected void removeCerts0(P11ObjectIdentifier objectId) throws P11TokenException {
    deletePkcs11Entry(certDir, objectId.getId());
  }

  @Override
  protected P11ObjectIdentifier addCert0(X509Cert cert, P11NewObjectControl control)
      throws P11TokenException, CertificateException {
    byte[] id = control.getId();
    if (id == null) {
      id = generateId();
    }

    String label = control.getLabel();

    savePkcs11Cert(id, label, cert);
    return new P11ObjectIdentifier(id, label);
  } // method addCert0

  @Override
  protected P11Identity generateSecretKey0(long keyType, int keysize,
      P11NewKeyControl control) throws P11TokenException {
    if (keysize % 8 != 0) {
      throw new IllegalArgumentException("keysize is not multiple of 8: " + keysize);
    }

    long mech;
    if (PKCS11Constants.CKK_AES == keyType) {
      mech = PKCS11Constants.CKM_AES_KEY_GEN;
    } else if (PKCS11Constants.CKK_DES3 == keyType) {
      mech = PKCS11Constants.CKM_DES3_KEY_GEN;
    } else if (PKCS11Constants.CKK_GENERIC_SECRET == keyType) {
      mech = PKCS11Constants.CKM_GENERIC_SECRET_KEY_GEN;
    } else if (PKCS11Constants.CKK_SHA_1_HMAC == keyType
        || PKCS11Constants.CKK_SHA224_HMAC == keyType
        || PKCS11Constants.CKK_SHA256_HMAC == keyType
        || PKCS11Constants.CKK_SHA384_HMAC == keyType
        || PKCS11Constants.CKK_SHA512_HMAC == keyType
        || PKCS11Constants.CKK_SHA3_224_HMAC == keyType
        || PKCS11Constants.CKK_SHA3_256_HMAC == keyType
        || PKCS11Constants.CKK_SHA3_384_HMAC == keyType
        || PKCS11Constants.CKK_SHA3_512_HMAC == keyType) {
      mech = PKCS11Constants.CKM_GENERIC_SECRET_KEY_GEN;
    } else {
      throw new IllegalArgumentException(
          "unsupported key type 0x" + Functions.toFullHex((int)keyType));
    }
    assertMechanismSupported(mech);

    byte[] keyBytes = new byte[keysize / 8];
    random.nextBytes(keyBytes);
    SecretKey key = new SecretKeySpec(keyBytes, getSecretKeyAlgorithm(keyType));
    return saveP11Entity(key, control);
  } // method generateSecretKey0

  @Override
  protected P11Identity importSecretKey0(long keyType, byte[] keyValue,
      P11NewKeyControl control) throws P11TokenException {
    SecretKey key = new SecretKeySpec(keyValue, getSecretKeyAlgorithm(keyType));
    return saveP11Entity(key, control);
  }

  private static String getSecretKeyAlgorithm(long keyType) {
    String algorithm;
    if (PKCS11Constants.CKK_GENERIC_SECRET == keyType) {
      algorithm = "generic";
    } else if (PKCS11Constants.CKK_AES == keyType) {
      algorithm = "AES";
    } else if (PKCS11Constants.CKK_SHA_1_HMAC == keyType) {
      algorithm = "HMACSHA1";
    } else if (PKCS11Constants.CKK_SHA224_HMAC == keyType) {
      algorithm = "HMACSHA224";
    } else if (PKCS11Constants.CKK_SHA256_HMAC == keyType) {
      algorithm = "HMACSHA256";
    } else if (PKCS11Constants.CKK_SHA384_HMAC == keyType) {
      algorithm = "HMACSHA384";
    } else if (PKCS11Constants.CKK_SHA512_HMAC == keyType) {
      algorithm = "HMACSHA512";
    } else if (PKCS11Constants.CKK_SHA3_224_HMAC == keyType) {
      algorithm = "HMACSHA3-224";
    } else if (PKCS11Constants.CKK_SHA3_256_HMAC == keyType) {
      algorithm = "HMACSHA3-256";
    } else if (PKCS11Constants.CKK_SHA3_384_HMAC == keyType) {
      algorithm = "HMACSHA3-384";
    } else if (PKCS11Constants.CKK_SHA3_512_HMAC == keyType) {
      algorithm = "HMACSHA3-512";
    } else {
      throw new IllegalArgumentException("unsupported keyType " + keyType);
    }
    return algorithm;
  } // method getSecretKeyAlgorithm

  @Override
  protected P11Identity generateRSAKeypair0(int keysize, BigInteger publicExponent,
      P11NewKeyControl control) throws P11TokenException {
    assertMechanismSupported(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);

    KeyPair keypair;
    try {
      keypair = KeyUtil.generateRSAKeypair(keysize, publicExponent, random);
    } catch (NoSuchAlgorithmException | NoSuchProviderException
        | InvalidAlgorithmParameterException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    return saveP11Entity(keypair, control);
  } // method generateRSAKeypair0

  @Override
  // CHECKSTYLE:SKIP
  protected P11Identity generateDSAKeypair0(BigInteger p, BigInteger q, BigInteger g,
      P11NewKeyControl control) throws P11TokenException {
    assertMechanismSupported(PKCS11Constants.CKM_DSA_KEY_PAIR_GEN);
    DSAParameters dsaParams = new DSAParameters(p, q, g);
    KeyPair keypair;
    try {
      keypair = KeyUtil.generateDSAKeypair(dsaParams, random);
    } catch (NoSuchAlgorithmException | NoSuchProviderException
        | InvalidAlgorithmParameterException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    return saveP11Entity(keypair, control);
  } // method generateDSAKeypair0

  @Override
  protected P11Identity generateSM2Keypair0(P11NewKeyControl control)
      throws P11TokenException {
    assertMechanismSupported(PKCS11Constants.CKM_VENDOR_SM2_KEY_PAIR_GEN);
    return generateECKeypair0(GMObjectIdentifiers.sm2p256v1, control);
  }

  @Override
  protected P11Identity generateECEdwardsKeypair0(ASN1ObjectIdentifier curveOid,
      P11NewKeyControl control) throws P11TokenException {
    assertMechanismSupported(PKCS11Constants.CKM_EC_EDWARDS_KEY_PAIR_GEN);

    KeyPair keypair;
    try {
      if (!EdECConstants.isEdwardsCurve(curveOid)) {
        throw new P11TokenException("unknown curve  " + curveOid.getId());
      }

      keypair = KeyUtil.generateEdECKeypair(curveOid, random);
    } catch (NoSuchAlgorithmException | NoSuchProviderException
        | InvalidAlgorithmParameterException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    return saveP11Entity(keypair, control);
  } // method generateECEdwardsKeypair0

  @Override
  protected P11Identity generateECMontgomeryKeypair0(ASN1ObjectIdentifier curveOid,
      P11NewKeyControl control) throws P11TokenException {
    assertMechanismSupported(PKCS11Constants.CKM_EC_MONTGOMERY_KEY_PAIR_GEN);

    KeyPair keypair;
    try {
      if (!EdECConstants.isMontgomeryCurve(curveOid)) {
        throw new P11TokenException("unknown curve  " + curveOid.getId());
      }

      keypair = KeyUtil.generateEdECKeypair(curveOid, random);
    } catch (NoSuchAlgorithmException | NoSuchProviderException
        | InvalidAlgorithmParameterException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    return saveP11Entity(keypair, control);
  } // method generateECMontgomeryKeypair0

  @Override
  protected P11Identity generateECKeypair0(ASN1ObjectIdentifier curveId,
      P11NewKeyControl control) throws P11TokenException {
    assertMechanismSupported(PKCS11Constants.CKM_EC_KEY_PAIR_GEN);
    KeyPair keypair;
    try {
      keypair = KeyUtil.generateECKeypair(curveId, random);
    } catch (NoSuchAlgorithmException | NoSuchProviderException
        | InvalidAlgorithmParameterException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    return saveP11Entity(keypair, control);
  } // method generateECKeypair0

  private P11Identity saveP11Entity(KeyPair keypair, P11NewObjectControl control)
      throws P11TokenException {
    byte[] id = control.getId();
    if (id == null) {
      id = generateId();
    }

    String label = control.getLabel();

    String keyLabel = savePkcs11PrivateKey(id, label, keypair.getPrivate());
    String pubKeyLabel = savePkcs11PublicKey(id, label, keypair.getPublic());
    String certLabel = null;
    X509Cert[] certs = null;
    P11IdentityId identityId = new P11IdentityId(slotId,
        new P11ObjectIdentifier(id, keyLabel), pubKeyLabel, certLabel);
    try {
      return new EmulatorP11Identity(this,identityId, keypair.getPrivate(),
          keypair.getPublic(), certs, maxSessions, random);
    } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException ex) {
      throw new P11TokenException(
          "could not construct KeyStoreP11Identity: " + ex.getMessage(), ex);
    }
  } // method saveP11Entity

  private P11Identity saveP11Entity(SecretKey key, P11NewObjectControl control)
      throws P11TokenException {
    byte[] id = control.getId();
    if (id == null) {
      id = generateId();
    }
    String label = control.getLabel();

    savePkcs11SecretKey(id, label, key);
    P11IdentityId identityId = new P11IdentityId(slotId,
        new P11ObjectIdentifier(id, label), null, null);
    return new EmulatorP11Identity(this,identityId, key, maxSessions, random);
  } // method saveP11Entity

  @Override
  protected void updateCertificate0(P11ObjectIdentifier keyId, X509Cert newCert)
      throws P11TokenException, CertificateException {
    removePkcs11Cert(keyId);
    savePkcs11Cert(keyId.getId(), keyId.getLabel(), newCert);
  } // method updateCertificate0

  private byte[] generateId() throws P11TokenException {
    while (true) {
      byte[] id = new byte[newObjectConf.getIdLength()];
      random.nextBytes(id);

      boolean duplicated = existsIdentityForId(id) || existsCertForId(id);
      if (!duplicated) {
        return id;
      }
    }
  } // method generateId

}
