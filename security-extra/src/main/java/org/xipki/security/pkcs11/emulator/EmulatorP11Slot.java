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

import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.EdECConstants;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.pkcs11.*;
import org.xipki.security.pkcs11.P11ModuleConf.P11MechanismFilter;
import org.xipki.security.pkcs11.P11ModuleConf.P11NewObjectConf;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.*;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

import static org.xipki.util.Args.*;
import static org.xipki.util.IoUtil.read;
import static org.xipki.util.IoUtil.save;
import static iaik.pkcs.pkcs11.wrapper.PKCS11Constants.*;

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
  private static final String PROP_ALGO = "algo";

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
    CKM_DSA_KEY_PAIR_GEN,        CKM_RSA_PKCS_KEY_PAIR_GEN,      CKM_EC_KEY_PAIR_GEN,
    CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EC_MONTGOMERY_KEY_PAIR_GEN, CKM_GENERIC_SECRET_KEY_GEN,

    // Digest
    CKM_SHA_1, CKM_SHA224, CKM_SHA256, CKM_SHA384, CKM_SHA512, CKM_SHA3_224, CKM_SHA3_256, CKM_SHA3_384, CKM_SHA3_512,

    // HMAC
    CKM_SHA_1_HMAC,    CKM_SHA224_HMAC,   CKM_SHA256_HMAC,   CKM_SHA384_HMAC,   CKM_SHA512_HMAC,
    CKM_SHA3_224_HMAC, CKM_SHA3_256_HMAC, CKM_SHA3_384_HMAC, CKM_SHA3_512_HMAC,

    // RSA
    CKM_RSA_X_509,
    CKM_RSA_PKCS,        CKM_SHA1_RSA_PKCS,     CKM_SHA224_RSA_PKCS,   CKM_SHA256_RSA_PKCS,   CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS, CKM_SHA3_224_RSA_PKCS, CKM_SHA3_256_RSA_PKCS, CKM_SHA3_384_RSA_PKCS, CKM_SHA3_512_RSA_PKCS,

    CKM_RSA_PKCS_PSS,          CKM_SHA1_RSA_PKCS_PSS,   CKM_SHA224_RSA_PKCS_PSS,   CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384_RSA_PKCS_PSS,   CKM_SHA512_RSA_PKCS_PSS, CKM_SHA3_224_RSA_PKCS_PSS, CKM_SHA3_256_RSA_PKCS_PSS,
    CKM_SHA3_384_RSA_PKCS_PSS, CKM_SHA3_512_RSA_PKCS_PSS,

    CKM_DSA,        CKM_DSA_SHA1,     CKM_DSA_SHA224,   CKM_DSA_SHA256,   CKM_DSA_SHA384,
    CKM_DSA_SHA512, CKM_DSA_SHA3_224, CKM_DSA_SHA3_256, CKM_DSA_SHA3_384, CKM_DSA_SHA3_512,

    CKM_ECDSA,        CKM_ECDSA_SHA1,     CKM_ECDSA_SHA224,   CKM_ECDSA_SHA256,   CKM_ECDSA_SHA384,
    CKM_ECDSA_SHA512, CKM_ECDSA_SHA3_224, CKM_ECDSA_SHA3_256, CKM_ECDSA_SHA3_384, CKM_ECDSA_SHA3_512,

    CKM_EDDSA,

    // SM2
    CKM_VENDOR_SM2_KEY_PAIR_GEN, CKM_VENDOR_SM2_SM3, CKM_VENDOR_SM2}; // method static

  private static final FilenameFilter INFO_FILENAME_FILTER = new InfoFilenameFilter();

  private final boolean namedCurveSupported;

  private final File slotDir;

  private final File privKeyDir;

  private final File pubKeyDir;

  private final File secKeyDir;

  private final File certDir;

  private final KeyCryptor keyCryptor;

  private final SecureRandom random = new SecureRandom();

  private final int maxSessions;

  private final P11NewObjectConf newObjectConf;

  EmulatorP11Slot(
      String moduleName, File slotDir, P11SlotIdentifier slotId, boolean readOnly,
      KeyCryptor keyCryptor, P11MechanismFilter mechanismFilter, P11NewObjectConf newObjectConf,
      Integer numSessions, List<Long> secretKeyTypes, List<Long> keypairTypes)
      throws P11TokenException {
    super(moduleName, slotId, readOnly, mechanismFilter, numSessions, secretKeyTypes, keypairTypes);

    this.newObjectConf = notNull(newObjectConf, "newObjectConf");
    this.slotDir = notNull(slotDir, "slotDir");
    this.keyCryptor = notNull(keyCryptor, "privateKeyCryptor");

    if (numSessions != null) {
      this.maxSessions = positive(numSessions, "numSessions");
    } else {
      this.maxSessions = 20;
    }

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
      this.namedCurveSupported = Boolean.parseBoolean(props.getProperty(PROP_NAMED_CURVE_SUPPORTED, "true"));
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
          String keyAlgo = props.getProperty(PROP_ALGO);
          P11ObjectIdentifier p11ObjId = new P11ObjectIdentifier(id, label);
          byte[] encodedValue = read(new File(secKeyDir, hexId + VALUE_FILE_SUFFIX));

          byte[] keyValue = keyCryptor.decrypt(encodedValue);
          SecretKey key = new SecretKeySpec(keyValue, keyAlgo);
          EmulatorP11Identity identity = new EmulatorP11Identity(this,
              new P11IdentityId(slotId, p11ObjId, null, null), key, maxSessions, random);
          LOG.info("added PKCS#11 secret key {}", p11ObjId);
          ret.addIdentity(identity);
        } catch (ClassCastException ex) {
          LogUtil.warn(LOG, ex,"InvalidKeyException while initializing key with key-id " + hexId);
        } catch (Throwable th) {
          LOG.error("unexpected exception while initializing key with key-id " + hexId, th);
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
          java.security.PublicKey publicKey = (cert == null) ? readPublicKey(id) : cert.getPublicKey();

          if (publicKey == null) {
            LOG.warn("Neither public key nor certificate is associated with private key {}", p11ObjId);
            continue;
          }

          byte[] encodedValue = read(new File(privKeyDir, hexId + VALUE_FILE_SUFFIX));
          PrivateKey privateKey = keyCryptor.decryptPrivateKey(encodedValue);

          X509Cert[] certs = (cert == null) ? null : new X509Cert[]{cert};

          EmulatorP11Identity identity = new EmulatorP11Identity(this,
              new P11IdentityId(slotId, p11ObjId, label, label), privateKey, publicKey, certs, maxSessions, random);
          LOG.info("added PKCS#11 key {}", p11ObjId);
          ret.addIdentity(identity);
        } catch (InvalidKeyException ex) {
          LogUtil.warn(LOG, ex,"InvalidKeyException while initializing key with key-id " + hexId);
        } catch (Throwable th) {
          LOG.error("unexpected exception while initializing key with key-id " + hexId, th);
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
      BigInteger exp = new BigInteger(props.getProperty(PROP_RSA_PUBLIC_EXPONENT), 16);
      BigInteger mod = new BigInteger(props.getProperty(PROP_RSA_MODUS), 16);

      RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
      try {
        return KeyUtil.generateRSAPublicKey(keySpec);
      } catch (InvalidKeySpecException ex) {
        throw new P11TokenException(ex.getMessage(), ex);
      }
    } else if (X9ObjectIdentifiers.id_dsa.getId().equals(algorithm)) {
      BigInteger prime = new BigInteger(props.getProperty(PROP_DSA_PRIME), 16); // p
      BigInteger subPrime = new BigInteger(props.getProperty(PROP_DSA_SUBPRIME), 16); // q
      BigInteger base = new BigInteger(props.getProperty(PROP_DSA_BASE), 16); // g
      BigInteger value = new BigInteger(props.getProperty(PROP_DSA_VALUE), 16); // y

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
    } else if (EdECConstants.id_X25519.getId().equals(algorithm) || EdECConstants.id_ED25519.getId().equals(algorithm)
        || EdECConstants.id_X448.getId().equals(algorithm)       || EdECConstants.id_ED448.getId().equals(algorithm)) {
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

  private boolean removePkcs11Entry(File dir, P11ObjectIdentifier objectId) throws P11TokenException {
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

        return label.equals(props.getProperty("label")) && deletePkcs11Entry(dir, id);
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
    byte[] encrytedValue = keyCryptor.encrypt(secretKey);
    savePkcs11Entry(secKeyDir, id, label, secretKey.getAlgorithm(), encrytedValue);
    return label;
  } // method savePkcs11SecretKey

  private String savePkcs11PrivateKey(byte[] id, String label, PrivateKey privateKey)
      throws P11TokenException {
    byte[] encryptedPrivKeyInfo = keyCryptor.encrypt(privateKey);
    savePkcs11Entry(privKeyDir, id, label, privateKey.getAlgorithm(), encryptedPrivKeyInfo);
    return label;
  } // method savePkcs11PrivateKey

  private String savePkcs11PublicKey(byte[] id, String label, PublicKey publicKey)
      throws P11TokenException {
    String hexId = hex(id);
    StringBuilder sb = new StringBuilder(100);
    sb.append(PROP_ID).append('=').append(hexId).append('\n');
    sb.append(PROP_LABEL).append('=').append(label).append('\n');

    if (publicKey instanceof RSAPublicKey) {
      sb.append(PROP_ALGORITHM).append('=').append(PKCSObjectIdentifiers.rsaEncryption.getId()).append('\n');

      RSAPublicKey rsaKey = (RSAPublicKey) publicKey;
      sb.append(PROP_RSA_MODUS).append('=').append(hex(rsaKey.getModulus().toByteArray())).append('\n');

      sb.append(PROP_RSA_PUBLIC_EXPONENT).append('=')
          .append(hex(rsaKey.getPublicExponent().toByteArray())).append('\n');
    } else if (publicKey instanceof DSAPublicKey) {
      sb.append(PROP_ALGORITHM).append('=').append(X9ObjectIdentifiers.id_dsa.getId()).append('\n');

      DSAPublicKey dsaKey = (DSAPublicKey) publicKey;
      sb.append(PROP_DSA_PRIME).append('=').append(hex(dsaKey.getParams().getP().toByteArray())).append('\n');

      sb.append(PROP_DSA_SUBPRIME).append('=').append(hex(dsaKey.getParams().getQ().toByteArray())).append('\n');

      sb.append(PROP_DSA_BASE).append('=').append(hex(dsaKey.getParams().getG().toByteArray())).append('\n');

      sb.append(PROP_DSA_VALUE).append('=').append(hex(dsaKey.getY().toByteArray())).append('\n');
    } else if (publicKey instanceof ECPublicKey) {
      sb.append(PROP_ALGORITHM).append('=').append(X9ObjectIdentifiers.id_ecPublicKey.getId()).append('\n');

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
      throw new IllegalArgumentException("unsupported public key " + publicKey.getClass().getName());
    }

    try {
      save(new File(pubKeyDir, hexId + INFO_FILE_SUFFIX), StringUtil.toUtf8Bytes(sb.toString()));
    } catch (IOException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }

    return label;
  } // method savePkcs11PublicKey

  private static void bigIntToBytes(String numName, BigInteger num, byte[] dest, int destPos, int length)
      throws P11TokenException {
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

  private void savePkcs11Cert(byte[] id, String label, X509Cert cert) throws P11TokenException {
    savePkcs11Entry(certDir, id, label, null, cert.getEncoded());
  }

  private void savePkcs11Entry(File dir, byte[] id, String label, String algo, byte[] value)
      throws P11TokenException {
    notNull(dir, "dir");
    notNull(id, "id");
    notBlank(label, "label");
    notNull(value, "value");

    String hexId = hex(id);

    String str = StringUtil.concat(PROP_ID, "=", hexId, "\n", PROP_LABEL, "=", label, "\n");
    if (algo != null) {
      str = StringUtil.concat(str, PROP_ALGO, "=", algo, "\n");
    }

    str = StringUtil.concat(str, PROP_SHA1SUM, "=", HashAlgo.SHA1.hexHash(value), "\n");

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
      b1 = removePkcs11Entry(certDir, identityId.getCertId());
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
  protected P11Identity generateSecretKey0(long keyType, int keysize, P11NewKeyControl control)
      throws P11TokenException {
    if (keysize % 8 != 0) {
      throw new IllegalArgumentException("keysize is not multiple of 8: " + keysize);
    }

    long mech;
    if (CKK_AES == keyType) {
      mech = CKM_AES_KEY_GEN;
    } else if (CKK_DES3 == keyType) {
      mech = CKM_DES3_KEY_GEN;
    } else if (CKK_GENERIC_SECRET == keyType) {
      mech = CKM_GENERIC_SECRET_KEY_GEN;
    } else if (CKK_SHA_1_HMAC == keyType || CKK_SHA224_HMAC   == keyType || CKK_SHA256_HMAC   == keyType
        || CKK_SHA384_HMAC    == keyType || CKK_SHA512_HMAC   == keyType || CKK_SHA3_224_HMAC == keyType
        || CKK_SHA3_256_HMAC  == keyType || CKK_SHA3_384_HMAC == keyType || CKK_SHA3_512_HMAC == keyType) {
      mech = CKM_GENERIC_SECRET_KEY_GEN;
    } else {
      throw new IllegalArgumentException("unsupported key type 0x" + Functions.toFullHex((int)keyType));
    }
    assertMechanismSupported(mech);

    byte[] keyBytes = new byte[keysize / 8];
    random.nextBytes(keyBytes);
    SecretKey key = new SecretKeySpec(keyBytes, getSecretKeyAlgorithm(keyType));
    return saveP11Entity(key, control);
  } // method generateSecretKey0

  @Override
  protected P11Identity importSecretKey0(long keyType, byte[] keyValue, P11NewKeyControl control)
      throws P11TokenException {
    SecretKey key = new SecretKeySpec(keyValue, getSecretKeyAlgorithm(keyType));
    return saveP11Entity(key, control);
  }

  private static String getSecretKeyAlgorithm(long keyType) {
    String algorithm;
    if (CKK_GENERIC_SECRET == keyType) {
      algorithm = "generic";
    } else if (CKK_AES == keyType) {
      algorithm = "AES";
    } else if (CKK_SHA_1_HMAC == keyType) {
      algorithm = "HMACSHA1";
    } else if (CKK_SHA224_HMAC == keyType) {
      algorithm = "HMACSHA224";
    } else if (CKK_SHA256_HMAC == keyType) {
      algorithm = "HMACSHA256";
    } else if (CKK_SHA384_HMAC == keyType) {
      algorithm = "HMACSHA384";
    } else if (CKK_SHA512_HMAC == keyType) {
      algorithm = "HMACSHA512";
    } else if (CKK_SHA3_224_HMAC == keyType) {
      algorithm = "HMACSHA3-224";
    } else if (CKK_SHA3_256_HMAC == keyType) {
      algorithm = "HMACSHA3-256";
    } else if (CKK_SHA3_384_HMAC == keyType) {
      algorithm = "HMACSHA3-384";
    } else if (CKK_SHA3_512_HMAC == keyType) {
      algorithm = "HMACSHA3-512";
    } else {
      throw new IllegalArgumentException("unsupported keyType " + keyType);
    }
    return algorithm;
  } // method getSecretKeyAlgorithm

  @Override
  protected P11Identity generateRSAKeypair0(int keysize, BigInteger publicExponent, P11NewKeyControl control)
      throws P11TokenException {
    KeyPair keypair;
    try {
      keypair = KeyUtil.generateRSAKeypair(keysize, publicExponent, random);
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    return saveP11Entity(keypair, control);
  } // method generateRSAKeypair0

  @Override
  protected PrivateKeyInfo generateRSAKeypairOtf0(int keysize, BigInteger publicExponent)
      throws P11TokenException {
    try {
      KeyPair kp = KeyUtil.generateRSAKeypair(keysize, publicExponent, random);
      return KeyUtil.toPrivateKeyInfo((RSAPrivateCrtKey) kp.getPrivate());
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | IOException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
  }

  @Override
  protected P11Identity generateDSAKeypair0(BigInteger p, BigInteger q, BigInteger g, P11NewKeyControl control)
      throws P11TokenException {
    DSAParameters dsaParams = new DSAParameters(p, q, g);
    KeyPair keypair;
    try {
      keypair = KeyUtil.generateDSAKeypair(dsaParams, random);
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    return saveP11Entity(keypair, control);
  } // method generateDSAKeypair0

  @Override
  protected PrivateKeyInfo generateDSAKeypairOtf0(BigInteger p, BigInteger q, BigInteger g)
      throws P11TokenException {
    DSAParameters spec = new DSAParameters(p, q, g);
    try {
      KeyPair kp = KeyUtil.generateDSAKeypair(spec, random);
      DSAParameter parameter = new DSAParameter(spec.getP(), spec.getQ(), spec.getG());
      AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, parameter);

      byte[] publicKey = new ASN1Integer(((DSAPublicKey) kp.getPublic()).getY()).getEncoded();

      // DSA private keys are represented as BER-encoded ASN.1 type INTEGER.
      DSAPrivateKey priv = (DSAPrivateKey) kp.getPrivate();
      return new PrivateKeyInfo(algId, new ASN1Integer(priv.getX()), null, publicKey);
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | IOException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
  }

  @Override
  protected P11Identity generateSM2Keypair0(P11NewKeyControl control) throws P11TokenException {
    return generateECKeypair0(GMObjectIdentifiers.sm2p256v1, control);
  }

  @Override
  protected PrivateKeyInfo generateSM2KeypairOtf0() throws P11TokenException {
    return generateECKeypairOtf0(GMObjectIdentifiers.sm2p256v1);
  }

  @Override
  protected P11Identity generateECEdwardsKeypair0(ASN1ObjectIdentifier curveOid, P11NewKeyControl control)
      throws P11TokenException {
    KeyPair keypair;
    try {
      if (!EdECConstants.isEdwardsCurve(curveOid)) {
        throw new P11TokenException("unknown curve  " + curveOid.getId());
      }

      keypair = KeyUtil.generateEdECKeypair(curveOid, random);
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    return saveP11Entity(keypair, control);
  } // method generateECEdwardsKeypair0

  @Override
  protected PrivateKeyInfo generateECEdwardsKeypairOtf0(ASN1ObjectIdentifier curveId)
      throws P11TokenException {
    try {
      KeyPair kp = KeyUtil.generateEdECKeypair(curveId, random);
      return PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
  }

  @Override
  protected P11Identity generateECMontgomeryKeypair0(ASN1ObjectIdentifier curveOid, P11NewKeyControl control)
      throws P11TokenException {
    KeyPair keypair;
    try {
      if (!EdECConstants.isMontgomeryCurve(curveOid)) {
        throw new P11TokenException("unknown curve  " + curveOid.getId());
      }

      keypair = KeyUtil.generateEdECKeypair(curveOid, random);
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    return saveP11Entity(keypair, control);
  } // method generateECMontgomeryKeypair0

  @Override
  protected PrivateKeyInfo generateECMontgomeryKeypairOtf0(ASN1ObjectIdentifier curveId)
      throws P11TokenException {
    try {
      KeyPair kp = KeyUtil.generateEdECKeypair(curveId, random);
      return PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
  }

  @Override
  protected P11Identity generateECKeypair0(ASN1ObjectIdentifier curveId, P11NewKeyControl control)
      throws P11TokenException {
    KeyPair keypair;
    try {
      keypair = KeyUtil.generateECKeypair(curveId, random);
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
    return saveP11Entity(keypair, control);
  } // method generateECKeypair0

  @Override
  protected PrivateKeyInfo generateECKeypairOtf0(ASN1ObjectIdentifier curveId) throws P11TokenException {
    try {
      AlgorithmIdentifier keyAlgId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curveId);

      KeyPair kp = KeyUtil.generateECKeypair(curveId, random);
      ECPublicKey pub = (ECPublicKey) kp.getPublic();
      int orderBitLength = pub.getParams().getOrder().bitLength();

      byte[] publicKey = KeyUtil.getUncompressedEncodedECPoint(pub.getW(), orderBitLength);

      ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();
      return new PrivateKeyInfo(keyAlgId,
          new org.bouncycastle.asn1.sec.ECPrivateKey(
              orderBitLength, priv.getS(), new DERBitString(publicKey), null));
    } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException ex) {
      throw new P11TokenException(ex.getMessage(), ex);
    }
  }

  private P11Identity saveP11Entity(KeyPair keypair, P11NewObjectControl control) throws P11TokenException {
    byte[] id = control.getId();
    if (id == null) {
      id = generateId();
    }

    String label = control.getLabel();

    long t1 = System.currentTimeMillis();

    String keyLabel = savePkcs11PrivateKey(id, label, keypair.getPrivate());
    long t2 = System.currentTimeMillis();
    String pubKeyLabel = savePkcs11PublicKey(id, label, keypair.getPublic());
    long t3 = System.currentTimeMillis();
    P11IdentityId identityId = new P11IdentityId(slotId, new P11ObjectIdentifier(id, keyLabel), pubKeyLabel, null);
    long t4 = System.currentTimeMillis();
    try {
      EmulatorP11Identity ret = new EmulatorP11Identity(this,identityId, keypair.getPrivate(),
          keypair.getPublic(), null, maxSessions, random);
      long t5 = System.currentTimeMillis();
      LOG.info("duration: t1: {}ms t2: {}ms t3 {}ms t4 {}ms t5", t2 - t1, t3 - t2, t4 - t3, t5 -t4);
      return ret;
    } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException ex) {
      throw new P11TokenException("could not construct KeyStoreP11Identity: " + ex.getMessage(), ex);
    }
  } // method saveP11Entity

  private P11Identity saveP11Entity(SecretKey key, P11NewObjectControl control) throws P11TokenException {
    byte[] id = control.getId();
    if (id == null) {
      id = generateId();
    }
    String label = control.getLabel();

    savePkcs11SecretKey(id, label, key);
    P11IdentityId identityId = new P11IdentityId(slotId, new P11ObjectIdentifier(id, label), null, null);
    return new EmulatorP11Identity(this,identityId, key, maxSessions, random);
  } // method saveP11Entity

  @Override
  protected void updateCertificate0(P11ObjectIdentifier keyId, X509Cert newCert)
      throws P11TokenException, CertificateException {
    removePkcs11Cert(keyId);
    savePkcs11Cert(keyId.getId(), keyId.getLabel(), newCert);
  } // method updateCertificate0

  private byte[] generateId() {
    while (true) {
      byte[] id = new byte[newObjectConf.getIdLength()];
      random.nextBytes(id);
      if (!(existsIdentityForId(id) || existsCertForId(id))) { // not duplicated
        return id;
      }
    }
  } // method generateId

}
