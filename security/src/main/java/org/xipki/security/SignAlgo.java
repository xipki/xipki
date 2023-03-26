// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.operator.OperatorCreationException;
import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.security.ObjectIdentifiers.Xipki;
import org.xipki.security.pkcs11.P11Key;
import org.xipki.util.Args;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.interfaces.*;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.bouncycastle.asn1.bsi.BSIObjectIdentifiers.*;
import static org.bouncycastle.asn1.cms.CMSObjectIdentifiers.*;
import static org.bouncycastle.asn1.gm.GMObjectIdentifiers.sm2sign_with_sm3;
import static org.bouncycastle.asn1.nist.NISTObjectIdentifiers.*;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.*;
import static org.bouncycastle.asn1.x9.X9ObjectIdentifiers.*;
import static org.xipki.security.EdECConstants.id_ED25519;
import static org.xipki.security.EdECConstants.id_ED448;
import static org.xipki.security.HashAlgo.*;
import static org.xipki.util.Args.notNull;

/**
 * Hash algorithm enum.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */
// See https://www.itu.int/ITU-T/formal-language/itu-t/x/x509/2019/AlgorithmObjectIdentifiers.html
public enum SignAlgo {

  // RSA PKCS#1v1.5
  RSA_SHA1("SHA1WITHRSA",     0x01, sha1WithRSAEncryption,   SHA1,   true),
  RSA_SHA224("SHA224WITHRSA", 0x02, sha224WithRSAEncryption, SHA224, true),
  RSA_SHA256("SHA256WITHRSA", 0x03, sha256WithRSAEncryption, SHA256, true),
  RSA_SHA384("SHA384WITHRSA", 0x04, sha384WithRSAEncryption, SHA384, true),
  RSA_SHA512("SHA512WITHRSA", 0x05, sha512WithRSAEncryption, SHA512, true),

  RSA_SHA3_224("SHA3-224WITHRSA", 0x06, id_rsassa_pkcs1_v1_5_with_sha3_224, SHA3_224, true),
  RSA_SHA3_256("SHA3-256WITHRSA", 0x07, id_rsassa_pkcs1_v1_5_with_sha3_256, SHA3_256, true),
  RSA_SHA3_384("SHA3-384WITHRSA", 0x08, id_rsassa_pkcs1_v1_5_with_sha3_384, SHA3_384, true),
  RSA_SHA3_512("SHA3-512WITHRSA", 0x09, id_rsassa_pkcs1_v1_5_with_sha3_512, SHA3_512, true),

  // RSA PSS with MGF1
  RSAPSS_SHA1("SHA1WITHRSAANDMGF1",     0x11, SHA1),
  RSAPSS_SHA224("SHA224WITHRSAANDMGF1", 0x12, SHA224),
  RSAPSS_SHA256("SHA256WITHRSAANDMGF1", 0x13, SHA256),
  RSAPSS_SHA384("SHA384WITHRSAANDMGF1", 0x14, SHA384),
  RSAPSS_SHA512("SHA512WITHRSAANDMGF1", 0x15, SHA512),

  RSAPSS_SHA3_224("SHA3-224WITHRSAANDMGF1", 0x16, SHA3_224),
  RSAPSS_SHA3_256("SHA3-256WITHRSAANDMGF1", 0x17, SHA3_256),
  RSAPSS_SHA3_384("SHA3-384WITHRSAANDMGF1", 0x18, SHA3_384),
  RSAPSS_SHA3_512("SHA3-512WITHRSAANDMGF1", 0x19, SHA3_512),

  // RSA PSS with SHAKE

  RSAPSS_SHAKE128("SHAKE128WITHRSAPSS", 0x1A, id_RSASSA_PSS_SHAKE128, SHAKE128, false),
  RSAPSS_SHAKE256("SHAKE256WITHRSAPSS", 0x1B, id_RSASSA_PSS_SHAKE256, SHAKE256, false),

  // DSA
  DSA_SHA1("SHA1WITHDSA",     0x21, id_dsa_with_sha1, SHA1, false),
  DSA_SHA224("SHA224WITHDSA", 0x22, dsa_with_sha224, SHA224, false),
  DSA_SHA256("SHA256WITHDSA", 0x23, dsa_with_sha256, SHA256, false),
  DSA_SHA384("SHA384WITHDSA", 0x24, dsa_with_sha384, SHA384, false),
  DSA_SHA512("SHA512WITHDSA", 0x25, dsa_with_sha512, SHA512, false),

  DSA_SHA3_224("SHA3-224WITHDSA", 0x26, id_dsa_with_sha3_224, SHA3_224, false),
  DSA_SHA3_256("SHA3-256WITHDSA", 0x27, id_dsa_with_sha3_256, SHA3_256, false),
  DSA_SHA3_384("SHA3-384WITHDSA", 0x28, id_dsa_with_sha3_384, SHA3_384, false),
  DSA_SHA3_512("SHA3-512WITHDSA", 0x29, id_dsa_with_sha3_512, SHA3_512, false),

  // ECDSA
  ECDSA_SHA1("SHA1WITHECDSA",     0x31, ecdsa_with_SHA1,   SHA1,   false),
  ECDSA_SHA224("SHA224WITHECDSA", 0x32, ecdsa_with_SHA224, SHA224, false),
  ECDSA_SHA256("SHA256WITHECDSA", 0x33, ecdsa_with_SHA256, SHA256, false),
  ECDSA_SHA384("SHA384WITHECDSA", 0x34, ecdsa_with_SHA384, SHA384, false),
  ECDSA_SHA512("SHA512WITHECDSA", 0x35, ecdsa_with_SHA512, SHA512, false),

  ECDSA_SHA3_224("SHA3-224WITHECDSA", 0x36, id_ecdsa_with_sha3_224, SHA3_224, false),
  ECDSA_SHA3_256("SHA3-256WITHECDSA", 0x37, id_ecdsa_with_sha3_256, SHA3_256, false),
  ECDSA_SHA3_384("SHA3-384WITHECDSA", 0x38, id_ecdsa_with_sha3_384, SHA3_384, false),
  ECDSA_SHA3_512("SHA3-512WITHECDSA", 0x39, id_ecdsa_with_sha3_512, SHA3_512, false),

  // SM2
  SM2_SM3("SM3WITHSM2", 0x3A, sm2sign_with_sm3, SM3, false),

  // ECDSA with SHAKE
  ECDSA_SHAKE128("SHAKE128WITHECDSA", 0x3B, id_ecdsa_with_shake128, SHAKE128, false),
  ECDSA_SHAKE256("SHAKE256WITHECDSA", 0x3C, id_ecdsa_with_shake256, SHAKE256, false),

  // Plain ECDSA
  PLAINECDSA_SHA1("SHA1WITHPLAINECDSA",     0x41, ecdsa_plain_SHA1,   SHA1,   false),
  PLAINECDSA_SHA224("SHA224WITHPLAINECDSA", 0x42, ecdsa_plain_SHA224, SHA224, false),
  PLAINECDSA_SHA256("SHA256WITHPLAINECDSA", 0x43, ecdsa_plain_SHA256, SHA256, false),
  PLAINECDSA_SHA384("SHA384WITHPLAINECDSA", 0x44, ecdsa_plain_SHA384, SHA384, false),
  PLAINECDSA_SHA512("SHA512WITHPLAINECDSA", 0x45, ecdsa_plain_SHA512, SHA512, false),

  // EdDSA
  ED25519("ED25519", 0x46, id_ED25519, null, false),

  ED448("ED448", 0x47, id_ED448, null, false),

  // HMAC
  HMAC_SHA1("HMACSHA1",     0x51, id_hmacWithSHA1,   SHA1,   true),
  HMAC_SHA224("HMACSHA224", 0x52, id_hmacWithSHA224, SHA224, true),
  HMAC_SHA256("HMACSHA256", 0x53, id_hmacWithSHA256, SHA256, true),
  HMAC_SHA384("HMACSHA384", 0x54, id_hmacWithSHA384, SHA384, true),
  HMAC_SHA512("HMACSHA512", 0x55, id_hmacWithSHA512, SHA512, true),
  HMAC_SHA3_224("HMACSHA3-224", 0x56, id_hmacWithSHA3_224, SHA3_224, true),
  HMAC_SHA3_256("HMACSHA3-256", 0x57, id_hmacWithSHA3_256, SHA3_256, true),
  HMAC_SHA3_384("HMACSHA3-384", 0x58, id_hmacWithSHA3_384, SHA3_384, true),
  HMAC_SHA3_512("HMACSHA3-512", 0x59, id_hmacWithSHA3_512, SHA3_512, true),

  // AES-GMAC
  // we ignore there the params of GMAC
  GMAC_AES128("AES-GMAC", 0x61, new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.9")),
  GMAC_AES192("AES-GMAC", 0x62, new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.29")),
  GMAC_AES256("AES-GMAC", 0x63, new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.49")),

  //DHPOP-MAC
  DHPOP_X25519("DHPOP-X25519", 0x5A, Xipki.id_alg_dhPop_x25519, SHA512, false),
  DHPOP_X448("DHPOP-X448", 0x5B, Xipki.id_alg_dhPop_x448, SHA512, false);

  private static final int TRAILER_FIELD_BC = 1;

  private static final Map<String, SignAlgo> map = new HashMap<>();

  private static final Map<HashAlgo, SignAlgo> mgf1HashToSigMap = new HashMap<>();

  private final ASN1ObjectIdentifier oid;

  private final AlgorithmIdentifier algId;

  private final String jceName;

  private final byte code;

  private final HashAlgo hashAlgo;

  static {
    for (SignAlgo type : SignAlgo.values()) {
      if (id_RSASSA_PSS.equals(type.oid)) {
        mgf1HashToSigMap.put(type.hashAlgo, type);
      } else {
        map.put(type.oid.getId(), type);
      }

      List<String> names = new LinkedList<>();
      names.add(type.jceName);
      if (type.jceName.endsWith("RSAANDMGF1")) {
        // RSAANDMGF1: alias RSAPSS
        names.add(type.jceName.replace("RSAANDMGF1", "RSAPSS"));
      }

      for (String name : names) {
        map.put(name, type);

        boolean withMinus = name.indexOf('-') != -1;
        if (withMinus) {
          map.put(name.replace("-", ""), type);
        }

        int index = name.indexOf("WITH");
        if (index != -1) {
          String inverseName = name.substring(index + "WITH".length()) + "WITH" + name.substring(0, index);
          map.put(inverseName, type);
          if (withMinus) {
            map.put(inverseName.replace("-", ""), type);
          }
        }
      }
    }
  }

  SignAlgo(String jceName, int code, ASN1ObjectIdentifier oid, HashAlgo hashAlgo, boolean withNullParams) {
    this.code = (byte) Args.range(code, "code", 0, 255);
    this.jceName = jceName.toUpperCase();
    this.oid = oid;
    this.hashAlgo = hashAlgo;
    if (withNullParams) {
      this.algId = new AlgorithmIdentifier(this.oid, DERNull.INSTANCE);
    } else {
      this.algId = new AlgorithmIdentifier(this.oid);
    }
  }

  // RSA PSS with MGF1
  SignAlgo(String jceName, int code, HashAlgo hashAlgo) {
    this.code = (byte) Args.range(code, "code", 0, 255);
    this.jceName = jceName.toUpperCase();
    this.hashAlgo = hashAlgo;

    AlgorithmIdentifier digAlgId = hashAlgo.getAlgIdWithNullParams();
    int saltSize = hashAlgo.getLength();
    RSASSAPSSparams params = new RSASSAPSSparams(digAlgId,
        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, digAlgId),
        new ASN1Integer(saltSize), RSASSAPSSparams.DEFAULT_TRAILER_FIELD);

    this.oid = PKCSObjectIdentifiers.id_RSASSA_PSS;
    this.algId = new AlgorithmIdentifier(this.oid, params);
  }

  // For GMAC: See https://tools.ietf.org/html/draft-ietf-lamps-cms-aes-gmac-alg-03
  SignAlgo(String jceName, int code, ASN1ObjectIdentifier oid) {
    if (!(jceName.startsWith("AES") && jceName.endsWith("GMAC"))) {
      throw new IllegalArgumentException("not AES*GMAC: " + jceName);
    }

    this.code = (byte) Args.range(code, "code", 0, 255);
    this.jceName = jceName.toUpperCase();
    this.oid = oid;
    this.hashAlgo = null;

    final int tagLen = 12;
    final int nonceLen = 12;

    /*
     * GMACParameters ::= SEQUENCE {
     *   nonce        OCTET STRING, -- recommended size is 12 octets
     *   length       MACLength DEFAULT 12 }
     *
     * MACLength ::= INTEGER (12 | 13 | 14 | 15 | 16)
     *
     */

    // nonce here is only placeholder, must be replaced before use: we use default
    // length (MACLength)
    // GMACParameters has exactly the same definition as GCMParameters (see RFC 5084)
    // so we use GCMParameters here (GMACParameters is not defined in BouncyCastle)
    GCMParameters params = new GCMParameters(new byte[nonceLen], tagLen);
    this.algId = new AlgorithmIdentifier(oid, params);
  }

  public HashAlgo getHashAlgo() {
    return hashAlgo;
  }

  public byte getCode() {
    return code;
  }

  public ASN1ObjectIdentifier getOid() {
    return oid;
  }

  public String getJceName() {
    return jceName;
  }

  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return algId;
  }

  public Signature newSignature() throws NoSuchAlgorithmException {
    return Signature.getInstance(jceName);
  }

  public Signature newSignature(String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
    return Signature.getInstance(jceName, provider);
  }

  public boolean isDSASigAlgo() {
    return this == DSA_SHA1
        || this == DSA_SHA224   || this == DSA_SHA256   || this == DSA_SHA384   || this == DSA_SHA512
        || this == DSA_SHA3_224 || this == DSA_SHA3_256 || this == DSA_SHA3_384 || this == DSA_SHA3_512;
  } // method isDSASigAlg

  public boolean isECDSASigAlgo() {
    return this == ECDSA_SHA1     || this == ECDSA_SHAKE128 || this == ECDSA_SHAKE256
        || this == ECDSA_SHA224   || this == ECDSA_SHA256   || this == ECDSA_SHA384   || this == ECDSA_SHA512
        || this == ECDSA_SHA3_224 || this == ECDSA_SHA3_256 || this == ECDSA_SHA3_384 || this == ECDSA_SHA3_512;
  } // method isECDSASigAlg

  public boolean isEDDSASigAlgo() {
    return this == ED448 || this == ED25519;
  } // method isEDDSASigAlg

  public boolean isPlainECDSASigAlgo() {
    return this == PLAINECDSA_SHA1   || this == PLAINECDSA_SHA224 || this == PLAINECDSA_SHA256
        || this == PLAINECDSA_SHA384 || this == PLAINECDSA_SHA512;
  } // method isPlainECDSASigAlg

  public boolean isSM2SigAlgo() {
    ASN1ObjectIdentifier oid = notNull(algId, "algId").getAlgorithm();
    return GMObjectIdentifiers.sm2sign_with_sm3.equals(oid);
    // other algorithms not supported yet.
  } // method isSM2SigAlg

  public boolean isRSAPkcs1SigAlgo() {
    return this == RSA_SHA1
        || this == RSA_SHA224   || this == RSA_SHA256   || this == RSA_SHA384   || this == RSA_SHA512
        || this == RSA_SHA3_224 || this == RSA_SHA3_256 || this == RSA_SHA3_384 || this == RSA_SHA3_512;
  } // method isRSASigAlgo

  public boolean isRSAPSSSigAlgo() {
    if (isRSAPSSMGF1SigAlgo()) {
      return true;
    }

    return this == RSAPSS_SHAKE128 || this == RSAPSS_SHAKE256;
  } // method isRSAPSSSigAlgo

  public boolean isRSAPSSMGF1SigAlgo() {
    return this == RSAPSS_SHA1
        || this == RSAPSS_SHA224   || this == RSAPSS_SHA256   || this == RSAPSS_SHA384   || this == RSAPSS_SHA512
        || this == RSAPSS_SHA3_224 || this == RSAPSS_SHA3_256 || this == RSAPSS_SHA3_384 || this == RSAPSS_SHA3_512;
  } // method isRSAPSSMGF1SigAlgo

  public boolean isHmac() {
    return this == HMAC_SHA1
        || this == HMAC_SHA224   || this == HMAC_SHA256   || this == HMAC_SHA384   || this == HMAC_SHA512
        || this == HMAC_SHA3_224 || this == HMAC_SHA3_256 || this == HMAC_SHA3_384 || this == HMAC_SHA3_512;
  }

  public boolean isGmac() {
    return this == GMAC_AES128 || this == GMAC_AES192 || this == GMAC_AES256;
  }

  public boolean isMac() {
    return isHmac() || isGmac();
  }

  public static SignAlgo getInstance(AlgorithmIdentifier algId) throws NoSuchAlgorithmException {
    ASN1ObjectIdentifier oid = algId.getAlgorithm();
    ASN1Encodable params = algId.getParameters();

    SignAlgo rv = null;
    if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(oid)) {
      RSASSAPSSparams param = RSASSAPSSparams.getInstance(params);
      AlgorithmIdentifier digestAlgId = param.getHashAlgorithm();

      AlgorithmIdentifier mgf = param.getMaskGenAlgorithm();
      ASN1ObjectIdentifier mgfOid = mgf.getAlgorithm();
      if (!PKCSObjectIdentifiers.id_mgf1.equals(mgfOid)) {
        throw new NoSuchAlgorithmException("mgf != MGF1");
      }

      AlgorithmIdentifier mgfDigestAlgId = AlgorithmIdentifier.getInstance(mgf.getParameters());
      if (!digestAlgId.equals(mgfDigestAlgId)) {
        throw new NoSuchAlgorithmException("digestAlg != MGF1.digestAlg");
      }

      if (TRAILER_FIELD_BC != param.getTrailerField().intValueExact()) {
        return null;
      }

      HashAlgo hashAlgo = HashAlgo.getInstance(digestAlgId);
      if (hashAlgo.getLength() != param.getSaltLength().intValueExact()) {
        return null;
      }

      return mgf1HashToSigMap.get(hashAlgo);
    } else if (SignAlgo.GMAC_AES128.oid.equals(oid) || SignAlgo.GMAC_AES192.oid.equals(oid)
        || SignAlgo.GMAC_AES256.oid.equals(oid)) {
      return SignAlgo.GMAC_AES128.oid.equals(oid) ? SignAlgo.GMAC_AES128
          : SignAlgo.GMAC_AES192.oid.equals(oid)  ? SignAlgo.GMAC_AES192 : SignAlgo.GMAC_AES256;
    } else {
      if (params != null) {
        if (!DERNull.INSTANCE.equals(params)) {
          return null;
        }
      }

      for (SignAlgo algo : values()) {
        if (algo.oid.equals(oid)) {
          rv = algo;
        }
      }
    }
    return rv;
  }

  public static SignAlgo getInstance(String nameOrOid) throws NoSuchAlgorithmException {
    SignAlgo alg = map.get(nameOrOid.toUpperCase().replace("-", ""));
    if (alg == null) {
      throw new NoSuchAlgorithmException("Unknown HashAlgo OID/name '" + nameOrOid + "'");
    }
    return alg;
  }

  public static SignAlgo getInstance(P11Key p11Key, SignerConf signerConf) throws NoSuchAlgorithmException {
    if (notNull(signerConf, "signerConf").getHashAlgo() == null) {
      return getInstance(signerConf.getConfValue("algo"));
    }

    SignatureAlgoControl algoControl = signerConf.getSignatureAlgoControl();
    HashAlgo hashAlgo = signerConf.getHashAlgo();

    long keyType = p11Key.getKeyType();
    if (keyType == PKCS11Constants.CKK_RSA) {
      boolean rsaPss = algoControl != null && algoControl.isRsaPss();
      return getRSAInstance(hashAlgo, rsaPss);
    } else if (keyType == PKCS11Constants.CKK_EC || keyType == PKCS11Constants.CKK_VENDOR_SM2) {
      boolean dsaPlain = algoControl != null && algoControl.isDsaPlain();
      boolean gm = algoControl != null && algoControl.isGm();
      return getECSigAlgo(hashAlgo, dsaPlain, gm);
    } else if (keyType == PKCS11Constants.CKK_DSA) {
      return getDSASigAlgo(hashAlgo);
    } else if (keyType == PKCS11Constants.CKK_EC_EDWARDS) {
      String keyAlgo = EdECConstants.getName(p11Key.getEcParams());
      if (keyAlgo.equalsIgnoreCase(EdECConstants.ED25519)) {
        return ED25519;
      } else if (keyAlgo.equalsIgnoreCase(EdECConstants.ED448)) {
        return ED448;
      } else {
        throw new NoSuchAlgorithmException("Unknown Edwards public key " + keyAlgo);
      }
    } else {
      throw new NoSuchAlgorithmException("Unknown key type " + PKCS11Constants.ckkCodeToName(keyType));
    }
  } // method getInstance

  public static SignAlgo getInstance(Key key, SignerConf signerConf) throws NoSuchAlgorithmException {
    if (notNull(signerConf, "signerConf").getHashAlgo() == null) {
      return getInstance(signerConf.getConfValue("algo"));
    }

    SignatureAlgoControl algoControl = signerConf.getSignatureAlgoControl();
    HashAlgo hashAlgo = signerConf.getHashAlgo();

    if (key instanceof RSAPublicKey || key instanceof RSAPrivateKey) {
      boolean rsaPss = algoControl != null && algoControl.isRsaPss();
      return getRSAInstance(hashAlgo, rsaPss);
    } else if (key instanceof ECPublicKey || key instanceof ECPrivateKey) {
      boolean dsaPlain = algoControl != null && algoControl.isDsaPlain();
      boolean gm = algoControl != null && algoControl.isGm();
      return getECSigAlgo(hashAlgo, dsaPlain, gm);
    } else if (key instanceof DSAPublicKey || key instanceof DSAPrivateKey) {
      return getDSASigAlgo(hashAlgo);
    } else if (key instanceof EdDSAKey) {
      String keyAlgo = key.getAlgorithm().toUpperCase();
      if (keyAlgo.equals(EdECConstants.ED25519)) {
        return ED25519;
      } else if (keyAlgo.equals(EdECConstants.ED448)) {
        return ED448;
      } else {
        throw new NoSuchAlgorithmException("Unknown Edwards public key " + keyAlgo);
      }
    } else {
      throw new NoSuchAlgorithmException("Unknown key " + key.getClass().getName());
    }
  } // method getInstance

  public static SignAlgo getInstance(Key key, HashAlgo hashAlgo, SignatureAlgoControl algoControl)
      throws NoSuchAlgorithmException {
    notNull(hashAlgo, "hashAlgo");
    notNull(key, "key");

    if (key instanceof RSAPublicKey || key instanceof RSAPrivateKey) {
      boolean rsaPss = algoControl != null && algoControl.isRsaPss();
      return getRSAInstance(hashAlgo, rsaPss);
    } else if (key instanceof ECPublicKey || key instanceof ECPrivateKey) {
      boolean dsaPlain = algoControl != null && algoControl.isDsaPlain();
      boolean gm = algoControl != null && algoControl.isGm();
      return getECSigAlgo(hashAlgo, dsaPlain, gm);
    } else if (key instanceof DSAPublicKey || key instanceof DSAPrivateKey) {
      return getDSASigAlgo(hashAlgo);
    } else if (key instanceof EdDSAKey) {
      String keyAlgo = key.getAlgorithm().toUpperCase();
      if (keyAlgo.equals(EdECConstants.ED25519)) {
        return ED25519;
      } else if (keyAlgo.equals(EdECConstants.ED448)) {
        return ED448;
      } else {
        throw new NoSuchAlgorithmException("Unknown Edwards public key " + keyAlgo);
      }
    } else {
      throw new NoSuchAlgorithmException("Unknown key '" + key.getClass().getName());
    }
  } // method getInstance

  private static SignAlgo getRSAInstance(HashAlgo hashAlgo, boolean rsaPss) throws NoSuchAlgorithmException {
    notNull(hashAlgo, "hashAlgo");
    switch (hashAlgo) {
      case SHAKE128:
        return RSAPSS_SHAKE128;
      case SHAKE256:
        return RSAPSS_SHAKE256;
      case SHA1:
        return rsaPss ? RSAPSS_SHA1 : RSA_SHA1;
      case SHA224:
        return rsaPss ? RSAPSS_SHA224 : RSA_SHA224;
      case SHA256:
        return rsaPss ? RSAPSS_SHA256 : RSA_SHA256;
      case SHA384:
        return rsaPss ? RSAPSS_SHA384 : RSA_SHA384;
      case SHA512:
        return rsaPss ? RSAPSS_SHA512 : RSA_SHA512;
      case SHA3_224:
        return rsaPss ? RSAPSS_SHA3_224 : RSA_SHA3_224;
      case SHA3_256:
        return rsaPss ? RSAPSS_SHA3_256 : RSA_SHA3_256;
      case SHA3_384:
        return rsaPss ? RSAPSS_SHA3_384 : RSA_SHA3_384;
      case SHA3_512:
        return rsaPss ? RSAPSS_SHA3_512 : RSA_SHA3_512;
      default:
        throw new NoSuchAlgorithmException("unsupported hash " + hashAlgo + " for RSA");
    }
  } // method getRSAInstance

  private static SignAlgo getDSASigAlgo(HashAlgo hashAlgo) throws NoSuchAlgorithmException {
    notNull(hashAlgo, "hashAlgo");
    switch (hashAlgo) {
      case SHAKE128:
        return RSAPSS_SHAKE128;
      case SHAKE256:
        return RSAPSS_SHAKE256;
      case SHA1:
        return DSA_SHA1;
      case SHA224:
        return DSA_SHA224;
      case SHA256:
        return DSA_SHA256;
      case SHA384:
        return DSA_SHA384;
      case SHA512:
        return DSA_SHA512;
      case SHA3_224:
        return DSA_SHA3_224;
      case SHA3_256:
        return DSA_SHA3_256;
      case SHA3_384:
        return DSA_SHA3_384;
      case SHA3_512:
        return DSA_SHA3_512;
      default:
        throw new NoSuchAlgorithmException("unsupported hash " + hashAlgo + " for DSA");
    }
  } // method getDSASigAlgo

  private static SignAlgo getECSigAlgo(HashAlgo hashAlgo, boolean plainSignature, boolean gm)
      throws NoSuchAlgorithmException {
    notNull(hashAlgo, "hashAlgo");
    if (gm && plainSignature) {
      throw new IllegalArgumentException("plainSignature and gm cannot be both true");
    }

    if (gm) {
      if (hashAlgo == SM3) {
        return SM2_SM3;
      }
      throw new NoSuchAlgorithmException("unsupported hash " + hashAlgo + " for SM2");
    } else if (plainSignature) {
      switch (hashAlgo) {
        case SHA1:
          return PLAINECDSA_SHA1;
        case SHA224:
          return PLAINECDSA_SHA224;
        case SHA256:
          return PLAINECDSA_SHA256;
        case SHA384:
          return PLAINECDSA_SHA384;
        case SHA512:
          return PLAINECDSA_SHA512;
        default:
          throw new NoSuchAlgorithmException("unsupported hash " + hashAlgo + " for PlainECDSA");
      }
    } else {
      switch (hashAlgo) {
        case SHA1:
          return ECDSA_SHA1;
        case SHA224:
          return ECDSA_SHA224;
        case SHA256:
          return ECDSA_SHA256;
        case SHA384:
          return ECDSA_SHA384;
        case SHA512:
          return ECDSA_SHA512;
        case SHA3_224:
          return ECDSA_SHA3_224;
        case SHA3_256:
          return ECDSA_SHA3_256;
        case SHA3_384:
          return ECDSA_SHA3_384;
        case SHA3_512:
          return ECDSA_SHA3_512;
        case SHAKE128:
          return ECDSA_SHAKE128;
        case SHAKE256:
          return ECDSA_SHAKE256;
        default:
          throw new NoSuchAlgorithmException("unsupported hash " + hashAlgo + " for ECDSA");
      }
    }
  } // method getECDSASigAlgo

  public void assertSameAlgorithm(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
      throws OperatorCreationException {
    if (!this.algId.equals(sigAlgId)) {
      throw new OperatorCreationException("sigAlgId differs");
    }

    if (hashAlgo != null) {
      if (!hashAlgo.getAlgorithmIdentifier().equals(digAlgId)) {
        throw new OperatorCreationException("digAlgId differs");
      }
    } else {
      if (digAlgId != null) {
        throw new OperatorCreationException("digAlgId differs");
      }
    }
  }

}
