// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.jcajce.interfaces.MLDSAKey;
import org.bouncycastle.operator.OperatorCreationException;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.security.pkcs11.composite.CompositeSigAlgoSuite;
import org.xipki.security.pkcs11.composite.P11CompositeKey;
import org.xipki.security.pkcs11.P11Key;
import org.xipki.security.util.EcCurveEnum;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Args;
import org.xipki.util.conf.InvalidConfException;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.xipki.security.HashAlgo.*;

/**
 * Hash algorithm enum.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */
// See https://www.itu.int/ITU-T/formal-language/itu-t/x/x509/2019/AlgorithmObjectIdentifiers.html
public enum SignAlgo {

  // RSA PKCS#1v1.5
  RSA_SHA1("SHA1WITHRSA",     0x01,
      OIDs.Algo.sha1WithRSAEncryption,   SHA1,   true),
  RSA_SHA224("SHA224WITHRSA", 0x02,
      OIDs.Algo.sha224WithRSAEncryption, SHA224, true),
  RSA_SHA256("SHA256WITHRSA", 0x03,
      OIDs.Algo.sha256WithRSAEncryption, SHA256, true),
  RSA_SHA384("SHA384WITHRSA", 0x04,
      OIDs.Algo.sha384WithRSAEncryption, SHA384, true),
  RSA_SHA512("SHA512WITHRSA", 0x05,
      OIDs.Algo.sha512WithRSAEncryption, SHA512, true),

  RSA_SHA3_224("SHA3-224WITHRSA", 0x06,
      OIDs.Algo.id_rsassa_pkcs1_v1_5_with_sha3_224,
      SHA3_224, true),
  RSA_SHA3_256("SHA3-256WITHRSA", 0x07,
      OIDs.Algo.id_rsassa_pkcs1_v1_5_with_sha3_256,
      SHA3_256, true),
  RSA_SHA3_384("SHA3-384WITHRSA", 0x08,
      OIDs.Algo.id_rsassa_pkcs1_v1_5_with_sha3_384,
      SHA3_384, true),
  RSA_SHA3_512("SHA3-512WITHRSA", 0x09,
      OIDs.Algo.id_rsassa_pkcs1_v1_5_with_sha3_512,
      SHA3_512, true),

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

  RSAPSS_SHAKE128("SHAKE128WITHRSAPSS", 0x1A,
      OIDs.Algo.id_RSASSA_PSS_SHAKE128, SHAKE128, false),
  RSAPSS_SHAKE256("SHAKE256WITHRSAPSS", 0x1B,
      OIDs.Algo.id_RSASSA_PSS_SHAKE256, SHAKE256, false),

  // ECDSA
  ECDSA_SHA1("SHA1WITHECDSA",     0x31,
      OIDs.Algo.ecdsa_with_SHA1,   SHA1,   false),
  ECDSA_SHA224("SHA224WITHECDSA", 0x32,
      OIDs.Algo.ecdsa_with_SHA224, SHA224, false),
  ECDSA_SHA256("SHA256WITHECDSA", 0x33,
      OIDs.Algo.ecdsa_with_SHA256, SHA256, false),
  ECDSA_SHA384("SHA384WITHECDSA", 0x34,
      OIDs.Algo.ecdsa_with_SHA384, SHA384, false),
  ECDSA_SHA512("SHA512WITHECDSA", 0x35,
      OIDs.Algo.ecdsa_with_SHA512, SHA512, false),

  ECDSA_SHA3_224("SHA3-224WITHECDSA", 0x36,
      OIDs.Algo.id_ecdsa_with_sha3_224, SHA3_224, false),
  ECDSA_SHA3_256("SHA3-256WITHECDSA", 0x37,
      OIDs.Algo.id_ecdsa_with_sha3_256, SHA3_256, false),
  ECDSA_SHA3_384("SHA3-384WITHECDSA", 0x38,
      OIDs.Algo.id_ecdsa_with_sha3_384, SHA3_384, false),
  ECDSA_SHA3_512("SHA3-512WITHECDSA", 0x39,
      OIDs.Algo.id_ecdsa_with_sha3_512, SHA3_512, false),

  // SM2
  SM2_SM3("SM3WITHSM2", 0x3A,
      OIDs.Algo.sm2sign_with_sm3, SM3, false),

  // ECDSA with SHAKE
  ECDSA_SHAKE128("SHAKE128WITHECDSA", 0x3B,
      OIDs.Algo.id_ecdsa_with_shake128, SHAKE128, false),
  ECDSA_SHAKE256("SHAKE256WITHECDSA", 0x3C,
      OIDs.Algo.id_ecdsa_with_shake256, SHAKE256, false),

  // EdDSA
  ED25519("ED25519", 0x46,
      OIDs.Curve.id_ED25519, null, false),

  ED448("ED448", 0x47,
      OIDs.Curve.id_ED448, null, false),

  // HMAC
  HMAC_SHA1("HMACSHA1",     0x51,
      OIDs.Algo.id_hmacWithSHA1,   SHA1,   true),
  HMAC_SHA224("HMACSHA224", 0x52,
      OIDs.Algo.id_hmacWithSHA224, SHA224, true),
  HMAC_SHA256("HMACSHA256", 0x53,
      OIDs.Algo.id_hmacWithSHA256, SHA256, true),
  HMAC_SHA384("HMACSHA384", 0x54,
      OIDs.Algo.id_hmacWithSHA384, SHA384, true),
  HMAC_SHA512("HMACSHA512", 0x55,
      OIDs.Algo.id_hmacWithSHA512, SHA512, true),
  HMAC_SHA3_224("HMACSHA3-224", 0x56,
      OIDs.Algo.id_hmacWithSHA3_224, SHA3_224, true),
  HMAC_SHA3_256("HMACSHA3-256", 0x57,
      OIDs.Algo.id_hmacWithSHA3_256, SHA3_256, true),
  HMAC_SHA3_384("HMACSHA3-384", 0x58,
      OIDs.Algo.id_hmacWithSHA3_384, SHA3_384, true),
  HMAC_SHA3_512("HMACSHA3-512", 0x59,
      OIDs.Algo.id_hmacWithSHA3_512, SHA3_512, true),

  // AES-GMAC
  // we ignore there the params of GMAC
  GMAC_AES128("AES-GMAC", 0x61,
      OIDs.Algo.AES128_GMAC),
  GMAC_AES192("AES-GMAC", 0x62,
      OIDs.Algo.AES192_GMAC),
  GMAC_AES256("AES-GMAC", 0x63,
      OIDs.Algo.AES256_GMAC),

  //DHPOP-MAC
  DHPOP_X25519("DHPOP-X25519", 0x5A,
      OIDs.Xipki.id_alg_dhPop_x25519, SHA512, false),
  DHPOP_X448("DHPOP-X448", 0x5B,
      OIDs.Xipki.id_alg_dhPop_x448, SHA512, false),

  // MLDSA
  ML_DSA_44("ML-DSA-44", 0x60,
      OIDs.Algo.id_ml_dsa_44, null, false),
  ML_DSA_65("ML-DSA-65", 0x61,
      OIDs.Algo.id_ml_dsa_65, null, false),
  ML_DSA_87("ML-DSA-87", 0x62,
      OIDs.Algo.id_ml_dsa_87, null, false),

  // KEM: decrypt the ciphertext using HPKE to get the shared secret key, using
  // it to compute the MAC value. The jceName KEM-AEW-GMAC is just a dummy
  // value.
  KEM_GMAC_256("KEM-GMAC-256", 0x84,
      OIDs.Xipki.id_alg_sig_KEM_GMAC_256, null, false),

  // composite algorithms
  MLDSA44_RSA2048_PSS_SHA256("MLDSA44-RSA2048-PSS-SHA256", 0x85,
      CompositeSigAlgoSuite.MLDSA44_RSA2048_PSS_SHA256),

  MLDSA44_RSA2048_PKCS15_SHA256("MLDSA44-RSA2048-PKCS15-SHA256", 0x86,
      CompositeSigAlgoSuite.MLDSA44_RSA2048_PKCS15_SHA256),

  MLDSA44_Ed25519_SHA512("MLDSA44-Ed25519-SHA512", 0x87,
      CompositeSigAlgoSuite.MLDSA44_Ed25519_SHA512),

  MLDSA44_ECDSA_P256_SHA256("MLDSA44-ECDSA-P256-SHA256", 0x88,
      CompositeSigAlgoSuite.MLDSA44_ECDSA_P256_SHA256),

  MLDSA65_RSA3072_PSS_SHA512("MLDSA65-RSA3072-PSS-SHA512", 0x89,
      CompositeSigAlgoSuite.MLDSA65_RSA3072_PSS_SHA512),

  MLDSA65_RSA3072_PKCS15_SHA512("MLDSA65-RSA3072-PKCS15-SHA512", 0x8a,
      CompositeSigAlgoSuite.MLDSA65_RSA3072_PKCS15_SHA512),

  MLDSA65_RSA4096_PSS_SHA512("MLDSA65-RSA4096-PSS-SHA512", 0x8b,
      CompositeSigAlgoSuite.MLDSA65_RSA4096_PSS_SHA512),

  MLDSA65_RSA4096_PKCS15_SHA512("MLDSA65-RSA4096-PKCS15-SHA512", 0x8c,
      CompositeSigAlgoSuite.MLDSA65_RSA4096_PKCS15_SHA512),

  MLDSA65_ECDSA_P256_SHA512("MLDSA65-ECDSA-P256-SHA512", 0x8d,
      CompositeSigAlgoSuite.MLDSA65_ECDSA_P256_SHA512),

  MLDSA65_ECDSA_P384_SHA512("MLDSA65-ECDSA-P384-SHA512", 0x8e,
       CompositeSigAlgoSuite.MLDSA65_ECDSA_P384_SHA512),

  MLDSA65_ECDSA_BP256_SHA512("MLDSA65-ECDSA-brainpoolP256r1-SHA512", 0x8f,
       CompositeSigAlgoSuite.MLDSA65_ECDSA_BP256_SHA512),

  MLDSA65_Ed25519_SHA512("MLDSA65-Ed25519-SHA512", 0x90,
       CompositeSigAlgoSuite.MLDSA65_Ed25519_SHA512),

  MLDSA87_ECDSA_P384_SHA512("MLDSA87-ECDSA-P384-SHA512", 0x91,
       CompositeSigAlgoSuite.MLDSA87_ECDSA_P384_SHA512),

  MLDSA87_ECDSA_BP384_SHA512("MLDSA87-ECDSA-brainpoolP384r1-SHA512", 0x92,
       CompositeSigAlgoSuite.MLDSA87_ECDSA_BP384_SHA512),

  MLDSA87_Ed448_SHAKE256("MLDSA87-Ed448-SHAKE256", 0x93,
       CompositeSigAlgoSuite.MLDSA87_Ed448_SHAKE256),

  MLDSA87_RSA3072_PSS_SHA512("MLDSA87-RSA3072-PSS-SHA512", 0x94,
       CompositeSigAlgoSuite.MLDSA87_RSA3072_PSS_SHA512),

  MLDSA87_RSA4096_PSS_SHA512("MLDSA87-RSA4096-PSS-SHA512", 0x95,
       CompositeSigAlgoSuite.MLDSA87_RSA4096_PSS_SHA512),

  MLDSA87_ECDSA_P521_SHA512("MLDSA87-ECDSA-P521-SHA512", 0x96,
       CompositeSigAlgoSuite.MLDSA87_ECDSA_P521_SHA512)
  ;

  private static final int TRAILER_FIELD_BC = 1;

  private static final Map<String, SignAlgo> map = new HashMap<>();

  private static final Map<HashAlgo, SignAlgo> mgf1HashToSigMap =
      new HashMap<>();

  private final ASN1ObjectIdentifier oid;

  private final AlgorithmIdentifier algId;

  private final String jceName;

  private final byte code;

  private final HashAlgo hashAlgo;

  private final CompositeSigAlgoSuite compositeSigAlgoSuite;

  static {
    for (SignAlgo type : SignAlgo.values()) {
      if (OIDs.Algo.id_RSASSA_PSS.equals(type.oid)) {
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
          String inverseName = name.substring(index + "WITH".length())
                                + "WITH" + name.substring(0, index);
          map.put(inverseName, type);
          if (withMinus) {
            map.put(inverseName.replace("-", ""), type);
          }
        }
      }
    }
  }

  SignAlgo(String jceName, int code, ASN1ObjectIdentifier oid,
           HashAlgo hashAlgo, boolean withNullParams) {
    this.code = (byte) Args.range(code, "code", 0, 255);
    this.jceName = jceName.toUpperCase();
    this.oid = oid;
    this.hashAlgo = hashAlgo;
    this.compositeSigAlgoSuite = null;
    this.algId = withNullParams
        ? new AlgorithmIdentifier(this.oid, DERNull.INSTANCE)
        : new AlgorithmIdentifier(this.oid);
  }

  // RSA PSS with MGF1
  SignAlgo(String jceName, int code, HashAlgo hashAlgo) {
    this.code = (byte) Args.range(code, "code", 0, 255);
    this.jceName = jceName.toUpperCase();
    this.hashAlgo = hashAlgo;

    AlgorithmIdentifier digAlgId = hashAlgo.getAlgIdWithNullParams();
    int saltSize = hashAlgo.getLength();
    RSASSAPSSparams params = new RSASSAPSSparams(digAlgId,
        new AlgorithmIdentifier(OIDs.Algo.id_mgf1, digAlgId),
        new ASN1Integer(saltSize), RSASSAPSSparams.DEFAULT_TRAILER_FIELD);

    this.oid = OIDs.Algo.id_RSASSA_PSS;
    this.algId = new AlgorithmIdentifier(this.oid, params);
    this.compositeSigAlgoSuite = null;
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

    // nonce here is only placeholder, must be replaced before use: we use
    // default length (MACLength).
    // GMACParameters has exactly the same definition as GCMParameters
    // (see RFC 5084) so we use GCMParameters here (GMACParameters is not
    // defined in BouncyCastle)
    GCMParameters params = new GCMParameters(new byte[nonceLen], tagLen);
    this.algId = new AlgorithmIdentifier(oid, params);
    this.compositeSigAlgoSuite = null;
  }

  // Composite Signature
  SignAlgo(String jceName, int code, CompositeSigAlgoSuite algoSuite) {
    this.code     = (byte) Args.range(code, "code", 0, 255);
    this.jceName  = jceName;
    this.algId    = algoSuite.algId();
    this.oid      = algoSuite.oid();
    this.hashAlgo = null;
    this.compositeSigAlgoSuite = algoSuite;
  }

  public HashAlgo getHashAlgo() {
    return hashAlgo;
  }

  public CompositeSigAlgoSuite compositeSigAlgoSuite() {
    return compositeSigAlgoSuite;
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

  public CompositeSigAlgoSuite getCompositeSigAlgoSuite() {
    return compositeSigAlgoSuite;
  }

  public Signature newSignature() throws NoSuchAlgorithmException {
    return Signature.getInstance(jceName);
  }

  public Signature newSignature(String provider)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    return Signature.getInstance(jceName, provider);
  }

  public boolean isECDSASigAlgo() {
    return this == ECDSA_SHA1
        || this == ECDSA_SHAKE128 || this == ECDSA_SHAKE256
        || this == ECDSA_SHA224   || this == ECDSA_SHA256
        || this == ECDSA_SHA384   || this == ECDSA_SHA512
        || this == ECDSA_SHA3_224 || this == ECDSA_SHA3_256
        || this == ECDSA_SHA3_384 || this == ECDSA_SHA3_512;
  } // method isECDSASigAlg

  public boolean isEDDSASigAlgo() {
    return this == ED448 || this == ED25519;
  } // method isEDDSASigAlg

  public boolean isSM2SigAlgo() {
    ASN1ObjectIdentifier oid = Args.notNull(algId, "algId").getAlgorithm();
    return OIDs.Algo.sm2sign_with_sm3.equals(oid);
    // other algorithms not supported yet.
  } // method isSM2SigAlg

  public boolean isRSASigAlgo() {
    return isRSAPSSSigAlgo() || isRSAPkcs1SigAlgo();
  } // method isRSAPSSSigAlgo

  public boolean isRSAPkcs1SigAlgo() {
    return this == RSA_SHA1
        || this == RSA_SHA224   || this == RSA_SHA256
        || this == RSA_SHA384   || this == RSA_SHA512
        || this == RSA_SHA3_224 || this == RSA_SHA3_256
        || this == RSA_SHA3_384 || this == RSA_SHA3_512;
  } // method isRSASigAlgo

  public boolean isRSAPSSSigAlgo() {
    if (isRSAPSSMGF1SigAlgo()) {
      return true;
    }

    return this == RSAPSS_SHAKE128 || this == RSAPSS_SHAKE256;
  } // method isRSAPSSSigAlgo

  public boolean isRSAPSSMGF1SigAlgo() {
    return this == RSAPSS_SHA1
        || this == RSAPSS_SHA224   || this == RSAPSS_SHA256
        || this == RSAPSS_SHA384   || this == RSAPSS_SHA512
        || this == RSAPSS_SHA3_224 || this == RSAPSS_SHA3_256
        || this == RSAPSS_SHA3_384 || this == RSAPSS_SHA3_512;
  } // method isRSAPSSMGF1SigAlgo

  public boolean isMLDSASigAlgo() {
    return this == ML_DSA_44 || this == ML_DSA_65 || this == ML_DSA_87;
  } // method isRSASigAlgo

  public boolean isCompositeMLDSA() {
    switch (this) {
      case MLDSA44_RSA2048_PSS_SHA256:
      case MLDSA44_RSA2048_PKCS15_SHA256:
      case MLDSA44_Ed25519_SHA512:
      case MLDSA44_ECDSA_P256_SHA256:
      case MLDSA65_RSA3072_PSS_SHA512:
      case MLDSA65_RSA3072_PKCS15_SHA512:
      case MLDSA65_RSA4096_PSS_SHA512:
      case MLDSA65_RSA4096_PKCS15_SHA512:
      case MLDSA65_ECDSA_P256_SHA512:
      case MLDSA65_ECDSA_P384_SHA512:
      case MLDSA65_ECDSA_BP256_SHA512:
      case MLDSA65_Ed25519_SHA512:
      case MLDSA87_ECDSA_P384_SHA512:
      case MLDSA87_ECDSA_BP384_SHA512:
      case MLDSA87_Ed448_SHAKE256:
      case MLDSA87_RSA3072_PSS_SHA512:
      case MLDSA87_RSA4096_PSS_SHA512:
      case MLDSA87_ECDSA_P521_SHA512:
       return true;
      default:
        return false;
    }
  }

  public boolean isHmac() {
    return this == HMAC_SHA1
        || this == HMAC_SHA224   || this == HMAC_SHA256
        || this == HMAC_SHA384   || this == HMAC_SHA512
        || this == HMAC_SHA3_224 || this == HMAC_SHA3_256
        || this == HMAC_SHA3_384 || this == HMAC_SHA3_512;
  }

  public boolean isGmac() {
    return this == GMAC_AES128 || this == GMAC_AES192 || this == GMAC_AES256;
  }

  public boolean isMac() {
    return isHmac() || isGmac();
  }

  public static SignAlgo getInstance(AlgorithmIdentifier algId)
      throws NoSuchAlgorithmException {
    ASN1ObjectIdentifier oid = algId.getAlgorithm();
    ASN1Encodable params = algId.getParameters();

    SignAlgo rv = null;
    if (OIDs.Algo.id_RSASSA_PSS.equals(oid)) {
      RSASSAPSSparams param = RSASSAPSSparams.getInstance(params);
      AlgorithmIdentifier digestAlgId = param.getHashAlgorithm();

      AlgorithmIdentifier mgf = param.getMaskGenAlgorithm();
      ASN1ObjectIdentifier mgfOid = mgf.getAlgorithm();
      if (!OIDs.Algo.id_mgf1.equals(mgfOid)) {
        throw new NoSuchAlgorithmException("mgf != MGF1");
      }

      AlgorithmIdentifier mgfDigestAlgId =
          AlgorithmIdentifier.getInstance(mgf.getParameters());
      if (!digestAlgId.equals(mgfDigestAlgId)) {
        throw new NoSuchAlgorithmException("digestAlg != MGF1.digestAlg");
      }

      int trailerField = param.getTrailerField().intValueExact();
      if (TRAILER_FIELD_BC != param.getTrailerField().intValueExact()) {
        throw new NoSuchAlgorithmException(
            "trailerField != 0xBC" + trailerField);
      }

      HashAlgo hashAlgo = HashAlgo.getInstance(digestAlgId);
      int saltLen = param.getSaltLength().intValueExact();
      if (hashAlgo.getLength() != saltLen) {
        throw new NoSuchAlgorithmException("saltLen != " +
            hashAlgo.getLength() + ": " + saltLen);
      }

      return mgf1HashToSigMap.get(hashAlgo);
    } else if (SignAlgo.GMAC_AES128.oid.equals(oid)
        || SignAlgo.GMAC_AES192.oid.equals(oid)
        || SignAlgo.GMAC_AES256.oid.equals(oid)) {
      return SignAlgo.GMAC_AES128.oid.equals(oid) ? SignAlgo.GMAC_AES128
          :  SignAlgo.GMAC_AES192.oid.equals(oid) ? SignAlgo.GMAC_AES192
          :  SignAlgo.GMAC_AES256;
    } else {
      if (params != null) {
        if (!DERNull.INSTANCE.equals(params)) {
          throw new NoSuchAlgorithmException("algId.parameters != NULL");
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

  public static SignAlgo getInstance(String nameOrOid)
      throws NoSuchAlgorithmException {
    SignAlgo alg = map.get(nameOrOid.toUpperCase().replace("-", ""));
    return Optional.ofNullable(alg).orElseThrow(
        () -> new NoSuchAlgorithmException(
            "Unknown SignAlgo OID/name '" + nameOrOid + "'"));
  }

  public static SignAlgo getInstance(P11Key p11Key)
      throws NoSuchAlgorithmException {
    return getInstance0(p11Key, null);
  }

  public static SignAlgo getInstance(P11Key p11Key, SignerConf signerConf)
      throws NoSuchAlgorithmException {
    return getInstance0(p11Key, signerConf);
  }

  public static SignAlgo getInstance(Key key)
      throws NoSuchAlgorithmException {
    return getInstance0(key, null);
  }

  public static SignAlgo getInstance(Key key, SignerConf signerConf)
      throws NoSuchAlgorithmException {
    return getInstance0(key, signerConf);
  }

  private static SignAlgo getInstance0(Object key, SignerConf signerConf)
      throws NoSuchAlgorithmException {
    SignAlgo algo = null;
    SignAlgoMode mode = null;
    HashAlgo hashAlgo = null;

    if (signerConf != null) {
      try {
        algo = signerConf.getAlgo();
        if (algo == null) {
          mode = signerConf.getMode();
          hashAlgo = signerConf.getHash();
        }
      } catch (InvalidConfException e) {
        throw new NoSuchAlgorithmException(e);
      }
    }

    if (key instanceof RSAKey) {
      int keyBitLen = ((RSAKey) key).getModulus().bitLength();
      return checkRSASignAlgo(algo, mode, hashAlgo, keyBitLen);
    } else if (key instanceof ECKey) {
      EcCurveEnum curve = EcCurveEnum.ofOid(
          KeyUtil.detectCurveOid(((ECKey) key).getParams()));
      return checkECSignAlgo(algo, hashAlgo, curve);
    } else if (key instanceof EdDSAKey) {
      EcCurveEnum curve = EcCurveEnum.ofAlias(((EdDSAKey) key).getAlgorithm());
      return checkECSignAlgo(algo, hashAlgo, curve);
    } else if (key instanceof MLDSAKey) {
      String paramSpec = ((MLDSAKey) key).getParameterSpec().getName();
      return checkMLDSASignAlgo(algo, hashAlgo, paramSpec);
    } else if (key instanceof CompositePublicKey) {
      return checkCompositeSignAlgo(algo, hashAlgo, (CompositePublicKey) key);
    } else if (key instanceof CompositePrivateKey) {
      return checkCompositeSignAlgo(algo, hashAlgo, (CompositePrivateKey) key);
    } else if (key instanceof P11Key) {
      P11Key p11Key = (P11Key) key;
      long keyType = p11Key.getKey().id().getKeyType();
      if (keyType == PKCS11T.CKK_RSA) {
        int keyBitLen = p11Key.getKey().rsaModulus().bitLength();
        return checkRSASignAlgo(algo, mode, hashAlgo, keyBitLen);
      } else if (keyType == PKCS11T.CKK_EC
          || keyType == PKCS11T.CKK_VENDOR_SM2) {
        EcCurveEnum curve = p11Key.getEcParams();
        return checkECSignAlgo(algo, hashAlgo, curve);
      } else if (keyType == PKCS11T.CKK_EC_EDWARDS) {
        EcCurveEnum curve = p11Key.getEcParams();
        return checkECSignAlgo(algo, hashAlgo, curve);
      } else if (keyType == PKCS11T.CKK_ML_DSA) {
        Long variant = p11Key.getKey().pqcVariant();
        if (variant == null) {
          throw new NoSuchAlgorithmException(
              "P11 MLDSA Variant is not present");
        }

        String paramSpec;
        if (variant == PKCS11T.CKP_ML_DSA_44) {
          paramSpec = "ML-DSA-44";
        } else if (variant == PKCS11T.CKP_ML_DSA_65) {
          paramSpec = "ML-DSA-65";
        } else if (variant == PKCS11T.CKP_ML_DSA_87) {
          paramSpec = "ML-DSA-87";
        } else {
          throw new NoSuchAlgorithmException(
              "unsupported MLDSA Variant " + variant);
        }

        return checkMLDSASignAlgo(algo, hashAlgo, paramSpec);
      } else {
        throw new NoSuchAlgorithmException("Unknown key type "
            + PKCS11T.ckkCodeToName(keyType));
      }
    } else if (key instanceof P11CompositeKey) {
      P11CompositeKey p11Key = (P11CompositeKey) key;
      CompositeSigAlgoSuite algoSuite = p11Key.getAlgoSuite();
      if (algo != null) {
        if (algo.compositeSigAlgoSuite != algoSuite) {
          throw new NoSuchAlgorithmException("compositeSigAlgoSuite unmatach");
        }
        return algo;
      } else {
        return SignAlgo.getSignAlgo(algoSuite);
      }
    } else {
      throw new NoSuchAlgorithmException(
          "Unknown key '" + key.getClass().getName());
    }
  } // method getInstance

  private static SignAlgo checkRSASignAlgo(
      SignAlgo algo, SignAlgoMode mode, HashAlgo hashAlgo, int keySize)
      throws NoSuchAlgorithmException {
    if (algo != null) {
      if (algo.isRSASigAlgo()) {
        return algo;
      } else {
        throw new NoSuchAlgorithmException(
            algo + " is not an RSA signature algorithm");
      }
    }

    if (hashAlgo == null) {
      hashAlgo = getDefaultHashAlgo(PKCS11T.CKK_RSA, keySize);
    }
    return getRSAInstance(hashAlgo, mode);
  }

  private static SignAlgo checkECSignAlgo(
      SignAlgo algo, HashAlgo hashAlgo, EcCurveEnum curve)
      throws NoSuchAlgorithmException {
    SignAlgo allowedSignAlgo;
    if (curve == EcCurveEnum.ED25519 || curve == EcCurveEnum.ED448) {
      if (hashAlgo != null) {
        throw new NoSuchAlgorithmException(
            "EDDSA does not allow any hash algorithm");
      }

      allowedSignAlgo = (curve == EcCurveEnum.ED25519)
          ? SignAlgo.ED25519 : ED448;
    } else {
      long keyType = PKCS11T.CKK_EC;
      if (curve == EcCurveEnum.SM2P256V1) {
        keyType = PKCS11T.CKK_VENDOR_SM2;
      }

      int fieldBitSize = curve.getFieldBitSize();
      HashAlgo allowedHashAlgo = getDefaultHashAlgo(keyType, fieldBitSize);
      boolean hashInvalid = (hashAlgo != null && hashAlgo != allowedHashAlgo);
      if (hashInvalid) {
        throw new NoSuchAlgorithmException("hash algo " + hashAlgo +
            " is not allowed for " + curve + " EC key");
      }

      allowedSignAlgo = getWeierstrassECSigAlgo(allowedHashAlgo);
    }

    if (algo != null) {
      if (algo != allowedSignAlgo) {
        throw new NoSuchAlgorithmException("Algo " + algo +
            " is not allowed for " + curve + " EC key");
      }
    }

    return allowedSignAlgo;
  }

  private static SignAlgo checkMLDSASignAlgo(
      SignAlgo algo, HashAlgo hashAlgo, String paramSpec)
      throws NoSuchAlgorithmException {
    if (hashAlgo != null) {
      throw new NoSuchAlgorithmException(
          "ML-DSA does not allow any hash algorithm");
    }
    SignAlgo allowedSignAlgo =
        "ML-DSA-44".equalsIgnoreCase(paramSpec) ? ML_DSA_44
            : "ML-DSA-65".equalsIgnoreCase(paramSpec) ? ML_DSA_65
            : "ML-DSA-87".equalsIgnoreCase(paramSpec) ? ML_DSA_87
            : null;
    if (allowedSignAlgo == null) {
      throw new NoSuchAlgorithmException(
          "unknown ML-DSA paramSpec " + paramSpec);
    }

    if (algo != null) {
      if (algo != allowedSignAlgo) {
        throw new NoSuchAlgorithmException("Algo " + algo +
            " is not allowed for ML-DSA key with paramSpec " + paramSpec);
      }
    }

    return allowedSignAlgo;
  }

  private static SignAlgo checkCompositeSignAlgo(
      SignAlgo algo, HashAlgo hashAlgo, Key key)
      throws NoSuchAlgorithmException {
    if (hashAlgo != null) {
      throw new NoSuchAlgorithmException(
          "Composite ML-DSA  does not allow any hash algorithm");
    }

    AlgorithmIdentifier algId;
    if (key instanceof PublicKey) {
      algId = SubjectPublicKeyInfo.getInstance(key.getEncoded()).getAlgorithm();
    } else {
      PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(key.getEncoded());
      algId = pkInfo.getPrivateKeyAlgorithm();
    }

    SignAlgo allowedSignAlgo = SignAlgo.getInstance(algId);
    if (allowedSignAlgo == null) {
      throw new NoSuchAlgorithmException(
          "unknown key OID " + algId.getAlgorithm());
    }

    if (algo != null) {
      if (algo != allowedSignAlgo) {
        throw new NoSuchAlgorithmException("Algo " + algo +
            " is not allowed for composite ML-DSA key with OID " +
            algId.getAlgorithm());
      }
    } else {
      algo = allowedSignAlgo;
    }

    return algo;
  }

  private static HashAlgo getDefaultHashAlgo(long keyType, int keySize) {
    if (keyType == PKCS11T.CKK_RSA) {
      return keySize > 3084 ? SHA512 :
          keySize > 2048 ? SHA384 : SHA256;
    } else if (keyType == PKCS11T.CKK_VENDOR_SM2) {
      return SM3;
    } else if (keyType == PKCS11T.CKK_EC) {
      return keySize > 384 + 8 ? SHA512 : // plus buffer 8
          keySize > 256 + 8 ? SHA384 : SHA256;
    } else {
      throw new IllegalArgumentException("unknown keyType "
          + PKCS11T.ckkCodeToName(keyType));
    }
  }

  private static SignAlgo getRSAInstance(HashAlgo hashAlgo, SignAlgoMode mode)
      throws NoSuchAlgorithmException {
    Args.notNull(hashAlgo, "hashAlgo");
    boolean rsaPss = mode == SignAlgoMode.RSAPSS;

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
        throw new NoSuchAlgorithmException(
            "unsupported hash " + hashAlgo + " for RSA");
    }
  } // method getRSAInstance

  private static SignAlgo getWeierstrassECSigAlgo(HashAlgo hashAlgo)
      throws NoSuchAlgorithmException {
    Args.notNull(hashAlgo, "hashAlgo");
    if (hashAlgo == SM3) {
      return SM2_SM3;
    }

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
        throw new NoSuchAlgorithmException(
            "unsupported hash " + hashAlgo + " for ECDSA");
    }
  } // method getECDSASigAlgo

  private static SignAlgo getSignAlgo(CompositeSigAlgoSuite algoSuite)
      throws NoSuchAlgorithmException {
    Args.notNull(algoSuite, "algoSuite");
    for (SignAlgo algo : SignAlgo.values()) {
      if (algo.compositeSigAlgoSuite == algoSuite) {
        return algo;
      }
    }

    throw new NoSuchAlgorithmException(
        "unsupported CompositeSigAlgoSuite " + algoSuite);
  }

  public void assertSameAlgorithm(
      AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
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
