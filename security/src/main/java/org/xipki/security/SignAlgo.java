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

package org.xipki.security;

// CHECKSTYLE:OFF
import static org.bouncycastle.asn1.bsi.BSIObjectIdentifiers.*;
import static org.bouncycastle.asn1.gm.GMObjectIdentifiers.*;
import static org.bouncycastle.asn1.nist.NISTObjectIdentifiers.*;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.*;
import static org.bouncycastle.asn1.x9.X9ObjectIdentifiers.*;
import static org.xipki.security.EdECConstants.*;
import static org.xipki.security.HashAlgo.*;
import static org.xipki.util.Args.notNull;
import static org.bouncycastle.asn1.cms.CMSObjectIdentifiers.*;
//CHECKSTYLE:ON

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PSSParameterSpec;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

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
import org.xipki.security.ObjectIdentifiers.Xipki;
import org.xipki.util.Args;

/**
 * Hash algorithm enum.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
// See https://www.itu.int/ITU-T/formal-language/itu-t/x/x509/2019/AlgorithmObjectIdentifiers.html
public enum SignAlgo {

  // RSA PKCS#1v1.5
  RSA_SHA1("SHA1WITHRSA", 0x01, sha1WithRSAEncryption, SHA1, true),
  RSA_SHA224("SHA224WITHRSA", 0x02, sha224WithRSAEncryption, SHA224, true),
  RSA_SHA256("SHA256WITHRSA", 0x03, sha256WithRSAEncryption, SHA256, true),
  RSA_SHA384("SHA384WITHRSA", 0x04, sha384WithRSAEncryption, SHA384, true),
  RSA_SHA512("SHA512WITHRSA", 0x05, sha512WithRSAEncryption, SHA512, true),

  RSA_SHA3_224("SHA3-224WITHRSA", 0x06, id_rsassa_pkcs1_v1_5_with_sha3_224, SHA3_224, true),
  RSA_SHA3_256("SHA3-256WITHRSA", 0x07, id_rsassa_pkcs1_v1_5_with_sha3_256, SHA3_256, true),
  RSA_SHA3_384("SHA3-384WITHRSA", 0x08, id_rsassa_pkcs1_v1_5_with_sha3_384, SHA3_384, true),
  RSA_SHA3_512("SHA3-512WITHRSA", 0x09, id_rsassa_pkcs1_v1_5_with_sha3_512, SHA3_512, true),

  // RSA PSS with MGF1
  RSAPSS_SHA1("SHA1WITHRSAANDMGF1", 0x11, SHA1),
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
  DSA_SHA1("SHA1WITHDSA", 0x21, id_dsa_with_sha1, SHA1, false),
  DSA_SHA224("SHA224WITHDSA", 0x22, dsa_with_sha224, SHA224, false),
  DSA_SHA256("SHA256WITHDSA", 0x23, dsa_with_sha256, SHA256, false),
  DSA_SHA384("SHA384WITHDSA", 0x24, dsa_with_sha384, SHA384, false),
  DSA_SHA512("SHA512WITHDSA", 0x25, dsa_with_sha512, SHA512, false),

  DSA_SHA3_224("SHA3-224WITHDSA", 0x26, id_dsa_with_sha3_224, SHA3_224, false),
  DSA_SHA3_256("SHA3-256WITHDSA", 0x27, id_dsa_with_sha3_256, SHA3_256, false),
  DSA_SHA3_384("SHA3-384WITHDSA", 0x28, id_dsa_with_sha3_384, SHA3_384, false),
  DSA_SHA3_512("SHA3-512WITHDSA", 0x29, id_dsa_with_sha3_512, SHA3_512, false),

  // ECDSA
  ECDSA_SHA1("SHA1WITHECDSA", 0x31, ecdsa_with_SHA1, SHA1, false),
  ECDSA_SHA224("SHA224WITHECDSA", 0x32, ecdsa_with_SHA224, SHA224, false),
  ECDSA_SHA256("SHA256WITHECDSA", 0x33, ecdsa_with_SHA256, SHA256, false),
  ECDSA_SHA384("SHA384WITHECDSA", 0x34, ecdsa_with_SHA384, SHA384, false),
  ECDSA_SHA512("SHA512WITHECDSA", 0x35, ecdsa_with_SHA512,  SHA512, false),

  ECDSA_SHA3_224("SHA3-224WITHECDSA", 0x36, id_ecdsa_with_sha3_224, SHA3_224, false),
  ECDSA_SHA3_256("SHA3-256WITHECDSA", 0x37, id_ecdsa_with_sha3_256, SHA3_256, false),
  ECDSA_SHA3_384("SHA3-384WITHECDSA", 0x38, id_ecdsa_with_sha3_384, SHA3_384, false),
  ECDSA_SHA3_512("SHA3-512WITHECDSA", 0x39, id_ecdsa_with_sha3_512,  SHA3_512, false),

  // SM2
  SM2_SM3("SM3WITHSM2", 0x3A, sm2sign_with_sm3, SM3, false),

  // ECDSA with SHAKE
  ECDSA_SHAKE128("SHAKE128WITHECDSA", 0x3B, id_ecdsa_with_shake128, SHAKE128, false),
  ECDSA_SHAKE256("SHAKE256WITHECDSA", 0x3C, id_ecdsa_with_shake256, SHAKE256, false),

  // Plain ECDSA
  PLAINECDSA_SHA1("SHA1WITHPLAINECDSA", 0x41, ecdsa_plain_SHA1, SHA1, false),
  PLAINECDSA_SHA224("SHA224WITHPLAINECDSA", 0x42, ecdsa_plain_SHA224, SHA224, false),
  PLAINECDSA_SHA256("SHA256WITHPLAINECDSA", 0x43, ecdsa_plain_SHA256, SHA256, false),
  PLAINECDSA_SHA384("SHA384WITHPLAINECDSA", 0x44, ecdsa_plain_SHA384, SHA384, false),
  PLAINECDSA_SHA512("SHA512WITHPLAINECDSA", 0x45, ecdsa_plain_SHA512, SHA512, false),

  // EdDSA
  ED25519("ED25519", 0x46, id_ED25519, null, false),

  ED448("ED448", 0x47, id_ED448, null, false),

  // HMAC
  HMAC_SHA1("HMACSHA1", 0x51, id_hmacWithSHA1, SHA1, true),
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
  GMAC_AES128("AES128GMAC", 0x61, new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.9")),
  GMAC_AES192("AES192GMAC", 0x62, new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.29")),
  GMAC_AES256("AES256GMAC", 0x63, new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.49")),

  //DHPOC-MAC
  DHPOP_X25519("DHPOP-X25519", 0x5A, Xipki.id_alg_dhPop_x25519, SHA512, false);

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
          String before = name.substring(0, index);
          String after = name.substring(index + "WITH".length());

          String inverseName = after + "WITH" + before;
          map.put(inverseName, type);
          if (withMinus) {
            map.put(inverseName.replace("-", ""), type);
          }
        }
      }
    }
  }

  private SignAlgo(String jceName, int code, ASN1ObjectIdentifier oid,
      HashAlgo hashAlgo, boolean withNullParams) {
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
  private SignAlgo(String jceName, int code, HashAlgo hashAlgo) {
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
  private SignAlgo(String jceName, int code, ASN1ObjectIdentifier oid) {
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

    // nonce here is only place holder, must be replaced before use: we use default
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

  public Signature newSignature()
      throws NoSuchAlgorithmException {
    return Signature.getInstance(jceName);
  }

  public Signature newSignature(String provider)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    return Signature.getInstance(jceName, provider);
  }

  // CHECKSTYLE:SKIP
  public boolean isDSASigAlgo() {
    switch (this) {
      case DSA_SHA1:
      case DSA_SHA224:
      case DSA_SHA256:
      case DSA_SHA384:
      case DSA_SHA512:
      case DSA_SHA3_224:
      case DSA_SHA3_256:
      case DSA_SHA3_384:
      case DSA_SHA3_512:
        return true;
      default:
        return false;
    }
  } // method isDSASigAlg

  // CHECKSTYLE:SKIP
  public boolean isECDSASigAlgo() {
    switch (this) {
      case ECDSA_SHA1:
      case ECDSA_SHA224:
      case ECDSA_SHA256:
      case ECDSA_SHA384:
      case ECDSA_SHA512:
      case ECDSA_SHA3_224:
      case ECDSA_SHA3_256:
      case ECDSA_SHA3_384:
      case ECDSA_SHA3_512:
      case ECDSA_SHAKE128:
      case ECDSA_SHAKE256:
        return true;
      default:
        return false;
    }
  } // method isECDSASigAlg

  // CHECKSTYLE:SKIP
  public boolean isEDDSASigAlgo() {
    switch (this) {
      case ED25519:
      case ED448:
        return true;
      default:
        return false;
    }
  } // method isEDDSASigAlg

  // CHECKSTYLE:SKIP
  public boolean isPlainECDSASigAlgo() {
    switch (this) {
      case PLAINECDSA_SHA1:
      case PLAINECDSA_SHA224:
      case PLAINECDSA_SHA256:
      case PLAINECDSA_SHA384:
      case PLAINECDSA_SHA512:
        return true;
      default:
        return false;
    }
  } // method isPlainECDSASigAlg

  // CHECKSTYLE:SKIP
  public boolean isSM2SigAlgo() {
    ASN1ObjectIdentifier oid = notNull(algId, "algId").getAlgorithm();
    if (GMObjectIdentifiers.sm2sign_with_sm3.equals(oid)) {
      return true;
    }

    // other algorithms not supported yet.
    return false;
  } // method isSM2SigAlg

  // CHECKSTYLE:SKIP
  public boolean isRSAPkcs1SigAlgo() {
    switch (this) {
      case RSA_SHA1:
      case RSA_SHA224:
      case RSA_SHA256:
      case RSA_SHA384:
      case RSA_SHA512:
      case RSA_SHA3_224:
      case RSA_SHA3_256:
      case RSA_SHA3_384:
      case RSA_SHA3_512:
        return true;
      default:
        return false;
    }
  } // method isRSASigAlgo

  // CHECKSTYLE:SKIP
  public boolean isRSAPSSSigAlgo() {
    if (isRSAPSSMGF1SigAlgo()) {
      return true;
    }

    switch (this) {
      case RSAPSS_SHAKE128:
      case RSAPSS_SHAKE256:
        return true;
      default:
        return false;
    }
  } // method isRSAPSSSigAlgo

  // CHECKSTYLE:SKIP
  public boolean isRSAPSSMGF1SigAlgo() {
    switch (this) {
      case RSAPSS_SHA1:
      case RSAPSS_SHA224:
      case RSAPSS_SHA256:
      case RSAPSS_SHA384:
      case RSAPSS_SHA512:
      case RSAPSS_SHA3_224:
      case RSAPSS_SHA3_256:
      case RSAPSS_SHA3_384:
      case RSAPSS_SHA3_512:
        return true;
      default:
        return false;
    }
  } // method isRSAPSSMGF1SigAlgo

  public boolean isHmac() {
    switch (this) {
      case HMAC_SHA1:
      case HMAC_SHA224:
      case HMAC_SHA256:
      case HMAC_SHA384:
      case HMAC_SHA512:
      case HMAC_SHA3_224:
      case HMAC_SHA3_256:
      case HMAC_SHA3_384:
        return true;
      default:
        return false;
    }
  }

  public boolean isGmac() {
    switch (this) {
      case GMAC_AES128:
      case GMAC_AES192:
      case GMAC_AES256:
        return true;
      default:
        return false;
    }
  }

  public boolean isMac() {
    return isHmac() || isGmac();
  }

  public static SignAlgo getInstance(AlgorithmIdentifier algId)
      throws NoSuchAlgorithmException {
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

      AlgorithmIdentifier mgfDigestAlgId = AlgorithmIdentifier.getInstance(
          mgf.getParameters());
      if (!digestAlgId.equals(mgfDigestAlgId)) {
        throw new NoSuchAlgorithmException("digestAlg != MGF1.digestAlg");
      }

      if (PSSParameterSpec.TRAILER_FIELD_BC != param.getTrailerField().intValueExact()) {
        return null;
      }

      HashAlgo hashAlgo = HashAlgo.getInstance(digestAlgId);
      if (hashAlgo == null) {
        throw new NoSuchAlgorithmException("hash != MGF1");
      }

      if (hashAlgo.getLength() != param.getSaltLength().intValueExact()) {
        return null;
      }

      return mgf1HashToSigMap.get(hashAlgo);
    } else if (SignAlgo.GMAC_AES128.oid.equals(oid)
        || SignAlgo.GMAC_AES192.oid.equals(oid)
        || SignAlgo.GMAC_AES256.oid.equals(oid)) {
      if (SignAlgo.GMAC_AES128.equals(oid)) {
        return SignAlgo.GMAC_AES128;
      } else if (SignAlgo.GMAC_AES128.equals(oid)) {
        return SignAlgo.GMAC_AES192;
      } else {
        return SignAlgo.GMAC_AES256;
      }
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

  public static SignAlgo getInstance(String nameOrOid)
      throws NoSuchAlgorithmException {
    SignAlgo alg = map.get(nameOrOid.toUpperCase());
    if (alg == null) {
      throw new NoSuchAlgorithmException(
          "Unknown HashAlgo OID/name '" + nameOrOid + "'");
    }
    return alg;
  }

  public static SignAlgo getInstance(Key key, SignerConf signerConf)
      throws NoSuchAlgorithmException {
    if (notNull(signerConf, "signerConf").getHashAlgo() == null) {
      return getInstance(signerConf.getConfValue("algo"));
    }

    SignatureAlgoControl algoControl = signerConf.getSignatureAlgoControl();
    HashAlgo hashAlgo = signerConf.getHashAlgo();

    if (key instanceof RSAPublicKey || key instanceof RSAPrivateKey) {
      boolean rsaPss = (algoControl == null) ? false : algoControl.isRsaPss();
      return getRSAInstance(hashAlgo, rsaPss);
    } else if (key instanceof ECPublicKey || key instanceof ECPrivateKey) {
      boolean dsaPlain = (algoControl == null) ? false : algoControl.isDsaPlain();
      boolean gm =  (algoControl == null) ? false : algoControl.isGm();
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

  public static SignAlgo getInstance(Key key, HashAlgo hashAlgo,
      SignatureAlgoControl algoControl)
          throws NoSuchAlgorithmException {
    notNull(hashAlgo, "hashAlgo");
    notNull(key, "key");

    if (key instanceof RSAPublicKey || key instanceof RSAPrivateKey) {
      boolean rsaPss = (algoControl == null) ? false : algoControl.isRsaPss();
      return getRSAInstance(hashAlgo, rsaPss);
    } else if (key instanceof ECPublicKey || key instanceof ECPrivateKey) {
      boolean dsaPlain = (algoControl == null) ? false : algoControl.isDsaPlain();
      boolean gm =  (algoControl == null) ? false : algoControl.isGm();
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

  // CHECKSTYLE:SKIP
  private static SignAlgo getRSAInstance(HashAlgo hashAlgo, boolean rsaPss)
      throws NoSuchAlgorithmException {
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

  // CHECKSTYLE:SKIP
  private static SignAlgo getDSASigAlgo(HashAlgo hashAlgo)
      throws NoSuchAlgorithmException {
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

  // CHECKSTYLE:SKIP
  private static SignAlgo getECSigAlgo(HashAlgo hashAlgo, boolean plainSignature,
      boolean gm)
          throws NoSuchAlgorithmException {
    notNull(hashAlgo, "hashAlgo");
    if (gm && plainSignature) {
      throw new IllegalArgumentException("plainSignature and gm cannot be both true");
    }

    if (gm) {
      switch (hashAlgo) {
        case SM3:
          return SM2_SM3;
        default:
          throw new NoSuchAlgorithmException("unsupported hash " + hashAlgo + " for SM2");
      }
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
    if (!sigAlgId.equals(sigAlgId)) {
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
