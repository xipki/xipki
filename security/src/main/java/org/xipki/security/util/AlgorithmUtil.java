/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.security.util;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.xipki.security.AlgorithmCode;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignatureAlgoControl;
import org.xipki.security.SignerConf;
import org.xipki.util.ParamUtil;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class AlgorithmUtil {

  private static final List<String> curveNames;

  private static final Map<String, ASN1ObjectIdentifier> curveNameToOidMap;

  private static final Map<ASN1ObjectIdentifier, String> curveOidToNameMap;

  private static final Map<ASN1ObjectIdentifier, AlgorithmCode> algOidToCodeMap;

  private static final Map<ASN1ObjectIdentifier, HashAlgo> sigAlgOidToDigestMap;

  private static final Map<ASN1ObjectIdentifier, HashAlgo> macAlgOidToDigestMap;

  private static final Map<HashAlgo, ASN1ObjectIdentifier> digestToECSigAlgMap;

  private static final Map<HashAlgo, ASN1ObjectIdentifier> digestToECPlainSigAlgMap;

  private static final Map<HashAlgo, ASN1ObjectIdentifier> digestToDSASigAlgMap;

  private static final Map<HashAlgo, ASN1ObjectIdentifier> digestToRSASigAlgMap;

  private static final Map<ASN1ObjectIdentifier, String> macAlgOidToNameMap;

  private static final Map<String, ASN1ObjectIdentifier> macAlgNameToOidMap;

  private static final Map<ASN1ObjectIdentifier, String> sigAlgOidToNameMap;

  private static final Map<String, ASN1ObjectIdentifier> sigAlgNameToOidMap;

  private static final Map<ASN1ObjectIdentifier, AlgorithmCode> digestToMgf1AlgCodeMap;

  private static final Map<ASN1ObjectIdentifier, String> digestOidToMgf1SigNameMap;

  private static final Map<String, HashAlgo> mgf1SigNameToDigestOidMap;

  static {
    //----- initialize the static fields curveNames, curveNameOidMap, curveOidNameMap
    {
      List<String> nameList = new LinkedList<>();
      Map<String, ASN1ObjectIdentifier> nameOidMap = new HashMap<>();
      Map<ASN1ObjectIdentifier, String> oidNameMap = new HashMap<>();

      Enumeration<?> names = ECNamedCurveTable.getNames();
      while (names.hasMoreElements()) {
        String name = ((String) names.nextElement()).toLowerCase();
        ASN1ObjectIdentifier oid = org.bouncycastle.asn1.x9.ECNamedCurveTable.getOID(name);
        if (oid == null) {
          continue;
        }

        nameList.add(name);
        nameOidMap.put(name, oid);
        oidNameMap.put(oid, name);
      }

      Collections.sort(nameList);
      curveNames = Collections.unmodifiableList(nameList);
      curveNameToOidMap = Collections.unmodifiableMap(nameOidMap);
      curveOidToNameMap = Collections.unmodifiableMap(oidNameMap);
    }

    //----- Initialize the static fields algNameCodeMap
    {
      Map<ASN1ObjectIdentifier, AlgorithmCode> map = new HashMap<>();
      // HMAC
      map.put(PKCSObjectIdentifiers.id_hmacWithSHA1,   AlgorithmCode.HMAC_SHA1);
      map.put(PKCSObjectIdentifiers.id_hmacWithSHA224, AlgorithmCode.HMAC_SHA224);
      map.put(PKCSObjectIdentifiers.id_hmacWithSHA256, AlgorithmCode.HMAC_SHA256);
      map.put(PKCSObjectIdentifiers.id_hmacWithSHA384, AlgorithmCode.HMAC_SHA384);
      map.put(PKCSObjectIdentifiers.id_hmacWithSHA512, AlgorithmCode.HMAC_SHA512);
      map.put(NISTObjectIdentifiers.id_hmacWithSHA3_224, AlgorithmCode.HMAC_SHA224);
      map.put(NISTObjectIdentifiers.id_hmacWithSHA3_256, AlgorithmCode.HMAC_SHA256);
      map.put(NISTObjectIdentifiers.id_hmacWithSHA3_384, AlgorithmCode.HMAC_SHA384);
      map.put(NISTObjectIdentifiers.id_hmacWithSHA3_512, AlgorithmCode.HMAC_SHA512);

      // GMAC
      map.put(NISTObjectIdentifiers.id_aes128_GCM, AlgorithmCode.AES128_GMAC);
      map.put(NISTObjectIdentifiers.id_aes192_GCM, AlgorithmCode.AES192_GMAC);
      map.put(NISTObjectIdentifiers.id_aes256_GCM, AlgorithmCode.AES256_GMAC);

      // ECDSA
      map.put(X9ObjectIdentifiers.ecdsa_with_SHA1,   AlgorithmCode.SHA1WITHECDSA);
      map.put(X9ObjectIdentifiers.ecdsa_with_SHA224, AlgorithmCode.SHA224WITHECDSA);
      map.put(X9ObjectIdentifiers.ecdsa_with_SHA256, AlgorithmCode.SHA256WITHECDSA);
      map.put(X9ObjectIdentifiers.ecdsa_with_SHA384, AlgorithmCode.SHA384WITHECDSA);
      map.put(X9ObjectIdentifiers.ecdsa_with_SHA512, AlgorithmCode.SHA512WITHECDSA);
      map.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_224, AlgorithmCode.SHA3_224WITHECDSA);
      map.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_256, AlgorithmCode.SHA3_256WITHECDSA);
      map.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_384, AlgorithmCode.SHA3_384WITHECDSA);
      map.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_512, AlgorithmCode.SHA3_512WITHECDSA);
      map.put(BSIObjectIdentifiers.ecdsa_plain_SHA1, AlgorithmCode.SHA1WITHPLAIN_ECDSA);
      map.put(BSIObjectIdentifiers.ecdsa_plain_SHA224, AlgorithmCode.SHA224WITHPLAIN_ECDSA);
      map.put(BSIObjectIdentifiers.ecdsa_plain_SHA256, AlgorithmCode.SHA256WITHPLAIN_ECDSA);
      map.put(BSIObjectIdentifiers.ecdsa_plain_SHA384, AlgorithmCode.SHA384WITHPLAIN_ECDSA);
      map.put(BSIObjectIdentifiers.ecdsa_plain_SHA512, AlgorithmCode.SHA512WITHPLAIN_ECDSA);

      // DSA
      map.put(X9ObjectIdentifiers.id_dsa_with_sha1, AlgorithmCode.SHA1WITHDSA);
      map.put(NISTObjectIdentifiers.dsa_with_sha224, AlgorithmCode.SHA224WITHDSA);
      map.put(NISTObjectIdentifiers.dsa_with_sha256, AlgorithmCode.SHA256WITHDSA);
      map.put(NISTObjectIdentifiers.dsa_with_sha384, AlgorithmCode.SHA384WITHDSA);
      map.put(NISTObjectIdentifiers.dsa_with_sha512, AlgorithmCode.SHA512WITHDSA);
      map.put(NISTObjectIdentifiers.id_dsa_with_sha3_224, AlgorithmCode.SHA3_224WITHDSA);
      map.put(NISTObjectIdentifiers.id_dsa_with_sha3_256, AlgorithmCode.SHA3_256WITHDSA);
      map.put(NISTObjectIdentifiers.id_dsa_with_sha3_384, AlgorithmCode.SHA3_384WITHDSA);
      map.put(NISTObjectIdentifiers.id_dsa_with_sha3_512, AlgorithmCode.SHA3_512WITHDSA);
      // RSA
      map.put(PKCSObjectIdentifiers.sha1WithRSAEncryption, AlgorithmCode.SHA1WITHRSA);
      map.put(PKCSObjectIdentifiers.sha224WithRSAEncryption, AlgorithmCode.SHA224WITHRSA);
      map.put(PKCSObjectIdentifiers.sha256WithRSAEncryption, AlgorithmCode.SHA256WITHRSA);
      map.put(PKCSObjectIdentifiers.sha384WithRSAEncryption, AlgorithmCode.SHA384WITHRSA);
      map.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, AlgorithmCode.SHA512WITHRSA);
      map.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224,
          AlgorithmCode.SHA3_224WITHRSA);
      map.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256,
          AlgorithmCode.SHA3_256WITHRSA);
      map.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384,
          AlgorithmCode.SHA3_384WITHRSA);
      map.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512,
          AlgorithmCode.SHA3_512WITHRSA);

      // SM2
      map.put(GMObjectIdentifiers.sm2sign_with_sm3, AlgorithmCode.SM2WITHSM3);

      // Hash
      for (HashAlgo hashAlgo : HashAlgo.values()) {
        map.put(hashAlgo.getOid(), hashAlgo.getAlgorithmCode());
      }
      algOidToCodeMap = Collections.unmodifiableMap(map);
    }

    //----- Initialize the static field digstMgf1AlgCodeMap
    {
      Map<ASN1ObjectIdentifier, AlgorithmCode> map = new HashMap<>();
      map.put(HashAlgo.SHA1.getOid(),   AlgorithmCode.SHA1WITHRSAANDMGF1);
      map.put(HashAlgo.SHA224.getOid(), AlgorithmCode.SHA224WITHRSAANDMGF1);
      map.put(HashAlgo.SHA256.getOid(), AlgorithmCode.SHA256WITHRSAANDMGF1);
      map.put(HashAlgo.SHA384.getOid(), AlgorithmCode.SHA384WITHRSAANDMGF1);
      map.put(HashAlgo.SHA512.getOid(), AlgorithmCode.SHA512WITHRSAANDMGF1);
      map.put(HashAlgo.SHA3_224.getOid(), AlgorithmCode.SHA3_224WITHRSAANDMGF1);
      map.put(HashAlgo.SHA3_256.getOid(), AlgorithmCode.SHA3_256WITHRSAANDMGF1);
      map.put(HashAlgo.SHA3_384.getOid(), AlgorithmCode.SHA3_384WITHRSAANDMGF1);
      map.put(HashAlgo.SHA3_512.getOid(), AlgorithmCode.SHA3_512WITHRSAANDMGF1);
      digestToMgf1AlgCodeMap = Collections.unmodifiableMap(map);
    }

    //----- Initialize the static fields digestECSigAlgMap, digestECPlainSigAlgMap,
    // digestDSASigAlgMap, digestRSASigAlgMap
    {
      // ECDSA
      Map<HashAlgo, ASN1ObjectIdentifier> map = new HashMap<>();
      map.put(HashAlgo.SHA1,   X9ObjectIdentifiers.ecdsa_with_SHA1);
      map.put(HashAlgo.SHA224, X9ObjectIdentifiers.ecdsa_with_SHA224);
      map.put(HashAlgo.SHA256, X9ObjectIdentifiers.ecdsa_with_SHA256);
      map.put(HashAlgo.SHA384, X9ObjectIdentifiers.ecdsa_with_SHA384);
      map.put(HashAlgo.SHA512, X9ObjectIdentifiers.ecdsa_with_SHA512);
      map.put(HashAlgo.SHA3_224, NISTObjectIdentifiers.id_ecdsa_with_sha3_224);
      map.put(HashAlgo.SHA3_256, NISTObjectIdentifiers.id_ecdsa_with_sha3_256);
      map.put(HashAlgo.SHA3_384, NISTObjectIdentifiers.id_ecdsa_with_sha3_384);
      map.put(HashAlgo.SHA3_512, NISTObjectIdentifiers.id_ecdsa_with_sha3_512);
      digestToECSigAlgMap = Collections.unmodifiableMap(map);

      // PlainECDSA
      map = new HashMap<>();
      map.put(HashAlgo.SHA1,   BSIObjectIdentifiers.ecdsa_plain_SHA1);
      map.put(HashAlgo.SHA224, BSIObjectIdentifiers.ecdsa_plain_SHA224);
      map.put(HashAlgo.SHA256, BSIObjectIdentifiers.ecdsa_plain_SHA256);
      map.put(HashAlgo.SHA384, BSIObjectIdentifiers.ecdsa_plain_SHA384);
      map.put(HashAlgo.SHA512, BSIObjectIdentifiers.ecdsa_plain_SHA512);
      digestToECPlainSigAlgMap = Collections.unmodifiableMap(map);

      // DSA
      map = new HashMap<>();
      map.put(HashAlgo.SHA1,   X9ObjectIdentifiers.id_dsa_with_sha1);
      map.put(HashAlgo.SHA224, NISTObjectIdentifiers.dsa_with_sha224);
      map.put(HashAlgo.SHA256, NISTObjectIdentifiers.dsa_with_sha256);
      map.put(HashAlgo.SHA384, NISTObjectIdentifiers.dsa_with_sha384);
      map.put(HashAlgo.SHA512, NISTObjectIdentifiers.dsa_with_sha512);
      map.put(HashAlgo.SHA3_224, NISTObjectIdentifiers.id_dsa_with_sha3_224);
      map.put(HashAlgo.SHA3_256, NISTObjectIdentifiers.id_dsa_with_sha3_256);
      map.put(HashAlgo.SHA3_384, NISTObjectIdentifiers.id_dsa_with_sha3_384);
      map.put(HashAlgo.SHA3_512, NISTObjectIdentifiers.id_dsa_with_sha3_512);
      digestToDSASigAlgMap = Collections.unmodifiableMap(map);

      // RSA
      map = new HashMap<>();
      map.put(HashAlgo.SHA1,   PKCSObjectIdentifiers.sha1WithRSAEncryption);
      map.put(HashAlgo.SHA224, PKCSObjectIdentifiers.sha224WithRSAEncryption);
      map.put(HashAlgo.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);
      map.put(HashAlgo.SHA384, PKCSObjectIdentifiers.sha384WithRSAEncryption);
      map.put(HashAlgo.SHA512, PKCSObjectIdentifiers.sha512WithRSAEncryption);
      map.put(HashAlgo.SHA3_224, NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224);
      map.put(HashAlgo.SHA3_256, NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256);
      map.put(HashAlgo.SHA3_384, NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384);
      map.put(HashAlgo.SHA3_512, NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512);
      digestToRSASigAlgMap = Collections.unmodifiableMap(map);
    }

    //----- Initialize the static fields sigAlgOidDigestMap
    {
      Map<ASN1ObjectIdentifier, HashAlgo> map = new HashMap<>();
      map.put(X9ObjectIdentifiers.ecdsa_with_SHA1,   HashAlgo.SHA1);
      map.put(X9ObjectIdentifiers.ecdsa_with_SHA224, HashAlgo.SHA224);
      map.put(X9ObjectIdentifiers.ecdsa_with_SHA256, HashAlgo.SHA256);
      map.put(X9ObjectIdentifiers.ecdsa_with_SHA384, HashAlgo.SHA384);
      map.put(X9ObjectIdentifiers.ecdsa_with_SHA512, HashAlgo.SHA512);
      map.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_224, HashAlgo.SHA3_224);
      map.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_256, HashAlgo.SHA3_256);
      map.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_384, HashAlgo.SHA3_384);
      map.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_512, HashAlgo.SHA3_512);
      map.put(BSIObjectIdentifiers.ecdsa_plain_SHA1,   HashAlgo.SHA1);
      map.put(BSIObjectIdentifiers.ecdsa_plain_SHA224, HashAlgo.SHA224);
      map.put(BSIObjectIdentifiers.ecdsa_plain_SHA256, HashAlgo.SHA256);
      map.put(BSIObjectIdentifiers.ecdsa_plain_SHA384, HashAlgo.SHA384);
      map.put(BSIObjectIdentifiers.ecdsa_plain_SHA512, HashAlgo.SHA512);
      map.put(X9ObjectIdentifiers.id_dsa_with_sha1,  HashAlgo.SHA1);
      map.put(NISTObjectIdentifiers.dsa_with_sha224, HashAlgo.SHA224);
      map.put(NISTObjectIdentifiers.dsa_with_sha256, HashAlgo.SHA256);
      map.put(NISTObjectIdentifiers.dsa_with_sha384, HashAlgo.SHA384);
      map.put(NISTObjectIdentifiers.dsa_with_sha512, HashAlgo.SHA512);
      map.put(NISTObjectIdentifiers.id_dsa_with_sha3_224, HashAlgo.SHA3_224);
      map.put(NISTObjectIdentifiers.id_dsa_with_sha3_256, HashAlgo.SHA3_256);
      map.put(NISTObjectIdentifiers.id_dsa_with_sha3_384, HashAlgo.SHA3_384);
      map.put(NISTObjectIdentifiers.id_dsa_with_sha3_512, HashAlgo.SHA3_512);
      map.put(PKCSObjectIdentifiers.sha1WithRSAEncryption,   HashAlgo.SHA1);
      map.put(PKCSObjectIdentifiers.sha224WithRSAEncryption, HashAlgo.SHA224);
      map.put(PKCSObjectIdentifiers.sha256WithRSAEncryption, HashAlgo.SHA256);
      map.put(PKCSObjectIdentifiers.sha384WithRSAEncryption, HashAlgo.SHA384);
      map.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, HashAlgo.SHA512);
      map.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224, HashAlgo.SHA3_224);
      map.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256, HashAlgo.SHA3_256);
      map.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384, HashAlgo.SHA3_384);
      map.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512, HashAlgo.SHA3_512);
      map.put(GMObjectIdentifiers.sm2sign_with_sm3, HashAlgo.SM3);
      sigAlgOidToDigestMap = Collections.unmodifiableMap(map);
    }

    //----- Initialize the static field macAlgOidDigestMap
    {
      Map<ASN1ObjectIdentifier, HashAlgo> map = new HashMap<>();
      map.put(PKCSObjectIdentifiers.id_hmacWithSHA1,   HashAlgo.SHA1);
      map.put(PKCSObjectIdentifiers.id_hmacWithSHA224, HashAlgo.SHA224);
      map.put(PKCSObjectIdentifiers.id_hmacWithSHA256, HashAlgo.SHA256);
      map.put(PKCSObjectIdentifiers.id_hmacWithSHA384, HashAlgo.SHA384);
      map.put(PKCSObjectIdentifiers.id_hmacWithSHA512, HashAlgo.SHA512);
      map.put(NISTObjectIdentifiers.id_hmacWithSHA3_224, HashAlgo.SHA224);
      map.put(NISTObjectIdentifiers.id_hmacWithSHA3_256, HashAlgo.SHA256);
      map.put(NISTObjectIdentifiers.id_hmacWithSHA3_384, HashAlgo.SHA384);
      map.put(NISTObjectIdentifiers.id_hmacWithSHA3_512, HashAlgo.SHA512);
      macAlgOidToDigestMap = Collections.unmodifiableMap(map);
    }

    //----- Initialize the static field macAlgIdNameMap
    {
      Map<ASN1ObjectIdentifier, String> m1 = new HashMap<>();
      Map<String, ASN1ObjectIdentifier> m2 = new HashMap<>();

      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_aes128_GCM, "AES128GMAC");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_aes192_GCM, "AES192GMAC");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_aes256_GCM, "AES256GMAC");
      addOidNameMap(m1, m2, PKCSObjectIdentifiers.id_hmacWithSHA1,   "HMACSHA1");
      addOidNameMap(m1, m2, PKCSObjectIdentifiers.id_hmacWithSHA224, "HMACSHA224");
      addOidNameMap(m1, m2, PKCSObjectIdentifiers.id_hmacWithSHA256, "HMACSHA256");
      addOidNameMap(m1, m2, PKCSObjectIdentifiers.id_hmacWithSHA384, "HMACSHA384");
      addOidNameMap(m1, m2, PKCSObjectIdentifiers.id_hmacWithSHA512, "HMACSHA512");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_hmacWithSHA3_224, "HMACSHA3-224");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_hmacWithSHA3_256, "HMACSHA3-256");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_hmacWithSHA3_384, "HMACSHA3-384");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_hmacWithSHA3_512, "HMACSHA3-512");
      macAlgOidToNameMap = Collections.unmodifiableMap(m1);
      macAlgNameToOidMap = Collections.unmodifiableMap(m2);
    }

    //----- Initialize the static fields sigAlgOidNameMap, digestMgf1SigAlgNameMap.
    {
      Map<ASN1ObjectIdentifier, String> m1 = new HashMap<>();
      Map<String, ASN1ObjectIdentifier> m2 = new HashMap<>();

      addOidNameMap(m1, m2, X9ObjectIdentifiers.ecdsa_with_SHA1, "SHA1WITHECDSA",
          "ECDSAWITHSHA1");
      addOidNameMap(m1, m2, X9ObjectIdentifiers.ecdsa_with_SHA224, "SHA224WITHECDSA",
          "ECDSAWITHSHA224");
      addOidNameMap(m1, m2, X9ObjectIdentifiers.ecdsa_with_SHA256, "SHA256WITHECDSA",
          "ECDSAWITHSHA256");
      addOidNameMap(m1, m2, X9ObjectIdentifiers.ecdsa_with_SHA384, "SHA384WITHECDSA",
          "ECDSAWITHSHA384");
      addOidNameMap(m1, m2, X9ObjectIdentifiers.ecdsa_with_SHA512, "SHA512WITHECDSA",
          "ECDSAWITHSHA512");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_ecdsa_with_sha3_224,
          "SHA3-224WITHECDSA", "ECDSAWITHSHA3-224");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_ecdsa_with_sha3_256,
          "SHA3-256WITHECDSA", "ECDSAWITHSHA3-256");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_ecdsa_with_sha3_384,
          "SHA3-384WITHECDSA", "ECDSAWITHSHA3-384");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_ecdsa_with_sha3_512,
          "SHA3-512WITHECDSA", "ECDSAWITHSHA3-512");
      addOidNameMap(m1, m2, BSIObjectIdentifiers.ecdsa_plain_SHA1,
          "SHA1WITHPLAINECDSA", "PLAINECDSAWITHSHA1");
      addOidNameMap(m1, m2, BSIObjectIdentifiers.ecdsa_plain_SHA224,
          "SHA224WITHPLAIN-ECDSA", "PLAINECDSAWITHSHA224");
      addOidNameMap(m1, m2, BSIObjectIdentifiers.ecdsa_plain_SHA256,
          "SHA256WITHPLAINECDSA", "PLAINECDSAWITHSHA256");
      addOidNameMap(m1, m2, BSIObjectIdentifiers.ecdsa_plain_SHA384,
          "SHA384WITHPLAINECDSA", "PLAINECDSAWITHSHA384");
      addOidNameMap(m1, m2, BSIObjectIdentifiers.ecdsa_plain_SHA512,
          "SHA512WITHPLAINECDSA", "PLAINECDSAWITHSHA512");
      addOidNameMap(m1, m2, X9ObjectIdentifiers.id_dsa_with_sha1, "SHA1WITHDSA",
          "DSAWITHSHA1");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.dsa_with_sha224, "SHA224WITHDSA",
          "DSAWITHSHA224");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.dsa_with_sha256, "SHA256WITHDSA",
          "DSAWITHSHA256");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.dsa_with_sha384, "SHA384WITHDSA",
          "DSAWITHSHA384");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.dsa_with_sha512, "SHA512WITHDSA",
          "DSAWITHSHA512");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_dsa_with_sha3_224, "SHA3-224WITHDSA",
          "DSAWITHSHA3-224");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_dsa_with_sha3_256, "SHA3-256WITHDSA",
          "DSAWITHSHA3-256");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_dsa_with_sha3_384, "SHA3-384WITHDSA",
          "DSAWITHSHA3-384");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_dsa_with_sha3_512, "SHA3-512WITHDSA",
          "DSAWITHSHA3-512");
      addOidNameMap(m1, m2, PKCSObjectIdentifiers.sha1WithRSAEncryption, "SHA1WITHRSA",
          "RSAWITHSHA1");
      addOidNameMap(m1, m2, PKCSObjectIdentifiers.sha224WithRSAEncryption, "SHA224WITHRSA",
          "RSAWITHSHA224");
      addOidNameMap(m1, m2, PKCSObjectIdentifiers.sha256WithRSAEncryption, "SHA256WITHRSA",
          "RSAWITHSHA256");
      addOidNameMap(m1, m2, PKCSObjectIdentifiers.sha384WithRSAEncryption, "SHA384WITHRSA",
          "RSAWITHSHA384");
      addOidNameMap(m1, m2, PKCSObjectIdentifiers.sha512WithRSAEncryption, "SHA512WITHRSA",
          "RSAWITHSHA512");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224,
          "SHA3-224WITHRSA", "RSAWITHSHA3-224");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256,
          "SHA3-256WITHRSA", "RSAWITHSHA3-256");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384,
          "SHA3-384WITHRSA", "RSAWITHSHA3-384");
      addOidNameMap(m1, m2, NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512,
          "SHA3-512WITHRSA", "RSAWITHSHA3-512");
      addOidNameMap(m1, m2, GMObjectIdentifiers.sm2sign_with_sm3, "SM3WITHSM2", "SM2WITHSM3");
      sigAlgOidToNameMap = Collections.unmodifiableMap(m1);
      sigAlgNameToOidMap = Collections.unmodifiableMap(m2);

      m1 = new HashMap<>();
      Map<String, HashAlgo> m3 = new HashMap<>();
      addHashAlgoNameMap(m1, m3, HashAlgo.SHA1,   "SHA1WITHRSAANDMGF1");
      addHashAlgoNameMap(m1, m3, HashAlgo.SHA224, "SHA224WITHRSAANDMGF1");
      addHashAlgoNameMap(m1, m3, HashAlgo.SHA256, "SHA256WITHRSAANDMGF1");
      addHashAlgoNameMap(m1, m3, HashAlgo.SHA384, "SHA384WITHRSAANDMGF1");
      addHashAlgoNameMap(m1, m3, HashAlgo.SHA512, "SHA512WITHRSAANDMGF1");
      addHashAlgoNameMap(m1, m3, HashAlgo.SHA3_224, "SHA3-224WITHRSAANDMGF1");
      addHashAlgoNameMap(m1, m3, HashAlgo.SHA3_256, "SHA3-256WITHRSAANDMGF1");
      addHashAlgoNameMap(m1, m3, HashAlgo.SHA3_384, "SHA3-384WITHRSAANDMGF1");
      addHashAlgoNameMap(m1, m3, HashAlgo.SHA3_512, "SHA3-512WITHRSAANDMGF1");
      digestOidToMgf1SigNameMap = Collections.unmodifiableMap(m1);
      mgf1SigNameToDigestOidMap = Collections.unmodifiableMap(m3);
    }

  }

  private static void addOidNameMap(Map<ASN1ObjectIdentifier, String> oidNameMap,
      Map<String, ASN1ObjectIdentifier> nameOidMap, ASN1ObjectIdentifier oid, String... names) {
    oidNameMap.put(oid, names[0].toUpperCase());
    nameOidMap.put(oid.getId(), oid);
    for (String name : names) {
      nameOidMap.put(name.toUpperCase(), oid);
    }
  }

  private static void addHashAlgoNameMap(Map<ASN1ObjectIdentifier, String> oidNameMap,
      Map<String, HashAlgo> nameOidMap, HashAlgo hashAlgo, String... names) {
    oidNameMap.put(hashAlgo.getOid(), names[0].toUpperCase());
    nameOidMap.put(hashAlgo.getOid().getId(), hashAlgo);
    for (String name : names) {
      nameOidMap.put(name.toUpperCase(), hashAlgo);
    }
  }

  private AlgorithmUtil() {
  }

  public static ASN1ObjectIdentifier getHashAlg(String hashAlgName)
      throws NoSuchAlgorithmException {
    ParamUtil.requireNonNull("hashAlgName", hashAlgName);
    HashAlgo hashAlgo = HashAlgo.getInstance(hashAlgName.toUpperCase());
    if (hashAlgo == null) {
      throw new NoSuchAlgorithmException("Unsupported hash algorithm " + hashAlgName);
    }
    return hashAlgo.getOid();
  } // method getHashAlg

  public static int getHashOutputSizeInOctets(ASN1ObjectIdentifier hashAlgo)
      throws NoSuchAlgorithmException {
    ParamUtil.requireNonNull("hashAlgo", hashAlgo);
    HashAlgo hashAlgoType = HashAlgo.getInstance(hashAlgo);
    if (hashAlgoType == null) {
      throw new NoSuchAlgorithmException("Unsupported hash algorithm " + hashAlgo.getId());
    }
    return hashAlgoType.getLength();
  } // method getHashOutputSizeInOctets

  public static AlgorithmCode getSigOrMacAlgoCode(AlgorithmIdentifier algId)
      throws NoSuchAlgorithmException {
    ASN1ObjectIdentifier oid = algId.getAlgorithm();
    AlgorithmCode code = algOidToCodeMap.get(oid);
    if (code != null) {
      return code;
    }

    if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(oid)) {
      RSASSAPSSparams param = RSASSAPSSparams.getInstance(algId.getParameters());
      ASN1ObjectIdentifier digestAlgOid = param.getHashAlgorithm().getAlgorithm();
      code = digestToMgf1AlgCodeMap.get(digestAlgOid);
      if (code == null) {
        throw new NoSuchAlgorithmException("unsupported digest algorithm " + digestAlgOid);
      }
      return code;
    } else {
      throw new NoSuchAlgorithmException("unsupported signature algorithm " + oid.getId());
    }
  } // method getSignatureAlgoName

  public static String getSigOrMacAlgoName(AlgorithmIdentifier sigAlgId)
      throws NoSuchAlgorithmException {
    ParamUtil.requireNonNull("sigAlgId", sigAlgId);
    ASN1ObjectIdentifier algOid = sigAlgId.getAlgorithm();
    String name = macAlgOidToNameMap.get(algOid);
    return (name != null) ? name : getSignatureAlgoName(sigAlgId);
  }

  public static String getSignatureAlgoName(AlgorithmIdentifier sigAlgId)
      throws NoSuchAlgorithmException {
    ParamUtil.requireNonNull("sigAlgId", sigAlgId);

    ASN1ObjectIdentifier algOid = sigAlgId.getAlgorithm();
    String name = null;
    if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algOid)) {
      RSASSAPSSparams param = RSASSAPSSparams.getInstance(sigAlgId.getParameters());
      ASN1ObjectIdentifier digestAlgOid = param.getHashAlgorithm().getAlgorithm();
      name = digestOidToMgf1SigNameMap.get(digestAlgOid);
      if (name == null) {
        throw new NoSuchAlgorithmException("unsupported digest algorithm " + digestAlgOid);
      }
    } else {
      name = sigAlgOidToNameMap.get(algOid);
    }

    if (name == null) {
      throw new NoSuchAlgorithmException("unsupported signature algorithm " + algOid.getId());
    }
    return name;
  } // method getSignatureAlgoName

  // CHECKSTYLE:SKIP
  public static boolean isDSAPlainSigAlg(AlgorithmIdentifier algId) {
    return isPlainECDSASigAlg(algId);
  }

  public static String canonicalizeSignatureAlgo(String algoName) throws NoSuchAlgorithmException {
    return getSignatureAlgoName(getSigAlgId(algoName));
  }

  public static AlgorithmIdentifier getMacAlgId(String macAlgName) throws NoSuchAlgorithmException {
    ParamUtil.requireNonNull("macAlgName", macAlgName);
    String algoS = macAlgName.toUpperCase();
    algoS = canonicalizeAlgoText(algoS);

    ASN1ObjectIdentifier oid = macAlgNameToOidMap.get(algoS);
    if (oid == null) {
      throw new NoSuchAlgorithmException("unsupported signature algorithm " + algoS);
    }
    return new AlgorithmIdentifier(oid, DERNull.INSTANCE);
  } // method getMacAlgId

  public static AlgorithmIdentifier getSigAlgId(String sigAlgName) throws NoSuchAlgorithmException {
    ParamUtil.requireNonNull("sigAlgName", sigAlgName);
    String algoS = sigAlgName.toUpperCase();
    algoS = canonicalizeAlgoText(algoS);

    AlgorithmIdentifier signatureAlgId;
    if (algoS.contains("MGF1")) {
      HashAlgo ha = mgf1SigNameToDigestOidMap.get(algoS);
      if (ha == null) {
        throw new NoSuchAlgorithmException("unknown algorithm " + algoS);
      }

      signatureAlgId = buildRSAPSSAlgId(ha);
    } else {
      ASN1ObjectIdentifier algOid = sigAlgNameToOidMap.get(algoS);
      if (algOid == null) {
        throw new NoSuchAlgorithmException("unknown algorithm " + algoS);
      }
      boolean withNullParam = algoS.contains("RSA");
      signatureAlgId = withNullParam ? new AlgorithmIdentifier(algOid, DERNull.INSTANCE)
          : new AlgorithmIdentifier(algOid);
    }

    return signatureAlgId;
  } // method getSigAlgId

  public static AlgorithmIdentifier getSigAlgId(PublicKey pubKey, SignerConf signerConf)
      throws NoSuchAlgorithmException {
    ParamUtil.requireNonNull("signerConf", signerConf);
    if (signerConf.getHashAlgo() == null) {
      return getSigAlgId(signerConf.getConfValue("algo"));
    } else {
      SignatureAlgoControl algoControl = signerConf.getSignatureAlgoControl();
      HashAlgo hashAlgo = signerConf.getHashAlgo();

      if (pubKey instanceof RSAPublicKey) {
        boolean rsaMgf1 = (algoControl == null) ? false : algoControl.isRsaMgf1();
        return getRSASigAlgId(hashAlgo, rsaMgf1);
      } else if (pubKey instanceof ECPublicKey) {
        boolean dsaPlain = (algoControl == null) ? false : algoControl.isDsaPlain();
        boolean gm =  (algoControl == null) ? false : algoControl.isGm();
        return getECSigAlgId(hashAlgo, dsaPlain, gm);
      } else if (pubKey instanceof DSAPublicKey) {
        return getDSASigAlgId(hashAlgo);
      } else {
        throw new NoSuchAlgorithmException("Unknown public key '" + pubKey.getClass().getName());
      }
    }
  }

  public static AlgorithmIdentifier getSigAlgId(PublicKey pubKey, HashAlgo hashAlgo,
      SignatureAlgoControl algoControl) throws NoSuchAlgorithmException {
    ParamUtil.requireNonNull("hashAlgo", hashAlgo);

    if (pubKey instanceof RSAPublicKey) {
      boolean rsaMgf1 = (algoControl == null) ? false : algoControl.isRsaMgf1();
      return getRSASigAlgId(hashAlgo, rsaMgf1);
    } else if (pubKey instanceof ECPublicKey) {
      boolean dsaPlain = (algoControl == null) ? false : algoControl.isDsaPlain();
      boolean gm =  (algoControl == null) ? false : algoControl.isGm();
      return getECSigAlgId(hashAlgo, dsaPlain, gm);
    } else if (pubKey instanceof DSAPublicKey) {
      return getDSASigAlgId(hashAlgo);
    } else {
      throw new NoSuchAlgorithmException("Unknown public key '" + pubKey.getClass().getName());
    }
  }

  // CHECKSTYLE:SKIP
  public static boolean isRSASigAlgId(AlgorithmIdentifier algId) {
    ParamUtil.requireNonNull("algId", algId);
    ASN1ObjectIdentifier oid = algId.getAlgorithm();
    if (PKCSObjectIdentifiers.sha1WithRSAEncryption.equals(oid)
        || PKCSObjectIdentifiers.sha224WithRSAEncryption.equals(oid)
        || PKCSObjectIdentifiers.sha256WithRSAEncryption.equals(oid)
        || PKCSObjectIdentifiers.sha384WithRSAEncryption.equals(oid)
        || PKCSObjectIdentifiers.sha512WithRSAEncryption.equals(oid)
        || NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224.equals(oid)
        || NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256.equals(oid)
        || NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384.equals(oid)
        || NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512.equals(oid)
        || PKCSObjectIdentifiers.id_RSASSA_PSS.equals(oid)) {
      return true;
    }

    return false;
  }

  // CHECKSTYLE:SKIP
  public static boolean isECSigAlg(AlgorithmIdentifier algId) {
    return isECDSASigAlg(algId) || isPlainECDSASigAlg(algId);
  }

  // CHECKSTYLE:SKIP
  private static boolean isECDSASigAlg(AlgorithmIdentifier algId) {
    ParamUtil.requireNonNull("algId", algId);

    ASN1ObjectIdentifier oid = algId.getAlgorithm();
    if (X9ObjectIdentifiers.ecdsa_with_SHA1.equals(oid)
        || X9ObjectIdentifiers.ecdsa_with_SHA224.equals(oid)
        || X9ObjectIdentifiers.ecdsa_with_SHA256.equals(oid)
        || X9ObjectIdentifiers.ecdsa_with_SHA384.equals(oid)
        || X9ObjectIdentifiers.ecdsa_with_SHA512.equals(oid)
        || NISTObjectIdentifiers.id_ecdsa_with_sha3_224.equals(oid)
        || NISTObjectIdentifiers.id_ecdsa_with_sha3_256.equals(oid)
        || NISTObjectIdentifiers.id_ecdsa_with_sha3_384.equals(oid)
        || NISTObjectIdentifiers.id_ecdsa_with_sha3_512.equals(oid)) {
      return true;
    }

    return false;
  }

  // CHECKSTYLE:SKIP
  public static boolean isPlainECDSASigAlg(AlgorithmIdentifier algId) {
    ParamUtil.requireNonNull("algId", algId);

    ASN1ObjectIdentifier oid = algId.getAlgorithm();
    if (BSIObjectIdentifiers.ecdsa_plain_SHA1.equals(oid)
        || BSIObjectIdentifiers.ecdsa_plain_SHA224.equals(oid)
        || BSIObjectIdentifiers.ecdsa_plain_SHA256.equals(oid)
        || BSIObjectIdentifiers.ecdsa_plain_SHA384.equals(oid)
        || BSIObjectIdentifiers.ecdsa_plain_SHA512.equals(oid)) {
      return true;
    }

    return false;
  }

  // CHECKSTYLE:SKIP
  public static boolean isSM2SigAlg(AlgorithmIdentifier algId) {
    ParamUtil.requireNonNull("algId", algId);

    ASN1ObjectIdentifier oid = algId.getAlgorithm();
    if (GMObjectIdentifiers.sm2sign_with_sm3.equals(oid)) {
      return true;
    }

    // other algorithms not supported yet.

    return false;
  }

  // CHECKSTYLE:SKIP
  public static boolean isDSASigAlg(AlgorithmIdentifier algId) {
    ParamUtil.requireNonNull("algId", algId);

    ASN1ObjectIdentifier oid = algId.getAlgorithm();
    if (X9ObjectIdentifiers.id_dsa_with_sha1.equals(oid)
        || NISTObjectIdentifiers.dsa_with_sha224.equals(oid)
        || NISTObjectIdentifiers.dsa_with_sha256.equals(oid)
        || NISTObjectIdentifiers.dsa_with_sha384.equals(oid)
        || NISTObjectIdentifiers.dsa_with_sha512.equals(oid)
        || NISTObjectIdentifiers.id_dsa_with_sha3_224.equals(oid)
        || NISTObjectIdentifiers.id_dsa_with_sha3_256.equals(oid)
        || NISTObjectIdentifiers.id_dsa_with_sha3_384.equals(oid)
        || NISTObjectIdentifiers.id_dsa_with_sha3_512.equals(oid)) {
      return true;
    }

    return false;
  }

  // CHECKSTYLE:SKIP
  private static AlgorithmIdentifier getRSASigAlgId(HashAlgo hashAlgo, boolean mgf1)
      throws NoSuchAlgorithmException {
    ParamUtil.requireNonNull("hashAlgo", hashAlgo);
    if (mgf1) {
      return buildRSAPSSAlgId(hashAlgo);
    }

    ASN1ObjectIdentifier sigAlgOid = digestToRSASigAlgMap.get(hashAlgo);
    if (sigAlgOid == null) {
      throw new NoSuchAlgorithmException("unsupported hash " + hashAlgo + " for RSA key");
    }

    return new AlgorithmIdentifier(sigAlgOid, DERNull.INSTANCE);
  } // method getRSASigAlgId

  // CHECKSTYLE:SKIP
  private static AlgorithmIdentifier getDSASigAlgId(HashAlgo hashAlgo)
      throws NoSuchAlgorithmException {
    ParamUtil.requireNonNull("hashAlgo", hashAlgo);

    ASN1ObjectIdentifier sigAlgOid  = digestToDSASigAlgMap.get(hashAlgo);
    if (sigAlgOid == null) {
      throw new NoSuchAlgorithmException("unsupported hash " + hashAlgo + " for DSA key");
    }

    return new AlgorithmIdentifier(sigAlgOid);
  } // method getDSASigAlgId

  // CHECKSTYLE:SKIP
  private static AlgorithmIdentifier getECSigAlgId(HashAlgo hashAlgo, boolean plainSignature,
      boolean gm) throws NoSuchAlgorithmException {
    ParamUtil.requireNonNull("hashAlgo", hashAlgo);
    if (gm && plainSignature) {
      throw new IllegalArgumentException("plainSignature and gm cannot be both true");
    }

    ASN1ObjectIdentifier sigAlgOid;

    if (gm) {
      switch (hashAlgo) {
        case SM3:
          sigAlgOid = GMObjectIdentifiers.sm2sign_with_sm3;
          break;
        default:
          throw new NoSuchAlgorithmException("unsupported hash " + hashAlgo + " for SM2 EC key");
      }
    } else if (plainSignature) {
      sigAlgOid = digestToECPlainSigAlgMap.get(hashAlgo);
      if (sigAlgOid == null) {
        throw new NoSuchAlgorithmException("unsupported hash " + hashAlgo + " for SM2 EC key");
      }
    } else {
      sigAlgOid = digestToECSigAlgMap.get(hashAlgo);
      if (sigAlgOid == null) {
        throw new NoSuchAlgorithmException("unsupported hash " + hashAlgo + " for EC key");
      }
    }

    return new AlgorithmIdentifier(sigAlgOid);
  } // method getECDSASigAlgId

  public static HashAlgo extractHashAlgoFromMacAlg(AlgorithmIdentifier macAlg) {
    ASN1ObjectIdentifier oid = macAlg.getAlgorithm();
    HashAlgo hashAlgo = macAlgOidToDigestMap.get(oid);
    if (hashAlgo == null) {
      throw new IllegalArgumentException("unknown algorithm identifier " + oid.getId());
    }
    return hashAlgo;
  }

  public static AlgorithmIdentifier extractDigesetAlgFromSigAlg(AlgorithmIdentifier sigAlgId)
      throws NoSuchAlgorithmException {
    ASN1ObjectIdentifier algOid = sigAlgId.getAlgorithm();

    ASN1ObjectIdentifier digestAlgOid;
    if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algOid)) {
      ASN1Encodable asn1Encodable = sigAlgId.getParameters();
      RSASSAPSSparams param = RSASSAPSSparams.getInstance(asn1Encodable);
      digestAlgOid = param.getHashAlgorithm().getAlgorithm();
    } else {
      HashAlgo digestAlg = sigAlgOidToDigestMap.get(algOid);
      if (digestAlg == null) {
        throw new NoSuchAlgorithmException("unknown signature algorithm " + algOid.getId());
      }
      digestAlgOid = digestAlg.getOid();
    }

    return new AlgorithmIdentifier(digestAlgOid, DERNull.INSTANCE);
  } // method extractDigesetAlgorithmIdentifier

  public static boolean equalsAlgoName(String algoNameA, String algoNameB) {
    ParamUtil.requireNonBlank("algoNameA", algoNameA);
    ParamUtil.requireNonBlank("algoNameB", algoNameB);
    if (algoNameA.equalsIgnoreCase(algoNameB)) {
      return true;
    }

    String tmpA = algoNameA;
    if (tmpA.indexOf('-') != -1) {
      tmpA = tmpA.replace("-", "");
    }

    String tmpB = algoNameB;
    if (tmpB.indexOf('-') != -1) {
      tmpB = tmpB.replace("-", "");
    }

    if (tmpA.equalsIgnoreCase(tmpB)) {
      return true;
    }

    return splitAlgoNameTokens(tmpA).equals(splitAlgoNameTokens(tmpB));
  }

  private static Set<String> splitAlgoNameTokens(String algoName) {
    ParamUtil.requireNonNull("algoName", algoName);
    String tmpAlgoName = algoName.toUpperCase();
    int idx = tmpAlgoName.indexOf("AND");
    Set<String> set = new HashSet<>();

    if (idx == -1) {
      set.add(tmpAlgoName);
      return set;
    }

    final int len = tmpAlgoName.length();

    int beginIndex = 0;
    int endIndex = idx;
    while (true) {
      String token = tmpAlgoName.substring(beginIndex, endIndex);
      if (StringUtil.isNotBlank(token)) {
        set.add(token);
      }

      if (endIndex >= len) {
        return set;
      }
      beginIndex = endIndex + 3; // 3 = "AND".length()
      endIndex = tmpAlgoName.indexOf("AND", beginIndex);
      if (endIndex == -1) {
        endIndex = len;
      }
    }
  }

  // CHECKSTYLE:SKIP
  private static AlgorithmIdentifier buildRSAPSSAlgId(HashAlgo digestAlg)
      throws NoSuchAlgorithmException {
    RSASSAPSSparams params = createPSSRSAParams(digestAlg);
    return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, params);
  }

  // CHECKSTYLE:SKIP
  private static RSASSAPSSparams createPSSRSAParams(HashAlgo digestAlg)
      throws NoSuchAlgorithmException {
    ParamUtil.requireNonNull("digestAlg", digestAlg);
    int saltSize = digestAlg.getLength();
    AlgorithmIdentifier digAlgId = new AlgorithmIdentifier(digestAlg.getOid(), DERNull.INSTANCE);
    return new RSASSAPSSparams(digAlgId,
        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, digAlgId),
        new ASN1Integer(saltSize), RSASSAPSSparams.DEFAULT_TRAILER_FIELD);
  } // method createPSSRSAParams

  private static ASN1ObjectIdentifier getCurveOidForName(String curveName) {
    ParamUtil.requireNonBlank("curveName", curveName);
    return curveNameToOidMap.get(curveName.toLowerCase());
  }

  // CHECKSTYLE:SKIP
  public static List<String> getECCurveNames() {
    return curveNames;
  }

  public static String getCurveName(ASN1ObjectIdentifier curveOid) {
    ParamUtil.requireNonNull("curveOid", curveOid);
    return curveOidToNameMap.get(curveOid);
  }

  public static ASN1ObjectIdentifier getCurveOidForCurveNameOrOid(String curveNameOrOid) {
    ParamUtil.requireNonBlank("curveNameOrOid", curveNameOrOid);
    ASN1ObjectIdentifier oid;
    try {
      oid = new ASN1ObjectIdentifier(curveNameOrOid);
    } catch (Exception ex) {
      oid = getCurveOidForName(curveNameOrOid);
    }
    return oid;
  }

  private static String canonicalizeAlgoText(String algoText) {
    if (algoText.indexOf('-') == -1) {
      return algoText;
    }

    StringBuilder sb = new StringBuilder(algoText.length());
    for (int i = 0; i < algoText.length(); i++) {
      char cc = algoText.charAt(i);
      if (cc == '-') {
        if (i > 3 && !(algoText.charAt(i - 4) == 'S' && algoText.charAt(i - 3) == 'H'
            && algoText.charAt(i - 2) == 'A' && algoText.charAt(i - 1) == '3')) {
          continue;
        }
      }

      sb.append(cc);
    }

    return sb.toString();
  }

}
