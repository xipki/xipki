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

package org.xipki.ocsp.client;

import static org.xipki.util.Args.positive;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xipki.security.HashAlgo;
import org.xipki.security.ObjectIdentifiers.Shake;

/**
 * OCSP request options.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RequestOptions {

  private static final Map<String, AlgorithmIdentifier> SIGALGS_MAP = new HashMap<>();

  static {
    String[] algoNames = {"SHA1WITHRSA", "SHA256WITHRSA", "SHA384WITHRSA", "SHA512WITHRSA",
      "SHA1WITHECDSA", "SHA256WITHECDSA", "SHA384WITHECDSA", "SHA512WITHECDSA",
      "SHA1WITHRSAANDMGF1", "SHA256WITHRSAANDMGF1", "SHA384WITHRSAANDMGF1", "SHA512WITHRSAANDMGF1"};

    for (String algoName : algoNames) {
      SIGALGS_MAP.put(algoName.toUpperCase(), createAlgId(algoName));
    }
  }

  private boolean signRequest;

  private boolean useNonce = true;

  private int nonceLen = 8;

  private boolean allowNoNonceInResponse;

  private boolean useHttpGetForRequest;

  private ASN1ObjectIdentifier hashAlgorithmId = NISTObjectIdentifiers.id_sha256;

  private List<AlgorithmIdentifier> preferredSignatureAlgorithms;

  public RequestOptions() {
  }

  public boolean isUseNonce() {
    return useNonce;
  }

  public void setUseNonce(boolean useNonce) {
    this.useNonce = useNonce;
  }

  public int getNonceLen() {
    return nonceLen;
  }

  public void setNonceLen(int nonceLen) {
    this.nonceLen = positive(nonceLen, "nonceLen");
  }

  public ASN1ObjectIdentifier getHashAlgorithmId() {
    return hashAlgorithmId;
  }

  public void setHashAlgorithmId(ASN1ObjectIdentifier hashAlgorithmId) {
    this.hashAlgorithmId = hashAlgorithmId;
  }

  public List<AlgorithmIdentifier> getPreferredSignatureAlgorithms() {
    return preferredSignatureAlgorithms;
  }

  public void setPreferredSignatureAlgorithms(
      AlgorithmIdentifier[] preferredSignatureAlgorithms) {
    this.preferredSignatureAlgorithms = Arrays.asList(preferredSignatureAlgorithms);
  }

  public void setPreferredSignatureAlgorithms(String[] preferredSignatureAlgoNames) {
    if (preferredSignatureAlgoNames == null || preferredSignatureAlgoNames.length == 0) {
      this.preferredSignatureAlgorithms = null;
      return;
    }

    for (String algoName : preferredSignatureAlgoNames) {
      AlgorithmIdentifier sigAlgId = SIGALGS_MAP.get(algoName.toUpperCase());
      if (sigAlgId == null) {
        // ignore it
        continue;
      }

      if (this.preferredSignatureAlgorithms == null) {
        this.preferredSignatureAlgorithms = new ArrayList<>(preferredSignatureAlgoNames.length);
      }
      this.preferredSignatureAlgorithms.add(sigAlgId);
    }
  }

  public boolean isUseHttpGetForRequest() {
    return useHttpGetForRequest;
  }

  public void setUseHttpGetForRequest(boolean useHttpGetForRequest) {
    this.useHttpGetForRequest = useHttpGetForRequest;
  }

  public boolean isSignRequest() {
    return signRequest;
  }

  public void setSignRequest(boolean signRequest) {
    this.signRequest = signRequest;
  }

  public boolean isAllowNoNonceInResponse() {
    return allowNoNonceInResponse;
  }

  public void setAllowNoNonceInResponse(boolean allowNoNonceInResponse) {
    this.allowNoNonceInResponse = allowNoNonceInResponse;
  }

  private static AlgorithmIdentifier createAlgId(String algoName) {
    algoName = algoName.toUpperCase();
    ASN1ObjectIdentifier algOid = null;

    ASN1Encodable params = null;

    if ("SHA1WITHRSA".equals(algoName)) {
      algOid = PKCSObjectIdentifiers.sha1WithRSAEncryption;
      params = DERNull.INSTANCE;
    } else if ("SHA256WITHRSA".equals(algoName)) {
      algOid = PKCSObjectIdentifiers.sha256WithRSAEncryption;
      params = DERNull.INSTANCE;
    } else if ("SHA384WITHRSA".equals(algoName)) {
      algOid = PKCSObjectIdentifiers.sha384WithRSAEncryption;
      params = DERNull.INSTANCE;
    } else if ("SHA512WITHRSA".equals(algoName)) {
      algOid = PKCSObjectIdentifiers.sha512WithRSAEncryption;
      params = DERNull.INSTANCE;
    } else if ("SHAKE128WITHRSAPSS".equals(algoName)) {
      algOid = Shake.id_RSASSA_PSS_SHAKE128;
    } else if ("SHAKE256WITHRSAPSS".equals(algoName)) {
      algOid = Shake.id_RSASSA_PSS_SHAKE256;
    } else if ("SHA1WITHECDSA".equals(algoName)) {
      algOid = X9ObjectIdentifiers.ecdsa_with_SHA1;
    } else if ("SHA256WITHECDSA".equals(algoName)) {
      algOid = X9ObjectIdentifiers.ecdsa_with_SHA256;
    } else if ("SHA384WITHECDSA".equals(algoName)) {
      algOid = X9ObjectIdentifiers.ecdsa_with_SHA384;
    } else if ("SHA512WITHECDSA".equals(algoName)) {
      algOid = X9ObjectIdentifiers.ecdsa_with_SHA512;
    } else if ("SHAKE128WITHECDSA".equals(algoName)) {
      algOid = Shake.id_ecdsa_with_shake128;
    } else if ("SHAKE256WITHECDSA".equals(algoName)) {
      algOid = Shake.id_ecdsa_with_shake256;
    } else if ("SHA1WITHRSAANDMGF1".equals(algoName) || "SHA256WITHRSAANDMGF1".equals(algoName)
        || "SHA384WITHRSAANDMGF1".equals(algoName) || "SHA512WITHRSAANDMGF1".equals(algoName)) {
      algOid = PKCSObjectIdentifiers.id_RSASSA_PSS;

      ASN1ObjectIdentifier digestAlgOid = null;
      if ("SHA1WITHRSAANDMGF1".equals(algoName)) {
        digestAlgOid = X509ObjectIdentifiers.id_SHA1;
      } else if ("SHA256WITHRSAANDMGF1".equals(algoName)) {
        digestAlgOid = NISTObjectIdentifiers.id_sha256;
      } else if ("SHA384WITHRSAANDMGF1".equals(algoName)) {
        digestAlgOid = NISTObjectIdentifiers.id_sha384;
      } else { // if ("SHA512WITHRSAANDMGF1".equals(algoName))
        digestAlgOid = NISTObjectIdentifiers.id_sha512;
      }
      params = createPSSRSAParams(digestAlgOid);
    } else {
      throw new IllegalStateException("Unsupported algorithm " + algoName); // should not happen
    }

    return new AlgorithmIdentifier(algOid, params);
  } // method createAlgId

  // CHECKSTYLE:SKIP
  public static RSASSAPSSparams createPSSRSAParams(ASN1ObjectIdentifier digestAlgOid) {
    int saltSize;
    if (X509ObjectIdentifiers.id_SHA1.equals(digestAlgOid)) {
      saltSize = 20;
    } else if (NISTObjectIdentifiers.id_sha224.equals(digestAlgOid)) {
      saltSize = 28;
    } else if (NISTObjectIdentifiers.id_sha256.equals(digestAlgOid)) {
      saltSize = 32;
    } else if (NISTObjectIdentifiers.id_sha384.equals(digestAlgOid)) {
      saltSize = 48;
    } else if (NISTObjectIdentifiers.id_sha512.equals(digestAlgOid)) {
      saltSize = 64;
    } else {
      throw new IllegalStateException("unknown digest algorithm " + digestAlgOid);
    }

    AlgorithmIdentifier digAlgId = HashAlgo.getInstance(digestAlgOid).getAlgorithmIdentifier();
    return new RSASSAPSSparams(digAlgId,
        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, digAlgId),
        new ASN1Integer(saltSize), RSASSAPSSparams.DEFAULT_TRAILER_FIELD);
  } // method createPSSRSAParams

}
