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

package org.xipki.ocsp.server;

import static org.xipki.util.Args.notEmpty;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.ocsp.server.type.ResponderID;
import org.xipki.ocsp.server.type.TaggedCertSequence;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;

/**
 * Response signer.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class ResponseSigner {

  private final Map<String, ConcurrentContentSigner> algoSignerMap;

  private final List<ConcurrentContentSigner> signers;

  private final TaggedCertSequence sequenceOfCert;

  private final X509Cert cert;

  private final TaggedCertSequence sequenceOfCertChain;

  private final X509Cert[] certChain;

  private final ResponderID responderIdByName;

  private final ResponderID responderIdByKey;

  private final boolean macSigner;

  ResponseSigner(List<ConcurrentContentSigner> signers) throws CertificateException, IOException {
    this.signers = notEmpty(signers, "signers");
    ConcurrentContentSigner firstSigner = signers.get(0);
    this.macSigner = firstSigner.isMac();

    if (this.macSigner) {
      this.responderIdByName = null;
      this.cert = null;
      this.certChain = null;
      this.sequenceOfCert = null;
      this.sequenceOfCertChain = null;

      byte[] keySha1 = firstSigner.getSha1OfMacKey();
      this.responderIdByKey = new ResponderID(keySha1);
    } else {
      X509Cert[] tmpCertChain = firstSigner.getCertificateChain();
      if (tmpCertChain == null || tmpCertChain.length == 0) {
        throw new CertificateException("no certificate is bound with the signer");
      }
      int len = tmpCertChain.length;
      if (len > 1) {
        X509Cert cert = tmpCertChain[len - 1];
        if (cert.getIssuer().equals(cert.getSubject())) {
          len--;
        }
      }
      this.certChain = new X509Cert[len];
      System.arraycopy(tmpCertChain, 0, this.certChain, 0, len);

      this.cert = certChain[0];

      byte[] encodedCert = this.cert.getEncoded();
      this.sequenceOfCert = new TaggedCertSequence(encodedCert);

      byte[][] encodedCertChain = new byte[this.certChain.length][];
      encodedCertChain[0] = encodedCert;
      for (int i = 1; i < certChain.length; i++) {
        encodedCertChain[i] = this.certChain[i].getEncoded();
      }
      this.sequenceOfCertChain = new TaggedCertSequence(encodedCertChain);

      Certificate bcCertificate = Certificate.getInstance(encodedCert);
      this.responderIdByName = new ResponderID(bcCertificate.getSubject());
      byte[] keySha1 = HashAlgo.SHA1.hash(
          bcCertificate.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
      this.responderIdByKey = new ResponderID(keySha1);
    }

    algoSignerMap = new HashMap<>();
    for (ConcurrentContentSigner signer : signers) {
      String algoName = signer.getAlgorithmName();
      algoSignerMap.put(algoName, signer);
    }
  } // constructor

  public boolean isMacSigner() {
    return macSigner;
  }

  public ConcurrentContentSigner getFirstSigner() {
    return signers.get(0);
  }

  public ConcurrentContentSigner getSignerForPreferredSigAlgs(
      List<AlgorithmIdentifier> prefSigAlgs) {
    if (prefSigAlgs == null) {
      return signers.get(0);
    }

    for (AlgorithmIdentifier sigAlgId : prefSigAlgs) {
      String algoName = getSignatureAlgorithmName(sigAlgId);
      if (algoSignerMap.containsKey(algoName)) {
        return algoSignerMap.get(algoName);
      }
    }
    return null;
  }

  public ResponderID getResponderId(boolean byName) {
    return byName ? responderIdByName :  responderIdByKey;
  }

  public X509Cert getCert() {
    return cert;
  }

  public X509Cert[] getCertChain() {
    return certChain;
  }

  public TaggedCertSequence getSequenceOfCert() {
    return sequenceOfCert;
  }

  public TaggedCertSequence getSequenceOfCertChain() {
    return sequenceOfCertChain;
  }

  public boolean isHealthy() {
    for (ConcurrentContentSigner signer : signers) {
      if (!signer.isHealthy()) {
        return false;
      }
    }

    return true;
  }

  private static String getSignatureAlgorithmName(AlgorithmIdentifier sigAlgId) {
    ASN1ObjectIdentifier algOid = sigAlgId.getAlgorithm();
    if (!PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algOid)) {
      return algOid.getId();
    }

    ASN1Encodable asn1Encodable = sigAlgId.getParameters();
    RSASSAPSSparams param = RSASSAPSSparams.getInstance(asn1Encodable);
    ASN1ObjectIdentifier digestAlgOid = param.getHashAlgorithm().getAlgorithm();
    return digestAlgOid.getId() + "WITHRSAANDMGF1";
  }

}
