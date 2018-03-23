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

package org.xipki.scep.message;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.xipki.scep.crypto.ScepHashAlgo;
import org.xipki.scep.exception.MessageEncodingException;
import org.xipki.scep.util.ScepUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public class NextCaMessage {

  private X509Certificate caCert;

  private List<X509Certificate> raCerts;

  public NextCaMessage() {
  }

  public X509Certificate getCaCert() {
    return caCert;
  }

  public void setCaCert(X509Certificate caCert) {
    this.caCert = caCert;
  }

  public List<X509Certificate> getRaCerts() {
    return raCerts;
  }

  public void setRaCerts(List<X509Certificate> raCerts) {
    this.raCerts = (raCerts == null || raCerts.isEmpty()) ? null
        : Collections.unmodifiableList(new ArrayList<X509Certificate>(raCerts));
  }

  public ContentInfo encode(PrivateKey signingKey, X509Certificate signerCert,
      X509Certificate[] cmsCertSet) throws MessageEncodingException {
    ScepUtil.requireNonNull("signingKey", signingKey);
    ScepUtil.requireNonNull("signerCert", signerCert);

    try {
      byte[] degenratedSignedDataBytes;
      try {
        CMSSignedDataGenerator degenerateSignedData = new CMSSignedDataGenerator();
        degenerateSignedData.addCertificate(new X509CertificateHolder(caCert.getEncoded()));
        if (raCerts != null && !raCerts.isEmpty()) {
          for (X509Certificate m : raCerts) {
            degenerateSignedData.addCertificate(new X509CertificateHolder(m.getEncoded()));
          }
        }

        degenratedSignedDataBytes = degenerateSignedData.generate(
            new CMSAbsentContent()).getEncoded();
      } catch (CertificateEncodingException ex) {
        throw new MessageEncodingException(ex.getMessage(), ex);
      }

      CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

      // I don't known which hash algorithm is supported by the client, use SHA-1
      String signatureAlgo = getSignatureAlgorithm(signingKey, ScepHashAlgo.SHA1);
      ContentSigner signer = new JcaContentSignerBuilder(signatureAlgo).build(signingKey);

      // signerInfo
      JcaSignerInfoGeneratorBuilder signerInfoBuilder = new JcaSignerInfoGeneratorBuilder(
          new BcDigestCalculatorProvider());

      signerInfoBuilder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator());

      SignerInfoGenerator signerInfo = signerInfoBuilder.build(signer, signerCert);
      generator.addSignerInfoGenerator(signerInfo);

      CMSTypedData cmsContent = new CMSProcessableByteArray(CMSObjectIdentifiers.signedData,
          degenratedSignedDataBytes);

      // certificateSet
      ScepUtil.addCmsCertSet(generator, cmsCertSet);
      return generator.generate(cmsContent, true).toASN1Structure();
    } catch (CMSException | CertificateEncodingException | IOException
        | OperatorCreationException ex) {
      throw new MessageEncodingException(ex);
    }
  } // method encode

  private static String getSignatureAlgorithm(PrivateKey key, ScepHashAlgo hashAlgo) {
    String algorithm = key.getAlgorithm();
    if ("RSA".equalsIgnoreCase(algorithm)) {
      return hashAlgo.getName() + "withRSA";
    } else {
      throw new UnsupportedOperationException(
          "getSignatureAlgorithm() for non-RSA is not supported yet.");
    }
  }

}
