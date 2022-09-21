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

package org.xipki.scep.message;

import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.xipki.scep.util.ScepUtil;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Get Next CA Response Message.
 *
 * @author Lijun Liao
 */

public class NextCaMessage {

  private X509Cert caCert;

  private List<X509Cert> raCerts;

  public NextCaMessage() {
  }

  public X509Cert getCaCert() {
    return caCert;
  }

  public void setCaCert(X509Cert caCert) {
    this.caCert = caCert;
  }

  public List<X509Cert> getRaCerts() {
    return raCerts;
  }

  public void setRaCerts(List<X509Cert> raCerts) {
    this.raCerts = CollectionUtil.isEmpty(raCerts) ? null : Collections.unmodifiableList(new ArrayList<>(raCerts));
  }

  public ContentInfo encode(PrivateKey signingKey, X509Cert signerCert, X509Cert[] cmsCertSet)
      throws MessageEncodingException {
    Args.notNull(signingKey, "signingKey");
    Args.notNull(signerCert, "signerCert");

    try {
      CMSSignedDataGenerator degenerateSignedData = new CMSSignedDataGenerator();
      degenerateSignedData.addCertificate(caCert.toBcCert());
      if (CollectionUtil.isNotEmpty(raCerts)) {
        for (X509Cert m : raCerts) {
          degenerateSignedData.addCertificate(m.toBcCert());
        }
      }

      byte[] degenratedSignedDataBytes = degenerateSignedData.generate(new CMSAbsentContent()).getEncoded();

      CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

      // I don't know which hash algorithm is supported by the client, use SHA-1
      String signatureAlgo = getSignatureAlgorithm(signingKey, HashAlgo.SHA1);
      ContentSigner signer = new JcaContentSignerBuilder(signatureAlgo).build(signingKey);

      // signerInfo
      JcaSignerInfoGeneratorBuilder signerInfoBuilder = new JcaSignerInfoGeneratorBuilder(
          new BcDigestCalculatorProvider());

      signerInfoBuilder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator());

      SignerInfoGenerator signerInfo = signerInfoBuilder.build(signer, signerCert.toBcCert());
      generator.addSignerInfoGenerator(signerInfo);

      CMSTypedData cmsContent = new CMSProcessableByteArray(CMSObjectIdentifiers.signedData, degenratedSignedDataBytes);

      // certificateSet
      ScepUtil.addCmsCertSet(generator, cmsCertSet);
      return generator.generate(cmsContent, true).toASN1Structure();
    } catch (CMSException | CertificateEncodingException | IOException | OperatorCreationException ex) {
      throw new MessageEncodingException(ex);
    }
  } // method encode

  private static String getSignatureAlgorithm(PrivateKey key, HashAlgo hashAlgo) {
    if ("RSA".equalsIgnoreCase(key.getAlgorithm())) {
      return hashAlgo.getJceName() + "withRSA";
    } else {
      throw new UnsupportedOperationException("getSignatureAlgorithm() for non-RSA is not supported yet.");
    }
  }

}
