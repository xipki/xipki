// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.scep.message;

import org.bouncycastle.asn1.cms.ContentInfo;
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
import org.xipki.security.HashAlgo;
import org.xipki.security.OIDs;
import org.xipki.security.X509Cert;
import org.xipki.security.scep.util.ScepUtil;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.extra.misc.CollectionUtil;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.util.List;

/**
 * Get Next CA Response Message.
 *
 * @author Lijun Liao (xipki)
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
    this.raCerts = CollectionUtil.isEmpty(raCerts) ? null
        : List.copyOf(raCerts);
  }

  public ContentInfo encode(PrivateKey signingKey, X509Cert signerCert,
                            X509Cert[] cmsCertSet)
      throws CodecException {
    Args.notNull(signingKey, "signingKey");
    Args.notNull(signerCert, "signerCert");

    try {
      CMSSignedDataGenerator degenerateSignedData =
          new CMSSignedDataGenerator();
      degenerateSignedData.addCertificate(caCert.toBcCert());
      if (CollectionUtil.isNotEmpty(raCerts)) {
        for (X509Cert m : raCerts) {
          degenerateSignedData.addCertificate(m.toBcCert());
        }
      }

      byte[] degenratedSignedDataBytes =
          degenerateSignedData.generate(new CMSAbsentContent()).getEncoded();

      CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

      // I don't know which hash algorithm is supported by the client, use SHA-1
      String signatureAlgo = getSignatureAlgorithm(signingKey, HashAlgo.SHA1);
      ContentSigner signer = new JcaContentSignerBuilder(
          signatureAlgo).build(signingKey);

      // signerInfo
      JcaSignerInfoGeneratorBuilder signerInfoBuilder =
          new JcaSignerInfoGeneratorBuilder(new BcDigestCalculatorProvider());

      signerInfoBuilder.setSignedAttributeGenerator(
          new DefaultSignedAttributeTableGenerator());

      SignerInfoGenerator signerInfo =
          signerInfoBuilder.build(signer, signerCert.toBcCert());
      generator.addSignerInfoGenerator(signerInfo);

      CMSTypedData cmsContent = new CMSProcessableByteArray(
          OIDs.CMS.signedData, degenratedSignedDataBytes);

      // certificateSet
      ScepUtil.addCmsCertSet(generator, cmsCertSet);
      return generator.generate(cmsContent, true).toASN1Structure();
    } catch (CMSException | CertificateEncodingException
             | IOException | OperatorCreationException ex) {
      throw new CodecException(ex);
    }
  } // method encode

  private static String getSignatureAlgorithm(
      PrivateKey key, HashAlgo hashAlgo) {
    if ("RSA".equalsIgnoreCase(key.getAlgorithm())) {
      return hashAlgo.getJceName() + "withRSA";
    }
    throw new UnsupportedOperationException(
        "getSignatureAlgorithm() for non-RSA is not supported yet.");
  }

}
