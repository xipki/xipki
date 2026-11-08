// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.scep.message;

import org.xipki.asn1.cms.ContentInfo;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.asn1.oid.CmsOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.cms.CmsSignedData;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.scep.util.ScepUtil;
import org.xipki.pkix.sign.SignatureSigner;
import org.xipki.util.exception.PkixException;
import org.xipki.util.misc.CollectionUtil;

import java.security.PrivateKey;
import java.util.List;

/**
 * Next CA Message.
 *
 * @author Lijun Liao (xipki)
 */
public class NextCaMessage {

  private X509Cert caCert;

  private List<X509Cert> raCerts;

  public NextCaMessage() {
  }

  public X509Cert caCert() {
    return caCert;
  }

  public void setCaCert(X509Cert caCert) {
    this.caCert = caCert;
  }

  public void setRaCerts(List<X509Cert> raCerts) {
    this.raCerts = CollectionUtil.isEmpty(raCerts) ? null : List.copyOf(raCerts);
  }

  public ContentInfo encode(PrivateKey signingKey, X509Cert signerCert, X509Cert[] cmsCertSet)
      throws CodecException {
    Args.notNull(signingKey, "signingKey");
    Args.notNull(signerCert, "signerCert");
    Args.notNull(caCert, "caCert");

    try {
      CmsSignedData.Builder degenerateSignedData = new CmsSignedData.Builder();
      degenerateSignedData.addCertificate(caCert.getCert());
      if (CollectionUtil.isNotEmpty(raCerts)) {
        for (X509Cert m : raCerts) {
          degenerateSignedData.addCertificate(m.getCert());
        }
      }

      byte[] degenratedSignedDataBytes = degenerateSignedData.build().getEncoded();

      // I don't know which hash algorithm is supported by the client, use SHA-1
      if (!"RSA".equalsIgnoreCase(signingKey.getAlgorithm())) {
        throw new UnsupportedOperationException("non-RSA signing key is not supported yet");
      }
      ContentSigner signer = SignatureSigner.newContentSigner(SignAlgo.RSA_SHA1, signingKey);

      CmsSignedData.Builder builder = new CmsSignedData.Builder()
          .setContent(CmsOIDs.signedData, degenratedSignedDataBytes, true)
          .addSigner(signer, signerCert.getCert(), HashAlgo.SHA1.algorithmIdentifier(),
              null, null);

      // certificateSet
      ScepUtil.addCmsCertSet(builder, cmsCertSet);
      return builder.build().toASN1Structure();
    } catch (PkixException | XiSecurityException ex) {
      throw new CodecException(ex);
    }
  } // method encode

}
