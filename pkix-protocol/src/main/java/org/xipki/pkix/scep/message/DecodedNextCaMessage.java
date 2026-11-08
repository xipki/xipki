// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.scep.message;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkix.asn1.cms.Attributes;
import org.xipki.pkix.asn1.cms.ContentInfo;
import org.xipki.pkix.asn1.cms.SignedData;
import org.xipki.pkix.asn1.x509.Attribute;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.AttributeOIDs;
import org.xipki.codec.asn1.oid.CmsOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.cms.CmsSignedData;
import org.xipki.pkix.cms.CmsSigner;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.scep.util.ScepUtil;
import org.xipki.util.exception.PkixException;
import org.xipki.util.misc.LogUtil;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

/**
 * Decoded Next CA Message.
 *
 * @author Lijun Liao (xipki)
 */
public class DecodedNextCaMessage {

  private static final Logger LOG = LoggerFactory.getLogger(DecodedNextCaMessage.class);

  private AuthorityCertStore authorityCertStore;

  private X509Cert signatureCert;

  private HashAlgo digestAlgorithm;

  private Boolean signatureValid;

  private Instant signingTime;

  private String failureMessage;

  public DecodedNextCaMessage() {
  }

  public AuthorityCertStore authorityCertStore() {
    return authorityCertStore;
  }

  public void setAuthorityCertStore(AuthorityCertStore authorityCertStore) {
    this.authorityCertStore = authorityCertStore;
  }

  public X509Cert signatureCert() {
    return signatureCert;
  }

  public void setSignatureCert(X509Cert signatureCert) {
    this.signatureCert = signatureCert;
  }

  public HashAlgo digestAlgorithm() {
    return digestAlgorithm;
  }

  public void setDigestAlgorithm(HashAlgo digestAlgorithm) {
    this.digestAlgorithm = digestAlgorithm;
  }

  public Boolean isSignatureValid() {
    return signatureValid;
  }

  public void setSignatureValid(Boolean signatureValid) {
    this.signatureValid = signatureValid;
  }

  public String failureMessage() {
    return failureMessage;
  }

  public void setFailureMessage(String failureMessage) {
    this.failureMessage = failureMessage;
  }

  public Instant signingTime() {
    return signingTime;
  }

  public void setSigningTime(Instant signingTime) {
    this.signingTime = signingTime;
  }

  @SuppressWarnings("unchecked")
  public static DecodedNextCaMessage decode(
      CmsSignedData pkiMessage, List<Certificate> certStore) throws CodecException {
    Args.notNull(pkiMessage, "pkiMessage");

    CmsSigner signerInfo = ScepUtil.getOnlySigner(pkiMessage);
    Certificate signerCert = ScepUtil.getSignerCert(pkiMessage, signerInfo, certStore);

    Attributes signedAttrs = Optional.ofNullable(
        signerInfo.getSignedAttributes()).orElseThrow(
            () -> new CodecException("missing signed attributes"));

    // signingTime
    Attribute attr = signedAttrs.getOnlyAttribute(AttributeOIDs.signingTime);
    Instant signingTime = (attr == null) ? null : attr.signingTime();

    DecodedNextCaMessage ret = new DecodedNextCaMessage();
    if (signingTime != null) {
      ret.setSigningTime(signingTime);
    }

    try {
      HashAlgo digestAlgo = HashAlgo.getInstance(signerInfo.getDigestAlgorithm());
      ret.setDigestAlgorithm(digestAlgo);

      String sigAlgOid = signerInfo.getSignatureAlgorithm().getAlgorithm().getId();
      if (!AlgorithmOIDs.id_rsaEncryption.getId().equals(sigAlgOid)) {
        SignAlgo signAlgo = SignAlgo.ofAlgorithmIdentifier(
            signerInfo.toASN1Structure().getSignatureAlgorithm());

        if (digestAlgo != signAlgo.hashAlgo()) {
          ret.setFailureMessage("digestAlgorithm and encryptionAlgorithm do " +
              "not use the same digestAlgorithm");
          return ret;
        }
      } // end if
    } catch (NoSuchAlgorithmException ex) {
      LogUtil.error(LOG, ex);
      ret.setFailureMessage(ex.getMessage());
      return ret;
    }

    X509Cert signerX509Cert = new X509Cert(signerCert);
    ret.setSignatureCert(signerX509Cert);

    // validate the signature
    boolean signatureValid;
    try {
      signatureValid = ScepUtil.verifySignature(signerInfo, signerX509Cert);
    } catch (PkixException ex) {
      final String msg = "could not verify the signature";
      LogUtil.error(LOG, ex, msg);
      ret.setFailureMessage(msg + ": " +  ex.getMessage());
      return ret;
    }

    ret.setSignatureValid(signatureValid);
    if (!signatureValid) {
      return ret;
    }

    // MessageData
    Asn1Oid signedContentType = pkiMessage.getContentType();
    if (!CmsOIDs.signedData.equals(signedContentType)) {
      // fall back: some SCEP client use id-data
      if (!CmsOIDs.data.equals(signedContentType)) {
        ret.setFailureMessage("either id-signedData or id-data is excepted, " +
            "but not '" + signedContentType.getId());
        return ret;
      }
    }

    byte[] content = pkiMessage.getContent();
    if (content == null) {
      ret.setFailureMessage("content is absent");
      return ret;
    }
    ContentInfo contentInfo = ContentInfo.fromEncoded(content);

    SignedData signedData = SignedData.fromAsn1(contentInfo.getContent().asSequence());

    List<X509Cert> certs;
    try {
      certs = ScepUtil.getCertsFromSignedData(signedData);
    } catch (CertificateException ex) {
      final String msg = "could not extract Certificates from the message";
      LogUtil.error(LOG, ex, msg);
      ret.setFailureMessage(msg + ": " +  ex.getMessage());
      return ret;
    }

    X509Cert caCert = null;
    List<X509Cert> raCerts = new LinkedList<>();
    for (X509Cert cert : certs) {
      if (cert.basicConstraints() > -1) {
        if (caCert != null) {
          final String msg = "multiple CA certificates is returned, but exactly 1 is expected";
          LOG.error(msg);
          ret.setFailureMessage(msg);
          return ret;
        }

        caCert = cert;
      } else {
        raCerts.add(cert);
      }
    } // end for

    if (caCert == null) {
      final String msg = "no CA certificate is returned";
      LOG.error(msg);
      ret.setFailureMessage(msg);
      return ret;
    }

    X509Cert[] localRaCerts = raCerts.isEmpty() ? null : raCerts.toArray(new X509Cert[0]);

    AuthorityCertStore authorityCertStore = AuthorityCertStore.getInstance(caCert, localRaCerts);
    ret.setAuthorityCertStore(authorityCertStore);

    return ret;
  } // method decode

}
