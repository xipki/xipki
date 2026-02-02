// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.scep.message;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.CollectionStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.HashAlgo;
import org.xipki.security.OIDs;
import org.xipki.security.SignAlgo;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.scep.util.ScepUtil;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.LogUtil;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

/**
 * Decoded {@link NextCaMessage}.
 *
 * @author Lijun Liao (xipki)
 */

public class DecodedNextCaMessage {

  private static final Logger LOG =
      LoggerFactory.getLogger(DecodedNextCaMessage.class);

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
      CMSSignedData pkiMessage,
      CollectionStore<X509CertificateHolder> certStore) throws CodecException {
    Args.notNull(pkiMessage, "pkiMessage");

    SignerInformationStore signerStore = pkiMessage.getSignerInfos();
    Collection<SignerInformation> signerInfos = signerStore.getSigners();
    if (signerInfos.size() != 1) {
      throw new CodecException("number of signerInfos is not 1, but "
          + signerInfos.size());
    }

    SignerInformation signerInfo = signerInfos.iterator().next();

    SignerId sid = signerInfo.getSID();

    Collection<?> signedDataCerts = null;
    if (certStore != null) {
      signedDataCerts = certStore.getMatches(sid);
    }

    if (CollectionUtil.isEmpty(signedDataCerts)) {
      signedDataCerts = pkiMessage.getCertificates()
          .getMatches(signerInfo.getSID());
    }

    if (signedDataCerts == null || signedDataCerts.size() != 1) {
      throw new CodecException(
          "could not find embedded certificate to verify the signature");
    }

    AttributeTable signedAttrs = Optional.ofNullable(
        signerInfo.getSignedAttributes()).orElseThrow(
            () -> new CodecException("missing signed attributes"));

    Instant signingTime = null;
    // signingTime
    ASN1Encodable attrValue = ScepUtil.getFirstAttrValue(signedAttrs,
        OIDs.PKCS9.pkcs9_at_signingTime);
    if (attrValue != null) {
      signingTime = ScepUtil.getTime(attrValue);
    }

    DecodedNextCaMessage ret = new DecodedNextCaMessage();
    if (signingTime != null) {
      ret.setSigningTime(signingTime);
    }

    try {
      HashAlgo digestAlgo = HashAlgo.getInstance(
          signerInfo.getDigestAlgorithmID());
      ret.setDigestAlgorithm(digestAlgo);

      String sigAlgOid = signerInfo.getEncryptionAlgOID();
      if (!OIDs.Algo.id_rsaEncryption.getId().equals(sigAlgOid)) {
        SignAlgo signAlgo = SignAlgo.getInstance(
            signerInfo.toASN1Structure().getDigestEncryptionAlgorithm());

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

    X509CertificateHolder signerCert =
        (X509CertificateHolder) signedDataCerts.iterator().next();
    ret.setSignatureCert(new X509Cert(signerCert));

    // validate the signature
    SignerInformationVerifier verifier;
    try {
      verifier = new JcaSimpleSignerInfoVerifierBuilder().build(signerCert);
    } catch (OperatorCreationException | CertificateException ex) {
      final String msg = "could not build signature verifier";
      LogUtil.error(LOG, ex, msg);
      ret.setFailureMessage(msg + ": " +  ex.getMessage());
      return ret;
    }

    boolean signatureValid;
    try {
      signatureValid = signerInfo.verify(verifier);
    } catch (CMSException ex) {
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
    CMSTypedData signedContent = pkiMessage.getSignedContent();
    ASN1ObjectIdentifier signedContentType = signedContent.getContentType();
    if (!OIDs.CMS.signedData.equals(signedContentType)) {
      // fall back: some SCEP client use id-data
      if (!OIDs.CMS.data.equals(signedContentType)) {
        ret.setFailureMessage("either id-signedData or id-data is excepted, " +
            "but not '" + signedContentType.getId());
        return ret;
      }
    }

    ContentInfo contentInfo =
        ContentInfo.getInstance(signedContent.getContent());
    SignedData signedData = SignedData.getInstance(contentInfo.getContent());

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
          final String msg = "multiple CA certificates is returned, " +
              "but exactly 1 is expected";
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

    X509Cert[] locaRaCerts = raCerts.isEmpty() ? null
        : raCerts.toArray(new X509Cert[0]);

    AuthorityCertStore authorityCertStore =
        AuthorityCertStore.getInstance(caCert, locaRaCerts);
    ret.setAuthorityCertStore(authorityCertStore);

    return ret;
  } // method decode

}
