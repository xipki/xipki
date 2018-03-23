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

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
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
import org.xipki.scep.exception.MessageDecodingException;
import org.xipki.scep.util.ScepUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public class DecodedNextCaMessage {

  private static final Logger LOG = LoggerFactory.getLogger(DecodedNextCaMessage.class);

  private AuthorityCertStore authorityCertStore;

  private X509Certificate signatureCert;

  private ASN1ObjectIdentifier digestAlgorithm;

  private Boolean signatureValid;

  private Date signingTime;

  private String failureMessage;

  public DecodedNextCaMessage() {
  }

  public AuthorityCertStore getAuthorityCertStore() {
    return authorityCertStore;
  }

  public void setAuthorityCertStore(AuthorityCertStore authorityCertStore) {
    this.authorityCertStore = authorityCertStore;
  }

  public X509Certificate getSignatureCert() {
    return signatureCert;
  }

  public void setSignatureCert(X509Certificate signatureCert) {
    this.signatureCert = signatureCert;
  }

  public ASN1ObjectIdentifier getDigestAlgorithm() {
    return digestAlgorithm;
  }

  public void setDigestAlgorithm(ASN1ObjectIdentifier digestAlgorithm) {
    this.digestAlgorithm = digestAlgorithm;
  }

  public Boolean isSignatureValid() {
    return signatureValid;
  }

  public void setSignatureValid(Boolean signatureValid) {
    this.signatureValid = signatureValid;
  }

  public String getFailureMessage() {
    return failureMessage;
  }

  public void setFailureMessage(String failureMessage) {
    this.failureMessage = failureMessage;
  }

  public Date getSigningTime() {
    return signingTime;
  }

  public void setSigningTime(Date signingTime) {
    this.signingTime = signingTime;
  }

  @SuppressWarnings("unchecked")
  public static DecodedNextCaMessage decode(CMSSignedData pkiMessage,
      CollectionStore<X509CertificateHolder> certStore)
      throws MessageDecodingException {
    ScepUtil.requireNonNull("pkiMessage", pkiMessage);

    SignerInformationStore signerStore = pkiMessage.getSignerInfos();
    Collection<SignerInformation> signerInfos = signerStore.getSigners();
    if (signerInfos.size() != 1) {
      throw new MessageDecodingException(
          "number of signerInfos is not 1, but " + signerInfos.size());
    }

    SignerInformation signerInfo = signerInfos.iterator().next();

    SignerId sid = signerInfo.getSID();

    Collection<?> signedDataCerts = null;
    if (certStore != null) {
      signedDataCerts = certStore.getMatches(sid);
    }

    if (signedDataCerts == null || signedDataCerts.isEmpty()) {
      signedDataCerts = pkiMessage.getCertificates().getMatches(signerInfo.getSID());
    }

    if (signedDataCerts == null || signedDataCerts.size() != 1) {
      throw new MessageDecodingException(
          "could not find embedded certificate to verify the signature");
    }

    AttributeTable signedAttrs = signerInfo.getSignedAttributes();
    if (signedAttrs == null) {
      throw new MessageDecodingException("missing signed attributes");
    }

    Date signingTime = null;
    // signingTime
    ASN1Encodable attrValue = ScepUtil.getFirstAttrValue(signedAttrs, CMSAttributes.signingTime);
    if (attrValue != null) {
      signingTime = Time.getInstance(attrValue).getDate();
    }

    DecodedNextCaMessage ret = new DecodedNextCaMessage();
    if (signingTime != null) {
      ret.setSigningTime(signingTime);
    }

    ASN1ObjectIdentifier digestAlgOid = signerInfo.getDigestAlgorithmID().getAlgorithm();
    ret.setDigestAlgorithm(digestAlgOid);

    String sigAlgOid = signerInfo.getEncryptionAlgOID();
    if (!PKCSObjectIdentifiers.rsaEncryption.getId().equals(sigAlgOid)) {
      ASN1ObjectIdentifier tmpDigestAlgOid;
      try {
        tmpDigestAlgOid = ScepUtil.extractDigesetAlgorithmIdentifier(
            signerInfo.getEncryptionAlgOID(), signerInfo.getEncryptionAlgParams());
      } catch (Exception ex) {
        final String msg = "could not extract digest algorithm from signerInfo.signatureAlgorithm: "
            + ex.getMessage();
        LOG.error(msg);
        LOG.debug(msg, ex);
        ret.setFailureMessage(msg);
        return ret;
      }
      if (!digestAlgOid.equals(tmpDigestAlgOid)) {
        ret.setFailureMessage("digestAlgorithm and encryptionAlgorithm do not use"
            + " the same digestAlgorithm");
        return ret;
      }
    } // end if

    X509CertificateHolder tmpSignerCert = (X509CertificateHolder) signedDataCerts.iterator().next();
    X509Certificate signerCert;
    try {
      signerCert = ScepUtil.toX509Cert(tmpSignerCert.toASN1Structure());
    } catch (CertificateException ex) {
      final String msg = "could not construct X509CertificateObject: " + ex.getMessage();
      LOG.error(msg);
      LOG.debug(msg, ex);
      ret.setFailureMessage(msg);
      return ret;
    }
    ret.setSignatureCert(signerCert);

    // validate the signature
    SignerInformationVerifier verifier;
    try {
      verifier = new JcaSimpleSignerInfoVerifierBuilder().build(signerCert.getPublicKey());
    } catch (OperatorCreationException ex) {
      final String msg = "could not build signature verifier: " + ex.getMessage();
      LOG.error(msg);
      LOG.debug(msg, ex);
      ret.setFailureMessage(msg);
      return ret;
    }

    boolean signatureValid;
    try {
      signatureValid = signerInfo.verify(verifier);
    } catch (CMSException ex) {
      final String msg = "could not verify the signature: " + ex.getMessage();
      LOG.error(msg);
      LOG.debug(msg, ex);
      ret.setFailureMessage(msg);
      return ret;
    }

    ret.setSignatureValid(signatureValid);
    if (!signatureValid) {
      return ret;
    }

    // MessageData
    CMSTypedData signedContent = pkiMessage.getSignedContent();
    ASN1ObjectIdentifier signedContentType = signedContent.getContentType();
    if (!CMSObjectIdentifiers.signedData.equals(signedContentType)) {
      // fall back: some SCEP client use id-data
      if (!CMSObjectIdentifiers.data.equals(signedContentType)) {
        ret.setFailureMessage("either id-signedData or id-data is excepted, but not '"
            + signedContentType.getId());
        return ret;
      }
    }

    ContentInfo contentInfo = ContentInfo.getInstance((byte[]) signedContent.getContent());
    SignedData signedData = SignedData.getInstance(contentInfo.getContent());

    List<X509Certificate> certs;
    try {
      certs = ScepUtil.getCertsFromSignedData(signedData);
    } catch (CertificateException ex) {
      final String msg = "could not extract Certificates from the message: " + ex.getMessage();
      LOG.error(msg);
      LOG.debug(msg, ex);
      ret.setFailureMessage(msg);
      return ret;
    }

    final int n = certs.size();

    X509Certificate caCert = null;
    List<X509Certificate> raCerts = new LinkedList<X509Certificate>();
    for (int i = 0; i < n; i++) {
      X509Certificate cert = certs.get(i);
      if (cert.getBasicConstraints() > -1) {
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

    X509Certificate[] locaRaCerts = raCerts.isEmpty()
        ? null : raCerts.toArray(new X509Certificate[0]);

    AuthorityCertStore authorityCertStore = AuthorityCertStore.getInstance(caCert, locaRaCerts);
    ret.setAuthorityCertStore(authorityCertStore);

    return ret;
  } // method decode

}
