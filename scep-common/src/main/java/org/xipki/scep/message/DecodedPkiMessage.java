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

import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSEnvelopedData;
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
import org.xipki.scep.transaction.FailInfo;
import org.xipki.scep.transaction.MessageType;
import org.xipki.scep.transaction.Nonce;
import org.xipki.scep.transaction.PkiStatus;
import org.xipki.scep.transaction.TransactionId;
import org.xipki.scep.util.ScepUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public class DecodedPkiMessage extends PkiMessage {

  private static final Logger LOG = LoggerFactory.getLogger(DecodedPkiMessage.class);

  private static final Set<ASN1ObjectIdentifier> SCEP_ATTR_TYPES
      = new HashSet<ASN1ObjectIdentifier>();

  private X509Certificate signatureCert;

  private ASN1ObjectIdentifier digestAlgorithm;

  private ASN1ObjectIdentifier contentEncryptionAlgorithm;

  private Boolean signatureValid;

  private Boolean decryptionSuccessful;

  private Date signingTime;

  private String failureMessage;

  static {
    SCEP_ATTR_TYPES.add(ScepObjectIdentifiers.ID_FAILINFO);
    SCEP_ATTR_TYPES.add(ScepObjectIdentifiers.ID_MESSAGE_TYPE);
    SCEP_ATTR_TYPES.add(ScepObjectIdentifiers.ID_PKI_STATUS);
    SCEP_ATTR_TYPES.add(ScepObjectIdentifiers.ID_RECIPIENT_NONCE);
    SCEP_ATTR_TYPES.add(ScepObjectIdentifiers.ID_SENDER_NONCE);
    SCEP_ATTR_TYPES.add(ScepObjectIdentifiers.ID_TRANSACTION_ID);
    SCEP_ATTR_TYPES.add(CMSAttributes.signingTime);
  }

  public DecodedPkiMessage(TransactionId transactionId, MessageType messageType,
      Nonce senderNonce) {
    super(transactionId, messageType, senderNonce);
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

  public void setSignatureValid(Boolean signatureValid) {
    this.signatureValid = signatureValid;
  }

  public void setContentEncryptionAlgorithm(ASN1ObjectIdentifier encryptionAlgorithm) {
    this.contentEncryptionAlgorithm = encryptionAlgorithm;
  }

  public String getFailureMessage() {
    return failureMessage;
  }

  public void setFailureMessage(String failureMessage) {
    this.failureMessage = failureMessage;
  }

  public ASN1ObjectIdentifier getContentEncryptionAlgorithm() {
    return contentEncryptionAlgorithm;
  }

  public Boolean isDecryptionSuccessful() {
    return decryptionSuccessful;
  }

  public void setDecryptionSuccessful(Boolean decryptionSuccessful) {
    this.decryptionSuccessful = decryptionSuccessful;
  }

  public Boolean isSignatureValid() {
    return signatureValid;
  }

  public Date getSigningTime() {
    return signingTime;
  }

  public void setSigningTime(Date signingTime) {
    this.signingTime = signingTime;
  }

  public static DecodedPkiMessage decode(CMSSignedData pkiMessage, PrivateKey recipientKey,
      X509Certificate recipientCert, CollectionStore<X509CertificateHolder> certStore)
      throws MessageDecodingException {
    EnvelopedDataDecryptorInstance decInstance = new EnvelopedDataDecryptorInstance(
        recipientCert, recipientKey);
    EnvelopedDataDecryptor recipient = new EnvelopedDataDecryptor(decInstance);
    return decode(pkiMessage, recipient, certStore);
  }

  @SuppressWarnings("unchecked")
  public static DecodedPkiMessage decode(CMSSignedData pkiMessage, EnvelopedDataDecryptor recipient,
      CollectionStore<X509CertificateHolder> certStore) throws MessageDecodingException {
    ScepUtil.requireNonNull("pkiMessage", pkiMessage);
    ScepUtil.requireNonNull("recipient", recipient);

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
      throw new MessageDecodingException("missing SCEP attributes");
    }

    Date signingTime = null;
    // signingTime
    ASN1Encodable attrValue = ScepUtil.getFirstAttrValue(signedAttrs, CMSAttributes.signingTime);
    if (attrValue != null) {
      signingTime = Time.getInstance(attrValue).getDate();
    }

    // transactionId
    String str = getPrintableStringAttrValue(signedAttrs, ScepObjectIdentifiers.ID_TRANSACTION_ID);
    if (str == null || str.isEmpty()) {
      throw new MessageDecodingException("missing required SCEP attribute transactionId");
    }
    TransactionId transactionId = new TransactionId(str);

    // messageType
    Integer intValue = getIntegerPrintStringAttrValue(signedAttrs,
        ScepObjectIdentifiers.ID_MESSAGE_TYPE);
    if (intValue == null) {
      throw new MessageDecodingException("tid " + transactionId.getId()
              + ": missing required SCEP attribute messageType");
    }

    MessageType messageType;
    try {
      messageType = MessageType.forValue(intValue);
    } catch (IllegalArgumentException ex) {
      throw new MessageDecodingException("tid " + transactionId.getId()
        + ": invalid messageType '" + intValue + "'");
    }

    // senderNonce
    Nonce senderNonce = getNonceAttrValue(signedAttrs, ScepObjectIdentifiers.ID_SENDER_NONCE);
    if (senderNonce == null) {
      throw new MessageDecodingException("tid " + transactionId.getId()
        + ": missing required SCEP attribute senderNonce");
    }

    DecodedPkiMessage ret = new DecodedPkiMessage(transactionId, messageType, senderNonce);
    if (signingTime != null) {
      ret.setSigningTime(signingTime);
    }

    Nonce recipientNonce = null;
    try {
      recipientNonce = getNonceAttrValue(signedAttrs, ScepObjectIdentifiers.ID_RECIPIENT_NONCE);
    } catch (MessageDecodingException ex) {
      ret.setFailureMessage("could not parse recipientNonce: " + ex.getMessage());
    }

    if (recipientNonce != null) {
      ret.setRecipientNonce(recipientNonce);
    }

    PkiStatus pkiStatus = null;
    FailInfo failInfo = null;
    if (MessageType.CertRep == messageType) {
      // pkiStatus
      try {
        intValue = getIntegerPrintStringAttrValue(signedAttrs, ScepObjectIdentifiers.ID_PKI_STATUS);
      } catch (MessageDecodingException ex) {
        ret.setFailureMessage("could not parse pkiStatus: " + ex.getMessage());
        return ret;
      }

      if (intValue == null) {
        ret.setFailureMessage("missing required SCEP attribute pkiStatus");
        return ret;
      }

      try {
        pkiStatus = PkiStatus.forValue(intValue);
      } catch (IllegalArgumentException ex) {
        ret.setFailureMessage("invalid pkiStatus '" + intValue + "'");
        return ret;
      }
      ret.setPkiStatus(pkiStatus);

      // failureInfo
      if (pkiStatus == PkiStatus.FAILURE) {
        try {
          intValue = getIntegerPrintStringAttrValue(signedAttrs, ScepObjectIdentifiers.ID_FAILINFO);
        } catch (MessageDecodingException ex) {
          ret.setFailureMessage("could not parse failInfo: " + ex.getMessage());
          return ret;
        }

        if (intValue == null) {
          ret.setFailureMessage("missing required SCEP attribute failInfo");
          return ret;
        }

        try {
          failInfo = FailInfo.forValue(intValue);
        } catch (IllegalArgumentException ex) {
          ret.setFailureMessage("invalid failInfo '" + intValue + "'");
          return ret;
        }

        ret.setFailInfo(failInfo);
      } // end if(pkiStatus == PkiStatus.FAILURE)
    } // end if (MessageType.CertRep == messageType)

    // other signedAttributes
    Attribute[] attrs = signedAttrs.toASN1Structure().getAttributes();
    for (Attribute attr : attrs) {
      ASN1ObjectIdentifier type = attr.getAttrType();
      if (!SCEP_ATTR_TYPES.contains(type)) {
        ret.addSignendAttribute(type, attr.getAttrValues().getObjectAt(0));
      }
    }

    // unsignedAttributes
    AttributeTable unsignedAttrs = signerInfo.getUnsignedAttributes();
    attrs = (unsignedAttrs == null) ? null : unsignedAttrs.toASN1Structure().getAttributes();
    if (attrs != null) {
      for (Attribute attr : attrs) {
        ASN1ObjectIdentifier type = attr.getAttrType();
        ret.addUnsignendAttribute(type, attr.getAttrValues().getObjectAt(0));
      }
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
        ret.setFailureMessage(
            "digestAlgorithm and encryptionAlgorithm do not use the same digestAlgorithm");
        return ret;
      } // end if
    } // end if

    X509CertificateHolder tmpSignerCert = (X509CertificateHolder) signedDataCerts.iterator().next();
    X509Certificate signerCert;
    try {
      signerCert = ScepUtil.toX509Cert(tmpSignerCert.toASN1Structure());
    } catch (CertificateException ex) {
      final String msg = "could not construct X509Certificate: " + ex.getMessage();
      LOG.error(msg);
      LOG.debug(msg, ex);
      ret.setFailureMessage(msg);
      return ret;
    }
    ret.setSignatureCert(signerCert);

    // validate the signature
    SignerInformationVerifier verifier;
    try {
      verifier = new JcaSimpleSignerInfoVerifierBuilder().build(tmpSignerCert);
    } catch (OperatorCreationException | CertificateException ex) {
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

    if (MessageType.CertRep == messageType
            && (pkiStatus == PkiStatus.FAILURE | pkiStatus == PkiStatus.PENDING)) {
      return ret;
    }

    // MessageData
    CMSTypedData signedContent = pkiMessage.getSignedContent();
    ASN1ObjectIdentifier signedContentType = signedContent.getContentType();
    if (!CMSObjectIdentifiers.envelopedData.equals(signedContentType)) {
      // fall back: some SCEP client, such as JSCEP use id-data
      if (!CMSObjectIdentifiers.data.equals(signedContentType)) {
        ret.setFailureMessage("either id-envelopedData or id-data is excepted, but not '"
            + signedContentType.getId());
        return ret;
      }
    }

    CMSEnvelopedData envData;
    try {
      envData = new CMSEnvelopedData((byte[]) signedContent.getContent());
    } catch (CMSException ex) {
      final String msg = "could not create the CMSEnvelopedData: " + ex.getMessage();
      LOG.error(msg);
      LOG.debug(msg, ex);
      ret.setFailureMessage(msg);
      return ret;
    }

    ret.setContentEncryptionAlgorithm(envData.getContentEncryptionAlgorithm().getAlgorithm());
    byte[] encodedMessageData;
    try {
      encodedMessageData = recipient.decrypt(envData);
    } catch (MessageDecodingException ex) {
      final String msg = "could not create the CMSEnvelopedData: " + ex.getMessage();
      LOG.error(msg);
      LOG.debug(msg, ex);
      ret.setFailureMessage(msg);

      ret.setDecryptionSuccessful(false);
      return ret;
    }

    ret.setDecryptionSuccessful(true);

    try {
      if (MessageType.PKCSReq == messageType || MessageType.RenewalReq == messageType
          || MessageType.UpdateReq == messageType) {
        CertificationRequest messageData = CertificationRequest.getInstance(encodedMessageData);
        ret.setMessageData(messageData);
      } else if (MessageType.CertPoll == messageType) {
        IssuerAndSubject messageData = IssuerAndSubject.getInstance(encodedMessageData);
        ret.setMessageData(messageData);
      } else if (MessageType.GetCert == messageType || MessageType.GetCRL == messageType) {
        IssuerAndSerialNumber messageData = IssuerAndSerialNumber.getInstance(encodedMessageData);
        ret.setMessageData(messageData);
        ret.setMessageData(messageData);
      } else if (MessageType.CertRep == messageType) {
        ContentInfo ci = ContentInfo.getInstance(encodedMessageData);
        ret.setMessageData(ci);
      } else {
        throw new RuntimeException("should not reach here, unknown messageType " + messageType);
      }
    } catch (Exception ex) {
      final String msg = "could not parse the messageData: " + ex.getMessage();
      LOG.error(msg);
      LOG.debug(msg, ex);
      ret.setFailureMessage(msg);
      return ret;
    }

    return ret;
  } // method decode

  private static String getPrintableStringAttrValue(AttributeTable attrs,
      ASN1ObjectIdentifier type) throws MessageDecodingException {
    ASN1Encodable value = ScepUtil.getFirstAttrValue(attrs, type);
    if (value instanceof DERPrintableString) {
      return ((DERPrintableString) value).getString();
    } else if (value != null) {
      throw new MessageDecodingException("the value of attribute " + type.getId()
        + " is not PrintableString");
    } else {
      return null;
    }
  }

  private static Integer getIntegerPrintStringAttrValue(AttributeTable attrs,
      ASN1ObjectIdentifier type) throws MessageDecodingException {
    String str = getPrintableStringAttrValue(attrs, type);
    if (str == null) {
      return null;
    }

    try {
      return Integer.parseInt(str);
    } catch (NumberFormatException ex) {
      throw new MessageDecodingException("invalid integer '" + str + "'");
    }
  }

  private static Nonce getNonceAttrValue(AttributeTable attrs, ASN1ObjectIdentifier type)
      throws MessageDecodingException {
    ASN1Encodable value = ScepUtil.getFirstAttrValue(attrs, type);
    if (value instanceof ASN1OctetString) {
      byte[] bytes = ((ASN1OctetString) value).getOctets();
      return new Nonce(bytes);
    } else if (value != null) {
      throw new MessageDecodingException("the value of attribute " + type.getId()
        + " is not OctetString");
    } else {
      return null;
    }
  }

}
