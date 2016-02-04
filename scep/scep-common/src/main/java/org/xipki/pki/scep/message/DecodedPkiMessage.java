/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.scep.message;

import java.security.PrivateKey;
import java.security.cert.CertificateParsingException;
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
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.CollectionStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pki.scep.exception.MessageDecodingException;
import org.xipki.pki.scep.transaction.FailInfo;
import org.xipki.pki.scep.transaction.MessageType;
import org.xipki.pki.scep.transaction.Nonce;
import org.xipki.pki.scep.transaction.PkiStatus;
import org.xipki.pki.scep.transaction.TransactionId;
import org.xipki.pki.scep.util.ParamUtil;
import org.xipki.pki.scep.util.ScepUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DecodedPkiMessage extends PkiMessage {

  private final static Logger LOG = LoggerFactory.getLogger(DecodedPkiMessage.class);

  private static final Set<ASN1ObjectIdentifier> scepAttrTypes
      = new HashSet<ASN1ObjectIdentifier>();

  private X509Certificate signatureCert;

  private ASN1ObjectIdentifier digestAlgorithm;

  private ASN1ObjectIdentifier contentEncryptionAlgorithm;

  private Boolean signatureValid;

  private Boolean decryptionSuccessful;

  private Date signingTime;

  private String failureMessage;

  static {
    scepAttrTypes.add(ScepObjectIdentifiers.id_failInfo);
    scepAttrTypes.add(ScepObjectIdentifiers.id_messageType);
    scepAttrTypes.add(ScepObjectIdentifiers.id_pkiStatus);
    scepAttrTypes.add(ScepObjectIdentifiers.id_recipientNonce);
    scepAttrTypes.add(ScepObjectIdentifiers.id_senderNonce);
    scepAttrTypes.add(ScepObjectIdentifiers.id_transactionID);
    scepAttrTypes.add(CMSAttributes.signingTime);
  }

  public DecodedPkiMessage(
      final TransactionId transactionId,
      final MessageType messageType,
      final Nonce senderNonce) {
    super(transactionId, messageType, senderNonce);
  }

  public X509Certificate getSignatureCert() {
    return signatureCert;
  }

  public void setSignatureCert(
      final X509Certificate signatureCert) {
    this.signatureCert = signatureCert;
  }

  public void setDigestAlgorithm(
      final ASN1ObjectIdentifier digestAlgorithm) {
    this.digestAlgorithm = digestAlgorithm;
  }

  public void setSignatureValid(
      final Boolean signatureValid) {
    this.signatureValid = signatureValid;
  }

  public ASN1ObjectIdentifier getDigestAlgorithm() {
    return digestAlgorithm;
  }

  public void setContentEncryptionAlgorithm(
      final ASN1ObjectIdentifier encryptionAlgorithm) {
    this.contentEncryptionAlgorithm = encryptionAlgorithm;
  }

  public String getFailureMessage() {
    return failureMessage;
  }

  public void setFailureMessage(
      final String failureMessage) {
    this.failureMessage = failureMessage;
  }

  public ASN1ObjectIdentifier getContentEncryptionAlgorithm() {
    return contentEncryptionAlgorithm;
  }

  public Boolean isDecryptionSuccessful() {
    return decryptionSuccessful;
  }

  public void setDecryptionSuccessful(
      final Boolean decryptionSuccessful) {
    this.decryptionSuccessful = decryptionSuccessful;
  }

  public Boolean isSignatureValid() {
    return signatureValid;
  }

  public Date getSigningTime() {
    return signingTime;
  }

  public void setSigningTime(
      final Date signingTime) {
    this.signingTime = signingTime;
  }

  public static DecodedPkiMessage decode(
      final CMSSignedData pkiMessage,
      final PrivateKey recipientKey,
      final X509Certificate recipientCert,
      final CollectionStore<X509CertificateHolder> certStore)
  throws MessageDecodingException {
    EnvelopedDataDecryptorInstance decInstance = new EnvelopedDataDecryptorInstance(
        recipientCert, recipientKey);
    EnvelopedDataDecryptor recipient = new EnvelopedDataDecryptor(decInstance);
    return decode(pkiMessage, recipient, certStore);
  }

  @SuppressWarnings("unchecked")
  public static DecodedPkiMessage decode(
      final CMSSignedData pkiMessage,
      final EnvelopedDataDecryptor recipient,
      final CollectionStore<X509CertificateHolder> certStore)
  throws MessageDecodingException {
    ParamUtil.assertNotNull("pkiMessage", pkiMessage);
    ParamUtil.assertNotNull("recipient", recipient);

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
    ASN1Encodable attrValue = ScepUtil.getFirstAttrValue(signedAttrs,
        CMSAttributes.signingTime);
    if (attrValue != null) {
      signingTime = Time.getInstance(attrValue).getDate();
    }

    // transactionId
    String s = getPrintableStringAttrValue(signedAttrs,
        ScepObjectIdentifiers.id_transactionID);
    if (s == null || s.isEmpty()) {
      throw new MessageDecodingException("missing required SCEP attribute transactionId");
    }
    TransactionId transactionId = new TransactionId(s);

    // messageType
    Integer i = getIntegerPrintStringAttrValue(signedAttrs,
        ScepObjectIdentifiers.id_messageType);
    if (i == null) {
      throw new MessageDecodingException("tid " + transactionId.getId()
          + ": missing required SCEP attribute messageType");
    }
    MessageType messageType = MessageType.valueForCode(i);
    if (messageType == null) {
      throw new MessageDecodingException("tid " + transactionId.getId()
          + ": invalid messageType '" + i + "'");
    }

    // senderNonce
    Nonce senderNonce = getNonceAttrValue(signedAttrs, ScepObjectIdentifiers.id_senderNonce);
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
      recipientNonce = getNonceAttrValue(signedAttrs,
          ScepObjectIdentifiers.id_recipientNonce);
    } catch (MessageDecodingException e) {
      ret.setFailureMessage("could not parse recipientNonce: " + e.getMessage());
    }

    if (recipientNonce != null) {
      ret.setRecipientNonce(recipientNonce);
    }

    PkiStatus pkiStatus = null;
    FailInfo failInfo = null;
    if (MessageType.CertRep == messageType) {
      // pkiStatus
      try {
        i = getIntegerPrintStringAttrValue(signedAttrs, ScepObjectIdentifiers.id_pkiStatus);
      } catch (MessageDecodingException e) {
        ret.setFailureMessage("could not parse pkiStatus: " + e.getMessage());
        return ret;
      }

      if (i == null) {
        ret.setFailureMessage("missing required SCEP attribute pkiStatus");
        return ret;
      }

      pkiStatus = PkiStatus.valueForCode(i);
      if (pkiStatus == null) {
        ret.setFailureMessage("invalid pkiStatus '" + i + "'");
        return ret;
      }
      ret.setPkiStatus(pkiStatus);

      // failureInfo
      if (pkiStatus == PkiStatus.FAILURE) {
        try {
          i = getIntegerPrintStringAttrValue(signedAttrs,
              ScepObjectIdentifiers.id_failInfo);
        } catch (MessageDecodingException e) {
          ret.setFailureMessage("could not parse failInfo: " + e.getMessage());
          return ret;
        }

        if (i == null) {
          ret.setFailureMessage("missing required SCEP attribute failureInfo");
          return ret;
        }

        failInfo = FailInfo.valueForCode(i);
        if (failInfo == null) {
          ret.setFailureMessage("invalid failureInfo '" + i + "'");
          return ret;
        }
        ret.setFailInfo(failInfo);
      } // end if(pkiStatus == PkiStatus.FAILURE)
    } // end if (MessageType.CertRep == messageType)

    // other signedAttributes
    Attribute[] attrs = signedAttrs.toASN1Structure().getAttributes();
    for (Attribute attr : attrs) {
      ASN1ObjectIdentifier type = attr.getAttrType();
      if (!scepAttrTypes.contains(type)) {
        ret.addSignendAttribute(type, attr.getAttrValues().getObjectAt(0));
      }
    }

    // unsignedAttributes
    AttributeTable unsignedAttrs = signerInfo.getUnsignedAttributes();
    attrs = (unsignedAttrs == null)
        ? null
        : unsignedAttrs.toASN1Structure().getAttributes();
    if (attrs != null) {
      for (Attribute attr : attrs) {
        ASN1ObjectIdentifier type = attr.getAttrType();
        ret.addUnsignendAttribute(type, attr.getAttrValues().getObjectAt(0));
      }
    }

    ASN1ObjectIdentifier digestAlgOID = signerInfo.getDigestAlgorithmID().getAlgorithm();
    ret.setDigestAlgorithm(digestAlgOID);

    String sigAlgOID = signerInfo.getEncryptionAlgOID();
    if (!PKCSObjectIdentifiers.rsaEncryption.getId().equals(sigAlgOID)) {
      ASN1ObjectIdentifier _digestAlgOID;
      try {
        _digestAlgOID = ScepUtil.extractDigesetAlgorithmIdentifier(
            signerInfo.getEncryptionAlgOID(), signerInfo.getEncryptionAlgParams());
      } catch (Exception e) {
        final String msg =
            "could not extract digest algorithm from signerInfo.signatureAlgorithm: "
            + e.getMessage();
        LOG.error(msg);
        LOG.debug(msg, e);
        ret.setFailureMessage(msg);
        return ret;
      }
      if (!digestAlgOID.equals(_digestAlgOID)) {
        ret.setFailureMessage("digestAlgorithm and encryptionAlgorithm do not use the"
            + " same digestAlgorithm");
        return ret;
      } // end if
    } // end if

    X509CertificateHolder _signerCert =
        (X509CertificateHolder) signedDataCerts.iterator().next();
    X509Certificate signerCert;
    try {
      signerCert = new X509CertificateObject(_signerCert.toASN1Structure());
    } catch (CertificateParsingException e) {
      final String msg = "could not construct X509CertificateObject: " + e.getMessage();
      LOG.error(msg);
      LOG.debug(msg, e);
      ret.setFailureMessage(msg);
      return ret;
    }
    ret.setSignatureCert(signerCert);

    // validate the signature
    SignerInformationVerifier verifier;
    try {
      verifier = new JcaSimpleSignerInfoVerifierBuilder().build(
          signerCert.getPublicKey());
    } catch (OperatorCreationException e) {
      final String msg = "could not build signature verifier: " + e.getMessage();
      LOG.error(msg);
      LOG.debug(msg, e);
      ret.setFailureMessage(msg);
      return ret;
    }

    boolean signatureValid;
    try {
      signatureValid = signerInfo.verify(verifier);
    } catch (CMSException e) {
      final String msg = "could not verify the signature: " + e.getMessage();
      LOG.error(msg);
      LOG.debug(msg, e);
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
    } catch (CMSException e) {
      final String msg = "could not create the CMSEnvelopedData: " + e.getMessage();
      LOG.error(msg);
      LOG.debug(msg, e);
      ret.setFailureMessage(msg);
      return ret;
    }

    ret.setContentEncryptionAlgorithm(envData.getContentEncryptionAlgorithm().getAlgorithm());
    byte[] encodedMessageData;
    try {
      encodedMessageData = recipient.decrypt(envData);
    } catch (MessageDecodingException e) {
      final String msg = "could not create the CMSEnvelopedData: " + e.getMessage();
      LOG.error(msg);
      LOG.debug(msg, e);
      ret.setFailureMessage(msg);

      ret.setDecryptionSuccessful(false);
      return ret;
    }

    ret.setDecryptionSuccessful(true);

    try {
      if (MessageType.PKCSReq == messageType || MessageType.RenewalReq == messageType
          || MessageType.UpdateReq == messageType) {
        CertificationRequest messageData =
            CertificationRequest.getInstance(encodedMessageData);
        ret.setMessageData(messageData);
      } else if (MessageType.CertPoll == messageType) {
        IssuerAndSubject messageData = IssuerAndSubject.getInstance(encodedMessageData);
        ret.setMessageData(messageData);
      } else if (MessageType.GetCert == messageType || MessageType.GetCRL == messageType) {
        IssuerAndSerialNumber messageData =
            IssuerAndSerialNumber.getInstance(encodedMessageData);
        ret.setMessageData(messageData);
        ret.setMessageData(messageData);
      } else if (MessageType.CertRep == messageType) {
        ContentInfo ci = ContentInfo.getInstance(encodedMessageData);
        ret.setMessageData(ci);
      } else {
        throw new RuntimeException("should not reach here, unknown messageType "
            + messageType);
      }
    } catch (Exception e) {
      final String msg = "error while trying to parse the messageData: " + e.getMessage();
      LOG.error(msg);
      LOG.debug(msg, e);
      ret.setFailureMessage(msg);
      return ret;
    }

    return ret;
  } // method decode

  private static String getPrintableStringAttrValue(
      final AttributeTable attrs,
      final ASN1ObjectIdentifier type)
  throws MessageDecodingException {
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

  private static Integer getIntegerPrintStringAttrValue(
      final AttributeTable attrs,
      final ASN1ObjectIdentifier type)
  throws MessageDecodingException {
    String s = getPrintableStringAttrValue(attrs, type);
    if (s == null) {
      return null;
    }

    try {
      return Integer.parseInt(s);
    } catch (NumberFormatException e) {
      throw new MessageDecodingException("invalid integer '" + s + "'");
    }
  }

  private static Nonce getNonceAttrValue(
      final AttributeTable attrs,
      final ASN1ObjectIdentifier type)
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
