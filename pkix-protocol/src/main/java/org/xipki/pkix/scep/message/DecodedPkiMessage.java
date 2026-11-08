// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.scep.message;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkix.asn1.cms.Attributes;
import org.xipki.pkix.asn1.cms.ContentInfo;
import org.xipki.pkix.asn1.cms.IssuerAndSerialNumber;
import org.xipki.pkix.asn1.pkcs10.CertificationRequest;
import org.xipki.pkix.asn1.scep.IssuerAndSubject;
import org.xipki.pkix.asn1.x509.Attribute;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.util.StringUtil;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.AttributeOIDs;
import org.xipki.codec.asn1.oid.CmsOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.cms.CmsEnvelopedData;
import org.xipki.pkix.cms.CmsSignedData;
import org.xipki.pkix.cms.CmsSigner;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.scep.message.EnvelopedDataDecryptor.EnvelopedDataDecryptorInstance;
import org.xipki.pkix.scep.transaction.FailInfo;
import org.xipki.pkix.scep.transaction.MessageType;
import org.xipki.pkix.scep.transaction.Nonce;
import org.xipki.pkix.scep.transaction.PkiStatus;
import org.xipki.pkix.scep.transaction.TransactionId;
import org.xipki.pkix.scep.util.ScepUtil;
import org.xipki.pkix.util.X509Util;
import org.xipki.util.exception.PkixException;
import org.xipki.util.misc.CollectionUtil;
import org.xipki.util.misc.LogUtil;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Decoded Pki Message.
 *
 * @author Lijun Liao (xipki)
 */
public class DecodedPkiMessage extends PkiMessage {

  private static final Logger LOG = LoggerFactory.getLogger(DecodedPkiMessage.class);

  private static final Set<Asn1Oid> SCEP_ATTR_TYPES;

  private X509Cert signatureCert;

  private HashAlgo digestAlgorithm;

  private Asn1Oid contentEncryptionAlgorithm;

  private Boolean signatureValid;

  private Boolean decryptionSuccessful;

  private Instant signingTime;

  private String failureMessage;

  static {
    SCEP_ATTR_TYPES = CollectionUtil.asSet(
        AttributeOIDs.scep_failInfo, AttributeOIDs.scep_messageType, AttributeOIDs.scep_pkiStatus,
        AttributeOIDs.scep_recipientNonce, AttributeOIDs.scep_senderNonce,
        AttributeOIDs.scep_transactionId,  AttributeOIDs.signingTime);
  }

  public DecodedPkiMessage(
      TransactionId transactionId, MessageType messageType, Nonce senderNonce) {
    super(transactionId, messageType, senderNonce);
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

  public void setSignatureValid(Boolean signatureValid) {
    this.signatureValid = signatureValid;
  }

  public void setContentEncryptionAlgorithm(Asn1Oid encryptionAlgorithm) {
    this.contentEncryptionAlgorithm = encryptionAlgorithm;
  }

  public String failureMessage() {
    return failureMessage;
  }

  public void setFailureMessage(String failureMessage) {
    this.failureMessage = failureMessage;
  }

  public Asn1Oid contentEncryptionAlgorithm() {
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

  public Instant signingTime() {
    return signingTime;
  }

  public void setSigningTime(Instant signingTime) {
    this.signingTime = signingTime;
  }

  public static DecodedPkiMessage decode(
      CmsSignedData pkiMessage, PrivateKey recipientKey, X509Cert recipientCert,
      List<Certificate> certStore) throws CodecException {
    EnvelopedDataDecryptorInstance decInstance =
        new EnvelopedDataDecryptorInstance(recipientCert, recipientKey);
    return decode(pkiMessage, new EnvelopedDataDecryptor(decInstance), certStore);
  }

  public static DecodedPkiMessage decode(
      CmsSignedData pkiMessage, EnvelopedDataDecryptor recipient,
      List<Certificate> certStore) throws CodecException {
    Args.notNull(recipient, "recipient");
    Args.notNull(pkiMessage, "pkiMessage");

    CmsSigner signerInfo = ScepUtil.getOnlySigner(pkiMessage);
    Certificate signerCert = ScepUtil.getSignerCert(pkiMessage, signerInfo, certStore);

    Attributes signedAttrs = Optional.ofNullable(
        signerInfo.getSignedAttributes()).orElseThrow(
            () -> new CodecException("missing SCEP attributes"));

    // signingTime
    Attribute attr = signedAttrs.getFirstAttribute(AttributeOIDs.signingTime);
    Instant signingTime = (attr == null) ? null : attr.signingTime();

    // transactionId
    attr = signedAttrs.getFirstAttribute(AttributeOIDs.scep_transactionId);
    String str = (attr == null) ? null : attr.scepTransactionId();
    if (StringUtil.isBlank(str)) {
      throw new CodecException("missing required SCEP attribute transactionId");
    }
    TransactionId tid = new TransactionId(str);

    // messageType
    attr = signedAttrs.getOnlyAttribute(AttributeOIDs.scep_messageType);
    if (attr == null) {
      throw new CodecException("tid " + tid.id() + ": missing required SCEP attribute messageType");
    }

    int iValue = attr.scepMessageType();

    MessageType messageType;
    try {
      messageType = MessageType.forValue(iValue);
    } catch (IllegalArgumentException ex) {
      throw new CodecException("tid " + tid.id() + ": invalid messageType '" + iValue + "'");
    }

    // senderNonce
    attr = signedAttrs.getOnlyAttribute(AttributeOIDs.scep_senderNonce);
    if (attr == null) {
      throw new CodecException("tid " + tid.id() + ": missing required SCEP attribute senderNonce");
    }

    Nonce senderNonce = new Nonce(attr.scepSenderNonce());

    DecodedPkiMessage ret = new DecodedPkiMessage(tid, messageType, senderNonce);

    if (signingTime != null) {
      ret.setSigningTime(signingTime);
    }

    attr = signedAttrs.getOnlyAttribute(AttributeOIDs.scep_recipientNonce);
    Nonce recipientNonce = (attr == null) ? null : new Nonce(attr.scepRecipientNonce());

    if (recipientNonce != null) {
      ret.setRecipientNonce(recipientNonce);
    }

    PkiStatus pkiStatus = null;
    FailInfo failInfo;
    if (MessageType.CertRep == messageType) {
      // pkiStatus
      attr = signedAttrs.getOnlyAttribute(AttributeOIDs.scep_pkiStatus);
      Integer intValue = (attr == null) ? null : attr.scepPkiStatus();

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
        attr = signedAttrs.getOnlyAttribute(AttributeOIDs.scep_failInfo);
        if (attr == null) {
          ret.setFailureMessage("missing required SCEP attribute failInfo");
          return ret;
        }

        intValue = attr.scepFailInfo();

        try {
          failInfo = FailInfo.forValue(intValue);
        } catch (IllegalArgumentException ex) {
          ret.setFailureMessage("invalid failInfo '" + intValue + "'");
          return ret;
        }

        ret.setFailInfo(failInfo);

        // failInfoText
        attr = signedAttrs.getOnlyAttribute(AttributeOIDs.scep_failInfoText);
        if (attr != null) {
          ret.setFailInfoText(attr.scepFailInfoText());
        }
      } // end if(pkiStatus == PkiStatus.FAILURE)
    } // end if (MessageType.CertRep == messageType)

    // other signedAttributes
    for (Attribute a : signedAttrs) {
      if (!SCEP_ATTR_TYPES.contains(a.getAttrType())) {
        ret.addSignedAttribute(a);
      }
    }

    // unsignedAttributes
    Attributes unsignedAttrs = signerInfo.getUnsignedAttributes();
    if (unsignedAttrs != null) {
      for (Attribute a : unsignedAttrs) {
        ret.addUnsignedAttribute(a);
      }
    }

    try {
      HashAlgo digestAlgo = HashAlgo.getInstance(signerInfo.getDigestAlgorithm());
      ret.setDigestAlgorithm(digestAlgo);

      String sigAlgOid = signerInfo.getSignatureAlgorithm().getAlgorithm().getId();
      if (!AlgorithmOIDs.id_rsaEncryption.getId().equals(sigAlgOid)) {
        SignAlgo signAlgo = SignAlgo.ofAlgorithmIdentifier(
            signerInfo.toASN1Structure().getSignatureAlgorithm());

        if (digestAlgo != signAlgo.hashAlgo()) {
          ret.setFailureMessage("digestAlgorithm and encryptionAlgorithm " +
              "do not use the same digestAlgorithm");
          return ret;
        }
      }
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
      LogUtil.error(LOG, ex);
      ret.setFailureMessage(msg + ": " + ex.getMessage());
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
    Asn1Oid signedContentType = pkiMessage.getContentType();
    if (!CmsOIDs.envelopedData.equals(signedContentType)) {
      // fall back: some SCEP client, such as JSCEP use id-data
      if (!CmsOIDs.data.equals(signedContentType)) {
        ret.setFailureMessage("either id-envelopedData or id-data is " +
            "excepted, but not '" + signedContentType.getId());
        return ret;
      }
    }

    CmsEnvelopedData envData;
    try {
      envData = new CmsEnvelopedData(pkiMessage.getContent());
    } catch (PkixException ex) {
      final String msg = "could not create the CMSEnvelopedData";
      LogUtil.error(LOG, ex);
      ret.setFailureMessage(msg + ": " + ex.getMessage());
      return ret;
    }

    ret.setContentEncryptionAlgorithm(envData.getContentEncryptionAlgorithm().getAlgorithm());

    byte[] encodedMessageData;
    try {
      encodedMessageData = recipient.decrypt(envData);
    } catch (CodecException ex) {
      final String msg = "could not create the CMSEnvelopedData";
      LogUtil.error(LOG, ex);
      ret.setFailureMessage(msg + ": " + ex.getMessage());

      ret.setDecryptionSuccessful(false);
      return ret;
    }

    ret.setDecryptionSuccessful(true);

    try {
      switch (messageType) {
        case PKCSReq:
        case RenewalReq:
          ret.setMessageData(CertificationRequest.fromEncoded(
                X509Util.toDerEncoded(encodedMessageData)));
          break;
        case CertPoll:
          ret.setMessageData(IssuerAndSubject.fromEncoded(encodedMessageData));
          break;
        case GetCert:
        case GetCRL:
          ret.setMessageData(IssuerAndSerialNumber.fromEncoded(encodedMessageData));
          break;
        case CertRep:
          ret.setMessageData(ContentInfo.fromEncoded(encodedMessageData));
          break;
        default:
          throw new RuntimeException("should not reach here, unknown messageType " + messageType);
      }
    } catch (Exception ex) {
      final String msg = "could not parse the messageData";
      LogUtil.error(LOG, ex);
      ret.setFailureMessage(msg + ": " + ex.getMessage());
      return ret;
    }

    return ret;
  } // method decode

}
