// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.message;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.CollectionStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.scep.message.EnvelopedDataDecryptor.EnvelopedDataDecryptorInstance;
import org.xipki.scep.transaction.*;
import org.xipki.scep.util.ScepUtil;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.DecodeException;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;

import static org.xipki.scep.util.ScepConstants.*;

/**
 * Decoded {@link PkiMessage}.
 *
 * @author Lijun Liao (xipki)
 */

public class DecodedPkiMessage extends PkiMessage {

  private static final Logger LOG = LoggerFactory.getLogger(DecodedPkiMessage.class);

  private static final Set<ASN1ObjectIdentifier> SCEP_ATTR_TYPES;

  private X509Cert signatureCert;

  private HashAlgo digestAlgorithm;

  private ASN1ObjectIdentifier contentEncryptionAlgorithm;

  private Boolean signatureValid;

  private Boolean decryptionSuccessful;

  private Instant signingTime;

  private String failureMessage;

  static {
    SCEP_ATTR_TYPES = CollectionUtil.asSet(ID_FAILINFO, ID_MESSAGE_TYPE, ID_PKI_STATUS,
        ID_RECIPIENT_NONCE, ID_SENDER_NONCE, ID_TRANSACTION_ID,  CMSAttributes.signingTime);
  }

  public DecodedPkiMessage(TransactionId transactionId, MessageType messageType, Nonce senderNonce) {
    super(transactionId, messageType, senderNonce);
  }

  public X509Cert getSignatureCert() {
    return signatureCert;
  }

  public void setSignatureCert(X509Cert signatureCert) {
    this.signatureCert = signatureCert;
  }

  public HashAlgo getDigestAlgorithm() {
    return digestAlgorithm;
  }

  public void setDigestAlgorithm(HashAlgo digestAlgorithm) {
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

  public Instant getSigningTime() {
    return signingTime;
  }

  public void setSigningTime(Instant signingTime) {
    this.signingTime = signingTime;
  }

  public static DecodedPkiMessage decode(CMSSignedData pkiMessage, PrivateKey recipientKey,
                                         X509Cert recipientCert, CollectionStore<X509CertificateHolder> certStore)
      throws DecodeException {
    EnvelopedDataDecryptorInstance decInstance = new EnvelopedDataDecryptorInstance(recipientCert, recipientKey);
    return decode(pkiMessage, new EnvelopedDataDecryptor(decInstance), certStore);
  }

  @SuppressWarnings("unchecked")
  public static DecodedPkiMessage decode(
      CMSSignedData pkiMessage, EnvelopedDataDecryptor recipient, CollectionStore<X509CertificateHolder> certStore)
      throws DecodeException {
    Args.notNull(recipient, "recipient");

    SignerInformationStore signerStore = Args.notNull(pkiMessage, "pkiMessage").getSignerInfos();
    Collection<SignerInformation> signerInfos = signerStore.getSigners();
    if (signerInfos.size() != 1) {
      throw new DecodeException("number of signerInfos is not 1, but " + signerInfos.size());
    }

    SignerInformation signerInfo = signerInfos.iterator().next();
    SignerId sid = signerInfo.getSID();

    Collection<?> signedDataCerts = (certStore == null) ? null : certStore.getMatches(sid);
    if (CollectionUtil.isEmpty(signedDataCerts)) {
      signedDataCerts = pkiMessage.getCertificates().getMatches(signerInfo.getSID());
    }

    if (signedDataCerts == null || signedDataCerts.size() != 1) {
      throw new DecodeException("could not find embedded certificate to verify the signature");
    }

    AttributeTable signedAttrs = Optional.ofNullable(signerInfo.getSignedAttributes()).orElseThrow(
        () -> new DecodeException("missing SCEP attributes"));

    // signingTime
    ASN1Encodable attrValue = ScepUtil.getFirstAttrValue(signedAttrs, CMSAttributes.signingTime);
    Instant signingTime = (attrValue == null) ? null : ScepUtil.getTime(attrValue);

    // transactionId
    String str = getPrintableStringAttrValue(signedAttrs, ID_TRANSACTION_ID);
    if (StringUtil.isBlank(str)) {
      throw new DecodeException("missing required SCEP attribute transactionId");
    }
    TransactionId tid = new TransactionId(str);

    // messageType
    int iValue = Optional.ofNullable(getIntegerPrintStringAttrValue(signedAttrs, ID_MESSAGE_TYPE)).orElseThrow(
      () -> new DecodeException("tid " + tid.getId() + ": missing required SCEP attribute messageType"));

    MessageType messageType;
    try {
      messageType = MessageType.forValue(iValue);
    } catch (IllegalArgumentException ex) {
      throw new DecodeException("tid " + tid.getId() + ": invalid messageType '" + iValue + "'");
    }

    // senderNonce
    Nonce senderNonce = Optional.ofNullable(getNonceAttrValue(signedAttrs, ID_SENDER_NONCE)).orElseThrow(
        () -> new DecodeException("tid " + tid.getId() + ": missing required SCEP attribute senderNonce"));

    DecodedPkiMessage ret = new DecodedPkiMessage(tid, messageType, senderNonce);
    if (signingTime != null) {
      ret.setSigningTime(signingTime);
    }

    Nonce recipientNonce = null;
    try {
      recipientNonce = getNonceAttrValue(signedAttrs, ID_RECIPIENT_NONCE);
    } catch (DecodeException ex) {
      ret.setFailureMessage("could not parse recipientNonce: " + ex.getMessage());
    }

    if (recipientNonce != null) {
      ret.setRecipientNonce(recipientNonce);
    }

    PkiStatus pkiStatus = null;
    FailInfo failInfo;
    if (MessageType.CertRep == messageType) {
      Integer intValue;
      // pkiStatus
      try {
        intValue = getIntegerPrintStringAttrValue(signedAttrs, ID_PKI_STATUS);
      } catch (DecodeException ex) {
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
          intValue = getIntegerPrintStringAttrValue(signedAttrs, ID_FAILINFO);
        } catch (DecodeException ex) {
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

        // failInfoText
        ASN1Encodable value = ScepUtil.getFirstAttrValue(signedAttrs, ID_SCEP_FAILINFOTEXT);
        if (value != null) {
          if (value instanceof ASN1UTF8String) {
            ret.setFailInfoText(((ASN1UTF8String) value).getString());
          } else {
            throw new DecodeException("the value of attribute failInfoText is not UTF8String");
          }
        }
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

    try {
      HashAlgo digestAlgo = HashAlgo.getInstance(signerInfo.getDigestAlgorithmID());
      ret.setDigestAlgorithm(digestAlgo);

      String sigAlgOid = signerInfo.getEncryptionAlgOID();
      if (!PKCSObjectIdentifiers.rsaEncryption.getId().equals(sigAlgOid)) {
        SignAlgo signAlgo = SignAlgo.getInstance(signerInfo.toASN1Structure().getDigestEncryptionAlgorithm());

        if (digestAlgo != signAlgo.getHashAlgo()) {
          ret.setFailureMessage("digestAlgorithm and encryptionAlgorithm do not use the same digestAlgorithm");
          return ret;
        }
      }
    } catch (NoSuchAlgorithmException ex) {
      LogUtil.error(LOG, ex);
      ret.setFailureMessage(ex.getMessage());
      return ret;
    }

    X509CertificateHolder signerCert = (X509CertificateHolder) signedDataCerts.iterator().next();
    ret.setSignatureCert(new X509Cert(signerCert));

    // validate the signature
    SignerInformationVerifier verifier;
    try {
      verifier = new JcaSimpleSignerInfoVerifierBuilder().build(signerCert);
    } catch (OperatorCreationException | CertificateException ex) {
      final String msg = "could not build signature verifier";
      LogUtil.error(LOG, ex);
      ret.setFailureMessage(msg + ": " + ex.getMessage());
      return ret;
    }

    boolean signatureValid;
    try {
      signatureValid = signerInfo.verify(verifier);
    } catch (CMSException ex) {
      final String msg = "could not verify the signature";
      LogUtil.error(LOG, ex);
      ret.setFailureMessage(msg + ": " + ex.getMessage());
      return ret;
    }

    ret.setSignatureValid(signatureValid);
    if (!signatureValid) {
      return ret;
    }

    if (MessageType.CertRep == messageType && (pkiStatus == PkiStatus.FAILURE | pkiStatus == PkiStatus.PENDING)) {
      return ret;
    }

    // MessageData
    CMSTypedData signedContent = pkiMessage.getSignedContent();
    ASN1ObjectIdentifier signedContentType = signedContent.getContentType();
    if (!CMSObjectIdentifiers.envelopedData.equals(signedContentType)) {
      // fall back: some SCEP client, such as JSCEP use id-data
      if (!CMSObjectIdentifiers.data.equals(signedContentType)) {
        ret.setFailureMessage("either id-envelopedData or id-data is excepted, but not '" + signedContentType.getId());
        return ret;
      }
    }

    CMSEnvelopedData envData;
    try {
      envData = new CMSEnvelopedData((byte[]) signedContent.getContent());
    } catch (CMSException ex) {
      final String msg = "could not create the CMSEnvelopedData";
      LogUtil.error(LOG, ex);
      ret.setFailureMessage(msg + ": " + ex.getMessage());
      return ret;
    }

    ret.setContentEncryptionAlgorithm(envData.getContentEncryptionAlgorithm().getAlgorithm());
    byte[] encodedMessageData;
    try {
      encodedMessageData = recipient.decrypt(envData);
    } catch (DecodeException ex) {
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
          ret.setMessageData(CertificationRequest.getInstance(X509Util.toDerEncoded(encodedMessageData)));
          break;
        case CertPoll:
          ret.setMessageData(IssuerAndSubject.getInstance(encodedMessageData));
          break;
        case GetCert:
        case GetCRL:
          ret.setMessageData(IssuerAndSerialNumber.getInstance(encodedMessageData));
          break;
        case CertRep:
          ret.setMessageData(ContentInfo.getInstance(encodedMessageData));
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

  private static String getPrintableStringAttrValue(AttributeTable attrs, ASN1ObjectIdentifier type)
      throws DecodeException {
    ASN1Encodable value = ScepUtil.getFirstAttrValue(attrs, type);
    if (value instanceof ASN1PrintableString) {
      return ((ASN1PrintableString) value).getString();
    } else if (value != null) {
      throw new DecodeException("the value of attribute " + type.getId() + " is not PrintableString");
    } else {
      return null;
    }
  }

  private static Integer getIntegerPrintStringAttrValue(AttributeTable attrs, ASN1ObjectIdentifier type)
      throws DecodeException {
    String str = getPrintableStringAttrValue(attrs, type);
    try {
      return str == null ? null : Integer.parseInt(str);
    } catch (NumberFormatException ex) {
      throw new DecodeException("invalid integer '" + str + "'");
    }
  }

  private static Nonce getNonceAttrValue(AttributeTable attrs, ASN1ObjectIdentifier type)
      throws DecodeException {
    ASN1Encodable value = ScepUtil.getFirstAttrValue(attrs, type);
    if (value instanceof ASN1OctetString) {
      byte[] bytes = ((ASN1OctetString) value).getOctets();
      return new Nonce(bytes);
    } else if (value != null) {
      throw new DecodeException("the value of attribute " + type.getId() + " is not OctetString");
    } else {
      return null;
    }
  }

}
