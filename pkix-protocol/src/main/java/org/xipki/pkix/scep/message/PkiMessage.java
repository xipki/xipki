// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.scep.message;

import org.xipki.asn1.cms.Attributes;
import org.xipki.asn1.cms.ContentInfo;
import org.xipki.asn1.x509.Attribute;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.asn1.oid.AttributeOIDs;
import org.xipki.codec.asn1.oid.CmsOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.pkix.cms.CmsEnvelopedData;
import org.xipki.pkix.cms.CmsSignedData;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.scep.transaction.FailInfo;
import org.xipki.pkix.scep.transaction.MessageType;
import org.xipki.pkix.scep.transaction.Nonce;
import org.xipki.pkix.scep.transaction.PkiStatus;
import org.xipki.pkix.scep.transaction.TransactionId;
import org.xipki.pkix.scep.util.ScepUtil;
import org.xipki.pkix.sign.SignatureSigner;
import org.xipki.util.exception.PkixException;
import org.xipki.util.misc.CollectionUtil;

import java.security.PrivateKey;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * Pki Message.
 *
 * @author Lijun Liao (xipki)
 */
public class PkiMessage {

  private static final Set<Asn1Oid> SCEP_ATTR_TYPES;

  private final Map<Asn1Oid, Attribute> signedAttributes = new HashMap<>();

  private final Map<Asn1Oid, Attribute> unsignedAttributes = new HashMap<>();

  private final MessageType messageType;

  private final Nonce senderNonce;

  private final TransactionId transactionId;

  private Nonce recipientNonce;

  private PkiStatus pkiStatus;

  private FailInfo failInfo;

  private String failInfoText;

  private Asn1Primitive messageData;

  static {
    SCEP_ATTR_TYPES = CollectionUtil.asSet(
        AttributeOIDs.scep_failInfo,     AttributeOIDs.scep_messageType,
        AttributeOIDs.scep_pkiStatus,    AttributeOIDs.scep_recipientNonce,
        AttributeOIDs.scep_senderNonce,  AttributeOIDs.scep_transactionId,
        AttributeOIDs.scep_failInfoText, AttributeOIDs.signingTime);
  }

  public PkiMessage(TransactionId transactionId, MessageType messageType) {
    this(transactionId, messageType, Nonce.randomNonce());
  }

  public PkiMessage(TransactionId transactionId, MessageType messageType, Nonce senderNonce) {
    this.transactionId = Args.notNull(transactionId, "transactionId");
    this.messageType = Args.notNull(messageType, "messageType");
    this.senderNonce = Args.notNull(senderNonce, "senderNonce");
  }

  public TransactionId transactionId() {
    return transactionId;
  }

  public Nonce senderNonce() {
    return senderNonce;
  }

  public MessageType messageType() {
    return messageType;
  }

  public Nonce recipientNonce() {
    return recipientNonce;
  }

  public void setRecipientNonce(Nonce recipientNonce) {
    this.recipientNonce = recipientNonce;
  }

  public PkiStatus pkiStatus() {
    return pkiStatus;
  }

  public void setPkiStatus(PkiStatus pkiStatus) {
    this.pkiStatus = pkiStatus;
  }

  public FailInfo failInfo() {
    return failInfo;
  }

  public void setFailInfo(FailInfo failInfo) {
    this.failInfo = failInfo;
  }

  public String failInfoText() {
    return failInfoText;
  }

  public void setFailInfoText(String failInfoText) {
    this.failInfoText = failInfoText;
  }

  public Asn1Primitive messageData() {
    return messageData;
  }

  public void setMessageData(Asn1Encodable messageData) {
    this.messageData = (messageData == null) ? null : messageData.toAsn1Primitive();
  }

  public Attribute addSignedAttribute(Attribute attr) {
    Asn1Oid type = attr.getAttrType();
    if (SCEP_ATTR_TYPES.contains(type)) {
      throw new IllegalArgumentException("Adding SCEP attribute via " +
          "addSignedAttribute() method is not permitted");
    }

    return signedAttributes.put(type, attr);
  }

  public Attribute addUnsignedAttribute(Attribute attr) {
    return unsignedAttributes.put(attr.getAttrType(), attr);
  }

  private Attributes signedAttributes() {
    List<Attribute> vec = new LinkedList<>();

    // messageType
    addAttribute(vec, Attribute.ofScepMessageType(messageType.code()));

    // senderNonce
    addAttribute(vec, Attribute.ofScepSenderNonce(senderNonce.bytes()));

    // transactionID
    addAttribute(vec, Attribute.ofScepTransactionId(transactionId.id()));

    // failInfo
    if (failInfo != null) {
      addAttribute(vec, Attribute.ofScepFailInfo(failInfo.code()));
    }

    // failInfoText
    if (failInfoText != null && !failInfoText.isEmpty()) {
      addAttribute(vec, Attribute.ofScepFailInfoText(failInfoText));
    }

    // pkiStatus
    if (pkiStatus != null) {
      addAttribute(vec, Attribute.ofScepPkiStatus(pkiStatus.code()));
    }

    // recipientNonce
    if (recipientNonce != null) {
      addAttribute(vec, Attribute.ofScepRecipientNonce(recipientNonce.bytes()));
    }

    for (Entry<Asn1Oid, Attribute> entry : signedAttributes.entrySet()) {
      addAttribute(vec, entry.getValue());
    }
    return new Attributes(vec);
  } // method getSignedAttributes

  private Attributes unsignedAttributes() {
    if (unsignedAttributes.isEmpty()) {
      return null;
    }

    List<Attribute> vec = new LinkedList<>();

    for (Entry<Asn1Oid, Attribute> entry : unsignedAttributes.entrySet()) {
      addAttribute(vec, entry.getValue());
    }
    return new Attributes(vec);
  }

  public ContentInfo encode(
      PrivateKey signerKey, SignAlgo signatureAlgorithm, X509Cert signerCert,
      X509Cert[] signerCertSet, X509Cert recipientCert, Asn1Oid encAlgId)
      throws CodecException {
    Args.notNull(signerKey, "signerKey");
    ContentSigner signer;
    try {
      signer = SignatureSigner.newContentSigner(signatureAlgorithm, signerKey);
    } catch (XiSecurityException ex) {
      throw new CodecException(ex);
    }
    return encode(signer, signerCert, signerCertSet, recipientCert, encAlgId);
  } // method encode

  public ContentInfo encode(
      ContentSigner signer, X509Cert signerCert, X509Cert[] cmsCertSet,
      X509Cert recipientCert, Asn1Oid encAlgId) throws CodecException {
    Args.notNull(signer, "signer");
    Args.notNull(signerCert, "signerCert");
    if (messageData != null) {
      Args.notNull(recipientCert, "recipientCert");
      Args.notNull(encAlgId, "encAlgId");
    }

    try {
      CmsSignedData.Builder builder = new CmsSignedData.Builder();
      // without messageData, e.g. in the CertRep with status FAILURE, the content is absent.
      if (messageData != null) {
        builder.setContent(CmsOIDs.envelopedData,
            encrypt(recipientCert, encAlgId).getEncoded(), true);
      }

      builder.addSigner(signer, signerCert.getCert(),
          ScepUtil.getDigestAlgorithm(signer.getAlgorithmIdentifier()),
          signedAttributes(), unsignedAttributes());

      // certificateSet
      ScepUtil.addCmsCertSet(builder, cmsCertSet);

      return builder.build().toASN1Structure();
    } catch (PkixException ex) {
      throw new CodecException(ex);
    }
  } // method encode

  // TODO: use password based encryption for not-encryptable public key.
  private CmsEnvelopedData encrypt(X509Cert recipient, Asn1Oid encAlgId)
      throws PkixException {
    return new CmsEnvelopedData.Builder()
        .addKeyTransRecipient(recipient.getCert())
        .build(encAlgId, messageData.getEncoded());
  }

  private static void addAttribute(List<Attribute> vector, Attribute attr) {
    vector.add(attr);
  }

}
