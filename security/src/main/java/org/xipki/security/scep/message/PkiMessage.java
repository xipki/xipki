// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.scep.message;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import org.xipki.security.OIDs;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.scep.transaction.FailInfo;
import org.xipki.security.scep.transaction.MessageType;
import org.xipki.security.scep.transaction.Nonce;
import org.xipki.security.scep.transaction.PkiStatus;
import org.xipki.security.scep.transaction.TransactionId;
import org.xipki.security.scep.util.ScepUtil;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.extra.misc.CollectionUtil;

import java.io.IOException;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * SCEP PKI-Message.
 *
 * @author Lijun Liao (xipki)
 */

public class PkiMessage {

  private static final Set<ASN1ObjectIdentifier> SCEP_ATTR_TYPES;

  private final Map<ASN1ObjectIdentifier, ASN1Encodable> signedAttributes =
      new HashMap<>();

  private final Map<ASN1ObjectIdentifier, ASN1Encodable> unsignedAttributes =
      new HashMap<>();

  private final MessageType messageType;

  private final Nonce senderNonce;

  private final TransactionId transactionId;

  private Nonce recipientNonce;

  private PkiStatus pkiStatus;

  private FailInfo failInfo;

  private String failInfoText;

  private ASN1Encodable messageData;

  static {
    SCEP_ATTR_TYPES = CollectionUtil.asSet(
        OIDs.Scep.failInfo, OIDs.Scep.messageType,
        OIDs.Scep.pkiStatus, OIDs.Scep.recipientNonce,
        OIDs.Scep.senderNonce, OIDs.Scep.transactionId,
        OIDs.Scep.failInfoText, OIDs.PKCS9.pkcs9_at_signingTime);
  }

  public PkiMessage(TransactionId transactionId, MessageType messageType) {
    this(transactionId, messageType, Nonce.randomNonce());
  }

  public PkiMessage(TransactionId transactionId, MessageType messageType,
                    Nonce senderNonce) {
    this.transactionId = Args.notNull(transactionId, "transactionId");
    this.messageType = Args.notNull(messageType, "messageType");
    this.senderNonce = Args.notNull(senderNonce, "senderNonce");
  }

  public TransactionId getTransactionId() {
    return transactionId;
  }

  public Nonce getSenderNonce() {
    return senderNonce;
  }

  public MessageType getMessageType() {
    return messageType;
  }

  public Nonce getRecipientNonce() {
    return recipientNonce;
  }

  public void setRecipientNonce(Nonce recipientNonce) {
    this.recipientNonce = recipientNonce;
  }

  public PkiStatus getPkiStatus() {
    return pkiStatus;
  }

  public void setPkiStatus(PkiStatus pkiStatus) {
    this.pkiStatus = pkiStatus;
  }

  public FailInfo getFailInfo() {
    return failInfo;
  }

  public void setFailInfo(FailInfo failInfo) {
    this.failInfo = failInfo;
  }

  public String getFailInfoText() {
    return failInfoText;
  }

  public void setFailInfoText(String failInfoText) {
    this.failInfoText = failInfoText;
  }

  public ASN1Encodable getMessageData() {
    return messageData;
  }

  public void setMessageData(ASN1Encodable messageData) {
    this.messageData = messageData;
  }

  public ASN1Encodable addSignedAttribute(
      ASN1ObjectIdentifier type, ASN1Encodable value) {
    if (SCEP_ATTR_TYPES.contains(type)) {
      throw new IllegalArgumentException("Adding SCEP attribute via " +
          "addSignedAttribute() method is not permitted");
    }
    return signedAttributes.put(type, value);
  }

  public ASN1Encodable addUnsignedAttribute(
      ASN1ObjectIdentifier type, ASN1Encodable value) {
    return unsignedAttributes.put(type, value);
  }

  public ASN1Encodable removeSignedAttribute(ASN1ObjectIdentifier type) {
    return signedAttributes.remove(type);
  }

  public ASN1Encodable removeUnsignedAttribute(ASN1ObjectIdentifier type) {
    return unsignedAttributes.remove(type);
  }

  public ASN1Encodable getSignedAtrributeValue(ASN1ObjectIdentifier type) {
    return signedAttributes.get(type);
  }

  public ASN1Encodable getUnsignedAtrributeValue(ASN1ObjectIdentifier type) {
    return unsignedAttributes.get(type);
  }

  private AttributeTable getSignedAttributes() {
    ASN1EncodableVector vec = new ASN1EncodableVector();
    // messageType
    addAttribute(vec, OIDs.Scep.messageType,
        new DERPrintableString(Integer.toString(messageType.getCode())));

    // senderNonce
    addAttribute(vec, OIDs.Scep.senderNonce,
        new DEROctetString(senderNonce.getBytes()));

    // transactionID
    addAttribute(vec, OIDs.Scep.transactionId,
        new DERPrintableString(transactionId.getId()));

    // failInfo
    if (failInfo != null) {
      addAttribute(vec, OIDs.Scep.failInfo,
          new DERPrintableString(Integer.toString(failInfo.getCode())));
    }

    // failInfoText
    if (failInfoText != null && !failInfoText.isEmpty()) {
      addAttribute(vec, OIDs.Scep.failInfoText,
          new DERUTF8String(failInfoText));
    }

    // pkiStatus
    if (pkiStatus != null) {
      addAttribute(vec, OIDs.Scep.pkiStatus,
          new DERPrintableString(Integer.toString(pkiStatus.getCode())));
    }

    // recipientNonce
    if (recipientNonce != null) {
      addAttribute(vec, OIDs.Scep.recipientNonce,
          new DEROctetString(recipientNonce.getBytes()));
    }

    for (Entry<ASN1ObjectIdentifier, ASN1Encodable> entry
        : signedAttributes.entrySet()) {
      addAttribute(vec, entry.getKey(), entry.getValue());
    }
    return new AttributeTable(vec);
  } // method getSignedAttributes

  private AttributeTable getUnsignedAttributes() {
    if (unsignedAttributes.isEmpty()) {
      return null;
    }
    ASN1EncodableVector vec = new ASN1EncodableVector();

    for (Entry<ASN1ObjectIdentifier, ASN1Encodable> entry
        : unsignedAttributes.entrySet()) {
      addAttribute(vec, entry.getKey(), entry.getValue());
    }
    return new AttributeTable(vec);
  }

  public ContentInfo encode(
      PrivateKey signerKey, SignAlgo signatureAlgorithm, X509Cert signerCert,
      X509Cert[] signerCertSet, X509Cert recipientCert,
      ASN1ObjectIdentifier encAlgId)
      throws CodecException {
    Args.notNull(signerKey, "signerKey");
    ContentSigner signer;
    try {
      signer = new JcaContentSignerBuilder(
                signatureAlgorithm.getJceName()).build(signerKey);
    } catch (OperatorCreationException ex) {
      throw new CodecException(ex);
    }
    return encode(signer, signerCert, signerCertSet, recipientCert, encAlgId);
  } // method encode

  public ContentInfo encode(
      ContentSigner signer, X509Cert signerCert, X509Cert[] cmsCertSet,
      X509Cert recipientCert, ASN1ObjectIdentifier encAlgId)
      throws CodecException {
    Args.notNull(signer, "signer");
    Args.notNull(signerCert, "signerCert");
    if (messageData != null) {
      Args.notNull(recipientCert, "recipientCert");
      Args.notNull(encAlgId, "encAlgId");
    }

    CMSTypedData content;
    if (messageData == null) {
      content = new CMSAbsentContent();
    } else {
      CMSEnvelopedData envelopedData = encrypt(recipientCert, encAlgId);
      byte[] encoded;
      try {
        encoded = envelopedData.getEncoded();
      } catch (IOException ex) {
        throw new CodecException(ex);
      }
      content = new CMSProcessableByteArray(OIDs.CMS.envelopedData, encoded);
    }

    try {
      CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

      // signerInfo
      JcaSignerInfoGeneratorBuilder signerInfoBuilder =
          new JcaSignerInfoGeneratorBuilder(new BcDigestCalculatorProvider());

      signerInfoBuilder.setSignedAttributeGenerator(
          new DefaultSignedAttributeTableGenerator(getSignedAttributes()));

      AttributeTable attrTable = getUnsignedAttributes();
      if (attrTable != null) {
        signerInfoBuilder.setUnsignedAttributeGenerator(
            new SimpleAttributeTableGenerator(attrTable));
      }

      // certificateSet
      ScepUtil.addCmsCertSet(generator, cmsCertSet);

      SignerInfoGenerator signerInfo;
      try {
        signerInfo = signerInfoBuilder.build(signer, signerCert.toBcCert());
      } catch (Exception ex) {
        throw new CodecException(ex);
      }

      generator.addSignerInfoGenerator(signerInfo);

      return generator.generate(content, true).toASN1Structure();
    } catch (Exception ex) {
      throw new CodecException(ex);
    }
  } // method encode

  // TODO: use password based encryption for not-encryptable public key.
  private CMSEnvelopedData encrypt(
      X509Cert recipient, ASN1ObjectIdentifier encAlgId)
      throws CodecException {
    Args.notNull(recipient, "recipient");
    Args.notNull(encAlgId, "encAlgId");

    byte[] messageDataBytes;
    try {
      messageDataBytes = messageData.toASN1Primitive().getEncoded();
    } catch (IOException ex) {
      throw new CodecException(ex);
    }

    CMSEnvelopedDataGenerator edGenerator = new CMSEnvelopedDataGenerator();
    CMSTypedData envelopable = new CMSProcessableByteArray(messageDataBytes);
    RecipientInfoGenerator recipientGenerator =
        new KeyTransRecipientInfoGenerator(
            new IssuerAndSerialNumber(recipient.getIssuer(),
                recipient.getSerialNumber()),
            new JceAsymmetricKeyWrapper(recipient.getPublicKey())) {};

    edGenerator.addRecipientInfoGenerator(recipientGenerator);
    try {
      return edGenerator.generate(envelopable,
          new JceCMSContentEncryptorBuilder(encAlgId).build());
    } catch (CMSException ex) {
      throw new CodecException(ex);
    }
  }

  private static void addAttribute(
      ASN1EncodableVector vector, ASN1ObjectIdentifier attrType,
      ASN1Encodable attrValue) {
    vector.add(new Attribute(attrType, new DERSet(attrValue)));
  }

}
