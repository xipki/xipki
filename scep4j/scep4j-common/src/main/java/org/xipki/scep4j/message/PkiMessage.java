/*
 * Copyright (c) 2015 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.scep4j.message;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.xipki.scep4j.exception.MessageEncodingException;
import org.xipki.scep4j.transaction.FailInfo;
import org.xipki.scep4j.transaction.MessageType;
import org.xipki.scep4j.transaction.Nonce;
import org.xipki.scep4j.transaction.PkiStatus;
import org.xipki.scep4j.transaction.TransactionId;
import org.xipki.scep4j.util.ParamUtil;
import org.xipki.scep4j.util.ScepUtil;

/**
 * @author Lijun Liao
 */

public class PkiMessage
{
    private static final Set<ASN1ObjectIdentifier> scepAttrTypes = new HashSet<ASN1ObjectIdentifier>();

    private final MessageType messageType;
    private final Nonce senderNonce;
    private final TransactionId transactionId;

    private Nonce recipientNonce;
    private PkiStatus pkiStatus;
    private FailInfo failInfo;

    private ASN1Encodable messageData;

    private final Map<ASN1ObjectIdentifier, ASN1Encodable> signedAttributes =
            new HashMap<ASN1ObjectIdentifier, ASN1Encodable>();
    private final Map<ASN1ObjectIdentifier, ASN1Encodable> unsignedAttributes =
            new HashMap<ASN1ObjectIdentifier, ASN1Encodable>();

    static
    {
        scepAttrTypes.add(ScepObjectIdentifiers.id_failInfo);
        scepAttrTypes.add(ScepObjectIdentifiers.id_messageType);
        scepAttrTypes.add(ScepObjectIdentifiers.id_pkiStatus);
        scepAttrTypes.add(ScepObjectIdentifiers.id_recipientNonce);
        scepAttrTypes.add(ScepObjectIdentifiers.id_senderNonce);
        scepAttrTypes.add(ScepObjectIdentifiers.id_transactionID);
        scepAttrTypes.add(CMSAttributes.signingTime);
    }

    public PkiMessage(
            final TransactionId transactionId,
            final MessageType messageType)
    {
        ParamUtil.assertNotNull("transactionId", transactionId);
        ParamUtil.assertNotNull("messageType", messageType);

        this.transactionId = transactionId;
        this.messageType = messageType;
        this.senderNonce = Nonce.randomNonce();
    }

    public PkiMessage(
            final TransactionId transactionId,
            final MessageType messageType,
            final Nonce senderNonce)
    {
        ParamUtil.assertNotNull("transactionId", transactionId);
        ParamUtil.assertNotNull("messageType", messageType);
        ParamUtil.assertNotNull("senderNonce", senderNonce);

        this.transactionId = transactionId;
        this.messageType = messageType;
        this.senderNonce = senderNonce;
    }

    public TransactionId getTransactionId()
    {
        return transactionId;
    }

    public Nonce getSenderNonce()
    {
        return senderNonce;
    }

    public final MessageType getMessageType()
    {
        return messageType;
    }

    public Nonce getRecipientNonce()
    {
        return recipientNonce;
    }

    public void setRecipientNonce(
            final Nonce recipientNonce)
    {
        this.recipientNonce = recipientNonce;
    }

    public PkiStatus getPkiStatus()
    {
        return pkiStatus;
    }

    public void setPkiStatus(
            final PkiStatus pkiStatus)
    {
        this.pkiStatus = pkiStatus;
    }

    public FailInfo getFailInfo()
    {
        return failInfo;
    }

    public void setFailInfo(
            final FailInfo failInfo)
    {
        this.failInfo = failInfo;
    }

    public ASN1Encodable getMessageData()
    {
        return messageData;
    }

    public void setMessageData(
            final ASN1Encodable messageData)
    {
        this.messageData = messageData;
    }

    public ASN1Encodable addSignendAttribute(
            final ASN1ObjectIdentifier type,
            final ASN1Encodable value)
    {
        if(scepAttrTypes.contains(type))
        {
            throw new IllegalArgumentException("Adding SCEP attribute via addSignedAttribute() method is not permitted");
        }
        return signedAttributes.put(type, value);
    }

    public ASN1Encodable addUnsignendAttribute(
            final ASN1ObjectIdentifier type,
            final ASN1Encodable value)
    {
        return unsignedAttributes.put(type, value);
    }

    public ASN1Encodable removeSignedAttribute(
            final ASN1ObjectIdentifier type)
    {
        return signedAttributes.remove(type);
    }

    public ASN1Encodable removeUnsignedAttribute(
            final ASN1ObjectIdentifier type)
    {
        return unsignedAttributes.remove(type);
    }

    public ASN1Encodable getSignedAtrributeValue(
            final ASN1ObjectIdentifier type)
    {
        return signedAttributes.get(type);
    }

    public ASN1Encodable getUnsignedAtrributeValue(
            final ASN1ObjectIdentifier type)
    {
        return unsignedAttributes.get(type);
    }

    private AttributeTable getSignedAttributes()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        // messageType
        addAttribute(v, ScepObjectIdentifiers.id_messageType,
                new DERPrintableString(
                        Integer.toString(messageType.getCode())));

        // senderNonce
        addAttribute(v, ScepObjectIdentifiers.id_senderNonce,
                new DEROctetString(senderNonce.getBytes()));

        // transactionID
        addAttribute(v, ScepObjectIdentifiers.id_transactionID,
                new DERPrintableString(transactionId.getId()));

        // failInfo
        if(failInfo != null)
        {
            addAttribute(v, ScepObjectIdentifiers.id_failInfo,
                    new DERPrintableString(
                            Integer.toString(failInfo.getCode())));
        }

        // pkiStatus
        if(pkiStatus != null)
        {
            addAttribute(v, ScepObjectIdentifiers.id_pkiStatus,
                    new DERPrintableString(
                            Integer.toString(pkiStatus.getCode())));
        }

        // recipientNonce
        if(recipientNonce != null)
        {
            addAttribute(v, ScepObjectIdentifiers.id_recipientNonce,
                    new DEROctetString(recipientNonce.getBytes()));
        }

        for(ASN1ObjectIdentifier type : signedAttributes.keySet())
        {
            addAttribute(v, type, signedAttributes.get(type));
        }
        return new AttributeTable(v);
    }

    private AttributeTable getUnsignedAttributes()
    {
        if(unsignedAttributes.isEmpty())
        {
            return null;
        }
        ASN1EncodableVector v = new ASN1EncodableVector();

        for(ASN1ObjectIdentifier type : unsignedAttributes.keySet())
        {
            addAttribute(v, type, unsignedAttributes.get(type));
        }
        return new AttributeTable(v);
    }

    public ContentInfo encode(
            final PrivateKey signerKey,
            final String signatureAlgorithm,
            final X509Certificate signerCert,
            final X509Certificate[] signerCertSet,
            final X509Certificate recipientCert,
            final ASN1ObjectIdentifier encAlgId)
    throws MessageEncodingException
    {
        ContentSigner signer;
        try
        {
            signer = new JcaContentSignerBuilder(signatureAlgorithm).build(signerKey);
        } catch (OperatorCreationException e)
        {
            throw new MessageEncodingException(e);
        }
        return encode(signer, signerCert, signerCertSet, recipientCert, encAlgId);
    }

    public ContentInfo encode(
            final ContentSigner signer,
            final X509Certificate signerCert,
            final X509Certificate[] cmsCertSet,
            final X509Certificate recipientCert,
            final ASN1ObjectIdentifier encAlgId)
    throws MessageEncodingException
    {
        CMSTypedData content;
        if(messageData == null)
        {
            content = new CMSAbsentContent();
        }
        else
        {
            CMSEnvelopedData envelopedData = encrypt(recipientCert, encAlgId);
            byte[] encoded;
            try
            {
                encoded = envelopedData.getEncoded();
            } catch (IOException e)
            {
                throw new MessageEncodingException(e);
            }
            content = new CMSProcessableByteArray(
                    CMSObjectIdentifiers.envelopedData, encoded);
        }

        try
        {
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

            // signerInfo
            JcaSignerInfoGeneratorBuilder signerInfoBuilder = new JcaSignerInfoGeneratorBuilder(
                    new BcDigestCalculatorProvider());

            signerInfoBuilder.setSignedAttributeGenerator(
                    new DefaultSignedAttributeTableGenerator(getSignedAttributes()));

            AttributeTable attrTable = getUnsignedAttributes();
            if(attrTable != null)
            {
                signerInfoBuilder.setUnsignedAttributeGenerator(
                        new SimpleAttributeTableGenerator(attrTable));
            }

            // certificateSet
            ScepUtil.addCmsCertSet(generator, cmsCertSet);

            SignerInfoGenerator signerInfo;
            try
            {
                signerInfo = signerInfoBuilder.build(signer, signerCert);
            } catch (Exception e)
            {
                throw new MessageEncodingException(e);
            }

            generator.addSignerInfoGenerator(signerInfo);

            CMSSignedData signedData = generator.generate(content, true);
            return signedData.toASN1Structure();
        } catch (CMSException e)
        {
            throw new MessageEncodingException(e);
        } catch (Exception e)
        {
            throw new MessageEncodingException(e);
        }
    }

    private CMSEnvelopedData encrypt(
            final X509Certificate recipient,
            final ASN1ObjectIdentifier encAlgId)
    throws MessageEncodingException
    {
        byte[] messageDataBytes;
        try
        {
            messageDataBytes = messageData.toASN1Primitive().getEncoded();
        } catch (IOException e)
        {
            throw new MessageEncodingException(e);
        }

        CMSEnvelopedDataGenerator edGenerator = new CMSEnvelopedDataGenerator();
        CMSTypedData envelopable = new CMSProcessableByteArray(messageDataBytes);
        RecipientInfoGenerator recipientGenerator;
        try
        {
            recipientGenerator = new JceKeyTransRecipientInfoGenerator(recipient);
        } catch (CertificateEncodingException e)
        {
            throw new MessageEncodingException(e);
        }
        edGenerator.addRecipientInfoGenerator(recipientGenerator);
        try
        {

            OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(encAlgId).build();

            CMSEnvelopedData pkcsPkiEnvelope = edGenerator.generate(envelopable, encryptor);
            return pkcsPkiEnvelope;
        } catch (CMSException e)
        {
            throw new MessageEncodingException(e);
        }
    }

    private static void addAttribute(
            final ASN1EncodableVector v,
            final ASN1ObjectIdentifier attrType,
            final ASN1Encodable attrValue)
    {
        v.add(new Attribute(attrType, new DERSet(attrValue)));
    }
}
