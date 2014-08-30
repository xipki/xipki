/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.remotep11.server;

import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.remote.KeyIdentifier;
import org.xipki.security.api.p11.remote.PSOTemplate;
import org.xipki.security.api.p11.remote.RemoteP11Constants;
import org.xipki.security.api.p11.remote.SlotAndKeyIdentifer;
import org.xipki.security.api.p11.remote.SlotIdentifier;

/**
 * @author Lijun Liao
 */

class CmpResponder
{
    private static final Logger LOG = LoggerFactory.getLogger(CmpResponder.class);

    private static final ASN1ObjectIdentifier[] knownTypes = new ASN1ObjectIdentifier[]
    {
            RemoteP11Constants.id_version,
            RemoteP11Constants.id_pso_ecdsa,
            RemoteP11Constants.id_pso_rsa_x509,
            RemoteP11Constants.id_pso_rsa_pkcs,
            RemoteP11Constants.id_get_certificate,
            RemoteP11Constants.id_get_publickey,
            RemoteP11Constants.id_list_slots,
            RemoteP11Constants.id_list_keylabels};

    private static final String UNKOWNTYPE_MSG = "PKIBody type %s is only supported with the sub-knownTypes " +
            RemoteP11Constants.id_version.getId() + ", " +
            RemoteP11Constants.id_pso_ecdsa.getId() + ", " +
            RemoteP11Constants.id_pso_rsa_x509.getId() + ", " +
            RemoteP11Constants.id_pso_rsa_pkcs.getId() + ", " +
            RemoteP11Constants.id_get_certificate.getId() + ", " +
            RemoteP11Constants.id_get_publickey.getId() + ", " +
            RemoteP11Constants.id_list_slots.getId() + " and" +
            RemoteP11Constants.id_list_keylabels.getId();

    private final SecureRandom random = new SecureRandom();
    private final GeneralName sender = RemoteP11Constants.CMP_SERVER;

    CmpResponder()
    {
    }

    PKIMessage processPKIMessage(LocalP11CryptService localP11CryptService, PKIMessage pkiMessage)
    {
        GeneralPKIMessage message = new GeneralPKIMessage(pkiMessage);

        PKIHeader reqHeader = message.getHeader();
        ASN1OctetString tid = reqHeader.getTransactionID();

        if(tid == null)
        {
            byte[] randomBytes = randomTransactionId();
            tid = new DEROctetString(randomBytes);
        }
        String tidStr = Hex.toHexString(tid.getOctets());

        PKIHeaderBuilder respHeader = new PKIHeaderBuilder(
                reqHeader.getPvno().getValue().intValue(),
                sender,
                reqHeader.getSender());
        respHeader.setTransactionID(tid);

        PKIBody reqBody = message.getBody();
        final int type = reqBody.getType();

        if(type != PKIBody.TYPE_GEN_MSG)
        {
            ErrorMsgContent emc = new ErrorMsgContent(
                    new PKIStatusInfo(PKIStatus.rejection,
                            new PKIFreeText("unsupported type " + type),
                            new PKIFailureInfo(PKIFailureInfo.badRequest)));

            PKIBody respBody = new PKIBody(PKIBody.TYPE_ERROR, emc);

            return new PKIMessage(respHeader.build(), respBody);
        }

        GenMsgContent genMsgBody = (GenMsgContent) reqBody.getContent();
        InfoTypeAndValue[] itvs = genMsgBody.toInfoTypeAndValueArray();

        InfoTypeAndValue itvP11 = null;
        if(itvs != null && itvs.length > 0)
        {
            for(InfoTypeAndValue itv : itvs)
            {
                ASN1ObjectIdentifier itvType = itv.getInfoType();
                for(ASN1ObjectIdentifier knownType : knownTypes)
                {
                    if(knownType.equals(itvType))
                    {
                        itvP11 = itv;
                        break;
                    }
                }

                if(itvP11 != null)
                {
                    break;
                }
            }
        }

        PKIStatus status = PKIStatus.rejection;
        String statusMessage = null;
        int failureInfo = PKIFailureInfo.badRequest;

        PKIBody respBody = null;

        if(itvP11 == null)
        {
            statusMessage = String.format(UNKOWNTYPE_MSG, type);
            failureInfo = PKIFailureInfo.badRequest;
        }
        else
        {
            P11CryptService p11CryptService = localP11CryptService.getP11CryptService();

            ASN1ObjectIdentifier itvType = itvP11.getInfoType();

            ASN1Encodable respItvInfoValue = null;
            try
            {
                if(RemoteP11Constants.id_version.equals(itvType))
                {
                    respItvInfoValue = new ASN1Integer(localP11CryptService.getVersion());
                }
                else if(RemoteP11Constants.id_pso_ecdsa.equals(itvType) ||
                        RemoteP11Constants.id_pso_rsa_x509.equals(itvType) ||
                        RemoteP11Constants.id_pso_rsa_pkcs.equals(itvType))
                {
                    PSOTemplate psoTemplate = PSOTemplate.getInstance(itvP11.getInfoValue());
                    byte[] psoMessage = psoTemplate.getMessage();
                    SlotAndKeyIdentifer slotAndKeyIdentifier = psoTemplate.getSlotAndKeyIdentifer();
                    P11SlotIdentifier slot = slotAndKeyIdentifier.getSlotIdentifier().getSlotId();
                    KeyIdentifier keyIdentifier = slotAndKeyIdentifier.getKeyIdentifier();

                    P11KeyIdentifier keyId = keyIdentifier.getKeyId();

                    byte[] signature;

                    if(RemoteP11Constants.id_pso_ecdsa.equals(itvType))
                    {
                        signature = p11CryptService.CKM_ECDSA(psoMessage, slot, keyId);
                    }
                    else if(RemoteP11Constants.id_pso_rsa_x509.equals(itvType))
                    {
                        signature = p11CryptService.CKM_RSA_X509(psoMessage, slot, keyId);
                    }
                    else
                    {
                        signature = p11CryptService.CKM_RSA_PKCS(psoMessage, slot, keyId);
                    }

                    respItvInfoValue = new DEROctetString(signature);
                }
                else if(RemoteP11Constants.id_get_certificate.equals(itvType) ||
                        RemoteP11Constants.id_get_publickey.equals(itvType))
                {
                    SlotAndKeyIdentifer slotAndKeyIdentifier = SlotAndKeyIdentifer.getInstance(itvP11.getInfoValue());
                    P11SlotIdentifier slot = slotAndKeyIdentifier.getSlotIdentifier().getSlotId();
                    KeyIdentifier keyIdentifier = slotAndKeyIdentifier.getKeyIdentifier();

                    P11KeyIdentifier keyId = keyIdentifier.getKeyId();

                    byte[] encodeCertOrKey;
                    if(RemoteP11Constants.id_get_certificate.equals(itvType))
                    {
                        encodeCertOrKey = p11CryptService.getCertificate(slot, keyId).getEncoded();
                    }
                    else
                    {
                        encodeCertOrKey = p11CryptService.getPublicKey(slot, keyId).getEncoded();
                    }

                    respItvInfoValue = new DEROctetString(encodeCertOrKey);
                }
                else if(RemoteP11Constants.id_list_slots.equals(itvType))
                {
                    P11SlotIdentifier[] slotIds = p11CryptService.getSlotIdentifiers();

                    ASN1EncodableVector vector = new ASN1EncodableVector();
                    for(P11SlotIdentifier slotId : slotIds)
                    {
                        vector.add(new SlotIdentifier(slotId));
                    }
                    respItvInfoValue = new DERSequence(vector);
                }
                else if(RemoteP11Constants.id_list_keylabels.equals(itvType))
                {
                    SlotIdentifier slotId = SlotIdentifier.getInstance(itvP11.getInfoValue());
                    String[] keyLabels = p11CryptService.getKeyLabels(slotId.getSlotId());

                    ASN1EncodableVector vector = new ASN1EncodableVector();
                    for(String keyLabel : keyLabels)
                    {
                        vector.add(new DERUTF8String(keyLabel));
                    }
                    respItvInfoValue = new DERSequence(vector);
                }

                if(respItvInfoValue != null)
                {
                    status = PKIStatus.granted;
                    InfoTypeAndValue itv = new InfoTypeAndValue(itvType, respItvInfoValue);
                    GenRepContent genRepContent = new GenRepContent(itv);
                    respBody = new PKIBody(PKIBody.TYPE_GEN_REP, genRepContent);
                }
            } catch (Throwable t)
            {
                LOG.error("Error while processing CMP message {}, message: {}", tidStr, t.getMessage());
                LOG.debug("Error while processing CMP message " + tidStr, t);
                failureInfo = PKIFailureInfo.systemFailure;
                statusMessage = t.getMessage();
            }
        }

        if(respBody == null)
        {
            ErrorMsgContent emc = new ErrorMsgContent(
                new PKIStatusInfo(status,
                        (statusMessage == null) ? null : new PKIFreeText(statusMessage),
                        new PKIFailureInfo(failureInfo)));
            respBody = new PKIBody(PKIBody.TYPE_ERROR, emc);
        }

        return new PKIMessage(respHeader.build(), respBody);
    }

    private byte[] randomTransactionId()
    {
        byte[] b = new byte[10];
        synchronized (random)
        {
            random.nextBytes(b);
        }
        return  b;
    }
}
