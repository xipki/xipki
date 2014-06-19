/*
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.remotep11.client;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.remotep11.common.RemoteP11Constants;
import org.xipki.remotep11.common.asn1.KeyIdentifier;
import org.xipki.remotep11.common.asn1.PSOTemplate;
import org.xipki.remotep11.common.asn1.SlotAndKeyIdentifer;
import org.xipki.remotep11.common.asn1.SlotIdentifier;
import org.xipki.security.api.P11CryptService;
import org.xipki.security.api.PKCS11SlotIdentifier;
import org.xipki.security.api.Pkcs11KeyIdentifier;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

public abstract class RemoteP11CryptService implements P11CryptService
{
    private static final Logger LOG = LoggerFactory.getLogger(RemoteP11CryptService.class);
    private final  Random random = new Random();

    private final GeneralName sender = RemoteP11Constants.CMP_CLIENT;
    private final GeneralName recipient = RemoteP11Constants.CMP_SERVER;

    public RemoteP11CryptService()
    {
    }

    protected abstract byte[] send(byte[] request)
    throws IOException;

    public int getServerVersion()
    throws SignerException
    {
        InfoTypeAndValue itv = new InfoTypeAndValue(RemoteP11Constants.id_version, DERNull.INSTANCE);
        ASN1Encodable result = send(itv);

        DERInteger derInt;
        try
        {
            derInt = DERInteger.getInstance(result);
        }catch(IllegalArgumentException e)
        {
            throw new SignerException("The returned result is not INTEGER");
        }

        return (derInt == null) ? 0 : derInt.getPositiveValue().intValue();
    }

    @Override
    public byte[] CKM_RSA_PKCS(byte[] encodedDigestInfo, PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        return pso(RemoteP11Constants.id_pso_rsa_pkcs, encodedDigestInfo, slotId, keyId);
    }

    @Override
    public byte[] CKM_RSA_X509(byte[] hash, PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        return pso(RemoteP11Constants.id_pso_rsa_x509, hash, slotId, keyId);
    }

    @Override
    public byte[] CKM_ECDSA(byte[] hash, PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        return pso(RemoteP11Constants.id_pso_ecdsa, hash, slotId, keyId);
    }

    @Override
    public PublicKey getPublicKey(PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        byte[] keyBytes = getCertOrKey(RemoteP11Constants.id_get_publickey, slotId, keyId);
        if(keyBytes == null)
        {
            throw new SignerException("Received no public key from server for " + keyId);
        }

        return generatePublicKey(keyBytes);
    }

    @Override
    public X509Certificate getCertificate(PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        byte[] certBytes = getCertOrKey(RemoteP11Constants.id_get_certificate, slotId, keyId);
        if(certBytes == null)
        {
            throw new SignerException("Received no certificate from server for " + keyId);
        }

        try
        {
            return IoCertUtil.parseCert(certBytes);
        } catch (CertificateException e)
        {
            throw new SignerException("CertificateException: " + e.getMessage(), e);
        } catch (IOException e)
        {
            throw new SignerException("IOException: " + e.getMessage(), e);
        }
    }

    @Override
    public X509Certificate[] getCertificates(PKCS11SlotIdentifier slotId,
            Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        X509Certificate cert = getCertificate(slotId, keyId);
        if(cert == null)
        {
            return null;
        }

        return new X509Certificate[]{cert};
    }

    private byte[] pso(ASN1ObjectIdentifier type, byte[] message,
            PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        SlotAndKeyIdentifer slotAndKeyIdentifier = buildSlotAndKeyIdentifier(slotId, keyId);
        PSOTemplate psoTemplate = new PSOTemplate(slotAndKeyIdentifier, message);

        InfoTypeAndValue itv = new InfoTypeAndValue(type, psoTemplate);
        ASN1Encodable result = send(itv);

        ASN1OctetString octetString;
        try
        {
            octetString = DEROctetString.getInstance(result);
        }catch(IllegalArgumentException e)
        {
            throw new SignerException("The returned result is not OCTETSTRING");
        }

        return (octetString == null) ? null : octetString.getOctets();
    }

    private byte[] getCertOrKey(ASN1ObjectIdentifier type,
            PKCS11SlotIdentifier slotId, Pkcs11KeyIdentifier keyId)
    throws SignerException
    {
        SlotAndKeyIdentifer slotAndKeyIdentifier = buildSlotAndKeyIdentifier(slotId, keyId);

        InfoTypeAndValue itv = new InfoTypeAndValue(type, slotAndKeyIdentifier);
        ASN1Encodable result = send(itv);

        ASN1OctetString octetString;
        try
        {
            octetString = DEROctetString.getInstance(result);
        }catch(IllegalArgumentException e)
        {
            throw new SignerException("The returned result is not OCTETSTRING");
        }

        return (octetString == null) ? null : octetString.getOctets();
    }

    private SlotAndKeyIdentifer buildSlotAndKeyIdentifier(PKCS11SlotIdentifier slotId,
            Pkcs11KeyIdentifier keyId)
    {
        SlotIdentifier slotIdentifier = new SlotIdentifier(slotId);
        KeyIdentifier keyIdentifier = new KeyIdentifier(keyId);
        return new SlotAndKeyIdentifer(slotIdentifier, keyIdentifier);
    }

    private ASN1Encodable send(InfoTypeAndValue itv)
    throws SignerException
    {
        PKIHeader header = buildPKIHeader(null);
        GenMsgContent genMsgContent = new GenMsgContent(itv);
        PKIBody body = new PKIBody(PKIBody.TYPE_GEN_MSG, genMsgContent);
        PKIMessage request = new PKIMessage(header, body);

        byte[] encodedRequest;
        try
        {
            encodedRequest = request.getEncoded();
        } catch (IOException e)
        {
            LOG.error("Error while encode the PKI request {}", request);
            throw new SignerException(e.getMessage(), e);
        }

        byte[] encodedResponse;
        try
        {
            encodedResponse = send(encodedRequest);
        } catch (IOException e)
        {
            LOG.error("Error while send the PKI request {} to server", request);
            throw new SignerException(e.getMessage(), e);
        }

        GeneralPKIMessage response;
        try
        {
            response = new GeneralPKIMessage(encodedResponse);
        } catch (IOException e)
        {
            LOG.error("Error while decode the received PKI message: {}", Hex.toHexString(encodedResponse));
            throw new SignerException(e.getMessage(), e);
        }

        PKIHeader respHeader = response.getHeader();
        ASN1OctetString tid = respHeader.getTransactionID();
        GeneralName recipient = respHeader.getRecipient();
        if(sender.equals(recipient) == false)
        {
            LOG.warn("tid={}: Unknown CMP requestor '{}'", tid, recipient);
        }

        return extractItvInfoValue(response, itv.getInfoType());
    }

    private static ASN1Encodable extractItvInfoValue(GeneralPKIMessage response, ASN1ObjectIdentifier exepectedType)
    throws SignerException
    {
        PKIBody respBody = response.getBody();
        int bodyType = respBody.getType();

        if(PKIBody.TYPE_ERROR == bodyType)
        {
            ErrorMsgContent content = (ErrorMsgContent) respBody.getContent();
            PKIStatusInfo statusInfo = content.getPKIStatusInfo();
            throw new SignerException("Server answers with ERROR: " + IoCertUtil.formatPKIStatusInfo(statusInfo));
        }

        else if(PKIBody.TYPE_GEN_REP != bodyType)
        {
            throw new SignerException("Unknown PKI body type " + bodyType +
                    " instead the exceptected [" + PKIBody.TYPE_GEN_REP  + ", " +
                    PKIBody.TYPE_ERROR + "]");
        }

        GenRepContent genRep = (GenRepContent) respBody.getContent();

        InfoTypeAndValue[] itvs = genRep.toInfoTypeAndValueArray();
        InfoTypeAndValue expectedItv = null;
        if(itvs != null && itvs.length > 0)
        {
            for(InfoTypeAndValue itv : itvs)
            {
                if(exepectedType.equals(itv.getInfoType()))
                {
                    expectedItv = itv;
                    break;
                }
            }
        }
        if(expectedItv == null)
        {
            throw new SignerException("The response does not contain InfoTypeAndValue "
                    + exepectedType);
        }

        return expectedItv.getInfoValue();

    }

    private PKIHeader buildPKIHeader(
            ASN1OctetString tid)
    {
        PKIHeaderBuilder hBuilder = new PKIHeaderBuilder(
                PKIHeader.CMP_2000,
                sender,
                recipient);
        hBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));

        if(tid == null)
        {
            tid = new DEROctetString(randomTransactionId());
        }
        hBuilder.setTransactionID(tid);

        return hBuilder.build();
    }

    private byte[] randomTransactionId()
    {
        byte[] tid = new byte[20];
        synchronized (random)
        {
            random.nextBytes(tid);
        }
        return tid;
    }

    private static PublicKey generatePublicKey(byte[] encodedSubjectPublicKeyInfo)
    throws SignerException
    {
        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(encodedSubjectPublicKeyInfo);

        X509EncodedKeySpec keyspec = new X509EncodedKeySpec(encodedSubjectPublicKeyInfo);
        ASN1ObjectIdentifier aid = pkInfo.getAlgorithm().getAlgorithm();

        KeyFactory kf;

        try
        {
            if(PKCSObjectIdentifiers.rsaEncryption.equals(aid))
            {
                kf = KeyFactory.getInstance("RSA");
            }
            else if(X9ObjectIdentifiers.id_ecPublicKey.equals(aid))
            {
                kf = KeyFactory.getInstance("ECDSA");
            }
            else
            {
                throw new SignerException("unsupported key algorithm: " + aid);
            }
        } catch (NoSuchAlgorithmException e)
        {
            throw new SignerException("NoSuchAlgorithmException: " + e.getMessage(), e);
        }

        try
        {
            return kf.generatePublic(keyspec);
        } catch (InvalidKeySpecException e)
        {
            throw new SignerException("InvalidKeySpecException: " + e.getMessage(), e);
        }
    }

    @Override
    public PKCS11SlotIdentifier[] getSlotIdentifiers()
    throws SignerException
    {
        InfoTypeAndValue itv = new InfoTypeAndValue(RemoteP11Constants.id_list_slots, null);
        ASN1Encodable resp = send(itv);
        if(resp instanceof ASN1Sequence == false)
        {
            throw new SignerException("response is not ASN1Sequence, but " + resp.getClass().getName());
        }

        ASN1Sequence seq = (ASN1Sequence) resp;
        int n = seq.size();

        PKCS11SlotIdentifier[] slotIds = new PKCS11SlotIdentifier[n];
        for(int i = 0; i < n; i++)
        {
            SlotIdentifier asn1SlotId;
            try
            {
                ASN1Encodable obj = seq.getObjectAt(i);
                asn1SlotId = SlotIdentifier.getInstance(obj);
            }catch(Exception e)
            {
                throw new SignerException(e);
            }

            slotIds[i] = asn1SlotId.getSlotId();
        }
        return slotIds;
    }

    @Override
    public String[] getKeyLabels(PKCS11SlotIdentifier slotId)
    throws SignerException
    {
        InfoTypeAndValue itv = new InfoTypeAndValue(RemoteP11Constants.id_list_keylabels,
                new SlotIdentifier(slotId));
        ASN1Encodable resp = send(itv);
        if(resp instanceof ASN1Sequence == false)
        {
            throw new SignerException("response is not ASN1Sequence, but " + resp.getClass().getName());
        }

        ASN1Sequence seq = (ASN1Sequence) resp;
        int n = seq.size();

        String[] keyLabels = new String[n];
        for(int i = 0; i < n; i++)
        {
            ASN1Encodable obj = seq.getObjectAt(i);
            if(obj instanceof ASN1String == false)
            {
                throw new SignerException("Object at index " + i + " is not ASN1String, but " + resp.getClass().getName());
            }
            keyLabels[i] = ((ASN1String) obj).getString();
        }

        return keyLabels;
    }

}
