/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License
 * (version 3 or later at your option)
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.security.p11;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
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
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11ModuleConf;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.api.p11.remote.KeyIdentifier;
import org.xipki.security.api.p11.remote.PSOTemplate;
import org.xipki.security.api.p11.remote.RemoteP11Constants;
import org.xipki.security.api.p11.remote.SlotAndKeyIdentifer;
import org.xipki.security.api.p11.remote.SlotIdentifier;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public abstract class RemoteP11CryptService implements P11CryptService
{
    private static final Logger LOG = LoggerFactory.getLogger(RemoteP11CryptService.class);
    private final  Random random = new Random();

    private final GeneralName sender = RemoteP11Constants.CMP_CLIENT;
    private final GeneralName recipient = RemoteP11Constants.CMP_SERVER;

    private final P11ModuleConf moduleConf;

    public RemoteP11CryptService(P11ModuleConf moduleConf)
    {
        ParamChecker.assertNotNull("moduleConf", moduleConf);
        this.moduleConf = moduleConf;
    }

    protected abstract byte[] send(byte[] request)
    throws IOException;

    public int getServerVersion()
    throws SignerException
    {
        InfoTypeAndValue itv = new InfoTypeAndValue(RemoteP11Constants.id_version, DERNull.INSTANCE);
        ASN1Encodable result = send(itv);

        ASN1Integer derInt;
        try
        {
            derInt = ASN1Integer.getInstance(result);
        }catch(IllegalArgumentException e)
        {
            throw new SignerException("The returned result is not INTEGER");
        }

        return (derInt == null) ? 0 : derInt.getPositiveValue().intValue();
    }

    @Override
    public byte[] CKM_RSA_PKCS(byte[] encodedDigestInfo, P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException
    {
        checkSlotId(slotId);
        return pso(RemoteP11Constants.id_pso_rsa_pkcs, encodedDigestInfo, slotId, keyId);
    }

    @Override
    public byte[] CKM_RSA_X509(byte[] hash, P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException
    {
        checkSlotId(slotId);
        return pso(RemoteP11Constants.id_pso_rsa_x509, hash, slotId, keyId);
    }

    @Override
    public byte[] CKM_ECDSA(byte[] hash, P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException
    {
        checkSlotId(slotId);
        return pso(RemoteP11Constants.id_pso_ecdsa, hash, slotId, keyId);
    }

    @Override
    public byte[] CKM_DSA(byte[] hash, P11SlotIdentifier slotId,
            P11KeyIdentifier keyId)
    throws SignerException
    {
        checkSlotId(slotId);
        return pso(RemoteP11Constants.id_pso_dsa, hash, slotId, keyId);    }

    @Override
    public PublicKey getPublicKey(P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException
    {
        checkSlotId(slotId);
        byte[] keyBytes = getCertOrKey(RemoteP11Constants.id_get_publickey, slotId, keyId);
        if(keyBytes == null)
        {
            throw new SignerException("Received no public key from server for " + keyId);
        }

        return generatePublicKey(keyBytes);
    }

    @Override
    public X509Certificate getCertificate(P11SlotIdentifier slotId, P11KeyIdentifier keyId)
    throws SignerException
    {
        checkSlotId(slotId);
        byte[] certBytes = getCertOrKey(RemoteP11Constants.id_get_certificate, slotId, keyId);
        if(certBytes == null)
        {
            throw new SignerException("Received no certificate from server for " + keyId);
        }

        try
        {
            return IoCertUtil.parseCert(certBytes);
        } catch (CertificateException | IOException e)
        {
            throw new SignerException(e.getClass().getName() + ": " + e.getMessage(), e);
        }
    }

    @Override
    public X509Certificate[] getCertificates(P11SlotIdentifier slotId,
            P11KeyIdentifier keyId)
    throws SignerException
    {
        checkSlotId(slotId);
        X509Certificate cert = getCertificate(slotId, keyId);
        if(cert == null)
        {
            return null;
        }

        return new X509Certificate[]{cert};
    }

    private byte[] pso(ASN1ObjectIdentifier type, byte[] message,
            P11SlotIdentifier slotId, P11KeyIdentifier keyId)
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
            P11SlotIdentifier slotId, P11KeyIdentifier keyId)
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

    private SlotAndKeyIdentifer buildSlotAndKeyIdentifier(P11SlotIdentifier slotId,
            P11KeyIdentifier keyId)
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
    public P11SlotIdentifier[] getSlotIdentifiers()
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

        List<P11SlotIdentifier> slotIds = new ArrayList<>(n);
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

            P11SlotIdentifier slotId = asn1SlotId.getSlotId();
            if(moduleConf.isSlotIncluded(slotId))
            {
                slotIds.add(slotId);
            }
        }
        return slotIds.toArray(new P11SlotIdentifier[0]);
    }

    @Override
    public String[] getKeyLabels(P11SlotIdentifier slotId)
    throws SignerException
    {
        checkSlotId(slotId);
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

    private void checkSlotId(P11SlotIdentifier slotId)
    throws SignerException
    {
        if(moduleConf.isSlotIncluded(slotId) == false)
        {
            throw new SignerException("cound not find slot ("+ slotId.toString() + ")");
        }
    }

    public P11ModuleConf getModuleConf()
    {
        return moduleConf;
    }

}
