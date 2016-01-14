/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
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

package org.xipki.security.p11.remote;

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
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
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
import org.xipki.common.util.ParamUtil;
import org.xipki.security.api.BadASN1ObjectException;
import org.xipki.security.api.ObjectIdentifiers;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.XipkiCmpConstants;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11KeyIdentifier;
import org.xipki.security.api.p11.P11ModuleConf;
import org.xipki.security.api.p11.P11SlotIdentifier;
import org.xipki.security.api.p11.remote.KeyIdentifier;
import org.xipki.security.api.p11.remote.PSOTemplate;
import org.xipki.security.api.p11.remote.SlotAndKeyIdentifer;
import org.xipki.security.api.p11.remote.SlotIdentifier;
import org.xipki.security.api.util.SecurityUtil;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

public abstract class RemoteP11CryptService implements P11CryptService {

    private static final Logger LOG = LoggerFactory.getLogger(RemoteP11CryptService.class);

    private final  Random random = new Random();

    private final GeneralName sender = XipkiCmpConstants.remotep11_cmp_client;

    private final GeneralName recipient = XipkiCmpConstants.remoteP11_cmp_server;

    private final P11ModuleConf moduleConf;

    public RemoteP11CryptService(
            final P11ModuleConf moduleConf) {
        ParamUtil.assertNotNull("moduleConf", moduleConf);
        this.moduleConf = moduleConf;
    }

    protected abstract byte[] send(
            byte[] request)
    throws IOException;

    public int getServerVersion()
    throws SignerException {
        ASN1Encodable result = send(XipkiCmpConstants.ACTION_RP11_VERSION, DERNull.INSTANCE);

        ASN1Integer derInt;
        try {
            derInt = ASN1Integer.getInstance(result);
        } catch (IllegalArgumentException e) {
            throw new SignerException("the returned result is not INTEGER");
        }

        return (derInt == null)
                ? 0
                : derInt.getPositiveValue().intValue();
    }

    @Override
    public byte[] CKM_RSA_PKCS(
            final byte[] encodedDigestInfo,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        checkSlotId(slotId);
        return pso(XipkiCmpConstants.ACTION_RP11_PSO_RSA_PKCS, encodedDigestInfo, slotId, keyId);
    }

    @Override
    public byte[] CKM_RSA_X509(
            final byte[] hash,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        checkSlotId(slotId);
        return pso(XipkiCmpConstants.ACTION_RP11_PSO_RSA_X509, hash, slotId, keyId);
    }

    @Override
    public byte[] CKM_ECDSA_Plain(
            final byte[] hash,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        checkSlotId(slotId);
        return pso(XipkiCmpConstants.ACTION_RP11_PSO_ECDSA_PLAIN, hash, slotId, keyId);
    }

    @Override
    public byte[] CKM_ECDSA_X962(
            final byte[] hash,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        checkSlotId(slotId);
        return pso(XipkiCmpConstants.ACTION_RP11_PSO_ECDSA_X962, hash, slotId, keyId);
    }

    @Override
    public byte[] CKM_DSA_Plain(
            final byte[] hash,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        checkSlotId(slotId);
        return pso(XipkiCmpConstants.ACTION_RP11_PSO_DSA_PLAIN, hash, slotId, keyId);
    }

    @Override
    public byte[] CKM_DSA_X962(
            final byte[] hash,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        checkSlotId(slotId);
        return pso(XipkiCmpConstants.ACTION_RP11_PSO_DSA_X962, hash, slotId, keyId);
    }

    @Override
    public PublicKey getPublicKey(
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        checkSlotId(slotId);
        byte[] keyBytes = getCertOrKey(XipkiCmpConstants.ACTION_RP11_GET_PUBLICKEY, slotId, keyId);
        if (keyBytes == null) {
            throw new SignerException("received no public key from server for " + keyId);
        }

        return generatePublicKey(keyBytes);
    }

    @Override
    public X509Certificate getCertificate(
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        checkSlotId(slotId);
        byte[] certBytes = getCertOrKey(XipkiCmpConstants.ACTION_RP11_GET_CERTIFICATE, slotId,
                keyId);
        if (certBytes == null) {
            throw new SignerException("received no certificate from server for " + keyId);
        }

        try {
            return X509Util.parseCert(certBytes);
        } catch (CertificateException | IOException e) {
            throw new SignerException(e.getClass().getName() + ": " + e.getMessage(), e);
        }
    }

    @Override
    public X509Certificate[] getCertificates(
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        checkSlotId(slotId);
        X509Certificate cert = getCertificate(slotId, keyId);
        if (cert == null) {
            return null;
        }

        return new X509Certificate[]{cert};
    }

    private byte[] pso(
            final int action,
            final byte[] message,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        PSOTemplate psoTemplate;
        try {
            SlotAndKeyIdentifer slotAndKeyIdentifier = buildSlotAndKeyIdentifier(slotId, keyId);
            psoTemplate = new PSOTemplate(slotAndKeyIdentifier, message);
        } catch (BadASN1ObjectException e) {
            throw new SignerException("BadASN1ObjectException: " + e.getMessage(), e);
        }

        ASN1Encodable result = send(action, psoTemplate);

        ASN1OctetString octetString;
        try {
            octetString = DEROctetString.getInstance(result);
        } catch (IllegalArgumentException e) {
            throw new SignerException("the returned result is not OCTETSTRING");
        }

        return (octetString == null)
                ? null
                : octetString.getOctets();
    } // method pso

    private byte[] getCertOrKey(
            final int action,
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws SignerException {
        SlotAndKeyIdentifer slotAndKeyIdentifier;
        try {
            slotAndKeyIdentifier = buildSlotAndKeyIdentifier(slotId, keyId);
        } catch (BadASN1ObjectException e) {
            throw new SignerException("BadASN1ObjectException: " + e.getMessage(), e);
        }

        ASN1Encodable result = send(action, slotAndKeyIdentifier);

        ASN1OctetString octetString;
        try {
            octetString = DEROctetString.getInstance(result);
        } catch (IllegalArgumentException e) {
            throw new SignerException("the returned result is not OCTETSTRING");
        }

        return (octetString == null)
                ? null
                : octetString.getOctets();
    }

    private SlotAndKeyIdentifer buildSlotAndKeyIdentifier(
            final P11SlotIdentifier slotId,
            final P11KeyIdentifier keyId)
    throws BadASN1ObjectException {
        SlotIdentifier slotIdentifier = new SlotIdentifier(slotId);
        KeyIdentifier keyIdentifier = new KeyIdentifier(keyId);
        return new SlotAndKeyIdentifer(slotIdentifier, keyIdentifier);
    }

    private ASN1Encodable send(
            final int action,
            final ASN1Encodable content)
    throws SignerException {
        PKIHeader header = buildPKIHeader(null);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(action));
        if (content != null) {
            v.add(content);
        }
        InfoTypeAndValue itvReq = new InfoTypeAndValue(ObjectIdentifiers.id_xipki_cm_cmpGenmsg,
                new DERSequence(v));

        GenMsgContent genMsgContent = new GenMsgContent(itvReq);
        PKIBody body = new PKIBody(PKIBody.TYPE_GEN_MSG, genMsgContent);
        PKIMessage request = new PKIMessage(header, body);

        byte[] encodedRequest;
        try {
            encodedRequest = request.getEncoded();
        } catch (IOException e) {
            LOG.error("error while encode the PKI request {}", request);
            throw new SignerException(e.getMessage(), e);
        }

        byte[] encodedResponse;
        try {
            encodedResponse = send(encodedRequest);
        } catch (IOException e) {
            LOG.error("error while send the PKI request {} to server", request);
            throw new SignerException(e.getMessage(), e);
        }

        GeneralPKIMessage response;
        try {
            response = new GeneralPKIMessage(encodedResponse);
        } catch (IOException e) {
            LOG.error("error while decode the received PKI message: {}",
                    Hex.toHexString(encodedResponse));
            throw new SignerException(e.getMessage(), e);
        }

        PKIHeader respHeader = response.getHeader();
        ASN1OctetString tid = respHeader.getTransactionID();
        GeneralName recipient = respHeader.getRecipient();
        if (!sender.equals(recipient)) {
            LOG.warn("tid={}: unknown CMP requestor '{}'", tid, recipient);
        }

        return extractItvInfoValue(action, response);
    } // method send

    private static ASN1Encodable extractItvInfoValue(
            final int action,
            final GeneralPKIMessage response)
    throws SignerException {
        PKIBody respBody = response.getBody();
        int bodyType = respBody.getType();

        if (PKIBody.TYPE_ERROR == bodyType) {
            ErrorMsgContent content = (ErrorMsgContent) respBody.getContent();
            PKIStatusInfo statusInfo = content.getPKIStatusInfo();
            throw new SignerException("server answered with ERROR: "
                    + SecurityUtil.formatPKIStatusInfo(statusInfo));
        } else if (PKIBody.TYPE_GEN_REP != bodyType) {
            throw new SignerException("unknown PKI body type " + bodyType
                    + " instead the exceptected [" + PKIBody.TYPE_GEN_REP  + ", "
                    + PKIBody.TYPE_ERROR + "]");
        }

        GenRepContent genRep = (GenRepContent) respBody.getContent();

        InfoTypeAndValue[] itvs = genRep.toInfoTypeAndValueArray();
        InfoTypeAndValue itv = null;
        if (itvs != null && itvs.length > 0) {
            for (InfoTypeAndValue m : itvs) {
                if (ObjectIdentifiers.id_xipki_cm_cmpGenmsg.equals(m.getInfoType())) {
                    itv = m;
                    break;
                }
            }
        }
        if (itv == null) {
            throw new SignerException("the response does not contain InfoTypeAndValue '"
                    + ObjectIdentifiers.id_xipki_cm_cmpGenmsg.getId() + "'");
        }

        ASN1Encodable itvValue = itv.getInfoValue();
        if (itvValue == null) {
            throw new SignerException("value of InfoTypeAndValue '"
                    + ObjectIdentifiers.id_xipki_cm_cmpGenmsg.getId() + "'  is incorrect");
        }
        try {
            ASN1Sequence seq = ASN1Sequence.getInstance(itvValue);
            int receivedAction = ASN1Integer.getInstance(seq.getObjectAt(0))
                    .getPositiveValue().intValue();
            if (receivedAction != action) {
                throw new SignerException("xipki action '"
                        + receivedAction + "'  is not the expected '" + action + "'");
            }
            return seq.size() > 1
                    ? seq.getObjectAt(1)
                    : null;
        } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
            throw new SignerException("value of response (type nfoTypeAndValue) '"
                    + ObjectIdentifiers.id_xipki_cm_cmpGenmsg.getId() + "'  is incorrect");
        }
    } // method extractItvInfoValue

    private PKIHeader buildPKIHeader(
            ASN1OctetString tid) {
        PKIHeaderBuilder hBuilder = new PKIHeaderBuilder(
                PKIHeader.CMP_2000,
                sender,
                recipient);
        hBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));

        if (tid == null) {
            tid = new DEROctetString(randomTransactionId());
        }
        hBuilder.setTransactionID(tid);

        return hBuilder.build();
    }

    private byte[] randomTransactionId() {
        byte[] tid = new byte[20];
        synchronized (random) {
            random.nextBytes(tid);
        }
        return tid;
    }

    @Override
    public P11SlotIdentifier[] getSlotIdentifiers()
    throws SignerException {
        ASN1Encodable resp = send(XipkiCmpConstants.ACTION_RP11_LIST_SLOTS, null);
        if (!(resp instanceof ASN1Sequence)) {
            throw new SignerException("response is not ASN1Sequence, but "
                    + resp.getClass().getName());
        }

        ASN1Sequence seq = (ASN1Sequence) resp;
        int n = seq.size();

        List<P11SlotIdentifier> slotIds = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            SlotIdentifier asn1SlotId;
            try {
                ASN1Encodable obj = seq.getObjectAt(i);
                asn1SlotId = SlotIdentifier.getInstance(obj);
            } catch (Exception e) {
                throw new SignerException(e.getMessage(), e);
            }

            P11SlotIdentifier slotId = asn1SlotId.getSlotId();
            if (moduleConf.isSlotIncluded(slotId)) {
                slotIds.add(slotId);
            }
        }
        return slotIds.toArray(new P11SlotIdentifier[0]);
    }

    @Override
    public String[] getKeyLabels(
            final P11SlotIdentifier slotId)
    throws SignerException {
        checkSlotId(slotId);
        SlotIdentifier _slotId = new SlotIdentifier(slotId);

        ASN1Encodable resp = send(XipkiCmpConstants.ACTION_RP11_LIST_KEYLABELS,
                _slotId);
        if (!(resp instanceof ASN1Sequence)) {
            throw new SignerException("response is not ASN1Sequence, but "
                    + resp.getClass().getName());
        }

        ASN1Sequence seq = (ASN1Sequence) resp;
        int n = seq.size();

        String[] keyLabels = new String[n];
        for (int i = 0; i < n; i++) {
            ASN1Encodable obj = seq.getObjectAt(i);
            if (!(obj instanceof ASN1String)) {
                throw new SignerException("object at index " + i + " is not ASN1String, but "
                        + resp.getClass().getName());
            }
            keyLabels[i] = ((ASN1String) obj).getString();
        }

        return keyLabels;
    }

    private void checkSlotId(
            final P11SlotIdentifier slotId)
    throws SignerException {
        if (!moduleConf.isSlotIncluded(slotId)) {
            throw new SignerException("cound not find slot (" + slotId.toString() + ")");
        }
    }

    public P11ModuleConf getModuleConf() {
        return moduleConf;
    }

    private static PublicKey generatePublicKey(
            final byte[] encodedSubjectPublicKeyInfo)
    throws SignerException {
        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(
                encodedSubjectPublicKeyInfo);

        X509EncodedKeySpec keyspec = new X509EncodedKeySpec(encodedSubjectPublicKeyInfo);
        ASN1ObjectIdentifier aid = pkInfo.getAlgorithm().getAlgorithm();

        KeyFactory kf;

        try {
            if (PKCSObjectIdentifiers.rsaEncryption.equals(aid)) {
                kf = KeyFactory.getInstance("RSA");
            } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(aid)) {
                kf = KeyFactory.getInstance("ECDSA");
            } else if (X9ObjectIdentifiers.id_dsa.equals(aid)) {
                kf = KeyFactory.getInstance("DSA");
            } else {
                throw new SignerException("unsupported key algorithm: " + aid);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new SignerException("NoSuchAlgorithmException: " + e.getMessage(), e);
        }

        try {
            return kf.generatePublic(keyspec);
        } catch (InvalidKeySpecException e) {
            throw new SignerException("InvalidKeySpecException: " + e.getMessage(), e);
        }
    }

}
