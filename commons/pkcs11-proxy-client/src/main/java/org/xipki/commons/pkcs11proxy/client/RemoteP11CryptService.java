/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.commons.pkcs11proxy.client;

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
import java.util.Set;

import javax.annotation.Nonnull;

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
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.pkcs11proxy.common.ASN1EntityIdentifier;
import org.xipki.commons.pkcs11proxy.common.ASN1P11Params;
import org.xipki.commons.pkcs11proxy.common.ASN1RSAPkcsPssParams;
import org.xipki.commons.pkcs11proxy.common.ASN1SignTemplate;
import org.xipki.commons.pkcs11proxy.common.ASN1SlotIdentifier;
import org.xipki.commons.security.api.ObjectIdentifiers;
import org.xipki.commons.security.api.SignerException;
import org.xipki.commons.security.api.XiCmpConstants;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11ModuleConf;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.p11.P11UnknownEntityException;
import org.xipki.commons.security.api.p11.P11UnsupportedMechanismException;
import org.xipki.commons.security.api.p11.parameters.P11Params;
import org.xipki.commons.security.api.p11.parameters.P11RSAPkcsPssParams;
import org.xipki.commons.security.api.util.CmpFailureUtil;
import org.xipki.commons.security.api.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class RemoteP11CryptService implements P11CryptService {

    private static final Logger LOG = LoggerFactory.getLogger(RemoteP11CryptService.class);

    private final Random random = new Random();

    private final GeneralName sender = XiCmpConstants.REMOTE_P11_CMP_CLIENT;

    private final GeneralName recipient = XiCmpConstants.REMOTE_P11_CMP_SERVER;

    private final P11ModuleConf moduleConf;

    public RemoteP11CryptService(
            final P11ModuleConf moduleConf) {
        this.moduleConf = ParamUtil.requireNonNull("moduleConf", moduleConf);
    }

    protected abstract byte[] send(
            @Nonnull byte[] request)
    throws IOException;

    private ASN1Encodable send(
            final int action,
            final ASN1Encodable content)
    throws P11TokenException {
        PKIHeader header = buildPkiHeader(null);
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new ASN1Integer(action));
        if (content != null) {
            vec.add(content);
        }
        InfoTypeAndValue itvReq = new InfoTypeAndValue(ObjectIdentifiers.id_xipki_cmp_cmpGenmsg,
                new DERSequence(vec));

        GenMsgContent genMsgContent = new GenMsgContent(itvReq);
        PKIBody body = new PKIBody(PKIBody.TYPE_GEN_MSG, genMsgContent);
        PKIMessage request = new PKIMessage(header, body);

        byte[] encodedRequest;
        try {
            encodedRequest = request.getEncoded();
        } catch (IOException ex) {
            final String msg = "could not encode the PKI request";
            LOG.error(msg + " {}", request);
            throw new P11TokenException(msg + ": " + ex.getMessage(), ex);
        }

        byte[] encodedResponse;
        try {
            encodedResponse = send(encodedRequest);
        } catch (IOException ex) {
            final String msg = "could not send the PKI request";
            LOG.error(msg + " {}", request);
            throw new P11TokenException(msg + ": " + ex.getMessage(), ex);
        }

        GeneralPKIMessage response;
        try {
            response = new GeneralPKIMessage(encodedResponse);
        } catch (IOException ex) {
            final String msg = "could not decode the received PKI message";
            LOG.error(msg + ": {}",
                    Hex.toHexString(encodedResponse));
            throw new P11TokenException(msg + ": " + ex.getMessage(), ex);
        }

        PKIHeader respHeader = response.getHeader();
        ASN1OctetString tid = respHeader.getTransactionID();
        GeneralName rec = respHeader.getRecipient();
        if (!sender.equals(rec)) {
            LOG.warn("tid={}: unknown CMP requestor '{}'", tid, rec);
        }

        return extractItvInfoValue(action, response);
    } // method send

    public int getServerVersion()
    throws P11TokenException {
        ASN1Encodable result = send(XiCmpConstants.ACTION_RP11_VERSION, DERNull.INSTANCE);

        ASN1Integer derInt;
        try {
            derInt = ASN1Integer.getInstance(result);
        } catch (IllegalArgumentException ex) {
            throw new P11TokenException("the returned result is not INTEGER");
        }

        return (derInt == null)
                ? 0
                : derInt.getPositiveValue().intValue();
    }

    @Override
    public Set<Long> getSupportedMechanisms(
            P11SlotIdentifier slotId)
    throws P11TokenException {
        // FIXME Auto-generated method stub
        return null;
    }

    @Override
    public boolean supportsMechanism(
            final P11SlotIdentifier slotId,
            final long mechanism) {
        // FIXME: get a list of supported mechanisms at start
        return false;
    }

    @Override
    public byte[] sign(
            final P11EntityIdentifier entityId,
            final long mechanism,
            final P11Params parameters,
            final byte[] content)
    throws P11UnknownEntityException, P11UnsupportedMechanismException, SignerException,
            P11TokenException {
        ParamUtil.requireNonNull("entityId", entityId);
        ParamUtil.requireNonNull("content", content);
        checkSlotId(entityId);

        ASN1EntityIdentifier asn1EntityId = new ASN1EntityIdentifier(entityId);
        ASN1Encodable asn1Param = null;
        if (parameters instanceof P11RSAPkcsPssParams) {
            asn1Param = new ASN1RSAPkcsPssParams((P11RSAPkcsPssParams) parameters);
        }
        ASN1SignTemplate signTemplate = new ASN1SignTemplate(asn1EntityId, mechanism,
                new ASN1P11Params(asn1Param), content);
        ASN1Encodable result = send(XiCmpConstants.ACTION_RP11_SIGN, signTemplate);

        ASN1OctetString octetString;
        try {
            octetString = DEROctetString.getInstance(result);
        } catch (IllegalArgumentException ex) {
            throw new P11TokenException("the returned result is not OCTET STRING");
        }

        return (octetString == null)
                ? null
                : octetString.getOctets();
    }

    @Override
    public PublicKey getPublicKey(
            final P11EntityIdentifier entityId)
    throws P11UnknownEntityException, P11TokenException {
        checkSlotId(entityId);
        byte[] keyBytes = getCertOrKey(XiCmpConstants.ACTION_RP11_GET_PUBLICKEY, entityId);
        if (keyBytes == null) {
            return null;
        }

        return generatePublicKey(keyBytes);
    }

    @Override
    public X509Certificate getCertificate(
            final P11EntityIdentifier entityId)
    throws P11UnknownEntityException, P11TokenException {
        checkSlotId(entityId);
        byte[] certBytes = getCertOrKey(XiCmpConstants.ACTION_RP11_GET_CERTIFICATE, entityId);
        if (certBytes == null) {
            return null;
        }

        try {
            return X509Util.parseCert(certBytes);
        } catch (CertificateException | IOException ex) {
            throw new P11TokenException(ex.getClass().getName() + ": " + ex.getMessage(), ex);
        }
    }

    @Override
    public X509Certificate[] getCertificates(
            final P11EntityIdentifier entityId)
    throws P11UnknownEntityException, P11TokenException {
        checkSlotId(entityId);
        X509Certificate cert = getCertificate(entityId);
        if (cert == null) {
            return null;
        }

        return new X509Certificate[]{cert};
    }

    private byte[] getCertOrKey(
            final int action,
            final P11EntityIdentifier entityId)
    throws P11UnknownEntityException, P11TokenException {
        ASN1EntityIdentifier asn1EntityId = new ASN1EntityIdentifier(entityId);
        ASN1Encodable result = send(action, asn1EntityId);

        ASN1OctetString octetString;
        try {
            octetString = DEROctetString.getInstance(result);
        } catch (IllegalArgumentException ex) {
            throw new P11TokenException("the returned result is not OCTETSTRING");
        }

        return (octetString == null)
                ? null
                : octetString.getOctets();
    }

    private static ASN1Encodable extractItvInfoValue(
            final int action,
            final GeneralPKIMessage response)
    throws P11TokenException {
        PKIBody respBody = response.getBody();
        int bodyType = respBody.getType();

        if (PKIBody.TYPE_ERROR == bodyType) {
            ErrorMsgContent content = (ErrorMsgContent) respBody.getContent();
            PKIStatusInfo statusInfo = content.getPKIStatusInfo();
            throw new P11TokenException("server answered with ERROR: "
                    + CmpFailureUtil.formatPkiStatusInfo(statusInfo));
        } else if (PKIBody.TYPE_GEN_REP != bodyType) {
            throw new P11TokenException("unknown PKI body type " + bodyType
                    + " instead the exceptected [" + PKIBody.TYPE_GEN_REP + ", "
                    + PKIBody.TYPE_ERROR + "]");
        }

        GenRepContent genRep = (GenRepContent) respBody.getContent();

        InfoTypeAndValue[] itvs = genRep.toInfoTypeAndValueArray();
        InfoTypeAndValue itv = null;
        if (itvs != null && itvs.length > 0) {
            for (InfoTypeAndValue m : itvs) {
                if (ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.equals(m.getInfoType())) {
                    itv = m;
                    break;
                }
            }
        }
        if (itv == null) {
            throw new P11TokenException("the response does not contain InfoTypeAndValue '"
                    + ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.getId() + "'");
        }

        ASN1Encodable itvValue = itv.getInfoValue();
        if (itvValue == null) {
            throw new P11TokenException("value of InfoTypeAndValue '"
                    + ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.getId() + "' is incorrect");
        }
        try {
            ASN1Sequence seq = ASN1Sequence.getInstance(itvValue);
            int receivedAction = ASN1Integer.getInstance(seq.getObjectAt(0))
                    .getPositiveValue().intValue();
            if (receivedAction != action) {
                throw new P11TokenException("xipki action '"
                        + receivedAction + "' is not the expected '" + action + "'");
            }
            return seq.size() > 1
                    ? seq.getObjectAt(1)
                    : null;
        } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException ex) {
            throw new P11TokenException("value of response (type nfoTypeAndValue) '"
                    + ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.getId() + "' is incorrect");
        }
    } // method extractItvInfoValue

    private PKIHeader buildPkiHeader(
            final ASN1OctetString tid) {
        PKIHeaderBuilder hdrBuilder = new PKIHeaderBuilder(
                PKIHeader.CMP_2000,
                sender,
                recipient);
        hdrBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));

        ASN1OctetString tmpTid;
        if (tid == null) {
            tmpTid = new DEROctetString(randomTransactionId());
        } else {
            tmpTid = tid;
        }
        hdrBuilder.setTransactionID(tmpTid);

        return hdrBuilder.build();
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
    throws P11TokenException {
        ASN1Encodable resp = send(XiCmpConstants.ACTION_RP11_LIST_SLOTS, null);
        if (!(resp instanceof ASN1Sequence)) {
            throw new P11TokenException("response is not ASN1Sequence, but "
                    + resp.getClass().getName());
        }

        ASN1Sequence seq = (ASN1Sequence) resp;
        final int n = seq.size();

        List<P11SlotIdentifier> slotIds = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            ASN1SlotIdentifier asn1SlotId;
            try {
                ASN1Encodable obj = seq.getObjectAt(i);
                asn1SlotId = ASN1SlotIdentifier.getInstance(obj);
            } catch (Exception ex) {
                throw new P11TokenException(ex.getMessage(), ex);
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
    throws P11TokenException {
        ParamUtil.requireNonNull("slotId", slotId);
        if (!moduleConf.isSlotIncluded(slotId)) {
            throw new P11UnknownEntityException(slotId);
        }

        ASN1SlotIdentifier tmpSlotId = new ASN1SlotIdentifier(slotId);

        ASN1Encodable resp = send(XiCmpConstants.ACTION_RP11_LIST_KEYLABELS,
                tmpSlotId);
        if (!(resp instanceof ASN1Sequence)) {
            throw new P11TokenException("response is not ASN1Sequence, but "
                    + resp.getClass().getName());
        }

        ASN1Sequence seq = (ASN1Sequence) resp;
        final int n = seq.size();

        String[] keyLabels = new String[n];
        for (int i = 0; i < n; i++) {
            ASN1Encodable obj = seq.getObjectAt(i);
            if (!(obj instanceof ASN1String)) {
                throw new P11TokenException("object at index " + i + " is not ASN1String, but "
                        + resp.getClass().getName());
            }
            keyLabels[i] = ((ASN1String) obj).getString();
        }

        return keyLabels;
    }

    private void checkSlotId(
            final P11EntityIdentifier entityId)
    throws P11UnknownEntityException {
        ParamUtil.requireNonNull("entityId", entityId);
        if (!moduleConf.isSlotIncluded(entityId.getSlotId())) {
            throw new P11UnknownEntityException(entityId);
        }
    }

    public P11ModuleConf getModuleConf() {
        return moduleConf;
    }

    private static PublicKey generatePublicKey(
            final byte[] encodedSubjectPublicKeyInfo)
    throws P11TokenException {
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
                throw new P11TokenException("unsupported key algorithm: " + aid);
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new P11TokenException("NoSuchAlgorithmException: " + ex.getMessage(), ex);
        }

        try {
            return kf.generatePublic(keyspec);
        } catch (InvalidKeySpecException ex) {
            throw new P11TokenException("InvalidKeySpecException: " + ex.getMessage(), ex);
        }
    }

}
