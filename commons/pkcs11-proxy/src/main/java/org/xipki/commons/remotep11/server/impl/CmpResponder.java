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

package org.xipki.commons.remotep11.server.impl;

import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
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
import org.xipki.commons.security.api.BadAsn1ObjectException;
import org.xipki.commons.security.api.ObjectIdentifiers;
import org.xipki.commons.security.api.XipkiCmpConstants;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.remote.KeyIdentifier;
import org.xipki.commons.security.api.p11.remote.PsoTemplate;
import org.xipki.commons.security.api.p11.remote.SlotAndKeyIdentifer;
import org.xipki.commons.security.api.p11.remote.SlotIdentifier;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class CmpResponder {

    private static final Logger LOG = LoggerFactory.getLogger(CmpResponder.class);

    private final SecureRandom random = new SecureRandom();

    private final GeneralName sender = XipkiCmpConstants.REMOTE_P11_CMP_SERVER;

    CmpResponder() {
    }

    PKIMessage processPkiMessage(
            final LocalP11CryptServicePool localP11CryptServicePool,
            final String moduleName,
            final PKIMessage pkiMessage) {
        GeneralPKIMessage message = new GeneralPKIMessage(pkiMessage);

        PKIHeader reqHeader = message.getHeader();
        ASN1OctetString tid = reqHeader.getTransactionID();

        if (tid == null) {
            byte[] randomBytes = randomTransactionId();
            tid = new DEROctetString(randomBytes);
        }
        String tidStr = Hex.toHexString(tid.getOctets());

        PKIHeaderBuilder respHeaderBuilder = new PKIHeaderBuilder(
                reqHeader.getPvno().getValue().intValue(),
                sender,
                reqHeader.getSender());
        respHeaderBuilder.setTransactionID(tid);

        PKIBody reqBody = message.getBody();
        final int type = reqBody.getType();

        PKIHeader respHeader = respHeaderBuilder.build();

        if (type != PKIBody.TYPE_GEN_MSG) {
            ErrorMsgContent emc = new ErrorMsgContent(
                    new PKIStatusInfo(PKIStatus.rejection,
                            new PKIFreeText("unsupported type " + type),
                            new PKIFailureInfo(PKIFailureInfo.badRequest)));

            PKIBody respBody = new PKIBody(PKIBody.TYPE_ERROR, emc);

            return new PKIMessage(respHeader, respBody);
        }

        GenMsgContent genMsgBody = (GenMsgContent) reqBody.getContent();
        InfoTypeAndValue[] itvs = genMsgBody.toInfoTypeAndValueArray();

        InfoTypeAndValue itv = null;
        if (itvs != null && itvs.length > 0) {
            for (InfoTypeAndValue m : itvs) {
                ASN1ObjectIdentifier itvType = m.getInfoType();
                if (ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.equals(itvType)) {
                    itv = m;
                    break;
                }
            }
        }

        if (itv == null) {
            final String statusMessage = String.format(
                    "PKIBody type %s is only supported with the sub-knownTypes",
                    ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.getId());
            return createRejectionPkiMessage(respHeader, PKIFailureInfo.badRequest, statusMessage);
        }

        try {
            ASN1Encodable asn1 = itv.getInfoValue();
            ASN1Integer asn1Code = null;
            ASN1Encodable reqValue = null;

            try {
                ASN1Sequence seq = ASN1Sequence.getInstance(asn1);
                asn1Code = ASN1Integer.getInstance(seq.getObjectAt(0));
                if (seq.size() > 1) {
                    reqValue = seq.getObjectAt(1);
                }
            } catch (IllegalArgumentException e) {
                final String statusMessage = "invalid value of the InfoTypeAndValue for "
                        + ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.getId();
                return createRejectionPkiMessage(respHeader, PKIFailureInfo.badRequest,
                        statusMessage);
            }

            int action = asn1Code.getPositiveValue().intValue();
            ASN1Encodable respItvInfoValue;

            P11CryptService p11CryptService =
                    localP11CryptServicePool.getP11CryptService(moduleName);

            switch (action) {
            case XipkiCmpConstants.ACTION_RP11_VERSION:
                respItvInfoValue = new ASN1Integer(localP11CryptServicePool.getVersion());
                break;
            case XipkiCmpConstants.ACTION_RP11_PSO_DSA_PLAIN:
            case XipkiCmpConstants.ACTION_RP11_PSO_DSA_X962:
            case XipkiCmpConstants.ACTION_RP11_PSO_ECDSA_PLAIN:
            case XipkiCmpConstants.ACTION_RP11_PSO_ECDSA_X962:
            case XipkiCmpConstants.ACTION_RP11_PSO_RSA_PKCS:
            case XipkiCmpConstants.ACTION_RP11_PSO_RSA_X509:
                byte[] psoMessage = null;
                P11SlotIdentifier slot = null;
                P11KeyIdentifier keyId = null;
                try {
                    PsoTemplate psoTemplate = PsoTemplate.getInstance(reqValue);
                    psoMessage = psoTemplate.getMessage();
                    SlotAndKeyIdentifer slotAndKeyIdentifier =
                            psoTemplate.getSlotAndKeyIdentifer();
                    slot = slotAndKeyIdentifier.getSlotIdentifier().getSlotId();
                    KeyIdentifier keyIdentifier = slotAndKeyIdentifier.getKeyIdentifier();
                    keyId = keyIdentifier.getKeyId();
                } catch (IllegalArgumentException e) {
                    final String statusMessage = "invalid PSOTemplate";
                    return createRejectionPkiMessage(respHeader, PKIFailureInfo.badRequest,
                            statusMessage);
                }

                byte[] signature;

                if (XipkiCmpConstants.ACTION_RP11_PSO_ECDSA_PLAIN == action) {
                    signature = p11CryptService.CKM_ECDSA_Plain(psoMessage, slot, keyId);
                } else if (XipkiCmpConstants.ACTION_RP11_PSO_ECDSA_X962 == action) {
                    signature = p11CryptService.CKM_ECDSA_X962(psoMessage, slot, keyId);
                } else if (XipkiCmpConstants.ACTION_RP11_PSO_DSA_PLAIN == action) {
                    signature = p11CryptService.CKM_DSA_Plain(psoMessage, slot, keyId);
                } else if (XipkiCmpConstants.ACTION_RP11_PSO_DSA_X962 == action) {
                    signature = p11CryptService.CKM_DSA_X962(psoMessage, slot, keyId);
                } else if (XipkiCmpConstants.ACTION_RP11_PSO_RSA_X509 == action) {
                    signature = p11CryptService.CKM_RSA_X509(psoMessage, slot, keyId);
                } else if (XipkiCmpConstants.ACTION_RP11_PSO_RSA_PKCS == action) {
                    signature = p11CryptService.CKM_RSA_PKCS(psoMessage, slot, keyId);
                } else {
                    throw new RuntimeException("should not reach here");
                }

                respItvInfoValue = new DEROctetString(signature);
                break;
            case XipkiCmpConstants.ACTION_RP11_GET_CERTIFICATE:
            case XipkiCmpConstants.ACTION_RP11_GET_PUBLICKEY:
                slot = null;
                keyId = null;
                try {
                    SlotAndKeyIdentifer slotAndKeyIdentifier =
                            SlotAndKeyIdentifer.getInstance(reqValue);
                    slot = slotAndKeyIdentifier.getSlotIdentifier().getSlotId();
                    KeyIdentifier keyIdentifier = slotAndKeyIdentifier.getKeyIdentifier();
                    keyId = keyIdentifier.getKeyId();
                } catch (IllegalArgumentException e) {
                    final String statusMessage = "invalid SlotAndKeyIdentifier";
                    return createRejectionPkiMessage(respHeader, PKIFailureInfo.badRequest,
                            statusMessage);
                }

                byte[] encodeCertOrKey;
                if (XipkiCmpConstants.ACTION_RP11_GET_CERTIFICATE == action) {
                    encodeCertOrKey = p11CryptService.getCertificate(slot, keyId).getEncoded();
                } else if (XipkiCmpConstants.ACTION_RP11_GET_PUBLICKEY == action) {
                    encodeCertOrKey = p11CryptService.getPublicKey(slot, keyId).getEncoded();
                } else {
                    throw new RuntimeException("should not reach here");
                }

                respItvInfoValue = new DEROctetString(encodeCertOrKey);
                break;
            case XipkiCmpConstants.ACTION_RP11_LIST_SLOTS:
                P11SlotIdentifier[] slotIds = p11CryptService.getSlotIdentifiers();

                ASN1EncodableVector vector = new ASN1EncodableVector();
                for (P11SlotIdentifier slotId : slotIds) {
                    vector.add(new SlotIdentifier(slotId));
                }
                respItvInfoValue = new DERSequence(vector);
                break;
            case XipkiCmpConstants.ACTION_RP11_LIST_KEYLABELS:
                SlotIdentifier slotId = SlotIdentifier.getInstance(reqValue);
                String[] keyLabels = p11CryptService.getKeyLabels(slotId.getSlotId());

                vector = new ASN1EncodableVector();
                for (String keyLabel : keyLabels) {
                    vector.add(new DERUTF8String(keyLabel));
                }
                respItvInfoValue = new DERSequence(vector);
                break;
            default:
                final String statusMessage = "unsupported XiPKI action code '" + action + "'";
                return createRejectionPkiMessage(respHeader,
                        PKIFailureInfo.badRequest, statusMessage);
            } // end switch (code)

            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(action));
            if (respItvInfoValue != null) {
                v.add(respItvInfoValue);
            }
            InfoTypeAndValue respItv = new InfoTypeAndValue(
                    ObjectIdentifiers.id_xipki_cmp_cmpGenmsg,
                    new DERSequence(v));
            GenRepContent genRepContent = new GenRepContent(respItv);
            PKIBody respBody = new PKIBody(PKIBody.TYPE_GEN_REP, genRepContent);
            return new PKIMessage(respHeader, respBody);
        } catch (BadAsn1ObjectException e) {
            return createRejectionPkiMessage(respHeader, PKIFailureInfo.badRequest,
                    e.getMessage());
        } catch (Throwable t) {
            LOG.error("error while processing CMP message {}, message: {}", tidStr,
                    t.getMessage());
            LOG.debug("error while processing CMP message " + tidStr, t);
            return createRejectionPkiMessage(respHeader, PKIFailureInfo.systemFailure,
                    t.getMessage());
        }
    } // method processPkiMessage

    private PKIMessage createRejectionPkiMessage(
            final PKIHeader header,
            final int pkiFailureInfo,
            final String statusMessage) {
        ErrorMsgContent emc = new ErrorMsgContent(
                new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText(statusMessage),
                new PKIFailureInfo(pkiFailureInfo)));
        PKIBody respBody = new PKIBody(PKIBody.TYPE_ERROR, emc);
        return new PKIMessage(header, respBody);
    }

    private byte[] randomTransactionId() {
        byte[] bytes = new byte[10];
        synchronized (random) {
            random.nextBytes(bytes);
        }
        return bytes;
    }

}
