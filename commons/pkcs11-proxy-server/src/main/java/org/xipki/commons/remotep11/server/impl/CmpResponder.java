/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
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
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.pkcs11proxy.common.Asn1EntityIdAndCert;
import org.xipki.commons.pkcs11proxy.common.Asn1GenDSAKeypairParams;
import org.xipki.commons.pkcs11proxy.common.Asn1GenECKeypairParams;
import org.xipki.commons.pkcs11proxy.common.Asn1GenRSAKeypairParams;
import org.xipki.commons.pkcs11proxy.common.Asn1P11EntityIdentifier;
import org.xipki.commons.pkcs11proxy.common.Asn1P11ObjectIdentifier;
import org.xipki.commons.pkcs11proxy.common.Asn1P11Params;
import org.xipki.commons.pkcs11proxy.common.Asn1P11SlotIdentifier;
import org.xipki.commons.pkcs11proxy.common.Asn1RSAPkcsPssParams;
import org.xipki.commons.pkcs11proxy.common.Asn1RemoveObjectsParams;
import org.xipki.commons.pkcs11proxy.common.Asn1SignTemplate;
import org.xipki.commons.pkcs11proxy.common.Asn1Util;
import org.xipki.commons.pkcs11proxy.common.P11ProxyConstants;
import org.xipki.commons.security.api.ObjectIdentifiers;
import org.xipki.commons.security.api.exception.BadAsn1ObjectException;
import org.xipki.commons.security.api.exception.P11DuplicateEntityException;
import org.xipki.commons.security.api.exception.P11TokenException;
import org.xipki.commons.security.api.exception.P11UnknownEntityException;
import org.xipki.commons.security.api.exception.P11UnsupportedMechanismException;
import org.xipki.commons.security.api.exception.XiSecurityException;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11Identity;
import org.xipki.commons.security.api.p11.P11ObjectIdentifier;
import org.xipki.commons.security.api.p11.P11Params;
import org.xipki.commons.security.api.p11.P11Slot;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.util.KeyUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class CmpResponder {
    private static final Logger LOG = LoggerFactory.getLogger(CmpResponder.class);

    private static Set<Integer> versions;

    private final SecureRandom random = new SecureRandom();

    private final GeneralName sender = P11ProxyConstants.REMOTE_P11_CMP_SERVER;

    static {
        Set<Integer> vers = new HashSet<>(2);
        vers.add(1);
        versions = Collections.unmodifiableSet(vers);
    }

    CmpResponder() {
    }

    public static Set<Integer> getVersions() {
        return versions;
    }

    PKIMessage processPkiMessage(
            final LocalP11CryptServicePool p11CryptServicePool,
            final String moduleName,
            final PKIMessage pkiMessage) {
        ParamUtil.requireNonNull("p11CryptServicePool", p11CryptServicePool);
        ParamUtil.requireNonNull("pkiMessage", pkiMessage);
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
            return doProcessPkiMessage(p11CryptServicePool, moduleName, itv, respHeader);
        } catch (BadAsn1ObjectException ex) {
            LogUtil.error(LOG, ex, "could not process CMP message " + tidStr);
            return createRejectionPkiMessage(respHeader, PKIFailureInfo.badRequest,
                    ex.getMessage());
        } catch (P11TokenException ex) {
            LogUtil.error(LOG, ex, "could not process CMP message " + tidStr);

            String p11ErrorType;
            if (ex instanceof P11UnknownEntityException) {
                p11ErrorType = P11ProxyConstants.ERROR_UNKNOWN_ENTITY;
            } else if (ex instanceof P11DuplicateEntityException) {
                p11ErrorType = P11ProxyConstants.ERROR_DUPLICATE_ENTITY;
            } else if (ex instanceof P11UnsupportedMechanismException) {
                p11ErrorType = P11ProxyConstants.ERROR_UNSUPPORTED_MECHANISM;
            } else {
                p11ErrorType = P11ProxyConstants.ERROR_P11_TOKENERROR;
            }

            String errorMessage = ex.getMessage();

            if (errorMessage == null) {
                errorMessage = "NULL";
            } else if (StringUtil.isBlank(errorMessage.trim())) {
                errorMessage = "NULL";
            }

            ConfPairs confPairs = new ConfPairs(p11ErrorType, errorMessage);
            return createRejectionPkiMessage(respHeader, PKIFailureInfo.badRequest,
                    confPairs.getEncoded());
        } catch (Throwable th) {
            LogUtil.error(LOG, th, "could not process CMP message " + tidStr);
            return createRejectionPkiMessage(respHeader, PKIFailureInfo.systemFailure,
                    "SYSTEM_FAILURE");
        }
    } // method processPkiMessage

    private PKIMessage doProcessPkiMessage(
            final LocalP11CryptServicePool p11CryptServicePool,
            final String moduleName,
            final InfoTypeAndValue itv,
            final PKIHeader respHeader)
    throws BadAsn1ObjectException, P11TokenException, CertificateException, XiSecurityException,
    InvalidKeyException {
        ASN1Sequence seq = Asn1Util.getSequence(itv.getInfoValue());
        Asn1Util.requireRange(seq, 3, 3);
        int protocolVersion = Asn1Util.getInteger(seq.getObjectAt(0)).intValue();
        int action = Asn1Util.getInteger(seq.getObjectAt(1)).intValue();
        ASN1Encodable reqValue = seq.getObjectAt(2);

        P11CryptService p11CryptService = p11CryptServicePool.getP11CryptService(moduleName);
        ASN1Encodable respItvInfoValue = null;

        if (P11ProxyConstants.ACTION_addCert == action) {
            Asn1EntityIdAndCert asn1 = Asn1EntityIdAndCert.getInstance(reqValue);
            P11Slot slot = getSlot(p11CryptService, asn1.getEntityId());
            X509Certificate cert = new X509CertificateObject(asn1.getCertificate());
            slot.addCert(asn1.getEntityId().getObjectId().getObjectId(), cert);
        } else if (P11ProxyConstants.ACTION_genKeypair_DSA == action) {
            Asn1GenDSAKeypairParams asn1 = Asn1GenDSAKeypairParams.getInstance(reqValue);
            P11Slot slot = getSlot(p11CryptService, asn1.getSlotId());
            P11ObjectIdentifier keyId = slot.generateDSAKeypair(asn1.getP(), asn1.getQ(),
                    asn1.getG(), asn1.getLabel());
            respItvInfoValue = new Asn1P11EntityIdentifier(asn1.getSlotId().getSlotId(), keyId);
        } else if (P11ProxyConstants.ACTION_genKeypair_EC == action) {
            Asn1GenECKeypairParams asn1 = Asn1GenECKeypairParams.getInstance(reqValue);
            P11Slot slot = getSlot(p11CryptService, asn1.getSlotId());
            P11ObjectIdentifier keyId = slot.generateECKeypair(asn1.getCurveId().getId(),
                    asn1.getLabel());
            respItvInfoValue = new Asn1P11EntityIdentifier(asn1.getSlotId().getSlotId(), keyId);
        } else if (P11ProxyConstants.ACTION_genKeypair_RSA == action) {
            Asn1GenRSAKeypairParams asn1 = Asn1GenRSAKeypairParams.getInstance(reqValue);
            P11Slot slot = getSlot(p11CryptService, asn1.getSlotId());
            P11ObjectIdentifier keyId = slot.generateRSAKeypair(asn1.getKeysize(),
                    asn1.getPublicExponent(), asn1.getLabel());
            respItvInfoValue = new Asn1P11EntityIdentifier(asn1.getSlotId().getSlotId(), keyId);
        } else if (P11ProxyConstants.ACTION_getCertificate == action) {
            P11EntityIdentifier entityId =
                    Asn1P11EntityIdentifier.getInstance(reqValue).getEntityId();
            X509Certificate cert = p11CryptService.getIdentity(entityId).getCertificate();
            respItvInfoValue = Certificate.getInstance(cert.getEncoded());
        } else if (P11ProxyConstants.ACTION_getCertIdentifiers == action
                || P11ProxyConstants.ACTION_getIdentityIdentifiers == action) {
            Asn1P11SlotIdentifier slotId = Asn1P11SlotIdentifier.getInstance(reqValue);
            P11Slot slot = p11CryptService.getModule().getSlot(slotId.getSlotId());
            Set<P11ObjectIdentifier> objectIds;
            if (P11ProxyConstants.ACTION_getCertIdentifiers == action) {
                objectIds = slot.getCertIdentifiers();
            } else {
                objectIds = slot.getIdentityIdentifiers();
            }
            ASN1EncodableVector vec = new ASN1EncodableVector();
            for (P11ObjectIdentifier objectId : objectIds) {
                vec.add(new Asn1P11ObjectIdentifier(objectId));
            }
            respItvInfoValue = new DERSequence(vec);
        } else if (P11ProxyConstants.ACTION_getMechanisms == action) {
            P11SlotIdentifier slotId = Asn1P11SlotIdentifier.getInstance(reqValue).getSlotId();
            Set<Long> mechs = p11CryptService.getSlot(slotId).getMechanisms();
            ASN1EncodableVector vec = new ASN1EncodableVector();
            for (Long mech : mechs) {
                vec.add(new ASN1Integer(mech));
            }
            respItvInfoValue = new DERSequence(vec);
        } else if (P11ProxyConstants.ACTION_getPublicKey == action) {
            P11EntityIdentifier identityId =
                    Asn1P11EntityIdentifier.getInstance(reqValue).getEntityId();
            PublicKey pubKey = p11CryptService.getIdentity(identityId).getPublicKey();
            if (pubKey == null) {
                throw new P11UnknownEntityException(identityId);
            }

            respItvInfoValue = KeyUtil.createSubjectPublicKeyInfo(pubKey);
        } else if (P11ProxyConstants.ACTION_getSlotIds == action) {
            List<P11SlotIdentifier> slotIds = p11CryptService.getModule().getSlotIdentifiers();

            ASN1EncodableVector vector = new ASN1EncodableVector();
            for (P11SlotIdentifier slotId : slotIds) {
                vector.add(new Asn1P11SlotIdentifier(slotId));
            }
            respItvInfoValue = new DERSequence(vector);
        } else if (P11ProxyConstants.ACTION_removeCerts == action) {
            Asn1P11EntityIdentifier asn1 = Asn1P11EntityIdentifier.getInstance(reqValue);
            P11Slot slot = getSlot(p11CryptService, asn1);
            slot.removeCerts(asn1.getObjectId().getObjectId());
        } else if (P11ProxyConstants.ACTION_removeIdentity == action) {
            Asn1P11EntityIdentifier asn1 = Asn1P11EntityIdentifier.getInstance(reqValue);
            P11Slot slot = getSlot(p11CryptService, asn1);
            slot.removeIdentity(asn1.getObjectId().getObjectId());
        } else if (P11ProxyConstants.ACTION_sign == action) {
            Asn1SignTemplate signTemplate = Asn1SignTemplate.getInstance(reqValue);
            long mechanism = signTemplate.getMechanism().getMechanism();
            Asn1P11Params tmpParams = signTemplate.getMechanism().getParams();
            ASN1Encodable asn1Params = null;
            if (tmpParams != null) {
                asn1Params = tmpParams.getP11Params();
            }
            P11Params params = null;
            if (asn1Params instanceof Asn1RSAPkcsPssParams) {
                params = ((Asn1RSAPkcsPssParams) asn1Params).getPkcsPssParams();
            } else if (asn1Params != null) {
                throw new BadAsn1ObjectException("unknown SignTemplate.params");
            }

            byte[] content = signTemplate.getMessage();
            P11Identity identity = p11CryptService.getIdentity(
                    signTemplate.getIdentityId().getEntityId());
            byte[] signature = identity.sign(mechanism, params, content);
            respItvInfoValue = new DEROctetString(signature);
        } else if (P11ProxyConstants.ACTION_updateCerificate == action) {
            Asn1EntityIdAndCert asn1 = Asn1EntityIdAndCert.getInstance(reqValue);
            P11Slot slot = getSlot(p11CryptService, asn1.getEntityId());
            slot.updateCertificate(asn1.getEntityId().getObjectId().getObjectId(),
                    new X509CertificateObject(asn1.getCertificate()));
        } else if (P11ProxyConstants.ACTION_removeObjects == action) {
            Asn1RemoveObjectsParams asn1 = Asn1RemoveObjectsParams.getInstance(reqValue);
            P11Slot slot = getSlot(p11CryptService, asn1.getSlotId());
            int num = slot.removeObjects(asn1.getObjectId(), asn1.getObjectLabel());
            respItvInfoValue = new ASN1Integer(num);
        } else {
            final String statusMessage = "unsupported XiPKI action code '" + action + "'";
            return createRejectionPkiMessage(respHeader,
                    PKIFailureInfo.badRequest, statusMessage);
        }

        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new ASN1Integer(protocolVersion));
        vec.add(new ASN1Integer(action));
        if (respItvInfoValue != null) {
            vec.add(respItvInfoValue);
        }

        InfoTypeAndValue respItv = new InfoTypeAndValue(
                ObjectIdentifiers.id_xipki_cmp_cmpGenmsg,
                new DERSequence(vec));
        GenRepContent genRepContent = new GenRepContent(respItv);
        PKIBody respBody = new PKIBody(PKIBody.TYPE_GEN_REP, genRepContent);
        return new PKIMessage(respHeader, respBody);
    }

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

    private P11Slot getSlot(
            final P11CryptService p11Service,
            final Asn1P11EntityIdentifier entityId)
    throws P11TokenException {
        return p11Service.getModule().getSlot(entityId.getSlotId().getSlotId());
    }

    private P11Slot getSlot(
            final P11CryptService p11Service,
            final Asn1P11SlotIdentifier slotId)
    throws P11TokenException {
        return p11Service.getModule().getSlot(slotId.getSlotId());
    }

}
