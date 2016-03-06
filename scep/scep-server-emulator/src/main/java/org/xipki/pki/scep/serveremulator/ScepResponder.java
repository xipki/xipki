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

package org.xipki.pki.scep.serveremulator;

import java.security.PrivateKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.audit.api.AuditEvent;
import org.xipki.commons.audit.api.AuditEventData;
import org.xipki.commons.audit.api.AuditStatus;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.pki.scep.crypto.HashAlgoType;
import org.xipki.pki.scep.exception.MessageDecodingException;
import org.xipki.pki.scep.message.CaCaps;
import org.xipki.pki.scep.message.DecodedPkiMessage;
import org.xipki.pki.scep.message.EnvelopedDataDecryptor;
import org.xipki.pki.scep.message.EnvelopedDataDecryptorInstance;
import org.xipki.pki.scep.message.IssuerAndSubject;
import org.xipki.pki.scep.message.NextCaMessage;
import org.xipki.pki.scep.message.PkiMessage;
import org.xipki.pki.scep.transaction.CaCapability;
import org.xipki.pki.scep.transaction.FailInfo;
import org.xipki.pki.scep.transaction.MessageType;
import org.xipki.pki.scep.transaction.Nonce;
import org.xipki.pki.scep.transaction.PkiStatus;
import org.xipki.pki.scep.transaction.TransactionId;
import org.xipki.pki.scep.util.ScepUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ScepResponder {

    private static final Logger LOG = LoggerFactory.getLogger(ScepResponder.class);

    private static final long DFLT_MAX_SIGNINGTIME_BIAS = 5L * 60 * 1000; // 5 minutes

    private static final Set<ASN1ObjectIdentifier> AES_ENC_ALGS
            = new HashSet<ASN1ObjectIdentifier>();

    private final CaCaps caCaps;

    private final CaEmulator caEmulator;

    private final RaEmulator raEmulator;

    private final NextCaAndRa nextCaAndRa;

    private final ScepControl control;

    private long maxSigningTimeBiasInMs = DFLT_MAX_SIGNINGTIME_BIAS;

    static {
        AES_ENC_ALGS.add(CMSAlgorithm.AES128_CBC);
        AES_ENC_ALGS.add(CMSAlgorithm.AES128_CCM);
        AES_ENC_ALGS.add(CMSAlgorithm.AES128_GCM);
        AES_ENC_ALGS.add(CMSAlgorithm.AES192_CBC);
        AES_ENC_ALGS.add(CMSAlgorithm.AES192_CCM);
        AES_ENC_ALGS.add(CMSAlgorithm.AES192_GCM);
        AES_ENC_ALGS.add(CMSAlgorithm.AES256_CBC);
        AES_ENC_ALGS.add(CMSAlgorithm.AES256_CCM);
        AES_ENC_ALGS.add(CMSAlgorithm.AES256_GCM);
    }

    public ScepResponder(
            final CaCaps caCaps,
            final CaEmulator caEmulator,
            final RaEmulator raEmulator,
            final NextCaAndRa nextCaAndRa,
            final ScepControl control)
    throws Exception {
        this.caCaps = ParamUtil.requireNonNull("caCaps", caCaps);
        this.caEmulator = ParamUtil.requireNonNull("caEmulator", caEmulator);
        this.control = ParamUtil.requireNonNull("control", control);

        this.raEmulator = raEmulator;
        this.nextCaAndRa = nextCaAndRa;
        CaCaps caps = caCaps;
        if (nextCaAndRa == null) {
            caps.removeCapability(CaCapability.GetNextCACert);
        } else {
            caps.addCapability(CaCapability.GetNextCACert);
        }
    }

    /**
    *
    * @param ms signing time bias in milliseconds. non-positive value deactivate
    *        the check of signing time.
    */
    public void setMaxSigningTimeBias(
            final long ms) {
        this.maxSigningTimeBiasInMs = ms;
    }

    public ContentInfo servicePkiOperation(
            final CMSSignedData requestContent,
            final AuditEvent auditEvent)
    throws MessageDecodingException, CaException {
        ParamUtil.requireNonNull("requestContent", requestContent);
        PrivateKey recipientKey = (raEmulator != null)
                ? raEmulator.getRaKey()
                : caEmulator.getCaKey();
        Certificate recipientCert = (raEmulator != null)
                ? raEmulator.getRaCert()
                : caEmulator.getCaCert();
        X509CertificateObject recipientX509Obj;
        try {
            recipientX509Obj = new X509CertificateObject(recipientCert);
        } catch (CertificateParsingException ex) {
            throw new MessageDecodingException("could not parse recipintCert "
                    + recipientCert.getTBSCertificate().getSubject());
        }

        EnvelopedDataDecryptorInstance decInstance =
                new EnvelopedDataDecryptorInstance(recipientX509Obj, recipientKey);
        EnvelopedDataDecryptor recipient = new EnvelopedDataDecryptor(decInstance);

        DecodedPkiMessage req = DecodedPkiMessage.decode(requestContent, recipient, null);

        PkiMessage rep = doServicePkiOperation(req, auditEvent);
        if (auditEvent != null) {
            AuditEventData eventData = new AuditEventData("pkiStatus",
                    rep.getPkiStatus().toString());
            auditEvent.addEventData(eventData);
            if (rep.getPkiStatus() == PkiStatus.FAILURE) {
                auditEvent.setStatus(AuditStatus.FAILED);
            }
            if (rep.getFailInfo() != null) {
                eventData = new AuditEventData("failInfo", rep.getFailInfo().toString());
                auditEvent.addEventData(eventData);
            }
        }

        String signatureAlgorithm = ScepUtil.getSignatureAlgorithm(getSigningKey(),
                HashAlgoType.getHashAlgoType(req.getDigestAlgorithm().getId()));

        try {
            X509Certificate jceSignerCert = new X509CertificateObject(getSigningCert());
            X509Certificate[] certs = control.isSendSignerCert()
                    ? new X509Certificate[]{jceSignerCert}
                    : null;

            return rep.encode(
                    getSigningKey(),
                    signatureAlgorithm,
                    jceSignerCert,
                    certs,
                    req.getSignatureCert(),
                    req.getContentEncryptionAlgorithm());
        } catch (Exception ex) {
            throw new CaException(ex);
        }
    } // method servicePkiOperation

    public ContentInfo encode(
            final NextCaMessage nextCaMsg)
    throws CaException {
        ParamUtil.requireNonNull("nextCAMsg", nextCaMsg);
        try {
            X509Certificate jceSignerCert = new X509CertificateObject(getSigningCert());

            X509Certificate[] certs = control.isSendSignerCert()
                    ? new X509Certificate[]{jceSignerCert}
                    : null;
            return nextCaMsg.encode(
                    getSigningKey(),
                    jceSignerCert,
                    certs);
        } catch (Exception ex) {
            throw new CaException(ex);
        }
    }

    private PkiMessage doServicePkiOperation(
            final DecodedPkiMessage req,
            final AuditEvent auditEvent)
    throws MessageDecodingException, CaException {

        TransactionId tid = req.getTransactionId();
        PkiMessage rep = new PkiMessage(tid, MessageType.CertRep, Nonce.randomNonce());
        rep.setPkiStatus(PkiStatus.SUCCESS);

        rep.setRecipientNonce(req.getSenderNonce());

        if (req.getFailureMessage() != null) {
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(FailInfo.badRequest);
        }

        Boolean bo = req.isSignatureValid();
        if (bo != null && !bo.booleanValue()) {
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(FailInfo.badMessageCheck);
        }

        bo = req.isDecryptionSuccessful();
        if (bo != null && !bo.booleanValue()) {
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(FailInfo.badRequest);
        }

        Date signingTime = req.getSigningTime();
        if (maxSigningTimeBiasInMs > 0) {
            boolean isTimeBad = false;
            if (signingTime == null) {
                isTimeBad = true;
            } else {
                long now = System.currentTimeMillis();
                long diff = now - signingTime.getTime();
                if (diff < 0) {
                    diff = -1 * diff;
                }
                isTimeBad = diff > maxSigningTimeBiasInMs;
            }

            if (isTimeBad) {
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badTime);
            }
        }

        // check the digest algorithm
        String oid = req.getDigestAlgorithm().getId();
        HashAlgoType hashAlgoType = HashAlgoType.getHashAlgoType(oid);
        if (hashAlgoType == null) {
            LOG.warn("tid={}: unknown digest algorithm {}", tid, oid);
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(FailInfo.badAlg);
        } else {
            boolean supported = false;
            if (hashAlgoType == HashAlgoType.SHA1) {
                if (caCaps.containsCapability(CaCapability.SHA1)) {
                    supported = true;
                }
            } else if (hashAlgoType == HashAlgoType.SHA256) {
                if (caCaps.containsCapability(CaCapability.SHA256)) {
                    supported = true;
                }
            } else if (hashAlgoType == HashAlgoType.SHA512) {
                if (caCaps.containsCapability(CaCapability.SHA512)) {
                    supported = true;
                }
            } else if (hashAlgoType == HashAlgoType.MD5) {
                if (control.isUseInsecureAlg()) {
                    supported = true;
                }
            }

            if (!supported) {
                LOG.warn("tid={}: unsupported digest algorithm {}", tid, oid);
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badAlg);
            } // end if
        } // end if

        // check the content encryption algorithm
        ASN1ObjectIdentifier encOid = req.getContentEncryptionAlgorithm();
        if (CMSAlgorithm.DES_EDE3_CBC.equals(encOid)) {
            if (!caCaps.containsCapability(CaCapability.DES3)) {
                LOG.warn("tid={}: encryption with DES3 algorithm is not permitted", tid, encOid);
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badAlg);
            }
        } else if (AES_ENC_ALGS.contains(encOid)) {
            if (!caCaps.containsCapability(CaCapability.AES)) {
                LOG.warn("tid={}: encryption with AES algorithm {} is not permitted", tid,
                        encOid);
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badAlg);
            }
        } else if (CMSAlgorithm.DES_CBC.equals(encOid)) {
            if (!control.isUseInsecureAlg()) {
                LOG.warn("tid={}: encryption with DES algorithm {} is not permitted", tid,
                        encOid);
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badAlg);
            }
        } else {
            LOG.warn("tid={}: encryption with algorithm {} is not permitted", tid, encOid);
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(FailInfo.badAlg);
        }

        if (rep.getPkiStatus() == PkiStatus.FAILURE) {
            return rep;
        }

        MessageType messageType = req.getMessageType();

        switch (messageType) {
        case PKCSReq:
            CertificationRequest p10ReqInfo = (CertificationRequest) req.getMessageData();

            String challengePwd = getChallengePassword(p10ReqInfo.getCertificationRequestInfo());
            if (challengePwd == null || !control.getSecret().equals(challengePwd)) {
                LOG.warn("challengePassword is not trusted");
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badRequest);
            }

            Certificate cert;
            try {
                cert = caEmulator.generateCert(p10ReqInfo);
            } catch (Exception ex) {
                throw new CaException("system failure: " + ex.getMessage(), ex);
            }

            if (cert != null && control.isPendingCert()) {
                rep.setPkiStatus(PkiStatus.PENDING);
            } else if (cert != null) {
                ContentInfo messageData = createSignedData(cert);
                rep.setMessageData(messageData);
            } else {
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badCertId);
            }

            break;
        case CertPoll:
            IssuerAndSubject is = (IssuerAndSubject) req.getMessageData();
            cert = caEmulator.pollCert(is.getIssuer(), is.getSubject());
            if (cert != null) {
                rep.setMessageData(createSignedData(cert));
            } else {
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badCertId);
            }

            break;
        case GetCert:
            IssuerAndSerialNumber isn = (IssuerAndSerialNumber) req.getMessageData();
            cert = caEmulator.getCert(isn.getName(),
                    isn.getSerialNumber().getValue());
            if (cert != null) {
                rep.setMessageData(createSignedData(cert));
            } else {
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badCertId);
            }

            break;
        case RenewalReq:
            if (!caCaps.containsCapability(CaCapability.Renewal)) {
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badRequest);
            } else {
                p10ReqInfo = (CertificationRequest) req.getMessageData();
                try {
                    cert = caEmulator.generateCert(p10ReqInfo);
                } catch (Exception ex) {
                    throw new CaException("system failure: " + ex.getMessage(), ex);
                }
                if (cert != null) {
                    rep.setMessageData(createSignedData(cert));
                } else {
                    rep.setPkiStatus(PkiStatus.FAILURE);
                    rep.setFailInfo(FailInfo.badCertId);
                }
            }
            break;
        case UpdateReq:
            if (!caCaps.containsCapability(CaCapability.Update)) {
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badRequest);
            } else {
                p10ReqInfo = (CertificationRequest) req.getMessageData();
                try {
                    cert = caEmulator.generateCert(p10ReqInfo);
                } catch (Exception ex) {
                    throw new CaException("system failure: " + ex.getMessage(), ex);
                }
                if (cert != null) {
                    rep.setMessageData(createSignedData(cert));
                } else {
                    rep.setPkiStatus(PkiStatus.FAILURE);
                    rep.setFailInfo(FailInfo.badCertId);
                }
            }
            break;
        case GetCRL:
            isn = (IssuerAndSerialNumber) req.getMessageData();
            CertificateList crl;
            try {
                crl = caEmulator.getCrl(isn.getName(), isn.getSerialNumber().getValue());
            } catch (Exception ex) {
                throw new CaException("system failure: " + ex.getMessage(), ex);
            }
            if (crl != null) {
                rep.setMessageData(createSignedData(crl));
            } else {
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badCertId);
            }
            break;
        default:
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(FailInfo.badRequest);
        } // end switch

        return rep;
    } // method doServicePkiOperation

    private ContentInfo createSignedData(
            final CertificateList crl)
    throws CaException {
        CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();
        cmsSignedDataGen.addCRL(new X509CRLHolder(crl));

        CMSSignedData cmsSigneddata;
        try {
            cmsSigneddata = cmsSignedDataGen.generate(new CMSAbsentContent());
        } catch (CMSException ex) {
            throw new CaException(ex.getMessage(), ex);
        }

        return cmsSigneddata.toASN1Structure();

    }

    private ContentInfo createSignedData(
            final Certificate cert)
    throws CaException {
        CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();

        CMSSignedData cmsSigneddata;
        try {
            cmsSignedDataGen.addCertificate(new X509CertificateHolder(cert));
            if (control.isSendCaCert()) {
                cmsSignedDataGen.addCertificate(new X509CertificateHolder(caEmulator.getCaCert()));
            }

            cmsSigneddata = cmsSignedDataGen.generate(new CMSAbsentContent());
        } catch (CMSException ex) {
            throw new CaException(ex);
        }

        return cmsSigneddata.toASN1Structure();
    }

    public PrivateKey getSigningKey() {
        return (raEmulator != null)
                ? raEmulator.getRaKey()
                : caEmulator.getCaKey();
    }

    public Certificate getSigningCert() {
        return (raEmulator != null)
                ? raEmulator.getRaCert()
                : caEmulator.getCaCert();
    }

    public CaCaps getCaCaps() {
        return caCaps;
    }

    public CaEmulator getCaEmulator() {
        return caEmulator;
    }

    public RaEmulator getRaEmulator() {
        return raEmulator;
    }

    public NextCaAndRa getNextCaAndRa() {
        return nextCaAndRa;
    }

    private static String getChallengePassword(
            final CertificationRequestInfo p10Req) {
        ASN1Set attrs = p10Req.getAttributes();
        for (int i = 0; i < attrs.size(); i++) {
            Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
            if (PKCSObjectIdentifiers.pkcs_9_at_challengePassword.equals(attr.getAttrType())) {
                ASN1String str = (ASN1String) attr.getAttributeValues()[0];
                return str.getString();
            }
        }
        return null;
    }

}
