/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.scep.serveremulator;

import java.security.PrivateKey;
import java.security.cert.CertificateException;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditStatus;
import org.xipki.common.util.ParamUtil;
import org.xipki.scep.crypto.ScepHashAlgoType;
import org.xipki.scep.exception.MessageDecodingException;
import org.xipki.scep.message.CaCaps;
import org.xipki.scep.message.DecodedPkiMessage;
import org.xipki.scep.message.EnvelopedDataDecryptor;
import org.xipki.scep.message.EnvelopedDataDecryptorInstance;
import org.xipki.scep.message.IssuerAndSubject;
import org.xipki.scep.message.NextCaMessage;
import org.xipki.scep.message.PkiMessage;
import org.xipki.scep.transaction.CaCapability;
import org.xipki.scep.transaction.FailInfo;
import org.xipki.scep.transaction.MessageType;
import org.xipki.scep.transaction.Nonce;
import org.xipki.scep.transaction.PkiStatus;
import org.xipki.scep.transaction.TransactionId;
import org.xipki.scep.util.ScepUtil;
import org.xipki.security.util.X509Util;

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

    public ScepResponder(final CaCaps caCaps, final CaEmulator caEmulator,
            final RaEmulator raEmulator, final NextCaAndRa nextCaAndRa, final ScepControl control)
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
    public void setMaxSigningTimeBias(final long ms) {
        this.maxSigningTimeBiasInMs = ms;
    }

    public ContentInfo servicePkiOperation(final CMSSignedData requestContent,
            final AuditEvent event) throws MessageDecodingException, CaException {
        ParamUtil.requireNonNull("requestContent", requestContent);
        PrivateKey recipientKey = (raEmulator != null) ? raEmulator.raKey()
                : caEmulator.caKey();
        Certificate recipientCert = (raEmulator != null) ? raEmulator.raCert()
                : caEmulator.caCert();
        X509Certificate recipientX509Obj;
        try {
            recipientX509Obj = X509Util.toX509Cert(recipientCert);
        } catch (CertificateException ex) {
            throw new MessageDecodingException("could not parse recipientCert "
                    + recipientCert.getTBSCertificate().getSubject());
        }

        EnvelopedDataDecryptorInstance decInstance =
                new EnvelopedDataDecryptorInstance(recipientX509Obj, recipientKey);
        EnvelopedDataDecryptor recipient = new EnvelopedDataDecryptor(decInstance);

        DecodedPkiMessage req = DecodedPkiMessage.decode(requestContent, recipient, null);

        PkiMessage rep = servicePkiOperation0(req, event);
        event.addEventData(ScepAuditConstants.NAME_pkiStatus, rep.pkiStatus());
        if (rep.pkiStatus() == PkiStatus.FAILURE) {
            event.setStatus(AuditStatus.FAILED);
        }
        if (rep.failInfo() != null) {
            event.addEventData(ScepAuditConstants.NAME_failInfo, rep.failInfo());
        }

        String signatureAlgorithm = ScepUtil.getSignatureAlgorithm(signingKey(),
                ScepHashAlgoType.forNameOrOid(req.digestAlgorithm().getId()));

        try {
            X509Certificate jceSignerCert = X509Util.toX509Cert(signingCert());
            X509Certificate[] certs = control.isSendSignerCert()
                    ? new X509Certificate[]{jceSignerCert} : null;

            return rep.encode(signingKey(), signatureAlgorithm, jceSignerCert, certs,
                    req.signatureCert(), req.contentEncryptionAlgorithm());
        } catch (Exception ex) {
            throw new CaException(ex);
        }
    } // method servicePkiOperation

    public ContentInfo encode(final NextCaMessage nextCaMsg) throws CaException {
        ParamUtil.requireNonNull("nextCAMsg", nextCaMsg);
        try {
            X509Certificate jceSignerCert = X509Util.toX509Cert(signingCert());
            X509Certificate[] certs = control.isSendSignerCert()
                    ? new X509Certificate[]{jceSignerCert} : null;
            return nextCaMsg.encode(signingKey(), jceSignerCert, certs);
        } catch (Exception ex) {
            throw new CaException(ex);
        }
    }

    private PkiMessage servicePkiOperation0(final DecodedPkiMessage req,
            final AuditEvent event) throws MessageDecodingException, CaException {

        TransactionId tid = req.transactionId();
        PkiMessage rep = new PkiMessage(tid, MessageType.CertRep, Nonce.randomNonce());
        rep.setPkiStatus(PkiStatus.SUCCESS);

        rep.setRecipientNonce(req.senderNonce());

        if (req.failureMessage() != null) {
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

        Date signingTime = req.signingTime();
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
        String oid = req.digestAlgorithm().getId();
        ScepHashAlgoType hashAlgoType = ScepHashAlgoType.forNameOrOid(oid);
        if (hashAlgoType == null) {
            LOG.warn("tid={}: unknown digest algorithm {}", tid, oid);
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(FailInfo.badAlg);
        } else {
            boolean supported = false;
            if (hashAlgoType == ScepHashAlgoType.SHA1) {
                if (caCaps.containsCapability(CaCapability.SHA1)) {
                    supported = true;
                }
            } else if (hashAlgoType == ScepHashAlgoType.SHA256) {
                if (caCaps.containsCapability(CaCapability.SHA256)) {
                    supported = true;
                }
            } else if (hashAlgoType == ScepHashAlgoType.SHA512) {
                if (caCaps.containsCapability(CaCapability.SHA512)) {
                    supported = true;
                }
            } else if (hashAlgoType == ScepHashAlgoType.MD5) {
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
        ASN1ObjectIdentifier encOid = req.contentEncryptionAlgorithm();
        if (CMSAlgorithm.DES_EDE3_CBC.equals(encOid)) {
            if (!caCaps.containsCapability(CaCapability.DES3)) {
                LOG.warn("tid={}: encryption with DES3 algorithm is not permitted", tid, encOid);
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badAlg);
            }
        } else if (AES_ENC_ALGS.contains(encOid)) {
            if (!caCaps.containsCapability(CaCapability.AES)) {
                LOG.warn("tid={}: encryption with AES algorithm {} is not permitted", tid, encOid);
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badAlg);
            }
        } else if (CMSAlgorithm.DES_CBC.equals(encOid)) {
            if (!control.isUseInsecureAlg()) {
                LOG.warn("tid={}: encryption with DES algorithm {} is not permitted", tid, encOid);
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badAlg);
            }
        } else {
            LOG.warn("tid={}: encryption with algorithm {} is not permitted", tid, encOid);
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(FailInfo.badAlg);
        }

        if (rep.pkiStatus() == PkiStatus.FAILURE) {
            return rep;
        }

        MessageType messageType = req.messageType();

        switch (messageType) {
        case PKCSReq:
            CertificationRequest csr = CertificationRequest.getInstance(req.messageData());

            String challengePwd = getChallengePassword(csr.getCertificationRequestInfo());
            if (challengePwd == null || !control.secret().equals(challengePwd)) {
                LOG.warn("challengePassword is not trusted");
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badRequest);
            }

            Certificate cert;
            try {
                cert = caEmulator.generateCert(csr);
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
            IssuerAndSubject is = IssuerAndSubject.getInstance(req.messageData());
            cert = caEmulator.pollCert(is.issuer(), is.subject());
            if (cert != null) {
                rep.setMessageData(createSignedData(cert));
            } else {
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badCertId);
            }

            break;
        case GetCert:
            IssuerAndSerialNumber isn = IssuerAndSerialNumber.getInstance(req.messageData());
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
                csr = CertificationRequest.getInstance(req.messageData());
                try {
                    cert = caEmulator.generateCert(csr);
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
                csr = CertificationRequest.getInstance(req.messageData());
                try {
                    cert = caEmulator.generateCert(csr);
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
            isn = IssuerAndSerialNumber.getInstance(req.messageData());
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
    } // method servicePkiOperation0

    private ContentInfo createSignedData(final CertificateList crl) throws CaException {
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

    private ContentInfo createSignedData(final Certificate cert) throws CaException {
        CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();

        CMSSignedData cmsSigneddata;
        try {
            cmsSignedDataGen.addCertificate(new X509CertificateHolder(cert));
            if (control.sendCaCert()) {
                cmsSignedDataGen.addCertificate(new X509CertificateHolder(caEmulator.caCert()));
            }

            cmsSigneddata = cmsSignedDataGen.generate(new CMSAbsentContent());
        } catch (CMSException ex) {
            throw new CaException(ex);
        }

        return cmsSigneddata.toASN1Structure();
    }

    public PrivateKey signingKey() {
        return (raEmulator != null) ? raEmulator.raKey() : caEmulator.caKey();
    }

    public Certificate signingCert() {
        return (raEmulator != null) ? raEmulator.raCert() : caEmulator.caCert();
    }

    public CaCaps caCaps() {
        return caCaps;
    }

    public CaEmulator caEmulator() {
        return caEmulator;
    }

    public RaEmulator raEmulator() {
        return raEmulator;
    }

    public NextCaAndRa nextCaAndRa() {
        return nextCaAndRa;
    }

    private static String getChallengePassword(final CertificationRequestInfo csr) {
        ASN1Set attrs = csr.getAttributes();
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
