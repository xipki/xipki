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

package org.xipki.pki.ca.server.impl.scep;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.audit.api.AuditEvent;
import org.xipki.commons.audit.api.AuditEventData;
import org.xipki.commons.audit.api.AuditStatus;
import org.xipki.commons.common.InvalidConfException;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.security.api.KeyCertPair;
import org.xipki.commons.security.api.SignerException;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.api.OperationException;
import org.xipki.pki.ca.api.OperationException.ErrorCode;
import org.xipki.pki.ca.api.RequestType;
import org.xipki.pki.ca.api.publisher.X509CertificateInfo;
import org.xipki.pki.ca.server.impl.CaManagerImpl;
import org.xipki.pki.ca.server.impl.KnowCertResult;
import org.xipki.pki.ca.server.impl.X509Ca;
import org.xipki.pki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.pki.ca.server.mgmt.api.CaStatus;
import org.xipki.pki.ca.server.mgmt.api.ScepControl;
import org.xipki.pki.ca.server.mgmt.api.ScepEntry;
import org.xipki.pki.scep.crypto.HashAlgoType;
import org.xipki.pki.scep.exception.MessageDecodingException;
import org.xipki.pki.scep.exception.MessageEncodingException;
import org.xipki.pki.scep.message.CaCaps;
import org.xipki.pki.scep.message.DecodedPkiMessage;
import org.xipki.pki.scep.message.EnvelopedDataDecryptor;
import org.xipki.pki.scep.message.EnvelopedDataDecryptorInstance;
import org.xipki.pki.scep.message.IssuerAndSubject;
import org.xipki.pki.scep.message.PkiMessage;
import org.xipki.pki.scep.transaction.CaCapability;
import org.xipki.pki.scep.transaction.FailInfo;
import org.xipki.pki.scep.transaction.MessageType;
import org.xipki.pki.scep.transaction.Nonce;
import org.xipki.pki.scep.transaction.PkiStatus;
import org.xipki.pki.scep.transaction.TransactionId;

/**
 *
 * @author Lijun Liao
 * @since 2.0.0
 *
 */
public class Scep {

    private static final Logger LOG = LoggerFactory.getLogger(Scep.class);

    private static final long DFLT_MAX_SIGNINGTIME_BIAS = 5L * 60 * 1000; // 5 minutes

    private static final Set<ASN1ObjectIdentifier> AES_ENC_ALGOS = new HashSet<>();

    private final String caName;

    private final ScepEntry dbEntry;

    private final ScepControl control;

    private final CaManagerImpl caManager;

    private PrivateKey responderKey;

    private X509Certificate responderCert;

    private CaCertRespBytes caCertRespBytes;

    private X509CertificateHolder caCert;

    private CaCaps caCaps;

    private EnvelopedDataDecryptor envelopedDataDecryptor;

    private long maxSigningTimeBiasInMs = DFLT_MAX_SIGNINGTIME_BIAS;

    static {
        AES_ENC_ALGOS.add(CMSAlgorithm.AES128_CBC);
        AES_ENC_ALGOS.add(CMSAlgorithm.AES128_CCM);
        AES_ENC_ALGOS.add(CMSAlgorithm.AES128_GCM);
        AES_ENC_ALGOS.add(CMSAlgorithm.AES192_CBC);
        AES_ENC_ALGOS.add(CMSAlgorithm.AES192_CCM);
        AES_ENC_ALGOS.add(CMSAlgorithm.AES192_GCM);
        AES_ENC_ALGOS.add(CMSAlgorithm.AES256_CBC);
        AES_ENC_ALGOS.add(CMSAlgorithm.AES256_CCM);
        AES_ENC_ALGOS.add(CMSAlgorithm.AES256_GCM);
    }

    public Scep(
            final ScepEntry dbEntry,
            final CaManagerImpl caManager)
    throws CaMgmtException {
        ParamUtil.assertNotNull("caManager", caManager);
        ParamUtil.assertNotNull("dbEntry", dbEntry);

        this.caName = dbEntry.getCaName();
        this.dbEntry = dbEntry;
        this.caManager = caManager;
        try {
            this.control = new ScepControl(dbEntry.getControl());
        } catch (InvalidConfException e) {
            throw new CaMgmtException(e);
        }
        LOG.info("SCEP {}: caCert.included={}, signerCert.included={}",
                this.caName, this.control.isIncludeCaCert(), this.control.isIncludeSignerCert());
    }

    /**
     *
     * @param ms signing time bias in milliseconds. non-positive value deactivate the check
     *    of signing time.
     */
    public void setMaxSigningTimeBias(
            final long ms) {
        this.maxSigningTimeBiasInMs = ms;
    }

    public void refreshCa()
    throws CaMgmtException {
        String type = dbEntry.getResponderType();
        if (!"PKCS12".equalsIgnoreCase(type) && !"JKS".equalsIgnoreCase(type)) {
            throw new CaMgmtException("unsupported SCEP responder type '" + type + "'");
        }

        KeyCertPair privKeyAndCert;
        try {
            privKeyAndCert = caManager.getSecurityFactory().createPrivateKeyAndCert(
                    dbEntry.getResponderType(), dbEntry.getResponderConf(),
                    dbEntry.getCertificate());
        } catch (SignerException e) {
            throw new CaMgmtException(e);
        }

        this.responderKey = privKeyAndCert.getPrivateKey();
        this.responderCert = privKeyAndCert.getCertificate();

        if (!(responderCert.getPublicKey() instanceof RSAPublicKey)) {
            throw new IllegalArgumentException(
                    "The responder key is not RSA key (CA=" + caName + ")");
        }

        // CACaps
        CaCaps caps = new CaCaps();
        caps.addCapability(CaCapability.AES);
        caps.addCapability(CaCapability.DES3);
        caps.addCapability(CaCapability.POSTPKIOperation);
        caps.addCapability(CaCapability.Renewal);
        caps.addCapability(CaCapability.SHA1);
        caps.addCapability(CaCapability.SHA256);
        caps.addCapability(CaCapability.SHA512);
        this.caCaps = caps;

        X509Ca ca = caManager.getX509Ca(caName);
        try {
            this.caCert = new X509CertificateHolder(
                    ca.getCaInfo().getCertificate().getEncodedCert());
            this.caCertRespBytes = new CaCertRespBytes(
                    ca.getCaInfo().getCertificate().getCert(), responderCert);
        } catch (CertificateException e) {
            throw new CaMgmtException(e);
        } catch (CMSException e) {
            throw new CaMgmtException(e);
        } catch (IOException e) {
            throw new CaMgmtException(e);
        }

        EnvelopedDataDecryptorInstance di = new EnvelopedDataDecryptorInstance(responderCert,
                responderKey);
        this.envelopedDataDecryptor = new EnvelopedDataDecryptor(di);
    } // method refreshCA

    public String getCaName() {
        return caName;
    }

    public ScepEntry getDbEntry() {
        return dbEntry;
    }

    public CaCaps getCaCaps() {
        return caCaps;
    }

    public void setCaCaps(
            final CaCaps caCaps) {
        ParamUtil.assertNotNull("caCaps", caCaps);
        this.caCaps = caCaps;
    }

    public CaCertRespBytes getCaCertResp() {
        return caCertRespBytes;
    }

    public boolean supportsCertProfile(
            final String profileName)
    throws CaMgmtException {
        return caManager.getX509Ca(caName).supportsCertProfile(profileName);
    }

    public CaStatus getStatus()
    throws CaMgmtException {
        return caManager.getX509Ca(caName).getCaInfo().getStatus();
    }

    public ContentInfo servicePkiOperation(
            final CMSSignedData requestContent,
            final String certProfileName,
            final AuditEvent auditEvent)
    throws MessageDecodingException, OperationException {
        DecodedPkiMessage req = DecodedPkiMessage.decode(requestContent,
                envelopedDataDecryptor, null);

        PkiMessage rep = doServicePkiOperation(req, certProfileName, auditEvent);
        if (auditEvent != null) {
            audit(auditEvent, "pkiStatus", rep.getPkiStatus().toString());
            if (rep.getPkiStatus() == PkiStatus.FAILURE) {
                auditEvent.setStatus(AuditStatus.FAILED);
            }
            if (rep.getFailInfo() != null) {
                audit(auditEvent, "failInfo", rep.getFailInfo().toString());
            }
        }
        return encodeResponse(rep, req);
    } // method servicePkiOperation

    private PkiMessage doServicePkiOperation(
            final DecodedPkiMessage req,
            final String certProfileName,
            final AuditEvent auditEvent)
    throws MessageDecodingException, OperationException {
        String tid = req.getTransactionId().getId();
        // verify and decrypt the request
        if (auditEvent != null) {
            audit(auditEvent, "tid", tid);
            if (req.getFailureMessage() != null) {
                audit(auditEvent, "failureMessage", req.getFailureMessage());
            }
            Boolean b = req.isSignatureValid();
            if (b != null && !b.booleanValue()) {
                audit(auditEvent, "signature", "invalid");
            }
            b = req.isDecryptionSuccessful();
            if (b != null && !b.booleanValue()) {
                audit(auditEvent, "decryption", "failed");
            }
        }

        PkiMessage rep = new PkiMessage(req.getTransactionId(), MessageType.CertRep,
                Nonce.randomNonce());
        rep.setRecipientNonce(req.getSenderNonce());

        if (req.getFailureMessage() != null) {
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(FailInfo.badRequest);
        }

        Boolean b = req.isSignatureValid();
        if (b != null && !b.booleanValue()) {
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(FailInfo.badMessageCheck);
        }

        b = req.isDecryptionSuccessful();
        if (b != null && !b.booleanValue()) {
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
        } // end if

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
            }

            if (!supported) {
                LOG.warn("tid={}: unsupported digest algorithm {}", tid, oid);
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badAlg);
            }
        }

        // check the content encryption algorithm
        ASN1ObjectIdentifier encOid = req.getContentEncryptionAlgorithm();
        if (CMSAlgorithm.DES_EDE3_CBC.equals(encOid)) {
            if (!caCaps.containsCapability(CaCapability.DES3)) {
                LOG.warn("tid={}: encryption with DES3 algorithm is not permitted", tid, encOid);
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badAlg);
            }
        } else if (AES_ENC_ALGOS.contains(encOid)) {
            if (!caCaps.containsCapability(CaCapability.AES)) {
                LOG.warn("tid={}: encryption with AES algorithm {} is not permitted", tid, encOid);
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

        X509Ca ca;
        try {
            ca = caManager.getX509Ca(caName);
        } catch (CaMgmtException e) {
            final String message = tid + "=" + tid + ",could not get X509CA";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, e.getMessage());
        }

        X500Name caX500Name = ca.getCaInfo().getCertificate().getSubjectAsX500Name();

        try {
            SignedData signedData;

            MessageType mt = req.getMessageType();
            if (auditEvent != null) {
                audit(auditEvent, "messageType", mt.toString());
            }

            switch (mt) {
                case PKCSReq:
                case RenewalReq:
                case UpdateReq:
                    CertificationRequest p10Req = (CertificationRequest) req.getMessageData();
                    X500Name reqSubject = p10Req.getCertificationRequestInfo().getSubject();
                    String reqSubjectText = X509Util.getRfc4519Name(reqSubject);
                    audit(auditEvent, "req-subject", reqSubjectText);
                    LOG.info("tid={}, subject={}", tid, reqSubjectText);

                    if (!caManager.getSecurityFactory().verifyPopo(p10Req)) {
                        LOG.warn("tid={}, POPO verification failed", tid);
                        throw FailInfoException.BAD_MESSAGE_CHECK;
                    }

                    CertificationRequestInfo p10ReqInfo = p10Req.getCertificationRequestInfo();

                    Extensions extensions = X509Util.getExtensions(p10ReqInfo);

                    X509Certificate reqSignatureCert = req.getSignatureCert();

                    boolean selfSigned = reqSignatureCert.getSubjectX500Principal().equals(
                            reqSignatureCert.getIssuerX500Principal());

                    String cn = X509Util.getCommonName(p10ReqInfo.getSubject());
                    if (cn == null) {
                        throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
                                "tid=" + tid + ": no CommonName in requested subject");
                    }

                    String user = null;
                    boolean authenticatedByPwd = false;

                    String challengePwd = X509Util.getChallengePassword(p10ReqInfo);
                    if (challengePwd != null) {
                        String[] strs = challengePwd.split(":");
                        if (strs != null && strs.length == 2) {
                            user = strs[0];
                            audit(auditEvent, "user", user);
                            String password = strs[1];
                            authenticatedByPwd = ca.authenticateUser(user, password.getBytes());

                            if (!authenticatedByPwd) {
                                LOG.warn("tid={}: could not verify the challengePassword", tid);
                                throw FailInfoException.BAD_REQUEST;
                            }
                        } else {
                            LOG.warn("tid={}: ignore challengePassword since it does not has the"
                                    + " format <user>:<password>",
                                    tid);
                        }
                    } // end if

                    if (selfSigned) {
                        if (MessageType.PKCSReq != mt) {
                            LOG.warn("tid={}: self-signed certificate is not permitted for"
                                    + " messageType {}", tid, mt);
                            throw FailInfoException.BAD_REQUEST;
                        }
                        if (user == null) {
                            LOG.warn("tid={}: could not extract user and password from"
                                    + " challengePassword, which are required for self-signed"
                                    + " signature certificate",
                                tid);
                            throw FailInfoException.BAD_REQUEST;
                        }
                        checkCommonName(ca, user, cn);
                    } else {
                        if (user == null) {
                            // up to draft-nourse-scep-23 the client sends all messages to enroll
                            // certificate via MessageType PKCSReq
                            KnowCertResult knowCertRes = ca.knowsCertificate(reqSignatureCert);
                            if (!knowCertRes.isKnown()) {
                                LOG.warn("tid={}: signature certiciate is not trusted by the CA",
                                        tid);
                                throw FailInfoException.BAD_REQUEST;
                            }
                            user = knowCertRes.getUser();
                            audit(auditEvent,
                                    "user",
                                    (user == null)
                                        ? "null"
                                        : user);
                        } // end if

                        // only the same subject is permitted
                        String cnInSignatureCert = X509Util.getCommonName(
                                X500Name.getInstance(
                                        reqSignatureCert.getSubjectX500Principal().getEncoded()));
                        boolean b2 = cn.equals(cnInSignatureCert);
                        if (!b2) {
                            if (user != null) {
                                checkCommonName(ca, user, cn);
                            } else {
                                LOG.warn("tid={}: signature certificate is not trusted and {}",
                                        tid, "no challengePassword is contained in the request");
                                throw FailInfoException.BAD_REQUEST;
                            }
                        } // end if
                    } // end if

                    byte[] tidBytes = getTransactionIdBytes(tid);

                    X509CertificateInfo cert = ca.generateCertificate(
                            true,
                            null,
                            certProfileName,
                            user,
                            p10ReqInfo.getSubject(),
                            p10ReqInfo.getSubjectPublicKeyInfo(),
                            extensions,
                            RequestType.SCEP,
                            tidBytes);

                    if (auditEvent != null) {
                        audit(auditEvent, "subject", cert.getCert().getSubject());
                    }

                    signedData = buildSignedData(cert.getCert().getCert());
                    break;
                case CertPoll:
                    IssuerAndSubject is = (IssuerAndSubject) req.getMessageData();
                    if (auditEvent != null) {
                        audit(auditEvent, "isser", X509Util.getRfc4519Name(is.getIssuer()));
                        audit(auditEvent, "subject", X509Util.getRfc4519Name(is.getSubject()));
                    }

                    ensureIssuedByThisCa(caX500Name, is.getIssuer());
                    signedData = pollCert(ca, is.getSubject(), req.getTransactionId());
                    break;
                case GetCert:
                    IssuerAndSerialNumber isn = (IssuerAndSerialNumber) req.getMessageData();
                    BigInteger serial = isn.getSerialNumber().getPositiveValue();
                    if (auditEvent != null) {
                        audit(auditEvent, "isser", X509Util.getRfc4519Name(isn.getName()));
                        audit(auditEvent, "serialNumber", serial.toString());
                    }
                    ensureIssuedByThisCa(caX500Name, isn.getName());
                    signedData = getCert(ca, isn.getSerialNumber().getPositiveValue());
                    break;
                case GetCRL:
                    isn = (IssuerAndSerialNumber) req.getMessageData();
                    serial = isn.getSerialNumber().getPositiveValue();
                    if (auditEvent != null) {
                        audit(auditEvent, "isser", X509Util.getRfc4519Name(isn.getName()));
                        audit(auditEvent, "serialNumber", serial.toString());
                    }
                    ensureIssuedByThisCa(caX500Name, isn.getName());
                    signedData = getCrl(ca, serial);
                    break;
                default:
                    LOG.error("unknown SCEP messageType '{}'", req.getMessageType());
                    throw FailInfoException.BAD_REQUEST;
            } // end switch

            ContentInfo ci = new ContentInfo(CMSObjectIdentifiers.signedData, signedData);
            rep.setMessageData(ci);
            rep.setPkiStatus(PkiStatus.SUCCESS);
        } catch (FailInfoException e) {
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(e.getFailInfo());
        }

        return rep;
    } // method doServicePkiOperation

    private SignedData getCert(
            final X509Ca ca,
            final BigInteger serialNumber)
    throws FailInfoException, OperationException {
        X509Certificate cert;
        try {
            cert = ca.getCertificate(serialNumber);
        } catch (CertificateException e) {
            final String message = "could not get certificate (CA='" + caName
                    + "' and serialNumber='" + serialNumber + "')";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, e.getMessage());
        }
        if (cert == null) {
            throw FailInfoException.BAD_CERTID;
        }
        return buildSignedData(cert);
    } // method getCert

    private SignedData pollCert(
            final X509Ca ca,
            final X500Name subject,
            final TransactionId tid)
    throws FailInfoException, OperationException {
        byte[] tidBytes = getTransactionIdBytes(tid.getId());
        List<X509Certificate> certs = ca.getCertificate(subject, tidBytes);
        if (CollectionUtil.isEmpty(certs)) {
            certs = ca.getCertificate(subject, null);
        }

        if (CollectionUtil.isEmpty(certs)) {
            throw FailInfoException.BAD_CERTID;
        }

        if (certs.size() > 1) {
            LOG.warn(
                "given certId (subject: {}) and transactionId {} match at least two certificates",
                X509Util.getRfc4519Name(subject), tid.getId());
            throw FailInfoException.BAD_CERTID;
        }

        return buildSignedData(certs.get(0));
    } // method pollCert

    private SignedData buildSignedData(
            final X509Certificate cert)
    throws OperationException {
        CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();
        try {
            X509CertificateHolder certHolder = new X509CertificateHolder(cert.getEncoded());
            cmsSignedDataGen.addCertificate(certHolder);
            if (control.isIncludeCaCert()) {
                cmsSignedDataGen.addCertificate(caCert);
            }
            CMSSignedData signedData = cmsSignedDataGen.generate(new CMSAbsentContent());
            return (SignedData) signedData.toASN1Structure().getContent();
        } catch (CMSException | IOException | CertificateEncodingException e) {
            final String message = "error in buildSignedData";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, e.getMessage());
        }
    } // method buildSignedData

    private SignedData getCrl(
            final X509Ca ca,
            final BigInteger serialNumber)
    throws FailInfoException, OperationException {
        CertificateList crl = ca.getCurrentCrl();
        if (crl == null) {
            throw FailInfoException.BAD_REQUEST;
        }
        CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();
        cmsSignedDataGen.addCRL(new X509CRLHolder(crl));

        CMSSignedData signedData;
        try {
            signedData = cmsSignedDataGen.generate(new CMSAbsentContent());
        } catch (CMSException e) {
            final String message = "could not generate CMSSignedData";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, e.getMessage());
        }
        return (SignedData) signedData.toASN1Structure().getContent();
    } // method getCRL

    private ContentInfo encodeResponse(
            final PkiMessage response,
            final DecodedPkiMessage request)
    throws OperationException {
        String signatureAlgorithm = getSignatureAlgorithm(responderKey,
                request.getDigestAlgorithm());
        ContentInfo ci;
        try {
            X509Certificate[] cmsCertSet;
            if (control.isIncludeSignerCert()) {
                cmsCertSet = new X509Certificate[]{responderCert};
            } else {
                cmsCertSet = null;
            }

            ci = response.encode(responderKey,
                    signatureAlgorithm, responderCert, cmsCertSet,
                    request.getSignatureCert(), request.getContentEncryptionAlgorithm());
        } catch (MessageEncodingException e) {
            final String message = "could not encode response";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, e.getMessage());
        }
        return ci;
    } // method encodeResponse

    private static void checkCommonName(
            final X509Ca ca,
            final String user,
            final String cn)
    throws OperationException {
        String cnRegex = ca.getCnRegexForUser(user);
        if (StringUtil.isNotBlank(cnRegex)) {
            Pattern pattern = Pattern.compile(cnRegex);
            if (!pattern.matcher(cn).matches()) {
                throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
                        "commonName '" + cn + "' is not permitted");
            }
        }
    }

    private static String getSignatureAlgorithm(
            final PrivateKey key,
            final ASN1ObjectIdentifier digestOid) {
        HashAlgoType hashAlgo = HashAlgoType.getHashAlgoType(digestOid.getId());
        if (hashAlgo == null) {
            hashAlgo = HashAlgoType.SHA256;
        }
        String algorithm = key.getAlgorithm();
        if ("RSA".equalsIgnoreCase(algorithm)) {
            return hashAlgo.getName() + "withRSA";
        } else {
            throw new UnsupportedOperationException(
                    "getSignatureAlgorithm() for non-RSA is not supported yet.");
        }
    } // method getSignatureAlgorithm

    private static void ensureIssuedByThisCa(
            final X500Name thisCAX500Name,
            final X500Name caX500Name)
    throws FailInfoException {
        if (!thisCAX500Name.equals(caX500Name)) {
            throw FailInfoException.BAD_CERTID;
        }
    }

    static CMSSignedData createDegeneratedSigendData(
            final X509Certificate... certs)
    throws CMSException, CertificateException {
        CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();
        try {
            for (X509Certificate cert : certs) {
                cmsSignedDataGen.addCertificate(new X509CertificateHolder(cert.getEncoded()));
            }
            return cmsSignedDataGen.generate(new CMSAbsentContent());
        } catch (IOException e) {
            throw new CMSException("could not build CMS SignedDta");
        }
    }

    private static byte[] getTransactionIdBytes(
            final String tid) {
        final int n = tid.length();
        if (n % 2 != 0) { // neither hex nor base64 encoded
            return tid.getBytes();
        }

        try {
            return Hex.decode(tid);
        } catch (Exception e) {
            if (n % 4 == 0) {
                try {
                    return Base64.decode(tid);
                } catch (Exception e2) {
                }
            }
        }
        return tid.getBytes();
    } // method getTransactionIdBytes

    private static void audit(
            final AuditEvent audit,
            final String name,
            final String value) {
        if (audit == null) {
            return;
        }

        audit.addEventData(
            new AuditEventData(name,
                (value == null)
                    ? "null"
                    : value));
    } // method audit

}
