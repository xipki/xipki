/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

package org.xipki.ca.server.impl.scep;

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
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditStatus;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.RequestType;
import org.xipki.ca.api.publisher.X509CertificateInfo;
import org.xipki.ca.server.impl.CAManagerImpl;
import org.xipki.ca.server.impl.KnowCertResult;
import org.xipki.ca.server.impl.X509CA;
import org.xipki.ca.server.mgmt.api.CAMgmtException;
import org.xipki.ca.server.mgmt.api.CAStatus;
import org.xipki.ca.server.mgmt.api.ScepControl;
import org.xipki.ca.server.mgmt.api.ScepEntry;
import org.xipki.common.ConfigurationException;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.common.util.X509Util;
import org.xipki.scep4j.crypto.HashAlgoType;
import org.xipki.scep4j.exception.MessageDecodingException;
import org.xipki.scep4j.exception.MessageEncodingException;
import org.xipki.scep4j.message.CACaps;
import org.xipki.scep4j.message.DecodedPkiMessage;
import org.xipki.scep4j.message.EnvelopedDataDecryptor;
import org.xipki.scep4j.message.EnvelopedDataDecryptorInstance;
import org.xipki.scep4j.message.IssuerAndSubject;
import org.xipki.scep4j.message.PkiMessage;
import org.xipki.scep4j.transaction.CACapability;
import org.xipki.scep4j.transaction.FailInfo;
import org.xipki.scep4j.transaction.MessageType;
import org.xipki.scep4j.transaction.Nonce;
import org.xipki.scep4j.transaction.PkiStatus;
import org.xipki.scep4j.transaction.TransactionId;
import org.xipki.security.api.KeyCertPair;
import org.xipki.security.api.SignerException;

/**
 *
 * @author Lijun Liao
 *
 */
public class Scep
{
    private static final Logger LOG = LoggerFactory.getLogger(Scep.class);

    private static final long DFLT_MAX_SIGNINGTIME_BIAS = 5L * 60 * 1000; // 5 minutes

    private final static Set<ASN1ObjectIdentifier> aesEncAlgs = new HashSet<>();

    private final String caName;
    private final ScepEntry dbEntry;
    private final ScepControl control;
    private final CAManagerImpl caManager;

    private PrivateKey responderKey;
    private X509Certificate responderCert;
    private CACertRespBytes cACertRespBytes;
    private X509CertificateHolder cACert;

    private CACaps caCaps;
    private EnvelopedDataDecryptor envelopedDataDecryptor;
    private long maxSigningTimeBiasInMs = DFLT_MAX_SIGNINGTIME_BIAS;

    static
    {
        aesEncAlgs.add(CMSAlgorithm.AES128_CBC);
        aesEncAlgs.add(CMSAlgorithm.AES128_CCM);
        aesEncAlgs.add(CMSAlgorithm.AES128_GCM);
        aesEncAlgs.add(CMSAlgorithm.AES192_CBC);
        aesEncAlgs.add(CMSAlgorithm.AES192_CCM);
        aesEncAlgs.add(CMSAlgorithm.AES192_GCM);
        aesEncAlgs.add(CMSAlgorithm.AES256_CBC);
        aesEncAlgs.add(CMSAlgorithm.AES256_CCM);
        aesEncAlgs.add(CMSAlgorithm.AES256_GCM);
    }

    public Scep(
            final ScepEntry dbEntry,
            final CAManagerImpl caManager)
    throws CAMgmtException
    {
        ParamUtil.assertNotNull("caManager", caManager);
        ParamUtil.assertNotNull("dbEntry", dbEntry);

        this.caName = dbEntry.getCaName();
        this.dbEntry = dbEntry;
        this.caManager = caManager;
        try
        {
            this.control = new ScepControl(dbEntry.getControl());
        } catch (ConfigurationException e)
        {
            throw new CAMgmtException(e);
        }
        LOG.info("SCEP {}: caCert.included={}, signerCert.included={}",
                this.caName, this.control.isIncludeCACert(), this.control.isIncludeSignerCert());
    }

    /**
     *
     * @param ms signing time bias in milliseconds. non-positive value deactivate the check of signing time.
     */
    public void setMaxSigningTimeBias(
            final long ms)
    {
        this.maxSigningTimeBiasInMs = ms;
    }

    public void refreshCA()
    throws CAMgmtException
    {
        String type = dbEntry.getResponderType();
        if("PKCS12".equalsIgnoreCase(type) == false && "JKS".equalsIgnoreCase(type) == false)
        {
            throw new CAMgmtException("unsupported SCEP responder type '" + type + "'");
        }

        KeyCertPair privKeyAndCert;
        try
        {
            privKeyAndCert = caManager.getSecurityFactory().createPrivateKeyAndCert(
                    dbEntry.getResponderType(), dbEntry.getResponderConf(), dbEntry.getCertificate());
        } catch (SignerException e)
        {
            throw new CAMgmtException(e);
        }

        this.responderKey = privKeyAndCert.getPrivateKey();
        this.responderCert = privKeyAndCert.getCertificate();

        if(responderCert.getPublicKey() instanceof RSAPublicKey == false)
        {
            throw new IllegalArgumentException("The responder key is not RSA key (CA=" + caName + ")");
        }

        // CACaps
        CACaps caps = new CACaps();
        caps.addCapability(CACapability.AES);
        caps.addCapability(CACapability.DES3);
        caps.addCapability(CACapability.POSTPKIOperation);
        caps.addCapability(CACapability.Renewal);
        caps.addCapability(CACapability.SHA1);
        caps.addCapability(CACapability.SHA256);
        caps.addCapability(CACapability.SHA512);
        this.caCaps = caps;

        X509CA ca = caManager.getX509CA(caName);
        try
        {
            this.cACert = new X509CertificateHolder(ca.getCAInfo().getCertificate().getEncodedCert());
            this.cACertRespBytes = new CACertRespBytes(
                    ca.getCAInfo().getCertificate().getCert(), responderCert);
        } catch (CertificateException e)
        {
            throw new CAMgmtException(e);
        } catch (CMSException e)
        {
            throw new CAMgmtException(e);
        } catch (IOException e)
        {
            throw new CAMgmtException(e);
        }

        EnvelopedDataDecryptorInstance di = new EnvelopedDataDecryptorInstance(responderCert, responderKey);
        this.envelopedDataDecryptor = new EnvelopedDataDecryptor(di);
    }

    public String getCaName()
    {
        return caName;
    }

    public ScepEntry getDbEntry()
    {
        return dbEntry;
    }

    public CACaps getCaCaps()
    {
        return caCaps;
    }

    public void setCaCaps(
            final CACaps caCaps)
    {
        ParamUtil.assertNotNull("caCaps", caCaps);
        this.caCaps = caCaps;
    }

    public CACertRespBytes getCACertResp()
    {
        return cACertRespBytes;
    }

    public boolean supportsCertProfile(
            final String profileName)
    throws CAMgmtException
    {
        return caManager.getX509CA(caName).supportsCertProfile(profileName);
    }

    public CAStatus getStatus()
    throws CAMgmtException
    {
        return caManager.getX509CA(caName).getCAInfo().getStatus();
    }

    public ContentInfo servicePkiOperation(
            final CMSSignedData requestContent,
            final String certProfileName,
            final AuditEvent auditEvent)
    throws MessageDecodingException, OperationException
    {
        DecodedPkiMessage req = DecodedPkiMessage.decode(requestContent, envelopedDataDecryptor, null);

        PkiMessage rep = doServicePkiOperation(req, certProfileName, auditEvent);
        if(auditEvent != null)
        {
            audit(auditEvent, "pkiStatus", rep.getPkiStatus().toString());
            if(rep.getPkiStatus() == PkiStatus.FAILURE)
            {
                auditEvent.setStatus(AuditStatus.FAILED);
            }
            if(rep.getFailInfo() != null)
            {
                audit(auditEvent, "failInfo", rep.getFailInfo().toString());
            }
        }
        return encodeResponse(rep, req);
    }

    private PkiMessage doServicePkiOperation(
            final DecodedPkiMessage req,
            final String certProfileName,
            final AuditEvent auditEvent)
    throws MessageDecodingException, OperationException
    {
        String tid = req.getTransactionId().getId();
        // verify and decrypt the request
        if(auditEvent != null)
        {
            audit(auditEvent, "tid", tid);
            if(req.getFailureMessage() != null)
            {
                audit(auditEvent, "failureMessage", req.getFailureMessage());
            }
            Boolean b = req.isSignatureValid();
            if(b != null && b.booleanValue() == false)
            {
                audit(auditEvent, "signature", "invalid");
            }
            b = req.isDecryptionSuccessful();
            if(b != null && b.booleanValue() == false)
            {
                audit(auditEvent, "decryption", "failed");
            }
        }

        PkiMessage rep = new PkiMessage(req.getTransactionId(), MessageType.CertRep, Nonce.randomNonce());
        rep.setRecipientNonce(req.getSenderNonce());

        if(req.getFailureMessage() != null)
        {
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(FailInfo.badRequest);
        }

        Boolean b = req.isSignatureValid();
        if(b != null && b.booleanValue() == false)
        {
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(FailInfo.badMessageCheck);
        }

        b = req.isDecryptionSuccessful();
        if(b != null && b.booleanValue() == false)
        {
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(FailInfo.badRequest);
        }

        Date signingTime = req.getSigningTime();
        if(maxSigningTimeBiasInMs > 0)
        {
            boolean isTimeBad = false;
            if(signingTime == null)
            {
                isTimeBad = true;
            }
            else
            {
                long now = System.currentTimeMillis();
                long diff = now - signingTime.getTime();
                if(diff < 0)
                {
                    diff = -1 * diff;
                }
                isTimeBad = diff > maxSigningTimeBiasInMs;
            }

            if(isTimeBad)
            {
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badTime);
            }
        }

        // check the digest algorithm
        String oid = req.getDigestAlgorithm().getId();
        HashAlgoType hashAlgoType = HashAlgoType.getHashAlgoType(oid);
        if(hashAlgoType == null)
        {
            LOG.warn("tid={}: unknown digest algorithm {}", tid, oid);
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(FailInfo.badAlg);
        } else
        {
            boolean supported = false;
            if(hashAlgoType == HashAlgoType.SHA1)
            {
                if(caCaps.containsCapability(CACapability.SHA1))
                {
                    supported = true;
                }
            }
            else if(hashAlgoType == HashAlgoType.SHA256)
            {
                if(caCaps.containsCapability(CACapability.SHA256))
                {
                    supported = true;
                }
            }
            else if(hashAlgoType == HashAlgoType.SHA512)
            {
                if(caCaps.containsCapability(CACapability.SHA512))
                {
                    supported = true;
                }
            }

            if(supported == false)
            {
                LOG.warn("tid={}: unsupported digest algorithm {}", tid, oid);
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badAlg);
            }
        }

        // check the content encryption algorithm
        ASN1ObjectIdentifier encOid = req.getContentEncryptionAlgorithm();
        if(CMSAlgorithm.DES_EDE3_CBC.equals(encOid))
        {
            if(caCaps.containsCapability(CACapability.DES3) == false)
            {
                LOG.warn("tid={}: encryption with DES3 algorithm is not permitted", tid, encOid);
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badAlg);
            }
        } else if(aesEncAlgs.contains(encOid))
        {
            if(caCaps.containsCapability(CACapability.AES) == false)
            {
                LOG.warn("tid={}: encryption with AES algorithm {} is not permitted", tid, encOid);
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badAlg);
            }
        } else
        {
            LOG.warn("tid={}: encryption with algorithm {} is not permitted", tid, encOid);
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(FailInfo.badAlg);
        }

        if(rep.getPkiStatus() == PkiStatus.FAILURE)
        {
            return rep;
        }

        X509CA ca;
        try
        {
            ca = caManager.getX509CA(caName);
        } catch (CAMgmtException e)
        {
            final String message = tid + "=" + tid + ",could not get X509CA";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, e.getMessage());
        }

        X500Name caX500Name = ca.getCAInfo().getCertificate().getSubjectAsX500Name();

        try
        {
            SignedData signedData;

            MessageType mt = req.getMessageType();
            if(auditEvent != null)
            {
                audit(auditEvent, "messageType", mt.toString());
            }

            switch(mt)
            {
                case PKCSReq:
                case RenewalReq:
                case UpdateReq:
                {
                    CertificationRequest p10Req = (CertificationRequest) req.getMessageData();
                    X500Name reqSubject = p10Req.getCertificationRequestInfo().getSubject();
                    String reqSubjectText = X509Util.getRFC4519Name(reqSubject);
                    audit(auditEvent, "req-subject", reqSubjectText);
                    LOG.info("tid={}, subject={}", tid, reqSubjectText);

                    if(caManager.getSecurityFactory().verifyPOPO(p10Req) == false)
                    {
                        LOG.warn("tid={}, POPO verification failed", tid);
                        throw FailInfoException.badMessageCheck;
                    }

                    CertificationRequestInfo p10ReqInfo = p10Req.getCertificationRequestInfo();

                    Extensions extensions = X509Util.getExtensions(p10ReqInfo);

                    X509Certificate reqSignatureCert = req.getSignatureCert();

                    boolean selfSigned = reqSignatureCert.getSubjectX500Principal().equals(
                            reqSignatureCert.getIssuerX500Principal());

                    String cn = X509Util.getCommonName(p10ReqInfo.getSubject());
                    if(cn == null)
                    {
                        throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
                                "tid=" + tid + ": no CommonName in requested subject");
                    }

                    String user = null;
                    boolean authenticatedByPwd = false;

                    String challengePwd = X509Util.getChallengePassword(p10ReqInfo);
                    if(challengePwd != null)
                    {
                        String[] strs = challengePwd.split(":");
                        if(strs != null && strs.length == 2)
                        {
                            user = strs[0];
                            audit(auditEvent, "user", user);
                            String password = strs[1];
                            authenticatedByPwd = ca.authenticateUser(user, password.getBytes());

                            if(authenticatedByPwd == false)
                            {
                                LOG.warn("tid={}: could not verify the challengePassword", tid);
                                throw FailInfoException.badRequest;
                            }
                        } else
                        {
                            LOG.warn("tid={}: ignore challengePassword since it does not has the format <user>:<password>",
                                    tid);
                        }
                    }

                    if(selfSigned)
                    {
                        if(MessageType.PKCSReq != mt)
                        {
                            LOG.warn("tid={}: self-signed certificate is not permitted for messageType {}", tid, mt);
                            throw FailInfoException.badRequest;
                        }
                        if(user == null)
                        {
                            LOG.warn("tid={}: could not extract user and password from challengePassword, {}",
                                    tid, "which are required for self-signed signature certificate");
                            throw FailInfoException.badRequest;
                        }
                        checkCN(ca, user, cn);
                    } else
                    {
                        if(user == null)
                        {
                            // up to draft-nourse-scep-23 the client sends all messages to enroll certificate
                            // via MessageType PKCSReq
                            KnowCertResult knowCertRes = ca.knowsCertificate(reqSignatureCert);
                            if(knowCertRes.isKnown() == false)
                            {
                                LOG.warn("tid={}: signature certiciate is not trusted by the CA", tid);
                                throw FailInfoException.badRequest;
                            }
                            user = knowCertRes.getUser();
                            audit(auditEvent, "user", user == null ? "null" : user);
                        }

                        // only the same subject is permitted
                        String cnInSignatureCert = X509Util.getCommonName(
                                X500Name.getInstance(reqSignatureCert.getSubjectX500Principal().getEncoded()));
                        boolean b2 = cn.equals(cnInSignatureCert);
                        if(b2 == false)
                        {
                            if(user != null)
                            {
                                checkCN(ca, user, cn);
                            }
                            else
                            {
                                LOG.warn("tid={}: signature certificate is not trusted and {}",
                                        tid, "no challengePassword is contained in the request");
                                throw FailInfoException.badRequest;
                            }
                        }
                    }

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

                    if(auditEvent != null)
                    {
                        audit(auditEvent, "subject", cert.getCert().getSubject());
                    }

                    signedData = buildSignedData(cert.getCert().getCert());
                    break;
                }
                case CertPoll:
                {
                    IssuerAndSubject is = (IssuerAndSubject) req.getMessageData();
                    if(auditEvent != null)
                    {
                        audit(auditEvent, "isser", X509Util.getRFC4519Name(is.getIssuer()));
                        audit(auditEvent, "subject", X509Util.getRFC4519Name(is.getSubject()));
                    }

                    ensureIssuedByThisCA(caX500Name, is.getIssuer());
                    signedData = pollCert(ca, is.getSubject(), req.getTransactionId());
                    break;
                }
                case GetCert:
                {
                    IssuerAndSerialNumber isn = (IssuerAndSerialNumber) req.getMessageData();
                    BigInteger serial = isn.getSerialNumber().getPositiveValue();
                    if(auditEvent != null)
                    {
                        audit(auditEvent, "isser", X509Util.getRFC4519Name(isn.getName()));
                        audit(auditEvent, "serialNumber", serial.toString());
                    }
                    ensureIssuedByThisCA(caX500Name, isn.getName());
                    signedData = getCert(ca, isn.getSerialNumber().getPositiveValue());
                    break;
                }
                case GetCRL:
                {
                    IssuerAndSerialNumber isn = (IssuerAndSerialNumber) req.getMessageData();
                    BigInteger serial = isn.getSerialNumber().getPositiveValue();
                    if(auditEvent != null)
                    {
                        audit(auditEvent, "isser", X509Util.getRFC4519Name(isn.getName()));
                        audit(auditEvent, "serialNumber", serial.toString());
                    }
                    ensureIssuedByThisCA(caX500Name, isn.getName());
                    signedData = getCRL(ca, serial);
                    break;
                }
                default:
                {
                    LOG.error("unknown SCEP messageType '{}'", req.getMessageType());
                    throw FailInfoException.badRequest;
                }
            } // end switch

            ContentInfo ci = new ContentInfo(CMSObjectIdentifiers.signedData, signedData);
            rep.setMessageData(ci);
            rep.setPkiStatus(PkiStatus.SUCCESS);
        }catch(FailInfoException e)
        {
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(e.getFailInfo());
        }

        return rep;
    }

    private SignedData getCert(
            final X509CA ca,
            final BigInteger serialNumber)
    throws FailInfoException, OperationException
    {
        X509Certificate cert;
        try
        {
            cert = ca.getCertificate(serialNumber);
        } catch (CertificateException e)
        {
            final String message = "could not get certificate (CA='" + caName + "' and serialNumber='" + serialNumber + "')";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, e.getMessage());
        }
        if(cert == null)
        {
            throw FailInfoException.badCertId;
        }
        return buildSignedData(cert);
    }

    private SignedData pollCert(
            final X509CA ca,
            final X500Name subject,
            final TransactionId tid)
    throws FailInfoException, OperationException
    {
        byte[] tidBytes = getTransactionIdBytes(tid.getId());
        List<X509Certificate> certs = ca.getCertificate(subject, tidBytes);
        if(CollectionUtil.isEmpty(certs))
        {
            certs = ca.getCertificate(subject, null);
        }

        if(CollectionUtil.isEmpty(certs))
        {
            throw FailInfoException.badCertId;
        }

        if(certs.size() > 1)
        {
            LOG.warn("given certId (subject: {}) and transactionId {} match at least two certificates",
                    X509Util.getRFC4519Name(subject), tid.getId());
            throw FailInfoException.badCertId;
        }

        return buildSignedData(certs.get(0));
    }

    private SignedData buildSignedData(
            final X509Certificate cert)
    throws OperationException
    {
        CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();
        try
        {
            X509CertificateHolder certHolder = new X509CertificateHolder(cert.getEncoded());
            cmsSignedDataGen.addCertificate(certHolder);
            if(control.isIncludeCACert())
            {
                cmsSignedDataGen.addCertificate(cACert);
            }
            CMSSignedData signedData = cmsSignedDataGen.generate(new CMSAbsentContent());
            return (SignedData) signedData.toASN1Structure().getContent();
        } catch (CMSException | IOException | CertificateEncodingException e)
        {
            final String message = "error in buildSignedData";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, e.getMessage());
        }
    }

    private SignedData getCRL(
            final X509CA ca,
            final BigInteger serialNumber)
    throws FailInfoException, OperationException
    {
        CertificateList crl = ca.getCurrentCRL();
        if(crl == null)
        {
            throw FailInfoException.badRequest;
        }
        CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();
        cmsSignedDataGen.addCRL(new X509CRLHolder(crl));

        CMSSignedData signedData;
        try
        {
            signedData = cmsSignedDataGen.generate(new CMSAbsentContent());
        }catch(CMSException e)
        {
            final String message = "could not generate CMSSignedData";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, e.getMessage());
        }
        return (SignedData) signedData.toASN1Structure().getContent();
    }

    private ContentInfo encodeResponse(
            final PkiMessage response,
            final DecodedPkiMessage request)
    throws OperationException
    {
        String signatureAlgorithm = getSignatureAlgorithm(responderKey, request.getDigestAlgorithm());
        ContentInfo ci;
        try
        {
            X509Certificate[] cmsCertSet;
            if(control.isIncludeSignerCert())
            {
                cmsCertSet = new X509Certificate[]{responderCert};
            } else
            {
                cmsCertSet = null;
            }

            ci = response.encode(responderKey,
                    signatureAlgorithm, responderCert, cmsCertSet,
                    request.getSignatureCert(), request.getContentEncryptionAlgorithm());
        } catch (MessageEncodingException e)
        {
            final String message = "could not encode response";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, e.getMessage());
        }
        return ci;

    }

    private static void checkCN(
            final X509CA ca,
            final String user,
            final String cn)
    throws OperationException
    {
        String cnRegex = ca.getCNRegexForUser(user);
        if(StringUtil.isNotBlank(cnRegex))
        {
            Pattern pattern = Pattern.compile(cnRegex);
            if(pattern.matcher(cn).matches() == false)
            {
                throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
                        "commonName '" + cn + "' is not permitted");
            }
        }
    }

    private static String getSignatureAlgorithm(
            final PrivateKey key,
            final ASN1ObjectIdentifier digestOid)
    {
        HashAlgoType hashAlgo = HashAlgoType.getHashAlgoType(digestOid.getId());
        if(hashAlgo == null)
        {
            hashAlgo = HashAlgoType.SHA256;
        }
        String algorithm = key.getAlgorithm();
        if("RSA".equalsIgnoreCase(algorithm))
        {
            return hashAlgo.getName() + "withRSA";
        } else
        {
            throw new UnsupportedOperationException("getSignatureAlgorithm() for non-RSA is not supported yet.");
        }
    }

    private static void ensureIssuedByThisCA(
            final X500Name thisCAX500Name,
            final X500Name caX500Name)
    throws FailInfoException
    {
        if(thisCAX500Name.equals(caX500Name) == false)
        {
            throw FailInfoException.badCertId;
        }
    }

    static CMSSignedData createDegeneratedSigendData(
            final X509Certificate... certs)
    throws CMSException, CertificateException
    {
        CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();
        try
        {
            for(X509Certificate cert : certs)
            {
                cmsSignedDataGen.addCertificate(new X509CertificateHolder(cert.getEncoded()));
            }
            return cmsSignedDataGen.generate(new CMSAbsentContent());
        } catch (IOException e)
        {
            throw new CMSException("could not build CMS SignedDta");
        }
    }

    private static byte[] getTransactionIdBytes(
            final String tid)
    {
        final int n = tid.length();
        if(n % 2 != 0)
        {   // neither hex nor base64 encoded
            return tid.getBytes();
        }

        try
        {
            return Hex.decode(tid);
        }catch(Exception e)
        {
            if(n % 4 == 0)
            {
                try
                {
                    return Base64.decode(tid);
                }catch(Exception e2)
                {
                }
            }
        }
        return tid.getBytes();
    }

    private static void audit(
            final AuditEvent audit,
            final String name,
            final String value)
    {
        if(audit != null)
        {
            audit.addEventData(new AuditEventData(name, value == null ? "null" : value));
        }
    }

}
