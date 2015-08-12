/*
 * Copyright (c) 2015 Lijun Liao
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

package org.xipki.scep4j.serveremulator;

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
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditStatus;
import org.xipki.scep4j.crypto.HashAlgoType;
import org.xipki.scep4j.exception.MessageDecodingException;
import org.xipki.scep4j.message.CACaps;
import org.xipki.scep4j.message.DecodedPkiMessage;
import org.xipki.scep4j.message.EnvelopedDataDecryptor;
import org.xipki.scep4j.message.EnvelopedDataDecryptorInstance;
import org.xipki.scep4j.message.IssuerAndSubject;
import org.xipki.scep4j.message.NextCAMessage;
import org.xipki.scep4j.message.PkiMessage;
import org.xipki.scep4j.transaction.CACapability;
import org.xipki.scep4j.transaction.FailInfo;
import org.xipki.scep4j.transaction.MessageType;
import org.xipki.scep4j.transaction.Nonce;
import org.xipki.scep4j.transaction.PkiStatus;
import org.xipki.scep4j.transaction.TransactionId;
import org.xipki.scep4j.util.ParamUtil;
import org.xipki.scep4j.util.ScepUtil;

/**
 * @author Lijun Liao
 */

public class ScepResponder
{
    private static final Logger LOG = LoggerFactory.getLogger(ScepResponder.class);

    private final CACaps cACaps;
    private final CAEmulator cAEmulator;
    private final RAEmulator rAEmulator;
    private final NextCAandRA nextCAandRA;
    private final ScepControl control;
    private static final long DFLT_MAX_SIGNINGTIME_BIAS = 5L * 60 * 1000; // 5 minutes

    private final static Set<ASN1ObjectIdentifier> aesEncAlgs = new HashSet<ASN1ObjectIdentifier>();
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

    public ScepResponder(
            final CACaps cACaps,
            final CAEmulator cAEmulator,
            final RAEmulator rAEmulator,
            final NextCAandRA nextCAandRA,
            final ScepControl control)
    throws Exception
    {
        ParamUtil.assertNotNull("cACaps", cACaps);
        ParamUtil.assertNotNull("cAEmulator", cAEmulator);
        ParamUtil.assertNotNull("control", control);

        this.cAEmulator = cAEmulator;
        this.rAEmulator = rAEmulator;
        this.nextCAandRA = nextCAandRA;
        this.control = control;
        CACaps caps = cACaps;
        if(nextCAandRA == null)
        {
            caps.removeCapability(CACapability.GetNextCACert);
        } else
        {
            caps.addCapability(CACapability.GetNextCACert);
        }
        this.cACaps = caps;
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

    public ContentInfo servicePkiOperation(
            final CMSSignedData requestContent,
            final AuditEvent auditEvent)
    throws MessageDecodingException, CAException
    {
        PrivateKey recipientKey = rAEmulator != null ? rAEmulator.getRAKey() : cAEmulator.getCAKey();
        Certificate recipientCert = rAEmulator != null ? rAEmulator.getRACert() : cAEmulator.getCACert();
        X509CertificateObject recipientX509Obj;
        try
        {
            recipientX509Obj = new X509CertificateObject(recipientCert);
        } catch (CertificateParsingException e)
        {
            throw new MessageDecodingException(
                    "error while parsing recipintCert " + recipientCert.getTBSCertificate().getSubject());
        }

        EnvelopedDataDecryptorInstance decInstance = new EnvelopedDataDecryptorInstance(recipientX509Obj, recipientKey);
        EnvelopedDataDecryptor recipient = new EnvelopedDataDecryptor(decInstance);

        DecodedPkiMessage req = DecodedPkiMessage.decode(requestContent, recipient, null);

        PkiMessage rep = doServicePkiOperation(req, auditEvent);
        if(auditEvent != null)
        {
            AuditEventData eventData = new AuditEventData("pkiStatus", rep.getPkiStatus().toString());
            auditEvent.addEventData(eventData);
            if(rep.getPkiStatus() == PkiStatus.FAILURE)
            {
                auditEvent.setStatus(AuditStatus.FAILED);
            }
            if(rep.getFailInfo() != null)
            {
                eventData = new AuditEventData("failInfo", rep.getFailInfo().toString());
                auditEvent.addEventData(eventData);
            }
        }

        String signatureAlgorithm = ScepUtil.getSignatureAlgorithm(getSigningKey(),
                HashAlgoType.getHashAlgoType(req.getDigestAlgorithm().getId()));

        try
        {
            X509Certificate jceSignerCert = new X509CertificateObject(getSigningCert());

            return rep.encode(
                    getSigningKey(),
                    signatureAlgorithm,
                    jceSignerCert,
                    control.isSendSignerCert() ? new X509Certificate[]{jceSignerCert} : null,
                    req.getSignatureCert(),
                    req.getContentEncryptionAlgorithm());
        } catch (Exception e)
        {
            throw new CAException(e);
        }
    }

    public ContentInfo encode(
            final NextCAMessage nextCAMsg)
    throws CAException
    {
        try
        {
            X509Certificate jceSignerCert = new X509CertificateObject(getSigningCert());

            return nextCAMsg.encode(
                    getSigningKey(),
                    jceSignerCert,
                    control.isSendSignerCert() ? new X509Certificate[]{jceSignerCert} : null);
        } catch (Exception e)
        {
            throw new CAException(e);
        }
    }

    private PkiMessage doServicePkiOperation(
            final DecodedPkiMessage req,
            final AuditEvent auditEvent)
    throws MessageDecodingException, CAException
    {

        TransactionId tid = req.getTransactionId();
        PkiMessage rep = new PkiMessage(tid, MessageType.CertRep, Nonce.randomNonce());
        rep.setPkiStatus(PkiStatus.SUCCESS);

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
                if(cACaps.containsCapability(CACapability.SHA1))
                {
                    supported = true;
                }
            }
            else if(hashAlgoType == HashAlgoType.SHA256)
            {
                if(cACaps.containsCapability(CACapability.SHA256))
                {
                    supported = true;
                }
            }
            else if(hashAlgoType == HashAlgoType.SHA512)
            {
                if(cACaps.containsCapability(CACapability.SHA512))
                {
                    supported = true;
                }
            }
            else if(hashAlgoType == HashAlgoType.MD5)
            {
                if(control.isUseInsecureAlg())
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
            if(cACaps.containsCapability(CACapability.DES3) == false)
            {
                LOG.warn("tid={}: encryption with DES3 algorithm is not permitted", tid, encOid);
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badAlg);
            }
        } else if(aesEncAlgs.contains(encOid))
        {
            if(cACaps.containsCapability(CACapability.AES) == false)
            {
                LOG.warn("tid={}: encryption with AES algorithm {} is not permitted", tid, encOid);
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badAlg);
            }
        } else if(CMSAlgorithm.DES_CBC.equals(encOid))
        {
            if(control.isUseInsecureAlg() == false)
            {
                LOG.warn("tid={}: encryption with DES algorithm {} is not permitted", tid, encOid);
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

        MessageType messageType = req.getMessageType();

        switch(messageType)
        {
        case PKCSReq:
        {
            CertificationRequest p10ReqInfo = (CertificationRequest) req.getMessageData();

            String challengePwd = getChallengePassword(p10ReqInfo.getCertificationRequestInfo());
            if(challengePwd == null || control.getSecret().equals(challengePwd) == false)
            {
                LOG.warn("challengePassword is not trusted");
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badRequest);
            }

            Certificate cert;
            try
            {
                cert = cAEmulator.generateCert(p10ReqInfo);
            } catch (Exception e)
            {
                throw new CAException("system failure: " + e.getMessage(), e);
            }

            if(cert != null && control.isPendingCert())
            {
                rep.setPkiStatus(PkiStatus.PENDING);
            }else if(cert != null)
            {
                ContentInfo messageData = createSignedData(cert);
                rep.setMessageData(messageData);
            } else
            {
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badCertId);
            }

            break;
        }
        case CertPoll:
        {
            IssuerAndSubject is = (IssuerAndSubject) req.getMessageData();
            Certificate cert = cAEmulator.pollCert(is.getIssuer(), is.getSubject());
            if(cert != null)
            {
                rep.setMessageData(createSignedData(cert));
            } else
            {
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badCertId);
            }

            break;
        }
        case GetCert:
        {
            IssuerAndSerialNumber isn = (IssuerAndSerialNumber) req.getMessageData();
            Certificate cert = cAEmulator.getCert(isn.getName(), isn.getSerialNumber().getValue());
            if(cert != null)
            {
                rep.setMessageData(createSignedData(cert));
            } else
            {
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badCertId);
            }

            break;
        }
        case RenewalReq:
        {
            if(cACaps.containsCapability(CACapability.Renewal) == false)
            {
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badRequest);
            } else
            {
                CertificationRequest p10ReqInfo = (CertificationRequest) req.getMessageData();
                Certificate cert;
                try
                {
                    cert = cAEmulator.generateCert(p10ReqInfo);
                } catch (Exception e)
                {
                    throw new CAException("system failure: " + e.getMessage(), e);
                }
                if(cert != null)
                {
                    rep.setMessageData(createSignedData(cert));
                } else
                {
                    rep.setPkiStatus(PkiStatus.FAILURE);
                    rep.setFailInfo(FailInfo.badCertId);
                }
            }
            break;
        }
        case UpdateReq:
        {
            if(cACaps.containsCapability(CACapability.Update) == false)
            {
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badRequest);
            } else
            {
                CertificationRequest p10ReqInfo = (CertificationRequest) req.getMessageData();
                Certificate cert;
                try
                {
                    cert = cAEmulator.generateCert(p10ReqInfo);
                } catch (Exception e)
                {
                    throw new CAException("system failure: " + e.getMessage(), e);
                }
                if(cert != null)
                {
                    rep.setMessageData(createSignedData(cert));
                } else
                {
                    rep.setPkiStatus(PkiStatus.FAILURE);
                    rep.setFailInfo(FailInfo.badCertId);
                }
            }
            break;
        }
        case GetCRL:
        {
            IssuerAndSerialNumber isn = (IssuerAndSerialNumber) req.getMessageData();
            CertificateList crl;
            try
            {
                crl = cAEmulator.getCRL(isn.getName(), isn.getSerialNumber().getValue());
            } catch (Exception e)
            {
                throw new CAException("system failure: " + e.getMessage(), e);
            }
            if(crl != null)
            {
                rep.setMessageData(createSignedData(crl));
            } else
            {
                rep.setPkiStatus(PkiStatus.FAILURE);
                rep.setFailInfo(FailInfo.badCertId);
            }
            break;
        }
        default:
        {
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(FailInfo.badRequest);
        }
        } // end switch

        return rep;
    }

    private ContentInfo createSignedData(
            final CertificateList crl)
    throws CAException
    {
        CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();
        cmsSignedDataGen.addCRL(new X509CRLHolder(crl));

        CMSSignedData cmsSigneddata;
        try
        {
            cmsSigneddata = cmsSignedDataGen.generate(new CMSAbsentContent());
        } catch (CMSException e)
        {
            throw new CAException(e.getMessage(), e);
        }

        return cmsSigneddata.toASN1Structure();

    }

    private ContentInfo createSignedData(
            final Certificate cert)
    throws CAException
    {
        CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();

        CMSSignedData cmsSigneddata;
        try
        {
            cmsSignedDataGen.addCertificate(new X509CertificateHolder(cert));
            if(control.isSendCACert())
            {
                cmsSignedDataGen.addCertificate(new X509CertificateHolder(cAEmulator.getCACert()));
            }

            cmsSigneddata = cmsSignedDataGen.generate(new CMSAbsentContent());
        } catch (CMSException e)
        {
            throw new CAException(e);
        }

        return cmsSigneddata.toASN1Structure();
    }

    public PrivateKey getSigningKey()
    {
        return rAEmulator != null ? rAEmulator.getRAKey() : cAEmulator.getCAKey();
    }

    public Certificate getSigningCert()
    {
        return rAEmulator != null ? rAEmulator.getRACert() : cAEmulator.getCACert();
    }

    public CACaps getCACaps()
    {
        return cACaps;
    }

    public CAEmulator getCAEmulator()
    {
        return cAEmulator;
    }

    public RAEmulator getRAEmulator()
    {
        return rAEmulator;
    }

    public NextCAandRA getNextCAandRA()
    {
        return nextCAandRA;
    }

    private static String getChallengePassword(
            final CertificationRequestInfo p10Req)
    {
        ASN1Set attrs = p10Req.getAttributes();
        for(int i = 0; i < attrs.size(); i++)
        {
            Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
            if(PKCSObjectIdentifiers.pkcs_9_at_challengePassword.equals(attr.getAttrType()))
            {
                ASN1String str = (ASN1String) attr.getAttributeValues()[0];
                return str.getString();
            }
        }
        return null;
    }

}
