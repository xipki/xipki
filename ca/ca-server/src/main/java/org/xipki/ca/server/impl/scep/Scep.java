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
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditEvent;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.RequestType;
import org.xipki.ca.api.publisher.X509CertificateInfo;
import org.xipki.ca.server.impl.CAManagerImpl;
import org.xipki.ca.server.impl.X509CA;
import org.xipki.ca.server.mgmt.api.CAMgmtException;
import org.xipki.ca.server.mgmt.api.CAStatus;
import org.xipki.ca.server.mgmt.api.ScepEntry;
import org.xipki.common.ParamChecker;
import org.xipki.common.util.CollectionUtil;
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
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;

/**
 *
 * @author Lijun Liao
 *
 */
public class Scep
{
    private static final Logger LOG = LoggerFactory.getLogger(Scep.class);

    private final String caName;
    private final ScepEntry dbEntry;
    private final CAManagerImpl caManager;

    private PrivateKey responderKey;
    private X509Certificate responderCert;
    private CACertRespBytes cACertRespBytes;

    private CACaps caCaps;
    private EnvelopedDataDecryptor envelopedDataDecryptor;

    public Scep(
            final ScepEntry dbEntry,
            final CAManagerImpl caManager)
    throws CAMgmtException
    {
        ParamChecker.assertNotNull("caManager", caManager);
        ParamChecker.assertNotNull("dbEntry", dbEntry);
        ParamChecker.assertNotNull("caManager", caManager);

        this.caName = dbEntry.getCaName();
        this.dbEntry = dbEntry;
        this.caManager = caManager;
    }

    public void refreshCA(SecurityFactory securityFactory)
    throws CAMgmtException
    {
        ParamChecker.assertNotNull("securityFactory", securityFactory);

        String type = dbEntry.getResponderType();
        if("PKCS12".equalsIgnoreCase(type) == false && "JKS".equalsIgnoreCase(type) == false)
        {
            throw new CAMgmtException("unsupported SCEP responder type '" + type + "'");
        }

        KeyCertPair privKeyAndCert;
        try
        {
            privKeyAndCert = securityFactory.createPrivateKeyAndCert(
                    dbEntry.getResponderType(), dbEntry.getResponderConf(), dbEntry.getCertificate());
        } catch (SignerException e)
        {
            throw new CAMgmtException(e);
        }

        this.responderKey = privKeyAndCert.getPrivateKey();
        this.responderCert = privKeyAndCert.getCertificate();

        if(responderCert.getPublicKey() instanceof RSAPublicKey == false)
        {
            throw new IllegalArgumentException("The responder key is not RSA key");
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
            this.cACertRespBytes = new CACertRespBytes(
                    ca.getCAInfo().getCertificate().getCert(), responderCert);
        } catch (CertificateException e)
        {
            throw new CAMgmtException(e);
        } catch (CMSException e)
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

    public void setCaCaps(CACaps caCaps)
    {
        ParamChecker.assertNotNull("caCaps", caCaps);
        this.caCaps = caCaps;
    }

    public CACertRespBytes getCACertResp()
    {
        return cACertRespBytes;
    }

    public boolean supportsCertProfile(String profileName)
    throws CAMgmtException
    {
        return caManager.getX509CA(caName).supportsCertProfile(profileName);
    }

    public CAStatus getStatus()
    throws CAMgmtException
    {
        return caManager.getX509CA(caName).getCAInfo().getStatus();
    }

    public ContentInfo servicePkiOperation(CMSSignedData requestContent,
            String certProfileName, AuditEvent auditEvent)
    throws MessageDecodingException, OperationException
    {
    	// verify and decrypt the request
        DecodedPkiMessage req = DecodedPkiMessage.decode(requestContent, envelopedDataDecryptor);
        PkiMessage rep = new PkiMessage(req.getTransactionId(), req.getMessageType(), Nonce.randomNonce());
        rep.setRecipientNonce(req.getSenderNonce());

        X509CA ca;
        try
        {
            ca = caManager.getX509CA(caName);
        } catch (CAMgmtException e)
        {
        	// TODO log
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, e.getMessage());
        }
        X500Name caX500Name = ca.getCAInfo().getCertificate().getSubjectAsX500Name();

        try
        {
            SignedData signedData;

	        //TODO: check the time
            MessageType mt = req.getMessageType();
            switch(mt)
            {
                case PKCSReq:
                case RenewalReq:
                case UpdateReq:
                {
                    CertificationRequest p10Req = (CertificationRequest) req.getMessageData();
                    CertificationRequestInfo p10ReqInfo = p10Req.getCertificationRequestInfo();

                    Extensions extensions = X509Util.getExtensions(p10ReqInfo);

                    X509Certificate reqSignatureCert = req.getSignatureCert();

                    boolean selfSigned = reqSignatureCert.getSubjectX500Principal().equals(
                            reqSignatureCert.getIssuerX500Principal());
                    String user = null;

                    if(selfSigned == false &&
                            ca.knowsCertificate(reqSignatureCert) == false)
                    {
                		// TODO log
                        throw new FailInfoException(FailInfo.badRequest);
                    } else
                    {
                        if(MessageType.PKCSReq == mt)
                        {
    		        		// up to draft-nourse-scep-23 the client sends all messages to enrol certificate
    		        		// via MessageType PKCSReq
                            Extension ext = extensions.getExtension(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
                            if(ext != null)
                            {
                                ASN1Encodable t = ((ASN1Set) ext.getParsedValue()).getObjectAt(0);
                                String challengePwd = ((ASN1String) t).getString();
                                String[] strs = challengePwd.split(":");
                                if(strs == null || strs.length != 2)
                                {
                                	// TODO LOG
                                    throw new FailInfoException(FailInfo.badRequest);
                                }
                                user = strs[0];
                                String password = strs[1];

                                if(ca.authenticateUser(user, password.getBytes()) == false)
                                {
                            		// TODO log
                                    throw new FailInfoException(FailInfo.badRequest);
                                }
                            }
                        }
                    }

                    TransactionId tid = req.getTransactionId();
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
                    signedData = buildSignedData(cert.getCert().getCert());
                    break;
                }
                case CertPoll:
                {
                    IssuerAndSubject is = (IssuerAndSubject) req.getMessageData();
                    ensureIssuedByThisCA(caX500Name, is.getIssuer());
                    TransactionId tid = req.getTransactionId();

                    signedData = pollCert(ca, is.getSubject(), tid);
                    break;
                }
                case GetCert:
                {
                    IssuerAndSerialNumber isn = (IssuerAndSerialNumber) req.getMessageData();
                    ensureIssuedByThisCA(caX500Name, isn.getName());
                    signedData = getCert(ca, isn.getSerialNumber().getPositiveValue());
                    break;
                }
                case GetCRL:
                {
                    IssuerAndSerialNumber isn = (IssuerAndSerialNumber) req.getMessageData();
                    ensureIssuedByThisCA(caX500Name, isn.getName());
                    signedData = getCRL(ca, isn.getSerialNumber().getPositiveValue());
                    break;
                }
                default:
                {
                    LOG.error("unknown SCEP messageType '{}'", req.getMessageType());
                    throw new FailInfoException(FailInfo.badRequest);
                }
            } // end switch

            rep.setMessageData(signedData);
            rep.setPkiStatus(PkiStatus.SUCCESS);
        }catch(FailInfoException e)
        {
            rep.setPkiStatus(PkiStatus.FAILURE);
            rep.setFailInfo(e.getFailInfo());
        }

        return encodeResponse(rep, req);
    }

    private SignedData getCert(X509CA ca, BigInteger serialNumber)
    throws FailInfoException, OperationException
    {
        X509Certificate cert;
        try
        {
            cert = ca.getCertificate(serialNumber);
        } catch (CertificateException e)
        {
			// TODO log
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, e.getMessage());
        }
        if(cert == null)
        {
            throw new FailInfoException(FailInfo.badCertId);
        }
        return buildSignedData(cert);
    }

    private SignedData pollCert(X509CA ca, X500Name subject, TransactionId tid)
    throws FailInfoException, OperationException
    {
        byte[] tidBytes = getTransactionIdBytes(tid);
        List<X509Certificate> certs = ca.getCertificate(subject, tidBytes);
        if(CollectionUtil.isEmpty(certs))
        {
            certs = ca.getCertificate(subject, null);
        }

        if(CollectionUtil.isEmpty(certs))
        {
            throw new FailInfoException(FailInfo.badCertId);
        }

        if(certs.size() > 1)
        {
        	// TODO
            throw new FailInfoException(FailInfo.badCertId);
        }

        return buildSignedData(certs.get(0));
    }

    private static SignedData buildSignedData(X509Certificate cert)
    throws OperationException
    {
        CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();
        try
        {
            X509CertificateHolder certHolder = new X509CertificateHolder(cert.getEncoded());
            cmsSignedDataGen.addCertificate(certHolder);
            CMSSignedData signedData = cmsSignedDataGen.generate(new CMSAbsentContent());
            return (SignedData) signedData.toASN1Structure().getContent();
        } catch (CMSException | IOException | CertificateEncodingException e)
        {
        	// TODO LOG
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, e.getMessage());
        }
    }

    private SignedData getCRL(X509CA ca, BigInteger serialNumber)
    throws FailInfoException, OperationException
    {
        try
        {
            CertificateList crl = ca.getCurrentCRL();
            if(crl == null)
            {
                throw new FailInfoException(FailInfo.badRequest);
            }
            CMSSignedDataGenerator cmsSignedDataGen = new CMSSignedDataGenerator();
            cmsSignedDataGen.addCRL(new X509CRLHolder(crl));
            CMSSignedData signedData = cmsSignedDataGen.generate(new CMSAbsentContent());
            return (SignedData) signedData.toASN1Structure().getContent();
        }catch(FailInfoException e)
        {
            throw e;
        }catch(CMSException e)
        {
        	// TODO: LOG
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, e.getMessage());
        }
    }

    private ContentInfo encodeResponse(PkiMessage response, DecodedPkiMessage request)
    throws OperationException
    {
        String signatureAlgorithm = getSignatureAlgorithm(responderKey, request.getDigestAlgorithm());
        ContentInfo ci;
        try
        {
            ci = response.encode(responderKey,
                    signatureAlgorithm, responderCert, null,
                    request.getSignatureCert(), request.getContentEncryptionAlgorithm());
        } catch (MessageEncodingException e)
        {
        	// TODO: log
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, e.getMessage());
        }
        return ci;

    }

    private static String getSignatureAlgorithm(PrivateKey key, ASN1ObjectIdentifier digestOid)
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

    private static void ensureIssuedByThisCA(X500Name thisCAX500Name, X500Name caX500Name)
    throws FailInfoException
    {
        if(thisCAX500Name.equals(caX500Name) == false)
        {
            throw new FailInfoException(FailInfo.badCertId);
        }
    }

    static CMSSignedData createDegeneratedSigendData(
            X509Certificate... certs)
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

    private static byte[] getTransactionIdBytes(TransactionId tid)
    {
        byte[] tidBytes;
        try
        {
            tidBytes = Hex.decode(tid.getId());
        }catch(DecoderException e)
        {
            tidBytes = tid.getId().getBytes();
        }
        return tidBytes;
    }

}
