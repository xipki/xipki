/*
 * Copyright (c) 2014 xipki.org
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

package org.xipki.ca.server;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.X509CRLObject;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CAMgmtException;
import org.xipki.ca.api.CAStatus;
import org.xipki.ca.api.CertAlreadyIssuedException;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.profile.BadCertTemplateException;
import org.xipki.ca.api.profile.CertProfile;
import org.xipki.ca.api.profile.CertProfileException;
import org.xipki.ca.api.profile.ExtensionOccurrence;
import org.xipki.ca.api.profile.ExtensionTuple;
import org.xipki.ca.api.profile.ExtensionTuples;
import org.xipki.ca.api.profile.IdentifiedCertProfile;
import org.xipki.ca.api.profile.OriginalProfileConf;
import org.xipki.ca.api.profile.SubjectInfo;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.ca.server.mgmt.CAEntry;
import org.xipki.ca.server.mgmt.CAManagerImpl;
import org.xipki.ca.server.mgmt.CertProfileEntry;
import org.xipki.ca.server.mgmt.PublisherEntry;
import org.xipki.ca.server.store.CertificateStore;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.common.CustomObjectIdentifiers;
import org.xipki.security.common.HealthCheckResult;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

public class X509CA
{
    public static final long MINUTE = 60L * 1000;
    public static final int CERT_REVOCATED = 1;
    public static final int CERT_NOT_EXISTS = 2;
    public static final int CERT_REVOCATION_EXCEPTION = 3;

    private static Logger LOG = LoggerFactory.getLogger(X509CA.class);

    public static long DAY = 24L * 60 * 60 * 1000;

    private final CertificateFactory cf;

    private final CAEntry caInfo;
    private final ConcurrentContentSigner caSigner;
    private final X500Name caSubjectX500Name;
    private final byte[] caSKI;
    private final MessageDigest sha1;
    private final CertificateStore certstore;
    private final CrlSigner crlSigner;

    private int signserviceTimeout = 5000; // 5 seconds
    private final CAManagerImpl caManager;
    private final Object nextSerialLock = new Object();
    private final Object crlLock = new Object();

    private final ConcurrentSkipListSet<String> pendingSubjectSha1Fps = new ConcurrentSkipListSet<String>();
    private final AtomicInteger numActiveRevocations = new AtomicInteger(0);

    public X509CA(
            CAManagerImpl caManager,
            CAEntry caInfo,
            ConcurrentContentSigner caSigner,
            CertificateStore certstore,
            CrlSigner crlSigner)
    throws OperationException
    {
        ParamChecker.assertNotNull("caManager", caManager);
        ParamChecker.assertNotNull("caInfo", caInfo);
        ParamChecker.assertNotNull("caSigner", caSigner);
        ParamChecker.assertNotNull("certstore", certstore);

        this.caManager = caManager;
        this.caInfo = caInfo;
        this.caSigner = caSigner;
        this.certstore = certstore;
        this.crlSigner = crlSigner;

        X509CertificateWithMetaInfo caCert = caInfo.getCertificate();
        this.caSubjectX500Name = X500Name.getInstance(
                caCert.getCert().getSubjectX500Principal().getEncoded());

        byte[] encodedSkiValue = caCert.getCert().getExtensionValue(Extension.subjectKeyIdentifier.getId());
        if(encodedSkiValue == null)
        {
            throw new OperationException(ErrorCode.System_Failure,
                    "CA certificate does not have required extension SubjectKeyIdentifier");
        }
        ASN1OctetString ski;
        try
        {
            ski = (ASN1OctetString) X509ExtensionUtil.fromExtensionValue(encodedSkiValue);
        } catch (IOException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getMessage());
        }
        this.caSKI = ski.getOctets();

        this.cf = new CertificateFactory();

        try
        {
            sha1 = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e)
        {
            throw new OperationException(ErrorCode.System_Failure, "NoSuchAlgorithmException: " + e.getMessage());
        }

        if(crlSigner != null && crlSigner.getPeriod() > 0)
        {
            // Add scheduled CRL generation service
            long lastThisUpdate;
            try
            {
                lastThisUpdate = certstore.getThisUpdateOfCurrentCRL(caCert);
            } catch (SQLException e)
            {
                throw new OperationException(ErrorCode.System_Failure, "SQLException: " + e.getMessage());
            }

            long period = crlSigner.getPeriod();

            long now = System.currentTimeMillis() / 1000; // in seconds

            long initialDelay;
            if(lastThisUpdate == 0 || // no CRL available
               now >= lastThisUpdate + period * 60) // no CRL is created in the period
            {
                initialDelay = 5; // generate CRL in 5 minutes to wait for the initialization of CA
            }
            else
            {
                initialDelay = period - (now - lastThisUpdate)/60;
            }

            ScheduledCRLGenerationService crlGenerationService = new ScheduledCRLGenerationService();
            caManager.getScheduledThreadPoolExecutor().scheduleAtFixedRate(
                    crlGenerationService, initialDelay, crlSigner.getPeriod(), TimeUnit.MINUTES);
        }

        Long greatestSerialNumber;
        try
        {
            greatestSerialNumber = certstore.getGreatestSerialNumber(caCert);
        } catch (SQLException e)
        {
            throw new OperationException(ErrorCode.System_Failure, "SQLException: " + e.getMessage());
        }

        if(greatestSerialNumber == null)
        {
            throw new OperationException(ErrorCode.System_Failure,
                    "Could not retrieve the greated serial number for ca " + caInfo.getName());
        }
        if(caInfo.getNextSerial() < greatestSerialNumber + 1)
        {
            LOG.warn("Corrected the next_serial of {} from {} to {}",
                    new Object[]{caInfo.getName(), caInfo.getNextSerial(), greatestSerialNumber + 1});
            caInfo.setNextSerial(greatestSerialNumber + 1);
        }

        ScheduledNextSerialCommitService nextSerialCommitService = new ScheduledNextSerialCommitService();
        caManager.getScheduledThreadPoolExecutor().scheduleAtFixedRate(
                nextSerialCommitService, 5, 5, TimeUnit.SECONDS); // commit the next_serial every 5 seconds
    }

    public void setSignserviceTimeout(int signserviceTimeout)
    {
        if(signserviceTimeout < 0)
        {
            throw new IllegalArgumentException("negative signserviceTimeout is not allowed: " + signserviceTimeout);
        }
        this.signserviceTimeout = signserviceTimeout;
    }

    public CAEntry getCAInfo()
    {
        return caInfo;
    }

    public X500Name getCASubjectX500Name()
    {
        return caSubjectX500Name;
    }

    public CertificateList getCurrentCRL()
    throws OperationException
    {
        LOG.info("START getCurrentCRL: ca={}", caInfo.getName());
        boolean successfull = false;

        try
        {
            byte[] encodedCrl = certstore.getEncodedCurrentCRL(caInfo.getCertificate());
            if(encodedCrl == null)
            {
                return null;
            }

            try
            {
                CertificateList crl = CertificateList.getInstance(encodedCrl);
                successfull = true;

                LOG.info("SUCCESSFULL getCurrentCRL: ca={}, thisUpdate={}", caInfo.getName(),
                        crl.getThisUpdate().getTime());

                return crl;
            } catch (RuntimeException e)
            {
                throw new OperationException(ErrorCode.System_Failure, e.getClass().getName() + ": " + e.getMessage());
            }
        }finally
        {
            if(successfull == false)
            {
                LOG.info("FAILED getCurrentCRL: ca={}", caInfo.getName());
            }
        }
    }

    public void cleanupCRLs()
    throws OperationException
    {
        int numCrls = caInfo.getNumCrls();
        LOG.info("START cleanupCRLs: ca={}, numCrls={}", caInfo.getName(), numCrls);

        boolean successfull = false;

        try
        {
            int numOfRemovedCRLs;
            if(numCrls > 0)
            {
                numOfRemovedCRLs = certstore.cleanupCRLs(caInfo.getCertificate(), caInfo.getNumCrls());
            }
            else
            {
                numOfRemovedCRLs = 0;
            }
            successfull = true;
            LOG.info("SUCCESSFULL cleanupCRLs: ca={}, numOfRemovedCRLs={}", caInfo.getName(),
                    numOfRemovedCRLs);
        } catch (RuntimeException e)
        {
            throw new OperationException(ErrorCode.System_Failure, e.getClass().getName() + ": " + e.getMessage());
        }
        finally
        {
            if(successfull == false)
            {
                LOG.info("FAILED cleanupCRLs: ca={}", caInfo.getName());
            }
        }
    }
    public X509CRL generateCRL()
    throws OperationException
    {
        LOG.info("START generateCRL: ca={}", caInfo.getName());

        boolean successfull = false;

        try
        {
            if(crlSigner == null)
            {
                throw new OperationException(ErrorCode.System_Failure, "CRL generation is not allowed");
            }

            synchronized (crlLock)
            {
                ConcurrentContentSigner signer = crlSigner.getSigner();

                boolean directCRL = signer == null;
                X500Name crlIssuer = directCRL ? caSubjectX500Name :
                    X500Name.getInstance(signer.getCertificate().getSubjectX500Principal().getEncoded());

                Date thisUpdate = new Date();
                X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(crlIssuer, thisUpdate);
                if(crlSigner.getPeriod() > 0)
                {
                    Date nextUpdate = new Date(thisUpdate.getTime() +
                            (crlSigner.getPeriod() + crlSigner.getOverlap()) * MINUTE);
                    crlBuilder.setNextUpdate(nextUpdate);
                }

                BigInteger startSerial = BigInteger.ONE;
                final int numEntries = 100;

                X509CertificateWithMetaInfo cacert = caInfo.getCertificate();
                List<CertRevocationInfo> revInfos;
                boolean isFirstCRLEntry = true;

                do
                {
                    try
                    {
                        revInfos = certstore.getRevocatedCertificates(cacert, thisUpdate, startSerial, numEntries);
                    } catch (SQLException e)
                    {
                        throw new OperationException(ErrorCode.System_Failure, "SQLException: " + e.getMessage());
                    }

                    BigInteger maxSerial = BigInteger.ONE;
                    for(CertRevocationInfo revInfo : revInfos)
                    {
                        BigInteger serial = revInfo.getSerial();
                        if(serial.compareTo(maxSerial) > 0)
                        {
                            maxSerial = serial;
                        }

                        int reason = revInfo.getReason();
                        Date revocationTime = revInfo.getRevocationTime();
                        Date invalidityTime = revInfo.getInvalidityTime();

                        if(directCRL || isFirstCRLEntry == false)
                        {
                            crlBuilder.addCRLEntry(revInfo.getSerial(), revocationTime, reason, invalidityTime);
                        }
                        else
                        {
                            List<Extension> extensions = new ArrayList<Extension>(3);
                            if(reason != 0)
                            {
                                Extension ext = createReasonExtension(reason);
                                extensions.add(ext);
                            }
                            if(invalidityTime != null)
                            {
                                Extension ext = createInvalidityDateExtension(invalidityTime);
                                extensions.add(ext);
                            }

                            Extension ext = createCertificateIssuerExtension(caSubjectX500Name);
                            extensions.add(ext);

                            Extensions asn1Extensions = new Extensions(extensions.toArray(new Extension[0]));
                            crlBuilder.addCRLEntry(revInfo.getSerial(), revocationTime, asn1Extensions);
                            isFirstCRLEntry = false;
                        }
                    }

                    startSerial = maxSerial.add(BigInteger.ONE);

                }while(revInfos.size() >= numEntries);

                int crlNumber;
                try
                {
                    crlNumber = certstore.getNextFreeCRLNumber(cacert);
                }catch(SQLException e)
                {
                    LOG.error("getNextFreeCRLNumber. {}: {}", e.getClass().getName(), e.getMessage());
                    LOG.debug("getNextFreeCRLNumber", e);
                    throw new OperationException(ErrorCode.System_Failure, e.getMessage());
                }

                try
                {
                    // AuthorityKeyIdentifier
                    byte[] akiValues = directCRL ? this.caSKI : crlSigner.getSubjectKeyIdentifier();
                    AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(akiValues);
                    crlBuilder.addExtension(Extension.authorityKeyIdentifier, false, aki);

                    // add extension CRL Number
                    crlBuilder.addExtension(Extension.cRLNumber, false, new ASN1Integer(crlNumber));

                    // IssuingDistributionPoint
                    IssuingDistributionPoint idp = new IssuingDistributionPoint(
                            (DistributionPointName) null, // distributionPoint,
                            true, // onlyContainsUserCerts,
                            false, // onlyContainsCACerts,
                            (ReasonFlags) null, // onlySomeReasons,
                            true, // indirectCRL,
                            false // onlyContainsAttributeCerts
                            );

                    crlBuilder.addExtension(Extension.issuingDistributionPoint, true, idp);
                } catch (CertIOException e)
                {
                    LOG.error("crlBuilder.addExtension. {}: {}", e.getClass().getName(), e.getMessage());
                    LOG.debug("crlBuilder.addExtension", e);

                    throw new OperationException(ErrorCode.System_Failure, e.getMessage());
                }

                startSerial = BigInteger.ONE;
                if(crlSigner.includeCertsInCrl())
                {
                    /*
                     * extValue is of type CertificateSet defined in RFC 5652 - Cryptographic Message Syntax
                     */
                    ASN1EncodableVector vector = new ASN1EncodableVector();

                    List<BigInteger> serials;

                    do
                    {
                        try
                        {
                            serials = certstore.getCertSerials(cacert, thisUpdate, startSerial, numEntries);
                        } catch (SQLException e)
                        {
                            throw new OperationException(ErrorCode.System_Failure, "SQLException: " + e.getMessage());
                        }

                        BigInteger maxSerial = BigInteger.ONE;
                        for(BigInteger serial : serials)
                        {
                            if(serial.compareTo(maxSerial) > 0)
                            {
                                maxSerial = serial;
                            }

                            byte[] encodedCert;
                            try
                            {
                                encodedCert = certstore.getEncodedCertificate(cacert, serial);
                            } catch (SQLException e)
                            {
                                throw new OperationException(ErrorCode.System_Failure, "SQLException: " + e.getMessage());
                            }

                            Certificate cert = Certificate.getInstance(encodedCert);
                            vector.add(cert);
                        }

                        startSerial = maxSerial.add(BigInteger.ONE);
                    }while(serials.size() >= numEntries);

                    try
                    {
                        crlBuilder.addExtension(new ASN1ObjectIdentifier(CustomObjectIdentifiers.id_crl_certset),
                                false, new DERSet(vector));
                    } catch (CertIOException e)
                    {
                        throw new OperationException(ErrorCode.System_Failure, "CertIOException: " + e.getMessage());
                    }
                }

                ConcurrentContentSigner concurrentSigner = (signer == null) ? caSigner : signer;
                ContentSigner contentSigner;
                try
                {
                    contentSigner = concurrentSigner.borrowContentSigner(signserviceTimeout);
                } catch (NoIdleSignerException e)
                {
                    throw new OperationException(ErrorCode.System_Failure, "NoIdleSignerException: " + e.getMessage());
                }

                X509CRLHolder crlHolder;
                try
                {
                    crlHolder = crlBuilder.build(contentSigner);
                }finally
                {
                    concurrentSigner.returnContentSigner(contentSigner);
                }

                try
                {
                    X509CRL crl = new X509CRLObject(crlHolder.toASN1Structure());
                    publishCRL(crl);

                    successfull = true;
                    LOG.info("SUCCESSFULL generateCRL: ca={}, crlNumber={}, thisUpdate={}",
                            new Object[]{caInfo.getName(), crlNumber, crl.getThisUpdate()});
                    return crl;
                } catch (CRLException e)
                {
                    throw new OperationException(ErrorCode.System_Failure, "CRLException: " + e.getMessage());
                }
            }// end synchronized crlLock
        }finally
        {
            if(successfull == false)
            {
                LOG.info("FAILED generateCRL: ca={}", caInfo.getName());
            }
        }
    }

    private static Extension createReasonExtension(int reasonCode)
    {
        org.bouncycastle.asn1.x509.CRLReason crlReason =
                org.bouncycastle.asn1.x509.CRLReason.lookup(reasonCode);

        try
        {
            return new Extension(Extension.reasonCode, false, crlReason.getEncoded());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error encoding reason: " + e.getMessage(), e);
        }
    }

    private static Extension createInvalidityDateExtension(Date invalidityDate)
    {
        try
        {
            ASN1GeneralizedTime asnTime = new ASN1GeneralizedTime(invalidityDate);
            return new Extension(Extension.invalidityDate, false, asnTime.getEncoded());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error encoding reason: " + e.getMessage(), e);
        }
    }

    /**
     * added by lijun liao add the support of
     * @param certificateIssuer
     * @return
     */
    private static Extension createCertificateIssuerExtension(X500Name certificateIssuer)
    {
        try
        {
            GeneralName generalName = new GeneralName(certificateIssuer);
            return new Extension(Extension.certificateIssuer, false, new GeneralNames(generalName).getEncoded());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error encoding reason: " + e.getMessage(), e);
        }
    }

    public CertificateInfo generateCertificate(
            boolean requestedByRA,
            String certProfileName,
            OriginalProfileConf origCertProfile,
            X500Name subject,
            SubjectPublicKeyInfo publicKeyInfo,
            Date notBefore,
            Date notAfter,
            Extensions extensions)
    throws OperationException, CertAlreadyIssuedException
    {
        LOG.info("START generateCertificate: CA={}, profile={}, origProfile={}, subject={}",
                new Object[]{caInfo.getName(), certProfileName, origCertProfile, subject});

        boolean successfull = false;

        try
        {
            if(caInfo.isAllowDuplicateKey() == false)
            {
                boolean b;
                try
                {
                    b = certstore.certIssuedForPublicKey(this.caInfo.getCertificate(), publicKeyInfo.getEncoded());
                } catch (IOException e)
                {
                    throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, "could not encode public key");
                }
                if(b)
                {
                    throw new CertAlreadyIssuedException("Certificate for the given public key already issued");
                }
            }

            try
            {
                CertificateInfo ret = intern_generateCertificate(requestedByRA, certProfileName, origCertProfile,
                        subject, publicKeyInfo,
                        notBefore, notAfter, extensions, false);
                successfull = true;

                LOG.info("SUCCESSFULL generateCertificate: CA={}, profile={}, origProfile={}, subject={}, serialNumber={}",
                        new Object[]{caInfo.getName(), certProfileName, origCertProfile,
                            ret.getCert().getSubject(), ret.getCert().getCert().getSerialNumber()});

                return ret;
            }catch(RuntimeException e)
            {
                LOG.warn("RuntimeException in generateCertificate(): {}", e.getMessage());
                LOG.debug("RuntimeException in generateCertificate()", e);
                throw new OperationException(ErrorCode.System_Failure, "RuntimeException:  " + e.getMessage());
            }
        }finally
        {
            if(successfull == false)
            {
                LOG.warn("FAILED generateCertificate: CA={}, profile={}, origProfile={}, subject={}",
                        new Object[]{caInfo.getName(), certProfileName, origCertProfile, subject});
            }
        }
    }

    public CertificateInfo regenerateCertificate(
            boolean requestedByRA,
            String certProfileName,
            OriginalProfileConf origCertProfile,
            X500Name subject,
            SubjectPublicKeyInfo publicKeyInfo,
            Date notBefore,
            Date notAfter,
            Extensions extensions)
    throws OperationException
    {
        LOG.info("START regenerateCertificate: CA={}, profile={}, origProfile={}, subject={}",
                new Object[]{caInfo.getName(), certProfileName, origCertProfile, subject});

        boolean successfull = false;

        try
        {
            CertificateInfo ret = intern_generateCertificate(requestedByRA, certProfileName, origCertProfile,
                    subject, publicKeyInfo,
                    notBefore, notAfter, extensions, false);
            successfull = true;
            LOG.info("SUCCESSFULL generateCertificate: CA={}, profile={}, origProfile={}, subject={}, serialNumber={}",
                    new Object[]{caInfo.getName(), certProfileName, origCertProfile,
                        ret.getCert().getSubject(), ret.getCert().getCert().getSerialNumber()});

            return ret;
        }catch(RuntimeException e)
        {
            LOG.warn("RuntimeException in regenerateCertificate()", e);
            throw new OperationException(ErrorCode.System_Failure, "RuntimeException:  " + e.getMessage());
        } catch (CertAlreadyIssuedException e)
        {
            LOG.warn("CertAlreadyIssuedException in regenerateCertificate(), should not reach here", e);
            throw new OperationException(ErrorCode.System_Failure, "CertAlreadyIssuedException:  " + e.getMessage());
        } finally
        {
            if(successfull == false)
            {
                LOG.warn("FAILED regenerateCertificate: CA={}, profile={}, origProfile={}, subject={}",
                        new Object[]{caInfo.getName(), certProfileName, origCertProfile, subject});
            }
        }
    }

    public boolean publishCertificate(CertificateInfo certInfo)
    {
        if(certstore.addCertificate(certInfo) == false)
        {
            return false;
        }

        for(IdentifiedCertPublisher publisher : getPublishers())
        {
            try
            {
                publisher.certificateAdded(certInfo);
            }
            catch (RuntimeException re)
            {
                String msg = "Error while publish certificate to the publisher " + publisher.getName();
                LOG.error(msg);
                LOG.debug(msg, re);
            }
        }

        return true;
    }

    public boolean republishCertificates(String publisherName)
    {
        if(publisherName == null)
        {
            throw new IllegalArgumentException("publisherName could not be null");
        }

        IdentifiedCertPublisher publisher = null;
        for(IdentifiedCertPublisher p : getPublishers())
        {
            if(p.getName().equals(publisherName))
            {
                publisher = p;
                break;
            }
        }

        if(publisher == null)
        {
            throw new IllegalArgumentException(
                    "Could not find publisher " + publisherName + " for CA " + caInfo.getName());
        }

        CAStatus status = caInfo.getStatus();

        caInfo.setStatus(CAStatus.INACTIVE);

        // wait till no certificate request in process
        while(pendingSubjectSha1Fps.isEmpty() == false || numActiveRevocations.get() > 0)
        {
            LOG.info("Certificate requests are still in process, wait 1 second");
            try
            {
                Thread.sleep(1000);
            }catch(InterruptedException e)
            {
            }
        }

        try
        {
            List<BigInteger> serials;
            X509CertificateWithMetaInfo cacert = caInfo.getCertificate();

            Date notExpiredAt = null;

            BigInteger startSerial = BigInteger.ONE;
            int numEntries = 100;

            do
            {
                try
                {
                    serials = certstore.getCertSerials(cacert, notExpiredAt, startSerial, numEntries);
                } catch (SQLException e)
                {
                    LOG.error("SQLException, message: {}", e.getMessage());
                    LOG.debug("SQLException, message", e);
                    return false;
                } catch (OperationException e)
                {
                    LOG.error("OperationException, message: {}", e.getMessage());
                    LOG.debug("OperationException, message", e);
                    return false;
                }

                BigInteger maxSerial = BigInteger.ONE;
                for(BigInteger serial : serials)
                {
                    if(serial.compareTo(maxSerial) > 0)
                    {
                        maxSerial = serial;
                    }

                    CertificateInfo certInfo;

                    try
                    {
                        certInfo = certstore.getCertificateInfo(cacert, serial);
                    } catch (SQLException e)
                    {
                        LOG.error("SQLException, message: {}", e.getMessage());
                        LOG.debug("SQLException, message", e);
                        return false;
                    } catch (OperationException e)
                    {
                        LOG.error("OperationException, message: {}", e.getMessage());
                        LOG.debug("OperationException, message", e);
                        return false;
                    } catch (CertificateException e)
                    {
                        LOG.error("CertificateException, message: {}", e.getMessage());
                        LOG.debug("CertificateException, message", e);
                        return false;
                    }

                    publisher.certificateAdded(certInfo);
                }

                startSerial = maxSerial.add(BigInteger.ONE);
            }while(serials.size() >= numEntries);

        }finally
        {
            caInfo.setStatus(status);
        }
        return true;
    }

    private boolean publishCRL(X509CRL crl)
    {
        X509CertificateWithMetaInfo cacert = caInfo.getCertificate();
        if(certstore.addCRL(cacert, crl) == false)
        {
            return false;
        }

        for(IdentifiedCertPublisher publisher : getPublishers())
        {
            try
            {
                publisher.crlAdded(cacert, crl);
            }
            catch (RuntimeException re)
            {
                LOG.error("Error while publish CRL to the publisher {}. {}: {}",
                        new Object[]{publisher.getName(), re.getClass().getName(), re.getMessage()});
                LOG.debug("Error while publish CRL to the publisher " + publisher.getName(), re);
            }
        }

        return true;
    }

    public X509Certificate revocateCertificate(BigInteger serialNumber,
            CRLReason reason, Date invalidityTime)
    throws OperationException
    {
        LOG.info("START revocateCertificate: ca={}, serialNumber={}, reason={}, invalidityTime={}",
                new Object[]{caInfo.getName(), serialNumber, reason.getValue(), invalidityTime});

        numActiveRevocations.addAndGet(1);

        X509Certificate revokedCert;

        try
        {
            byte[] revokedCertBytes= certstore.revocateCertificate(
                    caInfo.getCertificate(),
                    serialNumber, reason, invalidityTime);
            if(revokedCertBytes == null)
            {
                return null;
            }

            try
            {
                revokedCert = IoCertUtil.parseCert(revokedCertBytes);
            } catch (Exception e)
            {
                StringBuilder sb = new StringBuilder("Could not parse revoked certificate with ca=");
                sb.append(caInfo.getNextSerial()).append(" and serialNumber=").append(serialNumber);
                String msg = sb.toString();
                LOG.error(msg);
                LOG.debug(msg, e);
                throw new OperationException(ErrorCode.System_Failure, e.getMessage());
            }

            X509CertificateWithMetaInfo revokedCertWithInfo = new X509CertificateWithMetaInfo(revokedCert);

            Date revocationTime = new Date();

            if(revokedCert != null)
            {
                for(IdentifiedCertPublisher publisher : getPublishers())
                {
                    try
                    {
                        publisher.certificateRevoked(caInfo.getCertificate(),
                                revokedCertWithInfo,
                                revocationTime, reason.getValue().intValue(), invalidityTime);
                    }
                    catch (RuntimeException re)
                    {
                        String msg = "Error while publish certificate to the publisher " + publisher.getName();
                        LOG.error(msg);
                        LOG.debug(msg, re);
                    }
                }
            }

        }finally
        {
            numActiveRevocations.addAndGet(-1);
        }

        String resultText = revokedCert == null ? "CERT_NOT_EXIST" : "REVOKED";
        LOG.info("SUCCESSFULL revocateCertificate: ca={}, serialNumber={}, reason={}, invalidityTime={}, revocationResult={}",
                new Object[]{caInfo.getName(), serialNumber, reason.getValue(), invalidityTime, resultText});

        return revokedCert;
    }

    private List<IdentifiedCertPublisher> getPublishers()
    {
        List<PublisherEntry> dbEntries = caManager.getPublishersForCA(caInfo.getName());

        List<IdentifiedCertPublisher> publishers = new ArrayList<IdentifiedCertPublisher>(dbEntries.size());
        for(PublisherEntry dbEntry : dbEntries)
        {
            IdentifiedCertPublisher publisher = null;
            try
            {
                publisher = dbEntry.getCertPublisher();
            } catch (CertPublisherException e)
            {
                continue;
            }

            publishers.add(publisher);
        }
        return publishers;
    }

    private CertificateInfo intern_generateCertificate(
            boolean requestedByRA,
            String certProfileName,
            OriginalProfileConf origCertProfileConf,
            X500Name requestedSubject,
            SubjectPublicKeyInfo publicKeyInfo,
            Date notBefore,
            Date notAfter,
            org.bouncycastle.asn1.x509.Extensions extensions,
            boolean keyUpdate)
    throws OperationException, CertAlreadyIssuedException
    {
        IdentifiedCertProfile certProfile = getX509CertProfile(certProfileName);

        if(certProfile == null)
        {
            throw new OperationException(ErrorCode.UNKNOWN_CERT_PROFILE, "unknown cert profile " + certProfileName);
        }

        if(certProfile.isOnlyForRA() && requestedByRA == false)
        {
            throw new OperationException(ErrorCode.NO_PERMISSION_OF_CERT_PROFILE,
                    "Profile " + certProfileName + " not applied to non-RA");
        }

        // public key
        try
        {
            certProfile.checkPublicKey(publicKeyInfo);
        } catch (BadCertTemplateException e)
        {
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, e.getMessage());
        }

        // subject
        SubjectInfo subjectInfo;
        try
        {
            subjectInfo = certProfile.getSubject(requestedSubject);
        }catch(CertProfileException e)
        {
            throw new OperationException(ErrorCode.System_Failure, "exception in cert profile " + certProfileName);
        } catch (BadCertTemplateException e)
        {
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, e.getMessage());
        }

        X500Name grantedSubject = subjectInfo.getGrantedSubject();

        // make sure that the grantedSubject does not equal the CA's subject
        if(grantedSubject.equals(caSubjectX500Name))
        {
            throw new CertAlreadyIssuedException("Certificate with the same subject as CA is not allowed");
        }

        String sha1FpSubject = IoCertUtil.sha1sum_canonicalized_name(grantedSubject);
        String grandtedSubjectText = grantedSubject.toString();

        if(keyUpdate)
        {
            CertStatus certStatus = certstore.getCertStatusForSubject(
                    caInfo.getCertificate(), grantedSubject);

            if(certStatus == CertStatus.Revocated)
            {
                throw new OperationException(ErrorCode.CERT_REVOKED);
            }
            else if(certStatus == CertStatus.Unknown)
            {
                throw new OperationException(ErrorCode.UNKNOWN_CERT);
            }
        }
        else
        {
            if(caInfo.isAllowDuplicateSubject() == false)
            {
                boolean certWithSameSubjectIssued = certstore.certIssuedForSubject(this.caInfo.getCertificate(), sha1FpSubject);

                if(certWithSameSubjectIssued)
                {
                    boolean incSerialNumberAllowed = certProfile.incSerialNumberIfSubjectExists();
                    if(incSerialNumberAllowed && origCertProfileConf != null)
                    {
                        if(origCertProfileConf.isIncSerialNumberSpecified() &&
                                origCertProfileConf.getIncSerialNumber().booleanValue() == false)
                        {
                            incSerialNumberAllowed = false;
                        }
                    }

                    if(incSerialNumberAllowed == false)
                    {
                        throw new CertAlreadyIssuedException("Certificate for the given subject " + grandtedSubjectText + " already issued");
                    }

                    do
                    {
                        try
                        {
                            grantedSubject = incSerialNumber(certProfile, grantedSubject);
                        } catch (BadCertTemplateException e)
                        {
                            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, e.getMessage());
                        }
                    }while(certstore.certIssuedForSubject(this.caInfo.getCertificate(), grantedSubject.toString()));
                }
            }
        }

        // check request with the same subject is still in process
        synchronized (pendingSubjectSha1Fps)
        {
            if(pendingSubjectSha1Fps.contains(sha1FpSubject))
            {
                throw new CertAlreadyIssuedException("Certificate for the given subject " + grandtedSubjectText + " already in process");
            }
            pendingSubjectSha1Fps.add(sha1FpSubject);
        }

        try
        {
            StringBuilder msgBuilder = new StringBuilder();

            if(subjectInfo.getWarning() != null)
            {
                msgBuilder.append(", ").append(subjectInfo.getWarning());
            }

            notBefore = certProfile.getNotBefore(notBefore);
            if(notBefore == null)
            {
                notBefore = new Date();
            }

            Integer validity = certProfile.getValidity();
            if(validity == null)
            {
                validity = caInfo.getMaxValidity();
            }
            Date maxNotAfter = new Date(notBefore.getTime() + DAY * validity);

            if(notAfter != null)
            {
                if(notAfter.after(maxNotAfter))
                {
                    notAfter = maxNotAfter;
                    msgBuilder.append(", NotAfter modified");
                }
            }
            else
            {
                notAfter = maxNotAfter;
            }

            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                    caSubjectX500Name,
                    nextSerial(),
                    notBefore,
                    notAfter,
                    grantedSubject,
                    publicKeyInfo);

            CertificateInfo ret;

            try
            {
                String warningMsg = addExtensions(
                        certBuilder,
                        certProfile,
                        origCertProfileConf,
                        requestedSubject,
                        publicKeyInfo,
                        extensions,
                        caInfo.getPublicCAInfo());
                if(warningMsg != null && warningMsg.isEmpty() == false)
                {
                    msgBuilder.append(", ").append(warningMsg);
                }

                ContentSigner contentSigner;
                try
                {
                    contentSigner = caSigner.borrowContentSigner(signserviceTimeout);
                } catch (NoIdleSignerException e)
                {
                    throw new OperationException(ErrorCode.System_Failure, "NoIdleSignerException: " + e.getMessage());
                }

                Certificate bcCert;
                try
                {
                    bcCert = certBuilder.build(contentSigner).toASN1Structure();
                }finally
                {
                    caSigner.returnContentSigner(contentSigner);
                }

                byte[] encodedCert = bcCert.getEncoded();

                X509Certificate cert = (X509Certificate) cf.engineGenerateCertificate(new ByteArrayInputStream(encodedCert));

                try
                {
                    cert.verify(caInfo.getCertificate().getCert().getPublicKey());
                } catch (Exception e)
                {
                    throw new OperationException(ErrorCode.System_Failure, "Signature of created certificate is invalid");
                }

                X509CertificateWithMetaInfo certWithMeta =
                        new X509CertificateWithMetaInfo(cert, encodedCert);

                ret = new CertificateInfo(certWithMeta,
                        caInfo.getCertificate(), publicKeyInfo.getEncoded(),
                        origCertProfileConf == null ? certProfileName : origCertProfileConf.getProfileName());
            } catch (CertificateException e)
            {
                throw new OperationException(ErrorCode.System_Failure, "CertificateException: " + e.getMessage());
            } catch (IOException e)
            {
                throw new OperationException(ErrorCode.System_Failure, "IOException: " + e.getMessage());
            } catch (CertProfileException e)
            {
                throw new OperationException(ErrorCode.System_Failure, "PasswordResolverException: " + e.getMessage());
            } catch (BadCertTemplateException e)
            {
                throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, e.getMessage());
            }

            if(msgBuilder.length() > 0)
            {
                ret.setWarningMessage(msgBuilder.substring(2));
            }

            return ret;
        }finally
        {
            synchronized (pendingSubjectSha1Fps)
            {
                pendingSubjectSha1Fps.remove(sha1FpSubject);
            }
        }
    }

    private BigInteger nextSerial()
    throws OperationException
    {
        synchronized (nextSerialLock)
        {
            long thisSerial = caInfo.getNextSerial();
            long nextSerial = thisSerial + 1;
            caInfo.setNextSerial(nextSerial);
            return BigInteger.valueOf(thisSerial);
        }
    }

    private String addExtensions(X509v3CertificateBuilder certBuilder,
            CertProfile certProfile,
            OriginalProfileConf origCertProfileConf,
            X500Name requestedSubject,
            SubjectPublicKeyInfo requestedPublicKeyInfo,
            org.bouncycastle.asn1.x509.Extensions requestedExtensions,
            PublicCAInfo publicCaInfo)
    throws CertProfileException, BadCertTemplateException, IOException
    {
        addSubjectKeyIdentifier(certBuilder, requestedPublicKeyInfo, certProfile, origCertProfileConf);
        addAuthorityKeyIdentifier(certBuilder, certProfile, origCertProfileConf);
        addAuthorityInformationAccess(certBuilder, certProfile, origCertProfileConf);
        addCRLDistributionPoints(certBuilder, certProfile, origCertProfileConf);

        ExtensionTuples extensionTuples = certProfile.getExtensions(
                requestedSubject, requestedExtensions);
        for(ExtensionTuple extension : extensionTuples.getExtensions())
        {
            certBuilder.addExtension(extension.getType(),
                    extension.isCritical(), extension.getValue());
        }

        return extensionTuples.getWarning();
    }

    public IdentifiedCertProfile getX509CertProfile(String certProfileName)
    {
        if(certProfileName != null)
        {
            Set<String> profileNames = caManager.getCertProfilesForCA(caInfo.getName());
            if(profileNames == null || profileNames.contains(certProfileName) == false)
            {
                return null;
            }

            CertProfileEntry dbEntry = caManager.getCertProfile(certProfileName);
            if(dbEntry != null)
            {
                try
                {
                    return dbEntry.getCertProfile();
                } catch (CertProfileException e)
                {
                    return null;
                }
            }
        }
        return null;
    }

    private void addSubjectKeyIdentifier(
            X509v3CertificateBuilder certBuilder, SubjectPublicKeyInfo publicKeyInfo,
            CertProfile profile, OriginalProfileConf originalProfileConf)
    throws IOException
    {
        ExtensionOccurrence extOccurrence;
        if(originalProfileConf != null && originalProfileConf.isSubjectKeyIdentifierSpecified())
        {
            extOccurrence = originalProfileConf.getSubjectKeyIdentifier();
        }
        else
        {
            extOccurrence = profile.getOccurenceOfSubjectKeyIdentifier();
        }

        if(extOccurrence == null)
        {
            return;
        }

        byte[] skiValue;
        synchronized (sha1)
        {
            skiValue = sha1.digest(publicKeyInfo.getEncoded());
        }
        SubjectKeyIdentifier value = new SubjectKeyIdentifier(skiValue);

        certBuilder.addExtension(Extension.subjectKeyIdentifier, extOccurrence.isCritical(), value);
    }

    private void addAuthorityKeyIdentifier(X509v3CertificateBuilder certBuilder, CertProfile profile,
            OriginalProfileConf originalProfileConf)
    throws IOException
    {
        ExtensionOccurrence extOccurrence;
        if(originalProfileConf != null && originalProfileConf.isAuthorityKeyIdentifierSpecified())
        {
            extOccurrence = originalProfileConf.getAuthorityKeyIdentifier();
        }
        else
        {
            extOccurrence = profile.getOccurenceOfAuthorityKeyIdentifier();
        }

        if(extOccurrence == null)
        {
            return;
        }

        /*
         * TODO: make it configurable
        GeneralNames caSubject = new GeneralNames(new GeneralName(caSubjectX500Name));
        BigInteger caSN = caInfo.getCertificate().getCert().getSerialNumber();
        AuthorityKeyIdentifier value = new AuthorityKeyIdentifier(caSki, caSubject, caSN);
        */

        AuthorityKeyIdentifier value = new AuthorityKeyIdentifier(this.caSKI);

        certBuilder.addExtension(Extension.authorityKeyIdentifier, extOccurrence.isCritical(), value);
    }

    private void addAuthorityInformationAccess(X509v3CertificateBuilder certBuilder, CertProfile profile,
            OriginalProfileConf originalProfileConf)
    throws IOException, CertProfileException
    {
        ExtensionOccurrence extOccurrence;
        if(originalProfileConf != null && originalProfileConf.isAuthorityInfoAccessSpecified())
        {
            extOccurrence = originalProfileConf.getAuthorityInfoAccess();
        }
        else
        {
            extOccurrence = profile.getOccurenceOfAuthorityInfoAccess();
        }

        if(extOccurrence == null)
        {
            return;
        }

        AuthorityInformationAccess value = X509Util.createAuthorityInformationAccess(caInfo.getOcspUris());
        if(value == null)
        {
            if(extOccurrence.isRequired())
            {
                throw new CertProfileException("Could not add required extension authorityInfoAccess");
            }
            return;
        }
        else
        {
            certBuilder.addExtension(Extension.authorityInfoAccess, extOccurrence.isCritical(), value);
        }
    }

    private void addCRLDistributionPoints(X509v3CertificateBuilder certBuilder, CertProfile profile,
            OriginalProfileConf originalProfileConf)
    throws IOException, CertProfileException
    {
        ExtensionOccurrence extOccurrence;
        if(originalProfileConf != null && originalProfileConf.isCRLDisributionPointsSpecified())
        {
            extOccurrence = originalProfileConf.getCRLDisributionPoints();
        }
        else
        {
            extOccurrence = profile.getOccurenceOfCRLDistributinPoints();
        }

        if(extOccurrence == null)
        {
            return;
        }

        List<String> crlUris = caInfo.getCrlUris();
        X500Principal crlSignerSubject = null;
        if(crlSigner != null && crlSigner.getSigner() != null)
        {
            X509Certificate crlSignerCert =  crlSigner.getSigner().getCertificate();
            if(crlSignerCert != null)
            {
                crlSignerSubject = crlSignerCert.getSubjectX500Principal();
            }
        }

        CRLDistPoint value = X509Util.createCRLDistributionPoints(
                crlUris, caInfo.getCertificate().getCert().getSubjectX500Principal(),
                crlSignerSubject);
        if(value == null)
        {
            if(extOccurrence.isRequired())
            {
                throw new CertProfileException("Could not add required extension CRLDistributionPoints");
            }
            return;
        }
        else
        {
            certBuilder.addExtension(Extension.cRLDistributionPoints, extOccurrence.isCritical(), value);
        }
    }

    public CAManagerImpl getCAManager()
    {
        return caManager;
    }

    private class ScheduledCRLGenerationService implements Runnable
    {
        @Override
        public void run()
        {
            try
            {
                generateCRL();
                cleanupCRLs();
            } catch (OperationException e)
            {
            }
        }
    }

    private class ScheduledNextSerialCommitService implements Runnable
    {
        @Override
        public void run()
        {
            try
            {
                commitNextSerial();
            } catch (CAMgmtException e)
            {
                LOG.error("Could not increment the next_serial, CAMgmtException: {}", e.getMessage());
                LOG.debug("Could not increment the next_serial, CAMgmtException", e);
            }
        }
    }

    public synchronized void commitNextSerial()
    throws CAMgmtException
    {
        long nextSerial = caInfo.getNextSerial();
        long lastCommittedNextSerial = caInfo.getLastCommittedNextSerial();
        if(nextSerial > lastCommittedNextSerial)
        {
            caManager.setCANextSerial(caInfo.getName(), nextSerial);
            caInfo.setLastCommittedNextSerial(nextSerial);
            LOG.info("Committed next_serial of ca {} from {} to {}",
                    new Object[]{caInfo.getName(), lastCommittedNextSerial, nextSerial});
        }
    }

    public HealthCheckResult healthCheck()
    {
        HealthCheckResult result = new HealthCheckResult();

        boolean healthy = true;

        boolean caSignerHealthy = caSigner.isHealthy();
        healthy &= caSignerHealthy;
        result.putStatus("Signer.healthy", caSignerHealthy);

        boolean databaseHealthy = certstore.isHealthy();
        healthy &= databaseHealthy;
        result.putStatus("Database.healthy", databaseHealthy);

        if(crlSigner != null && crlSigner.getSigner() != null)
        {
            boolean crlSignerHealthy = crlSigner.getSigner().isHealthy();
            healthy &= crlSignerHealthy;
            result.putStatus("CRLSigner.healthy", crlSignerHealthy);
        }

        for(IdentifiedCertPublisher publisher : getPublishers())
        {
            boolean ph = publisher.isHealthy();
            healthy &= ph;
            result.putStatus("Publisher." + publisher.getName() + ".healthy", ph);
        }

        result.setHealthy(healthy);

        return result;
    }

    private static X500Name incSerialNumber(CertProfile profile, X500Name origName)
    throws BadCertTemplateException
    {
        RDN[] rdns = origName.getRDNs();

        int commonNameIndex = -1;
        int serialNumberIndex = -1;
        for(int i = 0; i < rdns.length; i++)
        {
            RDN rdn = rdns[i];
            ASN1ObjectIdentifier type = rdn.getFirst().getType();
            if(ObjectIdentifiers.id_at_commonName.equals(type))
            {
                commonNameIndex = i;
            }
            else if(ObjectIdentifiers.id_at_serialNumber.equals(type))
            {
                serialNumberIndex = i;
            }
        }

        String currentSerialNumber = null;
        if(serialNumberIndex != -1)
        {
            currentSerialNumber = IETFUtils.valueToString(rdns[serialNumberIndex].getFirst().getValue());
        }
        String newSerialNumber = profile.incSerialNumber(currentSerialNumber);
        RDN serialNumberRdn = new RDN(ObjectIdentifiers.id_at_serialNumber,
                new DERPrintableString(newSerialNumber));

        if(serialNumberIndex != -1)
        {
            rdns[serialNumberIndex] = serialNumberRdn;
            return new X500Name(rdns);
        }
        else
        {
            List<RDN> newRdns = new ArrayList<RDN>(rdns.length+1);

            if(commonNameIndex == -1)
            {
                newRdns.add(serialNumberRdn);
            }

            for(int i = 0; i < rdns.length; i++)
            {
                newRdns.add(rdns[i]);
                if(i == commonNameIndex)
                {
                    newRdns.add(serialNumberRdn);
                }
            }

            return new X500Name(newRdns.toArray(new RDN[0]));
        }
    }

}
