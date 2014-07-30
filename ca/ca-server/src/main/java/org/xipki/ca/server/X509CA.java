/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.SimpleTimeZone;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
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
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.profile.BadCertTemplateException;
import org.xipki.ca.api.profile.BadFormatException;
import org.xipki.ca.api.profile.CertProfileException;
import org.xipki.ca.api.profile.ExtensionOccurrence;
import org.xipki.ca.api.profile.ExtensionTuple;
import org.xipki.ca.api.profile.ExtensionTuples;
import org.xipki.ca.api.profile.SpecialCertProfileBehavior;
import org.xipki.ca.api.profile.SubjectInfo;
import org.xipki.ca.api.profile.X509Util;
import org.xipki.ca.api.publisher.CertPublisherException;
import org.xipki.ca.api.publisher.CertificateInfo;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.ca.server.mgmt.CAEntry;
import org.xipki.ca.server.mgmt.CAManagerImpl;
import org.xipki.ca.server.mgmt.CertProfileEntry;
import org.xipki.ca.server.mgmt.DuplicationMode;
import org.xipki.ca.server.mgmt.PublisherEntry;
import org.xipki.ca.server.store.CertWithRevocationInfo;
import org.xipki.ca.server.store.CertificateStore;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.common.CRLReason;
import org.xipki.security.common.CertRevocationInfo;
import org.xipki.security.common.CustomObjectIdentifiers;
import org.xipki.security.common.HashAlgoType;
import org.xipki.security.common.HashCalculator;
import org.xipki.security.common.HealthCheckResult;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.LogUtil;
import org.xipki.security.common.ObjectIdentifiers;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class X509CA
{
    private static final long MINUTE = 60L * 1000;
    private static long DAY = 24L * 60 * 60 * 1000;

    private static Logger LOG = LoggerFactory.getLogger(X509CA.class);

    private final CertificateFactory cf;

    private final boolean useRandomSerialNumber;
    private final RandomSerialNumberGenerator randomSNGenerator;
    private final CAEntry caInfo;
    private final ConcurrentContentSigner caSigner;
    private final X500Name caSubjectX500Name;
    private final byte[] caSKI;
    private final GeneralNames caSubjectAltName;
    private final CertificateStore certstore;
    private final CrlSigner crlSigner;

    private final CAManagerImpl caManager;
    private final Object nextSerialLock = new Object();
    private final Object crlLock = new Object();
    private Boolean tryXipkiNSStoVerify;

    private final ConcurrentSkipListMap<String, List<String>> pendingSubjectMap = new ConcurrentSkipListMap<>();
    private final ConcurrentSkipListMap<String, List<String>> pendingKeyMap = new ConcurrentSkipListMap<>();

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
            throw new OperationException(ErrorCode.INVALID_EXTENSION,
                    "CA certificate does not have required extension SubjectKeyIdentifier");
        }
        ASN1OctetString ski;
        try
        {
            ski = (ASN1OctetString) X509ExtensionUtil.fromExtensionValue(encodedSkiValue);
        } catch (IOException e)
        {
            throw new OperationException(ErrorCode.INVALID_EXTENSION, e.getMessage());
        }
        this.caSKI = ski.getOctets();

        byte[] encodedSubjectAltName = caCert.getCert().getExtensionValue(Extension.subjectAlternativeName.getId());
        if(encodedSubjectAltName == null)
        {
            this.caSubjectAltName = null;
        }
        else
        {
            try
            {
                this.caSubjectAltName = GeneralNames.getInstance(X509ExtensionUtil.fromExtensionValue(encodedSubjectAltName));
            } catch (IOException e)
            {
                throw new OperationException(ErrorCode.INVALID_EXTENSION, "invalid SubjectAltName extension in CA certificate");
            }
        }

        this.cf = new CertificateFactory();

        if(crlSigner != null && crlSigner.getPeriod() > 0)
        {
            // Add scheduled CRL generation service
            long lastThisUpdate;
            try
            {
                lastThisUpdate = certstore.getThisUpdateOfCurrentCRL(caCert);
            } catch (SQLException e)
            {
                throw new OperationException(ErrorCode.DATABASE_FAILURE, "SQLException: " + e.getMessage());
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
                initialDelay = period - (now - lastThisUpdate) / 60;
            }

            ScheduledCRLGenerationService crlGenerationService = new ScheduledCRLGenerationService();
            caManager.getScheduledThreadPoolExecutor().scheduleAtFixedRate(
                    crlGenerationService, initialDelay, crlSigner.getPeriod(), TimeUnit.MINUTES);
        }

        useRandomSerialNumber = caInfo.getNextSerial() < 1;
        randomSNGenerator = useRandomSerialNumber ? RandomSerialNumberGenerator.getInstance() : null;
        if(useRandomSerialNumber)
        {
            return;
        }

        Long greatestSerialNumber;
        try
        {
            greatestSerialNumber = certstore.getGreatestSerialNumber(caCert);
        } catch (SQLException e)
        {
            throw new OperationException(ErrorCode.DATABASE_FAILURE, "SQLException: " + e.getMessage());
        }

        if(greatestSerialNumber == null)
        {
            throw new OperationException(ErrorCode.DATABASE_FAILURE,
                    "Could not retrieve the greatest serial number for ca " + caInfo.getName());
        }

        if(caInfo.getNextSerial() < greatestSerialNumber + 1)
        {
            LOG.info("Corrected the next_serial of {} from {} to {}",
                    new Object[]{caInfo.getName(), caInfo.getNextSerial(), greatestSerialNumber + 1});
            caInfo.setNextSerial(greatestSerialNumber + 1);
        }

        ScheduledNextSerialCommitService nextSerialCommitService = new ScheduledNextSerialCommitService();
        caManager.getScheduledThreadPoolExecutor().scheduleAtFixedRate(
                nextSerialCommitService, 5, 5, TimeUnit.SECONDS); // commit the next_serial every 5 seconds
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
                throw new OperationException(ErrorCode.System_Failure,
                        e.getClass().getName() + ": " + e.getMessage());
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
            throw new OperationException(ErrorCode.System_Failure,
                    e.getClass().getName() + ": " + e.getMessage());
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
                throw new OperationException(ErrorCode.INSUFFICIENT_PERMISSION,
                        "CRL generation is not allowed");
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

                X509CertificateWithMetaInfo caCert = caInfo.getCertificate();
                List<CertRevocationInfoWithSerial> revInfos;
                boolean isFirstCRLEntry = true;

                Date notExpireAt;
                if(crlSigner.includeExpiredCerts())
                {
                    notExpireAt = new Date(0);
                }
                else
                {
                    // 10 minutes buffer
                    notExpireAt = new Date(thisUpdate.getTime() - 600L * 1000);
                }

                do
                {
                    try
                    {
                        revInfos = certstore.getRevokedCertificates(caCert, notExpireAt,
                                startSerial, numEntries);
                    } catch (SQLException e)
                    {
                        throw new OperationException(ErrorCode.DATABASE_FAILURE, "SQLException: " + e.getMessage());
                    }

                    BigInteger maxSerial = BigInteger.ONE;
                    for(CertRevocationInfoWithSerial revInfo : revInfos)
                    {
                        BigInteger serial = revInfo.getSerial();
                        if(serial.compareTo(maxSerial) > 0)
                        {
                            maxSerial = serial;
                        }

                        CRLReason reason = revInfo.getReason();
                        Date revocationTime = revInfo.getRevocationTime();
                        Date invalidityTime = revInfo.getInvalidityTime();

                        if(directCRL || isFirstCRLEntry == false)
                        {
                            crlBuilder.addCRLEntry(revInfo.getSerial(), revocationTime,
                                    reason.getCode(), invalidityTime);
                        }
                        else
                        {
                            List<Extension> extensions = new ArrayList<>(3);
                            if(reason != CRLReason.UNSPECIFIED)
                            {
                                Extension ext = createReasonExtension(reason.getCode());
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
                    crlNumber = certstore.getNextFreeCRLNumber(caCert);
                }catch(SQLException e)
                {
                    LogUtil.logErrorThrowable(LOG, "getNextFreeCRLNumber", e);
                    throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
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
                            directCRL == false, // indirectCRL,
                            false // onlyContainsAttributeCerts
                            );

                    crlBuilder.addExtension(Extension.issuingDistributionPoint, true, idp);
                } catch (CertIOException e)
                {
                    LogUtil.logErrorThrowable(LOG, "crlBuilder.addExtension", e);
                    throw new OperationException(ErrorCode.INVALID_EXTENSION, e.getMessage());
                }

                startSerial = BigInteger.ONE;
                if(crlSigner.includeCertsInCrl())
                {
                    ASN1EncodableVector vector = new ASN1EncodableVector();

                    List<BigInteger> serials;

                    do
                    {
                        try
                        {
                            serials = certstore.getCertSerials(caCert, notExpireAt, startSerial, numEntries);
                        } catch (SQLException e)
                        {
                            throw new OperationException(ErrorCode.DATABASE_FAILURE, "SQLException: " + e.getMessage());
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
                                certInfo = certstore.getCertificateInfoForSerial(caCert, serial);
                            } catch (SQLException e)
                            {
                                throw new OperationException(ErrorCode.DATABASE_FAILURE,
                                        "SQLException: " + e.getMessage());
                            } catch (CertificateException e)
                            {
                                throw new OperationException(ErrorCode.System_Failure,
                                        "CertificateException: " + e.getMessage());
                            }

                            Certificate cert = Certificate.getInstance(certInfo.getCert().getEncodedCert());

                            ASN1EncodableVector v = new ASN1EncodableVector();
                            v.add(cert);
                            String profileName = certInfo.getProfileName();
                            if(profileName != null && profileName.isEmpty() == false)
                            {
                                v.add(new DERUTF8String(certInfo.getProfileName()));
                            }
                            ASN1Sequence certWithInfo = new DERSequence(v);

                            vector.add(certWithInfo);
                        }

                        startSerial = maxSerial.add(BigInteger.ONE);
                    }while(serials.size() >= numEntries);

                    try
                    {
                        crlBuilder.addExtension(
                                new ASN1ObjectIdentifier(CustomObjectIdentifiers.id_crl_certset),
                                    false, new DERSet(vector));
                    } catch (CertIOException e)
                    {
                        throw new OperationException(ErrorCode.INVALID_EXTENSION,
                                "CertIOException: " + e.getMessage());
                    }
                }

                ConcurrentContentSigner concurrentSigner = (signer == null) ? caSigner : signer;
                ContentSigner contentSigner;
                try
                {
                    contentSigner = concurrentSigner.borrowContentSigner();
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
                    throw new OperationException(ErrorCode.CRL_FAILURE, "CRLException: " + e.getMessage());
                }
            }
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
            return new Extension(Extension.certificateIssuer, true,
                    new GeneralNames(generalName).getEncoded());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error encoding reason: " + e.getMessage(), e);
        }
    }

    public CertificateInfo generateCertificate(boolean requestedByRA,
            String certProfileName,
            String user,
            X500Name subject,
            SubjectPublicKeyInfo publicKeyInfo,
            Date notBefore,
            Date notAfter,
            Extensions extensions)
    throws OperationException
    {
        final String subjectText = IoCertUtil.canonicalizeName(subject);
        LOG.info("START generateCertificate: CA={}, profile={}, subject={}",
                new Object[]{caInfo.getName(), certProfileName, subjectText});

        boolean successfull = false;

        try
        {
            try
            {
                CertificateInfo ret = intern_generateCertificate(requestedByRA,
                        certProfileName, user,
                        subject, publicKeyInfo,
                        notBefore, notAfter, extensions, false);
                successfull = true;

                String prefix = ret.isAlreadyIssued() ? "RETURN_OLD_CERT" : "SUCCESSFULL";
                LOG.info("{} generateCertificate: CA={}, profile={},"
                        + " subject={}, serialNumber={}",
                        new Object[]{prefix, caInfo.getName(), certProfileName,
                            ret.getCert().getSubject(), ret.getCert().getCert().getSerialNumber()});
                return ret;
            }catch(RuntimeException e)
            {
                LogUtil.logWarnThrowable(LOG, "RuntimeException in generateCertificate()", e);
                throw new OperationException(ErrorCode.System_Failure, "RuntimeException:  " + e.getMessage());
            }
        }finally
        {
            if(successfull == false)
            {
                LOG.warn("FAILED generateCertificate: CA={}, profile={}, subject={}",
                        new Object[]{caInfo.getName(), certProfileName, subjectText});
            }
        }
    }

    public CertificateInfo regenerateCertificate(
            boolean requestedByRA,
            String certProfileName,
            String user,
            X500Name subject,
            SubjectPublicKeyInfo publicKeyInfo,
            Date notBefore,
            Date notAfter,
            Extensions extensions)
    throws OperationException
    {
        final String subjectText = IoCertUtil.canonicalizeName(subject);
        LOG.info("START regenerateCertificate: CA={}, profile={}, subject={}",
                new Object[]{caInfo.getName(), certProfileName, subjectText});

        boolean successfull = false;

        try
        {
            CertificateInfo ret = intern_generateCertificate(requestedByRA, certProfileName, user,
                    subject, publicKeyInfo,
                    notBefore, notAfter, extensions, false);
            successfull = true;
            LOG.info("SUCCESSFULL generateCertificate: CA={}, profile={},"
                    + " subject={}, serialNumber={}",
                    new Object[]{caInfo.getName(), certProfileName,
                        ret.getCert().getSubject(), ret.getCert().getCert().getSerialNumber()});

            return ret;
        }catch(RuntimeException e)
        {
            LogUtil.logWarnThrowable(LOG, "RuntimeException in regenerateCertificate()", e);
            throw new OperationException(ErrorCode.System_Failure, "RuntimeException:  " + e.getMessage());
        } finally
        {
            if(successfull == false)
            {
                LOG.warn("FAILED regenerateCertificate: CA={}, profile={}, subject={}",
                        new Object[]{caInfo.getName(), certProfileName, subjectText});
            }
        }
    }

    public boolean publishCertificate(CertificateInfo certInfo)
    {
        if(certInfo.isAlreadyIssued())
        {
            return true;
        }

        if(certstore.addCertificate(certInfo) == false)
        {
            return false;
        }

        for(IdentifiedCertPublisher publisher : getPublishers())
        {
            if(publisher.isAsyn() == false)
            {
                boolean successfull;
                try
                {
                    successfull = publisher.certificateAdded(certInfo);
                }
                catch (RuntimeException re)
                {
                    successfull = false;
                    LogUtil.logWarnThrowable(LOG, "Error while publish certificate to the publisher " +
                            publisher.getName(), re);
                }

                if(successfull)
                {
                    continue;
                }
            }

            Integer certId = certInfo.getCert().getCertId();
            try
            {
                certstore.addToPublishQueue(publisher.getName(), certId.intValue(), caInfo.getCertificate());
            } catch(Throwable t)
            {
                LogUtil.logErrorThrowable(LOG, "Error while add entry to PublishQueue: " + t.getMessage(), t);
                return false;
            }
        }

        return true;
    }

    public boolean republishCertificates(List<String> publisherNames)
    {
        List<IdentifiedCertPublisher> publishers;
        if(publisherNames == null)
        {
            publishers = getPublishers();
        }
        else
        {
            publishers = new ArrayList<>(publisherNames.size());

            for(String publisherName : publisherNames)
            {
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
                publishers.add(publisher);
            }
        }

        if(publishers.isEmpty())
        {
            return true;
        }

        CAStatus status = caInfo.getStatus();

        caInfo.setStatus(CAStatus.INACTIVE);

        // wait till no certificate request in process
        while(pendingSubjectMap.isEmpty() == false || numActiveRevocations.get() > 0)
        {
            LOG.info("Certificate requests are still in process, wait 1 second");
            try
            {
                Thread.sleep(1000);
            }catch(InterruptedException e)
            {
            }
        }

        for(IdentifiedCertPublisher publisher : publishers)
        {
            String name = publisher.getName();
            try
            {
                LOG.info("Clearing PublishQueue for publisher {}", name);
                certstore.clearPublishQueue(this.caInfo.getCertificate(), name);
                LOG.info(" Cleared PublishQueue for publisher {}", name);
            } catch (SQLException e)
            {
                LogUtil.logErrorThrowable(LOG, "Exception while clearing PublishQueue for publisher", e);
            }
        }

        try
        {
            List<BigInteger> serials;
            X509CertificateWithMetaInfo caCert = caInfo.getCertificate();

            Date notExpiredAt = null;

            BigInteger startSerial = BigInteger.ONE;
            int numEntries = 100;

            do
            {
                try
                {
                    serials = certstore.getCertSerials(caCert, notExpiredAt, startSerial, numEntries);
                } catch (SQLException e)
                {
                    LogUtil.logErrorThrowable(LOG, "Exception", e);
                    return false;
                } catch (OperationException e)
                {
                    LogUtil.logErrorThrowable(LOG, "Exception", e);
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
                        certInfo = certstore.getCertificateInfoForSerial(caCert, serial);
                    } catch (SQLException e)
                    {
                        LogUtil.logErrorThrowable(LOG, "Exception", e);
                        return false;
                    } catch (OperationException e)
                    {
                        LogUtil.logErrorThrowable(LOG, "Exception", e);
                        return false;
                    } catch (CertificateException e)
                    {
                        LogUtil.logErrorThrowable(LOG, "Exception", e);
                        return false;
                    }

                    for(IdentifiedCertPublisher publisher : publishers)
                    {
                        boolean successfull = publisher.certificateAdded(certInfo);
                        if(successfull == false)
                        {
                            LOG.error("Republish certificate serial={} to publisher {} failed", serial, publisher.getName());
                            return false;
                        }
                    }
                }

                startSerial = maxSerial.add(BigInteger.ONE);
            } while(serials.size() >= numEntries);

            if(caInfo.getRevocationInfo() != null)
            {
                for(IdentifiedCertPublisher publisher : publishers)
                {
                    boolean successfull = publisher.caRevoked(caInfo.getCertificate(), caInfo.getRevocationInfo());
                    if(successfull == false)
                    {
                       LOG.error("Republish CA revocation to publisher {} failed", publisher.getName());
                       return false;
                    }
                }
            }

            return true;
        } finally
        {
            caInfo.setStatus(status);
        }
    }

    public boolean clearPublishQueue(List<String> publisherNames)
    throws CAMgmtException
    {
        if(publisherNames == null)
        {
            try
            {
                certstore.clearPublishQueue(caInfo.getCertificate(), null);
                return true;
            } catch (SQLException e)
            {
                throw new CAMgmtException(e);
            }
        }

        for(String publisherName : publisherNames)
        {
            try
            {
                certstore.clearPublishQueue(caInfo.getCertificate(), publisherName);
            } catch (SQLException e)
            {
                throw new CAMgmtException(e);
            }
        }

        return true;
    }

    public boolean publishCertsInQueue()
    {
        boolean allSuccessfull = true;
        for(IdentifiedCertPublisher publisher : getPublishers())
        {
            if(publishCertsInQueue(publisher) == false)
            {
                allSuccessfull = false;
            }
        }

        return allSuccessfull;
    }

    private boolean publishCertsInQueue(IdentifiedCertPublisher publisher)
    {
        X509CertificateWithMetaInfo caCert = caInfo.getCertificate();

        final int numEntries = 500;

        while(true)
        {
            List<Integer> certIds;
            try
            {
                certIds = certstore.getPublishQueueEntries(caCert, publisher.getName(), numEntries);
            } catch (SQLException e)
            {
                LogUtil.logErrorThrowable(LOG, "Exception", e);
                return false;
            } catch (OperationException e)
            {
                LogUtil.logErrorThrowable(LOG, "Exception", e);
                return false;
            }

            if(certIds == null || certIds.isEmpty())
            {
                break;
            }

            for(Integer certId : certIds)
            {
                CertificateInfo certInfo;

                try
                {
                    certInfo = certstore.getCertificateInfoForId(caCert, certId);
                } catch (SQLException e)
                {
                    LogUtil.logErrorThrowable(LOG, "", e);
                    return false;
                } catch (OperationException e)
                {
                    LogUtil.logErrorThrowable(LOG, "", e);
                    return false;
                } catch (CertificateException e)
                {
                    LogUtil.logErrorThrowable(LOG, "", e);
                    return false;
                }

                boolean successfull = publisher.certificateAdded(certInfo);
                if(successfull)
                {
                    try
                    {
                        certstore.removeFromPublishQueue(publisher.getName(), certId);
                    } catch (SQLException e)
                    {
                        LogUtil.logWarnThrowable(LOG, "SQLException while removing republished cert id=" + certId +
                                " and publisher=" + publisher.getName(), e);
                        continue;
                    }
                }
                else
                {
                    LOG.error("Republish certificate id={} failed", certId);
                    return false;
                }
            }
        }

        return true;
    }

    private boolean publishCRL(X509CRL crl)
    {
        X509CertificateWithMetaInfo caCert = caInfo.getCertificate();
        if(certstore.addCRL(caCert, crl) == false)
        {
            return false;
        }

        for(IdentifiedCertPublisher publisher : getPublishers())
        {
            try
            {
                publisher.crlAdded(caCert, crl);
            }
            catch (RuntimeException re)
            {
                LogUtil.logErrorThrowable(LOG, "Error while publish CRL to the publisher " + publisher.getName(), re);
            }
        }

        return true;
    }

    public CertWithRevocationInfo revokeCertificate(BigInteger serialNumber,
            CRLReason reason, Date invalidityTime)
    throws OperationException
    {
        if(caInfo.isSelfSigned() && caInfo.getSerialNumber().equals(serialNumber))
        {
            throw new OperationException(ErrorCode.INSUFFICIENT_PERMISSION,
                    "Not allow to revoke CA certificate");
        }

        if(reason == null)
        {
            reason = CRLReason.UNSPECIFIED;
        }

        switch(reason)
        {
            case CA_COMPROMISE:
            case AA_COMPROMISE:
            case REMOVE_FROM_CRL:
                throw new OperationException(ErrorCode.INSUFFICIENT_PERMISSION,
                        "Not allow to revoke certificate with reason " + reason.getDescription());
            case UNSPECIFIED:
            case KEY_COMPROMISE:
            case AFFILIATION_CHANGED:
            case SUPERSEDED:
            case CESSATION_OF_OPERATION:
            case CERTIFICATE_HOLD:
            case PRIVILEGE_WITHDRAWN:
                break;
        }
        return do_revokeCertificate(serialNumber, reason, invalidityTime, false);
    }

    public X509CertificateWithMetaInfo unrevokeCertificate(BigInteger serialNumber)
    throws OperationException
    {
        if(caInfo.isSelfSigned() && caInfo.getSerialNumber().equals(serialNumber))
        {
            throw new OperationException(ErrorCode.INSUFFICIENT_PERMISSION,
                    "Not allow to unrevoke CA certificate");
        }

        return do_unrevokeCertificate(serialNumber, false);
    }

    public X509CertificateWithMetaInfo removeCertificate(BigInteger serialNumber)
    throws OperationException
    {
        if(caInfo.isSelfSigned() && caInfo.getSerialNumber().equals(serialNumber))
        {
            throw new OperationException(ErrorCode.INSUFFICIENT_PERMISSION,
                    "Not allow to remove CA certificate");
        }

        X509CertificateWithMetaInfo removedCert =
                certstore.removeCertificate(caInfo.getCertificate(), serialNumber);
        if(removedCert != null)
        {
            for(IdentifiedCertPublisher publisher : getPublishers())
            {
                boolean successfull;
                try
                {
                    successfull = publisher.certificateRemoved(caInfo.getCertificate(), removedCert);
                }
                catch (RuntimeException re)
                {
                    successfull = false;
                    LogUtil.logWarnThrowable(LOG, "Error while remove certificate to the publisher " + publisher.getName(),
                            re);
                }

                if(successfull == false)
                {
                    X509Certificate c = removedCert.getCert();
                    LOG.error("Removing certificate issuer={}, serial={}, subject={} from publisher {} failed."
                            + " Please remove it manually",
                            new Object[]
                            {
                                    IoCertUtil.canonicalizeName(c.getIssuerX500Principal()),
                                    c.getSerialNumber(),
                                    IoCertUtil.canonicalizeName(c.getSubjectX500Principal()),
                                    publisher.getName()});
                }
            }
        }

        return removedCert;
    }

    private CertWithRevocationInfo do_revokeCertificate(BigInteger serialNumber,
            CRLReason reason, Date invalidityTime, boolean force)
    throws OperationException
    {
        LOG.info("START revokeCertificate: ca={}, serialNumber={}, reason={}, invalidityTime={}",
                new Object[]{caInfo.getName(), serialNumber, reason.getDescription(), invalidityTime});

        numActiveRevocations.addAndGet(1);
        CertWithRevocationInfo revokedCert = null;

        try
        {
            CertRevocationInfo revInfo = new CertRevocationInfo(reason, new Date(), invalidityTime);
            revokedCert = certstore.revokeCertificate(
                    caInfo.getCertificate(),
                    serialNumber, revInfo, force);
            if(revokedCert == null)
            {
                return null;
            }

            for(IdentifiedCertPublisher publisher : getPublishers())
            {
                if(publisher.isAsyn() == false)
                {
                    boolean successfull;
                    try
                    {
                        successfull = publisher.certificateRevoked(caInfo.getCertificate(),
                                revokedCert.getCert(), revokedCert.getRevInfo());
                    }
                    catch (RuntimeException re)
                    {
                        successfull = false;
                        String msg = "Error while publish revocation of certificate to the publisher " + publisher.getName();
                        LogUtil.logErrorThrowable(LOG, msg, re);
                    }

                    if(successfull)
                    {
                        continue;
                    }
                }

                Integer certId = revokedCert.getCert().getCertId();
                try
                {
                    certstore.addToPublishQueue(publisher.getName(), certId.intValue(), caInfo.getCertificate());
                }catch(Throwable t)
                {
                    LogUtil.logErrorThrowable(LOG, "Error while add entry to PublishQueue", t);
                }
            }
        } finally
        {
            numActiveRevocations.addAndGet(-1);
        }

        String resultText = revokedCert == null ? "CERT_NOT_EXIST" : "REVOKED";
        LOG.info("SUCCESSFULL revokeCertificate: ca={}, serialNumber={}, reason={},"
                + " invalidityTime={}, revocationResult={}",
                new Object[]{caInfo.getName(), serialNumber, reason.getDescription(),
                        invalidityTime, resultText});

        return revokedCert;
    }

    private X509CertificateWithMetaInfo do_unrevokeCertificate(BigInteger serialNumber, boolean force)
    throws OperationException
    {
        LOG.info("START unrevokeCertificate: ca={}, serialNumber={}", caInfo.getName(), serialNumber);

        numActiveRevocations.addAndGet(1);
        X509CertificateWithMetaInfo unrevokedCert = null;

        try
        {
            unrevokedCert = certstore.unrevokeCertificate(caInfo.getCertificate(), serialNumber, force);
            if(unrevokedCert == null)
            {
                return null;
            }

            for(IdentifiedCertPublisher publisher : getPublishers())
            {
                if(publisher.isAsyn())
                {
                    boolean successfull;
                    try
                    {
                        successfull = publisher.certificateUnrevoked(caInfo.getCertificate(), unrevokedCert);
                    }
                    catch (RuntimeException re)
                    {
                        successfull = false;
                        String msg = "Error while publish unrevocation of certificate to the publisher " + publisher.getName();
                        LogUtil.logErrorThrowable(LOG, msg, re);
                    }

                    if(successfull)
                    {
                        continue;
                    }
                }

                Integer certId = unrevokedCert.getCertId();
                try
                {
                    certstore.addToPublishQueue(publisher.getName(), certId.intValue(), caInfo.getCertificate());
                }catch(Throwable t)
                {
                    LogUtil.logErrorThrowable(LOG, "Error while add entry to PublishQueue", t);
                }
            }
        } finally
        {
            numActiveRevocations.addAndGet(-1);
        }

        String resultText = unrevokedCert == null ? "CERT_NOT_EXIST" : "UNREVOKED";
        LOG.info("SUCCESSFULL unrevokeCertificate: ca={}, serialNumber={}, revocationResult={}",
                new Object[]{caInfo.getName(), serialNumber, resultText});

        return unrevokedCert;
    }

    public void revoke(CertRevocationInfo revocationInfo)
    throws OperationException
    {
        ParamChecker.assertNotNull("revocationInfo", revocationInfo);

        caInfo.setRevocationInfo(revocationInfo);
        if(caInfo.isSelfSigned())
        {
            do_revokeCertificate(caInfo.getSerialNumber(), revocationInfo.getReason(),
                revocationInfo.getInvalidityTime(), true);
        }

        for(IdentifiedCertPublisher publisher : getPublishers())
        {
            try
            {
                boolean successfull = publisher.caRevoked(caInfo.getCertificate(), revocationInfo);
                if(successfull == false)
                {
                    throw new OperationException(ErrorCode.System_Failure, "Publishing CA revocation failed");
                }
            }
            catch (RuntimeException re)
            {
                String msg = "Error while publish revocation of CA to the publisher " + publisher.getName();
                LogUtil.logErrorThrowable(LOG, msg, re);
                throw new OperationException(ErrorCode.System_Failure, msg);
            }
        }
    }

    public void unrevoke()
    throws OperationException
    {
        caInfo.setRevocationInfo(null);
        if(caInfo.isSelfSigned())
        {
            do_unrevokeCertificate(caInfo.getSerialNumber(), true);
        }

        for(IdentifiedCertPublisher publisher : getPublishers())
        {
            try
            {
                boolean successfull = publisher.caUnrevoked(caInfo.getCertificate());
                if(successfull == false)
                {
                    throw new OperationException(ErrorCode.System_Failure, "Publishing CA revocation failed");
                }
            }
            catch (RuntimeException re)
            {
                String msg = "Error while publish revocation of CA to the publisher " + publisher.getName();
                LogUtil.logErrorThrowable(LOG, msg, re);
                throw new OperationException(ErrorCode.System_Failure, msg);
            }
        }
    }

    private List<IdentifiedCertPublisher> getPublishers()
    {
        List<PublisherEntry> dbEntries = caManager.getPublishersForCA(caInfo.getName());

        List<IdentifiedCertPublisher> publishers = new ArrayList<>(dbEntries.size());
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

    private CertificateInfo intern_generateCertificate(boolean requestedByRA,
            String certProfileName,
            String user,
            X500Name requestedSubject,
            SubjectPublicKeyInfo publicKeyInfo,
            Date notBefore,
            Date notAfter,
            org.bouncycastle.asn1.x509.Extensions extensions,
            boolean keyUpdate)
    throws OperationException
    {
        IdentifiedCertProfile certProfile = getX509CertProfile(certProfileName);

        if(certProfile == null)
        {
            throw new OperationException(ErrorCode.UNKNOWN_CERT_PROFILE, "unknown cert profile " + certProfileName);
        }

        if(certProfile.isOnlyForRA() && requestedByRA == false)
        {
            throw new OperationException(ErrorCode.INSUFFICIENT_PERMISSION,
                    "Profile " + certProfileName + " not applied to non-RA");
        }

        notBefore = certProfile.getNotBefore(notBefore);
        Date now = new Date();
        if(notBefore == null)
        {
            notBefore = now;
        }

        long t = caInfo.getNoNewCertificateAfter();
        if(notBefore.getTime() > t || now.getTime() > t)
        {
            throw new OperationException(ErrorCode.NOT_PERMITTED,
                    "CA is not permitted to issue certifate after " + new Date(t));
        }

        publicKeyInfo = IoCertUtil.toRfc3279Style(publicKeyInfo);

        // public key
        try
        {
            certProfile.checkPublicKey(publicKeyInfo);
        } catch (BadCertTemplateException e)
        {
            throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE, e.getMessage());
        }

        Date gSMC_KFirstNotBefore = null;
        if(certProfile.getSpecialCertProfileBehavior() == SpecialCertProfileBehavior.gematik_gSMC_K)
        {
            gSMC_KFirstNotBefore = notBefore;

            RDN[] cnRDNs = requestedSubject.getRDNs(ObjectIdentifiers.DN_CN);
            if(cnRDNs != null && cnRDNs.length > 0)
            {
                String requestedCN = IETFUtils.valueToString(cnRDNs[0].getFirst().getValue());
                try
                {
                    Long gsmckFirstNotBeforeInSecond = certstore.getNotBeforeOfFirstCertStartsWithCN(
                            requestedCN, certProfileName);
                    if(gsmckFirstNotBeforeInSecond != null)
                    {
                        gSMC_KFirstNotBefore = new Date(gsmckFirstNotBeforeInSecond * 1000);
                    }
                } catch (SQLException e)
                {
                    LOG.debug("Error in certstore.getSubjectDNsContainsCN()", e);
                    throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
                }

                // append the commonName with '-' + yyyyMMdd
                SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMdd");
                dateF.setTimeZone(new SimpleTimeZone(0,"Z"));
                String yyyyMMdd = dateF.format(gSMC_KFirstNotBefore);
                String suffix = "-" + yyyyMMdd;

                // append the -YYYYMMDD to the commonName
                RDN[] rdns = requestedSubject.getRDNs();
                for(int i = 0; i < rdns.length; i++)
                {
                    if(ObjectIdentifiers.DN_CN.equals(rdns[i].getFirst().getType()))
                    {
                        rdns[i] = new RDN(ObjectIdentifiers.DN_CN, new DERUTF8String(requestedCN + suffix));
                    }
                }
                requestedSubject = new X500Name(rdns);
            }
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
            throw new OperationException(ErrorCode.ALREADY_ISSUED,
                    "Certificate with the same subject as CA is not allowed");
        }

        DuplicationMode keyMode = caInfo.getDuplicateKeyMode();
        if(keyMode == DuplicationMode.PERMITTED && certProfile.isDuplicateKeyPermitted() == false)
        {
            keyMode = DuplicationMode.FORBIDDEN_WITHIN_PROFILE;
        }

        DuplicationMode subjectMode = caInfo.getDuplicateSubjectMode();
        if(subjectMode == DuplicationMode.PERMITTED && certProfile.isDuplicateSubjectPermitted() == false)
        {
            subjectMode = DuplicationMode.FORBIDDEN_WITHIN_PROFILE;
        }

        String sha1FpSubject = IoCertUtil.sha1sum_canonicalized_name(grantedSubject);
        String grandtedSubjectText = IoCertUtil.canonicalizeName(grantedSubject);

        byte[] subjectPublicKeyData =  publicKeyInfo.getPublicKeyData().getBytes();
        String sha1FpPublicKey = IoCertUtil.sha1sum(subjectPublicKeyData);

        if(keyUpdate)
        {
            CertStatus certStatus = certstore.getCertStatusForSubject(caInfo.getCertificate(), grantedSubject);
            if(certStatus == CertStatus.Revoked)
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
            SubjectKeyProfileTripleCollection triples;
            try
            {
                triples = certstore.getSubjectKeyProfileTriples(
                        caInfo.getCertificate(), sha1FpSubject, sha1FpPublicKey);
            } catch (SQLException e)
            {
                throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
            }

            if(triples != null && triples.isEmpty() == false)
            {
                SubjectKeyProfileTriple triple = triples.getFirstTriple(sha1FpSubject, sha1FpPublicKey, certProfileName);
                if(triple != null)
                {
                    /*
                     * If there exists a certificate whose public key, subject and profile match the request,
                     * returns the certificate if it is not revoked, otherwise OperationException with
                     * ErrorCode CERT_REVOKED will be thrown
                     */

                    if(triple.isRevoked())
                    {
                        throw new OperationException(ErrorCode.CERT_REVOKED);
                    }
                    else
                    {
                        X509CertificateWithMetaInfo issuedCert;
                        try
                        {
                            issuedCert = certstore.getCertForId(triple.getCertId());
                        } catch (SQLException e)
                        {
                            throw new OperationException(ErrorCode.DATABASE_FAILURE, e.getMessage());
                        }

                        if(issuedCert == null)
                        {
                            throw new OperationException(ErrorCode.System_Failure,
                                "Find no certificate in table RAWCERT for CERT_ID " + triple.getCertId());
                        }
                        else
                        {
                            CertificateInfo certInfo;
                            try
                            {
                                certInfo = new CertificateInfo(issuedCert,
                                        caInfo.getCertificate(), subjectPublicKeyData, certProfileName);
                            } catch (CertificateEncodingException e)
                            {
                                 throw new OperationException(ErrorCode.System_Failure,
                                         "could not construct CertificateInfo: " + e.getMessage());
                            }
                            certInfo.setAlreadyIssued(true);
                            return certInfo;
                        }
                    }
                }

                if(keyMode == DuplicationMode.PERMITTED && subjectMode == DuplicationMode.PERMITTED)
                {
                }
                else if(triples.hasTripleForSubjectAndProfile(sha1FpSubject, certProfileName))
                {
                    if(subjectMode == DuplicationMode.FORBIDDEN || subjectMode == DuplicationMode.FORBIDDEN_WITHIN_PROFILE)
                    {
                        if(certProfile.incSerialNumberIfSubjectExists() == false)
                        {
                            throw new OperationException(ErrorCode.ALREADY_ISSUED,
                                    "Certificate for the given subject " + grandtedSubjectText +
                                    " and profile " + certProfileName + " already issued");
                        }

                        String latestSN;
                        try
                        {
                            Object[] objs = incSerialNumber(certProfile, grantedSubject, null);
                            latestSN = certstore.getLatestSN((X500Name) objs[0]);
                        }catch(BadFormatException e)
                        {
                            throw new OperationException(ErrorCode.System_Failure, "BadFormatException: " + e.getMessage());
                        }

                        boolean foundUniqueSubject = false;
                        // maximal 100 tries
                        for(int i = 0; i < 100; i++)
                        {
                            try
                            {
                                Object[] objs = incSerialNumber(certProfile, grantedSubject, latestSN);
                                grantedSubject = (X500Name) objs[0];
                                latestSN = (String) objs[1];
                            }catch (BadFormatException e)
                            {
                                throw new OperationException(ErrorCode.System_Failure, "BadFormatException: " + e.getMessage());
                            }

                            foundUniqueSubject = (certstore.certIssuedForSubject(caInfo.getCertificate(),
                                        IoCertUtil.sha1sum_canonicalized_name(grantedSubject)) == false);
                            if(foundUniqueSubject)
                            {
                                break;
                            }
                        }

                        if(foundUniqueSubject == false)
                        {
                            throw new OperationException(ErrorCode.ALREADY_ISSUED,
                                    "Certificate for the given subject " + grandtedSubjectText +
                                    " and profile " + certProfileName +
                                    " already issued, and could not create new unique serial number");
                        }
                    }
                }
                else if(triples.hasTripleForKeyAndProfile(sha1FpPublicKey, certProfileName))
                {
                    if(keyMode == DuplicationMode.FORBIDDEN || keyMode == DuplicationMode.FORBIDDEN_WITHIN_PROFILE)
                    {
                        throw new OperationException(ErrorCode.ALREADY_ISSUED,
                                "Certificate for the given public key and profile " + certProfileName + " already issued");
                    }
                }
                else if(triples.hasTripleForSubjectAndKey(sha1FpSubject, sha1FpPublicKey))
                {
                    if(keyMode == DuplicationMode.FORBIDDEN || subjectMode == DuplicationMode.FORBIDDEN)
                    {
                        throw new OperationException(ErrorCode.ALREADY_ISSUED,
                                "Certificate for the given subject and public key already issued");
                    }
                }
                else if(triples.hasTripleForKey(sha1FpPublicKey))
                {
                    if(keyMode == DuplicationMode.FORBIDDEN)
                    {
                        throw new OperationException(ErrorCode.ALREADY_ISSUED,
                                "Certificate for the given public key already issued");
                    }
                }
                else if(triples.hasTripleForSubject(sha1FpSubject))
                {
                    if(subjectMode == DuplicationMode.FORBIDDEN)
                    {
                        throw new OperationException(ErrorCode.ALREADY_ISSUED,
                                "Certificate for the given subject already issued");
                    }
                }
                else
                {
                    throw new OperationException(ErrorCode.System_Failure, "should not reach here");
                }
            }
        }

        if(certProfile.isSerialNumberInReqPermitted() == false)
        {
            RDN[] rdns = requestedSubject.getRDNs(ObjectIdentifiers.DN_SN);
            if(rdns != null && rdns.length > 0)
            {
                throw new OperationException(ErrorCode.BAD_CERT_TEMPLATE,
                        "SubjectDN SerialNumber in request is not permitted");
            }
        }

        if(subjectMode == DuplicationMode.FORBIDDEN || subjectMode == DuplicationMode.FORBIDDEN_WITHIN_PROFILE)
        {
            synchronized (pendingSubjectMap)
            {
                // check request with the same subject is still in process
                if(subjectMode == DuplicationMode.FORBIDDEN)
                {
                    if(pendingSubjectMap.containsKey(sha1FpSubject))
                    {
                        throw new OperationException(ErrorCode.ALREADY_ISSUED,
                                "Certificate for the given subject " + grandtedSubjectText + " already in process");
                    }
                }
                else if(subjectMode == DuplicationMode.FORBIDDEN_WITHIN_PROFILE)
                {
                    if(pendingSubjectMap.containsKey(sha1FpSubject) &&
                            pendingSubjectMap.get(sha1FpSubject).contains(certProfileName))
                    {
                        throw new OperationException(ErrorCode.ALREADY_ISSUED,
                               "Certificate for the given subject " + grandtedSubjectText +
                               " and profile " + certProfileName + " already in process");
                    }
                }
            }
        }

        if(keyMode == DuplicationMode.FORBIDDEN || keyMode == DuplicationMode.FORBIDDEN_WITHIN_PROFILE)
        {
            synchronized (pendingSubjectMap)
            {
                // check request with the same subject is still in process
                if(keyMode == DuplicationMode.FORBIDDEN)
                {
                    if(pendingKeyMap.containsKey(sha1FpPublicKey))
                    {
                        throw new OperationException(ErrorCode.ALREADY_ISSUED,
                                "Certificate for the given public key already in process");
                    }
                }
                else if(keyMode == DuplicationMode.FORBIDDEN_WITHIN_PROFILE)
                {
                    if(pendingKeyMap.containsKey(sha1FpPublicKey) &&
                            pendingKeyMap.get(sha1FpPublicKey).contains(certProfileName))
                    {
                        throw new OperationException(ErrorCode.ALREADY_ISSUED,
                               "Certificate for the given public key" +
                               " and profile " + certProfileName + " already in process");
                    }
                }
            }
        }

        try
        {
            if(subjectMode == DuplicationMode.FORBIDDEN || subjectMode == DuplicationMode.FORBIDDEN_WITHIN_PROFILE)
            {
                synchronized (pendingSubjectMap)
                {
                    List<String> profiles = pendingSubjectMap.get(sha1FpSubject);
                    if(profiles == null)
                    {
                        profiles = new LinkedList<>();
                        pendingSubjectMap.put(sha1FpSubject, profiles);
                    }
                    profiles.add(certProfileName);
                }
            }

            if(keyMode == DuplicationMode.FORBIDDEN || keyMode == DuplicationMode.FORBIDDEN_WITHIN_PROFILE)
            {
                synchronized (pendingSubjectMap)
                {
                    List<String> profiles = pendingKeyMap.get(sha1FpSubject);
                    if(profiles == null)
                    {
                        profiles = new LinkedList<>();
                        pendingKeyMap.put(sha1FpPublicKey, profiles);
                    }
                    profiles.add(certProfileName);
                }
            }

            StringBuilder msgBuilder = new StringBuilder();

            if(subjectInfo.getWarning() != null)
            {
                msgBuilder.append(", ").append(subjectInfo.getWarning());
            }

            Integer validity = certProfile.getValidity();
            if(validity == null)
            {
                validity = caInfo.getMaxValidity();
            }

            Date maxNotAfter = new Date(notBefore.getTime() + DAY * validity);
            if(certProfile.getSpecialCertProfileBehavior() == SpecialCertProfileBehavior.gematik_gSMC_K)
            {
                String s = certProfile.getParameter(SpecialCertProfileBehavior.PARAMETER_MAXLIFTIME);
                long maxLifetimeInDays = Long.parseLong(s);
                Date maxLifetime = new Date(gSMC_KFirstNotBefore.getTime() + maxLifetimeInDays * DAY);
                if(maxNotAfter.after(maxLifetime))
                {
                    maxNotAfter = maxLifetime;
                }
            }

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
                    contentSigner = caSigner.borrowContentSigner();
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

                X509Certificate cert = (X509Certificate) cf.engineGenerateCertificate(
                        new ByteArrayInputStream(encodedCert));
                if(verifySignature(cert) == false)
                {
                     throw new OperationException(ErrorCode.System_Failure,
                             "Could not verify the signature of generated certificate");
                }

                X509CertificateWithMetaInfo certWithMeta = new X509CertificateWithMetaInfo(cert, encodedCert);

                ret = new CertificateInfo(certWithMeta, caInfo.getCertificate(),
                        subjectPublicKeyData, certProfileName);
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

            if(msgBuilder.length() > 2)
            {
                ret.setWarningMessage(msgBuilder.substring(2));
            }

            return ret;
        }finally
        {
            synchronized (pendingSubjectMap)
            {
                List<String> profiles = pendingSubjectMap.remove(sha1FpSubject);
                if(profiles != null)
                {
                    profiles.remove(certProfileName);
                    if(profiles.isEmpty() == false)
                    {
                        pendingSubjectMap.put(sha1FpSubject, profiles);
                    }
                }

                profiles = pendingKeyMap.remove(sha1FpSubject);
                if(profiles != null)
                {
                    profiles.remove(certProfileName);
                    if(profiles.isEmpty() == false)
                    {
                        pendingKeyMap.put(sha1FpSubject, profiles);
                    }
                }
            }
        }
    }

    private BigInteger nextSerial()
    throws OperationException
    {
        synchronized (nextSerialLock)
        {
            if(useRandomSerialNumber)
            {
                return randomSNGenerator.getSerialNumber();
            }
            else
            {
                long thisSerial = caInfo.getNextSerial();
                long nextSerial = thisSerial + 1;
                caInfo.setNextSerial(nextSerial);
                return BigInteger.valueOf(thisSerial);
            }
        }
    }

    private String addExtensions(X509v3CertificateBuilder certBuilder,
            IdentifiedCertProfile certProfile,
            X500Name requestedSubject,
            SubjectPublicKeyInfo requestedPublicKeyInfo,
            org.bouncycastle.asn1.x509.Extensions requestedExtensions,
            PublicCAInfo publicCaInfo)
    throws CertProfileException, BadCertTemplateException, IOException
    {
        addSubjectKeyIdentifier(certBuilder, requestedPublicKeyInfo, certProfile);
        addAuthorityKeyIdentifier(certBuilder, certProfile);
        addAuthorityInformationAccess(certBuilder, certProfile);
        addCRLDistributionPoints(certBuilder, certProfile);
        addDeltaCRLDistributionPoints(certBuilder, certProfile);
        addIssuerAltName(certBuilder, certProfile);

        ExtensionTuples extensionTuples = certProfile.getExtensions(requestedSubject, requestedExtensions);
        for(ExtensionTuple extension : extensionTuples.getExtensions())
        {
            certBuilder.addExtension(extension.getType(), extension.isCritical(), extension.getValue());
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
            IdentifiedCertProfile profile)
    throws IOException
    {
        ExtensionOccurrence extOccurrence = profile.getOccurenceOfSubjectKeyIdentifier();
        if(extOccurrence == null)
        {
            return;
        }

        byte[] data = publicKeyInfo.getPublicKeyData().getBytes();
        byte[] skiValue = HashCalculator.hash(HashAlgoType.SHA1, data);
        SubjectKeyIdentifier value = new SubjectKeyIdentifier(skiValue);

        certBuilder.addExtension(Extension.subjectKeyIdentifier, extOccurrence.isCritical(), value);
    }

    private void addAuthorityKeyIdentifier(X509v3CertificateBuilder certBuilder, IdentifiedCertProfile profile)
    throws IOException
    {
        ExtensionOccurrence extOccurrence = profile.getOccurenceOfAuthorityKeyIdentifier();
        if(extOccurrence == null)
        {
            return;
        }

        AuthorityKeyIdentifier value;
        if(profile.includeIssuerAndSerialInAKI())
        {
            GeneralNames caSubject = new GeneralNames(new GeneralName(caSubjectX500Name));
            BigInteger caSN = caInfo.getCertificate().getCert().getSerialNumber();
            value = new AuthorityKeyIdentifier(this.caSKI, caSubject, caSN);
        }
        else
        {
            value = new AuthorityKeyIdentifier(this.caSKI);
        }

        certBuilder.addExtension(Extension.authorityKeyIdentifier, extOccurrence.isCritical(), value);
    }

    private void addIssuerAltName(X509v3CertificateBuilder certBuilder, IdentifiedCertProfile profile)
    throws IOException, CertProfileException
    {
        ExtensionOccurrence extOccurrence = profile.getOccurenceOfIssuerAltName();
        if(extOccurrence == null)
        {
            return;
        }

        if(caSubjectAltName == null)
        {
            if(extOccurrence.isRequired())
            {
                throw new CertProfileException("Could not add required extension issuerAltName");
            }
        }
        else
        {
            certBuilder.addExtension(Extension.issuerAlternativeName, extOccurrence.isCritical(), caSubjectAltName);
        }
    }

    private void addAuthorityInformationAccess(X509v3CertificateBuilder certBuilder, IdentifiedCertProfile profile)
    throws IOException, CertProfileException
    {
        ExtensionOccurrence extOccurrence = profile.getOccurenceOfAuthorityInfoAccess();
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

    private void addCRLDistributionPoints(X509v3CertificateBuilder certBuilder, IdentifiedCertProfile profile)
    throws IOException, CertProfileException
    {
        ExtensionOccurrence extOccurrence = profile.getOccurenceOfCRLDistributinPoints();
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

    private void addDeltaCRLDistributionPoints(X509v3CertificateBuilder certBuilder, IdentifiedCertProfile profile)
    throws IOException, CertProfileException
    {
        ExtensionOccurrence extOccurrence = profile.getOccurenceOfFreshestCRL();
        if(extOccurrence == null)
        {
            return;
        }

        List<String> uris = caInfo.getDeltaCrlUris();
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
                uris, caInfo.getCertificate().getCert().getSubjectX500Principal(),
                crlSignerSubject);
        if(value == null)
        {
            if(extOccurrence.isRequired())
            {
                throw new CertProfileException("Could not add required extension FreshestCRL");
            }
            return;
        }
        else
        {
            certBuilder.addExtension(Extension.deltaCRLIndicator, extOccurrence.isCritical(), value);
        }
    }

    public CAManagerImpl getCAManager()
    {
        return caManager;
    }

    private class ScheduledCRLGenerationService implements Runnable
    {
        private boolean inProcess = false;
        @Override
        public void run()
        {
            if(inProcess)
            {
                return;
            }

            inProcess = true;
            try
            {
                generateCRL();
                cleanupCRLs();
            } catch (OperationException e)
            {
            } finally
            {
                inProcess = false;
            }

        }
    }

    private class ScheduledNextSerialCommitService implements Runnable
    {
        private boolean inProcess = false;
        @Override
        public void run()
        {
            if(inProcess)
            {
                return;
            }

            inProcess = true;
            try
            {
                commitNextSerial();
            } catch (Throwable t)
            {
                LogUtil.logErrorThrowable(LOG, "Could not increment the next_serial", t);
            } finally
            {
                inProcess = false;
            }

        }
    }

    public synchronized void commitNextSerial()
    throws CAMgmtException
    {
        if(useRandomSerialNumber)
        {
            return;
        }
        long nextSerial = caInfo.getNextSerial();
        long lastCommittedNextSerial = caInfo.getLastCommittedNextSerial();
        if(nextSerial > lastCommittedNextSerial)
        {
            caManager.setCANextSerial(caInfo.getName(), nextSerial);
            caInfo.setLastCommittedNextSerial(nextSerial);
            LOG.debug("Committed next_serial of ca {} from {} to {}",
                    new Object[]{caInfo.getName(), lastCommittedNextSerial, nextSerial});
        }
    }

    public HealthCheckResult healthCheck()
    {
        HealthCheckResult result = new HealthCheckResult("X509CA");

        boolean healthy = true;

        boolean caSignerHealthy = caSigner.isHealthy();
        healthy &= caSignerHealthy;

        HealthCheckResult signerHealth = new HealthCheckResult("Signer");
        signerHealth.setHealthy(caSignerHealthy);
        result.addChildCheck(signerHealth);

        boolean databaseHealthy = certstore.isHealthy();
        healthy &= databaseHealthy;

        HealthCheckResult databaseHealth = new HealthCheckResult("Database");
        databaseHealth.setHealthy(databaseHealthy);
        result.addChildCheck(databaseHealth);

        if(crlSigner != null && crlSigner.getSigner() != null)
        {
            boolean crlSignerHealthy = crlSigner.getSigner().isHealthy();
            healthy &= crlSignerHealthy;

            HealthCheckResult crlSignerHealth = new HealthCheckResult("CRLSigner");
            crlSignerHealth.setHealthy(crlSignerHealthy);
            result.addChildCheck(crlSignerHealth);
        }

        for(IdentifiedCertPublisher publisher : getPublishers())
        {
            boolean ph = publisher.isHealthy();
            healthy &= ph;

            HealthCheckResult publisherHealth = new HealthCheckResult("Publisher");
            publisherHealth.setHealthy(publisher.isHealthy());
            result.addChildCheck(publisherHealth);
        }

        result.setHealthy(healthy);

        return result;
    }

    private static Object[] incSerialNumber(IdentifiedCertProfile profile, X500Name origName, String latestSN)
    throws BadFormatException
    {
        RDN[] rdns = origName.getRDNs();

        int commonNameIndex = -1;
        int serialNumberIndex = -1;
        for(int i = 0; i < rdns.length; i++)
        {
            RDN rdn = rdns[i];
            ASN1ObjectIdentifier type = rdn.getFirst().getType();
            if(ObjectIdentifiers.DN_CN.equals(type))
            {
                commonNameIndex = i;
            }
            else if(ObjectIdentifiers.DN_SERIALNUMBER.equals(type))
            {
                serialNumberIndex = i;
            }
        }

        String newSerialNumber = profile.incSerialNumber(latestSN);
        RDN serialNumberRdn = new RDN(ObjectIdentifiers.DN_SERIALNUMBER, new DERPrintableString(newSerialNumber));

        X500Name newName;
        if(serialNumberIndex != -1)
        {
            rdns[serialNumberIndex] = serialNumberRdn;
            newName = new X500Name(rdns);
        }
        else
        {
            List<RDN> newRdns = new ArrayList<>(rdns.length + 1);

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

            newName = new X500Name(newRdns.toArray(new RDN[0]));
        }

        return new Object[]{newName, newSerialNumber};
    }

    private boolean verifySignature(X509Certificate cert)
    {
        PublicKey caPublicKey = caInfo.getCertificate().getCert().getPublicKey();
        try
        {
            final String provider = "XipkiNSS";

            if(tryXipkiNSStoVerify == null)
            {
                // Not for ECDSA
                if(caPublicKey instanceof ECPublicKey)
                {
                    tryXipkiNSStoVerify = Boolean.FALSE;
                }
                else
                {
                    if(Security.getProvider(provider) == null)
                    {
                        LOG.info("Security provider {} is not registered", provider);
                        tryXipkiNSStoVerify = Boolean.FALSE;
                    }
                    else
                    {
                        byte[] tbs = cert.getTBSCertificate();
                        byte[] signatureValue = cert.getSignature();
                        String sigAlgName = cert.getSigAlgName();
                        try
                        {
                            Signature verifier = Signature.getInstance(sigAlgName, provider);
                            verifier.initVerify(caPublicKey);
                            verifier.update(tbs);
                            boolean sigValid = verifier.verify(signatureValue);

                            LOG.info("Use {} to verify {} signature", provider, sigAlgName);
                            tryXipkiNSStoVerify = Boolean.TRUE;
                            return sigValid;
                        }catch(Exception e)
                        {
                            LOG.info("Cannot use {} to verify {} signature", provider, sigAlgName);
                            tryXipkiNSStoVerify = Boolean.FALSE;
                        }
                    }
                }
            }

            if(tryXipkiNSStoVerify)
            {
                byte[] tbs = cert.getTBSCertificate();
                byte[] signatureValue = cert.getSignature();
                String sigAlgName = cert.getSigAlgName();
                Signature verifier = Signature.getInstance(sigAlgName, provider);
                verifier.initVerify(caPublicKey);
                verifier.update(tbs);
                return verifier.verify(signatureValue);
            }
            else
            {
                cert.verify(caPublicKey);
                return true;
            }
        } catch (SignatureException e)
        {
            LOG.debug("SignatureException while verifying signature: {}", e.getMessage());
            return false;
        } catch (InvalidKeyException e)
        {
            LOG.debug("InvalidKeyException while verifying signature: {}", e.getMessage());
            return false;
        } catch (CertificateException e)
        {
            LOG.debug("CertificateException while verifying signature: {}", e.getMessage());
            return false;
        } catch (NoSuchAlgorithmException e)
        {
            LOG.debug("NoSuchAlgorithmException while verifying signature: {}", e.getMessage());
            return false;
        } catch (NoSuchProviderException e)
        {
            LOG.debug("NoSuchProviderException while verifying signature: {}", e.getMessage());
            return false;
        }
    }

}
