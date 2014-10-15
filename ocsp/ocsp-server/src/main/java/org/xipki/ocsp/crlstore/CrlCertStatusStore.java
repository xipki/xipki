/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp.crlstore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.ocsp.CrlID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditLevel;
import org.xipki.audit.api.AuditLoggingService;
import org.xipki.audit.api.AuditStatus;
import org.xipki.audit.api.PCIAuditEvent;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.ocsp.IssuerHashNameAndKey;
import org.xipki.ocsp.api.CertStatusInfo;
import org.xipki.ocsp.api.CertStatusStore;
import org.xipki.ocsp.api.CertStatusStoreException;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.CRLReason;
import org.xipki.security.common.CertRevocationInfo;
import org.xipki.security.common.CustomObjectIdentifiers;
import org.xipki.security.common.HashAlgoType;
import org.xipki.security.common.HashCalculator;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.LogUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CrlCertStatusStore extends CertStatusStore
{
    private static final Logger LOG = LoggerFactory.getLogger(CrlCertStatusStore.class);

    private static class CertWithInfo
    {
        private Certificate cert;
        private String profileName;

        public CertWithInfo(Certificate cert, String profileName)
        {
            this.cert = cert;
            this.profileName = profileName;
        }
    }

    private class StoreUpdateService implements Runnable
    {
        @Override
        public void run()
        {
            initializeStore(false);
        }
    }

    private final Map<BigInteger, CrlCertStatusInfo> certStatusInfoMap = new ConcurrentHashMap<>();

    private final X509Certificate caCert;
    private final X509Certificate issuerCert;
    private final String crlFilename;
    private final String deltaCrlFilename;
    private final SHA1Digest sha1;
    private final String crlUrl;
    private final Date caNotBefore;
    private final String certsDirname;

    private boolean useUpdateDatesFromCRL;
    private boolean caRevoked;
    private Date caRevocationTime;

    private CrlID crlID;

    private byte[] fpOfCrlFile;
    private long lastmodifiedOfCrlFile = 0;

    private byte[] fpOfDeltaCrlFile;
    private long lastModifiedOfDeltaCrlFile = 0;

    private Date thisUpdate;
    private Date nextUpdate;
    private final Map<HashAlgoType, IssuerHashNameAndKey> issuerHashMap = new ConcurrentHashMap<>();

    private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

    private boolean initialized = false;
    private boolean initializationFailed = false;

    public CrlCertStatusStore(
            String name,
            String crlFile,
            String deltaCrlFile,
            X509Certificate caCert,
            String crlUrl,
            String certsDirname)
    {
        this(name, crlFile, (String) null, caCert, (X509Certificate) null, crlUrl, certsDirname);
    }

    public CrlCertStatusStore(
            String name,
            String crlFilename,
            String deltaCrlFilename,
            X509Certificate caCert,
            X509Certificate issuerCert,
            String crlUrl,
            String certsDirname)
    {
        super(name);
        ParamChecker.assertNotEmpty("crlFile", crlFilename);
        ParamChecker.assertNotNull("caCert", caCert);

        this.crlFilename = IoCertUtil.expandFilepath(crlFilename);
        this.deltaCrlFilename = deltaCrlFilename == null ? null : IoCertUtil.expandFilepath(deltaCrlFilename);
        this.caCert = caCert;
        this.issuerCert = issuerCert;
        this.crlUrl = crlUrl;
        this.caNotBefore = caCert.getNotBefore();
        this.certsDirname = certsDirname;

        this.sha1 = new SHA1Digest();
        initializeStore(true);

        StoreUpdateService storeUpdateService = new StoreUpdateService();
        scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1);
        scheduledThreadPoolExecutor.scheduleAtFixedRate(
                storeUpdateService, 60, 60, TimeUnit.SECONDS);
    }

    private synchronized void initializeStore(boolean force)
    {
        Boolean updateCRLSuccessfull = null;

        try
        {
            File fullCrlFile = new File(crlFilename);
            if(fullCrlFile.exists() == false)
            {
                // file does not exist
                LOG.warn("CRL File {} does not exist", crlFilename);
                return;
            }

            long newLastModifed = fullCrlFile.lastModified();

            boolean deltaCrlExists;
            File deltaCrlFile = null;
            if(deltaCrlFilename != null)
            {
                deltaCrlFile = new File(deltaCrlFilename);
                deltaCrlExists = deltaCrlFile.exists();
            }
            else
            {
                deltaCrlExists = false;
            }

            long newLastModifedOfDeltaCrl = deltaCrlExists ? deltaCrlFile.lastModified() : 0;

            if(force  == false)
            {
                long now = System.currentTimeMillis();
                if(newLastModifed != lastmodifiedOfCrlFile)
                {
                    if(now - newLastModifed < 5000)
                    {
                        return; // still in copy process
                    }
                }

                if(deltaCrlExists)
                {
                    if(newLastModifedOfDeltaCrl != lastModifiedOfDeltaCrlFile)
                    {
                        if(now - newLastModifed < 5000)
                        {
                            return; // still in copy process
                        }
                    }
                }
            }

            byte[] newFp = sha1Fp(fullCrlFile);
            boolean crlFileChanged = Arrays.equals(newFp, fpOfCrlFile) == false;

            if(crlFileChanged == false)
            {
                auditLogPCIEvent(AuditLevel.INFO, "UPDATE_CERTSTORE", "current CRL is still up-to-date");
                return;
            }

            byte[] newFpOfDeltaCrl = deltaCrlExists ? sha1Fp(deltaCrlFile) : null;
            boolean deltaCrlFileChanged = Arrays.equals(newFpOfDeltaCrl, fpOfDeltaCrlFile) == false;

            if(crlFileChanged == false && deltaCrlFileChanged == false)
            {
                return;
            }

            if(crlFileChanged)
            {
                LOG.info("CRL file {} has changed, updating of the CertStore required", crlFilename);
            }
            if(deltaCrlFileChanged)
            {
                LOG.info("DeltaCRL file {} has changed, updating of the CertStore required", deltaCrlFilename);
            }

            auditLogPCIEvent(AuditLevel.INFO, "UPDATE_CERTSTORE", "a newer version of CRL is available");
            updateCRLSuccessfull = false;

            X509CRL crl = IoCertUtil.parseCRL(crlFilename);
            BigInteger crlNumber;
            {
                byte[] octetString = crl.getExtensionValue(Extension.cRLNumber.getId());
                if(octetString != null)
                {
                    byte[] extnValue = DEROctetString.getInstance(octetString).getOctets();
                    crlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();
                }
                else
                {
                    crlNumber = null;
                }
            }

            X500Principal issuer = crl.getIssuerX500Principal();

            boolean caAsCrlIssuer = true;
            if(caCert.getSubjectX500Principal().equals(issuer) == false)
            {
                caAsCrlIssuer = false;
                if(issuerCert != null)
                {
                    if(issuerCert.getSubjectX500Principal().equals(issuer) == false)
                    {
                        throw new IllegalArgumentException("The issuerCert and CRL do not match");
                    }
                }
                else
                {
                    throw new IllegalArgumentException("issuerCert could not be null");
                }
            }

            X509Certificate crlSignerCert = caAsCrlIssuer ? caCert : issuerCert;
            try
            {
                crl.verify(crlSignerCert.getPublicKey());
            }catch(Exception e)
            {
                throw new CertStatusStoreException(e);
            }

            X509CRL deltaCrl = null;
            BigInteger deltaCrlNumber = null;
            BigInteger baseCrlNumber = null;

            if(deltaCrlExists)
            {
                if(crlNumber == null)
                {
                    throw new CertStatusStoreException("baseCRL does not contains CRLNumber");
                }

                deltaCrl = IoCertUtil.parseCRL(deltaCrlFilename);
                byte[] octetString = deltaCrl.getExtensionValue(Extension.deltaCRLIndicator.getId());
                if(octetString == null)
                {
                    deltaCrl = null;
                    LOG.warn("{} is a full CRL instead of delta CRL, ignore it", deltaCrlFilename);
                }
                else
                {
                    byte[] extnValue = DEROctetString.getInstance(octetString).getOctets();
                    baseCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();
                    if(baseCrlNumber.equals(crlNumber) == false)
                    {
                        deltaCrl = null;
                        LOG.info("{} is not a deltaCRL for the CRL {}, ignore it", deltaCrlFilename, crlFilename);
                    }
                    else
                    {
                        octetString = deltaCrl.getExtensionValue(Extension.cRLNumber.getId());
                        extnValue = DEROctetString.getInstance(octetString).getOctets();
                        deltaCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();
                    }
                }
            }

            if(crlFileChanged == false && deltaCrl == null)
            {
                return;
            }

            Date newThisUpdate;
            Date newNextUpdate;

            if(deltaCrl != null)
            {
                LOG.info("Try to update CRL with CRLNumber={} and DeltaCRL with CRLNumber={}", crlNumber, deltaCrlNumber);
                newThisUpdate = deltaCrl.getThisUpdate();
                newNextUpdate = deltaCrl.getNextUpdate();
            }
            else
            {
                newThisUpdate = crl.getThisUpdate();
                newNextUpdate = crl.getNextUpdate();
            }

            // Construct CrlID
            ASN1EncodableVector v = new ASN1EncodableVector();
            if(crlUrl != null && crlUrl.isEmpty() == false)
            {
                v.add(new DERTaggedObject(true, 0, new DERIA5String(crlUrl, true)));
            }
            byte[] extValue = (deltaCrlExists ? deltaCrl : crl).getExtensionValue(Extension.cRLNumber.getId());
            if(extValue != null)
            {
                ASN1Integer asn1CrlNumber = ASN1Integer.getInstance(
                        removingTagAndLenFromExtensionValue(extValue));
                v.add(new DERTaggedObject(true, 1, asn1CrlNumber));
            }
            v.add(new DERTaggedObject(true, 2, new DERGeneralizedTime(newThisUpdate)));
            this.crlID = CrlID.getInstance(new DERSequence(v));

            byte[] encodedCaCert;
            try
            {
                encodedCaCert = caCert.getEncoded();
            } catch (CertificateEncodingException e)
            {
                throw new CertStatusStoreException(e);
            }

            Certificate bcCaCert = Certificate.getInstance(encodedCaCert);
            byte[] encodedName;
            try
            {
                encodedName = bcCaCert.getSubject().getEncoded("DER");
            } catch (IOException e)
            {
                throw new CertStatusStoreException(e);
            }

            byte[] encodedKey = bcCaCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();

            Map<HashAlgoType, IssuerHashNameAndKey> newIssuerHashMap = new ConcurrentHashMap<>();

            for(HashAlgoType hashAlgo : HashAlgoType.values())
            {
                byte[] issuerNameHash = HashCalculator.hash(hashAlgo, encodedName);
                byte[] issuerKeyHash = HashCalculator.hash(hashAlgo, encodedKey);
                IssuerHashNameAndKey issuerHash = new IssuerHashNameAndKey(hashAlgo, issuerNameHash, issuerKeyHash);
                newIssuerHashMap.put(hashAlgo, issuerHash);
            }

            X500Name caName = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());

            // extract the certificate, only in full CRL, not in delta CRL
            boolean certsIncluded = false;
            Set<CertWithInfo> certs = new HashSet<>();
            String oidExtnCerts = CustomObjectIdentifiers.id_crl_certset;
            byte[] extnValue = crl.getExtensionValue(oidExtnCerts);
            if(extnValue != null)
            {
                extnValue = removingTagAndLenFromExtensionValue(extnValue);
                certsIncluded = true;
                ASN1Set asn1Set = DERSet.getInstance(extnValue);
                int n = asn1Set.size();
                for(int i = 0; i < n; i++)
                {
                    ASN1Encodable asn1 = asn1Set.getObjectAt(i);
                    Certificate bcCert;
                    String profileName = null;

                    try
                    {
                        ASN1Sequence seq = ASN1Sequence.getInstance(asn1);
                        bcCert = Certificate.getInstance(seq.getObjectAt(0));
                        if(seq.size() > 1)
                        {
                            profileName = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
                        }
                    }catch(IllegalArgumentException e)
                    {
                        // backwards compatibility
                        bcCert = Certificate.getInstance(asn1);
                    }

                    if(caName.equals(bcCert.getIssuer()) == false)
                    {
                        throw new CertStatusStoreException("Invalid entry in CRL Extension certs");
                    }

                    certs.add(new CertWithInfo(bcCert, profileName));
                }
            }

            if(certsDirname != null)
            {
                certsIncluded = true;
                Set<CertWithInfo> tmpCerts = readCertWithInfosFromDir(caCert, certsDirname);
                certs.addAll(tmpCerts);
            }

            Map<BigInteger, CrlCertStatusInfo> newCertStatusInfoMap = new ConcurrentHashMap<>();

            // First consider only full CRL
            Set<? extends X509CRLEntry> revokedCertListInFullCRL = crl.getRevokedCertificates();
            if(revokedCertListInFullCRL != null)
            {
                for(X509CRLEntry revokedCert : revokedCertListInFullCRL)
                {
                    X500Principal thisIssuer = revokedCert.getCertificateIssuer();
                    if(thisIssuer != null)
                    {
                        if(caCert.getSubjectX500Principal().equals(thisIssuer) == false)
                        {
                            throw new CertStatusStoreException("Invalid CRLEntry");
                        }
                    }
                }
            }

            Set<? extends X509CRLEntry> revokedCertListInDeltaCRL = null;
            if(deltaCrl != null)
            {
                revokedCertListInDeltaCRL = deltaCrl.getRevokedCertificates();
                if(revokedCertListInDeltaCRL != null)
                {
                    for(X509CRLEntry revokedCert : revokedCertListInDeltaCRL)
                    {
                        X500Principal thisIssuer = revokedCert.getCertificateIssuer();
                        if(thisIssuer != null)
                        {
                            if(caCert.getSubjectX500Principal().equals(thisIssuer) == false)
                            {
                                throw new CertStatusStoreException("Invalid CRLEntry");
                            }
                        }
                    }
                }
            }

            Map<BigInteger, X509CRLEntry> revokedCertMap = null;

            // merge the revoked list
            if(revokedCertListInDeltaCRL != null && revokedCertListInDeltaCRL.isEmpty() == false)
            {
                revokedCertMap = new HashMap<BigInteger, X509CRLEntry>();
                for(X509CRLEntry entry : revokedCertListInFullCRL)
                {
                    revokedCertMap.put(entry.getSerialNumber(), entry);
                }

                for(X509CRLEntry entry : revokedCertListInDeltaCRL)
                {
                    BigInteger serialNumber = entry.getSerialNumber();
                    java.security.cert.CRLReason reason = entry.getRevocationReason();
                    if(reason == java.security.cert.CRLReason.REMOVE_FROM_CRL)
                    {
                        revokedCertMap.remove(serialNumber);
                    }
                    else
                    {
                        revokedCertMap.put(serialNumber, entry);
                    }
                }
            }

            Iterator<? extends X509CRLEntry> it = null;
            if(revokedCertMap != null)
            {
                it = revokedCertMap.values().iterator();
            }
            else if(revokedCertListInFullCRL != null)
            {
                it = revokedCertListInFullCRL.iterator();
            }

            if(it != null)
            {
                while(it.hasNext())
                {
                    X509CRLEntry revokedCert = it.next();
                    BigInteger serialNumber = revokedCert.getSerialNumber();
                    byte[] encodedExtnValue = revokedCert.getExtensionValue(Extension.reasonCode.getId());

                    int reasonCode;
                    if(encodedExtnValue != null)
                    {
                        ASN1Enumerated enumerated = ASN1Enumerated.getInstance(
                                removingTagAndLenFromExtensionValue(encodedExtnValue));
                        reasonCode = enumerated.getValue().intValue();
                    }
                    else
                    {
                        reasonCode = CRLReason.UNSPECIFIED.getCode();
                    }

                    Date revTime = revokedCert.getRevocationDate();

                    Date invalidityTime = null;
                    extnValue = revokedCert.getExtensionValue(Extension.invalidityDate.getId());

                    if(extnValue != null)
                    {
                        extnValue = removingTagAndLenFromExtensionValue(extnValue);
                        ASN1GeneralizedTime gTime = DERGeneralizedTime.getInstance(extnValue);
                        try
                        {
                            invalidityTime = gTime.getDate();
                        } catch (ParseException e)
                        {
                            throw new CertStatusStoreException(e);
                        }

                        if(revTime.equals(invalidityTime))
                        {
                            invalidityTime = null;
                        }
                    }

                    CertWithInfo cert = null;
                    if(certsIncluded)
                    {
                        for(CertWithInfo bcCert : certs)
                        {
                            if(bcCert.cert.getIssuer().equals(caName) &&
                                    bcCert.cert.getSerialNumber().getPositiveValue().equals(serialNumber))
                            {
                                cert = bcCert;
                                break;
                            }
                        }

                        if(cert == null)
                        {
                            LOG.info("Could not find certificate (issuer = '{}', serialNumber = '{}'",
                                    IoCertUtil.canonicalizeName(caName), serialNumber);
                        }
                        else
                        {
                            certs.remove(cert);
                        }
                    }

                    Map<HashAlgoType, byte[]> certHashes = (cert == null) ? null : getCertHashes(cert.cert);

                    if(caRevoked && inheritCaRevocation)
                    {
                        if(revTime.after(caRevocationTime))
                        {
                            revTime = caRevocationTime;
                            reasonCode = CRLReason.CA_COMPROMISE.getCode();
                        }
                        if(invalidityTime != null && invalidityTime.after(caRevocationTime))
                        {
                            invalidityTime = null;
                            reasonCode = CRLReason.CA_COMPROMISE.getCode();
                        }
                    }

                    CertRevocationInfo revocationInfo = new CertRevocationInfo(reasonCode, revTime, invalidityTime);
                    CrlCertStatusInfo crlCertStatusInfo = CrlCertStatusInfo.getRevokedCertStatusInfo(
                            revocationInfo,
                            (cert == null) ? null : cert.profileName,
                            certHashes);
                    newCertStatusInfoMap.put(serialNumber, crlCertStatusInfo);
                }
            }

            for(CertWithInfo cert : certs)
            {
                Map<HashAlgoType, byte[]> certHashes = getCertHashes(cert.cert);
                CrlCertStatusInfo crlCertStatusInfo;
                if(caRevoked && inheritCaRevocation)
                {
                    CertRevocationInfo revocationInfo = new CertRevocationInfo(
                            CRLReason.CA_COMPROMISE.getCode(), caRevocationTime, null);
                    crlCertStatusInfo = CrlCertStatusInfo.getRevokedCertStatusInfo(
                            revocationInfo, cert.profileName, certHashes);
                }
                else
                {
                    crlCertStatusInfo = CrlCertStatusInfo.getGoodCertStatusInfo(
                            cert.profileName, certHashes);
                }
                newCertStatusInfoMap.put(cert.cert.getSerialNumber().getPositiveValue(), crlCertStatusInfo);
            }

            this.initialized = false;
            this.lastmodifiedOfCrlFile = newLastModifed;
            this.fpOfCrlFile = newFp;

            this.lastModifiedOfDeltaCrlFile = newLastModifedOfDeltaCrl;
            this.fpOfDeltaCrlFile = newFpOfDeltaCrl;

            this.issuerHashMap.clear();
            this.issuerHashMap.putAll(newIssuerHashMap);
            this.certStatusInfoMap.clear();
            this.certStatusInfoMap.putAll(newCertStatusInfoMap);
            this.thisUpdate = newThisUpdate;
            this.nextUpdate = newNextUpdate;

            this.initializationFailed = false;
            this.initialized = true;
            updateCRLSuccessfull = true;
            LOG.info("Updated CertStore {}", getName());
        } catch (Exception e)
        {
            final String message = "Could not executing initializeStore()";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            initializationFailed = true;
            initialized = true;
        } finally
        {
            if(updateCRLSuccessfull != null)
            {
                AuditLevel auditLevel;
                AuditStatus auditStatus;
                String eventType = "UPDATE_CRL";
                if(updateCRLSuccessfull)
                {
                    auditLevel = AuditLevel.INFO;
                    auditStatus = AuditStatus.FAILED;
                }
                else
                {
                    auditLevel = AuditLevel.ERROR;
                    auditStatus = AuditStatus.SUCCESSFUL;
                }

                auditLogPCIEvent(auditLevel, eventType, auditStatus.name());
            }
        }
    }

    private static Map<HashAlgoType, byte[]> getCertHashes(Certificate cert)
    throws CertStatusStoreException
    {
        byte[] encodedCert;
        try
        {
            encodedCert = cert.getEncoded();
        } catch (IOException e)
        {
            throw new CertStatusStoreException(e);
        }

        Map<HashAlgoType, byte[]> certHashes = new ConcurrentHashMap<>();
        for(HashAlgoType hashAlgo : HashAlgoType.values())
        {
            byte[] certHash = HashCalculator.hash(hashAlgo, encodedCert);
            certHashes.put(hashAlgo, certHash);
        }

        return certHashes;
    }

    @Override
    public CertStatusInfo getCertStatus(
            HashAlgoType hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash,
            BigInteger serialNumber, Set<String> excludeCertProfiles)
    throws CertStatusStoreException
    {
        // wait for max. 0.5 second
        int n = 5;
        while(initialized == false && (n-- > 0))
        {
            try
            {
                Thread.sleep(100);
            }catch(InterruptedException e)
            {
            }
        }

        if(initialized == false)
        {
            throw new CertStatusStoreException("Initialization of CertStore is still in process");
        }

        if(initializationFailed)
        {
            throw new CertStatusStoreException("Initialization of CertStore failed");
        }

        HashAlgoType certHashAlgo = null;
        if(includeCertHash)
        {
            certHashAlgo = certHashAlgorithm == null ? hashAlgo : certHashAlgorithm;
        }

        Date thisUpdate;
        Date nextUpdate = null;

        if(useUpdateDatesFromCRL)
        {
            thisUpdate = this.thisUpdate;

            if(this.nextUpdate != null)
            {
                // this.nextUpdate is still in the future (10 seconds buffer)
                if(this.nextUpdate.getTime() > System.currentTimeMillis() + 10 * 1000)
                {
                    nextUpdate = this.nextUpdate;
                }
            }
        }
        else
        {
            thisUpdate = new Date();
        }

        IssuerHashNameAndKey issuerHashNameAndKey = issuerHashMap.get(hashAlgo);

        if(issuerHashNameAndKey.match(hashAlgo, issuerNameHash, issuerKeyHash) == false)
        {
            return CertStatusInfo.getIssuerUnknownCertStatusInfo(thisUpdate, nextUpdate);
        }

        CertStatusInfo certStatusInfo = null;

        CrlCertStatusInfo crlCertStatusInfo = certStatusInfoMap.get(serialNumber);

        // SerialNumber is unknown
        if(crlCertStatusInfo != null)
        {
            String profile = crlCertStatusInfo.getCertProfile();
            if(profile == null || excludeCertProfiles == null || excludeCertProfiles.contains(profile) == false)
            {
                certStatusInfo = crlCertStatusInfo.getCertStatusInfo(certHashAlgo, thisUpdate, nextUpdate);
            }
        }

        if(certStatusInfo == null)
        {
            if(unknownSerialAsGood)
            {
                if(caRevoked && inheritCaRevocation)
                {
                    CertRevocationInfo revocationInfo = new CertRevocationInfo(
                            CRLReason.CA_COMPROMISE.getCode(), caRevocationTime, null);
                    certStatusInfo = CertStatusInfo.getRevokedCertStatusInfo(revocationInfo,
                            null, null, thisUpdate, nextUpdate, null);
                }
                else
                {
                    certStatusInfo = CertStatusInfo.getGoodCertStatusInfo(
                            certHashAlgo, null, thisUpdate, nextUpdate, null);
                }
            }
            else
            {
                certStatusInfo = CertStatusInfo.getUnknownCertStatusInfo(thisUpdate, nextUpdate);
            }
        }

        if(includeCrlID)
        {
            certStatusInfo.setCrlID(crlID);
        }

        if(includeArchiveCutoff)
        {
            Date t;
            if(retentionInterval != 0)
            {
                // expired certificate remains in status store for ever
                if(retentionInterval < 0)
                {
                    t = caNotBefore;
                }
                else
                {
                    long nowÍnMs = System.currentTimeMillis();
                    long tInMs = Math.max(caNotBefore.getTime(), nowÍnMs - DAY * retentionInterval);
                    t = new Date(tInMs);
                }

                certStatusInfo.setArchiveCutOff(t);
            }
        }

        return certStatusInfo;
    }

    private static byte[] removingTagAndLenFromExtensionValue(byte[] encodedExtensionValue)
    {
        DEROctetString derOctet = (DEROctetString) DEROctetString.getInstance(encodedExtensionValue);
        return derOctet.getOctets();
    }

    public X509Certificate getCaCert()
    {
        return caCert;
    }

    @Override
    public boolean isHealthy()
    {
        return true;
    }

    private void auditLogPCIEvent(AuditLevel auditLevel, String eventType, String auditStatus)
    {
        AuditLoggingService auditLoggingService = getAuditLoggingService();
        if(auditLoggingService != null)
        {
            PCIAuditEvent auditEvent = new PCIAuditEvent(new Date());
            auditEvent.setUserId("SYSTEM");
            auditEvent.setEventType(eventType);
            auditEvent.setAffectedResource("CRL-Updater");
            auditEvent.setStatus(auditStatus);
            auditEvent.setLevel(auditLevel);
            auditLoggingService.logEvent(auditEvent);
        }
    }

    @Override
    public void init(String conf, DataSourceFactory datasourceFactory, PasswordResolver passwordResolver)
    throws CertStatusStoreException
    {
    }

    @Override
    public void shutdown()
    throws CertStatusStoreException
    {
        if(scheduledThreadPoolExecutor != null)
        {
            scheduledThreadPoolExecutor.shutdown();
            scheduledThreadPoolExecutor = null;
        }
    }

    public boolean isUseUpdateDatesFromCRL()
    {
        return useUpdateDatesFromCRL;
    }

    public void setUseUpdateDatesFromCRL(boolean useUpdateDatesFromCRL)
    {
        this.useUpdateDatesFromCRL = useUpdateDatesFromCRL;
    }

    public boolean isCaRevoked()
    {
        return caRevoked;
    }

    public void setCaRevoked(boolean caRevoked)
    {
        this.caRevoked = caRevoked;
    }

    public Date getCaRevocationTime()
    {
        return caRevocationTime;
    }

    public void setCaRevocationTime(Date caRevocationTime)
    {
        this.caRevocationTime = caRevocationTime;
    }

    private Set<CertWithInfo> readCertWithInfosFromDir(X509Certificate caCert, String certsDirname)
    {
        File certsDir = new File(certsDirname);

        if(certsDir.exists() == false)
        {
            LOG.warn("The folder " + certsDirname + " does not exist, ignore it");
            return Collections.emptySet();
        }

        if(certsDir.isDirectory() == false)
        {
            LOG.warn("The path " + certsDirname + " does not point to a folder, ignore it");
            return Collections.emptySet();
        }

        if(certsDir.canRead() == false)
        {
            LOG.warn("The folder " + certsDirname + " cannot be read, ignore it");
            return Collections.emptySet();
        }

        File[] certFiles = certsDir.listFiles(new FilenameFilter()
        {
            @Override
            public boolean accept(File dir, String name)
            {
                return name.endsWith(".der") || name.endsWith(".crt");
            }
        });

        if(certFiles == null || certFiles.length == 0)
        {
            return Collections.emptySet();
        }

        X500Name issuer = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
        Set<CertWithInfo> certs = new HashSet<>();

        final String profileName = "UNKNOWN";
        for(File certFile : certFiles)
        {
            Certificate bcCert;

            try
            {
                byte[] encoded = IoCertUtil.read(certFile);
                bcCert = Certificate.getInstance(encoded);
            }catch(IllegalArgumentException | IOException e)
            {
                LOG.warn("Cannot parse certificate {}, ignore it", certFile.getPath());
                continue;
            }

            // not issued by the given issuer
            if(issuer.equals(bcCert.getIssuer()) == false)
            {
                continue;
            }

            certs.add(new CertWithInfo(bcCert, profileName));
        }

        return certs;
    }

    private final byte[] sha1Fp(File file)
    throws IOException
    {
        synchronized (sha1)
        {
            sha1.reset();
            FileInputStream in = new FileInputStream(file);
            byte[] buffer = new byte[1024];
            int readed;

            try
            {
                while((readed = in.read(buffer)) != -1)
                {
                    if(readed > 0)
                    {
                        sha1.update(buffer, 0, readed);
                    }
                }
            }finally
            {
                try
                {
                    in.close();
                }catch(IOException e)
                {
                }
            }

            byte[] fp = new byte[20];
            sha1.doFinal(fp, 0);
            return fp;
        }
    }

}
