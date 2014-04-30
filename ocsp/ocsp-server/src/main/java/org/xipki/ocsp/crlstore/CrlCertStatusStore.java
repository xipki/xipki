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

package org.xipki.ocsp.crlstore;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
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
import org.xipki.ocsp.IssuerHashNameAndKey;
import org.xipki.ocsp.api.CertRevocationInfo;
import org.xipki.ocsp.api.CertStatusInfo;
import org.xipki.ocsp.api.CertStatusStore;
import org.xipki.ocsp.api.CertStatusStoreException;
import org.xipki.ocsp.api.HashAlgoType;
import org.xipki.security.common.CustomObjectIdentifiers;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

public class CrlCertStatusStore implements CertStatusStore
{
    private static final Logger LOG = LoggerFactory.getLogger(CrlCertStatusStore.class);

    private class StoreUpdateService implements Runnable
    {
        @Override
        public void run()
        {
            initializeStore(false);
        }
    }

    private final Map<BigInteger, CrlCertStatusInfo> certStatusInfoMap
        = new ConcurrentHashMap<BigInteger, CrlCertStatusInfo>();

    private final boolean unknownSerialAsGood;
    private final X509Certificate caCert;
    private final X509Certificate issuerCert;
    private final boolean useUpdateDatesFromCRL;
    private final String name;
    private final String crlFile;
    private final SHA1Digest sha1;

    private byte[] fpOfCrlFile;
    private long   lastmodifiedOfCrlFile = 0;

    private Date thisUpdate;
    private Date nextUpdate;
    private final Map<HashAlgoType, IssuerHashNameAndKey> issuerHashMap =
            new ConcurrentHashMap<HashAlgoType, IssuerHashNameAndKey>();

    private AuditLoggingService auditLoggingService;

    private boolean initialized = false;
    private boolean initializationFailed = false;

    public CrlCertStatusStore(String name, String crlFile, X509Certificate caCert, boolean useUpdateDatesFromCRL,
            boolean unknownSerialAsGood)
    {
        this(name, crlFile, caCert, null, useUpdateDatesFromCRL, unknownSerialAsGood);
    }

    public CrlCertStatusStore(String name, String crlFile, X509Certificate caCert, X509Certificate issuerCert,
            boolean useUpdateDatesFromCRL, boolean unknownSerialAsGood)
    {
        ParamChecker.assertNotEmpty("name", name);
        ParamChecker.assertNotEmpty("crlFile", crlFile);
        ParamChecker.assertNotNull("caCert", caCert);

        this.name = name;
        this.crlFile = crlFile;
        this.caCert = caCert;
        this.issuerCert = issuerCert;
        this.unknownSerialAsGood = unknownSerialAsGood;
        this.useUpdateDatesFromCRL = useUpdateDatesFromCRL;

        this.sha1 = new SHA1Digest();
        initializeStore(true);

        StoreUpdateService storeUpdateService = new StoreUpdateService();
        ScheduledThreadPoolExecutor scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1);
        scheduledThreadPoolExecutor.scheduleAtFixedRate(
                storeUpdateService, 60, 60, TimeUnit.SECONDS);
    }

    private synchronized void initializeStore(boolean force)
    {
        Boolean updateCRLSuccessfull = null;

        try
        {
            File f = new File(crlFile);
            if(f.exists() == false)
            {
                // file does not exist
                return;
            }

            long newLastModifed = f.lastModified();

            if(force  == false)
            {
                if(newLastModifed == lastmodifiedOfCrlFile)
                {
                    return;
                }

                long now = System.currentTimeMillis();
                if(now - newLastModifed < 5000)
                {
                    return; // still in copy process
                }
            }

            byte[] newFp = null;
            synchronized (sha1)
            {
                sha1.reset();
                FileInputStream in = new FileInputStream(f);
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

                newFp = new byte[20];
                sha1.doFinal(newFp, 0);
            }

            if(Arrays.equals(newFp, fpOfCrlFile))
            {
                auditLogPCIEvent(AuditLevel.INFO, "UPDATE_CERTSTORE", "current CRL is still up-to-date");
                return;
            }

            LOG.info("CRL file {} has changed, updating of the CertStore required", crlFile);
            auditLogPCIEvent(AuditLevel.INFO, "UPDATE_CERTSTORE", "a newer version of CRL is available");
            updateCRLSuccessfull = false;

            X509CRL crl = IoCertUtil.parseCRL(crlFile);

            X500Principal issuer = crl.getIssuerX500Principal();

            boolean caAsCrlIssuer = true;
            if(caCert.getSubjectX500Principal().equals(issuer) == false)
            {
                caAsCrlIssuer = false;
                if(issuerCert != null)
                {
                    if(issuerCert.getSubjectX500Principal().equals(issuer) == false)
                    {
                        throw new IllegalArgumentException("The issuerCert and crl do not match");
                    }
                }
                else
                {
                    throw new IllegalArgumentException("issuerCert could not be null");
                }
            }

            try
            {
                crl.verify((caAsCrlIssuer ? caCert : issuerCert).getPublicKey());
            }catch(Exception e)
            {
                throw new CertStatusStoreException(e);
            }

            Date newThisUpdate = crl.getThisUpdate();
            Date newNextUpdate = crl.getNextUpdate();

            HashCalculator hashCalculator;
            try
            {
                hashCalculator = new HashCalculator();
            } catch (NoSuchAlgorithmException e)
            {
                throw new CertStatusStoreException(e);
            }

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

            Map<HashAlgoType, IssuerHashNameAndKey> newIssuerHashMap =
                    new ConcurrentHashMap<HashAlgoType, IssuerHashNameAndKey>();

            for(HashAlgoType hashAlgo : HashAlgoType.values())
            {
                byte[] issuerNameHash = hashCalculator.hash(hashAlgo, encodedName);
                byte[] issuerKeyHash = hashCalculator.hash(hashAlgo, encodedKey);
                IssuerHashNameAndKey issuerHash = new IssuerHashNameAndKey(hashAlgo, issuerNameHash, issuerKeyHash);
                newIssuerHashMap.put(hashAlgo, issuerHash);
            }

            X500Name caName = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());

            // extract the certificate
            boolean certsIncluded = false;
            Set<Certificate> certs = new HashSet<Certificate>();
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
                    Certificate bcCert = Certificate.getInstance(asn1);
                    if(caName.equals(bcCert.getIssuer()) == false)
                    {
                        throw new CertStatusStoreException("Invalid entry in CRL Extension certs");
                    }

                    certs.add(bcCert);
                }
            }

            Map<BigInteger, CrlCertStatusInfo> newCertStatusInfoMap
                = new ConcurrentHashMap<BigInteger, CrlCertStatusInfo>();

            Set<? extends X509CRLEntry> revokedCertList = crl.getRevokedCertificates();
            if(revokedCertList != null)
            {
                for(X509CRLEntry revokedCert : revokedCertList)
                {
                    X500Principal thisIssuer = revokedCert.getCertificateIssuer();
                    if(thisIssuer != null)
                    {
                        if(caCert.getSubjectX500Principal().equals(thisIssuer) == false)
                        {
                            throw new CertStatusStoreException("Invalid CRLEntry");
                        }
                    }

                    BigInteger serialNumber = revokedCert.getSerialNumber();
                    byte[] encodedExtnValue = revokedCert.getExtensionValue(Extension.reasonCode.getId());
                    DEREnumerated enumerated = DEREnumerated.getInstance(
                            DEROctetString.getInstance(encodedExtnValue).getOctets());
                    int reasonCode = enumerated.getValue().intValue();
                    Date revTime = revokedCert.getRevocationDate();

                    Date invalidityTime = null;
                    extnValue = revokedCert.getExtensionValue(Extension.invalidityDate.getId());

                    if(extnValue != null)
                    {
                        extnValue = removingTagAndLenFromExtensionValue(extnValue);
                        DERGeneralizedTime gTime = DERGeneralizedTime.getInstance(extnValue);
                        try
                        {
                            invalidityTime = gTime.getDate();
                        } catch (ParseException e)
                        {
                            throw new CertStatusStoreException(e);
                        }
                    }

                    Certificate cert = null;
                    if(certsIncluded)
                    {
                        for(Certificate bcCert : certs)
                        {
                            if(bcCert.getIssuer().equals(caName) &&
                                    bcCert.getSerialNumber().getPositiveValue().equals(serialNumber))
                            {
                                cert = bcCert;
                                break;
                            }
                        }

                        if(cert == null)
                        {
                            throw new CertStatusStoreException("Could not find certificate (issuer = '" +
                                    IoCertUtil.canonicalizeName(caName) + "', serialNumber = '" + serialNumber + "')");
                        }
                        certs.remove(cert);
                    }

                    Map<HashAlgoType, byte[]> certHashes = (cert == null) ? null : getCertHashes(hashCalculator, cert);

                    CertRevocationInfo revocationInfo = new CertRevocationInfo(reasonCode, revTime, invalidityTime);
                    CrlCertStatusInfo crlCertStatusInfo = CrlCertStatusInfo.getRevocatedCertStatusInfo(
                            revocationInfo, certHashes);
                    newCertStatusInfoMap.put(serialNumber, crlCertStatusInfo);
                }
            }

            for(Certificate cert : certs)
            {
                CrlCertStatusInfo crlCertStatusInfo = CrlCertStatusInfo.getGoodCertStatusInfo(
                        getCertHashes(hashCalculator, cert));
                newCertStatusInfoMap.put(cert.getSerialNumber().getPositiveValue(), crlCertStatusInfo);
            }

            this.initialized = false;
            this.lastmodifiedOfCrlFile = newLastModifed;
            this.fpOfCrlFile = newFp;
            this.issuerHashMap.clear();
            this.issuerHashMap.putAll(newIssuerHashMap);
            this.certStatusInfoMap.clear();
            this.certStatusInfoMap.putAll(newCertStatusInfoMap);
            this.thisUpdate = newThisUpdate;
            this.nextUpdate = newNextUpdate;
            this.initializationFailed = false;
            this.initialized = true;
            updateCRLSuccessfull = true;
            LOG.info("Updated CertStore {}", name);
        } catch (Exception e)
        {
            LOG.error("Could not executing initializeStore() for {},  {}: {}",
                    new Object[]{name, e.getClass().getName(), e.getMessage()});
            LOG.debug("Could not executing initializeStore()", e);

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
                    auditStatus = AuditStatus.SUCCSEEFULL;
                }

                auditLogPCIEvent(auditLevel, eventType, auditStatus.name());
            }
        }
    }

    private static Map<HashAlgoType, byte[]> getCertHashes(HashCalculator hashCalculator, Certificate cert)
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

        Map<HashAlgoType, byte[]> certHashes = new ConcurrentHashMap<HashAlgoType, byte[]>();
        for(HashAlgoType hashAlgo : HashAlgoType.values())
        {
            byte[] certHash = hashCalculator.hash(hashAlgo, encodedCert);
            certHashes.put(hashAlgo, certHash);
        }

        return certHashes;
    }

    @Override
    public CertStatusInfo getCertStatus(
            HashAlgoType hashAlgo, byte[] issuerNameHash, byte[] issuerKeyHash,
            BigInteger serialNumber,
            boolean includeCertHash,
            HashAlgoType certHashAlgo)
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

        if(includeCertHash && certHashAlgo == null)
        {
            certHashAlgo = hashAlgo;
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

        CrlCertStatusInfo certStatusInfo = certStatusInfoMap.get(serialNumber);

        // SerialNumber is unknown
        if(certStatusInfo == null)
        {
            return unknownSerialAsGood ?
                    CertStatusInfo.getGoodCertStatusInfo(certHashAlgo, null, thisUpdate, nextUpdate) :
                    CertStatusInfo.getUnknownCertStatusInfo(thisUpdate, nextUpdate);
        }

        return certStatusInfo.getCertStatusInfo(certHashAlgo, thisUpdate, nextUpdate);
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

    @Override
    public String getName()
    {
        return name;
    }

    @Override
    public AuditLoggingService getAuditLoggingService()
    {
        return auditLoggingService;
    }

    @Override
    public void setAuditLoggingService(AuditLoggingService auditLoggingService)
    {
        this.auditLoggingService = auditLoggingService;
    }

    private void auditLogPCIEvent(AuditLevel auditLevel, String eventType, String auditStatus)
    {
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
}
