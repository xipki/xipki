/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.pki.ocsp.server.impl.certstore;

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
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
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
import org.xipki.commons.audit.api.AuditLevel;
import org.xipki.commons.audit.api.AuditService;
import org.xipki.commons.audit.api.AuditStatus;
import org.xipki.commons.audit.api.PCIAuditEvent;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.datasource.api.DataSourceWrapper;
import org.xipki.commons.security.api.CRLReason;
import org.xipki.commons.security.api.CertRevocationInfo;
import org.xipki.commons.security.api.HashAlgoType;
import org.xipki.commons.security.api.HashCalculator;
import org.xipki.commons.security.api.ObjectIdentifiers;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ocsp.api.CertStatusInfo;
import org.xipki.pki.ocsp.api.CertStatusStore;
import org.xipki.pki.ocsp.api.CertStatusStoreException;
import org.xipki.pki.ocsp.api.CertprofileOption;
import org.xipki.pki.ocsp.api.IssuerHashNameAndKey;

/**
 * @author Lijun Liao
 */

public class CrlCertStatusStore extends CertStatusStore {

    private class StoreUpdateService implements Runnable {

        @Override
        public void run() {
            initializeStore(false);
        }

    } // StoreUpdateService

    private static final Logger LOG = LoggerFactory.getLogger(CrlCertStatusStore.class);

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

    private CertRevocationInfo caRevInfo;

    private CrlID crlID;

    private byte[] fpOfCrlFile;

    private long lastmodifiedOfCrlFile = 0;

    private byte[] fpOfDeltaCrlFile;

    private long lastModifiedOfDeltaCrlFile = 0;

    private Date thisUpdate;

    private Date nextUpdate;

    private BigInteger crlNumber;

    private final Set<HashAlgoType> certHashAlgos;

    private final Map<HashAlgoType, IssuerHashNameAndKey> issuerHashMap =
            new ConcurrentHashMap<>();

    private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

    private boolean initialized = false;

    private boolean initializationFailed = false;

    public CrlCertStatusStore(
            final String name,
            final String crlFile,
            final String deltaCrlFile,
            final X509Certificate caCert,
            final String crlUrl,
            final String certsDirname,
            final Set<HashAlgoType> certHashAlgos) {
        this(name, crlFile, (String) null, caCert, (X509Certificate) null, crlUrl,
                certsDirname, certHashAlgos);
    }

    public CrlCertStatusStore(
            final String name,
            final String crlFilename,
            final String deltaCrlFilename,
            final X509Certificate caCert,
            final X509Certificate issuerCert,
            final String crlUrl,
            final String certsDirname,
            final Set<HashAlgoType> certHashAlgos) {
        super(name);
        ParamUtil.assertNotBlank("crlFile", crlFilename);
        ParamUtil.assertNotNull("caCert", caCert);
        ParamUtil.assertNotNull("certHashAlgos", certHashAlgos);

        this.crlFilename = IoUtil.expandFilepath(crlFilename);
        this.deltaCrlFilename = (deltaCrlFilename == null)
                ? null
                : IoUtil.expandFilepath(deltaCrlFilename);
        this.caCert = caCert;
        this.issuerCert = issuerCert;
        this.crlUrl = crlUrl;
        this.caNotBefore = caCert.getNotBefore();
        this.certsDirname = certsDirname;

        this.certHashAlgos = certHashAlgos;
        this.sha1 = new SHA1Digest();
    }

    private synchronized void initializeStore(
            final boolean force) {
        Boolean updateCRLSuccessful = null;

        try {
            File fullCrlFile = new File(crlFilename);
            if (!fullCrlFile.exists()) {
                // file does not exist
                LOG.warn("CRL File {} does not exist", crlFilename);
                return;
            }

            long newLastModifed = fullCrlFile.lastModified();

            boolean deltaCrlExists;
            File deltaCrlFile = null;
            if (deltaCrlFilename != null) {
                deltaCrlFile = new File(deltaCrlFilename);
                deltaCrlExists = deltaCrlFile.exists();
            } else {
                deltaCrlExists = false;
            }

            long newLastModifedOfDeltaCrl = deltaCrlExists
                    ? deltaCrlFile.lastModified()
                    : 0;

            if (!force) {
                long now = System.currentTimeMillis();
                if (newLastModifed != lastmodifiedOfCrlFile) {
                    if (now - newLastModifed < 5000) {
                        return; // still in copy process
                    }
                }

                if (deltaCrlExists) {
                    if (newLastModifedOfDeltaCrl != lastModifiedOfDeltaCrlFile) {
                        if (now - newLastModifed < 5000) {
                            return; // still in copy process
                        }
                    }
                }
            } // end if (force)

            byte[] newFp = sha1Fp(fullCrlFile);
            boolean crlFileChanged = !Arrays.equals(newFp, fpOfCrlFile);

            if (!crlFileChanged) {
                auditPCIEvent(AuditLevel.INFO, "UPDATE_CERTSTORE",
                        "current CRL is still up-to-date");
                return;
            }

            byte[] newFpOfDeltaCrl = deltaCrlExists
                    ? sha1Fp(deltaCrlFile)
                    : null;
            boolean deltaCrlFileChanged =
                    !Arrays.equals(newFpOfDeltaCrl, fpOfDeltaCrlFile);

            if (!crlFileChanged && !deltaCrlFileChanged) {
                return;
            }

            if (crlFileChanged) {
                LOG.info("CRL file {} has changed, updating of the CertStore required",
                        crlFilename);
            }
            if (deltaCrlFileChanged) {
                LOG.info("DeltaCRL file {} has changed, updating of the CertStore required",
                        deltaCrlFilename);
            }

            auditPCIEvent(AuditLevel.INFO, "UPDATE_CERTSTORE",
                    "a newer version of CRL is available");
            updateCRLSuccessful = false;

            X509CRL crl = X509Util.parseCRL(crlFilename);

            byte[] octetString = crl.getExtensionValue(Extension.cRLNumber.getId());
            if (octetString == null) {
                throw new CertStatusStoreException("CRL withour CRLNumber is not supported");
            }
            BigInteger newCrlNumber = ASN1Integer.getInstance(
                    DEROctetString.getInstance(octetString).getOctets())
                    .getPositiveValue();

            if (crlNumber != null && newCrlNumber.compareTo(crlNumber) <= 0) {
                throw new CertStatusStoreException(
                        String.format("CRLNumber of new CRL (%s) <= current CRL (%s)",
                            newCrlNumber, crlNumber));
            }

            X500Principal issuer = crl.getIssuerX500Principal();

            boolean caAsCrlIssuer = true;
            if (!caCert.getSubjectX500Principal().equals(issuer)) {
                caAsCrlIssuer = false;
                if (issuerCert == null) {
                    throw new IllegalArgumentException("issuerCert could not be null");
                }

                if (!issuerCert.getSubjectX500Principal().equals(issuer)) {
                    throw new IllegalArgumentException("The issuerCert and CRL do not match");
                }
            }

            X509Certificate crlSignerCert = caAsCrlIssuer
                    ? caCert
                    : issuerCert;
            try {
                crl.verify(crlSignerCert.getPublicKey());
            } catch (Exception e) {
                throw new CertStatusStoreException(e.getMessage(), e);
            }

            X509CRL deltaCrl = null;
            BigInteger deltaCrlNumber = null;
            BigInteger baseCrlNumber = null;

            if (deltaCrlExists) {
                if (newCrlNumber == null) {
                    throw new CertStatusStoreException("baseCRL does not contains CRLNumber");
                }

                deltaCrl = X509Util.parseCRL(deltaCrlFilename);
                octetString =
                        deltaCrl.getExtensionValue(Extension.deltaCRLIndicator.getId());
                if (octetString == null) {
                    deltaCrl = null;
                    LOG.warn("{} is a full CRL instead of delta CRL, ignore it", deltaCrlFilename);
                } else {
                    byte[] extnValue = DEROctetString.getInstance(octetString).getOctets();
                    baseCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();
                    if (!baseCrlNumber.equals(newCrlNumber)) {
                        deltaCrl = null;
                        LOG.info("{} is not a deltaCRL for the CRL {}, ignore it",
                                deltaCrlFilename, crlFilename);
                    } else {
                        octetString = deltaCrl.getExtensionValue(Extension.cRLNumber.getId());
                        extnValue = DEROctetString.getInstance(octetString).getOctets();
                        deltaCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();
                    }
                } // end if(octetString == null)
            } // end if(deltaCrlExists)

            if (!crlFileChanged && deltaCrl == null) {
                return;
            }

            Date newThisUpdate;
            Date newNextUpdate;

            if (deltaCrl != null) {
                LOG.info("try to update CRL with CRLNumber={} and DeltaCRL with CRLNumber={}",
                        newCrlNumber, deltaCrlNumber);
                newThisUpdate = deltaCrl.getThisUpdate();
                newNextUpdate = deltaCrl.getNextUpdate();
            } else {
                newThisUpdate = crl.getThisUpdate();
                newNextUpdate = crl.getNextUpdate();
            }

            // Construct CrlID
            ASN1EncodableVector v = new ASN1EncodableVector();
            if (StringUtil.isNotBlank(crlUrl)) {
                v.add(new DERTaggedObject(true, 0, new DERIA5String(crlUrl, true)));
            }

            X509CRL tCrl = deltaCrlExists
                    ? deltaCrl
                    : crl;
            byte[] extValue = tCrl.getExtensionValue(Extension.cRLNumber.getId());
            if (extValue != null) {
                ASN1Integer asn1CrlNumber = ASN1Integer.getInstance(
                        removeTagAndLenFromExtensionValue(extValue));
                v.add(new DERTaggedObject(true, 1, asn1CrlNumber));
            }
            v.add(new DERTaggedObject(true, 2, new DERGeneralizedTime(newThisUpdate)));
            this.crlID = CrlID.getInstance(new DERSequence(v));

            byte[] encodedCaCert;
            try {
                encodedCaCert = caCert.getEncoded();
            } catch (CertificateEncodingException e) {
                throw new CertStatusStoreException(e.getMessage(), e);
            }

            Certificate bcCaCert = Certificate.getInstance(encodedCaCert);
            byte[] encodedName;
            try {
                encodedName = bcCaCert.getSubject().getEncoded("DER");
            } catch (IOException e) {
                throw new CertStatusStoreException(e.getMessage(), e);
            }

            byte[] encodedKey = bcCaCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();

            Map<HashAlgoType, IssuerHashNameAndKey> newIssuerHashMap = new ConcurrentHashMap<>();

            for (HashAlgoType hashAlgo : HashAlgoType.values()) {
                byte[] issuerNameHash = HashCalculator.hash(hashAlgo, encodedName);
                byte[] issuerKeyHash = HashCalculator.hash(hashAlgo, encodedKey);
                IssuerHashNameAndKey issuerHash =
                        new IssuerHashNameAndKey(hashAlgo, issuerNameHash, issuerKeyHash);
                newIssuerHashMap.put(hashAlgo, issuerHash);
            }

            X500Name caName = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());

            // extract the certificate, only in full CRL, not in delta CRL
            boolean certsConsidered = false;
            Map<BigInteger, CertWithInfo> certsMap = new HashMap<>();
            String oidExtnCerts = ObjectIdentifiers.id_xipki_ext_crlCertset.getId();
            byte[] extnValue = crl.getExtensionValue(oidExtnCerts);

            if (extnValue != null) {
                extnValue = removeTagAndLenFromExtensionValue(extnValue);
                certsConsidered = true;
                ASN1Set asn1Set = DERSet.getInstance(extnValue);
                int n = asn1Set.size();
                for (int i = 0; i < n; i++) {
                    ASN1Encodable asn1 = asn1Set.getObjectAt(i);

                    ASN1Sequence seq = ASN1Sequence.getInstance(asn1);
                    BigInteger serialNumber = ASN1Integer.getInstance(
                            seq.getObjectAt(0)).getValue();

                    Certificate bcCert = null;
                    String profileName = null;

                    final int size = seq.size();
                    for (int j = 1; j < size; j++) {
                        ASN1TaggedObject taggedObj = DERTaggedObject.getInstance(
                                seq.getObjectAt(j));
                        int tagNo = taggedObj.getTagNo();
                        switch (tagNo) {
                        case 0:
                            bcCert = Certificate.getInstance(taggedObj.getObject());
                            break;
                        case 1:
                            profileName = DERUTF8String.getInstance(
                                    taggedObj.getObject()).getString();
                            break;
                        default:
                            break;
                        }
                    }

                    if (bcCert != null) {
                        if (!caName.equals(bcCert.getIssuer())) {
                            throw new CertStatusStoreException(
                                "issuer not match (serial=" + serialNumber
                                + ") in CRL Extension Xipki-CertSet");
                        }

                        if (!serialNumber.equals(bcCert.getSerialNumber().getValue())) {
                            throw new CertStatusStoreException(
                                    "serialNumber not match (serial=" + serialNumber
                                    + ") in CRL Extension Xipki-CertSet");
                            }
                    }

                    if (profileName == null) {
                        profileName = "UNKNOWN";
                    }

                    CertWithInfo entry = new CertWithInfo(serialNumber);
                    entry.setProfileName(profileName);
                    if (!certHashAlgos.isEmpty()) {
                        entry.setCert(bcCert);
                    }
                    certsMap.put(serialNumber, entry);
                } // end for
            } // end if (extnValue != null)

            if (certsDirname != null) {
                if (extnValue != null) {
                    LOG.warn("ignore certsDir '{}', since certificates are included in {}",
                            certsDirname, " CRL Extension certs");
                } else {
                    certsConsidered = true;
                    readCertWithInfosFromDir(caCert, certsDirname, certsMap);
                }
            }

            Map<BigInteger, CrlCertStatusInfo> newCertStatusInfoMap = new ConcurrentHashMap<>();

            // First consider only full CRL
            Set<? extends X509CRLEntry> revokedCertListInFullCRL = crl.getRevokedCertificates();
            if (revokedCertListInFullCRL != null) {
                for (X509CRLEntry revokedCert : revokedCertListInFullCRL) {
                    X500Principal thisIssuer = revokedCert.getCertificateIssuer();
                    if (thisIssuer != null
                            && !caCert.getSubjectX500Principal().equals(thisIssuer)) {
                        throw new CertStatusStoreException("invalid CRLEntry");
                    }
                }
            }

            Set<? extends X509CRLEntry> revokedCertListInDeltaCRL = null;
            if (deltaCrl != null) {
                revokedCertListInDeltaCRL = deltaCrl.getRevokedCertificates();
                if (revokedCertListInDeltaCRL != null) {
                    for (X509CRLEntry revokedCert : revokedCertListInDeltaCRL) {
                        X500Principal thisIssuer = revokedCert.getCertificateIssuer();
                        if (thisIssuer != null
                                && !caCert.getSubjectX500Principal().equals(thisIssuer)) {
                            throw new CertStatusStoreException("invalid CRLEntry");
                        }
                    } // end for
                } // end if
            } // end if(deltaCrl != null)

            Map<BigInteger, X509CRLEntry> revokedCertMap = null;

            // merge the revoked list
            if (CollectionUtil.isNotEmpty(revokedCertListInDeltaCRL)) {
                revokedCertMap = new HashMap<BigInteger, X509CRLEntry>();
                for (X509CRLEntry entry : revokedCertListInFullCRL) {
                    revokedCertMap.put(entry.getSerialNumber(), entry);
                }

                for (X509CRLEntry entry : revokedCertListInDeltaCRL) {
                    BigInteger serialNumber = entry.getSerialNumber();
                    java.security.cert.CRLReason reason = entry.getRevocationReason();
                    if (reason == java.security.cert.CRLReason.REMOVE_FROM_CRL) {
                        revokedCertMap.remove(serialNumber);
                    } else {
                        revokedCertMap.put(serialNumber, entry);
                    }
                } // end for
            } // end if

            Iterator<? extends X509CRLEntry> it = null;
            if (revokedCertMap != null) {
                it = revokedCertMap.values().iterator();
            } else if (revokedCertListInFullCRL != null) {
                it = revokedCertListInFullCRL.iterator();
            }

            if (it != null) {
                while (it.hasNext()) {
                    X509CRLEntry revokedCert = it.next();
                    BigInteger serialNumber = revokedCert.getSerialNumber();
                    byte[] encodedExtnValue = revokedCert.getExtensionValue(
                            Extension.reasonCode.getId());

                    int reasonCode;
                    if (encodedExtnValue != null) {
                        ASN1Enumerated enumerated = ASN1Enumerated.getInstance(
                                removeTagAndLenFromExtensionValue(encodedExtnValue));
                        reasonCode = enumerated.getValue().intValue();
                    } else {
                        reasonCode = CRLReason.UNSPECIFIED.getCode();
                    }

                    Date revTime = revokedCert.getRevocationDate();

                    Date invalidityTime = null;
                    extnValue = revokedCert.getExtensionValue(Extension.invalidityDate.getId());

                    if (extnValue != null) {
                        extnValue = removeTagAndLenFromExtensionValue(extnValue);
                        ASN1GeneralizedTime gTime = DERGeneralizedTime.getInstance(extnValue);
                        try {
                            invalidityTime = gTime.getDate();
                        } catch (ParseException e) {
                            throw new CertStatusStoreException(e.getMessage(), e);
                        }

                        if (revTime.equals(invalidityTime)) {
                            invalidityTime = null;
                        }
                    }

                    CertWithInfo cert = null;
                    if (certsConsidered) {
                        cert = certsMap.remove(serialNumber);
                        if (cert == null) {
                            LOG.info("could not find certificate (serialNumber='{}')",
                                    serialNumber);
                        }
                    }

                    Map<HashAlgoType, byte[]> certHashes =
                            (cert == null || cert.getCert() == null)
                                ? null
                                : getCertHashes(cert.getCert());

                    CertRevocationInfo revocationInfo = new CertRevocationInfo(reasonCode, revTime,
                            invalidityTime);

                    String profileName = (cert == null)
                            ? null
                            : cert.getProfileName();

                    CrlCertStatusInfo crlCertStatusInfo =
                            CrlCertStatusInfo.getRevokedCertStatusInfo(
                                    revocationInfo,
                                    profileName,
                                    certHashes);
                    newCertStatusInfoMap.put(serialNumber, crlCertStatusInfo);
                } // end while (it.hasNext())
            } // end if (it)

            for (BigInteger serialNumber : certsMap.keySet()) {
                CertWithInfo cert = certsMap.get(serialNumber);
                Map<HashAlgoType, byte[]> certHashes = (cert.getCert() == null)
                        ? null
                        : getCertHashes(cert.getCert());
                CrlCertStatusInfo crlCertStatusInfo = CrlCertStatusInfo.getGoodCertStatusInfo(
                        cert.getProfileName(), certHashes);
                newCertStatusInfoMap.put(cert.getSerialNumber(),
                        crlCertStatusInfo);
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
            this.crlNumber = newCrlNumber;

            this.initializationFailed = false;
            this.initialized = true;
            updateCRLSuccessful = true;
            LOG.info("updated CertStore {}", getName());
        } catch (Exception e) {
            final String message = "could not execute initializeStore()";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
            initializationFailed = true;
            initialized = true;
        } finally {
            if (updateCRLSuccessful != null) {
                AuditLevel auditLevel;
                AuditStatus auditStatus;
                String eventType = "UPDATE_CRL";
                if (updateCRLSuccessful) {
                    auditLevel = AuditLevel.INFO;
                    auditStatus = AuditStatus.FAILED;
                } else {
                    auditLevel = AuditLevel.ERROR;
                    auditStatus = AuditStatus.SUCCESSFUL;
                }

                auditPCIEvent(auditLevel, eventType, auditStatus.name());
            }
        }
    } // method initializeStore

    @Override
    public CertStatusInfo getCertStatus(
            final HashAlgoType hashAlgo,
            final byte[] issuerNameHash,
            final byte[] issuerKeyHash,
            final BigInteger serialNumber,
            final boolean includeCertHash,
            final HashAlgoType certHashAlg,
            final CertprofileOption certprofileOption)
    throws CertStatusStoreException {
        // wait for max. 0.5 second
        int n = 5;
        while (!initialized && (n-- > 0)) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
            }
        }

        if (!initialized) {
            throw new CertStatusStoreException("initialization of CertStore is still in process");
        }

        if (initializationFailed) {
            throw new CertStatusStoreException("initialization of CertStore failed");
        }

        HashAlgoType certHashAlgo = null;
        if (includeCertHash) {
            certHashAlgo = (certHashAlg == null)
                    ? hashAlgo
                    : certHashAlg;
        }

        Date thisUpdate;
        Date nextUpdate = null;

        if (useUpdateDatesFromCRL) {
            thisUpdate = this.thisUpdate;

            if (this.nextUpdate != null) {
                // this.nextUpdate is still in the future (10 seconds buffer)
                if (this.nextUpdate.getTime() > System.currentTimeMillis() + 10 * 1000) {
                    nextUpdate = this.nextUpdate;
                }
            }
        } else {
            thisUpdate = new Date();
        }

        IssuerHashNameAndKey issuerHashNameAndKey = issuerHashMap.get(hashAlgo);

        if (!issuerHashNameAndKey.match(hashAlgo, issuerNameHash, issuerKeyHash)) {
            return CertStatusInfo.getIssuerUnknownCertStatusInfo(thisUpdate, nextUpdate);
        }

        CertStatusInfo certStatusInfo = null;

        CrlCertStatusInfo crlCertStatusInfo = certStatusInfoMap.get(serialNumber);

        if (crlCertStatusInfo != null) {
            String profileName = crlCertStatusInfo.getCertprofile();
            boolean ignore = profileName != null
                    && certprofileOption != null
                    && !certprofileOption.include(profileName);
            if (ignore) {
                certStatusInfo = CertStatusInfo.getIgnoreCertStatusInfo(thisUpdate, nextUpdate);
            } else {
                certStatusInfo = crlCertStatusInfo.getCertStatusInfo(certHashAlgo, thisUpdate,
                        nextUpdate);
            }
        } else {
            // SerialNumber is unknown
            if (isUnknownSerialAsGood()) {
                certStatusInfo = CertStatusInfo.getGoodCertStatusInfo(
                        null, null, thisUpdate, nextUpdate, null);
            } else {
                certStatusInfo = CertStatusInfo.getUnknownCertStatusInfo(thisUpdate, nextUpdate);
            }
        }

        if (isIncludeCrlID()) {
            certStatusInfo.setCrlID(crlID);
        }

        if (isIncludeArchiveCutoff()) {
            int retentionInterval = getRetentionInterval();
            Date t;
            if (retentionInterval != 0) {
                // expired certificate remains in status store for ever
                if (retentionInterval < 0) {
                    t = caNotBefore;
                } else {
                    long nowInMs = System.currentTimeMillis();
                    long tInMs = Math.max(caNotBefore.getTime(), nowInMs - DAY * retentionInterval);
                    t = new Date(tInMs);
                }

                certStatusInfo.setArchiveCutOff(t);
            }
        }

        return certStatusInfo;
    } // method getCertStatus

    public X509Certificate getCaCert() {
        return caCert;
    }

    @Override
    public boolean isHealthy() {
        return true;
    }

    private void auditPCIEvent(
            final AuditLevel auditLevel,
            final String eventType,
            final String auditStatus) {
        AuditService auditService = getAuditService();
        if (auditService == null) {
            return;
        }

        PCIAuditEvent auditEvent = new PCIAuditEvent(new Date());
        auditEvent.setUserId("SYSTEM");
        auditEvent.setEventType(eventType);
        auditEvent.setAffectedResource("CRL-Updater");
        auditEvent.setStatus(auditStatus);
        auditEvent.setLevel(auditLevel);
        auditService.logEvent(auditEvent);
    }

    @Override
    public void init(
            final String conf,
            final DataSourceWrapper datasource)
    throws CertStatusStoreException {
        initializeStore(true);

        StoreUpdateService storeUpdateService = new StoreUpdateService();
        scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1);
        scheduledThreadPoolExecutor.scheduleAtFixedRate(
                storeUpdateService, 60, 60, TimeUnit.SECONDS);
    }

    @Override
    public void shutdown()
    throws CertStatusStoreException {
        if (scheduledThreadPoolExecutor == null) {
            return;
        }

        scheduledThreadPoolExecutor.shutdown();
        scheduledThreadPoolExecutor = null;
    }

    public boolean isUseUpdateDatesFromCRL() {
        return useUpdateDatesFromCRL;
    }

    public void setUseUpdateDatesFromCRL(
            final boolean useUpdateDatesFromCRL) {
        this.useUpdateDatesFromCRL = useUpdateDatesFromCRL;
    }

    private void readCertWithInfosFromDir(
            final X509Certificate caCert,
            final String certsDirname,
            final Map<BigInteger, CertWithInfo> certsMap)
    throws CertificateEncodingException {
        File certsDir = new File(certsDirname);

        if (!certsDir.exists()) {
            LOG.warn("the folder " + certsDirname + " does not exist, ignore it");
            return;
        }

        if (!certsDir.isDirectory()) {
            LOG.warn("the path " + certsDirname + " does not point to a folder, ignore it");
            return;
        }

        if (!certsDir.canRead()) {
            LOG.warn("the folder " + certsDirname + " could not be read, ignore it");
            return;
        }

        File[] certFiles = certsDir.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(
                    final File dir,
                    final String name) {
                return name.endsWith(".der") || name.endsWith(".crt");
            }
        });

        if (certFiles == null || certFiles.length == 0) {
            return;
        }

        X500Name issuer = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
        byte[] issuerSKI = X509Util.extractSKI(caCert);

        final String profileName = "UNKNOWN";
        final boolean needsCert = !certHashAlgos.isEmpty();

        for (File certFile : certFiles) {
            Certificate bcCert;

            try {
                byte[] encoded = IoUtil.read(certFile);
                bcCert = Certificate.getInstance(encoded);
            } catch (IllegalArgumentException | IOException e) {
                LOG.warn("could not parse certificate {}, ignore it", certFile.getPath());
                continue;
            }

            BigInteger serialNumber = bcCert.getSerialNumber().getValue();
            if (certsMap.containsKey(serialNumber)) {
                continue;
            }

            // not issued by the given issuer
            if (!issuer.equals(bcCert.getIssuer())) {
                continue;
            }

            if (issuerSKI != null) {
                byte[] aki = null;
                try {
                    aki = X509Util.extractAKI(bcCert);
                } catch (CertificateEncodingException e) {
                    final String message = "could not extract AuthorityKeyIdentifier";
                    if (LOG.isErrorEnabled()) {
                        LOG.error(LogUtil.buildExceptionLogFormat(message),
                                e.getClass().getName(), e.getMessage());
                    }
                    LOG.debug(message, e);
                }

                if (aki == null || !Arrays.equals(issuerSKI, aki)) {
                    continue;
                }
            } // end if

            CertWithInfo entry = new CertWithInfo(serialNumber);
            entry.setProfileName(profileName);
            if (needsCert) {
                entry.setCert(bcCert);
            }
            certsMap.put(serialNumber, entry);
        } // end for
    } // method readCertWithInfosFromDir

    private byte[] sha1Fp(
            final File file)
    throws IOException {
        synchronized (sha1) {
            sha1.reset();
            FileInputStream in = new FileInputStream(file);
            byte[] buffer = new byte[1024];
            int readed;

            try {
                while ((readed = in.read(buffer)) != -1) {
                    if (readed > 0) {
                        sha1.update(buffer, 0, readed);
                    }
                }
            } finally {
                try {
                    in.close();
                } catch (IOException e) {
                }
            }

            byte[] fp = new byte[20];
            sha1.doFinal(fp, 0);
            return fp;
        }
    }

    @Override
    public boolean canResolveIssuer(
            final HashAlgoType hashAlgo,
            final byte[] issuerNameHash,
            final byte[] issuerKeyHash) {
        IssuerHashNameAndKey hashes = issuerHashMap.get(hashAlgo);
        if (hashes == null) {
            return false;
        }

        return hashes.match(hashAlgo, issuerNameHash, issuerKeyHash);
    }

    @Override
    public Set<IssuerHashNameAndKey> getIssuerHashNameAndKeys() {
        Set<IssuerHashNameAndKey> ret = new HashSet<>();
        ret.addAll(issuerHashMap.values());
        return ret;
    }

    public void setCARevocationInfo(
            final Date revocationTime) {
        ParamUtil.assertNotNull("revocationTime", revocationTime);
        this.caRevInfo = new CertRevocationInfo(CRLReason.CA_COMPROMISE, revocationTime, null);
    }

    @Override
    public CertRevocationInfo getCARevocationInfo(
            final HashAlgoType hashAlgo,
            final byte[] issuerNameHash,
            final byte[] issuerKeyHash) {
        if (!canResolveIssuer(hashAlgo, issuerNameHash, issuerKeyHash)) {
            return null;
        }

        return caRevInfo;
    }

    private Map<HashAlgoType, byte[]> getCertHashes(
            final Certificate cert)
    throws CertStatusStoreException {
        if (certHashAlgos.isEmpty()) {
            return null;
        }

        byte[] encodedCert;
        try {
            encodedCert = cert.getEncoded();
        } catch (IOException e) {
            throw new CertStatusStoreException(e.getMessage(), e);
        }

        Map<HashAlgoType, byte[]> certHashes = new ConcurrentHashMap<>();
        for (HashAlgoType hashAlgo : certHashAlgos) {
            byte[] certHash = HashCalculator.hash(hashAlgo, encodedCert);
            certHashes.put(hashAlgo, certHash);
        }

        return certHashes;
    }

    private static byte[] removeTagAndLenFromExtensionValue(
            final byte[] encodedExtensionValue) {
        return ASN1OctetString.getInstance(encodedExtensionValue).getOctets();
    }

}
