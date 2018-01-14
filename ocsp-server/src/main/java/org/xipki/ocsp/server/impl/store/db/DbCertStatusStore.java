/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ocsp.server.impl.store.db;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.Base64;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.ocsp.api.CertStatus;
import org.xipki.ocsp.api.CertStatusInfo;
import org.xipki.ocsp.api.OcspStore;
import org.xipki.ocsp.api.OcspStoreException;
import org.xipki.ocsp.api.RequestIssuer;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.HashAlgoType;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DbCertStatusStore extends OcspStore {

    private static final Map<HashAlgoType, String> certHashAlgoColNameMap = new HashMap<>();

    {
        certHashAlgoColNameMap.put(HashAlgoType.SHA1, "S1");
        certHashAlgoColNameMap.put(HashAlgoType.SHA256, "S256");
        certHashAlgoColNameMap.put(HashAlgoType.SHA3_256, "S3_256");
    }

    private static class SimpleIssuerEntry {

        private final int id;

        private final Long revocationTimeMs;

        SimpleIssuerEntry(int id, Long revocationTimeMs) {
            this.id = id;
            this.revocationTimeMs = revocationTimeMs;
        }

        public boolean match(IssuerEntry issuer) {
            if (id != issuer.id()) {
                return false;
            }

            if (revocationTimeMs == null) {
                return issuer.revocationInfo() == null;
            }

            return (issuer.revocationInfo() == null) ? false
                    : revocationTimeMs == issuer.revocationInfo().revocationTime().getTime();
        }

    } // class SimpleIssuerEntry

    private class StoreUpdateService implements Runnable {

        @Override
        public void run() {
            initIssuerStore();
        }

    } // class StoreUpdateService

    protected DataSourceWrapper datasource;

    private static final Logger LOG = LoggerFactory.getLogger(DbCertStatusStore.class);

    private final AtomicBoolean storeUpdateInProcess = new AtomicBoolean(false);

    private String sqlCsNoRit;

    private String sqlCs;

    private Map<HashAlgoType, String> sqlCsNoRitMap;

    private Map<HashAlgoType, String> sqlCsMap;

    private IssuerFilter issuerFilter;

    private IssuerStore issuerStore;

    private boolean initialized;

    private boolean initializationFailed;

    private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

    protected List<Runnable> getScheduledServices() {
        return Collections.emptyList();
    }

    private synchronized void initIssuerStore() {
        if (storeUpdateInProcess.get()) {
            return;
        }

        storeUpdateInProcess.set(true);
        try {
            if (initialized) {
                final String sql = "SELECT ID,REV,RT,S1C FROM ISSUER";
                PreparedStatement ps = preparedStatement(sql);
                ResultSet rs = null;

                try {
                    Map<Integer, SimpleIssuerEntry> newIssuers = new HashMap<>();

                    rs = ps.executeQuery();
                    while (rs.next()) {
                        String sha1Fp = rs.getString("S1C");
                        if (!issuerFilter.includeIssuerWithSha1Fp(sha1Fp)) {
                            continue;
                        }

                        int id = rs.getInt("ID");
                        boolean revoked = rs.getBoolean("REV");
                        Long revTimeMs = revoked ? rs.getLong("RT") * 1000 : null;
                        SimpleIssuerEntry issuerEntry = new SimpleIssuerEntry(id, revTimeMs);
                        newIssuers.put(id, issuerEntry);
                    }

                    // no change in the issuerStore
                    Set<Integer> newIds = newIssuers.keySet();
                    Set<Integer> ids = (issuerStore != null) ? issuerStore.ids()
                            : Collections.emptySet();

                    boolean issuersUnchanged = (ids.size() == newIds.size())
                            && ids.containsAll(newIds) && newIds.containsAll(ids);

                    if (issuersUnchanged) {
                        for (Integer id : newIds) {
                            IssuerEntry entry = issuerStore.getIssuerForId(id);
                            SimpleIssuerEntry newEntry = newIssuers.get(id);
                            if (newEntry.match(entry)) {
                                issuersUnchanged = false;
                                break;
                            }
                        }
                    }

                    if (issuersUnchanged) {
                        return;
                    }
                } finally {
                    releaseDbResources(ps, rs);
                }
            } // end if(initialized)

            final String sql = "SELECT ID,NBEFORE,REV,RT,S1C,CERT,CRL_INFO FROM ISSUER";
            PreparedStatement ps = preparedStatement(sql);

            ResultSet rs = null;
            try {
                rs = ps.executeQuery();
                List<IssuerEntry> caInfos = new LinkedList<>();
                while (rs.next()) {
                    String sha1Fp = rs.getString("S1C");
                    if (!issuerFilter.includeIssuerWithSha1Fp(sha1Fp)) {
                        continue;
                    }

                    int id = rs.getInt("ID");
                    String b64Cert = rs.getString("CERT");
                    X509Certificate cert = X509Util.parseBase64EncodedCert(b64Cert);

                    IssuerEntry caInfoEntry = new IssuerEntry(id, cert);
                    String crlInfoStr = rs.getString("CRL_INFO");
                    if (StringUtil.isNotBlank(crlInfoStr)) {
                        CrlInfo crlInfo = new CrlInfo(crlInfoStr);
                        caInfoEntry.setCrlInfo(crlInfo);
                    }
                    RequestIssuer reqIssuer = new RequestIssuer(HashAlgoType.SHA1,
                            caInfoEntry.getEncodedHash(HashAlgoType.SHA1));
                    for (IssuerEntry existingIssuer : caInfos) {
                        if (existingIssuer.matchHash(reqIssuer)) {
                            throw new Exception(
                                "found at least two issuers with the same subject and key");
                        }
                    }

                    boolean revoked = rs.getBoolean("REV");
                    if (revoked) {
                        long lo = rs.getLong("RT");
                        caInfoEntry.setRevocationInfo(new Date(lo * 1000));
                    }

                    caInfos.add(caInfoEntry);
                } // end while (rs.next())

                initialized = false;
                this.issuerStore = new IssuerStore(caInfos);
                LOG.info("Updated issuers: {}", name);
                initializationFailed = false;
                initialized = true;
            } finally {
                releaseDbResources(ps, rs);
            }
        } catch (Throwable th) {
            storeUpdateInProcess.set(false);
            LogUtil.error(LOG, th, "could not executing initIssuerStore()");
            initializationFailed = true;
            initialized = true;
        }
    } // method initIssuerStore

    @Override
    public CertStatusInfo getCertStatus(Date time, RequestIssuer reqIssuer,
            BigInteger serialNumber, boolean includeCertHash, boolean includeRit,
            boolean inheritCaRevocation, HashAlgoType certHashAlg) throws OcspStoreException {
        if (serialNumber.signum() != 1) { // non-positive serial number
            return CertStatusInfo.getUnknownCertStatusInfo(new Date(), null);
        }

        if (!initialized) {
            throw new OcspStoreException("initialization of CertStore is still in process");
        }

        if (initializationFailed) {
            throw new OcspStoreException("initialization of CertStore failed");
        }

        String sql;

        try {
            IssuerEntry issuer = issuerStore.getIssuerForFp(reqIssuer);
            if (issuer == null) {
                return null;
            }

            HashAlgoType certHashAlgo = null;
            if (includeCertHash) {
                certHashAlgo = (certHashAlg == null) ? reqIssuer.hashAlgorithm() : certHashAlg;
                switch(certHashAlgo) {
                    case SHA1:
                    case SHA256:
                    case SHA3_256:
                        break;
                    case SHA3_224:
                    case SHA3_384:
                    case SHA3_512:
                        certHashAlgo = HashAlgoType.SHA3_256;
                        break;
                    default:
                        certHashAlgo = HashAlgoType.SHA256;
                }
                sql = (includeRit ? sqlCsMap : sqlCsNoRitMap).get(certHashAlgo);
            } else {
                sql = includeRit ? sqlCs : sqlCsNoRit;
            }

            CrlInfo crlInfo = issuer.crlInfo();

            Date thisUpdate;
            Date nextUpdate = null;

            if (crlInfo != null && crlInfo.isUseCrlUpdates()) {
                thisUpdate = crlInfo.thisUpdate();

                // this.nextUpdate is still in the future (10 seconds buffer)
                if (crlInfo.nextUpdate().getTime() - System.currentTimeMillis() > 10 * 1000) {
                    nextUpdate = crlInfo.nextUpdate();
                }
            } else {
                thisUpdate = new Date();
            }

            ResultSet rs = null;
            CertStatusInfo certStatusInfo = null;

            boolean unknown = true;
            boolean ignore = false;
            String certprofile = null;
            String b64CertHash = null;
            boolean revoked = false;
            int reason = 0;
            long revTime = 0;
            long invalTime = 0;

            PreparedStatement ps = datasource.prepareStatement(datasource.getConnection(), sql);

            try {
                ps.setInt(1, issuer.id());
                ps.setString(2, serialNumber.toString(16));
                rs = ps.executeQuery();

                if (rs.next()) {
                    unknown = false;

                    long timeInSec = time.getTime() / 1000;
                    if (!ignore && ignoreNotYetValidCert) {
                        long notBeforeInSec = rs.getLong("NBEFORE");
                        if (notBeforeInSec != 0 && timeInSec < notBeforeInSec) {
                            ignore = true;
                        }
                    }

                    if (!ignore && ignoreExpiredCert) {
                        long notAfterInSec = rs.getLong("NAFTER");
                        if (notAfterInSec != 0 && timeInSec > notAfterInSec) {
                            ignore = true;
                        }
                    }

                    if (!ignore) {
                        if (certHashAlgo != null) {
                            String colName = certHashAlgoColNameMap.get(certHashAlgo);
                            b64CertHash = rs.getString(colName);
                        }

                        revoked = rs.getBoolean("REV");
                        if (revoked) {
                            reason = rs.getInt("RR");
                            revTime = rs.getLong("RT");
                            if (includeRit) {
                                invalTime = rs.getLong("RIT");
                            }
                        }
                    }
                } // end if (rs.next())
            } catch (SQLException ex) {
                throw datasource.translate(sql, ex);
            } finally {
                releaseDbResources(ps, rs);
            }

            if (unknown) {
                if (unknownSerialAsGood) {
                    certStatusInfo = CertStatusInfo.getGoodCertStatusInfo(certHashAlgo, null,
                            thisUpdate, nextUpdate, null);
                } else {
                    certStatusInfo = CertStatusInfo.getUnknownCertStatusInfo(thisUpdate,
                            nextUpdate);
                }
            } else {
                if (ignore) {
                    certStatusInfo = CertStatusInfo.getIgnoreCertStatusInfo(thisUpdate, nextUpdate);
                } else {
                    byte[] certHash = (b64CertHash == null) ? null : Base64.decodeFast(b64CertHash);
                    if (revoked) {
                        Date invTime = (invalTime == 0 || invalTime == revTime)
                                ? null : new Date(invalTime * 1000);
                        CertRevocationInfo revInfo = new CertRevocationInfo(reason,
                                new Date(revTime * 1000), invTime);
                        certStatusInfo = CertStatusInfo.getRevokedCertStatusInfo(revInfo,
                                certHashAlgo, certHash, thisUpdate, nextUpdate, certprofile);
                    } else {
                        certStatusInfo = CertStatusInfo.getGoodCertStatusInfo(certHashAlgo,
                                certHash, thisUpdate, nextUpdate, certprofile);
                    }
                }
            }

            if (includeCrlId && crlInfo != null) {
                certStatusInfo.setCrlId(crlInfo.crlId());
            }

            if (includeArchiveCutoff) {
                if (retentionInterval != 0) {
                    Date date;
                    // expired certificate remains in status store for ever
                    if (retentionInterval < 0) {
                        date = issuer.notBefore();
                    } else {
                        long nowInMs = System.currentTimeMillis();
                        long dateInMs = Math.max(issuer.notBefore().getTime(),
                                nowInMs - DAY * retentionInterval);
                        date = new Date(dateInMs);
                    }

                    certStatusInfo.setArchiveCutOff(date);
                }
            }

            if ((!inheritCaRevocation) || issuer.revocationInfo() == null) {
                return certStatusInfo;
            }

            CertRevocationInfo caRevInfo = issuer.revocationInfo();
            CertStatus certStatus = certStatusInfo.certStatus();
            boolean replaced = false;
            if (certStatus == CertStatus.GOOD || certStatus == CertStatus.UNKNOWN) {
                replaced = true;
            } else if (certStatus == CertStatus.REVOKED) {
                if (certStatusInfo.revocationInfo().revocationTime().after(
                        caRevInfo.revocationTime())) {
                    replaced = true;
                }
            }

            if (replaced) {
                CertRevocationInfo newRevInfo;
                if (caRevInfo.reason() == CrlReason.CA_COMPROMISE) {
                    newRevInfo = caRevInfo;
                } else {
                    newRevInfo = new CertRevocationInfo(CrlReason.CA_COMPROMISE,
                            caRevInfo.revocationTime(), caRevInfo.invalidityTime());
                }
                certStatusInfo = CertStatusInfo.getRevokedCertStatusInfo(newRevInfo,
                        certStatusInfo.certHashAlgo(), certStatusInfo.certHash(),
                        certStatusInfo.thisUpdate(), certStatusInfo.nextUpdate(),
                        certStatusInfo.certprofile());
            }
            return certStatusInfo;
        } catch (DataAccessException ex) {
            throw new OcspStoreException(ex.getMessage(), ex);
        }

    } // method getCertStatus

    /**
     * Borrow Prepared Statement.
     * @return the next idle preparedStatement, {@code null} will be returned if no
     *     PreparedStatement can be created within 5 seconds.
     */
    private PreparedStatement preparedStatement(String sqlQuery) throws DataAccessException {
        return datasource.prepareStatement(datasource.getConnection(), sqlQuery);
    }

    @Override
    public boolean isHealthy() {
        if (!isInitialized()) {
            return false;
        }

        if (isInitializationFailed()) {
            return false;
        }

        final String sql = "SELECT ID FROM ISSUER";

        try {
            PreparedStatement ps = preparedStatement(sql);
            ResultSet rs = null;
            try {
                rs = ps.executeQuery();
                return true;
            } finally {
                releaseDbResources(ps, rs);
            }
        } catch (Exception ex) {
            LogUtil.error(LOG, ex);
            return false;
        }
    }

    private void releaseDbResources(Statement ps, ResultSet rs) {
        datasource.releaseResources(ps, rs);
    }

    @Override
    public void init(String conf, DataSourceWrapper datasource) throws OcspStoreException {
        ParamUtil.requireNonNull("conf", conf);
        this.datasource = ParamUtil.requireNonNull("datasource", datasource);

        sqlCs = datasource.buildSelectFirstSql(1,
                "NBEFORE,NAFTER,REV,RR,RT,RIT FROM CERT WHERE IID=? AND SN=?");
        sqlCsNoRit = datasource.buildSelectFirstSql(1,
                "NBEFORE,NAFTER,REV,RR,RT FROM CERT WHERE IID=? AND SN=?");

        sqlCsMap = new HashMap<>();
        sqlCsNoRitMap = new HashMap<>();

        Set<HashAlgoType> hashAlgos = certHashAlgoColNameMap.keySet();
        for (HashAlgoType hashAlgo : hashAlgos) {
            String shortName = certHashAlgoColNameMap.get(hashAlgo);
            String coreSql = "NBEFORE,NAFTER,ID,REV,RR,RT,RIT," + shortName
                + " FROM CERT INNER JOIN CHASH ON CERT.IID=? AND CERT.SN=? AND CERT.ID=CHASH.CID";
            sqlCsMap.put(hashAlgo, datasource.buildSelectFirstSql(1, coreSql));

            coreSql = "NBEFORE,NAFTER,ID,REV,RR,RT," + shortName
                + " FROM CERT INNER JOIN CHASH ON CERT.IID=? AND CERT.SN=? AND CERT.ID=CHASH.CID";
            sqlCsNoRitMap.put(hashAlgo, datasource.buildSelectFirstSql(1, coreSql));
        }

        StoreConf storeConf = new StoreConf(conf);

        try {
            Set<X509Certificate> includeIssuers = null;
            Set<X509Certificate> excludeIssuers = null;

            if (CollectionUtil.isNonEmpty(storeConf.caCertsIncludes())) {
                includeIssuers = parseCerts(storeConf.caCertsIncludes());
            }

            if (CollectionUtil.isNonEmpty(storeConf.caCertsExcludes())) {
                excludeIssuers = parseCerts(storeConf.caCertsExcludes());
            }

            this.issuerFilter = new IssuerFilter(includeIssuers, excludeIssuers);
        } catch (CertificateException ex) {
            throw new OcspStoreException(ex.getMessage(), ex);
        } // end try

        initIssuerStore();

        if (this.scheduledThreadPoolExecutor != null) {
            this.scheduledThreadPoolExecutor.shutdownNow();
        }
        StoreUpdateService storeUpdateService = new StoreUpdateService();
        List<Runnable> scheduledServices = getScheduledServices();
        int size = 1;
        if (scheduledServices != null) {
            size += scheduledServices.size();
        }
        this.scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(size);

        Random random = new Random();
        this.scheduledThreadPoolExecutor.scheduleAtFixedRate(storeUpdateService,
                60 + random.nextInt(60), 60, TimeUnit.SECONDS);
        if (scheduledServices != null) {
            for (Runnable service : scheduledServices) {
                this.scheduledThreadPoolExecutor.scheduleAtFixedRate(service,
                        60 + random.nextInt(60), 60, TimeUnit.SECONDS);
            }
        }
    }

    @Override
    public void shutdown() throws OcspStoreException {
        if (scheduledThreadPoolExecutor != null) {
            scheduledThreadPoolExecutor.shutdown();
            scheduledThreadPoolExecutor = null;
        }

        if (datasource != null) {
            datasource.close();
        }
    }

    @Override
    public boolean canResolveIssuer(RequestIssuer reqIssuer) {
        return null != issuerStore.getIssuerForFp(reqIssuer);
    }

    @Override
    public X509Certificate getIssuerCert(RequestIssuer reqIssuer) {
        IssuerEntry issuer = issuerStore.getIssuerForFp(reqIssuer);
        return (issuer == null) ? null : issuer.cert();
    }

    protected boolean isInitialized() {
        return initialized;
    }

    protected boolean isInitializationFailed() {
        return initializationFailed;
    }

    private static Set<X509Certificate> parseCerts(Set<String> certFiles)
            throws OcspStoreException {
        Set<X509Certificate> certs = new HashSet<>(certFiles.size());
        for (String certFile : certFiles) {
            try {
                certs.add(X509Util.parseCert(certFile));
            } catch (CertificateException | IOException ex) {
                throw new OcspStoreException("could not parse X.509 certificate from file "
                        + certFile + ": " + ex.getMessage(), ex);
            }
        }
        return certs;
    }

}
