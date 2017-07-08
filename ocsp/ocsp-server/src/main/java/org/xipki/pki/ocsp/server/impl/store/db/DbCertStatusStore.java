/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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

package org.xipki.pki.ocsp.server.impl.store.db;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
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

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.pki.ocsp.api.CertStatusInfo;
import org.xipki.pki.ocsp.api.IssuerHashNameAndKey;
import org.xipki.pki.ocsp.api.OcspStore;
import org.xipki.pki.ocsp.api.OcspStoreException;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.HashAlgoType;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DbCertStatusStore extends OcspStore {

    private static class SimpleIssuerEntry {

        private final int id;

        private final Long revocationTimeMs;

        SimpleIssuerEntry(final int id, final Long revocationTimeMs) {
            this.id = id;
            this.revocationTimeMs = revocationTimeMs;
        }

        public boolean match(final IssuerEntry issuer) {
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

    private String sqlCs;

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
                PreparedStatement ps = borrowPreparedStatement(sql);
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
            PreparedStatement ps = borrowPreparedStatement(sql);

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
                    IssuerHashNameAndKey sha1IssuerHash
                            = caInfoEntry.getIssuerHashNameAndKey(HashAlgoType.SHA1);
                    for (IssuerEntry existingIssuer : caInfos) {
                        if (existingIssuer.matchHash(HashAlgoType.SHA1,
                                sha1IssuerHash.issuerNameHash(),
                                sha1IssuerHash.issuerKeyHash())) {
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
    public CertStatusInfo getCertStatus(final Date time, final HashAlgoType hashAlgo,
            final byte[] issuerNameHash, final byte[] issuerKeyHash, final BigInteger serialNumber,
            final boolean includeCertHash, final HashAlgoType certHashAlg)
            throws OcspStoreException {
        ParamUtil.requireNonNull("hashAlgo", hashAlgo);
        ParamUtil.requireNonNull("serialNumber", serialNumber);

        if (serialNumber.signum() != 1) { // non-positive serial number
            return CertStatusInfo.getUnknownCertStatusInfo(new Date(), null);
        }

        // wait for max. 0.5 second
        int num = 5;
        while (!initialized && (num-- > 0)) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException ex) { // CHECKSTYLE:SKIP
            }
        }

        if (!initialized) {
            throw new OcspStoreException("initialization of CertStore is still in process");
        }

        if (initializationFailed) {
            throw new OcspStoreException("initialization of CertStore failed");
        }

        String sql;
        HashAlgoType certHashAlgo = null;
        if (includeCertHash) {
            certHashAlgo = (certHashAlg == null) ? hashAlgo : certHashAlg;
            sql = sqlCsMap.get(certHashAlgo);
        } else {
            sql = sqlCs;
        }

        try {
            IssuerEntry issuer = issuerStore.getIssuerForFp(hashAlgo, issuerNameHash,
                    issuerKeyHash);
            if (issuer == null) {
                return CertStatusInfo.getIssuerUnknownCertStatusInfo(new Date(), null);
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
            long revocationTime = 0;
            long invalidatityTime = 0;

            PreparedStatement ps = borrowPreparedStatement(sql);

            try {
                int idx = 1;
                ps.setInt(idx++, issuer.id());
                ps.setString(idx++, serialNumber.toString(16));

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
                            b64CertHash = rs.getString(certHashAlgo.getShortName());
                        }

                        revoked = rs.getBoolean("REV");
                        if (revoked) {
                            reason = rs.getInt("RR");
                            revocationTime = rs.getLong("RT");
                            invalidatityTime = rs.getLong("RIT");
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
                    byte[] certHash = null;
                    if (b64CertHash != null) {
                        certHash = Base64.decode(b64CertHash);
                    }

                    if (revoked) {
                        Date invTime = null;
                        if (invalidatityTime != 0 && invalidatityTime != revocationTime) {
                            invTime = new Date(invalidatityTime * 1000);
                        }
                        CertRevocationInfo revInfo = new CertRevocationInfo(reason,
                                new Date(revocationTime * 1000), invTime);
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
    private PreparedStatement borrowPreparedStatement(final String sqlQuery)
            throws DataAccessException {
        PreparedStatement ps = null;
        Connection conn = datasource.getConnection();
        if (conn != null) {
            ps = datasource.prepareStatement(conn, sqlQuery);
        }
        if (ps == null) {
            throw new DataAccessException("could not create prepared statement for " + sqlQuery);
        }
        return ps;
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
            PreparedStatement ps = borrowPreparedStatement(sql);
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

    private void releaseDbResources(final Statement ps, final ResultSet rs) {
        datasource.releaseResources(ps, rs);
    }

    @Override
    public void init(final String conf, final DataSourceWrapper datasource)
            throws OcspStoreException {
        ParamUtil.requireNonNull("conf", conf);
        this.datasource = ParamUtil.requireNonNull("datasource", datasource);

        sqlCs = datasource.buildSelectFirstSql(1,
                "NBEFORE,NAFTER,REV,RR,RT,RIT,FROM CERT WHERE IID=? AND SN=?");
        sqlCsMap = new HashMap<>();

        HashAlgoType[] hashAlgos = new HashAlgoType[]{HashAlgoType.SHA1,  HashAlgoType.SHA224,
            HashAlgoType.SHA256, HashAlgoType.SHA384, HashAlgoType.SHA512};
        for (HashAlgoType hashAlgo : hashAlgos) {
            String coreSql = "NBEFORE,NAFTER,ID,REV,RR,RT,RIT," + hashAlgo.getShortName()
                + " FROM CERT INNER JOIN CHASH ON CERT.IID=? AND CERT.SN=? AND CERT.ID=CHASH.CID";
            sqlCsMap.put(hashAlgo, datasource.buildSelectFirstSql(1, coreSql));
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
    public boolean canResolveIssuer(final HashAlgoType hashAlgo, final byte[] issuerNameHash,
            final byte[] issuerKeyHash) {
        return null != issuerStore.getIssuerForFp(hashAlgo, issuerNameHash, issuerKeyHash);
    }

    @Override
    public X509Certificate getIssuerCert(HashAlgoType hashAlgo, byte[] issuerNameHash,
            byte[] issuerKeyHash) {
        IssuerEntry issuer = issuerStore.getIssuerForFp(hashAlgo, issuerNameHash, issuerKeyHash);
        return (issuer == null) ? null : issuer.cert();
    }

    @Override
    public Set<IssuerHashNameAndKey> issuerHashNameAndKeys() {
        return issuerStore.issuerHashNameAndKeys();
    }

    @Override
    public CertRevocationInfo getCaRevocationInfo(final HashAlgoType hashAlgo,
            final byte[] issuerNameHash, final byte[] issuerKeyHash) {
        IssuerEntry issuer = issuerStore.getIssuerForFp(hashAlgo, issuerNameHash, issuerKeyHash);
        return (issuer == null) ? null : issuer.revocationInfo();
    }

    protected boolean isInitialized() {
        return initialized;
    }

    protected boolean isInitializationFailed() {
        return initializationFailed;
    }

    private static Set<X509Certificate> parseCerts(final Set<String> certFiles)
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
