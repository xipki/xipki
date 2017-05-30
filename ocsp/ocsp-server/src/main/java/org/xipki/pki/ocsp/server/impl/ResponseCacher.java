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

package org.xipki.pki.ocsp.server.impl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.InvalidConfException;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.datasource.DataSourceWrapper;
import org.xipki.commons.datasource.springframework.dao.DataAccessException;
import org.xipki.commons.datasource.springframework.dao.DataIntegrityViolationException;
import org.xipki.commons.datasource.springframework.jdbc.DuplicateKeyException;
import org.xipki.commons.security.AlgorithmCode;
import org.xipki.commons.security.HashAlgoType;
import org.xipki.commons.security.util.X509Util;
import org.xipki.pki.ocsp.api.IssuerHashNameAndKey;
import org.xipki.pki.ocsp.server.impl.OcspRespWithCacheInfo.ResponseCacheInfo;
import org.xipki.pki.ocsp.server.impl.store.db.IssuerEntry;
import org.xipki.pki.ocsp.server.impl.store.db.IssuerStore;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

class ResponseCacher {
    private static final Logger LOG = LoggerFactory.getLogger(ResponseCacher.class);

    private static final String SQL_ADD_ISSUER = "INSERT INTO ISSUER (ID,S1C,CERT) VALUES (?,?,?)";

    private static final String SQL_SELECT_ISSUER_ID = "SELECT ID FROM ISSUER";

    private static final String SQL_SELECT_ISSUER = "SELECT ID,CERT FROM ISSUER";

    private static final String SQL_DELETE_EXPIRED_RESP = "DELETE FROM OCSP WHERE THIS_UPDATE<?";

    private static final String SQL_ADD_RESP = "INSERT INTO OCSP (ID,IID,IDENT,"
            + "THIS_UPDATE,NEXT_UPDATE,RESP) VALUES (?,?,?,?,?,?)";

    private static final String SQL_UPDATE_RESP = "UPDATE OCSP SET THIS_UPDATE=?,"
            + "NEXT_UPDATE=?,RESP=? WHERE ID=?";

    private final BlockingDeque<Digest> idDigesters;

    private class IssuerUpdater implements Runnable {

        @Override
        public void run() {
            try {
                updateCacheStore();
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "error while calling updateCacheStore()");
            }
        }

    } // class StoreUpdateService

    private class ExpiredResponsesCleaner implements Runnable {

        private boolean inProcess;

        @Override
        public void run() {
            if (inProcess) {
                return;
            }

            inProcess = true;
            long maxThisUpdate = System.currentTimeMillis() / 1000 - validity;
            try {
                int num = removeExpiredResponses(maxThisUpdate);
                LOG.info("removed {} response with thisUpdate < {}", num, maxThisUpdate);
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "could not remove expired responses");
            } finally {
                inProcess = false;
            }
        } // method run

    } // class ExpiredResponsesCleaner

    private final DataSourceWrapper datasource;

    private final String sqlSelectIssuerCert;

    private final String sqlSelectOcsp;

    private final boolean master;

    private final int validity;

    private AtomicBoolean onService;

    private IssuerStore issuerStore;

    private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

    private ScheduledFuture<?> responseCleaner;

    private ScheduledFuture<?> issuerUpdater;

    ResponseCacher(DataSourceWrapper datasource, boolean master, int validity) {
        this.datasource = ParamUtil.requireNonNull("datasource", datasource);
        this.master = master;
        this.validity = ParamUtil.requireMin("validity", validity, 1);
        this.sqlSelectIssuerCert = datasource.buildSelectFirstSql(1,
                "CERT FROM ISSUER WHERE ID=?");
        this.sqlSelectOcsp = datasource.buildSelectFirstSql(1,
                "IID,IDENT,THIS_UPDATE,NEXT_UPDATE,RESP FROM OCSP WHERE ID=?");
        this.onService = new AtomicBoolean(false);

        this.idDigesters = new LinkedBlockingDeque<>();
        for (int i = 0; i < 20; i++) {
            Digest md = HashAlgoType.SHA1.createDigest();
            idDigesters.addLast(md);
        }
    }

    boolean isOnService() {
        return onService.get() && issuerStore != null;
    }

    void init() {
        updateCacheStore();

        scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1);
        scheduledThreadPoolExecutor.setRemoveOnCancelPolicy(true);

        // check every 600 seconds (10 minutes)
        this.responseCleaner = scheduledThreadPoolExecutor.scheduleAtFixedRate(
                new ExpiredResponsesCleaner(), 348, 600, TimeUnit.SECONDS);

        // check every 600 seconds (10 minutes)
        this.issuerUpdater = scheduledThreadPoolExecutor.scheduleAtFixedRate(
                new IssuerUpdater(), 448, 600, TimeUnit.SECONDS);
    }

    void shutdown() {
        if (scheduledThreadPoolExecutor == null) {
            return;
        }

        if (responseCleaner != null) {
            responseCleaner.cancel(false);
            responseCleaner = null;
        }

        if (issuerUpdater != null) {
            issuerUpdater.cancel(false);
            issuerUpdater = null;
        }

        scheduledThreadPoolExecutor.shutdown();
        while (!scheduledThreadPoolExecutor.isTerminated()) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException ex) {
                LOG.error("interrupted: {}", ex.getMessage());
            }
        }
        scheduledThreadPoolExecutor = null;
    }

    Integer getIssuerId(HashAlgoType hashAlgo, byte[] nameHash, byte[] keyHash) {
        IssuerEntry issuer = issuerStore.getIssuerForFp(hashAlgo, nameHash, keyHash);
        return (issuer == null) ? null : issuer.getId();
    }

    Integer storeIssuer(X509Certificate issuerCert)
            throws CertificateException, InvalidConfException, DataAccessException {
        if (!master) {
            throw new IllegalStateException("storeIssuer is not permitted in slave mode");
        }

        for (Integer id : issuerStore.getIds()) {
            if (issuerStore.getIssuerForId(id).getCert().equals(issuerCert)) {
                return id;
            }
        }

        byte[] encodedCert = issuerCert.getEncoded();
        String sha1FpCert = HashAlgoType.SHA1.base64Hash(encodedCert);

        int maxId = (int) datasource.getMax(null, "ISSUER", "ID");
        int id = maxId + 1;
        try {
            final String sql = SQL_ADD_ISSUER;
            PreparedStatement ps = null;
            try {
                ps = prepareStatement(sql);
                int idx = 1;
                ps.setInt(idx++, id);
                ps.setString(idx++, sha1FpCert);
                ps.setString(idx++, Base64.toBase64String(encodedCert));

                ps.execute();

                IssuerEntry newInfo = new IssuerEntry(id, issuerCert);
                issuerStore.addIssuer(newInfo);
                return id;
            } catch (SQLException ex) {
                throw datasource.translate(sql, ex);
            } finally {
                datasource.releaseResources(ps, null);
            }
        } catch (DataAccessException ex) {
            if (ex instanceof DuplicateKeyException) {
                return id;
            }
            throw ex;
        }
    }

    OcspRespWithCacheInfo getOcspResponse(int issuerId, BigInteger serialNumber,
            AlgorithmCode sigAlg, AlgorithmCode certHashAlg)
            throws DataAccessException {
        final String sql = sqlSelectOcsp;
        String ident = buildIdent(serialNumber, sigAlg, certHashAlg);
        long id = deriveId(issuerId, ident);
        PreparedStatement ps = prepareStatement(sql);
        ResultSet rs = null;

        try {
            ps.setLong(1, id);
            rs = ps.executeQuery();
            if (!rs.next()) {
                return null;
            }

            int dbIid = rs.getInt("IID");
            if (dbIid != issuerId) {
                return null;
            }

            String dbIdent = rs.getString("IDENT");
            if (!ident.equals(dbIdent)) {
                return null;
            }

            long nextUpdate = rs.getLong("NEXT_UPDATE");
            if (nextUpdate != 0) {
                // nextUpdate must be at least in 600 seconds
                long minNextUpdate = System.currentTimeMillis() / 1000 + 600;

                if (nextUpdate < minNextUpdate) {
                    return null;
                }
            }

            long thisUpdate = rs.getLong("THIS_UPDATE");
            String b64Resp = rs.getString("RESP");
            OCSPResp resp;
            try {
                resp = new OCSPResp(Base64.decode(b64Resp));
            } catch (IOException ex) {
                LOG.warn("could not parse OCSPResp");
                return null;
            }
            ResponseCacheInfo cacheInfo = new ResponseCacheInfo(thisUpdate);
            if (nextUpdate != 0) {
                cacheInfo.setNextUpdate(nextUpdate);
            }
            return new OcspRespWithCacheInfo(resp, cacheInfo);
        } catch (SQLException ex) {
            throw datasource.translate(sql, ex);
        } finally {
            datasource.releaseResources(ps, rs);
        }
    }

    void storeOcspResponse(int issuerId, BigInteger serialNumber, long thisUpdate,
            Long nextUpdate, AlgorithmCode sigAlgCode, AlgorithmCode certHashAlgCode,
            OCSPResp response) {
        String ident = buildIdent(serialNumber, sigAlgCode, certHashAlgCode);
        try {
            byte[] encodedResp;
            try {
                encodedResp = response.getEncoded();
            } catch (IOException ex) {
                LogUtil.error(LOG, ex,
                    "could not cache OCSP response iid=" + issuerId + ", ident=" + ident);
                return;
            }

            long id = deriveId(issuerId, ident);

            Connection conn = datasource.getConnection();
            try {
                String sql = SQL_ADD_RESP;
                PreparedStatement ps = datasource.prepareStatement(conn, sql);

                Boolean dataIntegrityViolationException = null;
                try {
                    int idx = 1;
                    ps.setLong(idx++, id);
                    ps.setInt(idx++, issuerId);
                    ps.setString(idx++, ident);
                    ps.setLong(idx++, thisUpdate);
                    if (nextUpdate != null && nextUpdate > 0) {
                        ps.setLong(idx++, nextUpdate);
                    } else {
                        ps.setNull(idx++, java.sql.Types.BIGINT);
                    }
                    ps.setString(idx++, Base64.toBase64String(encodedResp));
                    ps.execute();
                } catch (SQLException ex) {
                    DataAccessException dex = datasource.translate(sql, ex);
                    if (dex instanceof DataIntegrityViolationException) {
                        dataIntegrityViolationException = Boolean.TRUE;
                    } else {
                        throw dex;
                    }
                } finally {
                    datasource.releaseResources(ps, null, false);
                }

                if (dataIntegrityViolationException == null) {
                    LOG.debug("added cached OCSP response iid={}, ident={}", issuerId, ident);
                    return;
                }

                sql = SQL_UPDATE_RESP;
                ps = datasource.prepareStatement(conn, sql);
                try {
                    int idx = 1;
                    ps.setLong(idx++, thisUpdate);
                    if (nextUpdate != null && nextUpdate > 0) {
                        ps.setLong(idx++, nextUpdate);
                    } else {
                        ps.setNull(idx++, java.sql.Types.BIGINT);
                    }
                    ps.setString(idx++, Base64.toBase64String(encodedResp));
                    ps.setLong(idx++, id);
                    ps.executeUpdate();
                } catch (SQLException ex) {
                    throw datasource.translate(sql, ex);
                } finally {
                    datasource.releaseResources(ps, null, false);
                }
            } finally {
                datasource.returnConnection(conn);
            }
        } catch (DataAccessException ex) {
            LOG.info("could not cache OCSP response iid={}, ident={}", issuerId, ident);
            if (LOG.isDebugEnabled()) {
                LOG.debug("could not cache OCSP response iid=" + issuerId + ", ident=" + ident, ex);
            }
        }
    }

    private int removeExpiredResponses(long maxThisUpdate) throws DataAccessException {
        final String sql = SQL_DELETE_EXPIRED_RESP;
        PreparedStatement ps = null;
        try {
            ps = prepareStatement(sql);
            ps.setLong(1, maxThisUpdate);
            return ps.executeUpdate();
        } catch (SQLException ex) {
            throw datasource.translate(sql, ex);
        } finally {
            datasource.releaseResources(ps, null);
        }
    }

    private void updateCacheStore() {
        boolean stillOnService = doUpdateCacheStore();
        this.onService.set(stillOnService);
        if (!stillOnService) {
            LOG.error("OCSP response cacher is out of service");
        } else {
            LOG.info("OCSP response cacher is on service");
        }
    }

    /**
     * update the cache store.
     * @return whether the ResponseCacher is on service.
     */
    private boolean doUpdateCacheStore() {
        try {
            if (this.issuerStore == null) {
                PreparedStatement ps = null;
                ResultSet rs = null;

                try {
                    ps = prepareStatement(SQL_SELECT_ISSUER);
                    rs = ps.executeQuery();
                    List<IssuerEntry> caInfos = new LinkedList<>();
                    while (rs.next()) {
                        int id = rs.getInt("ID");
                        String b64Cert = rs.getString("CERT");
                        X509Certificate cert = X509Util.parseBase64EncodedCert(b64Cert);
                        IssuerEntry caInfoEntry = new IssuerEntry(id, cert);
                        IssuerHashNameAndKey sha1IssuerHash
                                = caInfoEntry.getIssuerHashNameAndKey(HashAlgoType.SHA1);
                        for (IssuerEntry existingIssuer : caInfos) {
                            if (existingIssuer.matchHash(HashAlgoType.SHA1,
                                    sha1IssuerHash.getIssuerNameHash(),
                                    sha1IssuerHash.getIssuerKeyHash())) {
                                LOG.error(
                                    "found at least two issuers with the same subject and key");
                                return false;
                            }
                        }
                        caInfos.add(caInfoEntry);
                    } // end while (rs.next())

                    this.issuerStore = new IssuerStore(caInfos);
                    LOG.info("Updated issuers");
                } catch (SQLException ex) {
                    throw datasource.translate(SQL_SELECT_ISSUER, ex);
                } finally {
                    datasource.releaseResources(ps, rs, false);
                }

                return true;
            }

            // check for new issuers
            PreparedStatement ps = null;
            ResultSet rs = null;

            Set<Integer> ids = new HashSet<>();
            try {
                ps = prepareStatement(SQL_SELECT_ISSUER_ID);
                rs = ps.executeQuery();

                if (master) {
                    // If in master mode, the issuers are always up-to-date. Here just to check
                    // whether the database is accessible
                    return true;
                }

                while (rs.next()) {
                    ids.add(rs.getInt("ID"));
                }
            } catch (SQLException ex) {
                LogUtil.error(LOG, datasource.translate(SQL_SELECT_ISSUER_ID, ex),
                        "could not executing updateCacheStore()");
                return false;
            } catch (Exception ex) {
                LogUtil.error(LOG, ex, "could not executing updateCacheStore()");
                return false;
            } finally {
                datasource.releaseResources(ps, rs, false);
            }

            // add the new issuers
            ps = null;
            rs = null;

            Set<Integer> currentIds = issuerStore.getIds();

            for (Integer id : ids) {
                if (currentIds.contains(id)) {
                    continue;
                }

                try {
                    if (ps == null) {
                        ps = prepareStatement(sqlSelectIssuerCert);
                    }

                    ps.setInt(1, id);
                    rs = ps.executeQuery();
                    rs.next();
                    String b64Cert = rs.getString("CERT");
                    X509Certificate cert = X509Util.parseBase64EncodedCert(b64Cert);
                    IssuerEntry caInfoEntry = new IssuerEntry(id, cert);
                    issuerStore.addIssuer(caInfoEntry);
                    LOG.info("added issuer {}", id);
                } catch (SQLException ex) {
                    LogUtil.error(LOG, datasource.translate(sqlSelectIssuerCert, ex),
                            "could not executing updateCacheStore()");
                    return false;
                } catch (Exception ex) {
                    LogUtil.error(LOG, ex, "could not executing updateCacheStore()");
                    return false;
                } finally {
                    datasource.releaseResources(null, rs, false);
                }
            }

            if (ps != null) {
                datasource.releaseResources(ps, null, false);
            }
        } catch (DataAccessException ex) {
            LogUtil.error(LOG, ex, "could not executing updateCacheStore()");
            return false;
        } catch (CertificateException ex) {
            // don't set the onService to false.
            LogUtil.error(LOG, ex, "could not executing updateCacheStore()");
        }

        return true;
    } // method updateCacheStore

    private PreparedStatement prepareStatement(String sqlQuery) throws DataAccessException {
        Connection conn = datasource.getConnection();
        try {
            return datasource.prepareStatement(conn, sqlQuery);
        } catch (DataAccessException ex) {
            datasource.returnConnection(conn);
            throw ex;
        }
    }

    private static String buildIdent(BigInteger serialNumber,
            AlgorithmCode sigAlg, AlgorithmCode certHashAlg) {
        byte[] snBytes = serialNumber.toByteArray();
        byte[] bytes = new byte[2 + snBytes.length];
        bytes[0] = sigAlg.getCode();
        bytes[1] = (certHashAlg == null) ? 0 : certHashAlg.getCode();
        System.arraycopy(snBytes, 0, bytes, 2, snBytes.length);
        return Hex.toHexString(snBytes);
    }

    private long deriveId(int issuerId, String ident) {
        Digest digest = null;
        try {
            digest = idDigesters.poll(10, TimeUnit.SECONDS);
        } catch (InterruptedException ex) {
            digest = HashAlgoType.SHA1.createDigest();
        }

        byte[] hash = new byte[20];
        try {
            digest.update(intToBytes(issuerId), 0, 2);
            byte[] bytes = ident.getBytes();
            digest.update(bytes, 0, bytes.length);
            digest.doFinal(hash, 0);
        } finally {
            idDigesters.addLast(digest);
        }

        byte[] hiBytes = new byte[8];
        System.arraycopy(hash, 0, hiBytes, 0, 8);
        return new BigInteger(1, hiBytes).clearBit(63).longValue();
    }

    private static byte[] intToBytes(int value) {
        if (value < 65535) {
            return new byte[]{(byte) (value >> 8), (byte) value};
        } else {
            throw new IllegalArgumentException("value is too large");
        }
    }

}
