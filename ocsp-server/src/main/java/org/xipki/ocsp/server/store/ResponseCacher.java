// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.store;

import org.bouncycastle.crypto.Digest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.api.RequestIssuer;
import org.xipki.ocsp.server.OcspRespWithCacheInfo;
import org.xipki.ocsp.server.OcspRespWithCacheInfo.ResponseCacheInfo;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.datasource.DataAccessException;
import org.xipki.util.datasource.DataAccessException.Reason;
import org.xipki.util.datasource.DataSourceWrapper;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.extra.misc.SqlUtil;
import org.xipki.util.extra.type.Validity;
import org.xipki.util.misc.StringUtil;

import java.io.Closeable;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Response cacher.
 *
 * @author Lijun Liao (xipki)
 */

public class ResponseCacher implements Closeable {

  private static final Logger LOG =
      LoggerFactory.getLogger(ResponseCacher.class);

  private static final long SEC_DFLT_NEXT_UPDATE_DURATION = 7L * 24 * 60 * 60;

  private static final long SEC_NEXT_UPDATE_BUFFER = 600;

  private static final String SQL_ADD_ISSUER =
      SqlUtil.buildInsertSql("ISSUER", "ID,S1C,CERT");

  private static final String SQL_SELECT_ISSUER_ID = "SELECT ID FROM ISSUER";

  private static final String SQL_DELETE_EXPIRED_RESP =
      "DELETE FROM OCSP WHERE GENERATED_AT<? OR NEXT_UPDATE<?";

  private static final String SQL_ADD_RESP = SqlUtil.buildInsertSql("OCSP",
      "ID,IID,IDENT,GENERATED_AT,NEXT_UPDATE,RESP");

  private static final String SQL_UPDATE_RESP =
      "UPDATE OCSP SET GENERATED_AT=?,NEXT_UPDATE=?,RESP=? WHERE ID=?";

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

    private final Object lock = new Object();

    private final AtomicBoolean inProcess = new AtomicBoolean(false);

    @Override
    public void run() {
      if (inProcess.get()) {
        return;
      }

      synchronized (lock) {
        inProcess.set(true);
        long now = Instant.now().getEpochSecond();
        long maxGeneratedAt = now - validity;
        long minNextUpdate = now + SEC_NEXT_UPDATE_BUFFER;

        try {
          int num1 = removeExpiredResponses(maxGeneratedAt, minNextUpdate);
          if (num1 > 0 && LOG.isInfoEnabled()) {
            LOG.info("removed {} with thisUpdate < {} ({}) OR " +
                "nextUpdate < {} ({})",
                num1 == 1 ? "1 response" : num1 + " responses",
                maxGeneratedAt, Instant.ofEpochSecond(maxGeneratedAt),
                minNextUpdate, Instant.ofEpochSecond(minNextUpdate));
          }
        } catch (Throwable th) {
          LogUtil.error(LOG, th, "could not remove expired responses");
        } finally {
          inProcess.set(false);
        }
      } // end lock
    } // method run

  } // class ExpiredResponsesCleaner

  private final String sqlSelectIssuerCert;

  private final String sqlSelectOcsp;

  private final boolean master;

  // validity in seconds
  private final int validity;

  private final AtomicBoolean onService;

  private DataSourceWrapper datasource;

  private final IssuerStore issuerStore = new IssuerStore();

  private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

  private ScheduledFuture<?> responseCleaner;

  private ScheduledFuture<?> issuerUpdater;

  private final AtomicInteger cachedIssuerId = new AtomicInteger(0);

  public ResponseCacher(DataSourceWrapper datasource, boolean master,
                        Validity validity) {
    this.datasource = Args.notNull(datasource, "datasource");
    this.master = master;
    this.validity = (int) (Args.notNull(validity, "validity")
                            .approxMinutes() * 60);
    this.sqlSelectIssuerCert = datasource.buildSelectFirstSql(1,
        "CERT FROM ISSUER WHERE ID=?");
    this.sqlSelectOcsp = datasource.buildSelectFirstSql(1,
        "IID,IDENT,GENERATED_AT,NEXT_UPDATE,RESP FROM OCSP WHERE ID=?");
    this.onService = new AtomicBoolean(false);
  }

  public boolean isOnService() {
    return onService.get();
  }

  public void init() {
    updateCacheStore();

    scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1);
    scheduledThreadPoolExecutor.setRemoveOnCancelPolicy(true);

    // check every 600 seconds (10 minutes)
    this.responseCleaner = scheduledThreadPoolExecutor.scheduleAtFixedRate(
        new ExpiredResponsesCleaner(), 348, 600, TimeUnit.SECONDS);

    // check every 600 seconds (10 minutes)
    this.issuerUpdater = scheduledThreadPoolExecutor.scheduleAtFixedRate(
        new IssuerUpdater(), 448, 600, TimeUnit.SECONDS);
  } // method init

  @Override
  public void close() {
    if (datasource != null) {
      datasource.close();
      datasource = null;
    }

    if (responseCleaner != null) {
      responseCleaner.cancel(false);
      responseCleaner = null;
    }

    if (issuerUpdater != null) {
      issuerUpdater.cancel(false);
      issuerUpdater = null;
    }

    if (scheduledThreadPoolExecutor != null) {
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
  } // method close

  public IssuerEntry getIssuer(RequestIssuer reqIssuer) {
    return issuerStore.getIssuerForFp(reqIssuer);
  }

  public synchronized IssuerEntry storeIssuer(X509Cert issuerCert)
      throws CertificateException, DataAccessException {
    if (!master) {
      throw new IllegalStateException(
          "storeIssuer is not permitted in slave mode");
    }

    for (Integer id : issuerStore.ids()) {
      IssuerEntry issuer = issuerStore.getIssuerForId(id);
      if (issuer.cert().equals(issuerCert)) {
        return issuer;
      }
    }

    byte[] encodedCert = issuerCert.getEncoded();
    String sha1FpCert = HashAlgo.SHA1.base64Hash(encodedCert);

    int maxId = (int) datasource.getMax(null, "ISSUER", "ID");
    int id = Math.max(maxId, cachedIssuerId.get()) + 1;
    cachedIssuerId.set(id);

    try {
      final String sql = SQL_ADD_ISSUER;
      PreparedStatement ps = null;
      try {
        ps = datasource.prepareStatement(sql);
        int idx = 1;
        ps.setInt(idx++, id);
        ps.setString(idx++, sha1FpCert);
        ps.setString(idx, Base64.getEncoder().encodeToString(encodedCert));

        ps.execute();

        IssuerEntry newInfo = new IssuerEntry(id, issuerCert);
        issuerStore.addIssuer(newInfo);
        return newInfo;
      } catch (SQLException ex) {
        throw datasource.translate(sql, ex);
      } finally {
        datasource.releaseResources(ps, null);
      }
    } catch (DataAccessException ex) {
      if (ex.reason().isDescendantOrSelfOf(Reason.DuplicateKey)) {
        return issuerStore.getIssuerForId(id);
      }
      throw ex;
    }
  } // method storeIssuer

  public OcspRespWithCacheInfo getOcspResponse(
      int issuerId, BigInteger serialNumber, SignAlgo sigAlgo)
      throws DataAccessException {
    final String sql = sqlSelectOcsp;
    byte[] identBytes = buildIdent(serialNumber, sigAlgo);
    long id = deriveId(issuerId, identBytes);
    PreparedStatement ps = datasource.prepareStatement(sql);
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

      String ident = Base64.getEncoder().encodeToString(identBytes);
      String dbIdent = rs.getString("IDENT");
      if (!ident.equals(dbIdent)) {
        return null;
      }

      long nextUpdate = rs.getLong("NEXT_UPDATE");
      if (nextUpdate != 0) {
        // nextUpdate must be at least in 600 seconds
        long minNextUpdate = Instant.now().getEpochSecond() + 600;

        if (nextUpdate < minNextUpdate) {
          return null;
        }
      }

      long generatedAt = rs.getLong("GENERATED_AT");
      String b64Resp = rs.getString("RESP");
      byte[] resp = Base64.decodeFast(b64Resp);
      ResponseCacheInfo cacheInfo = new ResponseCacheInfo(generatedAt);
      if (nextUpdate != 0) {
        cacheInfo.setNextUpdate(nextUpdate);
      }
      return new OcspRespWithCacheInfo(resp, cacheInfo);
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, rs);
    }
  } // method getOcspResponse

  public void storeOcspResponse(
      int issuerId, BigInteger serialNumber, long generatedAt,
      Long nextUpdate, SignAlgo sigAlgo, byte[] response) {
    long nowInSec = Instant.now().getEpochSecond();
    if (nextUpdate == null) {
      nextUpdate = nowInSec + SEC_DFLT_NEXT_UPDATE_DURATION;
    }

    if (nextUpdate - nowInSec < validity) {
      return;
    }

    byte[] identBytes = buildIdent(serialNumber, sigAlgo);
    String ident = Base64.getEncoder().encodeToString(identBytes);
    try {
      long id = deriveId(issuerId, identBytes);

      Connection conn = datasource.getConnection();
      try {
        String sql = SQL_ADD_RESP;
        PreparedStatement ps = datasource.prepareStatement(conn, sql);

        String b64Response = Base64.getEncoder().encodeToString(response);
        Boolean dataIntegrityViolationException = null;
        try {
          int idx = 1;
          ps.setLong(idx++, id);
          ps.setInt(idx++, issuerId);
          ps.setString(idx++, ident);
          ps.setLong(idx++, generatedAt);
          ps.setLong(idx++, nextUpdate);
          ps.setString(idx, b64Response);
          ps.execute();
        } catch (SQLException ex) {
          DataAccessException dex = datasource.translate(sql, ex);
          if (dex.reason().isDescendantOrSelfOf(
                Reason.DataIntegrityViolation)) {
            dataIntegrityViolationException = Boolean.TRUE;
          } else {
            throw dex;
          }
        } finally {
          datasource.releaseResources(ps, null, false);
        }

        if (dataIntegrityViolationException == null) {
          LOG.debug("added cached OCSP response iid={}, ident={}",
              issuerId, ident);
          return;
        }

        sql = SQL_UPDATE_RESP;
        ps = datasource.prepareStatement(conn, sql);
        try {
          int idx = 1;
          ps.setLong(idx++, generatedAt);
          ps.setLong(idx++, nextUpdate);
          ps.setString(idx++, b64Response);
          ps.setLong(idx, id);
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
      LOG.info("could not cache OCSP response iid={}, ident={}",
          issuerId, ident);
      if (LOG.isDebugEnabled()) {
        LOG.debug("could not cache OCSP response iid={}, ident={}",
            issuerId, ident, ex);
      }
    }
  } // method storeOcspResponse

  private int removeExpiredResponses(long maxGeneratedAt, long minNextUpdate)
      throws DataAccessException {
    final String sql = SQL_DELETE_EXPIRED_RESP;
    PreparedStatement ps = null;
    try {
      ps = datasource.prepareStatement(sql);
      ps.setLong(1, maxGeneratedAt);
      ps.setLong(2, minNextUpdate);
      return ps.executeUpdate();
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method removeExpiredResponses

  private void updateCacheStore() {
    boolean stillOnService = updateCacheStore0();
    this.onService.set(stillOnService);
    if (!stillOnService) {
      LOG.error("OCSP response cacher is out of service");
    } else {
      LOG.info("OCSP response cacher is on service");
    }
  } // method updateCacheStore

  /**
   * update the cache store.
   * @return whether the ResponseCacher is on service.
   */
  private boolean updateCacheStore0() {
    try {
      // check for new issuers
      PreparedStatement ps = null;
      ResultSet rs = null;

      Set<Integer> ids = new HashSet<>();
      try {
        ps = datasource.prepareStatement(SQL_SELECT_ISSUER_ID);
        rs = ps.executeQuery();

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
        datasource.releaseResources(ps, rs, true);
      }

      // add the new issuers
      rs = null;

      ids.removeAll(issuerStore.ids());
      if (ids.isEmpty()) {
        // no new issuer
        return true;
      }

      ps = datasource.prepareStatement(sqlSelectIssuerCert);
      try {
        for (Integer id : ids) {
          try {
            ps.setInt(1, id);
            rs = ps.executeQuery();
            rs.next();
            X509Cert cert = X509Util.parseCert(
                StringUtil.toUtf8Bytes(rs.getString("CERT")));
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
            // only release ResultSet rs here
            datasource.releaseResources(null, rs, false);
          }
        }
      } finally {
        datasource.releaseResources(ps, null, true);
      }
    } catch (DataAccessException ex) {
      LogUtil.error(LOG, ex, "could not executing updateCacheStore()");
      return false;
    }

    return true;
  } // method updateCacheStore0

  private static byte[] buildIdent(BigInteger serialNumber, SignAlgo sigAlgo) {
    byte[] snBytes = serialNumber.toByteArray();
    byte[] bytes = new byte[1 + snBytes.length];
    bytes[0] = sigAlgo.code();
    System.arraycopy(snBytes, 0, bytes, 1, snBytes.length);
    return bytes;
  }

  private long deriveId(int issuerId, byte[] identBytes) {
    byte[] hash = new byte[20];
    Digest digest = HashAlgo.SHA1.createDigest();
    digest.reset();
    digest.update(int2Bytes(issuerId), 0, 2);
    digest.update(identBytes, 0, identBytes.length);
    digest.doFinal(hash, 0);

    return (0x7FL & hash[0]) << 56 // ignore the first bit
        | (0xFFL & hash[1]) << 48 | (0xFFL & hash[2]) << 40
        | (0xFFL & hash[3]) << 32 | (0xFFL & hash[4]) << 24
        | (0xFFL & hash[5]) << 16 | (0xFFL & hash[6]) << 8
        | (0xFFL & hash[7]);
  } // method deriveId

  private static byte[] int2Bytes(int value) {
    if (value > -1 && value < 65535) {
      return new byte[]{(byte) (value >> 8), (byte) value};
    } else {
      throw new IllegalArgumentException(
          "value is out of the range [0, 65535]: " + value);
    }
  }

}
