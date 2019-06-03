/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.ocsp.server.store;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Collection;
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
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.ocsp.api.CertStatusInfo;
import org.xipki.ocsp.api.CertStatusInfo.CertStatus;
import org.xipki.ocsp.api.CertStatusInfo.UnknownCertBehaviour;
import org.xipki.ocsp.api.OcspStore;
import org.xipki.ocsp.api.OcspStoreException;
import org.xipki.ocsp.api.RequestIssuer;
import org.xipki.ocsp.server.IssuerFilter;
import org.xipki.ocsp.server.OcspServerConf;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.CollectionUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;

import com.alibaba.fastjson.JSON;

/**
 * OcspStore for XiPKI OCSP database.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DbCertStatusStore extends OcspStore {

  private class StoreUpdateService implements Runnable {

    @Override
    public void run() {
      updateIssuerStore();
    }

  } // class StoreUpdateService

  protected DataSourceWrapper datasource;

  private static final Logger LOG = LoggerFactory.getLogger(DbCertStatusStore.class);

  private final AtomicBoolean storeUpdateInProcess = new AtomicBoolean(false);

  private String sqlCsNoRit;

  private String sqlCs;

  private String sqlCsNoRitWithCertHash;

  private String sqlCsWithCertHash;

  private IssuerFilter issuerFilter;

  private IssuerStore issuerStore = new IssuerStore();

  private HashAlgo certHashAlgo;

  private boolean initialized;

  private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

  protected List<Runnable> getScheduledServices() {
    return Arrays.asList(new StoreUpdateService());
  }

  protected IssuerStore getIssuerStore() {
    return issuerStore;
  }

  private synchronized void updateIssuerStore() {
    updateIssuerStore(false);
  }

  protected synchronized void updateIssuerStore(boolean force) {
    if (force) {
      while (storeUpdateInProcess.get()) {
        try {
          Thread.sleep(1000);
        } catch (InterruptedException ex) {
          LOG.warn("interrputed, continue waiting");
        }
      }
    } else {
      if (storeUpdateInProcess.get()) {
        return;
      }
    }

    storeUpdateInProcess.set(true);
    try {
      updateIssuers();
      updateCrls();
    } finally {
      initialized = true;
      storeUpdateInProcess.set(false);
    }
  }

  private void updateIssuers() {
    try {
      if (initialized) {
        final String sql = "SELECT ID,REV_INFO,S1C FROM ISSUER";
        PreparedStatement ps = preparedStatement(sql);
        ResultSet rs = null;

        try {
          Map<Integer, SimpleIssuerEntry> newIssuers = new HashMap<>();

          rs = ps.executeQuery();
          while (rs.next()) {
            if (!issuerFilter.includeAll()) {
              String sha1Fp = rs.getString("S1C");
              if (!issuerFilter.includeIssuerWithSha1Fp(sha1Fp)) {
                continue;
              }
            }

            int id = rs.getInt("ID");
            Long revTimeMs = null;
            String str = rs.getString("REV_INFO");
            if (str != null) {
              CertRevocationInfo revInfo = CertRevocationInfo.fromEncoded(str);
              revTimeMs = revInfo.getRevocationTime().getTime();
            }
            SimpleIssuerEntry issuerEntry = new SimpleIssuerEntry(id, revTimeMs);
            newIssuers.put(id, issuerEntry);
          }

          // no change in the issuerStore
          Set<Integer> newIds = newIssuers.keySet();
          Set<Integer> ids = (issuerStore != null) ? issuerStore.getIds() : Collections.emptySet();

          boolean issuersUnchanged = (ids.size() == newIds.size())
              && ids.containsAll(newIds) && newIds.containsAll(ids);

          if (issuersUnchanged) {
            for (Integer id : newIds) {
              IssuerEntry entry = issuerStore.getIssuerForId(id);
              SimpleIssuerEntry newEntry = newIssuers.get(id);
              if (!newEntry.match(entry)) {
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

      final String sql = "SELECT ID,NBEFORE,REV_INFO,S1C,CERT FROM ISSUER";
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

          X509Certificate cert = X509Util.parseCert(StringUtil.toUtf8Bytes(rs.getString("CERT")));

          IssuerEntry caInfoEntry = new IssuerEntry(rs.getInt("ID"), cert);
          RequestIssuer reqIssuer = new RequestIssuer(HashAlgo.SHA1,
              caInfoEntry.getEncodedHash(HashAlgo.SHA1));
          for (IssuerEntry existingIssuer : caInfos) {
            if (existingIssuer.matchHash(reqIssuer)) {
              throw new Exception("found at least two issuers with the same subject and key");
            }
          }

          String str = rs.getString("REV_INFO");
          if (str != null) {
            CertRevocationInfo revInfo = CertRevocationInfo.fromEncoded(str);
            caInfoEntry.setRevocationInfo(revInfo.getRevocationTime());
          }

          caInfos.add(caInfoEntry);
        } // end while (rs.next())

        this.issuerStore.setIssuers(caInfos);
        LOG.info("Updated issuers: {}", name);
      } finally {
        releaseDbResources(ps, rs);
      }
    } catch (Throwable th) {
      LogUtil.error(LOG, th, "error while executing updateIssuers()");
    }
  } // method updateIssuers

  private void updateCrls() {
    try {
      final String sql = "SELECT ID,INFO FROM CRL_INFO";
      PreparedStatement ps = preparedStatement(sql);
      ResultSet rs = null;

      try {
        Map<Integer, CrlInfo> crlInfos = new HashMap<>();

        rs = ps.executeQuery();
        while (rs.next()) {
          int id = rs.getInt("ID");
          String str = rs.getString("INFO");
          CrlInfo crlInfo = new CrlInfo(str);
          crlInfos.put(id, crlInfo);
        }

        issuerStore.setCrlInfos(crlInfos);

        LOG.info("Updated issuers: {}", name);
      } finally {
        releaseDbResources(ps, rs);
      }
    } catch (Throwable th) {
      LogUtil.error(LOG, th, "error while executing updateCrls()");
    }
  } // method updateCrls

  @Override
  protected CertStatusInfo getCertStatus0(Date time, RequestIssuer reqIssuer,
      BigInteger serialNumber, boolean includeCertHash, boolean includeRit,
      boolean inheritCaRevocation) throws OcspStoreException {
    if (serialNumber.signum() != 1) { // non-positive serial number
      return CertStatusInfo.getUnknownCertStatusInfo(new Date(), null);
    }

    if (!initialized) {
      throw new OcspStoreException("initialization of CertStore is still in process");
    }

    String sql;

    try {
      IssuerEntry issuer = issuerStore.getIssuerForFp(reqIssuer);
      if (issuer == null) {
        return null;
      }

      if (includeCertHash) {
        sql = includeRit ? sqlCsWithCertHash : sqlCsNoRitWithCertHash;
      } else {
        sql = includeRit ? sqlCs : sqlCsNoRit;
      }

      ResultSet rs = null;
      CertStatusInfo certStatusInfo = null;

      boolean unknown = true;
      boolean ignore = false;
      String b64CertHash = null;
      boolean revoked = false;
      int reason = 0;
      long revTime = 0;
      long invalTime = 0;
      int crlId = 0;

      PreparedStatement ps = datasource.prepareStatement(sql);

      try {
        ps.setInt(1, issuer.getId());
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
            crlId = rs.getInt("CRL_ID");
            if (includeCertHash) {
              b64CertHash = rs.getString("HASH");
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

      CrlInfo crlInfo = (crlId != 0) ? null : issuerStore.getCrlInfo(crlId);
      Date thisUpdate;
      Date nextUpdate;
      if (crlInfo == null) {
        thisUpdate = new Date();
        nextUpdate = null;
      } else {
        thisUpdate = crlInfo.getThisUpdate();
        nextUpdate = crlInfo.getNextUpdate();
      }

      if (unknown) {
        certStatusInfo = CertStatusInfo.getUnknownCertStatusInfo(thisUpdate, nextUpdate);
      } else if (ignore) {
        certStatusInfo = CertStatusInfo.getIgnoreCertStatusInfo(thisUpdate, nextUpdate);
      } else {
        byte[] certHash = (b64CertHash == null) ? null : Base64.decodeFast(b64CertHash);
        if (revoked) {
          Date invTime = (invalTime == 0 || invalTime == revTime)
              ? null : new Date(invalTime * 1000);
          CertRevocationInfo revInfo = new CertRevocationInfo(reason,
              new Date(revTime * 1000), invTime);
          certStatusInfo = CertStatusInfo.getRevokedCertStatusInfo(revInfo,
              certHashAlgo, certHash, thisUpdate, nextUpdate, null);
        } else {
          certStatusInfo = CertStatusInfo.getGoodCertStatusInfo(certHashAlgo,
              certHash, thisUpdate, nextUpdate, null);
        }
      }

      if (includeCrlId && crlInfo != null) {
        certStatusInfo.setCrlId(crlInfo.getCrlId());
      }

      if (includeArchiveCutoff) {
        if (retentionInterval != 0) {
          Date date;
          // expired certificate remains in status store for ever
          if (retentionInterval < 0) {
            date = issuer.getNotBefore();
          } else {
            long nowInMs = System.currentTimeMillis();
            long dateInMs = Math.max(issuer.getNotBefore().getTime(),
                nowInMs - DAY * retentionInterval);
            date = new Date(dateInMs);
          }

          certStatusInfo.setArchiveCutOff(date);
        }
      }

      if ((!inheritCaRevocation) || issuer.getRevocationInfo() == null) {
        return certStatusInfo;
      }

      CertRevocationInfo caRevInfo = issuer.getRevocationInfo();
      CertStatus certStatus = certStatusInfo.getCertStatus();
      boolean replaced = false;
      if (certStatus == CertStatus.GOOD) {
        replaced = true;
      } else if (certStatus == CertStatus.UNKNOWN || certStatus == CertStatus.IGNORE) {
        if (unknownCertBehaviour == UnknownCertBehaviour.good) {
          replaced = true;
        }
      } else if (certStatus == CertStatus.REVOKED) {
        if (certStatusInfo.getRevocationInfo().getRevocationTime().after(
              caRevInfo.getRevocationTime())) {
          replaced = true;
        }
      }

      if (replaced) {
        CertRevocationInfo newRevInfo;
        if (caRevInfo.getReason() == CrlReason.CA_COMPROMISE) {
          newRevInfo = caRevInfo;
        } else {
          newRevInfo = new CertRevocationInfo(CrlReason.CA_COMPROMISE,
              caRevInfo.getRevocationTime(), caRevInfo.getInvalidityTime());
        }
        certStatusInfo = CertStatusInfo.getRevokedCertStatusInfo(newRevInfo,
            certStatusInfo.getCertHashAlgo(), certStatusInfo.getCertHash(),
            certStatusInfo.getThisUpdate(), certStatusInfo.getNextUpdate(),
            certStatusInfo.getCertprofile());
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
    return datasource.prepareStatement(sqlQuery);
  }

  @Override
  public boolean isHealthy() {
    if (!isInitialized()) {
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

  /**
   * Initialize the store.
   *
   * @param sourceConf
   * the store source configuration. It contains following key-value pairs:
   * <ul>
   * <li>caCerts: optional
   *   <p/>
   *   CA certificate files to be included / excluded.</li>
   *  </ul>
   * @param datasource DataSource.
   */
  @Override
  public void init(Map<String, ? extends Object> sourceConf, DataSourceWrapper datasource)
      throws OcspStoreException {
    OcspServerConf.CaCerts caCerts = null;
    if (sourceConf != null) {
      Object objValue = sourceConf.get("caCerts");
      if (objValue != null) {
        caCerts = JSON.parseObject(JSON.toJSONBytes(objValue), OcspServerConf.CaCerts.class);
      }
    }

    this.datasource = Args.notNull(datasource, "datasource");

    sqlCs = datasource.buildSelectFirstSql(1,
        "NBEFORE,NAFTER,REV,RR,RT,RIT,CRL_ID FROM CERT WHERE IID=? AND SN=?");
    sqlCsNoRit = datasource.buildSelectFirstSql(1,
        "NBEFORE,NAFTER,REV,RR,RT,CRL_ID FROM CERT WHERE IID=? AND SN=?");

    sqlCsWithCertHash = datasource.buildSelectFirstSql(1,
        "NBEFORE,NAFTER,REV,RR,RT,RIT,HASH,CRL_ID FROM CERT WHERE IID=? AND SN=?");
    sqlCsNoRitWithCertHash = datasource.buildSelectFirstSql(1,
        "NBEFORE,NAFTER,REV,RR,RT,HASH,CRL_ID FROM CERT WHERE IID=? AND SN=?");

    try {
      this.certHashAlgo = getCertHashAlgo(datasource);
    } catch (DataAccessException ex) {
      throw new OcspStoreException(
          "Could not retrieve the certhash's algorithm from the database", ex);
    }

    try {
      Set<X509Certificate> includeIssuers = null;
      Set<X509Certificate> excludeIssuers = null;

      if (caCerts != null) {
        if (CollectionUtil.isNotEmpty(caCerts.getIncludes())) {
          includeIssuers = parseCerts(caCerts.getIncludes());
        }

        if (CollectionUtil.isNotEmpty(caCerts.getExcludes())) {
          excludeIssuers = parseCerts(caCerts.getExcludes());
        }
      }

      this.issuerFilter = new IssuerFilter(includeIssuers, excludeIssuers);
    } catch (CertificateException ex) {
      throw new OcspStoreException(ex.getMessage(), ex);
    } // end try

    updateIssuerStore();

    if (this.scheduledThreadPoolExecutor != null) {
      this.scheduledThreadPoolExecutor.shutdownNow();
    }

    if (updateInterval != null) {
      List<Runnable> scheduledServices = getScheduledServices();
      int size = scheduledServices == null ? 0 : scheduledServices.size();
      if (size > 0) {
        this.scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(size);
        Random random = new Random();
        long intervalSeconds = updateInterval.approxMinutes() * 60;
        for (Runnable service : scheduledServices) {
          this.scheduledThreadPoolExecutor.scheduleAtFixedRate(service,
              intervalSeconds + random.nextInt(60), intervalSeconds,
              TimeUnit.SECONDS);
        }
      }
    }
  }

  @Override
  public void close() {
    if (scheduledThreadPoolExecutor != null) {
      scheduledThreadPoolExecutor.shutdown();
      scheduledThreadPoolExecutor = null;
    }

    if (datasource != null) {
      datasource.close();
    }
  }

  @Override
  public boolean knowsIssuer(RequestIssuer reqIssuer) {
    return issuerStore != null && null != issuerStore.getIssuerForFp(reqIssuer);
  }

  @Override
  public X509Certificate getIssuerCert(RequestIssuer reqIssuer) {
    if (issuerStore == null) {
      return null;
    }
    IssuerEntry issuer = issuerStore.getIssuerForFp(reqIssuer);
    return (issuer == null) ? null : issuer.getCert();
  }

  protected boolean isInitialized() {
    return initialized;
  }

  static Set<X509Certificate> parseCerts(Collection<String> certFiles)
      throws OcspStoreException {
    Set<X509Certificate> certs = new HashSet<>(certFiles.size());
    for (String certFile : certFiles) {
      try {
        certs.add(X509Util.parseCert(new File(certFile)));
      } catch (CertificateException | IOException ex) {
        throw new OcspStoreException("could not parse X.509 certificate from file "
            + certFile + ": " + ex.getMessage(), ex);
      }
    }
    return certs;
  }

  public static HashAlgo getCertHashAlgo(DataSourceWrapper datasource) throws DataAccessException {
    // analyze the database
    String certHashAlgoStr = datasource.getFirstValue(null, "DBSCHEMA", "VALUE2",
        "NAME='CERTHASH_ALGO'", String.class);

    if (certHashAlgoStr == null) {
      throw new DataAccessException(
          "Column with NAME='CERTHASH_ALGO' is not defined in table DBSCHEMA");
    }

    return HashAlgo.getNonNullInstance(certHashAlgoStr);
  }

}
