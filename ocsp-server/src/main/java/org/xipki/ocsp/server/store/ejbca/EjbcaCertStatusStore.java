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

package org.xipki.ocsp.server.store.ejbca;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
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
import org.xipki.ocsp.api.CertStatus;
import org.xipki.ocsp.api.CertStatusInfo;
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
import org.xipki.util.CollectionUtil;
import org.xipki.util.Hex;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;

import com.alibaba.fastjson.JSON;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class EjbcaCertStatusStore extends OcspStore {

  private class StoreUpdateService implements Runnable {

    @Override
    public void run() {
      updateIssuerStore();
    }

  } // class StoreUpdateService

  private static final Logger LOG = LoggerFactory.getLogger(EjbcaCertStatusStore.class);

  private final HashAlgo certHashAlgo = HashAlgo.SHA1;

  private final AtomicBoolean storeUpdateInProcess = new AtomicBoolean(false);

  private DataSourceWrapper datasource;

  private String sqlCs;

  private String sqlCsWithCertHash;

  private IssuerFilter issuerFilter;

  private EjbcaIssuerStore issuerStore;

  private boolean initialized;

  private boolean initializationFailed;

  private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

  protected List<Runnable> getScheduledServices() {
    return Collections.emptyList();
  }

  private synchronized void updateIssuerStore() {
    if (storeUpdateInProcess.get()) {
      return;
    }

    final String sql = "SELECT data FROM CAData";

    storeUpdateInProcess.set(true);
    try {
      PreparedStatement ps = preparedStatement(sql);
      ResultSet rs = null;

      try {
        Map<String, EjbcaIssuerEntry> newIssuers = new HashMap<>();

        rs = ps.executeQuery();
        while (rs.next()) {
          String caData = rs.getString("data");
          String b64Cert = extractTextFromCaData(caData, "certificatechain", "string");
          if (b64Cert == null) {
            // not an X.509CA
            continue;
          }

          X509Certificate cert = X509Util.parseCert(StringUtil.toUtf8Bytes(b64Cert.trim()));
          EjbcaIssuerEntry issuerEntry = new EjbcaIssuerEntry(cert);
          String sha1Fp = issuerEntry.getId();

          if (!issuerFilter.includeIssuerWithSha1Fp(sha1Fp)) {
            continue;
          }

          RequestIssuer reqIssuer =
              new RequestIssuer(HashAlgo.SHA1, issuerEntry.getEncodedHash(HashAlgo.SHA1));
          for (EjbcaIssuerEntry m : newIssuers.values()) {
            if (m.matchHash(reqIssuer)) {
              throw new Exception("found at least two issuers with the same subject and key");
            }
          }

          // extract the revocation time of CA
          String str = extractTextFromCaData(caData, "revokationreason", "int");
          if (str != null && !"-1".contentEquals(str)) {
            // CA is revoked
            str = extractTextFromCaData(caData, "revokationdate", "long");

            Date revTime;
            if (str != null && !"-1".contentEquals(str)) {
              revTime = new Date(Long.parseLong(str));
            } else {
              revTime = new Date();
            }

            issuerEntry.setRevocationInfo(revTime);
          }

          newIssuers.put(sha1Fp, issuerEntry);
        }

        // no change in the issuerStore
        Set<String> newIds = newIssuers.keySet();
        Set<String> ids = (issuerStore != null) ? issuerStore.getIds() : Collections.emptySet();

        boolean issuersUnchanged = (ids.size() == newIds.size())
            && ids.containsAll(newIds) && newIds.containsAll(ids);

        if (issuersUnchanged) {
          for (String id : newIds) {
            EjbcaIssuerEntry entry = issuerStore.getIssuerForId(id);
            EjbcaIssuerEntry newEntry = newIssuers.get(id);
            if (!newEntry.equals(entry)) {
              issuersUnchanged = false;
              break;
            }
          }
        }

        if (issuersUnchanged) {
          return;
        }

        initialized = false;
        this.issuerStore = new EjbcaIssuerStore(newIssuers.values());
        LOG.info("Updated issuers: {}", name);
        initializationFailed = false;
        initialized = true;
      } finally {
        releaseDbResources(ps, rs);
      }
    } catch (Throwable th) {
      LogUtil.error(LOG, th, "error while executing updateIssuerStore()");
      initializationFailed = true;
      initialized = true;
    } finally {
      storeUpdateInProcess.set(false);
    }
  } // method initIssuerStore

  @Override
  protected CertStatusInfo getCertStatus0(Date time, RequestIssuer reqIssuer,
      BigInteger serialNumber, boolean includeCertHash, boolean includeRit,
      boolean inheritCaRevocation) throws OcspStoreException {
    if (includeRit) {
      throw new OcspStoreException("EJBCA store does not support includeRit");
    }

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
      EjbcaIssuerEntry issuer = issuerStore.getIssuerForFp(reqIssuer);
      if (issuer == null) {
        return null;
      }

      if (includeCertHash) {
        sql = sqlCsWithCertHash;
      } else {
        sql = sqlCs;
      }

      Date thisUpdate = new Date();
      Date nextUpdate = null;

      ResultSet rs = null;
      CertStatusInfo certStatusInfo = null;

      boolean unknown = true;
      boolean ignore = false;
      String hexCertHash = null;
      boolean revoked = false;
      int reason = 0;
      long revTime = 0;

      PreparedStatement ps = datasource.prepareStatement(sql);

      try {
        ps.setString(1, issuer.getId());
        // decimal serial number
        ps.setString(2, serialNumber.toString());
        rs = ps.executeQuery();

        if (rs.next()) {
          unknown = false;

          long timeInMs = time.getTime();
          if (!ignore && ignoreNotYetValidCert) {
            long notBefore = rs.getLong("notBefore");
            if (timeInMs < notBefore) {
              ignore = true;
            }
          }

          if (!ignore && ignoreExpiredCert) {
            long notAfterInSec = rs.getLong("expireDate");
            if (timeInMs > notAfterInSec) {
              ignore = true;
            }
          }

          if (!ignore) {
            if (includeCertHash) {
              hexCertHash = rs.getString("fingerprint");
            }

            int status = rs.getInt("status");
            revoked = status == 40;
            if (revoked) {
              reason = rs.getInt("revocationReason");
              revTime = rs.getLong("revocationDate") / 1000;
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
          certStatusInfo = CertStatusInfo.getUnknownCertStatusInfo(thisUpdate, nextUpdate);
        }
      } else {
        if (ignore) {
          certStatusInfo = CertStatusInfo.getIgnoreCertStatusInfo(thisUpdate, nextUpdate);
        } else {
          byte[] certHash = (hexCertHash == null) ? null : Hex.decode(hexCertHash);
          if (revoked) {
            CertRevocationInfo revInfo = new CertRevocationInfo(reason,
                new Date(revTime * 1000), null);
            certStatusInfo = CertStatusInfo.getRevokedCertStatusInfo(revInfo,
                certHashAlgo, certHash, thisUpdate, nextUpdate, null);
          } else {
            certStatusInfo = CertStatusInfo.getGoodCertStatusInfo(certHashAlgo,
                certHash, thisUpdate, nextUpdate, null);
          }
        }
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
      if (certStatus == CertStatus.GOOD || certStatus == CertStatus.UNKNOWN) {
        replaced = true;
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

    if (isInitializationFailed()) {
      return false;
    }

    final String sql = "SELECT cAId FROM CAData";

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
    if (includeCrlId) {
      throw new OcspStoreException("includeCrlId must not be true");
    }

    OcspServerConf.CaCerts caCerts = null;
    if (sourceConf != null) {
      Object objValue = sourceConf.get("caCerts");
      if (objValue != null) {
        caCerts = JSON.parseObject(JSON.toJSONBytes(objValue), OcspServerConf.CaCerts.class);
      }
    }

    this.datasource = Args.notNull(datasource, "datasource");

    String coreSql = "notBefore,expireDate,status,revocationReason,revocationDate"
        + " FROM CertificateData WHERE cAFingerprint=? AND serialNumber=?";
    sqlCs = datasource.buildSelectFirstSql(1, coreSql);

    sqlCsWithCertHash = datasource.buildSelectFirstSql(1, "fingerprint," + coreSql);

    try {
      Set<X509Certificate> includeIssuers = null;
      Set<X509Certificate> excludeIssuers = null;

      if (caCerts != null) {
        if (CollectionUtil.isNonEmpty(caCerts.getIncludes())) {
          includeIssuers = parseCerts(caCerts.getIncludes());
        }

        if (CollectionUtil.isNonEmpty(caCerts.getExcludes())) {
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
    return null != issuerStore.getIssuerForFp(reqIssuer);
  }

  @Override
  public X509Certificate getIssuerCert(RequestIssuer reqIssuer) {
    EjbcaIssuerEntry issuer = issuerStore.getIssuerForFp(reqIssuer);
    return (issuer == null) ? null : issuer.getCert();
  }

  protected boolean isInitialized() {
    return initialized;
  }

  protected boolean isInitializationFailed() {
    return initializationFailed;
  }

  private static Set<X509Certificate> parseCerts(Collection<String> certFiles)
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

  private static String extractTextFromCaData(String caData, String key, String valueType) {
    String keyTag = "<string>" + key + "</string>";
    int index = caData.indexOf(keyTag);
    if (index == -1) {
      return null;
    }

    String valueStartTag = "<" + valueType + ">";
    String valueEndTag = "</" + valueType + ">";

    index = caData.indexOf(valueStartTag, index + keyTag.length());
    if (index == -1) {
      return null;
    }
    int startIndex = index + valueStartTag.length();

    index = caData.indexOf(valueEndTag, startIndex);
    if (index == -1) {
      return null;
    }

    return caData.substring(startIndex, index);
  }

}
