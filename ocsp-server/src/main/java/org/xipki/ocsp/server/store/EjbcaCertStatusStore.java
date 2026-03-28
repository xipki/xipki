// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server.store;

import org.bouncycastle.asn1.x509.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ocsp.api.CertStatusInfo;
import org.xipki.ocsp.api.CertStatusInfo.CertStatus;
import org.xipki.ocsp.api.CertStatusInfo.UnknownCertBehaviour;
import org.xipki.ocsp.api.OcspStore;
import org.xipki.ocsp.api.OcspStoreException;
import org.xipki.ocsp.api.RequestIssuer;
import org.xipki.ocsp.server.IssuerFilter;
import org.xipki.ocsp.server.OcspServerConf;
import org.xipki.security.HashAlgo;
import org.xipki.security.pkix.CertRevocationInfo;
import org.xipki.security.pkix.CrlReason;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.util.Asn1Util;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Hex;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.datasource.DataAccessException;
import org.xipki.util.datasource.DataSourceWrapper;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.CompareUtil;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.extra.misc.RandomUtil;
import org.xipki.util.misc.StringUtil;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Ejbca Cert Status Store store definition.
 *
 * @author Lijun Liao (xipki)
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

  private final StoreUpdateService storeUpdateService = new StoreUpdateService();

  private final AtomicBoolean storeUpdateInProcess = new AtomicBoolean(false);

  private final Object lock = new Object();

  private DataSourceWrapper datasource;

  private String sqlCs;

  private String sqlCsWithCertHash;

  private IssuerFilter issuerFilter;

  private EjbcaIssuerStore issuerStore;

  private boolean initialized;

  private boolean initializationFailed;

  private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

  protected List<Runnable> getScheduledServices() {
    return Collections.singletonList(storeUpdateService);
  }

  private void updateIssuerStore() {
    if (storeUpdateInProcess.get()) {
      return;
    }

    final String sql = "SELECT data FROM CAData";

    synchronized (lock) {
      storeUpdateInProcess.set(true);
      try {
        PreparedStatement ps = preparedStatement(sql);
        ResultSet rs = null;

        try {
          Map<String, EjbcaIssuerEntry> newIssuers = new HashMap<>();

          rs = ps.executeQuery();
          while (rs.next()) {
            String caData = rs.getString("data");

            String str = extractTextFromCaData(caData, "catype", "int");
            if (!"1".equals(str)) {
              // not X.509CA
              continue;
            }

            String b64Cert = extractTextFromCaData(caData, "certificatechain", "string");
            if (b64Cert == null) {
              // not an X.509CA
              continue;
            }

            X509Cert cert = X509Util.parseCert(StringUtil.toUtf8Bytes(b64Cert.trim()));

            EjbcaIssuerEntry issuerEntry = new EjbcaIssuerEntry(cert);
            String sha1Fp = issuerEntry.id();

            if (!issuerFilter.includeIssuerWithSha1Fp(sha1Fp)) {
              continue;
            }

            RequestIssuer reqIssuer = new RequestIssuer(HashAlgo.SHA1,
                issuerEntry.getEncodedHash(HashAlgo.SHA1));

            for (EjbcaIssuerEntry m : newIssuers.values()) {
              if (m.matchHash(reqIssuer)) {
                throw new Exception("found at least two issuers with the same subject and key");
              }
            }

            // extract the revocation time of CA
            str = extractTextFromCaData(caData, "revokationreason", "int");
            if (str != null && !"-1".contentEquals(str)) {
              // CA is revoked
              str = extractTextFromCaData(caData, "revokationdate", "long");

              Instant revTime = (str == null || "-1".contentEquals(str))
                  ? Instant.now() : Instant.ofEpochMilli(Long.parseLong(str));
              issuerEntry.setRevocationInfo(revTime);
            }

            newIssuers.put(sha1Fp, issuerEntry);
          }

          // no change in the issuerStore
          Set<String> newIds = newIssuers.keySet();
          Set<String> ids = (issuerStore != null) ? issuerStore.ids() : Collections.emptySet();

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

          if (LOG.isInfoEnabled()) {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, EjbcaIssuerEntry> m : newIssuers.entrySet()) {
              sb.append(overviewString(m.getValue().cert())).append("\n");
            }
            if (sb.length() > 1) {
              sb.deleteCharAt(sb.length() - 1);
            }
            LOG.info("Updated store {} with issuers {}", name, sb);
          }

          LOG.info("Updated issuers of store {}", name);
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
    } // end lock
  } // method updateIssuerStore

  @Override
  protected CertStatusInfo getCertStatus0(
      Instant time, RequestIssuer reqIssuer, BigInteger serialNumber, boolean includeCertHash,
      boolean includeRit, boolean inheritCaRevocation) throws OcspStoreException {
    if (includeRit) {
      throw new OcspStoreException("EJBCA store does not support includeRit");
    }

    if (serialNumber.signum() != 1) { // non-positive serial number
      return CertStatusInfo.getUnknownCertStatusInfo(Instant.now(), null);
    }

    if (!initialized) {
      throw new OcspStoreException("initialization of CertStore is still in process");
    }

    if (initializationFailed) {
      throw new OcspStoreException("initialization of CertStore failed");
    }

    try {
      EjbcaIssuerEntry issuer = issuerStore.getIssuerForFp(reqIssuer);
      if (issuer == null) {
        return null;
      }

      String sql = includeCertHash ? sqlCsWithCertHash : sqlCs;

      Instant thisUpdate = Instant.now();

      ResultSet rs = null;

      boolean unknown = true;
      boolean ignore = false;
      String hexCertHash = null;
      boolean revoked = false;
      int reason = 0;
      long revTime = 0;

      PreparedStatement ps = datasource.prepareStatement(sql);

      try {
        ps.setString(1, issuer.id());
        // decimal serial number
        ps.setString(2, serialNumber.toString());
        rs = ps.executeQuery();

        if (rs.next()) {
          unknown = false;

          long timeInMs = time.toEpochMilli();
          if (ignoreNotYetValidCert) {
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

      CertStatusInfo certStatusInfo;
      if (unknown) {
        certStatusInfo = CertStatusInfo.getUnknownCertStatusInfo(thisUpdate, null);
      } else if (ignore) {
        certStatusInfo = CertStatusInfo.getIgnoreCertStatusInfo(thisUpdate, null);
      } else {
        byte[] certHash = (hexCertHash == null) ? null : Hex.decode(hexCertHash);

        if (revoked) {
          CertRevocationInfo revInfo = new CertRevocationInfo(reason,
              Instant.ofEpochSecond(revTime), null);

          certStatusInfo = CertStatusInfo.getRevokedCertStatusInfo(revInfo,
              certHashAlgo, certHash, thisUpdate, null, null);
        } else {
          certStatusInfo = CertStatusInfo.getGoodCertStatusInfo(certHashAlgo,
              certHash, thisUpdate, null, null);
        }
      }

      if (includeArchiveCutoff) {
        if (retentionInterval != 0) {
          Instant date;
          // expired certificate remains in status store forever
          if (retentionInterval < 0) {
            date = issuer.notBefore();
          } else {
            Instant t1 = Instant.now().minus(retentionInterval, ChronoUnit.DAYS);
            date = issuer.notBefore().isAfter(t1) ? issuer.notBefore() : t1;
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
      if (certStatus == CertStatus.GOOD) {
        replaced = true;
      } else if (certStatus == CertStatus.UNKNOWN || certStatus == CertStatus.IGNORE) {
        if (unknownCertBehaviour == UnknownCertBehaviour.good) {
          replaced = true;
        }
      } else if (certStatus == CertStatus.REVOKED) {
        if (certStatusInfo.revocationInfo().revocationTime().isAfter(caRevInfo.revocationTime())) {
          replaced = true;
        }
      }

      if (replaced) {
        CertRevocationInfo newRevInfo = (caRevInfo.reason() == CrlReason.CA_COMPROMISE)
            ? caRevInfo
            : new CertRevocationInfo(CrlReason.CA_COMPROMISE,
                caRevInfo.revocationTime(), caRevInfo.invalidityTime());
        certStatusInfo = CertStatusInfo.getRevokedCertStatusInfo(newRevInfo,
            certStatusInfo.certHashAlgo(), certStatusInfo.certHash(),
            certStatusInfo.thisUpdate(), certStatusInfo.nextUpdate(), certStatusInfo.certprofile());
      }
      return certStatusInfo;
    } catch (DataAccessException ex) {
      throw new OcspStoreException(ex.getMessage(), ex);
    }

  } // method getCertStatus0

  /**
   * Borrow PreparedStatement.
   * @return the next idle preparedStatement, {@code null} will be returned if
   *         no PreparedStatement can be created within 5 seconds.
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
  } // method isHealthy

  private void releaseDbResources(PreparedStatement ps, ResultSet rs) {
    datasource.releaseResources(ps, rs);
  }

  /**
   * Initialize the store.
   *
   * @param sourceConf
   * the store source configuration. It contains following key-value pairs:
   * <ul>
   * <li>caCerts: optional
   *   <p>
   *   CA certificate files to be included / excluded.</li>
   *  </ul>
   * @param datasource DataSource.
   */
  @Override
  public void init(JsonMap sourceConf, DataSourceWrapper datasource) throws OcspStoreException {
    if (includeCrlId) {
      throw new OcspStoreException("includeCrlId must not be true");
    }

    OcspServerConf.CaCerts caCerts = null;
    if (sourceConf != null) {
      caCerts = OcspServerConf.CaCerts.parseSourceConf(sourceConf);
    }

    this.datasource = Args.notNull(datasource, "datasource");

    String coreSql = "notBefore,expireDate,status,revocationReason," +
        "revocationDate FROM CertificateData WHERE cAFingerprint=? AND serialNumber=?";
    sqlCs = datasource.buildSelectFirstSql(1, coreSql);

    sqlCsWithCertHash = datasource.buildSelectFirstSql(1, "fingerprint," + coreSql);

    Set<X509Cert> includeIssuers = null;
    Set<X509Cert> excludeIssuers = null;

    if (caCerts != null) {
      if (CollectionUtil.isNotEmpty(caCerts.includes())) {
        includeIssuers = parseCerts(caCerts.includes());
      }

      if (CollectionUtil.isNotEmpty(caCerts.excludes())) {
        excludeIssuers = parseCerts(caCerts.excludes());
      }
    }

    this.issuerFilter = new IssuerFilter(includeIssuers, excludeIssuers);

    updateIssuerStore();

    if (this.scheduledThreadPoolExecutor != null) {
      this.scheduledThreadPoolExecutor.shutdownNow();
    }

    if (updateInterval != null) {
      List<Runnable> scheduledServices = getScheduledServices();
      int size = scheduledServices.size();
      if (size > 0) {
        this.scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(size);
        long intervalSeconds = updateInterval.approxMinutes() * 60;
        for (Runnable service : scheduledServices) {
          this.scheduledThreadPoolExecutor.scheduleAtFixedRate(service,
              intervalSeconds + RandomUtil.nextInt(60), intervalSeconds, TimeUnit.SECONDS);
        }
      }
    }
  } // method init

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
  public X509Cert getIssuerCert(RequestIssuer reqIssuer) {
    EjbcaIssuerEntry issuer = issuerStore.getIssuerForFp(reqIssuer);
    return (issuer == null) ? null : issuer.cert();
  }

  protected boolean isInitialized() {
    return initialized;
  }

  protected boolean isInitializationFailed() {
    return initializationFailed;
  }

  private static Set<X509Cert> parseCerts(Collection<String> certFiles) throws OcspStoreException {
    Set<X509Cert> certs = new HashSet<>(certFiles.size());
    for (String certFile : certFiles) {
      try {
        certs.add(X509Util.parseCert(new File(certFile)));
      } catch (CertificateException | IOException ex) {
        throw new OcspStoreException("could not parse X.509 certificate " +
            "from file " + certFile + ": " + ex.getMessage(), ex);
      }
    }
    return certs;
  } // method parseCerts

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
    return (index == -1) ? null : caData.substring(startIndex, index);
  } // method extractTextFromCaData

  /**
   * IssuerEntry for the EJBCA database.
   *
   * @author Lijun Liao (xipki)
   */

  private static class EjbcaIssuerEntry {

    private final String id;

    private final Map<HashAlgo, byte[]> issuerHashMap;

    private final Instant notBefore;

    private final X509Cert cert;

    private CertRevocationInfo revocationInfo;

    public EjbcaIssuerEntry(X509Cert cert) throws CertificateEncodingException {
      this.cert = Args.notNull(cert, "cert");
      this.notBefore = cert.notBefore();
      byte[] encodedCert = cert.getEncoded();
      this.id = HashAlgo.SHA1.hexHash(encodedCert);
      this.issuerHashMap = getIssuerHashAndKeys(encodedCert);
    }

    private static Map<HashAlgo, byte[]> getIssuerHashAndKeys(byte[] encodedCert)
        throws CertificateEncodingException {
      byte[] encodedName;
      byte[] encodedKey;
      try {
        Certificate bcCert = Certificate.getInstance(encodedCert);
        encodedName = bcCert.getSubject().getEncoded("DER");
        encodedKey  = Asn1Util.getPublicKeyData(bcCert.getSubjectPublicKeyInfo());
      } catch (IllegalArgumentException | IOException ex) {
        throw new CertificateEncodingException(ex.getMessage(), ex);
      }

      Map<HashAlgo, byte[]> hashes = new HashMap<>();
      for (HashAlgo ha : HashAlgo.values()) {
        int hlen = ha.length();
        byte[] nameAndKeyHash = new byte[(2 + hlen) << 1];
        int offset = 0;
        nameAndKeyHash[offset++] = 0x04;
        nameAndKeyHash[offset++] = (byte) hlen;
        System.arraycopy(ha.hash(encodedName), 0, nameAndKeyHash, offset, hlen);
        offset += hlen;

        nameAndKeyHash[offset++] = 0x04;
        nameAndKeyHash[offset++] = (byte) hlen;
        System.arraycopy(ha.hash(encodedKey), 0, nameAndKeyHash, offset, hlen);

        hashes.put(ha, nameAndKeyHash);
      }
      return hashes;
    } // method getIssuerHashAndKeys

    public String id() {
      return id;
    }

    public byte[] getEncodedHash(HashAlgo hashAlgo) {
      byte[] data = issuerHashMap.get(hashAlgo);
      return Arrays.copyOf(data, data.length);
    }

    public boolean matchHash(RequestIssuer reqIssuer) {
      byte[] issuerHash = issuerHashMap.get(reqIssuer.hashAlgorithm());
      return issuerHash != null &&
          CompareUtil.areEqual(issuerHash, 0, reqIssuer.data(),
              reqIssuer.nameHashFrom(), issuerHash.length);
    }

    public void setRevocationInfo(Instant revocationTime) {
      this.revocationInfo = new CertRevocationInfo(CrlReason.CA_COMPROMISE,
          Args.notNull(revocationTime, "revocationTime"), null);
    }

    public CertRevocationInfo revocationInfo() {
      return revocationInfo;
    }

    public Instant notBefore() {
      return notBefore;
    }

    public X509Cert cert() {
      return cert;
    }

    @Override
    public int hashCode() {
      return id.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) {
        return true;
      }

      if (!(obj instanceof EjbcaIssuerEntry)) {
        return false;
      }

      EjbcaIssuerEntry other = (EjbcaIssuerEntry) obj;
      return id.equals(other.id) && CompareUtil.equals(revocationInfo, other.revocationInfo);
      // The comparison of id implies the comparison of issuerHashMap, notBefore and cert.
    } // method equals

  }

  /**
   * IssuerStore for the EJBCA database.
   *
   * @author Lijun Liao (xipki)
   */

  private static class EjbcaIssuerStore {

    private final List<EjbcaIssuerEntry> entries;

    private final Set<String> ids;

    public EjbcaIssuerStore(Collection<EjbcaIssuerEntry> entries) {
      this.entries = new ArrayList<>(entries.size());
      Set<String> idSet = new HashSet<>(entries.size());

      for (EjbcaIssuerEntry entry : entries) {
        for (EjbcaIssuerEntry existingEntry : this.entries) {
          if (existingEntry.id().contentEquals(entry.id())) {
            throw new IllegalArgumentException(
                "issuer with the same id (fingerprint) " + entry.id() + " already available");
          }
        }
        this.entries.add(entry);
        idSet.add(entry.id());
      }

      this.ids = Collections.unmodifiableSet(idSet);
    }

    public int size() {
      return ids.size();
    }

    public Set<String> ids() {
      return ids;
    }

    public EjbcaIssuerEntry getIssuerForId(String id) {
      for (EjbcaIssuerEntry entry : entries) {
        if (entry.id().contentEquals(id)) {
          return entry;
        }
      }

      return null;
    }

    public EjbcaIssuerEntry getIssuerForFp(RequestIssuer reqIssuer) {
      for (EjbcaIssuerEntry entry : entries) {
        if (entry.matchHash(reqIssuer)) {
          return entry;
        }
      }

      return null;
    }

  }
}
