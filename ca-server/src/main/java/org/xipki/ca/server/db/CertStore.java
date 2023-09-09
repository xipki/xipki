// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.db;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.TBSCertList.CRLEntry;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.util.Pack;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.CertificateInfo;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CertListInfo;
import org.xipki.ca.api.mgmt.CertListOrderBy;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.server.CaIdNameMap;
import org.xipki.ca.server.CaUtil;
import org.xipki.ca.server.CertRevInfoWithSerial;
import org.xipki.ca.server.UniqueIdGenerator;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.security.*;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;
import org.xipki.util.*;
import org.xipki.util.exception.OperationException;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.xipki.util.Args.*;
import static org.xipki.util.exception.ErrorCode.*;

/**
 * CA cert store.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

// TODO: add entry to table CA with the same ID and name as in the database 'ca'.
public class CertStore extends CertStoreBase {

  public enum CertStatus {

    UNKNOWN,
    REVOKED,
    GOOD

  } // class CertStatus

  public static class SerialWithId {

    private final long id;

    private final BigInteger serial;

    public SerialWithId(long id, BigInteger serial) {
      this.id = id;
      this.serial = serial;
    }

    public BigInteger getSerial() {
      return serial;
    }

    public long getId() {
      return id;
    }

  }

  private static final Logger LOG = LoggerFactory.getLogger(CertStore.class);

  private final String sqlCertForId;

  private final String sqlCertWithRevInfo;

  private final String sqlCertWithRevInfoBySubjectAndSan;

  private final String sqlCertIdByCaSn;

  private final String sqlCertInfo;

  private final String sqlCertStatusForSubjectFp;

  private final String sqlCrl;

  private final String sqlCrlWithNo;

  private final String sqlSelectUnrevokedSn100;

  private final String sqlSelectUnrevokedSn;

  private final LruCache<Integer, String> cacheSqlExpiredSerials = new LruCache<>(5);

  private final LruCache<Integer, String> cacheSqlSuspendedSerials = new LruCache<>(5);

  private final LruCache<Integer, String> cacheSqlRevokedCerts = new LruCache<>(5);

  private final LruCache<Integer, String> cacheSqlSerials = new LruCache<>(5);

  private final LruCache<Integer, String> cacheSqlSerialsRevoked = new LruCache<>(5);

  private final UniqueIdGenerator idGenerator;

  private final AtomicInteger cachedCrlId = new AtomicInteger(0);

  private final long earliestNotBefore;

  public CertStore(DataSourceWrapper datasource, DataSourceWrapper caConfDatasource,
                   UniqueIdGenerator idGenerator, PasswordResolver passwordResolver)
      throws DataAccessException, CaMgmtException {
    super(datasource, caConfDatasource, passwordResolver);

    this.idGenerator = notNull(idGenerator, "idGenerator");

    this.sqlCertForId = buildSelectFirstSql("PID,RID,REV,RR,RT,RIT,CERT FROM CERT WHERE ID=?");
    this.sqlCertWithRevInfo = buildSelectFirstSql("ID,REV,RR,RT,RIT,PID,CERT FROM CERT WHERE CA_ID=? AND SN=?");
    this.sqlCertWithRevInfoBySubjectAndSan = buildSelectFirstSql("NBEFORE DESC",
        "ID,NBEFORE,REV,RR,RT,RIT,PID,CERT FROM CERT WHERE CA_ID=? AND FP_S=? AND FP_SAN=?");

    this.sqlCertIdByCaSn = buildSelectFirstSql("ID FROM CERT WHERE CA_ID=? AND SN=?");
    this.sqlCertInfo = buildSelectFirstSql("PID,RID,REV,RR,RT,RIT,CERT FROM CERT WHERE CA_ID=? AND SN=?");
    this.sqlCertStatusForSubjectFp = buildSelectFirstSql("REV FROM CERT WHERE FP_S=? AND CA_ID=?");
    this.sqlCrl = buildSelectFirstSql("THISUPDATE DESC", "THISUPDATE,CRL FROM CRL WHERE CA_ID=?");
    this.sqlCrlWithNo = buildSelectFirstSql("THISUPDATE DESC",
        "THISUPDATE,CRL FROM CRL WHERE CA_ID=? AND CRL_NO=?");

    this.sqlSelectUnrevokedSn = buildSelectFirstSql("LUPDATE FROM CERT WHERE REV=0 AND SN=?");
    final String prefix = "SN,LUPDATE FROM CERT WHERE REV=0 AND SN";
    this.sqlSelectUnrevokedSn100 = buildArraySql(datasource, prefix, 100);
    this.earliestNotBefore = datasource.getMin(null, "CERT", "NBEFORE");
  } // constructor

  public void removeCa(String name) throws CaMgmtException {
    removeEntry(name, "CA");
  }

  public void removeCertProfile(String name) throws CaMgmtException {
    removeEntry(name, "PROFILE");
  }

  public void removeRequestor(String name) throws CaMgmtException {
    removeEntry(name, "REQUESTOR");
  }

  private void removeEntry(String name, String table) throws CaMgmtException {
    if (dbSchemaVersion < 8) {
      return;
    }

    notBlank(name, "name");
    final String sql = "DELETE FROM " + table + " WHERE NAME=?";

    try {
      execUpdatePrepStmt0(sql, col2Str(name));
    } catch (OperationException ex) {
      throw new CaMgmtException(ex);
    }
  }

  public void addCertProfile(NameId ident) throws CaMgmtException {
    addNameId(ident, "PROFILE");
  }

  public void addRequestor(NameId ident) throws CaMgmtException {
    addNameId(ident, "REQUESTOR");
  }

  private void addNameId(NameId ident, String table) throws CaMgmtException {
    if (dbSchemaVersion < 8) {
      return;
    }

    notNull(ident, "ident");

    if (existsIdent(ident, table)) {
      return;
    }

    int num;
    try {
      final String sql = SqlUtil.buildInsertSql(table, "ID,NAME");
      num = execUpdatePrepStmt0(sql, col2Int(ident.getId()), col2Str(ident.getName()));
    } catch (OperationException ex) {
      throw new CaMgmtException(ex);
    }

    if (num == 0) {
      throw new CaMgmtException("could not add requestor " + ident);
    }

    if (LOG.isInfoEnabled()) {
      LOG.info("added requestor '{}'", ident);
    }
  } // method addRequestor

  public void addCa(NameId ident, X509Cert caCert) throws CaMgmtException {
    if (dbSchemaVersion < 8) {
      return;
    }

    notNull(ident, "ident");
    notNull(caCert, "caCert");

    if (existsIdent(ident, "CA")) {
      byte[] existingCert;
      try {
        existingCert = Base64.decode(
            datasource.getFirstStringValue(null, "CA", "CERT", "ID=" + ident.getId()));
      } catch (DataAccessException e) {
        throw new CaMgmtException(e);
      }

      if (Arrays.equals(existingCert, caCert.getEncoded())) {
        return;
      } else {
        throw new CaMgmtException("an entry in table CA with ID=" + ident.getId() +
            " exists, but the certificate differs");
      }
    }

    int num;
    try {
      String subjectText = X509Util.cutText(caCert.getSubjectText(), maxX500nameLen);
      String sql = SqlUtil.buildInsertSql("CA", "ID,NAME,SUBJECT,CERT");
      num = execUpdatePrepStmt0(sql, col2Int(ident.getId()), col2Str(ident.getName()),
                col2Str(subjectText), col2Str(Base64.encodeToString(caCert.getEncoded())));
    } catch (OperationException ex) {
      throw new CaMgmtException(ex);
    }

    if (num == 0) {
      throw new CaMgmtException("could not add CA " + ident);
    }
  }

  private boolean existsIdent(NameId ident, String table) throws CaMgmtException {
    String existingName;
    try {
      existingName = datasource.getFirstStringValue(null, table, "NAME", "ID=" + ident.getId());
    } catch (DataAccessException e) {
      throw new CaMgmtException(e);
    }

    if (existingName == null) {
      return false;
    }

    if (ident.getName().equals(existingName)) {
      // already existing, do nothing
      return true;
    }

    // an entry with given id exists, but the name differs.
    throw new CaMgmtException("an entry in table " + table + " with ID=" + ident.getId() +
        " exists, but the name differs (expected " + ident.getName() + ", is " + existingName);
  }

  public void revokeCa(String caName, CertRevocationInfo revocationInfo) throws CaMgmtException {
    if (dbSchemaVersion < 8) {
      return;
    }

    try {
      execUpdatePrepStmt0("UPDATE CA SET REV_INFO=? WHERE NAME=?",
          col2Str(revocationInfo.getEncoded()), col2Str(caName));
    } catch (OperationException ex) {
      throw new CaMgmtException(ex);
    }
  }

  public void unrevokeCa(String caName) throws CaMgmtException {
    if (dbSchemaVersion < 8) {
      return;
    }

    try {
      execUpdatePrepStmt0("UPDATE CA SET REV_INFO=? WHERE NAME=?", col2Str(null), col2Str(caName));
    } catch (OperationException ex) {
      throw new CaMgmtException(ex);
    }
  }

  public boolean addCert(CertificateInfo certInfo, boolean saveKeypair) {
    if (saveKeypair && certInfo.getPrivateKey() != null) {
      if (keypairEncKey == null) {
        LOG.error("no keypair encryption key is configured");
        // no key encryption is configured
        return false;
      }
    }

    notNull(certInfo, "certInfo");

    byte[] encodedCert = null;

    try {
      String privateKeyInfo = null;
      CertWithDbId cert = certInfo.getCert();
      String tid = certInfo.getTransactionId();
      X500Name reqSubject = certInfo.getRequestedSubject();

      final long certId = idGenerator.nextId();
      if (saveKeypair && certInfo.getPrivateKey() != null) {
        // we use certId as the nonce
        byte[] nonce = new byte[12];
        Pack.longToBigEndian(certId, nonce, 4);
        byte[] encodedPrivateKey = certInfo.getPrivateKey().getEncoded();
        Cipher cipher = Cipher.getInstance(keypairEncAlg, keypairEncProvider);
        GCMParameterSpec spec = new GCMParameterSpec(96, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keypairEncKey, spec);
        byte[] encrypted = cipher.doFinal(encodedPrivateKey);
        privateKeyInfo = keypairEncAlgId + ":" + keypairEncKeyId + ":"
                + Base64.encodeToString(nonce) + ":" + Base64.encodeToString(encrypted);
      }

      String subjectText = X509Util.cutText(cert.getCert().getSubjectText(), maxX500nameLen);
      long fpSubject = X509Util.fpCanonicalizedName(cert.getCert().getSubject());

      byte[] san = cert.getCert().getSubjectAltNames();
      Long fpSan = san == null ? null : FpIdCalculator.hash(san);

      String reqSubjectText = null;
      Long fpReqSubject = null;
      if (reqSubject != null) {
        fpReqSubject = X509Util.fpCanonicalizedName(reqSubject);
        if (fpSubject == fpReqSubject) {
          fpReqSubject = null;
        } else {
          reqSubjectText = X509Util.cutX500Name(CaUtil.sortX509Name(reqSubject), maxX500nameLen);
        }
      }

      encodedCert = cert.getCert().getEncoded();
      String b64FpCert = HashAlgo.SHA1.base64Hash(encodedCert);

      X509Cert cert0 = cert.getCert();
      boolean isEeCert = cert0.getBasicConstraints() == -1;

      List<SqlColumn2> columns = new ArrayList<>(20);

      columns.add(col2Long(certId));
      // currentTimeSeconds
      columns.add(col2Long(Instant.now().getEpochSecond()));
      columns.add(col2Str(cert0.getSerialNumber().toString(16)));
      columns.add(col2Str(subjectText));
      columns.add(col2Long(fpSubject));
      columns.add(col2Long(fpReqSubject));
      columns.add(col2Long(fpSan));
      // notBeforeSeconds
      columns.add(col2Long(cert0.getNotBefore().getEpochSecond()));
      // notAfterSeconds
      columns.add(col2Long(cert0.getNotAfter().getEpochSecond()));
      columns.add(col2Bool(false));

      columns.add(col2Int(certInfo.getProfile().getId()));
      columns.add(col2Int(certInfo.getIssuer().getId()));
      columns.add(col2Int(certInfo.getRequestor().getId()));

      columns.add(col2Int(isEeCert ? 1 : 0));
      columns.add(col2Str(tid));
      columns.add(col2Str(b64FpCert));
      columns.add(col2Str(reqSubjectText));
      // in this version we set CRL_SCOPE to fixed value 0
      columns.add(col2Int(0));
      columns.add(col2Str(Base64.encodeToString(encodedCert)));
      columns.add(col2Str(privateKeyInfo));

      execUpdatePrepStmt0(SQL_ADD_CERT, columns.toArray(new SqlColumn2[0]));

      cert.setCertId(certId);
    } catch (Exception ex) {
      LOG.error("could not save certificate {}: {}. Message: {}",
          certInfo.getCert().getCert().getSubject(),
          encodedCert == null ? "null" : Base64.encodeToString(encodedCert, true), ex.getMessage());
      LOG.debug("error", ex);
      return false;
    }

    return true;
  } // method addCert

  public long getMaxFullCrlNumber(NameId ca) throws OperationException {
    return getMaxCrlNumber(ca, SQL_MAX_FULL_CRLNO);
  }

  public long getMaxCrlNumber(NameId ca) throws OperationException {
    return getMaxCrlNumber(ca, SQL_MAX_CRLNO);
  }

  private long getMaxCrlNumber(NameId ca, String sql) throws OperationException {
    notNull(ca, "ca");

    long maxCrlNumber = execQueryLongPrepStmt(sql, col2Int(ca.getId()));
    return (maxCrlNumber < 0) ? 0 : maxCrlNumber;
  } // method getMaxCrlNumber

  public long getThisUpdateOfCurrentCrl(NameId ca, boolean deltaCrl) throws OperationException {
    notNull(ca, "ca");

    return execQueryLongPrepStmt(SQL_MAX_THISUPDAATE_CRL, col2Int(ca.getId()), col2Int(deltaCrl ? 1 : 0));
  } // method getThisUpdateOfCurrentCrl

  public void addCrl(NameId ca, X509CRLHolder crl) throws OperationException, CRLException {
    notNulls(ca, "ca", crl, "crl");

    Extensions extns = crl.getExtensions();
    byte[] extnValue = X509Util.getCoreExtValue(extns, Extension.cRLNumber);
    Long crlNumber = (extnValue == null) ? null : ASN1Integer.getInstance(extnValue).getPositiveValue().longValue();

    extnValue = X509Util.getCoreExtValue(extns, Extension.deltaCRLIndicator);
    Long baseCrlNumber = null;
    if (extnValue != null) {
      baseCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue().longValue();
    }

    int currentMaxCrlId = (int) getMax("CRL", "ID");
    int crlId = Math.max(cachedCrlId.get(), currentMaxCrlId) + 1;
    cachedCrlId.set(crlId);

    byte[] encodedCrl;
    try {
      encodedCrl = crl.getEncoded();
    } catch (IOException ex) {
      throw new CRLException(ex.getMessage(), ex);
    }

    boolean withSha1Column = dbSchemaVersion >= 7;
    String b64Sha1 = withSha1Column ? HashAlgo.SHA1.base64Hash(encodedCrl) : null;
    String b64Crl = Base64.encodeToString(encodedCrl);

    List<SqlColumn2> columns = new ArrayList<>(10);
    columns.add(col2Int(crlId));
    columns.add(col2Int(ca.getId()));
    columns.add(col2Long(crlNumber));
    columns.add(col2Long(DateUtil.toEpochSecond(crl.getThisUpdate())));
    columns.add(col2Long(getDateSeconds(crl.getNextUpdate())));
    columns.add(col2Bool((baseCrlNumber != null)));
    columns.add(col2Long(baseCrlNumber));
    // in this version we set CRL_SCOPE to fixed value 0
    columns.add(col2Int(0));
    if (withSha1Column) {
      columns.add(col2Str(b64Sha1));
    }
    columns.add(col2Str(b64Crl));

    execUpdatePrepStmt0(SQL_ADD_CRL, columns.toArray(new SqlColumn2[0]));
  } // method addCrl

  public CertWithRevocationInfo revokeCert(
      NameId ca, BigInteger serialNumber, CertRevocationInfo revInfo, boolean force, CaIdNameMap idNameMap)
      throws OperationException {
    notNulls(ca, "ca", serialNumber, "serialNumber", revInfo, "revInfo");

    CertWithRevocationInfo certWithRevInfo = getCertWithRevocationInfo(ca.getId(), serialNumber, idNameMap);
    if (certWithRevInfo == null) {
      LOG.warn("certificate with CA={} and serialNumber={} does not exist",
          ca.getName(), LogUtil.formatCsn(serialNumber));
      return null;
    }

    CertRevocationInfo currentRevInfo = certWithRevInfo.getRevInfo();
    if (currentRevInfo != null) {
      CrlReason currentReason = currentRevInfo.getReason();
      if (currentReason == CrlReason.CERTIFICATE_HOLD) {
        if (revInfo.getReason() == CrlReason.CERTIFICATE_HOLD) {
          throw new OperationException(CERT_REVOKED, "certificate already revoked with the requested reason "
              + currentReason.getDescription());
        } else {
          revInfo.setRevocationTime(currentRevInfo.getRevocationTime());
          revInfo.setInvalidityTime(currentRevInfo.getInvalidityTime());
        }
      } else if (!force) {
        throw new OperationException(CERT_REVOKED,
            "certificate already revoked with reason " + currentReason.getDescription());
      }
    }

    Long invTimeSeconds = null;
    if (revInfo.getInvalidityTime() != null) {
      invTimeSeconds = revInfo.getInvalidityTime().getEpochSecond();
    }

    int count = execUpdatePrepStmt0(SQL_REVOKE_CERT,
        col2Long(Instant.now().getEpochSecond()), col2Bool(true),
        col2Long(revInfo.getRevocationTime().getEpochSecond()), // revTimeSeconds
        col2Long(invTimeSeconds), col2Int(revInfo.getReason().getCode()),
        col2Long(certWithRevInfo.getCert().getCertId())); // certId
    if (count != 1) {
      String message = (count > 1) ? count + " rows modified, but exactly one is expected"
          : "no row is modified, but exactly one is expected";
      throw new OperationException(SYSTEM_FAILURE, message);
    }

    certWithRevInfo.setRevInfo(revInfo);
    return certWithRevInfo;
  } // method revokeCert

  public CertWithRevocationInfo revokeSuspendedCert(
      NameId ca, SerialWithId serialNumber, CrlReason reason, CaIdNameMap idNameMap)
      throws OperationException {
    notNulls(ca, "ca", serialNumber, "serialNumber", reason, "reason");

    CertWithRevocationInfo certWithRevInfo = getCertWithRevocationInfo(serialNumber.getId(), idNameMap);
    if (certWithRevInfo == null) {
      LOG.warn("certificate with CA={} and serialNumber={} does not exist",
          ca.getName(), LogUtil.formatCsn(serialNumber.getSerial()));
      return null;
    }

    CertRevocationInfo currentRevInfo = certWithRevInfo.getRevInfo();
    if (currentRevInfo == null) {
      throw new OperationException(CERT_UNREVOKED, "certificate is not revoked");
    }

    CrlReason currentReason = currentRevInfo.getReason();
    if (currentReason != CrlReason.CERTIFICATE_HOLD) {
      throw new OperationException(CERT_REVOKED, "certificate is revoked but not with reason "
          + CrlReason.CERTIFICATE_HOLD.getDescription());
    }

    int count = execUpdatePrepStmt0(SQL_REVOKE_SUSPENDED_CERT, col2Long(Instant.now().getEpochSecond()),
        col2Int(reason.getCode()), col2Long(serialNumber.getId())); // certId

    if (count != 1) {
      String message = (count > 1) ? count + " rows modified, but exactly one is expected"
            : "no row is modified, but exactly one is expected";
      throw new OperationException(SYSTEM_FAILURE, message);
    }

    currentRevInfo.setReason(reason);
    return certWithRevInfo;
  } // method revokeSuspendedCert

  public CertWithDbId unsuspendCert(NameId ca, BigInteger serialNumber, boolean force, CaIdNameMap idNamMap)
      throws OperationException {
    notNulls(ca, "ca", serialNumber, "serialNumber");

    CertWithRevocationInfo certWithRevInfo = getCertWithRevocationInfo(ca.getId(), serialNumber, idNamMap);
    if (certWithRevInfo == null) {
      if (LOG.isWarnEnabled()) {
        LOG.warn("certificate with CA={} and serialNumber={} does not exist",
            ca.getName(), LogUtil.formatCsn(serialNumber));
      }
      return null;
    }

    CertRevocationInfo currentRevInfo = certWithRevInfo.getRevInfo();
    if (currentRevInfo == null) {
      throw new OperationException(CERT_UNREVOKED, "certificate is not revoked");
    }

    CrlReason currentReason = currentRevInfo.getReason();
    if (!force) {
      if (currentReason != CrlReason.CERTIFICATE_HOLD) {
        throw new OperationException(NOT_PERMITTED, "could not unsuspend certificate revoked with reason "
            + currentReason.getDescription());
      }
    }

    SqlColumn2 nullInt = new SqlColumn2(ColumnType.INT, null);
    int count = execUpdatePrepStmt0("UPDATE CERT SET LUPDATE=?,REV=?,RT=?,RIT=?,RR=? WHERE ID=?",
        col2Long(Instant.now().getEpochSecond()), // currentTimeSeconds
        col2Bool(false), nullInt, nullInt, nullInt,
        col2Long(certWithRevInfo.getCert().getCertId())); // certId

    if (count != 1) {
      String message = (count > 1) ? count + " rows modified, but exactly one is expected"
          : "no row is modified, but exactly one is expected";
      throw new OperationException(SYSTEM_FAILURE, message);
    }

    return certWithRevInfo.getCert();
  } // method unsuspendCert

  public void removeCert(long id) throws OperationException {
    execUpdatePrepStmt0(SQL_REMOVE_CERT_FOR_ID, col2Long(id));
  }

  public long getCountOfCerts(NameId ca, boolean onlyRevoked) throws OperationException {
    final String sql = onlyRevoked ? "SELECT COUNT(*) FROM CERT WHERE CA_ID=? AND REV=1"
                    : "SELECT COUNT(*) FROM CERT WHERE CA_ID=?";

    return execQueryLongPrepStmt(sql, col2Int(ca.getId()));
  } // method getCountOfCerts

  public long getCountOfCerts(long notBeforeSince) throws OperationException {
    if (notBeforeSince <= earliestNotBefore) {
      final String sql = "SELECT COUNT(*) FROM CERT";
      return execQueryLongPrepStmt(sql);
    } else {
      final String sql = "SELECT COUNT(*) FROM CERT WHERE NBEFORE>?";
      return execQueryLongPrepStmt(sql, col2Long(notBeforeSince - 1));
    }
  } // method getCountOfCerts

  public List<SerialWithId> getSerialNumbers(NameId ca,  long startId, int numEntries, boolean onlyRevoked)
      throws OperationException {
    notNulls(ca, "ca", numEntries, "numEntries");

    LruCache<Integer, String> cache = onlyRevoked ? cacheSqlSerialsRevoked : cacheSqlSerials;
    String sql = cache.get(numEntries);
    if (sql == null) {
      String coreSql = "ID,SN FROM CERT WHERE ID>? AND CA_ID=?";
      if (onlyRevoked) {
        coreSql += "AND REV=1";
      }
      sql = datasource.buildSelectFirstSql(numEntries, "ID ASC", coreSql);
      cache.put(numEntries, sql);
    }

    return getSerialWithIds(sql, numEntries, col2Long(startId - 1), col2Int(ca.getId()));
  } // method getSerialNumbers

  private List<SerialWithId> getSerialWithIds(String sql, int numEntries, SqlColumn2... params)
      throws OperationException {
    List<ResultRow> rows = execQueryPrepStmt0(sql, params);

    List<SerialWithId> ret = new ArrayList<>();
    for (ResultRow rs : rows) {
      ret.add(new SerialWithId(rs.getLong("ID"), new BigInteger(rs.getString("SN"), 16)));
      if (ret.size() >= numEntries) {
        break;
      }
    }

    return ret;
  }

  public List<SerialWithId> getExpiredUnrevokedSerialNumbers(NameId ca, long expiredAt, int numEntries)
      throws OperationException {
    notNull(ca, "ca");
    positive(numEntries, "numEntries");

    String sql = cacheSqlExpiredSerials.get(numEntries);
    if (sql == null) {
      sql = datasource.buildSelectFirstSql(numEntries, "ID,SN FROM CERT WHERE CA_ID=? AND NAFTER<? AND REV=0");
      cacheSqlExpiredSerials.put(numEntries, sql);
    }

    return getSerialNumbers0(sql, numEntries, col2Int(ca.getId()), col2Long(expiredAt));
  } // method getExpiredSerialNumbers

  public List<SerialWithId> getSuspendedCertSerials(NameId ca, Instant latestLastUpdate, int numEntries)
      throws OperationException {
    notNull(ca, "ca");
    positive(numEntries, "numEntries");

    String sql = cacheSqlSuspendedSerials.get(numEntries);
    if (sql == null) {
      sql = datasource.buildSelectFirstSql(numEntries, "ID,SN FROM CERT WHERE CA_ID=? AND LUPDATE<? AND RR=?");
      cacheSqlSuspendedSerials.put(numEntries, sql);
    }

    return getSerialNumbers0(sql, numEntries, col2Int(ca.getId()), col2Long(latestLastUpdate.getEpochSecond() + 1),
            col2Int(CrlReason.CERTIFICATE_HOLD.getCode()));
  } // method getSuspendedCertIds

  private List<SerialWithId> getSerialNumbers0(String sql, int numEntries, SqlColumn2... params)
      throws OperationException {
    List<ResultRow> rows = execQueryPrepStmt0(sql, params);
    List<SerialWithId> ret = new ArrayList<>();
    for (ResultRow row : rows) {
      ret.add(new SerialWithId(row.getLong("ID"), new BigInteger(row.getString("SN"), 16)));
      if (ret.size() >= numEntries) {
        break;
      }
    }
    return ret;
  } // method getExpiredSerialNumbers

  private byte[] getEncodedCrl(NameId ca) throws OperationException {
    notNull(ca, "ca");

    List<ResultRow> rows = execQueryPrepStmt0(sqlCrl, col2Int(ca.getId()));
    long currentThisUpdate = 0;

    String b64Crl = null;
    // iterate all entries to make sure that the latest CRL will be returned
    for (ResultRow rs : rows) {
      long thisUpdate = rs.getLong("THISUPDATE");
      if (thisUpdate >= currentThisUpdate) {
        b64Crl = rs.getString("CRL");
        currentThisUpdate = thisUpdate;
      }
    }

    return (b64Crl == null) ? null : Base64.decodeFast(b64Crl);
  } // method getEncodedCrl

  public byte[] getEncodedCrl(NameId ca, BigInteger crlNumber) throws OperationException {
    notNull(ca, "ca");

    if (crlNumber == null) {
      return getEncodedCrl(ca);
    }

    ResultRow rs = execQuery1PrepStmt0(sqlCrlWithNo, col2Int(ca.getId()), col2Long(crlNumber.longValue()));

    return rs == null ? null : Base64.decodeFast(rs.getString("CRL"));
  } // method getEncodedCrl

  public int cleanupCrls(NameId ca, int numCrls) throws OperationException {
    notNull(ca, "ca");
    positive(numCrls, "numCrls");

    List<Long> crlNumbers = new LinkedList<>();

    List<ResultRow> rows = execQueryPrepStmt0("SELECT CRL_NO FROM CRL WHERE CA_ID=? AND DELTACRL=?",
        col2Int(ca.getId()), col2Bool(false));
    for (ResultRow rs : rows) {
      crlNumbers.add(rs.getLong("CRL_NO"));
    }

    int size = crlNumbers.size();
    Collections.sort(crlNumbers);

    int numCrlsToDelete = size - numCrls;
    if (numCrlsToDelete < 1) {
      return 0;
    }

    long crlNumber = crlNumbers.get(numCrlsToDelete - 1);
    execUpdatePrepStmt0("DELETE FROM CRL WHERE CA_ID=? AND CRL_NO<?", col2Int(ca.getId()), col2Long(crlNumber + 1));

    return numCrlsToDelete;
  } // method cleanupCrls

  public CertificateInfo getCertForId(NameId ca, X509Cert caCert, long certId, CaIdNameMap idNameMap)
      throws OperationException {
    notNulls(ca, "ca", caCert, "caCert", idNameMap, "idNameMap");

    ResultRow rs = execQuery1PrepStmt0(sqlCertForId, col2Long(certId));
    if (rs == null) {
      return null;
    }

    X509Cert cert = parseCert(Base64.decodeFast(rs.getString("CERT")));
    CertWithDbId certWithMeta = new CertWithDbId(cert);
    certWithMeta.setCertId(certId);
    CertificateInfo certInfo = new CertificateInfo(certWithMeta, null, ca, caCert,
        idNameMap.getCertprofile(rs.getInt("PID")), idNameMap.getRequestor(rs.getInt("RID")));
    certInfo.setRevocationInfo(buildCertRevInfo(rs));
    return certInfo;
  } // method getCertForId

  public CertWithRevocationInfo getCertWithRevocationInfo(long certId, CaIdNameMap idNameMap)
      throws OperationException {
    ResultRow rs = execQuery1PrepStmt0(sqlCertForId, col2Long(certId));
    if (rs == null) {
      return null;
    }
    return buildCertWithRevInfo(certId, rs, idNameMap);
  }

  public CertWithRevocationInfo getCertWithRevocationInfo(int caId, BigInteger serial, CaIdNameMap idNameMap)
      throws OperationException {
    notNulls(serial, "serial", idNameMap, "idNameMap");

    ResultRow rs = execQuery1PrepStmt0(sqlCertWithRevInfo,
        col2Int(caId), col2Str(serial.toString(16)));
    if (rs == null) {
      return null;
    }

    return buildCertWithRevInfo(rs.getLong("ID"), rs, idNameMap);
  } // method getCertWithRevocationInfo

  public CertWithRevocationInfo getCertWithRevocationInfoBySubject(
      int caId, X500Name subject, byte[] san, CaIdNameMap idNameMap)
      throws OperationException {
    notNull(subject, "subject");

    long fpSubject = X509Util.fpCanonicalizedName(subject);
    Long fpSan = san == null ? null : FpIdCalculator.hash(san);

    ResultRow rs = execQuery1PrepStmt0(sqlCertWithRevInfoBySubjectAndSan,
        col2Int(caId), col2Long(fpSubject), col2Long(fpSan));
    if (rs == null) {
      return null;
    }

    return buildCertWithRevInfo(rs.getLong("ID"), rs, idNameMap);
  } // method getCertWithRevocationInfo

  private CertWithRevocationInfo buildCertWithRevInfo(long certId, ResultRow rs, CaIdNameMap idNameMap)
      throws OperationException {
    X509Cert cert = parseCert(Base64.decodeFast(rs.getString("CERT")));
    CertWithDbId certWithMeta = new CertWithDbId(cert);
    certWithMeta.setCertId(certId);

    CertWithRevocationInfo ret = new CertWithRevocationInfo();
    ret.setCertprofile(idNameMap.getCertprofileName(rs.getInt("PID")));
    ret.setCert(certWithMeta);
    ret.setRevInfo(buildCertRevInfo(rs));
    return ret;
  } // method getCertWithRevocationInfo

  public long getCertId(NameId ca, BigInteger serial) throws OperationException {
    notNulls(ca, "ca", serial, "serial");

    ResultRow rs = execQuery1PrepStmt0(sqlCertIdByCaSn, col2Int(ca.getId()), col2Str(serial.toString(16)));
    return (rs == null) ? 0 : rs.getLong("ID");
  }

  public CertificateInfo getCertInfo(NameId ca, X509Cert caCert, BigInteger serial, CaIdNameMap idNameMap)
      throws OperationException {
    notNulls(ca, "ca", caCert, "caCert", idNameMap, "idNameMap", serial, "serial");

    ResultRow rs = execQuery1PrepStmt0(sqlCertInfo, col2Int(ca.getId()), col2Str(serial.toString(16)));
    if (rs == null) {
      return null;
    }

    byte[] encodedCert = Base64.decodeFast(rs.getString("CERT"));
    CertWithDbId certWithMeta = new CertWithDbId(parseCert(encodedCert));

    CertificateInfo certInfo = new CertificateInfo(certWithMeta, null, ca, caCert,
        idNameMap.getCertprofile(rs.getInt("PID")), idNameMap.getRequestor(rs.getInt("RID")));

    certInfo.setRevocationInfo(buildCertRevInfo(rs));
    return certInfo;
  } // method getCertInfo

  /**
   * Get certificate for given subject and transactionId.
   *
   * @param subjectName Subject of Certificate or requested Subject.
   * @param transactionId the transactionId
   * @return certificate for given subject and transactionId.
   * @throws OperationException
   *           If error occurs.
   */
  public X509Cert getCert(X500Name subjectName, String transactionId)
      throws OperationException {
    final String sql = buildSelectFirstSql("CERT FROM CERT WHERE TID=? AND (FP_S=? OR FP_RS=?)");

    long fpSubject = X509Util.fpCanonicalizedName(subjectName);

    SqlColumn2[] params = new SqlColumn2[3];
    params[0] = col2Str(transactionId);
    params[1] = col2Long(fpSubject);
    params[2] = col2Long(fpSubject);

    List<ResultRow> rows = execQueryPrepStmt0(sql, params);
    return rows == null || rows.isEmpty() ? null : parseCert(Base64.decodeFast(rows.get(0).getString("CERT")));
  } // method getCert

  public List<CertListInfo> listCerts(
      NameId ca, X500Name subjectPattern, Instant validFrom, Instant validTo, CertListOrderBy orderBy, int numEntries)
      throws OperationException {
    notNull(ca, "ca");
    positive(numEntries, "numEntries");

    StringBuilder sb = new StringBuilder(200);
    sb.append("SN,NBEFORE,NAFTER,SUBJECT FROM CERT WHERE CA_ID=?");

    List<SqlColumn2> params = new ArrayList<>(4);
    params.add(col2Int(ca.getId()));

    if (validFrom != null) {
      sb.append(" AND NBEFORE<?");
      params.add(col2Long(validFrom.getEpochSecond() - 1));
    }
    if (validTo != null) {
      sb.append(" AND NAFTER>?");
      params.add(col2Long(validTo.getEpochSecond()));
    }

    if (subjectPattern != null) {
      sb.append(" AND SUBJECT LIKE ?");

      StringBuilder buffer = new StringBuilder(100);
      buffer.append("%");
      RDN[] rdns = subjectPattern.getRDNs();
      for (RDN rdn : rdns) {
        X500Name rdnName = new X500Name(new RDN[]{rdn});
        String rdnStr = X509Util.x500NameText(rdnName);
        if (rdnStr.indexOf('%') != -1) {
          throw new OperationException(BAD_REQUEST, "the character '%' is not allowed in subjectPattern");
        }
        if (rdnStr.indexOf('*') != -1) {
          rdnStr = rdnStr.replace('*', '%');
        }
        buffer.append(rdnStr);
        buffer.append("%");
      }
      params.add(col2Str(buffer.toString()));
    }

    String sortByStr = null;
    if (orderBy != null) {
      if (orderBy == CertListOrderBy.NOT_BEFORE) {
        sortByStr = "NBEFORE";
      } else if (orderBy == CertListOrderBy.NOT_BEFORE_DESC) {
        sortByStr = "NBEFORE DESC";
      } else if (orderBy == CertListOrderBy.NOT_AFTER) {
        sortByStr = "NAFTER";
      } else if (orderBy == CertListOrderBy.NOT_AFTER_DESC) {
        sortByStr = "NAFTER DESC";
      } else if (orderBy == CertListOrderBy.SUBJECT) {
        sortByStr = "SUBJECT";
      } else if (orderBy == CertListOrderBy.SUBJECT_DESC) {
        sortByStr = "SUBJECT DESC";
      } else {
        throw new IllegalStateException("unknown CertListOrderBy " + orderBy);
      }
    }

    final String sql = datasource.buildSelectFirstSql(numEntries, sortByStr, sb.toString());
    List<ResultRow> rows = execQueryPrepStmt0(sql, params.toArray(new SqlColumn2[0]));

    List<CertListInfo> ret = new LinkedList<>();
    for (ResultRow rs : rows) {
      CertListInfo info = new CertListInfo(new BigInteger(rs.getString("SN"), 16),
          rs.getString("SUBJECT"), Instant.ofEpochSecond(rs.getLong("NBEFORE")),
          Instant.ofEpochSecond(rs.getLong("NAFTER")));
      ret.add(info);
    }
    return ret;
  } // method listCerts

  public List<CertRevInfoWithSerial> getRevokedCerts(NameId ca, Instant notExpiredAt, long startId, int numEntries)
      throws OperationException {
    notNulls(ca, "ca", notExpiredAt, "notExpiredAt");
    positive(numEntries, "numEntries");

    String sql = cacheSqlRevokedCerts.get(numEntries);
    if (sql == null) {
      String coreSql = "ID,SN,RR,RT,RIT FROM CERT WHERE ID>? AND CA_ID=? AND REV=1 AND NAFTER>?";
      sql = datasource.buildSelectFirstSql(numEntries, "ID ASC", coreSql);
      cacheSqlRevokedCerts.put(numEntries, sql);
    }

    List<ResultRow> rows = execQueryPrepStmt0(sql,
        col2Long(startId - 1), col2Int(ca.getId()), col2Long(notExpiredAt.getEpochSecond() + 1));

    List<CertRevInfoWithSerial> ret = new LinkedList<>();
    for (ResultRow rs : rows) {
      long revInvalidityTime = rs.getLong("RIT");
      Instant invalidityTime = (revInvalidityTime == 0) ? null : Instant.ofEpochSecond(revInvalidityTime);
      CertRevInfoWithSerial revInfo = new CertRevInfoWithSerial(rs.getLong("ID"),
          new BigInteger(rs.getString("SN"), 16), rs.getInt("RR"), // revReason
          Instant.ofEpochSecond(rs.getLong("RT")), invalidityTime);
      ret.add(revInfo);
    }

    return ret;
  } // method getRevokedCerts

  public List<CertRevInfoWithSerial> getCertsForDeltaCrl(NameId ca, BigInteger baseCrlNumber, Instant notExpiredAt)
      throws OperationException {
    notNulls(ca, "ca", notExpiredAt, "notExpiredAt", baseCrlNumber, "baseCrlNumber");

    // Get the Base FullCRL
    byte[] encodedCrl = getEncodedCrl(ca, baseCrlNumber);
    CertificateList crl = CertificateList.getInstance(encodedCrl);
    // Get revoked certs in CRL
    Enumeration<?> revokedCertsInCrl = crl.getRevokedCertificateEnumeration();

    Set<BigInteger> allSnSet = null;

    boolean supportInSql = datasource.getDatabaseType().supportsInArray();
    List<BigInteger> snList = new LinkedList<>();

    List<CertRevInfoWithSerial> ret = new LinkedList<>();

    PreparedStatement ps = null;
    try {
      while (revokedCertsInCrl.hasMoreElements()) {
        CRLEntry crlEntry = (CRLEntry) revokedCertsInCrl.nextElement();
        if (allSnSet == null) {
          // guess the size of revoked certificate, very rough
          int averageSize = encodedCrl.length / crlEntry.getEncoded().length;
          allSnSet = new HashSet<>((int) (1.1 * averageSize));
        }

        BigInteger sn = crlEntry.getUserCertificate().getPositiveValue();
        snList.add(sn);
        allSnSet.add(sn);

        if (!supportInSql) {
          continue;
        }

        if (snList.size() == 100) {
          // check whether revoked certificates have been unrevoked.

          // due to the memory consumption do not use the executeQueryPreparedStament0() method.
          if (ps == null) {
            ps = prepareStatement(sqlSelectUnrevokedSn100);
          }

          for (int i = 1; i < 101; i++) {
            ps.setString(i, snList.get(i - 1).toString(16));
          }
          snList.clear();

          ResultSet rs = ps.executeQuery();
          try {
            while (rs.next()) {
              ret.add(new CertRevInfoWithSerial(0L, new BigInteger(rs.getString("SN"), 16),
                  CrlReason.REMOVE_FROM_CRL, // reason
                  Instant.ofEpochSecond(rs.getLong("LUPDATE")), //revocationTime,
                  null)); // invalidityTime
            }
          } finally {
            datasource.releaseResources(null, rs);
          }
        }
      }
    } catch (SQLException ex) {
      throw new OperationException(DATABASE_FAILURE, datasource.translate(sqlSelectUnrevokedSn100, ex).getMessage());
    } catch (IOException ex) {
      throw new OperationException(CRL_FAILURE, ex.getMessage());
    } finally {
      datasource.releaseResources(ps, null);
    }

    if (!snList.isEmpty()) {
      // check whether revoked certificates have been unrevoked.
      ps = prepareStatement(sqlSelectUnrevokedSn);
      try {
        for (BigInteger sn : snList) {
          ps.setString(1, sn.toString(16));
          ResultSet rs = ps.executeQuery();
          try {
            if (rs.next()) {
              ret.add(new CertRevInfoWithSerial(0L, sn, CrlReason.REMOVE_FROM_CRL,
                  Instant.ofEpochSecond(rs.getLong("LUPDATE")), //revocationTime,
                  null)); // invalidityTime
            }
          } finally {
            datasource.releaseResources(null, rs);
          }
        }
      } catch (SQLException ex) {
        throw new OperationException(DATABASE_FAILURE, datasource.translate(sqlSelectUnrevokedSn, ex).getMessage());
      } finally {
        datasource.releaseResources(ps, null);
      }
    }

    // get list of certificates revoked after the generation of Base FullCRL
    // we check all revoked certificates with LUPDATE field (last update) > THISUPDATE - 1.
    final int numEntries = 1000;

    String coreSql = "ID,SN,RR,RT,RIT FROM CERT WHERE ID>? AND CA_ID=? AND REV=1 AND NAFTER>? AND LUPDATE>?";
    String sql = datasource.buildSelectFirstSql(numEntries, "ID ASC", coreSql);
    ps = prepareStatement(sql);
    long startId = 1;

    // -1: so that no entry is ignored: consider all revoked certificates with
    // Database.lastUpdate >= CRL.thisUpdate
    final long updatedSince = DateUtil.toEpochSecond(crl.getThisUpdate().getDate()) - 1;

    try {
      ResultSet rs;
      while (true) {
        ps.setLong(1, startId - 1);
        ps.setInt(2, ca.getId());
        ps.setLong(3, notExpiredAt.getEpochSecond() + 1);
        ps.setLong(4, updatedSince);
        rs = ps.executeQuery();

        try {
          int num = 0;
          while (rs.next()) {
            num++;
            long id = rs.getLong("ID");
            if (id > startId) {
              startId = id;
            }

            BigInteger sn = new BigInteger(rs.getString("SN"), 16);
            if (allSnSet != null && allSnSet.contains(sn)) {
              // already contained in CRL
              continue;
            }

            long revInvalidityTime = rs.getLong("RIT");
            Instant invalidityTime = (revInvalidityTime == 0) ? null : Instant.ofEpochSecond(revInvalidityTime);
            CertRevInfoWithSerial revInfo = new CertRevInfoWithSerial(id, sn,
                rs.getInt("RR"), Instant.ofEpochSecond(rs.getLong("RT")), invalidityTime);
            ret.add(revInfo);
          }

          if (num < numEntries) {
            // no more entries
            break;
          }
        } finally {
          datasource.releaseResources(null,rs);
        }
      }
    } catch (SQLException ex) {
      throw new OperationException(DATABASE_FAILURE, datasource.translate(sql, ex).getMessage());
    } finally {
      datasource.releaseResources(ps, null);
    }

    return ret;
  } // method getCertsForDeltaCrl

  public CertStatus getCertStatusForSubject(NameId ca, X500Name subject) throws OperationException {
    long subjectFp = X509Util.fpCanonicalizedName(subject);
    ResultRow rs = execQuery1PrepStmt0(sqlCertStatusForSubjectFp, col2Long(subjectFp), col2Int(ca.getId()));
    return (rs == null) ? CertStatus.UNKNOWN : rs.getBoolean("REV") ? CertStatus.REVOKED : CertStatus.GOOD;
  } // method getCertStatusForSubjectFp

  public boolean isHealthy() {
    try {
      execUpdateStmt("SELECT ID FROM CA");
      return true;
    } catch (Exception ex) {
      LOG.error("isHealthy(). {}: {}", ex.getClass().getName(), ex.getMessage());
      LOG.debug("isHealthy()", ex);
      return false;
    }
  } // method isHealthy

  private static Long getDateSeconds(Date date) {
    return date == null ? null : DateUtil.toEpochSecond(date);
  }

}
