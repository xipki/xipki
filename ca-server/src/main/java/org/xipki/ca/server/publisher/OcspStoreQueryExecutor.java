// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.publisher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CertWithDbId;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.exception.ErrorCode;
import org.xipki.security.exception.OperationException;
import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.datasource.DataAccessException;
import org.xipki.util.datasource.DataSourceWrapper;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.extra.misc.SqlUtil;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * XiPKI OCSP database query executor.
 *
 * @author Lijun Liao (xipki)
 */

class OcspStoreQueryExecutor {

  private static class IssuerEntry {

    private final int id;

    private final byte[] cert;

    IssuerEntry(int id, String b64Cert) {
      this.id = id;
      this.cert = Base64.decode(b64Cert);
    }

    int getId() {
      return id;
    }

    boolean matchCert(byte[] encodedCert) {
      return Arrays.equals(this.cert, encodedCert);
    }
  } // class IssuerEntry

  private static class IssuerStore {

    private final List<IssuerEntry> entries;

    IssuerStore(List<IssuerEntry> entries) {
      Args.notNull(entries, "entries");
      this.entries = new ArrayList<>(entries.size());

      for (IssuerEntry entry : entries) {
        addIdentityEntry(entry);
      }
    } // constructor

    final void addIdentityEntry(IssuerEntry entry) {
      Args.notNull(entry, "entry");
      for (IssuerEntry existingEntry : entries) {
        if (existingEntry.getId() == entry.getId()) {
          throw new IllegalArgumentException("issuer with the same id "
              + entry.getId() + " already available");
        }
      }

      entries.add(entry);
    } // method addIdentityEntry

    Integer getIdForCert(byte[] encodedCert) {
      Args.notNull(encodedCert, "encodedCert");
      for (IssuerEntry entry : entries) {
        if (entry.matchCert(encodedCert)) {
          return entry.getId();
        }
      }

      return null;
    } // method getIdForCert

  } // class IssuerStore

  private static final String SQL_ADD_REVOKED_CERT =
      SqlUtil.buildInsertSql("CERT",
          "ID,LUPDATE,SN,NBEFORE,NAFTER,REV,IID,HASH,SUBJECT,RT,RIT,RR");

  private static final String SQL_ADD_CERT =
      SqlUtil.buildInsertSql("CERT",
          "ID,LUPDATE,SN,NBEFORE,NAFTER,REV,IID,HASH,SUBJECT");

  private static final Logger LOG =
      LoggerFactory.getLogger(OcspStoreQueryExecutor.class);

  private final DataSourceWrapper datasource;

  private final String sqlCertRegistered;

  private final IssuerStore issuerStore;

  private final boolean publishGoodCerts;

  @SuppressWarnings("unused")
  private final int dbSchemaVersion;

  private final int maxX500nameLen;

  private final HashAlgo certhashAlgo;

  private final AtomicInteger cachedIssuerId = new AtomicInteger(0);

  OcspStoreQueryExecutor(DataSourceWrapper datasource, boolean publishGoodCerts)
      throws DataAccessException, NoSuchAlgorithmException {
    this.datasource = Args.notNull(datasource, "datasource");
    this.issuerStore = initIssuerStore();
    this.publishGoodCerts = publishGoodCerts;

    this.sqlCertRegistered = datasource.buildSelectFirstSql(1,
        "ID FROM CERT WHERE SN=? AND IID=?");
    final String sql = "SELECT NAME,VALUE2 FROM DBSCHEMA";

    Map<String, String> variables = new HashMap<>();
    PreparedStatement stmt = null;
    ResultSet rs = null;

    try {
      stmt = Optional.ofNullable(datasource.prepareStatement(sql)).orElseThrow(
          () -> new DataAccessException("could not create statement"));

      rs = stmt.executeQuery();
      while (rs.next()) {
        String name = rs.getString("NAME");
        String value = rs.getString("VALUE2");
        variables.put(name, value);
      }
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }

    String str = variables.get("VERSION");
    this.dbSchemaVersion = Integer.parseInt(str);
    str = variables.get("X500NAME_MAXLEN");
    this.maxX500nameLen = Integer.parseInt(str);

    str = variables.get("CERTHASH_ALGO");
    this.certhashAlgo = HashAlgo.getInstance(str);
  } // constructor

  private IssuerStore initIssuerStore() throws DataAccessException {
    final String sql = "SELECT ID,CERT FROM ISSUER";
    PreparedStatement ps = datasource.prepareStatement(sql);
    ResultSet rs = null;

    try {
      rs = ps.executeQuery();
      List<IssuerEntry> caInfos = new LinkedList<>();
      while (rs.next()) {
        caInfos.add(new IssuerEntry(rs.getInt("ID"), rs.getString("CERT")));
      }

      return new IssuerStore(caInfos);
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, rs);
    }
  } // method initIssuerStore

  void addCert(X509Cert issuer, CertWithDbId certificate,
               CertRevocationInfo revInfo)
      throws DataAccessException, OperationException {
    addOrUpdateCert(issuer, certificate, revInfo);
  }

  private void addOrUpdateCert(
      X509Cert issuer, CertWithDbId certificate, CertRevocationInfo revInfo)
      throws DataAccessException, OperationException {
    Args.notNull(issuer, "issuer");

    boolean revoked = (revInfo != null);
    int issuerId = getIssuerId(issuer);

    BigInteger serialNumber = certificate.cert().serialNumber();
    Long certRegisteredId = getCertId(issuerId, serialNumber);

    if (!publishGoodCerts && !revoked && certRegisteredId != null) {
      return;
    }

    if (certRegisteredId != null) {
      updateRegisteredCert(certRegisteredId, revInfo);
      return;
    }

    final String sql = revoked ? SQL_ADD_REVOKED_CERT : SQL_ADD_CERT;

    long certId = certificate.certId();
    byte[] encodedCert = certificate.cert().getEncoded();
    String certHash = certhashAlgo.base64Hash(encodedCert);

    X509Cert cert = certificate.cert();
    String cuttedSubject = X509Util.cutText(
        certificate.cert().subjectText(), maxX500nameLen);

    PreparedStatement ps = datasource.prepareStatement(sql);

    try {
      // CERT
      int idx = 1;
      ps.setLong(idx++, certId);
      ps.setLong(idx++, Instant.now().getEpochSecond()); // currentTimeSeconds
      ps.setString(idx++, serialNumber.toString(16));
      ps.setLong(idx++, cert.notBefore().getEpochSecond());
      ps.setLong(idx++, cert.notAfter().getEpochSecond());
      setBoolean(ps, idx++, revoked);
      ps.setInt(idx++, issuerId);
      ps.setString(idx++, certHash);
      ps.setString(idx++, cuttedSubject);

      if (revoked) {
        long revTime = revInfo.revocationTime().getEpochSecond();
        ps.setLong(idx++, revTime);
        if (revInfo.invalidityTime() != null) {
          ps.setLong(idx++, revInfo.invalidityTime().getEpochSecond());
        } else {
          ps.setNull(idx++, Types.BIGINT);
        }
        int reasonCode = (revInfo.reason() == null)
            ? 0 : revInfo.reason().code();
        ps.setInt(idx, reasonCode);
      }

      try {
        ps.executeUpdate();
      } catch (Throwable th) {
        // more secure
        datasource.deleteFromTable(null, "CERT", "ID", certId);

        if (th instanceof SQLException) {
          SQLException ex = (SQLException) th;
          LOG.error("datasource {} could not add certificate with id {}: {}",
              datasource.name(), certId, th.getMessage());
          throw datasource.translate(sql, ex);
        } else {
          throw new OperationException(ErrorCode.SYSTEM_FAILURE, th);
        }
      }
    } catch (SQLException ex) {
      throw datasource.translate(null, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addOrUpdateCert

  private void updateRegisteredCert(
      long registeredCertId, CertRevocationInfo revInfo)
      throws DataAccessException {
    boolean revoked = (revInfo != null);

    final String sql =
        "UPDATE CERT SET LUPDATE=?,REV=?,RT=?,RIT=?,RR=? WHERE ID=?";

    PreparedStatement ps = datasource.prepareStatement(sql);

    try {
      int idx = 1;
      ps.setLong(idx++, Instant.now().getEpochSecond()); // currentTimeSeconds
      setBoolean(ps, idx++, revoked);
      if (revoked) {
        long revTime = revInfo.revocationTime().getEpochSecond();
        ps.setLong(idx++, revTime);
        if (revInfo.invalidityTime() != null) {
          ps.setLong(idx++, revInfo.invalidityTime().getEpochSecond());
        } else {
          ps.setNull(idx++, Types.INTEGER);
        }
        ps.setInt(idx++, revInfo.reason().code());
      } else {
        ps.setNull(idx++, Types.INTEGER); // rev_time
        ps.setNull(idx++, Types.INTEGER); // rev_invalidity_time
        ps.setNull(idx++, Types.INTEGER); // rev_reason
      }
      ps.setLong(idx, registeredCertId);
      ps.executeUpdate();
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method updateRegisteredCert

  void revokeCert(X509Cert caCert, CertWithDbId cert,
                  CertRevocationInfo revInfo)
      throws DataAccessException, OperationException {
    addOrUpdateCert(caCert, cert, revInfo);
  }

  void unrevokeCert(X509Cert issuer, CertWithDbId cert)
      throws DataAccessException {
    Args.notNull(issuer, "issuer");
    Args.notNull(cert, "cert");

    Integer issuerId = issuerStore.getIdForCert(issuer.getEncoded());
    if (issuerId == null) {
      return;
    }

    BigInteger serialNumber = cert.cert().serialNumber();
    Long certRegisteredId = getCertId(issuerId, serialNumber);

    if (certRegisteredId == null) {
      return;
    }

    if (publishGoodCerts) {
      final String sql =
          "UPDATE CERT SET LUPDATE=?,REV=?,RT=?,RIT=?,RR=? WHERE ID=?";
      PreparedStatement ps = datasource.prepareStatement(sql);

      try {
        int idx = 1;
        ps.setLong(idx++, Instant.now().getEpochSecond());
        setBoolean(ps, idx++, false);
        ps.setNull(idx++, Types.INTEGER);
        ps.setNull(idx++, Types.INTEGER);
        ps.setNull(idx++, Types.INTEGER);
        ps.setLong(idx, certRegisteredId);
        ps.executeUpdate();
      } catch (SQLException ex) {
        throw datasource.translate(sql, ex);
      } finally {
        datasource.releaseResources(ps, null);
      }
    } else {
      final String sql = "DELETE FROM CERT WHERE IID=? AND SN=?";
      PreparedStatement ps = datasource.prepareStatement(sql);

      try {
        ps.setInt(1, issuerId);
        ps.setString(2, serialNumber.toString(16));
        ps.executeUpdate();
      } catch (SQLException ex) {
        throw datasource.translate(sql, ex);
      } finally {
        datasource.releaseResources(ps, null);
      }
    }

  } // method unrevokeCert

  void removeCert(X509Cert issuer, CertWithDbId cert)
      throws DataAccessException {
    Args.notNull(cert, "cert");

    Integer issuerId = issuerStore.getIdForCert(
        Args.notNull(issuer, "issuer").getEncoded());
    if (issuerId == null) {
      return;
    }

    final String sql = "DELETE FROM CERT WHERE IID=? AND SN=?";
    PreparedStatement ps = datasource.prepareStatement(sql);

    try {
      ps.setInt(1, issuerId);
      ps.setString(2, cert.cert().serialNumber().toString(16));
      ps.executeUpdate();
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method removeCert

  void revokeCa(X509Cert caCert, CertRevocationInfo revInfo)
      throws DataAccessException {
    Args.notNull(revInfo, "revInfo");

    int issuerId = getIssuerId(Args.notNull(caCert, "caCert"));
    final String sql = "UPDATE ISSUER SET REV_INFO=? WHERE ID=?";
    PreparedStatement ps = datasource.prepareStatement(sql);

    try {
      ps.setString(1, revInfo.encode());
      ps.setInt(2, issuerId);
      ps.executeUpdate();
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method revokeCa

  void unrevokeCa(X509Cert caCert) throws DataAccessException {
    int issuerId = getIssuerId(caCert);
    final String sql = "UPDATE ISSUER SET REV_INFO=? WHERE ID=?";
    PreparedStatement ps = datasource.prepareStatement(sql);

    try {
      ps.setNull(1, Types.VARCHAR);
      ps.setInt(2, issuerId);
      ps.executeUpdate();
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method unrevokeCa

  private int getIssuerId(X509Cert issuerCert) {
    return Optional.ofNullable(
        issuerStore.getIdForCert(
            Args.notNull(issuerCert, "issuerCert").getEncoded()))
        .orElseThrow(() -> new IllegalStateException("could not find issuer, "
            + "please start XiPKI in master mode first the restart this " +
            "XiPKI system"));
  }

  void addIssuer(X509Cert issuerCert) throws DataAccessException {
    if (issuerStore.getIdForCert(issuerCert.getEncoded()) != null) {
      return;
    }

    String sha1FpCert = HashAlgo.SHA1.base64Hash(issuerCert.getEncoded());
    int maxIdInDb = (int) datasource.getMax(null, "ISSUER", "ID");
    int id = Math.max(maxIdInDb, cachedIssuerId.get()) + 1;
    cachedIssuerId.set(id);

    byte[] encodedCert = issuerCert.getEncoded();

    final String sql =
        "INSERT INTO ISSUER (ID,SUBJECT,NBEFORE,NAFTER,S1C,CERT) " +
        "VALUES (?,?,?,?,?,?)";

    PreparedStatement ps = datasource.prepareStatement(sql);

    try {
      String b64Cert = Base64.encodeToString(encodedCert);
      String subject = issuerCert.subjectText();
      int idx = 1;
      ps.setInt(idx++, id);
      ps.setString(idx++, subject);
      ps.setLong(idx++, issuerCert.notBefore().getEpochSecond());
      ps.setLong(idx++, issuerCert.notAfter().getEpochSecond());
      ps.setString(idx++, sha1FpCert);
      ps.setString(idx, b64Cert);

      ps.execute();
      issuerStore.addIdentityEntry(new IssuerEntry(id, b64Cert));
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addIssuer

  /**
   * Returns the database id for the given issuer and serialNumber.
   * @return the database table id if registered, <code>null</code> otherwise.
   */
  private Long getCertId(int issuerId, BigInteger serialNumber)
      throws DataAccessException {
    final String sql = sqlCertRegistered;
    ResultSet rs = null;
    PreparedStatement ps = datasource.prepareStatement(sql);

    try {
      ps.setString(1, serialNumber.toString(16));
      ps.setInt(2, issuerId);

      rs = ps.executeQuery();
      return rs.next() ? rs.getLong("ID") : null;
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, rs);
    }
  } // method getCertId

  boolean isHealthy() {
    final String sql = "SELECT ID FROM ISSUER";

    try {
      ResultSet rs = null;
      PreparedStatement ps = datasource.prepareStatement(sql);

      try {
        rs = ps.executeQuery();
      } finally {
        datasource.releaseResources(ps, rs);
      }
      return true;
    } catch (Exception ex) {
      LogUtil.error(LOG, ex);
      return false;
    }
  } // method isHealthy

  private static void setBoolean(PreparedStatement ps, int index, boolean value)
      throws SQLException {
    ps.setInt(index, value ? 1 : 0);
  }

}
