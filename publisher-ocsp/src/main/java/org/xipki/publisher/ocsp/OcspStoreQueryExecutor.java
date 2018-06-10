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

package org.xipki.publisher.ocsp;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CertWithDbId;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;
import org.xipki.util.LogUtil;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class OcspStoreQueryExecutor {

  private static final String SQL_ADD_REVOKED_CERT =
      "INSERT INTO CERT (ID,LUPDATE,SN,NBEFORE,NAFTER,REV,IID,PN,HASH,SUBJECT,RT,RIT,RR)"
      + " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";

  private static final String SQL_ADD_CERT =
      "INSERT INTO CERT (ID,LUPDATE,SN,NBEFORE,NAFTER,REV,IID,PN,HASH,SUBJECT) "
      + "VALUES (?,?,?,?,?,?,?,?,?,?)";

  private static final Logger LOG = LoggerFactory.getLogger(OcspStoreQueryExecutor.class);

  private final DataSourceWrapper datasource;

  private final String sqlCertRegistered;

  private final IssuerStore issuerStore;

  private final boolean publishGoodCerts;

  @SuppressWarnings("unused")
  private final int dbSchemaVersion;

  private final int maxX500nameLen;

  private final HashAlgo certhashAlgo;

  OcspStoreQueryExecutor(DataSourceWrapper datasource, boolean publishGoodCerts)
      throws DataAccessException, NoSuchAlgorithmException {
    this.datasource = ParamUtil.requireNonNull("datasource", datasource);
    this.issuerStore = initIssuerStore();
    this.publishGoodCerts = publishGoodCerts;

    this.sqlCertRegistered = datasource.buildSelectFirstSql(1, "ID FROM CERT WHERE SN=? AND IID=?");
    final String sql = "SELECT NAME,VALUE2 FROM DBSCHEMA";
    Connection conn = datasource.getConnection();
    if (conn == null) {
      throw new DataAccessException("could not get connection");
    }

    Map<String, String> variables = new HashMap<>();
    Statement stmt = null;
    ResultSet rs = null;

    try {
      stmt = datasource.createStatement(conn);
      if (stmt == null) {
        throw new DataAccessException("could not create statement");
      }

      rs = stmt.executeQuery(sql);
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
    this.certhashAlgo = HashAlgo.getNonNullInstance(str);
  } // constructor

  private IssuerStore initIssuerStore() throws DataAccessException {
    final String sql = "SELECT ID,SUBJECT,S1C,CERT FROM ISSUER";
    PreparedStatement ps = borrowPreparedStatement(sql);
    ResultSet rs = null;

    try {
      rs = ps.executeQuery();
      List<IssuerEntry> caInfos = new LinkedList<>();
      while (rs.next()) {
        int id = rs.getInt("ID");
        String subject = rs.getString("SUBJECT");
        String sha1Fp = rs.getString("S1C");
        String b64Cert = rs.getString("CERT");

        IssuerEntry caInfoEntry = new IssuerEntry(id, subject, sha1Fp, b64Cert);
        caInfos.add(caInfoEntry);
      }

      return new IssuerStore(caInfos);
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, rs);
    }
  } // method initIssuerStore

  void addCert(X509Cert issuer, CertWithDbId certificate, String certprofile)
      throws DataAccessException, OperationException {
    addCert(issuer, certificate, certprofile, null);
  }

  void addCert(X509Cert issuer, CertWithDbId certificate, String certprofile,
      CertRevocationInfo revInfo) throws DataAccessException, OperationException {
    addOrUpdateCert(issuer, certificate, certprofile, revInfo);
  }

  private void addOrUpdateCert(X509Cert issuer, CertWithDbId certificate, String certprofile,
      CertRevocationInfo revInfo) throws DataAccessException, OperationException {
    ParamUtil.requireNonNull("issuer", issuer);

    boolean revoked = (revInfo != null);
    int issuerId = getIssuerId(issuer);

    BigInteger serialNumber = certificate.getCert().getSerialNumber();
    Long certRegisteredId = getCertId(issuerId, serialNumber);

    if (!publishGoodCerts && !revoked && certRegisteredId != null) {
      return;
    }

    if (certRegisteredId != null) {
      updateRegisteredCert(certRegisteredId, revInfo);
      return;
    }

    final String sql = revoked ? SQL_ADD_REVOKED_CERT : SQL_ADD_CERT;

    long certId = certificate.getCertId();
    byte[] encodedCert = certificate.getEncodedCert();
    String certHash = certhashAlgo.base64Hash(encodedCert);

    X509Certificate cert = certificate.getCert();
    long notBeforeSeconds = cert.getNotBefore().getTime() / 1000;
    long notAfterSeconds = cert.getNotAfter().getTime() / 1000;
    String cuttedSubject = X509Util.cutText(certificate.getSubject(), maxX500nameLen);

    PreparedStatement ps = borrowPreparedStatement(sql);

    try {
      // CERT
      int idx = 1;
      ps.setLong(idx++, certId);
      ps.setLong(idx++, System.currentTimeMillis() / 1000); // currentTimeSeconds
      ps.setString(idx++, serialNumber.toString(16));
      ps.setLong(idx++, notBeforeSeconds);
      ps.setLong(idx++, notAfterSeconds);
      setBoolean(ps, idx++, revoked);
      ps.setInt(idx++, issuerId);
      ps.setString(idx++, certprofile);
      ps.setString(idx++, certHash);
      ps.setString(idx++, cuttedSubject);

      if (revoked) {
        long revTime = revInfo.getRevocationTime().getTime() / 1000;
        ps.setLong(idx++, revTime);
        if (revInfo.getInvalidityTime() != null) {
          ps.setLong(idx++, revInfo.getInvalidityTime().getTime() / 1000);
        } else {
          ps.setNull(idx++, Types.BIGINT);
        }
        int reasonCode = (revInfo.getReason() == null) ? 0 : revInfo.getReason().getCode();
        ps.setInt(idx++, reasonCode);
      }

      try {
        ps.executeUpdate();
      } catch (Throwable th) {
        // more secure
        datasource.deleteFromTable(null, "CERT", "ID", certId);

        if (th instanceof SQLException) {
          SQLException ex = (SQLException) th;
          LOG.error("datasource {} could not add certificate with id {}: {}",
              datasource.getName(), certId, th.getMessage());
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

  private void updateRegisteredCert(long registeredCertId, CertRevocationInfo revInfo)
      throws DataAccessException {
    boolean revoked = (revInfo != null);

    final String sql = "UPDATE CERT SET LUPDATE=?,REV=?,RT=?,RIT=?,RR=? WHERE ID=?";

    PreparedStatement ps = borrowPreparedStatement(sql);

    try {
      int idx = 1;
      ps.setLong(idx++, System.currentTimeMillis() / 1000); // currentTimeSeconds
      setBoolean(ps, idx++, revoked);
      if (revoked) {
        long revTime = revInfo.getRevocationTime().getTime() / 1000;
        ps.setLong(idx++, revTime);
        if (revInfo.getInvalidityTime() != null) {
          ps.setLong(idx++, revInfo.getInvalidityTime().getTime() / 1000);
        } else {
          ps.setNull(idx++, Types.INTEGER);
        }
        ps.setInt(idx++, revInfo.getReason().getCode());
      } else {
        ps.setNull(idx++, Types.INTEGER); // rev_time
        ps.setNull(idx++, Types.INTEGER); // rev_invalidity_time
        ps.setNull(idx++, Types.INTEGER); // rev_reason
      }
      ps.setLong(idx++, registeredCertId);
      ps.executeUpdate();
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  }

  void revokeCert(X509Cert caCert, CertWithDbId cert, String certprofile,
      CertRevocationInfo revInfo) throws DataAccessException, OperationException {
    addOrUpdateCert(caCert, cert, certprofile, revInfo);
  }

  void unrevokeCert(X509Cert issuer, CertWithDbId cert) throws DataAccessException {
    ParamUtil.requireNonNull("issuer", issuer);
    ParamUtil.requireNonNull("cert", cert);

    Integer issuerId = issuerStore.getIdForCert(issuer.getEncodedCert());
    if (issuerId == null) {
      return;
    }

    BigInteger serialNumber = cert.getCert().getSerialNumber();
    Long certRegisteredId = getCertId(issuerId, serialNumber);

    if (certRegisteredId == null) {
      return;
    }

    if (publishGoodCerts) {
      final String sql = "UPDATE CERT SET LUPDATE=?,REV=?,RT=?,RIT=?,RR=? WHERE ID=?";
      PreparedStatement ps = borrowPreparedStatement(sql);

      try {
        int idx = 1;
        ps.setLong(idx++, System.currentTimeMillis() / 1000);
        setBoolean(ps, idx++, false);
        ps.setNull(idx++, Types.INTEGER);
        ps.setNull(idx++, Types.INTEGER);
        ps.setNull(idx++, Types.INTEGER);
        ps.setLong(idx++, certRegisteredId);
        ps.executeUpdate();
      } catch (SQLException ex) {
        throw datasource.translate(sql, ex);
      } finally {
        datasource.releaseResources(ps, null);
      }
    } else {
      final String sql = "DELETE FROM CERT WHERE IID=? AND SN=?";
      PreparedStatement ps = borrowPreparedStatement(sql);

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

  void removeCert(X509Cert issuer, CertWithDbId cert) throws DataAccessException {
    ParamUtil.requireNonNull("issuer", issuer);
    ParamUtil.requireNonNull("cert", cert);

    Integer issuerId = issuerStore.getIdForCert(issuer.getEncodedCert());
    if (issuerId == null) {
      return;
    }

    final String sql = "DELETE FROM CERT WHERE IID=? AND SN=?";
    PreparedStatement ps = borrowPreparedStatement(sql);

    try {
      ps.setInt(1, issuerId);
      ps.setString(2, cert.getCert().getSerialNumber().toString(16));
      ps.executeUpdate();
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method removeCert

  void revokeCa(X509Cert caCert, CertRevocationInfo revInfo) throws DataAccessException {
    ParamUtil.requireNonNull("caCert", caCert);
    ParamUtil.requireNonNull("revInfo", revInfo);

    int issuerId = getIssuerId(caCert);
    final String sql = "UPDATE ISSUER SET REV_INFO=? WHERE ID=?";
    PreparedStatement ps = borrowPreparedStatement(sql);

    try {
      ps.setString(1, revInfo.getEncoded());
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
    PreparedStatement ps = borrowPreparedStatement(sql);

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

  private int getIssuerId(X509Cert issuerCert) throws DataAccessException {
    ParamUtil.requireNonNull("issuerCert", issuerCert);
    Integer id = issuerStore.getIdForCert(issuerCert.getEncodedCert());
    if (id == null) {
      throw new IllegalStateException("could not find issuer, "
          + "please start XiPKI in master mode first the restart this XiPKI system");
    }
    return id.intValue();
  }

  void addIssuer(X509Cert issuerCert) throws DataAccessException {
    if (issuerStore.getIdForCert(issuerCert.getEncodedCert()) != null) {
      return;
    }

    String sha1FpCert = HashAlgo.SHA1.base64Hash(issuerCert.getEncodedCert());
    long maxId = datasource.getMax(null, "ISSUER", "ID");
    int id = (int) maxId + 1;

    byte[] encodedCert = issuerCert.getEncodedCert();
    long notBeforeSeconds = issuerCert.getCert().getNotBefore().getTime() / 1000;
    long notAfterSeconds = issuerCert.getCert().getNotAfter().getTime() / 1000;

    final String sql =
        "INSERT INTO ISSUER (ID,SUBJECT,NBEFORE,NAFTER,S1C,CERT) VALUES (?,?,?,?,?,?)";

    PreparedStatement ps = borrowPreparedStatement(sql);

    try {
      String b64Cert = Base64.encodeToString(encodedCert);
      String subject = issuerCert.getSubject();
      int idx = 1;
      ps.setInt(idx++, id);
      ps.setString(idx++, subject);
      ps.setLong(idx++, notBeforeSeconds);
      ps.setLong(idx++, notAfterSeconds);
      ps.setString(idx++, sha1FpCert);
      ps.setString(idx++, b64Cert);

      ps.execute();

      IssuerEntry newInfo = new IssuerEntry(id, subject, sha1FpCert, b64Cert);
      issuerStore.addIdentityEntry(newInfo);
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method addIssuer

  /**
   * TODO.
   * @param sqlQuery the SQL query
   * @return the next idle preparedStatement, {@code null} will be returned if no PreparedStament
   *      can be created within 5 seconds.
   */
  private PreparedStatement borrowPreparedStatement(String sqlQuery) throws DataAccessException {
    PreparedStatement ps = null;
    Connection col = datasource.getConnection();
    if (col != null) {
      ps = datasource.prepareStatement(col, sqlQuery);
    }
    if (ps == null) {
      throw new DataAccessException("could not create prepared statement for " + sqlQuery);
    }
    return ps;
  }

  /**
   * Returns the database Id for the given issuer and serialNumber.
   * @return the database table id if registered, <code>null</code> otherwise.
   */
  private Long getCertId(int issuerId, BigInteger serialNumber) throws DataAccessException {
    final String sql = sqlCertRegistered;
    ResultSet rs = null;
    PreparedStatement ps = borrowPreparedStatement(sql);

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
      PreparedStatement ps = borrowPreparedStatement(sql);

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
