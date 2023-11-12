// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.db;

import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.server.CaConfStore;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.Hex;
import org.xipki.util.SqlUtil;
import org.xipki.util.exception.ErrorCode;
import org.xipki.util.exception.OperationException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Base class to exec the database queries to manage CA system.
 *
 * @author Lijun Liao (xipki)
 */
public class CertStoreBase extends QueryExecutor {

  protected final String SQL_ADD_CERT;

  protected static final String SQL_REVOKE_CERT = "UPDATE CERT SET LUPDATE=?,REV=?,RT=?,RIT=?,RR=? WHERE ID=?";

  protected static final String SQL_REVOKE_SUSPENDED_CERT = "UPDATE CERT SET LUPDATE=?,RR=? WHERE ID=?";

  protected static final String SQL_MAX_CRLNO = "SELECT MAX(CRL_NO) FROM CRL WHERE CA_ID=?";

  protected static final String SQL_MAX_FULL_CRLNO = "SELECT MAX(CRL_NO) FROM CRL WHERE CA_ID=? AND DELTACRL = 0";

  protected static final String SQL_MAX_THISUPDAATE_CRL =
      "SELECT MAX(THISUPDATE) FROM CRL WHERE CA_ID=? AND DELTACRL=?";

  protected final String SQL_ADD_CRL;

  protected static final String SQL_REMOVE_CERT_FOR_ID = "DELETE FROM CERT WHERE ID=?";

  protected final int dbSchemaVersion;

  protected final int maxX500nameLen;

  protected final String keypairEncAlg = "AES/GCM/NoPadding";

  protected final int keypairEncAlgId = 1;

  protected String keypairEncProvider;

  protected String keypairEncKeyId;

  protected SecretKey keypairEncKey;

  protected final CaConfStore  caConfStore;

  protected CertStoreBase(DataSourceWrapper datasource, CaConfStore caConfStore,
                          PasswordResolver passwordResolver)
      throws DataAccessException, CaMgmtException {
    super(datasource);
    this.caConfStore = Args.notNull(caConfStore, "caConfStore");

    Map<String, String> caConfDbSchemaInfo = caConfStore.getDbSchemas();
    String vendor = caConfStore.getDbSchemas().get("VENDOR");
    if (vendor != null && !vendor.equalsIgnoreCase("XIPKI")) {
      throw new CaMgmtException("unsupported vendor " + vendor);
    }

    this.dbSchemaVersion = Integer.parseInt(caConfDbSchemaInfo.get("VERSION"));
    if (this.dbSchemaVersion < 9) {
      throw new CaMgmtException("dbSchemaVersion < 9 unsupported: " + dbSchemaVersion);
    }

    String str = caConfDbSchemaInfo.get("X500NAME_MAXLEN");
    this.maxX500nameLen = str == null ? 350 : Integer.parseInt(str);

    String addCertSql = "ID,LUPDATE,SN,SUBJECT,FP_S,FP_RS,FP_SAN,NBEFORE,NAFTER,REV,PID,CA_ID,RID,EE,TID,SHA1," +
                    "REQ_SUBJECT,CRL_SCOPE,CERT,PRIVATE_KEY";
    this.SQL_ADD_CERT = SqlUtil.buildInsertSql("CERT", addCertSql);

    this.SQL_ADD_CRL = SqlUtil.buildInsertSql("CRL", "ID,CA_ID,CRL_NO,THISUPDATE,NEXTUPDATE," +
        "DELTACRL,BASECRL_NO,CRL_SCOPE,SHA1,CRL");

    updateDbInfo(passwordResolver);
  } // constructor

  public void updateDbInfo(PasswordResolver passwordResolver) throws DataAccessException, CaMgmtException {
    // Save keypair control
    String str = caConfStore.getDbSchemas().get("KEYPAIR_ENC_KEY");
    if (str == null) {
      return;
    }

    try {
      char[] keyChars = passwordResolver.resolvePassword(str);
      byte[] encodedEncKey = Hex.decode(keyChars);
      int n = encodedEncKey.length;
      if (n != 16 && n != 24 && n != 32) {
        throw new CaMgmtException("error resolving KEYPAIR_ENC_KEY");
      }
      this.keypairEncKey = new SecretKeySpec(encodedEncKey, "AES");
      this.keypairEncKeyId = Hex.encode(Arrays.copyOf(HashAlgo.SHA1.hash(encodedEncKey), 8));
    } catch (PasswordResolverException ex) {
      throw new CaMgmtException("error resolving KEYPAIR_ENC_KEY", ex);
    }

    try {
      Cipher.getInstance(keypairEncAlg, "SunJCE");
      keypairEncProvider = "SunJCE";
    } catch (NoSuchProviderException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
      try {
        Cipher cipher = Cipher.getInstance(keypairEncAlg);
        keypairEncProvider = cipher.getProvider().getName();
      } catch (NoSuchAlgorithmException | NoSuchPaddingException ex2) {
        throw new IllegalStateException("Unsupported cipher " + keypairEncAlg);
      }
    }
  }

  protected static CertRevocationInfo buildCertRevInfo(ResultRow rs) {
    boolean revoked = rs.getBoolean("REV");
    if (!revoked) {
      return null;
    }

    long revTime    = rs.getLong("RT");
    long revInvTime = rs.getLong("RIT");

    Instant invalidityTime = (revInvTime == 0) ? null : Instant.ofEpochSecond(revInvTime);
    return new CertRevocationInfo(rs.getInt("RR"), Instant.ofEpochSecond(revTime), invalidityTime);
  }

  protected long getMax(String table, String column) throws OperationException {
    try {
      return datasource.getMax(null, table, column);
    } catch (DataAccessException ex) {
      throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
    }
  }

  protected int execUpdateStmt0(String sql) throws OperationException {
    try {
      return execUpdateStmt(sql);
    } catch (DataAccessException ex) {
      throw new OperationException(ErrorCode.DATABASE_FAILURE, ex);
    }
  }

  protected int execUpdatePrepStmt0(String sql, SqlColumn2... params) throws OperationException {
    try {
      return execUpdatePrepStmt(sql, params);
    } catch (DataAccessException ex) {
      throw new OperationException(ErrorCode.DATABASE_FAILURE, ex);
    }
  }

  protected ResultRow execQuery1PrepStmt0(String sql, SqlColumn2... params) throws OperationException {
    try {
      return execQuery1PrepStmt(sql, params);
    } catch (DataAccessException ex) {
      throw new OperationException(ErrorCode.DATABASE_FAILURE, ex);
    }
  }

  protected List<ResultRow> execQueryPrepStmt0(String sql, SqlColumn2... params) throws OperationException {
    try {
      return execQueryPrepStmt(sql, params);
    } catch (DataAccessException ex) {
      throw new OperationException(ErrorCode.DATABASE_FAILURE, ex);
    }
  }

  protected PreparedStatement buildPrepStmt0(String sql, SqlColumn2... columns) throws OperationException {
    try {
      return buildPrepStmt(sql, columns);
    } catch (DataAccessException ex) {
      throw new OperationException(ErrorCode.DATABASE_FAILURE, ex);
    }
  }

  protected long execQueryLongPrepStmt(String sql, SqlColumn2... params) throws OperationException {
    PreparedStatement ps = buildPrepStmt0(sql, params);
    ResultSet rs = null;
    try {
      rs = ps.executeQuery();
      return rs.next() ? rs.getLong(1) : 0;
    } catch (SQLException ex) {
      throw new OperationException(ErrorCode.DATABASE_FAILURE, datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, rs);
    }
  }

  protected PreparedStatement prepareStatement(String sqlQuery) throws OperationException {
    try {
      return datasource.prepareStatement(sqlQuery);
    } catch (DataAccessException ex) {
      throw new OperationException(ErrorCode.DATABASE_FAILURE, ex);
    }
  } // method borrowPrepStatement

  protected static String buildArraySql(DataSourceWrapper datasource, String prefix, int num) {
    String sql = prefix + " IN (?" + ",?".repeat(Math.max(0, num - 1)) + ")";
    return datasource.buildSelectFirstSql(num, sql);
  }

  protected static X509Cert parseCert(byte[] encodedCert) throws OperationException {
    try {
      return X509Util.parseCert(encodedCert);
    } catch (CertificateException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex);
    }
  }

}
