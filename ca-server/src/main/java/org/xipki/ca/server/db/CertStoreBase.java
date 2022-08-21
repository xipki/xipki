/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.server.db;

import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.HashAlgo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.Hex;
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
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.xipki.util.SqlUtil.buildInsertSql;
import static org.xipki.util.exception.ErrorCode.DATABASE_FAILURE;
import static org.xipki.util.exception.ErrorCode.SYSTEM_FAILURE;

/**
 * Base class to exec the database queries to manage CA system.
 *
 * @author Lijun Liao
 */
public class CertStoreBase extends QueryExecutor {

  protected final String SQL_ADD_CERT;

  protected static final String SQL_REVOKE_CERT = "UPDATE CERT SET LUPDATE=?,REV=?,RT=?,RIT=?,RR=? WHERE ID=?";

  protected static final String SQL_REVOKE_SUSPENDED_CERT = "UPDATE CERT SET LUPDATE=?,RR=? WHERE ID=?";

  protected static final String SQL_INSERT_PUBLISHQUEUE = buildInsertSql("PUBLISHQUEUE", "PID,CA_ID,CID");

  protected static final String SQL_REMOVE_PUBLISHQUEUE = "DELETE FROM PUBLISHQUEUE WHERE PID=? AND CID=?";

  protected static final String SQL_MAX_CRLNO = "SELECT MAX(CRL_NO) FROM CRL WHERE CA_ID=?";

  protected static final String SQL_MAX_FULL_CRLNO = "SELECT MAX(CRL_NO) FROM CRL WHERE CA_ID=? AND DELTACRL = 0";

  protected static final String SQL_MAX_THISUPDAATE_CRL =
      "SELECT MAX(THISUPDATE) FROM CRL WHERE CA_ID=? AND DELTACRL=?";

  protected final String SQL_ADD_CRL;

  protected static final String SQL_REMOVE_CERT_FOR_ID = "DELETE FROM CERT WHERE ID=?";

  protected static final String SQL_DELETE_UNREFERENCED_REQUEST =
      "DELETE FROM REQUEST WHERE ID NOT IN (SELECT req.RID FROM REQCERT req)";

  protected static final String SQL_ADD_REQUEST = buildInsertSql("REQUEST", "ID,LUPDATE,DATA");

  protected static final String SQL_ADD_REQCERT = buildInsertSql("REQCERT", "ID,RID,CID");

  protected final int dbSchemaVersion;

  protected final int maxX500nameLen;

  protected final String keypairEncAlg = "AES/GCM/NoPadding";

  protected final int keypairEncAlgId = 1;

  protected String keypairEncProvider;

  protected String keypairEncKeyId;

  protected SecretKey keypairEncKey;

  protected CertStoreBase(DataSourceWrapper datasource, PasswordResolver passwordResolver)
      throws DataAccessException, CaMgmtException {
    super(datasource);

    DbSchemaInfo dbSchemaInfo = new DbSchemaInfo(datasource);
    String vendor = dbSchemaInfo.variableValue("VENDOR");
    if (vendor != null && !vendor.equalsIgnoreCase("XIPKI")) {
      throw new CaMgmtException("unsupported vendor " + vendor);
    }

    this.dbSchemaVersion = Integer.parseInt(dbSchemaInfo.variableValue("VERSION"));
    if (this.dbSchemaVersion < 7) {
      throw new CaMgmtException("dbSchemaVersion < 7 unsupported: " + dbSchemaVersion);
    }
    this.maxX500nameLen = Integer.parseInt(dbSchemaInfo.variableValue("X500NAME_MAXLEN"));

    this.SQL_ADD_CERT = buildInsertSql("CERT", "ID,LUPDATE,SN,SUBJECT,FP_S,FP_RS," +
        "NBEFORE,NAFTER,REV,PID,CA_ID,RID,EE,TID,SHA1,REQ_SUBJECT,CRL_SCOPE,CERT, PRIVATE_KEY");

    this.SQL_ADD_CRL = buildInsertSql("CRL", "ID,CA_ID,CRL_NO,THISUPDATE,NEXTUPDATE," +
        "DELTACRL,BASECRL_NO,CRL_SCOPE,SHA1,CRL");

    // INSERT INTO CRL
    updateDbInfo(passwordResolver);
  } // constructor

  public void updateDbInfo(PasswordResolver passwordResolver)
      throws DataAccessException, CaMgmtException {
    DbSchemaInfo dbSchemaInfo = new DbSchemaInfo(datasource);

    // Save keypair control
    String str = dbSchemaInfo.variableValue("KEYPAIR_ENC_KEY");
    if (str != null) {
      try {
        char[] keyChars = passwordResolver.resolvePassword(str);
        byte[] encodedEncKey = Hex.decode(keyChars);
        int n = encodedEncKey.length;
        if (n != 16 && n != 24 && n != 32) {
          throw new CaMgmtException("error resolving KEYPAIR_ENC_KEY");
        }
        this.keypairEncKey = new SecretKeySpec(encodedEncKey, "AES");
        byte[] keyIdBytes = Arrays.copyOf(HashAlgo.SHA1.hash(encodedEncKey), 8);
        this.keypairEncKeyId = Hex.encode(keyIdBytes);
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
  }

  protected static CertRevocationInfo buildCertRevInfo(ResultRow rs) {
    boolean revoked = rs.getBoolean("REV");
    if (!revoked) {
      return null;
    }

    long revTime    = rs.getLong("RT");
    long revInvTime = rs.getLong("RIT");

    Date invalidityTime = (revInvTime == 0) ? null : new Date(revInvTime * 1000);
    return new CertRevocationInfo(rs.getInt("RR"), new Date(revTime * 1000), invalidityTime);
  }

  protected long getMax(String table, String column) throws OperationException {
    try {
      return datasource.getMax(null, table, column);
    } catch (DataAccessException ex) {
      throw new OperationException(DATABASE_FAILURE, ex.getMessage());
    }
  }

  protected int execUpdateStmt0(String sql) throws OperationException {
    try {
      return execUpdateStmt(sql);
    } catch (DataAccessException ex) {
      throw new OperationException(ErrorCode.DATABASE_FAILURE, ex);
    }
  }

  protected int execUpdatePrepStmt0(String sql, SqlColumn2... params)
      throws OperationException {
    try {
      return execUpdatePrepStmt(sql, params);
    } catch (DataAccessException ex) {
      throw new OperationException(ErrorCode.DATABASE_FAILURE, ex);
    }
  }

  protected ResultRow execQuery1PrepStmt0(String sql, SqlColumn2... params)
      throws OperationException {
    try {
      return execQuery1PrepStmt(sql, params);
    } catch (DataAccessException ex) {
      throw new OperationException(ErrorCode.DATABASE_FAILURE, ex);
    }
  }

  protected List<ResultRow> execQueryPrepStmt0(String sql, SqlColumn2... params)
      throws OperationException {
    try {
      return execQueryPrepStmt(sql, params);
    } catch (DataAccessException ex) {
      throw new OperationException(ErrorCode.DATABASE_FAILURE, ex);
    }
  }

  protected PreparedStatement buildPrepStmt0(String sql, SqlColumn2... columns)
      throws OperationException {
    try {
      return buildPrepStmt(sql, columns);
    } catch (DataAccessException ex) {
      throw new OperationException(ErrorCode.DATABASE_FAILURE, ex);
    }
  }

  protected long execQueryLongPrepStmt(String sql, SqlColumn2... params)
      throws OperationException {
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

  protected PreparedStatement prepareStatement(String sqlQuery)
      throws OperationException {
    try {
      return datasource.prepareStatement(sqlQuery);
    } catch (DataAccessException ex) {
      throw new OperationException(DATABASE_FAILURE, ex);
    }
  } // method borrowPrepStatement

  protected static String buildArraySql(DataSourceWrapper datasource, String prefix, int num) {
    StringBuilder sb = new StringBuilder(prefix.length() + num * 2);
    sb.append(prefix).append(" IN (?");
    for (int i = 1; i < num; i++) {
      sb.append(",?");
    }
    sb.append(")");
    return datasource.buildSelectFirstSql(num, sb.toString());
  }

  protected static X509Cert parseCert(byte[] encodedCert) throws OperationException {
    try {
      return X509Util.parseCert(encodedCert);
    } catch (CertificateException ex) {
      throw new OperationException(SYSTEM_FAILURE, ex);
    }
  }

}
