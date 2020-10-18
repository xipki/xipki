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

import static org.xipki.ca.api.OperationException.ErrorCode.DATABASE_FAILURE;
import static org.xipki.ca.api.OperationException.ErrorCode.SYSTEM_FAILURE;

import java.security.cert.CertificateException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Date;
import java.util.List;

import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;

/**
 * Base class to exec the database queries to manage CA system.
 *
 * @author Lijun Liao
 */
public class CertStoreBase extends QueryExecutor {

  protected static final SqlColumn3 COL3_ID = col3Long("ID");

  protected static final SqlColumn3 COL3_PID = col3Int("PID");

  protected static final SqlColumn3 COL3_RID = col3Int("RID");

  protected static final SqlColumn3 COL3_REV = col3Bool("REV");

  protected static final SqlColumn3 COL3_RR  = col3Int("RR");

  protected static final SqlColumn3 COL3_RT  = col3Long("RT");

  protected static final SqlColumn3 COL3_RIT = col3Long("RIT");

  protected static final SqlColumn3 COL3_REQ_ID = col3Long("REQ_ID");

  protected static final SqlColumn3 COL3_NBEFORE = col3Long("NBEFORE");

  protected static final SqlColumn3 COL3_NAFTER = col3Long("NAFTER");

  protected static final SqlColumn3 COL3_UID = col3Int("UID");

  protected static final SqlColumn3 COL3_CID = col3Int("CID");

  protected static final SqlColumn3 COL3_THISUPDATE = col3Long("THISUPDATE");

  protected static final SqlColumn3 COL3_NEXTUPDATE = col3Long("NEXTUPDATE");

  protected static final SqlColumn3 COL3_CRL_NO = col3Long("CRL_NO");

  protected static final SqlColumn3 COL3_PERMISSION = col3Int("PERMISSION");

  protected static final String SQL_ADD_CERT =
      "INSERT INTO CERT (ID,LUPDATE,SN,SUBJECT,FP_S,FP_RS,NBEFORE,NAFTER,REV,PID,"
      + "CA_ID,RID,UID,EE,RTYPE,TID,SHA1,REQ_SUBJECT,CRL_SCOPE,CERT)"
      + " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

  protected static final String SQL_ADD_CERT_V4 =
      SQL_ADD_CERT.replace("CERT)", "CERT,FP_K)").replace(",?)", ",?,0)");

  protected static final String SQL_REVOKE_CERT =
      "UPDATE CERT SET LUPDATE=?,REV=?,RT=?,RIT=?,RR=? WHERE ID=?";

  protected static final String SQL_REVOKE_SUSPENDED_CERT =
      "UPDATE CERT SET LUPDATE=?,RR=? WHERE ID=?";

  protected static final String SQL_INSERT_PUBLISHQUEUE =
      "INSERT INTO PUBLISHQUEUE (PID,CA_ID,CID) VALUES (?,?,?)";

  protected static final String SQL_REMOVE_PUBLISHQUEUE =
      "DELETE FROM PUBLISHQUEUE WHERE PID=? AND CID=?";

  protected static final String SQL_MAX_CRLNO = "SELECT MAX(CRL_NO) FROM CRL WHERE CA_ID=?";

  protected static final String SQL_MAX_FULL_CRLNO =
      "SELECT MAX(CRL_NO) FROM CRL WHERE CA_ID=? AND DELTACRL = 0";

  protected static final String SQL_MAX_THISUPDAATE_CRL =
      "SELECT MAX(THISUPDATE) FROM CRL WHERE CA_ID=? AND DELTACRL=?";

  protected static final String SQL_ADD_CRL =
      "INSERT INTO CRL (ID,CA_ID,CRL_NO,THISUPDATE,NEXTUPDATE,DELTACRL,BASECRL_NO,CRL_SCOPE,CRL)"
      + " VALUES (?,?,?,?,?,?,?,?,?)";

  protected static final String SQL_REMOVE_CERT = "DELETE FROM CERT WHERE CA_ID=? AND SN=?";

  protected static final String SQL_DELETE_UNREFERENCED_REQUEST =
      "DELETE FROM REQUEST WHERE ID NOT IN (SELECT req.RID FROM REQCERT req)";

  protected static final String SQL_ADD_REQUEST =
      "INSERT INTO REQUEST (ID,LUPDATE,DATA) VALUES(?,?,?)";

  protected static final String SQL_ADD_REQCERT = "INSERT INTO REQCERT (ID,RID,CID) VALUES(?,?,?)";

  protected final int dbSchemaVersion;

  protected final int maxX500nameLen;

  protected CertStoreBase(DataSourceWrapper datasource) throws DataAccessException {
    super(datasource);

    DbSchemaInfo dbSchemaInfo = new DbSchemaInfo(datasource);
    this.dbSchemaVersion = Integer.parseInt(dbSchemaInfo.variableValue("VERSION"));
    this.maxX500nameLen = Integer.parseInt(dbSchemaInfo.variableValue("X500NAME_MAXLEN"));
  } // constructor

  protected static SqlColumn3[] col3s(SqlColumn3... cols) {
    return cols;
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
      return datasource.getMax(null, "CRL", "ID");
    } catch (DataAccessException ex) {
      throw new OperationException(DATABASE_FAILURE, ex.getMessage());
    }
  }

  protected int execUpdateStmt0(String sql)
      throws OperationException {
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

  protected List<ResultRow> execQueryStmt0(String sql, SqlColumn3[] resultColumns)
      throws OperationException {
    try {
      return execQueryStmt(sql, resultColumns);
    } catch (DataAccessException ex) {
      throw new OperationException(ErrorCode.DATABASE_FAILURE, ex);
    }
  }

  protected ResultRow execQuery1PrepStmt0(
      String sql, SqlColumn3[] resultColumns, SqlColumn2... params)
      throws OperationException {
    try {
      return execQuery1PrepStmt(sql, resultColumns, params);
    } catch (DataAccessException ex) {
      throw new OperationException(ErrorCode.DATABASE_FAILURE, ex);
    }
  }

  protected List<ResultRow> execQueryPrepStmt0(
      String sql, SqlColumn3[] resultColumns, SqlColumn2... params)
      throws OperationException {
    try {
      return execQueryPrepStmt(sql, resultColumns, params);
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
