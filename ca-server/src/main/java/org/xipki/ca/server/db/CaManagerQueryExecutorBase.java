// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.db;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.SignerConf;
import org.xipki.util.StringUtil;

import java.sql.*;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.xipki.util.StringUtil.concat;

/**
 * Base class to execute the database queries to manage CA system.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
class CaManagerQueryExecutorBase extends QueryExecutor {

  protected enum Table {
    // SMALLINT or INT
    REQUESTOR,
    PUBLISHER,
    PROFILE,
    CA
  }

  private static final Logger LOG = LoggerFactory.getLogger(QueryExecutor.class);

  protected int dbSchemaVersion;

  CaManagerQueryExecutorBase(DataSourceWrapper datasource) throws CaMgmtException {
    super(datasource);
    try {
      DbSchemaInfo dbSchemaInfo = new DbSchemaInfo(datasource);
      this.dbSchemaVersion = Integer.parseInt(dbSchemaInfo.variableValue("VERSION"));
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }

    if (dbSchemaVersion < 7) {
      throw new CaMgmtException("DB version < 7 is not supported: " + dbSchemaVersion);
    }
  }

  public int getDbSchemaVersion() {
    return dbSchemaVersion;
  }

  protected String buildSelectFirstSql(String coreSql) {
    return datasource.buildSelectFirstSql(1, coreSql);
  }

  private Statement createStatement() throws CaMgmtException {
    try {
      return datasource.createStatement();
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }
  } // method createStatement

  private PreparedStatement prepareStatement(String sql) throws CaMgmtException {
    try {
      return datasource.prepareStatement(sql);
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }
  } // method prepareStatement

  public List<String> namesFromTable(String table) throws CaMgmtException {
    final String sql = concat("SELECT NAME FROM ", table);
    List<ResultRow> rows = execQueryStmt0(sql);

    List<String> names = new LinkedList<>();
    for (ResultRow rs : rows) {
      String name = rs.getString("NAME");
      if (StringUtil.isNotBlank(name)) {
        names.add(name);
      }
    }

    return names;
  } // method namesFromTable

  public boolean deleteRowWithName(String name, String table) throws CaMgmtException {
    final String sql = concat("DELETE FROM ", table, " WHERE NAME=?");
    int num = execUpdatePrepStmt0(sql, col2Str(name));
    return num > 0;
  } // method deleteRowWithName

  protected static String str(String sa, String sb) {
    return (sa != null) ? getRealString(sa) : sb;
  }

  protected int execUpdateStmt0(String sql) throws CaMgmtException {
    try {
      return execUpdateStmt(sql);
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }
  }

  protected int execUpdatePrepStmt0(String sql, SqlColumn2... params) throws CaMgmtException {
    try {
      return execUpdatePrepStmt(sql, params);
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }
  }

  protected List<ResultRow> execQueryStmt0(String sql) throws CaMgmtException {
    try {
      return execQueryStmt(sql);
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }
  }

  protected ResultRow execQuery1PrepStmt0(String sql, SqlColumn2... params) throws CaMgmtException {
    try {
      return execQuery1PrepStmt(sql, params);
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }
  }

  protected List<ResultRow> execQueryPrepStmt0(String sql, SqlColumn2... params) throws CaMgmtException {
    try {
      return execQueryPrepStmt(sql, params);
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }
  }

  protected void changeIfNotNull(String tableName, SqlColumn whereColumn, SqlColumn... columns)
      throws CaMgmtException {
    StringBuilder buf = new StringBuilder("UPDATE ");
    buf.append(tableName).append(" SET ");
    boolean noAction = true;
    for (SqlColumn col : columns) {
      if (col.value() != null) {
        noAction = false;
        buf.append(col.name()).append("=?,");
      }
    }

    if (noAction) {
      throw new IllegalArgumentException("nothing to change");
    }

    buf.deleteCharAt(buf.length() - 1); // delete the last ','
    buf.append(" WHERE ").append(whereColumn.name()).append("=?");

    final String sql = buf.toString();

    PreparedStatement ps = null;
    try {
      ps = prepareStatement(sql);

      Map<String, String> changedColumns = new HashMap<>();

      int index = 1;
      for (SqlColumn col : columns) {
        if (col.value() != null) {
          setColumn(changedColumns, ps, index, col);
          index++;
        }
      }
      setColumn(null, ps, index, whereColumn);

      if (ps.executeUpdate() == 0) {
        throw new CaMgmtException("could not update table " + tableName);
      }

      LOG.info("updated table {} WHERE {}={}: {}", tableName, whereColumn.name(), whereColumn.value(), changedColumns);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method changeIfNotNull

  private void setColumn(Map<String, String> changedColumns, PreparedStatement ps, int index, SqlColumn column)
      throws SQLException {
    String name = column.name();
    ColumnType type = column.type();
    Object value = column.value();

    boolean sensitive = column.sensitive();

    String valText;
    if (type == ColumnType.STRING) {
      String val = getRealString((String) value);
      ps.setString(index, val);

      valText = val;
      if (val != null && column.isSignerConf()) {
        valText = SignerConf.eraseSensitiveData(valText);

        if (valText.length() > 100) {
          valText = StringUtil.concat(valText.substring(0, 97), "...");
        }
      }
    } else if (type == ColumnType.INT) {
      if (value == null) {
        ps.setNull(index, Types.INTEGER);
        valText = "null";
      } else {
        int val = ((Integer) value);
        ps.setInt(index, val);
        valText = Integer.toString(val);
      }
    } else if (type == ColumnType.LONG) {
      if (value == null) {
        ps.setNull(index, Types.BIGINT);
        valText = "null";
      } else {
        long val = ((Long) value);
        ps.setLong(index, val);
        valText = Long.toString(val);
      }
    } else if (type == ColumnType.BOOL) {
      if (value == null) {
        ps.setNull(index, Types.INTEGER);
        valText = "null";
      } else {
        int val = (Boolean) value ? 1 : 0;
        ps.setInt(index, val);
        valText = Integer.toString(val);
      }
    } else if (type == ColumnType.TIMESTAMP) {
      if (value == null) {
        ps.setNull(index, Types.TIMESTAMP);
        valText = "null";
      } else {
        Timestamp val = (Timestamp) value;
        ps.setTimestamp(index, val);
        valText = val.toString();
      }
    } else {
      throw new IllegalStateException("should not reach here, unknown type " + column.type());
    }

    if (changedColumns != null) {
      changedColumns.put(name, sensitive ? "*****" : valText);
    }
  } // method setColumn

  private static String getRealString(String str) {
    return CaManager.NULL.equalsIgnoreCase(str) ? null : str;
  }

  protected int getNonNullIdForName(String sql, String name) throws CaMgmtException {
    Integer id = getIdForName(sql, name);
    if (id != null) {
      return id;
    }

    throw new CaMgmtException(concat("Found no entry named ",name));
  } // method getNonNullIdForName

  protected Integer getIdForName(String sql, String name) throws CaMgmtException {
    PreparedStatement ps = null;
    ResultSet rs = null;
    try {
      ps = prepareStatement(sql);
      ps.setString(1, name);
      rs = ps.executeQuery();
      if (!rs.next()) {
        return null;
      }

      return rs.getInt("ID");
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, rs);
    }
  } // method getIdForName

  protected Map<Integer, String> getIdNameMap(String tableName) throws CaMgmtException {
    final String sql = concat("SELECT ID,NAME FROM ", tableName);
    Statement ps = null;
    ResultSet rs = null;

    Map<Integer, String> ret = new HashMap<>();
    try {
      ps = createStatement();
      rs = ps.executeQuery(sql);
      while (rs.next()) {
        ret.put(rs.getInt("ID"), rs.getString("NAME"));
      }
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, rs);
    }

    return ret;
  } // method getIdNameMap

}
