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

import static org.xipki.util.Args.notNull;

import java.math.BigDecimal;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Time;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;

/**
 * Base class to execute the database queries to manage CA system.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
class QueryExecutor {

  protected static enum ColumnType {
    INT,
    LONG,
    STRING,
    BOOL,
    TIMESTAMP,
  } // class ColumnType

  static class ResultRow {

    private final Map<String, Object> columns = new HashMap<>();

    public ResultRow(ResultSet rs) throws SQLException {
      ResultSetMetaData metaData = rs.getMetaData();
      int count = metaData.getColumnCount();

      for (int index = 1; index <= count; index++) {
        String label = metaData.getColumnLabel(index);
        int itype = metaData.getColumnType(index);

        Object value;
        switch (itype) {
          case Types.BOOLEAN:
          case Types.BIT:
            value = rs.getBoolean(index);
            break;
          case Types.TINYINT:
          case Types.SMALLINT:
          case Types.INTEGER:
            value = rs.getInt(index);
            break;
          case Types.BIGINT:
            value = rs.getLong(index);
            break;
          case Types.CHAR:
          case Types.VARCHAR:
          case Types.LONGVARCHAR:
          case Types.NCHAR:
          case Types.NVARCHAR:
          case Types.LONGNVARCHAR:
            value = rs.getString(index);
            break;
          case Types.CLOB:
          case Types.NCLOB:
            Clob clob = rs.getClob(index);
            long len = clob.length();
            value = clob.getSubString(1, (int) len);
            break;
          case Types.TIMESTAMP:
          case Types.TIMESTAMP_WITH_TIMEZONE:
            value = rs.getTimestamp(index);
            break;
          case Types.DATE:
            value = rs.getDate(index);
            break;
          case Types.TIME:
            value = rs.getTime(index);
            break;
          case Types.REAL:
            value = rs.getFloat(index);
            break;
          case Types.FLOAT:
          case Types.DOUBLE:
            value = rs.getDouble(index);
            break;
          case Types.NUMERIC:
          case Types.DECIMAL:
            value = rs.getBigDecimal(index);
            break;
          case Types.BINARY:
          case Types.VARBINARY:
          case Types.LONGVARBINARY:
            value = rs.getBytes(index);
            break;
          case Types.BLOB:
            Blob blob = rs.getBlob(index);
            value = blob.getBytes(1, (int) blob.length());
            break;
          default:
            throw new SQLException("unknown data type " + itype);
        }

        columns.put(label.toUpperCase(), value);
      }
    }

    public int getInt(String label) throws SQLException {
      Object obj = columns.get(label.toUpperCase());
      if (obj == null) {
        return 0;
      }

      if (obj instanceof Integer) {
        return (int) obj;
      } else if (obj instanceof Long) {
        return (int) ((long) obj);
      } else if (obj instanceof Boolean) {
        return ((boolean) obj) ? 1 : 0;
      } else {
        throw new IllegalArgumentException(
            "cannot convert " + obj.getClass().getName() + " to int");
      }
    }

    public boolean getBoolean(String label) throws SQLException {
      Object obj = columns.get(label.toUpperCase());
      if (obj == null) {
        return false;
      }

      if (obj instanceof Boolean) {
        return (boolean) obj;
      } else if (obj instanceof Integer) {
        return ((int) obj) != 0;
      } else if (obj instanceof Long) {
        return ((long) obj) != 0;
      } else {
        throw new IllegalArgumentException(
            "cannot convert " + obj.getClass().getName() + " to boolean");
      }
    }

    public long getLong(String label) throws SQLException {
      Object obj = columns.get(label.toUpperCase());
      if (obj == null) {
        return 0;
      }

      if (obj instanceof Long) {
        return (long) obj;
      } else if (obj instanceof Integer) {
        return (long) ((int) obj);
      } else if (obj instanceof Boolean) {
        return ((boolean) obj) ? 1 : 0;
      } else {
        throw new IllegalArgumentException(
            "cannot convert " + obj.getClass().getName() + " to long");
      }
    }

    public String getString(String label) {
      Object obj = columns.get(label.toUpperCase());
      if (obj == null) {
        return null;
      }

      if (obj instanceof Boolean) {
        return ((boolean) obj) ? "TRUE" : "FALSE";
      } else if (obj instanceof String) {
        return (String) obj;
      } else {
        return obj.toString();
      }
    }

    public Timestamp getTimestamp(String label) throws SQLException {
      Object obj = columns.get(label.toUpperCase());
      if (obj == null) {
        return null;
      }

      if (obj instanceof Timestamp) {
        return (Timestamp) obj;
      } else {
        throw new IllegalArgumentException(
            "cannot convert " + obj.getClass().getName() + " to Timestamp");
      }
    }

    public byte[] getBytes(String label) throws SQLException {
      Object obj = columns.get(label.toUpperCase());
      if (obj == null) {
        return null;
      }

      if (obj instanceof byte[]) {
        return (byte[]) obj;
      } else {
        throw new IllegalArgumentException(
            "cannot convert " + obj.getClass().getName() + " to byte[]");
      }
    }

    public Time getTime(String label) throws SQLException {
      Object obj = columns.get(label.toUpperCase());
      if (obj == null) {
        return null;
      }

      if (obj instanceof Time) {
        return (Time) obj;
      } else {
        throw new IllegalArgumentException(
            "cannot convert " + obj.getClass().getName() + " to Time");
      }
    }

    public Date getDate(String label) throws SQLException {
      Object obj = columns.get(label.toUpperCase());
      if (obj == null) {
        return null;
      }

      if (obj instanceof Date) {
        return (Date) obj;
      } else {
        throw new IllegalArgumentException(
            "cannot convert " + obj.getClass().getName() + " to Date");
      }
    }

    public float getFloat(String label) throws SQLException {
      Object obj = columns.get(label.toUpperCase());
      if (obj == null) {
        return 0;
      }

      if (obj instanceof Float) {
        return (float) obj;
      } else if (obj instanceof Double) {
        return (float) ((double) obj);
      } else {
        throw new IllegalArgumentException(
            "cannot convert " + obj.getClass().getName() + " to float");
      }
    }

    public double getDouble(String label) throws SQLException {
      Object obj = columns.get(label.toUpperCase());
      if (obj == null) {
        return 0;
      }

      if (obj instanceof Double) {
        return (double) obj;
      } else if (obj instanceof Float) {
        return (double) ((float) obj);
      } else {
        throw new IllegalArgumentException(
            "cannot convert " + obj.getClass().getName() + " to double");
      }
    }

    public BigDecimal getBigDecimal(String label) throws SQLException {
      Object obj = columns.get(label.toUpperCase());
      if (obj == null) {
        return null;
      }

      if (obj instanceof BigDecimal) {
        return (BigDecimal) obj;
      } else {
        throw new IllegalArgumentException(
            "cannot convert " + obj.getClass().getName() + " to BigDecimal");
      }
    }

  }

  protected static class SqlColumn {

    private ColumnType type;
    private String name;
    private Object value;
    private boolean sensitive;
    private boolean signerConf;

    public SqlColumn(ColumnType type, String name, Object value) {
      this(type, name, value, false, false);
    }

    public SqlColumn(ColumnType type, String name, Object value, boolean sensitive,
        boolean signerConf) {
      this.type = notNull(type, "type");
      this.name = notNull(name, "name");
      this.value = value;
      this.sensitive = sensitive;
      this.signerConf = signerConf;
    }

    public ColumnType type() {
      return type;
    }

    public String name() {
      return name;
    }

    public Object value() {
      return value;
    }

    public boolean sensitive() {
      return sensitive;
    }

    public boolean isSignerConf() {
      return signerConf;
    }

  } // class SqlColumn

  protected static class SqlColumn2 {

    private ColumnType type;
    private Object value;

    public SqlColumn2(ColumnType type, Object value) {
      this.type = notNull(type, "type");
      this.value = value;
    }

    public ColumnType type() {
      return type;
    }

    public Object value() {
      return value;
    }

  } // class SqlColumn2

  protected static class DbSchemaInfo {
    private final Map<String, String> variables = new HashMap<>();

    protected DbSchemaInfo(DataSourceWrapper datasource)
        throws DataAccessException {
      notNull(datasource, "datasource");
      final String sql = "SELECT NAME,VALUE2 FROM DBSCHEMA";

      Statement stmt = null;
      ResultSet rs = null;

      try {
        stmt = datasource.createStatement();
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
    } // constructor

    public String variableValue(String variableName) {
      return variables.get(notNull(variableName, "variableName"));
    }

  } // class DbSchemaInfo

  protected final DataSourceWrapper datasource;

  QueryExecutor(DataSourceWrapper datasource) {
    this.datasource = notNull(datasource, "datasource");
  } // constructor

  protected String buildSelectFirstSql(String coreSql) {
    return datasource.buildSelectFirstSql(1, coreSql);
  }

  protected String buildSelectFirstSql(String orderBy, String coreSql) {
    return datasource.buildSelectFirstSql(1, orderBy, coreSql);
  }

  protected static SqlColumn colBool(String name, Boolean value) {
    return new SqlColumn(ColumnType.BOOL, name, value);
  }

  protected static SqlColumn colInt(String name, Integer value) {
    return new SqlColumn(ColumnType.INT, name, value);
  }

  protected static SqlColumn colLong(String name, Long value) {
    return new SqlColumn(ColumnType.LONG, name, value);
  }

  protected static SqlColumn colStr(String name, String value) {
    return new SqlColumn(ColumnType.STRING, name, value);
  }

  protected static SqlColumn colStr(String name, String value, boolean sensitive,
      boolean signerConf) {
    return new SqlColumn(ColumnType.STRING, name, value, sensitive, signerConf);
  }

  protected static SqlColumn2 col2Bool(Boolean value) {
    return new SqlColumn2(ColumnType.BOOL, value);
  }

  protected static SqlColumn2 col2Int(Integer value) {
    return new SqlColumn2(ColumnType.INT, value);
  }

  protected static SqlColumn2 col2Long(Long value) {
    return new SqlColumn2(ColumnType.LONG, value);
  }

  protected static SqlColumn2 col2Str(String value) {
    return new SqlColumn2(ColumnType.STRING, value);
  }

  protected static SqlColumn2 col2Timestamp(Timestamp value) {
    return new SqlColumn2(ColumnType.TIMESTAMP, value);
  }

  protected int execUpdateStmt(String sql)
      throws DataAccessException {
    Statement ps = datasource.createStatement();
    try {
      return ps.executeUpdate(sql);
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  }

  protected int execUpdatePrepStmt(String sql, SqlColumn2... params)
      throws DataAccessException {
    PreparedStatement ps = buildPrepStmt(sql, params);
    try {
      return ps.executeUpdate();
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  }

  protected List<ResultRow> execQueryStmt(String sql) throws DataAccessException {
    return execQueryStmt(false, sql);
  }

  private List<ResultRow> execQueryStmt(boolean single, String sql) throws DataAccessException {
    Statement stmt = datasource.createStatement();
    ResultSet rs = null;

    try {
      rs = stmt.executeQuery(sql);
      List<ResultRow> rows = new LinkedList<>();
      while (rs.next()) {
        rows.add(new ResultRow(rs));
        if (single) {
          break;
        }
      }
      return rows;
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  }

  protected ResultRow execQuery1PrepStmt(String sql, SqlColumn2... params)
      throws DataAccessException {
    List<ResultRow> rows = execQueryPrepStmt(true, sql, params);
    return rows.isEmpty() ? null : rows.get(0);
  }

  protected List<ResultRow> execQueryPrepStmt(String sql, SqlColumn2... params)
      throws DataAccessException {
    return execQueryPrepStmt(false, sql, params);
  }

  private List<ResultRow> execQueryPrepStmt(boolean single, String sql, SqlColumn2... params)
      throws DataAccessException {
    PreparedStatement ps = buildPrepStmt(sql, params);
    ResultSet rs = null;
    try {
      rs = ps.executeQuery();
      List<ResultRow> rows = new LinkedList<>();
      while (rs.next()) {
        rows.add(new ResultRow(rs));
        if (single) {
          break;
        }
      }
      return rows;
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, rs);
    }
  }

  protected PreparedStatement buildPrepStmt(String sql,  SqlColumn2... columns)
      throws DataAccessException {
    PreparedStatement ps = null;
    boolean succ = false;
    try {
      ps = datasource.prepareStatement(sql);

      int index = 0;
      for (SqlColumn2 col : columns) {
        index++;

        ColumnType type = col.type();
        Object value = col.value();

        try {
          if (type == ColumnType.STRING) {
            ps.setString(index, (String) value);
          } else if (type == ColumnType.INT) {
            if (value == null) {
              ps.setNull(index, Types.INTEGER);
            } else {
              ps.setInt(index, ((Integer) value).intValue());
            }
          } else if (type == ColumnType.LONG) {
            if (value == null) {
              ps.setNull(index, Types.BIGINT);
            } else {
              ps.setLong(index, ((Long) value).longValue());
            }
          } else if (type == ColumnType.BOOL) {
            if (value == null) {
              ps.setNull(index, Types.INTEGER);
            } else {
              ps.setInt(index, (Boolean) value ? 1 : 0);
            }
          } else if (type == ColumnType.TIMESTAMP) {
            if (value == null) {
              ps.setNull(index, Types.TIMESTAMP);
            } else {
              ps.setTimestamp(index, (Timestamp) value);
            }
          } else {
            throw new IllegalStateException("should not reach here, unknown type " + type);
          }
        } catch (SQLException ex) {
          throw datasource.translate(sql, ex);
        }
      }

      succ = true;
      return ps;
    } finally {
      if (!succ) {
        datasource.releaseResources(ps, null);
      }
    }
  }

  protected void notNulls(Object param1, String name1, Object param2, String name2) {
    notNull(param1, name1);
    notNull(param2, name2);
  }

  protected void notNulls(Object param1, String name1, Object param2, String name2,
      Object param3, String name3) {
    notNull(param1, name1);
    notNull(param2, name2);
    notNull(param3, name3);
  }

  protected void notNulls(Object param1, String name1, Object param2, String name2,
      Object param3, String name3, Object param4, String name4) {
    notNull(param1, name1);
    notNull(param2, name2);
    notNull(param3, name3);
    notNull(param4, name4);
  }

}
