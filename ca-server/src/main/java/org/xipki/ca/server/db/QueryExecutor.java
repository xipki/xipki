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
import static org.xipki.util.StringUtil.concat;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.security.SignerConf;
import org.xipki.util.StringUtil;

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

    public ResultRow(ResultSet rs, SqlColumn3[] resultColumns)
        throws SQLException {
      ResultSetMetaData metaData = rs.getMetaData();
      int count = metaData.getColumnCount();
      for (int index = 1; index <= count; index++) {
        String label = metaData.getColumnLabel(index);
        ColumnType type = ColumnType.STRING;
        if (resultColumns != null) {
          for (SqlColumn3 c3 : resultColumns) {
            if (label.equalsIgnoreCase(label)) {
              type = c3.type();
              break;
            }
          }
        }

        Object value;
        if (type == ColumnType.BOOL) {
          value = rs.getBoolean(label);
        } else if (type == ColumnType.INT) {
          value = rs.getInt(label);
        } else if (type == ColumnType.LONG) {
          value = rs.getLong(label);
        } else if (type == ColumnType.STRING) {
          value = rs.getString(label);
        } else if (type == ColumnType.TIMESTAMP) {
          value = rs.getTimestamp(label);
        } else {
          throw new IllegalArgumentException("unknown ColumnType " + type);
        }

        columns.put(label.toUpperCase(), value);
      }
    }

    public int getInt(String label) {
      return (int) columns.get(label.toUpperCase());
    }

    public boolean getBoolean(String label) {
      return (boolean) columns.get(label.toUpperCase());
    }

    public long getLong(String label) {
      return (long) columns.get(label.toUpperCase());
    }

    public String getString(String label) {
      return (String) columns.get(label.toUpperCase());
    }

    public Timestamp getTimestamp(String label) {
      return (Timestamp) columns.get(label.toUpperCase());
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

  protected static class SqlColumn3 {

    private String label;

    private ColumnType type;

    public SqlColumn3(String label, ColumnType type) {
      this.label = notNull(label, "label");
      this.type = notNull(type, "type");
    }

    public String label() {
      return label;
    }

    public ColumnType type() {
      return type;
    }

  } // class SqlColumn3

  private static final Logger LOG = LoggerFactory.getLogger(QueryExecutor.class);

  protected final DataSourceWrapper datasource;

  QueryExecutor(DataSourceWrapper datasource) {
    this.datasource = notNull(datasource, "datasource");
  } // constructor

  protected String buildSelectFirstSql(String coreSql) {
    return datasource.buildSelectFirstSql(1, coreSql);
  }

  private Statement createStatement()
      throws CaMgmtException {
    try {
      return datasource.createStatement();
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }
  } // method createStatement

  private PreparedStatement prepareStatement(String sql)
      throws CaMgmtException {
    try {
      return datasource.prepareStatement(sql);
    } catch (DataAccessException ex) {
      throw new CaMgmtException(ex);
    }
  } // method prepareStatement

  public List<String> namesFromTable(String table)
      throws CaMgmtException {
    final String sql = concat("SELECT NAME FROM ", table);
    List<ResultRow> rows = executeQueryStament(sql, null);

    List<String> names = new LinkedList<>();
    for (ResultRow rs : rows) {
      String name = rs.getString("NAME");
      if (StringUtil.isNotBlank(name)) {
        names.add(name);
      }
    }

    return names;
  } // method namesFromTable

  public boolean deleteRowWithName(String name, String table)
      throws CaMgmtException {
    final String sql = concat("DELETE FROM ", table, " WHERE NAME=?");
    int num = executeUpdatePreparedStament(sql, col2Str(name));
    return num > 0;
  } // method deleteRowWithName

  protected static SqlColumn colBool(String name, boolean value) {
    return new SqlColumn(ColumnType.BOOL, name, value);
  }

  protected static SqlColumn colInt(String name, int value) {
    return new SqlColumn(ColumnType.INT, name, value);
  }

  protected static SqlColumn colLong(String name, long value) {
    return new SqlColumn(ColumnType.LONG, name, value);
  }

  protected static SqlColumn colStr(String name, String value) {
    return new SqlColumn(ColumnType.STRING, name, value);
  }

  protected static SqlColumn colStr(String name, String value, boolean sensitive,
      boolean signerConf) {
    return new SqlColumn(ColumnType.STRING, name, value, sensitive, signerConf);
  }

  protected static SqlColumn2 col2Bool(boolean value) {
    return new SqlColumn2(ColumnType.BOOL, value);
  }

  protected static SqlColumn2 col2Int(int value) {
    return new SqlColumn2(ColumnType.INT, value);
  }

  protected static SqlColumn2 col2Long(long value) {
    return new SqlColumn2(ColumnType.LONG, value);
  }

  protected static SqlColumn2 col2Str(String value) {
    return new SqlColumn2(ColumnType.STRING, value);
  }

  protected static SqlColumn2 col2Timestamp(Timestamp value) {
    return new SqlColumn2(ColumnType.TIMESTAMP, value);
  }

  protected static SqlColumn3 col3Bool(String label) {
    return new SqlColumn3(label, ColumnType.BOOL);
  }

  protected static SqlColumn3 col3Int(String label) {
    return new SqlColumn3(label, ColumnType.INT);
  }

  protected static SqlColumn3 col3Long(String label) {
    return new SqlColumn3(label, ColumnType.LONG);
  }

  protected static String str(String sa, String sb) {
    return (sa != null) ? getRealString(sa) : sb;
  }

  protected int executeUpdateStament(String sql)
      throws CaMgmtException {
    Statement ps = createStatement();
    try {
      return ps.executeUpdate(sql);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  }

  protected int executeUpdatePreparedStament(String sql, SqlColumn2... params)
      throws CaMgmtException {
    PreparedStatement ps = buildPreparedStament(sql, params);
    try {
      return ps.executeUpdate();
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  }

  protected List<ResultRow> executeQueryStament(String sql, SqlColumn3[] resultColumns)
      throws CaMgmtException {
    return executeQueryStament(false, sql, resultColumns);
  }

  private List<ResultRow> executeQueryStament(boolean single,
      String sql, SqlColumn3[] resultColumns)
      throws CaMgmtException {
    Statement stmt = createStatement();
    ResultSet rs = null;

    try {
      rs = stmt.executeQuery(sql);
      List<ResultRow> rows = new LinkedList<>();
      while (rs.next()) {
        rows.add(new ResultRow(rs, resultColumns));
        if (single) {
          break;
        }
      }
      return rows;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  }

  protected ResultRow executeQuery1PreparedStament(
      String sql, SqlColumn3[] resultColumns, SqlColumn2... params)
      throws CaMgmtException {
    List<ResultRow> rows = executeQueryPreparedStament(true, sql, resultColumns, params);
    return rows.isEmpty() ? null : rows.get(0);
  }

  protected List<ResultRow> executeQueryPreparedStament(
      String sql, SqlColumn3[] resultColumns, SqlColumn2... params)
      throws CaMgmtException {
    return executeQueryPreparedStament(false, sql, resultColumns, params);
  }

  private List<ResultRow> executeQueryPreparedStament(boolean single,
      String sql, SqlColumn3[] resultColumns, SqlColumn2... params)
      throws CaMgmtException {
    PreparedStatement ps = buildPreparedStament(sql, params);
    ResultSet rs = null;
    try {
      rs = ps.executeQuery();
      List<ResultRow> rows = new LinkedList<>();
      while (rs.next()) {
        rows.add(new ResultRow(rs, resultColumns));
        if (single) {
          break;
        }
      }
      return rows;
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, rs);
    }
  }

  protected PreparedStatement buildPreparedStament(String sql,  SqlColumn2... columns)
      throws CaMgmtException {
    PreparedStatement ps = null;
    boolean succ = false;
    try {
      ps = prepareStatement(sql);

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
          throw new CaMgmtException(datasource.translate(sql, ex));
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

    String sql = buf.toString();

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

      LOG.info("updated table {} WHERE {}={}: {}", tableName,
          whereColumn.name(), whereColumn.value(), changedColumns);
    } catch (SQLException ex) {
      throw new CaMgmtException(datasource.translate(sql, ex));
    } finally {
      datasource.releaseResources(ps, null);
    }
  } // method changeIfNotNull

  private void setColumn(Map<String, String> changedColumns, PreparedStatement ps,
      int index, SqlColumn column)
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
        int val = ((Integer) value).intValue();
        ps.setInt(index, val);
        valText = Integer.toString(val);
      }
    } else if (type == ColumnType.LONG) {
      if (value == null) {
        ps.setNull(index, Types.BIGINT);
        valText = "null";
      } else {
        long val = ((Long) value).longValue();
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

  protected int getNonNullIdForName(String sql, String name)
      throws CaMgmtException {
    Integer id = getIdForName(sql, name);
    if (id != null) {
      return id.intValue();
    }

    throw new CaMgmtException(concat("Found no entry named ",name));
  } // method getNonNullIdForName

  protected Integer getIdForName(String sql, String name)
      throws CaMgmtException {
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

  protected Map<Integer, String> getIdNameMap(String tableName)
      throws CaMgmtException {
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
