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

  protected List<ResultRow> execQueryStmt(String sql, SqlColumn3[] resultColumns)
      throws DataAccessException {
    return execQueryStmt(false, sql, resultColumns);
  }

  private List<ResultRow> execQueryStmt(boolean single, String sql, SqlColumn3[] resultColumns)
      throws DataAccessException {
    Statement stmt = datasource.createStatement();
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
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(stmt, rs);
    }
  }

  protected ResultRow execQuery1PrepStmt(
      String sql, SqlColumn3[] resultColumns, SqlColumn2... params)
      throws DataAccessException {
    List<ResultRow> rows = execQueryPrepStmt(true, sql, resultColumns, params);
    return rows.isEmpty() ? null : rows.get(0);
  }

  protected List<ResultRow> execQueryPrepStmt(
      String sql, SqlColumn3[] resultColumns, SqlColumn2... params)
      throws DataAccessException {
    return execQueryPrepStmt(false, sql, resultColumns, params);
  }

  private List<ResultRow> execQueryPrepStmt(boolean single,
      String sql, SqlColumn3[] resultColumns, SqlColumn2... params)
      throws DataAccessException {
    PreparedStatement ps = buildPrepStmt(sql, params);
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
