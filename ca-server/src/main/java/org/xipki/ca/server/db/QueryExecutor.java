// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.db;

import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.util.Args;

import java.sql.*;
import java.util.*;

/**
 * Base class to execute the database queries to manage CA system.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */
class QueryExecutor {

  protected enum ColumnType {
    INT,
    LONG,
    STRING,
    BOOL,
    TIMESTAMP,
  } // class ColumnType

  protected static class SqlColumn {

    private final ColumnType type;
    private final String name;
    private final Object value;
    private final boolean sensitive;
    private final boolean signerConf;

    public SqlColumn(ColumnType type, String name, Object value) {
      this(type, name, value, false, false);
    }

    public SqlColumn(ColumnType type, String name, Object value, boolean sensitive, boolean signerConf) {
      this.type = Args.notNull(type, "type");
      this.name = Args.notNull(name, "name");
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

    private final ColumnType type;
    private final Object value;

    public SqlColumn2(ColumnType type, Object value) {
      this.type = Args.notNull(type, "type");
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

    protected DbSchemaInfo(DataSourceWrapper datasource) throws DataAccessException {
      Args.notNull(datasource, "datasource");
      final String sql = "SELECT NAME,VALUE2 FROM DBSCHEMA";

      PreparedStatement stmt = null;
      ResultSet rs = null;

      try {
        stmt = Optional.ofNullable(datasource.prepareStatement(sql))
            .orElseThrow(() -> new DataAccessException("could not create statement"));

        rs = stmt.executeQuery();
        while (rs.next()) {
          variables.put(rs.getString("NAME"), rs.getString("VALUE2"));
        }
      } catch (SQLException ex) {
        throw datasource.translate(sql, ex);
      } finally {
        datasource.releaseResources(stmt, rs);
      }
    } // constructor

    public Set<String> getVariableNames() {
      return Collections.unmodifiableSet(variables.keySet());
    }

    public String variableValue(String variableName) {
      return variables.get(Args.notNull(variableName, "variableName"));
    }

  } // class DbSchemaInfo

  protected final DataSourceWrapper datasource;

  QueryExecutor(DataSourceWrapper datasource) {
    this.datasource = Args.notNull(datasource, "datasource");
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

  protected static SqlColumn colStr(String name, String value, boolean sensitive, boolean signerConf) {
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

  protected int execUpdateStmt(String sql) throws DataAccessException {
    PreparedStatement ps = datasource.prepareStatement(sql);
    try {
      return ps.executeUpdate();
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    } finally {
      datasource.releaseResources(ps, null);
    }
  }

  protected int execUpdatePrepStmt(String sql, SqlColumn2... params) throws DataAccessException {
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
    PreparedStatement stmt = datasource.prepareStatement(sql);
    ResultSet rs = null;

    try {
      rs = stmt.executeQuery();
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

  protected ResultRow execQuery1PrepStmt(String sql, SqlColumn2... params) throws DataAccessException {
    List<ResultRow> rows = execQueryPrepStmt(true, sql, params);
    return rows.isEmpty() ? null : rows.get(0);
  }

  protected List<ResultRow> execQueryPrepStmt(String sql, SqlColumn2... params) throws DataAccessException {
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

  protected PreparedStatement buildPrepStmt(String sql,  SqlColumn2... columns) throws DataAccessException {
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
              ps.setInt(index, (Integer) value);
            }
          } else if (type == ColumnType.LONG) {
            if (value == null) {
              ps.setNull(index, Types.BIGINT);
            } else {
              ps.setLong(index, (Long) value);
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
    Args.notNull(param1, name1);
    Args.notNull(param2, name2);
  }

  protected void notNulls(Object param1, String name1, Object param2, String name2, Object param3, String name3) {
    Args.notNull(param1, name1);
    Args.notNull(param2, name2);
    Args.notNull(param3, name3);
  }

  protected void notNulls(Object param1, String name1, Object param2, String name2,
      Object param3, String name3, Object param4, String name4) {
    Args.notNull(param1, name1);
    Args.notNull(param2, name2);
    Args.notNull(param3, name3);
    Args.notNull(param4, name4);
  }

}
