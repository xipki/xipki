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

package org.xipki.datasource;

import java.io.Closeable;
import java.io.PrintWriter;
import java.sql.BatchUpdateException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataAccessException.Reason;
import org.xipki.util.LogUtil;
import org.xipki.util.LruCache;
import org.xipki.util.Args;
import org.xipki.util.StringUtil;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class DataSourceWrapper implements Closeable {

  // CHECKSTYLE:SKIP
  private static class MySQL extends DataSourceWrapper {

    MySQL(String name, HikariDataSource service) {
      super(name, service, DatabaseType.MYSQL);
    }

    MySQL(String name, HikariDataSource service, DatabaseType type) {
      super(name, service, type);
    }

    @Override
    public String buildSelectFirstSql(int rows, String orderBy, String coreSql) {
      return StringUtil.concat("SELECT ", coreSql,
          (StringUtil.isBlank(orderBy) ? "" : " ORDER BY " + orderBy),
          " LIMIT ", Integer.toString(rows));
    }

    @Override
    protected String buildCreateSequenceSql(String sequenceName, long startValue) {
      return StringUtil.concat("INSERT INTO SEQ_TBL (SEQ_NAME,SEQ_VALUE) VALUES('",
          sequenceName, "', ", Long.toString(startValue), ")");
    }

    @Override
    protected String buildDropSequenceSql(String sequenceName) {
      return StringUtil.concat("DELETE FROM SEQ_TBL WHERE SEQ_NAME='", sequenceName, "'");
    }

    @Override
    protected String buildNextSeqValueSql(String sequenceName) {
      return StringUtil.concat("UPDATE SEQ_TBL SET SEQ_VALUE=(@cur_value:=SEQ_VALUE)+1 "
          + "WHERE SEQ_NAME='", sequenceName, "'");
    }

    @Override
    public long nextSeqValue(Connection conn, String sequenceName) throws DataAccessException {
      final String sqlUpdate = buildAndCacheNextSeqValueSql(sequenceName);
      final String sqlSelect = "SELECT @cur_value";
      String sql = null;

      Statement stmt = null;
      ResultSet rs = null;

      long ret;
      try {
        stmt = conn == null ? createStatement() : createStatement(conn);
        sql = sqlUpdate;
        stmt.executeUpdate(sql);

        sql = sqlSelect;
        rs = stmt.executeQuery(sql);
        if (rs.next()) {
          ret = rs.getLong(1);
        } else {
          throw new DataAccessException("could not increment the sequence " + sequenceName);
        }
      } catch (SQLException ex) {
        throw translate(sqlUpdate, ex);
      } finally {
        releaseResources(stmt, rs, conn == null);
      }

      LOG.debug("datasource {} NEXVALUE({}): {}", name, sequenceName, ret);
      return ret;
    } // method nextSeqValue

    @Override
    protected String getSqlToDropForeignKeyConstraint(String constraintName, String baseTable)
            throws DataAccessException {
      return StringUtil.concat("ALTER TABLE ", baseTable, " DROP FOREIGN KEY ", constraintName);
    }

    @Override
    protected String getSqlToDropIndex(String table, String indexName) {
      return StringUtil.concat("DROP INDEX ", indexName, " ON ", table);
    }

    @Override
    protected String getSqlToDropUniqueConstraint(String constraintName, String table) {
      return StringUtil.concat("ALTER TABLE ", table, " DROP KEY ", constraintName);
    }

  } // class MySQL

  // CHECKSTYLE:SKIP
  private static class MariaDB extends MySQL {

    MariaDB(String name, HikariDataSource service) {
      super(name, service, DatabaseType.MARIADB);
    }

  }

  // CHECKSTYLE:SKIP
  private static class DB2 extends DataSourceWrapper {

    DB2(String name, HikariDataSource service) {
      super(name, service, DatabaseType.DB2);
    }

    @Override
    public String buildSelectFirstSql(int rows, String orderBy, String coreSql) {
      return StringUtil.concat("SELECT ", coreSql,
          (StringUtil.isBlank(orderBy) ? "" : " ORDER BY " + orderBy),
          " FETCH FIRST ", Integer.toString(rows), " ROWS ONLY");
    }

    @Override
    protected String buildCreateSequenceSql(String sequenceName, long startValue) {
      return StringUtil.concat("CREATE SEQUENCE ", sequenceName, " AS BIGINT START WITH ",
          Long.toString(startValue), " INCREMENT BY 1 NO CYCLE NO CACHE");
    }

    @Override
    protected String buildDropSequenceSql(String sequenceName) {
      return StringUtil.concat("DROP SEQUENCE ", sequenceName);
    }

    @Override
    protected String buildNextSeqValueSql(String sequenceName) {
      return StringUtil.concat("SELECT NEXT VALUE FOR ", sequenceName, " FROM sysibm.sysdummy1");
    }

  } // class DB2

  // CHECKSTYLE:SKIP
  private static class PostgreSQL extends DataSourceWrapper {

    PostgreSQL(String name, HikariDataSource service) {
      super(name, service, DatabaseType.POSTGRES);
    }

    @Override
    public String buildSelectFirstSql(int rows, String orderBy, String coreSql) {
      return StringUtil.concat("SELECT ", coreSql,
          (StringUtil.isBlank(orderBy) ? "" : " ORDER BY " + orderBy),
          " FETCH FIRST ", Integer.toString(rows), " ROWS ONLY");
    }

    @Override
    protected String buildCreateSequenceSql(String sequenceName, long startValue) {
      return StringUtil.concat("CREATE SEQUENCE ", sequenceName, " START WITH ",
          Long.toString(startValue), " INCREMENT BY 1 NO CYCLE");
    }

    @Override
    protected String buildDropSequenceSql(String sequenceName) {
      return StringUtil.concat("DROP SEQUENCE ", sequenceName);
    }

    @Override
    protected String buildNextSeqValueSql(String sequenceName) {
      return StringUtil.concat("SELECT NEXTVAL ('", sequenceName, "')");
    }

    @Override
    protected boolean isUseSqlStateAsCode() {
      return true;
    }

    @Override
    protected String getSqlToDropPrimaryKey(String primaryKeyName, String table) {
      return StringUtil.concat("DO $$ DECLARE constraint_name varchar;\n",
        "BEGIN\n",
        "  SELECT tc.CONSTRAINT_NAME into strict constraint_name\n",
        "  FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc\n",
        "  WHERE CONSTRAINT_TYPE='PRIMARY KEY'\n",
        "  AND TABLE_NAME='", table.toLowerCase(),
          "' AND TABLE_SCHEMA='public';\n",
          "  EXECUTE 'alter table public.", table.toLowerCase(),
          " drop constraint ' || constraint_name;\n",
        "END $$;");
    }

  } // class PostgreSQL

  private static class Oracle extends DataSourceWrapper {

    Oracle(String name, HikariDataSource service) {
      super(name, service, DatabaseType.ORACLE);
    }

    /*
     * Oracle: http://www.oracle.com/technetwork/issue-archive/2006/06-sep/o56asktom-086197.html
     *
     */
    @Override
    public String buildSelectFirstSql(int rows, String orderBy, String coreSql) {
      if (StringUtil.isBlank(orderBy)) {
        return StringUtil.concat("SELECT ", coreSql,
            (coreSql.contains(" WHERE") ? " AND" : " WHERE"), " ROWNUM<",
            Integer.toString(rows + 1));
      } else {
        return StringUtil.concat("SELECT * FROM (SELECT ", coreSql, " ORDER BY ", orderBy,
            " ) WHERE ROWNUM<", Integer.toString(rows + 1));
      }
    }

    @Override
    protected String buildCreateSequenceSql(String sequenceName, long startValue) {
      return StringUtil.concat("CREATE SEQUENCE ", sequenceName, " START WITH ",
          Long.toString(startValue), " INCREMENT BY 1 NOCYCLE NOCACHE");
    }

    @Override
    protected String buildDropSequenceSql(String sequenceName) {
      return StringUtil.concat("DROP SEQUENCE ", sequenceName);
    }

    @Override
    protected String buildNextSeqValueSql(String sequenceName) {
      return StringUtil.concat("SELECT ", sequenceName, ".NEXTVAL FROM DUAL");
    }

    @Override
    protected String getSqlToDropPrimaryKey(String primaryKeyName, String table) {
      return getSqlToDropUniqueConstraint(primaryKeyName, table);
    }

    @Override
    protected String getSqlToDropUniqueConstraint(String contraintName, String table) {
      return StringUtil.concat("ALTER TABLE ", table, " DROP CONSTRAINT ", contraintName,
          " DROP INDEX");
    }

    @Override
    protected String getSqlToAddForeignKeyConstraint(String constraintName,
        String baseTable, String baseColumn, String referencedTable,
        String referencedColumn, String onDeleteAction, String onUpdateAction) {
      return StringUtil.concat("ALTER TABLE ", baseTable, " ADD CONSTRAINT ", constraintName,
          " FOREIGN KEY (", baseColumn, ")", " REFERENCES ", referencedTable,
          " (", referencedColumn, ")", " ON DELETE ", onDeleteAction);
    }

    @Override
    protected String getSqlToAddPrimaryKey(String primaryKeyName, String table, String... columns) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("ALTER TABLE ").append(table);
      sb.append(" ADD CONSTRAINT ").append(primaryKeyName);
      sb.append(" PRIMARY KEY(");
      final int n = columns.length;
      for (int i = 0; i < n; i++) {
        if (i != 0) {
          sb.append(",");
        }
        sb.append(columns[i]);
      }
      sb.append(")");
      return sb.toString();
    }

  } // class Oracle

  private static class H2 extends DataSourceWrapper {

    H2(String name, HikariDataSource service) {
      super(name, service, DatabaseType.H2);
    }

    @Override
    public String buildSelectFirstSql(int rows, String orderBy, String coreSql) {
      return StringUtil.concat("SELECT ", coreSql,
          (StringUtil.isBlank(orderBy) ? "" : " ORDER BY " + orderBy),
          " LIMIT ", Integer.toString(rows));
    }

    @Override
    protected String buildCreateSequenceSql(String sequenceName, long startValue) {
      return StringUtil.concat("CREATE SEQUENCE ", sequenceName, " START WITH ",
          Long.toString(startValue), " INCREMENT BY 1 NO CYCLE NO CACHE");
    }

    @Override
    protected String buildDropSequenceSql(String sequenceName) {
      return StringUtil.concat("DROP SEQUENCE ", sequenceName);
    }

    @Override
    protected String buildNextSeqValueSql(String sequenceName) {
      return StringUtil.concat("SELECT NEXTVAL ('", sequenceName, "')");
    }

  } // class H2

  // CHECKSTYLE:SKIP
  private static class HSQL extends DataSourceWrapper {

    HSQL(String name, HikariDataSource service) {
      super(name, service, DatabaseType.HSQL);
    }

    @Override
    public String buildSelectFirstSql(int rows, String orderBy, String coreSql) {
      return StringUtil.concat("SELECT ", coreSql,
          (StringUtil.isBlank(orderBy) ? "" : " ORDER BY " + orderBy), " LIMIT ",
          Integer.toString(rows));
    }

    @Override
    protected String buildCreateSequenceSql(String sequenceName, long startValue) {
      return StringUtil.concat("CREATE SEQUENCE ", sequenceName, " AS BIGINT START WITH ",
          Long.toString(startValue), " INCREMENT BY 1");
    }

    @Override
    protected String buildDropSequenceSql(String sequenceName) {
      return StringUtil.concat("DROP SEQUENCE ", sequenceName);
    }

    @Override
    protected String buildNextSeqValueSql(String sequenceName) {
      return StringUtil.concat("SELECT NEXTVAL ('", sequenceName, "')");
    }

  } // class HSQL

  private static final Logger LOG = LoggerFactory.getLogger(DataSourceWrapper.class);

  /**
   * References the real data source implementation this class acts as pure
   * proxy for. Derived classes must set this field at construction time.
   */
  protected final HikariDataSource service;

  protected final String name;

  private final Object lastUsedSeqValuesLock = new Object();

  private final ConcurrentHashMap<String, Long> lastUsedSeqValues = new ConcurrentHashMap<>();

  private final SqlErrorCodes sqlErrorCodes;

  private final SqlStateCodes sqlStateCodes;

  private final DatabaseType databaseType;

  private final LruCache<String, String> cacheSeqNameSqls;

  private DataSourceWrapper(String name, HikariDataSource service, DatabaseType dbType) {
    this.service = Args.notNull(service, "service");
    this.databaseType = Args.notNull(dbType, "dbType");
    this.name = name;
    this.sqlErrorCodes = SqlErrorCodes.newInstance(dbType);
    this.sqlStateCodes = SqlStateCodes.newInstance(dbType);
    this.cacheSeqNameSqls = new LruCache<>(100);
  }

  public final String getName() {
    return name;
  }

  public final DatabaseType getDatabaseType() {
    return this.databaseType;
  }

  public final int getMaximumPoolSize() {
    return service.getMaximumPoolSize();
  }

  public final Connection getConnection() throws DataAccessException {
    try {
      return service.getConnection();
    } catch (Exception ex) {
      Throwable cause = ex.getCause();
      if (cause instanceof SQLException) {
        ex = (SQLException) cause;
      }
      LogUtil.error(LOG, ex, "could not create connection to database");
      if (ex instanceof SQLException) {
        throw translate(null, (SQLException) ex);
      } else {
        throw new DataAccessException(
            "error occured while getting Connection: " + ex.getMessage(), ex);
      }
    }
  }

  public void returnConnection(Connection conn) {
    if (conn == null) {
      return;
    }

    try {
      conn.close();
    } catch (Exception ex) {
      Throwable cause = ex.getCause();
      if (cause instanceof SQLException) {
        ex = (SQLException) cause;
      }
      LogUtil.error(LOG, ex, "could not close connection to database {}");
    }
  }

  @Override
  public void close() {
    try {
      service.close();
    } catch (RuntimeException ex) {
      LOG.warn("could not close datasource: {}", ex.getMessage());
      LOG.debug("could not close datasource", ex);
    }
  }

  public final PrintWriter getLogWriter() throws SQLException {
    return service.getLogWriter();
  }

  public Statement createStatement(Connection conn) throws DataAccessException {
    Args.notNull(conn, "conn");
    try {
      return conn.createStatement();
    } catch (SQLException ex) {
      throw translate(null, ex);
    }
  }

  public Statement createStatement() throws DataAccessException {
    Connection conn = getConnection();
    boolean succ = false;
    try {
      Statement stmt = conn.createStatement();
      succ = true;
      return stmt;
    } catch (SQLException ex) {
      throw translate(null, ex);
    } finally {
      if (!succ) {
        returnConnection(conn);
      }
    }
  }

  public PreparedStatement prepareStatement(Connection conn, String sqlQuery)
      throws DataAccessException {
    Args.notNull(conn, "conn");
    try {
      return conn.prepareStatement(sqlQuery);
    } catch (SQLException ex) {
      throw translate(sqlQuery, ex);
    }
  }

  public PreparedStatement prepareStatement(String sqlQuery) throws DataAccessException {
    Connection conn = getConnection();

    boolean succ = false;
    try {
      PreparedStatement ps = conn.prepareStatement(sqlQuery);
      succ = true;
      return ps;
    } catch (SQLException ex) {
      throw translate(sqlQuery, ex);
    } finally {
      if (!succ) {
        returnConnection(conn);
      }
    }
  }

  public void releaseResources(Statement ps, ResultSet rs) {
    releaseResources(ps, rs, true);
  }

  public void releaseResources(Statement ps, ResultSet rs, boolean returnConnection) {
    if (rs != null) {
      try {
        rs.close();
      } catch (Throwable th) {
        LOG.warn("could not close ResultSet", th);
      }
    }

    if (ps == null) {
      return;
    } else if (returnConnection) {
      Connection conn = null;
      try {
        conn = ps.getConnection();
      } catch (SQLException ex) {
        LOG.error("could not get connection from statement: {}", ex.getMessage());
      }

      try {
        ps.close();
      } catch (Throwable th) {
        LOG.warn("could not close statement", th);
      } finally {
        if (conn != null) {
          returnConnection(conn);
        }
      }
    } else {
      try {
        ps.close();
      } catch (Throwable th) {
        LOG.warn("could not close statement", th);
      }
    }
  }

  public String buildSelectFirstSql(int rows, String coreSql) {
    return buildSelectFirstSql(rows, null, coreSql);
  }

  public abstract String buildSelectFirstSql(int rows, String orderBy, String coreSql);

  public <T> T getFirstValue(Connection conn, String table, String column, String criteria,
      Class<T> type) throws DataAccessException {
    final String sql = "SELECT " + column + " FROM " + table + " WHERE " + criteria;
    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = conn == null ? createStatement() : createStatement(conn);
      rs = stmt.executeQuery(sql);
      if (rs.next()) {
        return rs.getObject(column, type);
      } else {
        return null;
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs, conn == null);
    }
  }

  public long getMin(Connection conn, String table, String column) throws DataAccessException {
    return getMin(conn, table, column, null);
  }

  public long getMin(Connection conn, String table, String column, String condition)
      throws DataAccessException {
    Args.notBlank(table, "table");
    Args.notBlank(column, "column");

    String sql = StringUtil.concat("SELECT MIN(", column, ") FROM ", table,
        (StringUtil.isBlank(condition) ? "" : " WHERE " + condition));

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = conn == null ? createStatement() : createStatement(conn);
      rs = stmt.executeQuery(sql);
      rs.next();
      return rs.getLong(1);
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs, conn == null);
    }
  }

  public int getCount(Connection conn, String table) throws DataAccessException {
    Args.notBlank(table, "table");

    final String sql = StringUtil.concat("SELECT COUNT(*) FROM ", table);

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = conn == null ? createStatement() : createStatement(conn);
      rs = stmt.executeQuery(sql);
      rs.next();
      return rs.getInt(1);
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs, conn == null);
    }
  }

  public long getMax(Connection conn, String table, String column) throws DataAccessException {
    return getMax(conn, table, column, null);
  }

  public long getMax(Connection conn, String table, String column, String condition)
      throws DataAccessException {
    Args.notBlank(table, "table");
    Args.notBlank(column, "column");

    final String sql = StringUtil.concat("SELECT MAX(", column, ") FROM ", table,
        (StringUtil.isBlank(condition) ? "" : " WHERE " + condition));

    Statement stmt = null;
    ResultSet rs = null;
    try {
      stmt = conn == null ? createStatement() : createStatement(conn);
      rs = stmt.executeQuery(sql);
      rs.next();
      return rs.getLong(1);
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs, conn == null);
    }
  }

  public boolean deleteFromTable(Connection conn, String table, String idColumn, long id) {
    Args.notBlank(table, "table");
    Args.notBlank(idColumn, "idColumn");
    final String sql = StringUtil.concat("DELETE FROM ", table, " WHERE ", idColumn,
        "=", Long.toString(id));

    Statement stmt = null;
    try {
      stmt = conn == null ? createStatement() : createStatement(conn);
      stmt.execute(sql);
    } catch (Throwable th) {
      if (LOG.isWarnEnabled()) {
        LOG.warn("datasource {} could not deletefrom table {}: {}", name, table, th.getMessage());
      }
      return false;
    } finally {
      releaseResources(stmt, null, conn == null);
    }

    return true;
  }

  public boolean columnExists(Connection conn, String table, String column, Object value)
      throws DataAccessException {
    Args.notBlank(table, "table");
    Args.notBlank(column, "column");
    Args.notNull(value, "value");

    String coreSql = StringUtil.concat(column, " FROM ", table, " WHERE ", column, "=?");
    String sql = buildSelectFirstSql(1, coreSql);

    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      stmt = conn == null ? prepareStatement(sql) : prepareStatement(conn, sql);
      if (value instanceof Integer) {
        stmt.setInt(1, (Integer) value);
      } else if (value instanceof Long) {
        stmt.setLong(1, (Long) value);
      } else if (value instanceof String) {
        stmt.setString(1, (String) value);
      } else {
        stmt.setString(1, value.toString());
      }
      rs = stmt.executeQuery();
      return rs.next();
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, rs, conn == null);
    }
  } // method columnExists

  public boolean tableHasColumn(Connection conn, String table, String column)
      throws DataAccessException {
    Args.notBlank(table, "table");
    Args.notBlank(column, "column");

    String coreSql = StringUtil.concat(column, " FROM ", table);
    final String sql = buildSelectFirstSql(1, coreSql);

    Statement stmt = null;
    try {
      stmt = conn == null ? createStatement() : createStatement(conn);
      stmt.execute(sql);
      return true;
    } catch (SQLException ex) {
      return false;
    } finally {
      releaseResources(stmt, null, conn == null);
    }
  }

  public boolean tableExists(Connection conn, String table) throws DataAccessException {
    Args.notBlank(table, "table");

    final String sql = buildSelectFirstSql(1, StringUtil.concat("1 FROM ", table));
    Statement stmt = null;
    try {
      stmt = conn == null ? createStatement() : createStatement(conn);
      stmt.execute(sql);
      return true;
    } catch (SQLException ex) {
      return false;
    } finally {
      releaseResources(stmt, null, conn == null);
    }
  }

  protected abstract String buildCreateSequenceSql(String sequenceName, long startValue);

  protected abstract String buildDropSequenceSql(String sequenceName);

  protected abstract String buildNextSeqValueSql(String sequenceName);

  protected final String buildAndCacheNextSeqValueSql(String sequenceName) {
    String sql = cacheSeqNameSqls.get(sequenceName);
    if (sql == null) {
      sql = buildNextSeqValueSql(sequenceName);
      cacheSeqNameSqls.put(sequenceName, sql);
    }
    return sql;
  }

  protected boolean isUseSqlStateAsCode() {
    return false;
  }

  public void dropAndCreateSequence(String sequenceName, long startValue)
      throws DataAccessException {
    try {
      dropSequence(sequenceName);
    } catch (DataAccessException ex) {
      LOG.error("could not drop sequence {}: {}", sequenceName, ex.getMessage());
    }

    createSequence(sequenceName, startValue);
  }

  public void createSequence(String sequenceName, long startValue) throws DataAccessException {
    Args.notBlank(sequenceName, "sequenceName");
    final String sql = buildCreateSequenceSql(sequenceName, startValue);
    Statement stmt = null;
    try {
      stmt = createStatement();
      stmt.execute(sql);
      LOG.info("datasource {} CREATESEQ {} START {}", name, sequenceName, startValue);
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, null);
    }
  }

  public void dropSequence(String sequenceName) throws DataAccessException {
    Args.notBlank(sequenceName, "sequenceName");
    final String sql = buildDropSequenceSql(sequenceName);
    Statement stmt = null;
    try {
      stmt = createStatement();
      stmt.execute(sql);
      LOG.info("datasource {} DROPSEQ {}", name, sequenceName);
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, null);
    }
  }

  public void setLastUsedSeqValue(String sequenceName, long sequenceValue) {
    Args.notBlank(sequenceName, "sequenceName");
    lastUsedSeqValues.put(sequenceName, sequenceValue);
  }

  public long nextSeqValue(Connection conn, String sequenceName) throws DataAccessException {
    Args.notBlank(sequenceName, "sequenceName");
    final String sql = buildAndCacheNextSeqValueSql(sequenceName);
    Statement stmt = null;

    long next;
    try {
      stmt = conn == null ? createStatement() : createStatement(conn);

      while (true) {
        ResultSet rs = stmt.executeQuery(sql);
        try {
          if (rs.next()) {
            next = rs.getLong(1);
            synchronized (lastUsedSeqValuesLock) {
              Long lastValue = lastUsedSeqValues.get(sequenceName);
              if (lastValue == null || next > lastValue) {
                lastUsedSeqValues.put(sequenceName, next);
                break;
              }
            }
          } else {
            throw new DataAccessException("could not increment the sequence " + sequenceName);
          }
        } finally {
          releaseResources(null, rs, false);
        }
      }
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, null, conn == null);
    }

    LOG.debug("datasource {} NEXVALUE({}): {}", name, sequenceName, next);
    return next;
  } // method nextSeqValue

  protected String getSqlToDropPrimaryKey(String primaryKeyName, String table) {
    Args.notBlank(primaryKeyName, "primaryKeyName");
    Args.notBlank(table, "table");
    return StringUtil.concat("ALTER TABLE ", table, " DROP PRIMARY KEY ");
  }

  public void dropPrimaryKey(Connection conn, String primaryKeyName, String table)
      throws DataAccessException {
    executeUpdate(conn, getSqlToDropPrimaryKey(primaryKeyName, table));
  }

  protected String getSqlToAddPrimaryKey(String primaryKeyName, String table, String... columns) {
    Args.notBlank(primaryKeyName, "primaryKeyName");
    Args.notBlank(table, "table");

    final StringBuilder sb = new StringBuilder(100);
    sb.append("ALTER TABLE ").append(table);
    sb.append(" ADD CONSTRAINT ").append(primaryKeyName);
    sb.append(" PRIMARY KEY (");
    final int n = columns.length;
    for (int i = 0; i < n; i++) {
      if (i != 0) {
        sb.append(",");
      }
      sb.append(columns[i]);
    }
    sb.append(")");

    return sb.toString();
  }

  public void addPrimaryKey(Connection conn, String primaryKeyName, String table, String... columns)
      throws DataAccessException {
    executeUpdate(conn, getSqlToAddPrimaryKey(primaryKeyName, table, columns));
  }

  protected String getSqlToDropForeignKeyConstraint(String constraintName, String baseTable)
      throws DataAccessException {
    Args.notBlank(constraintName, "constraintName");
    Args.notBlank(baseTable, "baseTable");

    return StringUtil.concat("ALTER TABLE ", baseTable, " DROP CONSTRAINT ", constraintName);
  }

  public void dropForeignKeyConstraint(Connection conn, String constraintName, String baseTable)
      throws DataAccessException {
    executeUpdate(conn, getSqlToDropForeignKeyConstraint(constraintName, baseTable));
  }

  protected String getSqlToAddForeignKeyConstraint(String constraintName, String baseTable,
      String baseColumn, String referencedTable, String referencedColumn, String onDeleteAction,
      String onUpdateAction) {
    Args.notBlank(constraintName, "constraintName");
    Args.notBlank(baseTable, "baseTable");
    Args.notBlank(baseColumn, "baseColumn");
    Args.notBlank(referencedTable, "referencedTable");
    Args.notBlank(referencedColumn, "referencedColumn");
    Args.notBlank(onDeleteAction, "onDeleteAction");
    Args.notBlank(onUpdateAction, "onUpdateAction");

    return StringUtil.concat("ALTER TABLE ", baseTable, " ADD CONSTRAINT ", constraintName,
      " FOREIGN KEY (", baseColumn, ")", " REFERENCES ", referencedTable,
      " (", referencedColumn, ")", " ON DELETE ", onDeleteAction, " ON UPDATE ", onUpdateAction);
  }

  public void addForeignKeyConstraint(Connection conn, String constraintName, String baseTable,
      String baseColumn, String referencedTable, String referencedColumn, String onDeleteAction,
      String onUpdateAction) throws DataAccessException {
    final String sql = getSqlToAddForeignKeyConstraint(constraintName, baseTable, baseColumn,
        referencedTable, referencedColumn, onDeleteAction, onUpdateAction);
    executeUpdate(conn, sql);
  }

  protected String getSqlToDropIndex(String table, String indexName) {
    Args.notBlank(indexName, "indexName");
    return "DROP INDEX " + indexName;
  }

  public void dropIndex(Connection conn, String table, String indexName)
      throws DataAccessException {
    executeUpdate(conn, getSqlToDropIndex(table, indexName));
  }

  protected String getSqlToCreateIndex(String indexName, String table, String... columns) {
    Args.notBlank(indexName, "indexName");
    Args.notBlank(table, "table");
    if (columns == null || columns.length == 0) {
      throw new IllegalArgumentException("columns must not be null and empty");
    }

    final StringBuilder sb = new StringBuilder(200);
    sb.append("CREATE INDEX ").append(indexName);
    sb.append(" ON ").append(table).append("(");
    for (String column : columns) {
      Args.notBlank(column, "column");
      sb.append(column).append(',');
    }
    sb.deleteCharAt(sb.length() - 1); // delete the last ","
    sb.append(")");
    return sb.toString();
  }

  public void createIndex(Connection conn, String indexName, String table, String... columns)
      throws DataAccessException {
    executeUpdate(conn, getSqlToCreateIndex(indexName, table, columns));
  }

  protected String getSqlToDropUniqueConstraint(String constraintName, String table) {
    Args.notBlank(table, "table");
    Args.notBlank(constraintName, "constraintName");

    return StringUtil.concat("ALTER TABLE ", table, " DROP CONSTRAINT ", constraintName);
  }

  public void dropUniqueConstrain(Connection conn, String constraintName, String table)
      throws DataAccessException {
    executeUpdate(conn, getSqlToDropUniqueConstraint(constraintName, table));
  }

  protected String getSqlToAddUniqueConstrain(String constraintName, String table,
      String... columns) {
    Args.notBlank(constraintName, "constraintName");
    Args.notBlank(table, "table");

    final StringBuilder sb = new StringBuilder(100);
    sb.append("ALTER TABLE ").append(table).append(" ADD CONSTRAINT ")
      .append(constraintName).append(" UNIQUE (");
    final int n = columns.length;
    for (int i = 0; i < n; i++) {
      if (i != 0) {
        sb.append(",");
      }
      sb.append(columns[i]);
    }
    return sb.append(")").toString();
  }

  public void addUniqueConstrain(Connection conn, String constraintName,
      String table, String... columns) throws DataAccessException {
    executeUpdate(conn, getSqlToAddUniqueConstrain(constraintName, table, columns));
  }

  public DataAccessException translate(String sql, SQLException ex) {
    Args.notNull(ex, "ex");

    if (sql == null) {
      sql = "";
    }

    SQLException sqlEx = ex;
    if (sqlEx instanceof BatchUpdateException && sqlEx.getNextException() != null) {
      SQLException nestedSqlEx = sqlEx.getNextException();
      if (nestedSqlEx.getErrorCode() > 0 || nestedSqlEx.getSQLState() != null) {
        LOG.debug("Using nested SQLException from the BatchUpdateException");
        sqlEx = nestedSqlEx;
      }
    }

    // Check SQLErrorCodes with corresponding error code, if available.
    String errorCode;
    String sqlState;

    if (sqlErrorCodes.useSqlStateForTranslation) {
      errorCode = sqlEx.getSQLState();
      sqlState = null;
    } else {
      // Try to find SQLException with actual error code, looping through the causes.
      // E.g. applicable to java.sql.DataTruncation as of JDK 1.6.
      SQLException current = sqlEx;
      while (current.getErrorCode() == 0 && current.getCause() instanceof SQLException) {
        current = (SQLException) current.getCause();
      }
      errorCode = Integer.toString(current.getErrorCode());
      sqlState = current.getSQLState();
    }

    if (errorCode != null) {
      // look for grouped error codes.
      if (sqlErrorCodes.badSqlGrammarCodes.contains(errorCode)) {
        logTranslation(sql, sqlEx);
        return new DataAccessException(Reason.BadSqlGrammar, buildMessage(sql, sqlEx), sqlEx);
      } else if (sqlErrorCodes.invalidResultSetAccessCodes.contains(errorCode)) {
        logTranslation(sql, sqlEx);
        return new DataAccessException(Reason.InvalidResultSetAccess,
            buildMessage(sql, sqlEx), sqlEx);
      } else if (sqlErrorCodes.duplicateKeyCodes.contains(errorCode)) {
        logTranslation(sql, sqlEx);
        return new DataAccessException(Reason.DuplicateKey, buildMessage(sql, sqlEx), sqlEx);
      } else if (sqlErrorCodes.dataIntegrityViolationCodes.contains(errorCode)) {
        logTranslation(sql, sqlEx);
        return new DataAccessException(Reason.DataIntegrityViolation,
            buildMessage(sql, sqlEx), sqlEx);
      } else if (sqlErrorCodes.permissionDeniedCodes.contains(errorCode)) {
        logTranslation(sql, sqlEx);
        return new DataAccessException(Reason.PermissionDeniedDataAccess,
            buildMessage(sql, sqlEx), sqlEx);
      } else if (sqlErrorCodes.dataAccessResourceFailureCodes.contains(errorCode)) {
        logTranslation(sql, sqlEx);
        return new DataAccessException(Reason.DataAccessResourceFailure,
            buildMessage(sql, sqlEx), sqlEx);
      } else if (sqlErrorCodes.transientDataAccessResourceCodes.contains(errorCode)) {
        logTranslation(sql, sqlEx);
        return new DataAccessException(Reason.TransientDataAccessResource,
            buildMessage(sql, sqlEx), sqlEx);
      } else if (sqlErrorCodes.cannotAcquireLockCodes.contains(errorCode)) {
        logTranslation(sql, sqlEx);
        return new DataAccessException(Reason.CannotAcquireLock, buildMessage(sql, sqlEx), sqlEx);
      } else if (sqlErrorCodes.deadlockLoserCodes.contains(errorCode)) {
        logTranslation(sql, sqlEx);
        return new DataAccessException(Reason.DeadlockLoserDataAccess,
            buildMessage(sql, sqlEx), sqlEx);
      } else if (sqlErrorCodes.cannotSerializeTransactionCodes.contains(errorCode)) {
        logTranslation(sql, sqlEx);
        return new DataAccessException(Reason.CannotSerializeTransaction,
            buildMessage(sql, sqlEx), sqlEx);
      }
    } // end if (errorCode)

    // try SQLState
    if (sqlState != null && sqlState.length() >= 2) {
      String classCode = sqlState.substring(0, 2);
      if (sqlStateCodes.badSqlGrammarCodes.contains(classCode)) {
        return new DataAccessException(Reason.BadSqlGrammar, buildMessage(sql, sqlEx), ex);
      } else if (sqlStateCodes.dataIntegrityViolationCodes.contains(classCode)) {
        return new DataAccessException(Reason.DataIntegrityViolation, buildMessage(sql, ex), ex);
      } else if (sqlStateCodes.dataAccessResourceFailureCodes.contains(classCode)) {
        return new DataAccessException(Reason.DataAccessResourceFailure, buildMessage(sql, ex), ex);
      } else if (sqlStateCodes.transientDataAccessResourceCodes.contains(classCode)) {
        return new DataAccessException(Reason.TransientDataAccessResource,
            buildMessage(sql, ex), ex);
      } else if (sqlStateCodes.concurrencyFailureCodes.contains(classCode)) {
        return new DataAccessException(Reason.ConcurrencyFailure, buildMessage(sql, ex), ex);
      }
    }

    // For MySQL: exception class name indicating a timeout?
    // (since MySQL doesn't throw the JDBC 4 SQLTimeoutException)
    if (ex.getClass().getName().contains("Timeout")) {
      return new DataAccessException(Reason.QueryTimeout, buildMessage(sql, ex), ex);
    }

    // We couldn't identify it more precisely
    if (LOG.isDebugEnabled()) {
      String codes;
      if (sqlErrorCodes.useSqlStateForTranslation) {
        codes = StringUtil.concatObjectsCap(60, "SQL state '", sqlEx.getSQLState(),
            "', error code '", sqlEx.getErrorCode());
      } else {
        codes = StringUtil.concat("Error code '", Integer.toString(sqlEx.getErrorCode()), "'");
      }
      LOG.debug("Unable to translate SQLException with " + codes);
    }

    return new DataAccessException(Reason.UncategorizedSql, buildMessage(sql, sqlEx), sqlEx);
  } // method translate

  private void logTranslation(String sql, SQLException sqlEx) {
    if (!LOG.isDebugEnabled()) {
      return;
    }

    LOG.debug("Translating SQLException: SQL state '{}', error code '{}', message [{}]; SQL "
        + "was [{}]", sqlEx.getSQLState(), sqlEx.getErrorCode(), sqlEx.getMessage(), sql);
  }

  private String buildMessage(String sql, SQLException ex) {
    String msg = ex.getMessage();
    return msg.contains(sql) ? msg : StringUtil.concat("SQL [", sql, "]; ", msg);
  }

  private void executeUpdate(Connection conn, String sql) throws DataAccessException {
    Statement stmt = null;
    try {
      stmt = conn == null ? createStatement() : createStatement(conn);
      stmt.executeUpdate(sql);
    } catch (SQLException ex) {
      throw translate(sql, ex);
    } finally {
      releaseResources(stmt, null, conn == null);
    }
  }

  static DataSourceWrapper createDataSource(String name, Properties props,
      DatabaseType databaseType) {
    Args.notNull(props, "props");
    Args.notNull(databaseType, "databaseType");

    // The DB2 schema name is case-sensitive, and must be specified in uppercase characters
    String datasourceClassName = props.getProperty("dataSourceClassName");
    if (datasourceClassName != null) {
      if (datasourceClassName.contains(".db2.")) {
        String propName = "dataSource.currentSchema";
        String schema = props.getProperty(propName);
        if (schema != null) {
          String upperCaseSchema = schema.toUpperCase();
          if (!schema.equals(upperCaseSchema)) {
            props.setProperty(propName, upperCaseSchema);
          }
        }
      }
    } else {
      String propName = "jdbcUrl";
      final String url = props.getProperty(propName);
      if (StringUtil.startsWithIgnoreCase(url, "jdbc:db2:")) {
        String sep = ":currentSchema=";
        int idx = url.indexOf(sep);
        if (idx != 1) {
          String schema = url.substring(idx + sep.length());
          if (schema.endsWith(";")) {
            schema = schema.substring(0, schema.length() - 1);
          }

          String upperCaseSchema = schema.toUpperCase();
          if (!schema.equals(upperCaseSchema)) {
            String newUrl = url.replace(sep + schema, sep + upperCaseSchema);
            props.setProperty(propName, newUrl);
          }
        }
      }
    } // end if

    if (databaseType == DatabaseType.DB2 || databaseType == DatabaseType.H2
        || databaseType == DatabaseType.HSQL || databaseType == DatabaseType.MYSQL
        || databaseType == DatabaseType.MARIADB || databaseType == DatabaseType.ORACLE
        || databaseType == DatabaseType.POSTGRES) {
      HikariConfig conf = new HikariConfig(props);
      HikariDataSource service = new HikariDataSource(conf);
      switch (databaseType) {
        case DB2:
          return new DB2(name, service);
        case H2:
          return new H2(name, service);
        case HSQL:
          return new HSQL(name, service);
        case MYSQL:
          return new MySQL(name, service);
        case MARIADB:
          return new MariaDB(name, service);
        case ORACLE:
          return new Oracle(name, service);
        default: // POSTGRESQL:
          return new PostgreSQL(name, service);
      }
    } else {
      throw new IllegalArgumentException("unknown datasource type " + databaseType);
    }
  } // method createDataSource

}
