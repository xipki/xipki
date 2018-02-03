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
import org.xipki.common.LruCache;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.datasource.DataAccessException.Reason;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class DataSourceWrapper {

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
            // 'SELECT ': 7
            // ' LIMIT ': 7
            // rows (till 9999): 4
            int size = coreSql.length() + 18;
            if (StringUtil.isNotBlank(orderBy)) {
                // ' ORDER BY ': 10
                size += 10 + orderBy.length();
            }
            StringBuilder sql = new StringBuilder(size);
            sql.append("SELECT ").append(coreSql);
            if (StringUtil.isNotBlank(orderBy)) {
                sql.append(" ORDER BY ").append(orderBy);
            }
            return sql.append(" LIMIT ").append(rows).toString();
        }

        @Override
        protected String buildCreateSequenceSql(String sequenceName, long startValue) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 75);
            sql.append("INSERT INTO SEQ_TBL (SEQ_NAME,SEQ_VALUE) VALUES('");
            return sql.append(sequenceName).append("', ").append(startValue).append(")").toString();
        }

        @Override
        protected String buildDropSequenceSql(String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 40);
            sql.append("DELETE FROM SEQ_TBL WHERE SEQ_NAME='").append(sequenceName).append("'");
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 75);
            sql.append("UPDATE SEQ_TBL SET SEQ_VALUE=(@cur_value:=SEQ_VALUE)+1 WHERE SEQ_NAME='");
            return sql.append(sequenceName).append("'").toString();
        }

        @Override
        public long nextSeqValue(Connection conn, String sequenceName) throws DataAccessException {
            final String sqlUpdate = buildAndCacheNextSeqValueSql(sequenceName);
            final String sqlSelect = "SELECT @cur_value";
            String sql = null;

            boolean newConn = (conn == null);
            Connection tmpConn = (conn != null) ? conn : getConnection();

            Statement stmt = null;
            ResultSet rs = null;

            long ret;
            try {
                stmt = tmpConn.createStatement();
                sql = sqlUpdate;
                stmt.executeUpdate(sql);

                sql = sqlSelect;
                rs = stmt.executeQuery(sql);
                if (rs.next()) {
                    ret = rs.getLong(1);
                } else {
                    throw new DataAccessException(
                            "could not increment the sequence " + sequenceName);
                }
            } catch (SQLException ex) {
                throw translate(sqlUpdate, ex);
            } finally {
                if (newConn) {
                    releaseResources(stmt, rs);
                } else {
                    super.releaseStatementAndResultSet(stmt, rs);
                }
            }

            LOG.debug("datasource {} NEXVALUE({}): {}", name, sequenceName, ret);
            return ret;
        } // method nextSeqValue

        @Override
        protected String getSqlToDropForeignKeyConstraint(String constraintName,
                String baseTable) throws DataAccessException {
            StringBuilder sb = new StringBuilder(baseTable.length() + constraintName.length() + 30);
            return sb.append("ALTER TABLE ").append(baseTable).append(" DROP FOREIGN KEY ")
                    .append(constraintName).toString();
        }

        @Override
        protected String getSqlToDropIndex(String table, String indexName) {
            StringBuilder sb = new StringBuilder(indexName.length() + table.length() + 15);
            return sb.append("DROP INDEX ").append(indexName).append(" ON ").append(table)
                    .toString();
        }

        @Override
        protected String getSqlToDropUniqueConstraint(String constraintName, String table) {
            StringBuilder sb = new StringBuilder(constraintName.length() + table.length() + 22);
            return sb.append("ALTER TABLE ").append(table).append(" DROP KEY ")
                    .append(constraintName).toString();
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
            // 'SELECT ': 7
            // ' FETCH FIRST ': 15
            // ' ROWS ONLY' : 10
            // rows (till 9999): 4
            int size = coreSql.length() + 36;
            if (StringUtil.isNotBlank(orderBy)) {
                // ' ORDER BY ': 10
                size += 10 + orderBy.length();
            }
            StringBuilder sql = new StringBuilder(size);

            sql.append("SELECT ").append(coreSql);

            if (StringUtil.isNotBlank(orderBy)) {
                sql.append(" ORDER BY ").append(orderBy);
            }

            return sql.append(" FETCH FIRST ").append(rows).append(" ROWS ONLY").toString();
        }

        @Override
        protected String buildCreateSequenceSql(String sequenceName, long startValue) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("CREATE SEQUENCE ").append(sequenceName).append(" AS BIGINT START WITH ");
            return sql.append(startValue).append(" INCREMENT BY 1 NO CYCLE NO CACHE").toString();
        }

        @Override
        protected String buildDropSequenceSql(String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 14);
            return sql.append("DROP SEQUENCE ").append(sequenceName).toString();
        }

        @Override
        protected String buildNextSeqValueSql(String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 44);
            sql.append("SELECT NEXT VALUE FOR ").append(sequenceName)
                .append(" FROM sysibm.sysdummy1");
            return sql.toString();
        }

    } // class DB2

    // CHECKSTYLE:SKIP
    private static class PostgreSQL extends DataSourceWrapper {

        PostgreSQL(String name, HikariDataSource service) {
            super(name, service, DatabaseType.POSTGRES);
        }

        @Override
        public String buildSelectFirstSql(int rows, String orderBy, String coreSql) {
            // 'SELECT ': 7
            // ' FETCH FIRST ': 13
            // ' ROWS ONLY': 10
            // rows (till 9999): 4
            int size = coreSql.length() + 34;
            if (StringUtil.isNotBlank(orderBy)) {
                // ' ORDER BY ': 10
                size += 10 + orderBy.length();
            }
            StringBuilder sql = new StringBuilder(size);

            sql.append("SELECT ").append(coreSql);

            if (StringUtil.isNotBlank(orderBy)) {
                sql.append(" ORDER BY ").append(orderBy);
            }

            return sql.append(" FETCH FIRST ").append(rows).append(" ROWS ONLY").toString();
        }

        @Override
        protected String buildCreateSequenceSql(String sequenceName, long startValue) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 70);
            sql.append("CREATE SEQUENCE ").append(sequenceName).append(" START WITH ");
            return sql.append(startValue).append(" INCREMENT BY 1 NO CYCLE").toString();
        }

        @Override
        protected String buildDropSequenceSql(String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 14);
            return sql.append("DROP SEQUENCE ").append(sequenceName).toString();
        }

        @Override
        protected String buildNextSeqValueSql(String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            return sql.append("SELECT NEXTVAL ('").append(sequenceName).append("')").toString();
        }

        @Override
        protected boolean isUseSqlStateAsCode() {
            return true;
        }

        @Override
        protected String getSqlToDropPrimaryKey(String primaryKeyName, String table) {
            StringBuilder sb = new StringBuilder(500);
            sb.append("DO $$ DECLARE constraint_name varchar;\n");
            sb.append("BEGIN\n");
            sb.append("  SELECT tc.CONSTRAINT_NAME into strict constraint_name\n");
            sb.append("  FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc\n");
            sb.append("  WHERE CONSTRAINT_TYPE='PRIMARY KEY'\n");
            sb.append("  AND TABLE_NAME='").append(table.toLowerCase())
                    .append("' AND TABLE_SCHEMA='public';\n");
            sb.append("  EXECUTE 'alter table public.").append(table.toLowerCase())
                    .append(" drop constraint ' || constraint_name;\n");
            sb.append("END $$;");
            return sb.toString();
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
            int size = coreSql.length() + 18;
            size += StringUtil.isBlank(orderBy) ? 14 : orderBy.length() + 40;

            // ' ROWNUM < ': 10
            // rows (till 9999): 4
            size += 14;
            StringBuilder sql = new StringBuilder(size);

            if (StringUtil.isBlank(orderBy)) {
                sql.append("SELECT ").append(coreSql);
                sql.append(coreSql.contains(" WHERE") ? " AND" : " WHERE");
            } else {
                sql.append("SELECT * FROM (SELECT ").append(coreSql);
                sql.append(" ORDER BY ").append(orderBy).append(" ) WHERE");
            }

            return sql.append(" ROWNUM<").append(rows + 1).toString();
        }

        @Override
        protected String buildCreateSequenceSql(String sequenceName, long startValue) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 59);
            sql.append("CREATE SEQUENCE ").append(sequenceName);
            sql.append(" START WITH ").append(startValue);
            return sql.append(" INCREMENT BY 1 NOCYCLE NOCACHE").toString();
        }

        @Override
        protected String buildDropSequenceSql(String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 14);
            return sql.append("DROP SEQUENCE ").append(sequenceName).toString();
        }

        @Override
        protected String buildNextSeqValueSql(String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 21);
            sql.append("SELECT ").append(sequenceName).append(".NEXTVAL FROM DUAL");
            return sql.toString();
        }

        @Override
        protected String getSqlToDropPrimaryKey(String primaryKeyName, String table) {
            return getSqlToDropUniqueConstraint(primaryKeyName, table);
        }

        @Override
        protected String getSqlToDropUniqueConstraint(String contraintName, String table) {
            StringBuilder sql = new StringBuilder(table.length() + contraintName.length() + 40);
            return sql.append("ALTER TABLE ").append(table)
                    .append(" DROP CONSTRAINT ").append(contraintName)
                    .append(" DROP INDEX").toString();
        }

        @Override
        protected String getSqlToAddForeignKeyConstraint(String constraintName,
                String baseTable, String baseColumn, String referencedTable,
                String referencedColumn, String onDeleteAction, String onUpdateAction) {
            final StringBuilder sb = new StringBuilder(100);
            sb.append("ALTER TABLE ").append(baseTable);
            sb.append(" ADD CONSTRAINT ").append(constraintName);
            sb.append(" FOREIGN KEY (").append(baseColumn).append(")");
            sb.append(" REFERENCES ").append(referencedTable);
            sb.append(" (").append(referencedColumn).append(")");
            return sb.append(" ON DELETE ").append(onDeleteAction).toString();
        }

        @Override
        protected String getSqlToAddPrimaryKey(String primaryKeyName, String table,
                String... columns) {
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
            // 'SELECT ': 7
            // ' LIMIT ': 7
            // rows (till 9999): 4
            int size = coreSql.length() + 18;
            if (StringUtil.isNotBlank(orderBy)) {
                // ' ORDER BY ': 10
                size += 10 + orderBy.length();
            }
            StringBuilder sql = new StringBuilder(size);

            sql.append("SELECT ").append(coreSql);

            if (StringUtil.isNotBlank(orderBy)) {
                sql.append(" ORDER BY ").append(orderBy);
            }

            sql.append(" LIMIT ").append(rows);
            return sql.toString();
        }

        @Override
        protected String buildCreateSequenceSql(String sequenceName, long startValue) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("CREATE SEQUENCE ").append(sequenceName);
            sql.append(" START WITH ").append(startValue);
            return sql.append(" INCREMENT BY 1 NO CYCLE NO CACHE").toString();
        }

        @Override
        protected String buildDropSequenceSql(String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 14);
            return sql.append("DROP SEQUENCE ").append(sequenceName).toString();
        }

        @Override
        protected String buildNextSeqValueSql(String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            return sql.append("SELECT NEXTVAL ('").append(sequenceName).append("')").toString();
        }

    } // class H2

    // CHECKSTYLE:SKIP
    private static class HSQL extends DataSourceWrapper {

        HSQL(String name, HikariDataSource service) {
            super(name, service, DatabaseType.HSQL);
        }

        @Override
        public String buildSelectFirstSql(int rows, String orderBy, String coreSql) {
            // 'SELECT ': 7
            // ' LIMIT ': 7
            // rows (till 9999): 4
            int size = coreSql.length() + 18;
            if (StringUtil.isNotBlank(orderBy)) {
                // ' ORDER BY ': 10
                size += 10 + orderBy.length();
            }
            StringBuilder sql = new StringBuilder(size);

            sql.append("SELECT ").append(coreSql);

            if (StringUtil.isNotBlank(orderBy)) {
                sql.append(" ORDER BY ").append(orderBy);
            }

            return sql.append(" LIMIT ").append(rows).toString();
        }

        @Override
        protected String buildCreateSequenceSql(String sequenceName, long startValue) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 70);
            sql.append("CREATE SEQUENCE ").append(sequenceName);
            sql.append(" AS BIGINT START WITH ").append(startValue);
            return sql.append(" INCREMENT BY 1").toString();
        }

        @Override
        protected String buildDropSequenceSql(String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 14);
            return sql.append("DROP SEQUENCE ").append(sequenceName).toString();
        }

        @Override
        protected String buildNextSeqValueSql(String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            return sql.append("SELECT NEXTVAL ('").append(sequenceName).append("')").toString();
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
        this.service = ParamUtil.requireNonNull("service", service);
        this.databaseType = ParamUtil.requireNonNull("dbType", dbType);
        this.name = name;
        this.sqlErrorCodes = SqlErrorCodes.newInstance(dbType);
        this.sqlStateCodes = SqlStateCodes.newInstance(dbType);
        this.cacheSeqNameSqls = new LruCache<>(100);
    }

    public final String datasourceName() {
        return name;
    }

    public final DatabaseType databaseType() {
        return this.databaseType;
    }

    public final int maximumPoolSize() {
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

    public void close() {
        try {
            service.close();
        } catch (Exception ex) {
            LOG.warn("could not close datasource: {}", ex.getMessage());
            LOG.debug("could not close datasource", ex);
        }
    }

    public final PrintWriter getLogWriter() throws SQLException {
        return service.getLogWriter();
    }

    public Statement createStatement(Connection conn) throws DataAccessException {
        ParamUtil.requireNonNull("conn", conn);
        try {
            return conn.createStatement();
        } catch (SQLException ex) {
            throw translate(null, ex);
        }
    }

    public PreparedStatement prepareStatement(Connection conn, String sqlQuery)
            throws DataAccessException {
        ParamUtil.requireNonNull("conn", conn);
        try {
            return conn.prepareStatement(sqlQuery);
        } catch (SQLException ex) {
            throw translate(sqlQuery, ex);
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

        if (ps != null) {
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
                if (returnConnection && conn != null) {
                    returnConnection(conn);
                }
            }
        }
    }

    private void releaseStatementAndResultSet(Statement ps, ResultSet rs) {
        if (rs != null) {
            try {
                rs.close();
            } catch (Throwable th) {
                LOG.warn("could not close ResultSet", th);
            }
        }

        if (ps != null) {
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
            stmt = (conn != null) ? conn.createStatement() : getConnection().createStatement();
            rs = stmt.executeQuery(sql);
            if (rs.next()) {
                return rs.getObject(column, type);
            } else {
                return null;
            }
        } catch (SQLException ex) {
            throw translate(sql, ex);
        } finally {
            if (conn == null) {
                releaseResources(stmt, rs);
            } else {
                releaseStatementAndResultSet(stmt, rs);
            }
        }
    }

    public long getMin(Connection conn, String table, String column) throws DataAccessException {
        return getMin(conn, table, column, null);
    }

    public long getMin(Connection conn, String table, String column, String condition)
            throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);
        ParamUtil.requireNonBlank("column", column);

        int size = column.length() + table.length() + 20;
        if (StringUtil.isNotBlank(condition)) {
            size += 7 + condition.length();
        }

        StringBuilder sqlBuilder = new StringBuilder(size);
        sqlBuilder.append("SELECT MIN(").append(column).append(") FROM ").append(table);
        if (StringUtil.isNotBlank(condition)) {
            sqlBuilder.append(" WHERE ").append(condition);
        }

        final String sql = sqlBuilder.toString();

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = (conn != null) ? conn.createStatement() : getConnection().createStatement();
            rs = stmt.executeQuery(sql);
            rs.next();
            return rs.getLong(1);
        } catch (SQLException ex) {
            throw translate(sql, ex);
        } finally {
            if (conn == null) {
                releaseResources(stmt, rs);
            } else {
                releaseStatementAndResultSet(stmt, rs);
            }
        }
    }

    public int getCount(Connection conn, String table) throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);

        StringBuilder sqlBuilder = new StringBuilder(table.length() + 21);
        sqlBuilder.append("SELECT COUNT(*) FROM ").append(table);
        final String sql = sqlBuilder.toString();

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = (conn != null) ? conn.createStatement() : getConnection().createStatement();
            rs = stmt.executeQuery(sql);
            rs.next();
            return rs.getInt(1);
        } catch (SQLException ex) {
            throw translate(sql, ex);
        } finally {
            if (conn == null) {
                releaseResources(stmt, rs);
            } else {
                releaseStatementAndResultSet(stmt, rs);
            }
        }
    }

    public long getMax(Connection conn, String table, String column) throws DataAccessException {
        return getMax(conn, table, column, null);
    }

    public long getMax(Connection conn, String table, String column, String condition)
            throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);
        ParamUtil.requireNonBlank("column", column);
        int size = column.length() + table.length() + 20;
        if (StringUtil.isNotBlank(condition)) {
            size += 7 + condition.length();
        }

        StringBuilder sqlBuilder = new StringBuilder(size);
        sqlBuilder.append("SELECT MAX(").append(column).append(") FROM ").append(table);
        if (StringUtil.isNotBlank(condition)) {
            sqlBuilder.append(" WHERE ").append(condition);
        }
        final String sql = sqlBuilder.toString();

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = (conn != null) ? conn.createStatement() : getConnection().createStatement();
            rs = stmt.executeQuery(sql);
            rs.next();
            return rs.getLong(1);
        } catch (SQLException ex) {
            throw translate(sql, ex);
        } finally {
            if (conn == null) {
                releaseResources(stmt, rs);
            } else {
                releaseStatementAndResultSet(stmt, rs);
            }
        }
    }

    public boolean deleteFromTable(Connection conn, String table, String idColumn, long id) {
        ParamUtil.requireNonBlank("table", table);
        ParamUtil.requireNonBlank("idColumn", idColumn);
        final StringBuilder sb = new StringBuilder(table.length() + idColumn.length() + 35);
        sb.append("DELETE FROM ").append(table).append(" WHERE ")
            .append(idColumn).append("=").append(id);
        final String sql = sb.toString();

        Connection tmpConn;
        if (conn != null) {
            tmpConn = conn;
        } else {
            try {
                tmpConn = getConnection();
            } catch (Throwable th) {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("datasource {} could not get connection: {}", name, th.getMessage());
                }
                return false;
            }
        }

        Statement stmt = null;
        try {
            stmt = tmpConn.createStatement();
            stmt.execute(sql);
        } catch (Throwable th) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("datasource {} could not deletefrom table {}: {}", name, table,
                        th.getMessage());
            }
            return false;
        } finally {
            if (conn == null) {
                releaseResources(stmt, null);
            } else {
                releaseStatementAndResultSet(stmt, null);
            }
        }

        return true;
    }

    public boolean columnExists(Connection conn, String table, String column, Object value)
            throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);
        ParamUtil.requireNonBlank("column", column);
        ParamUtil.requireNonNull("value", value);

        StringBuilder sb = new StringBuilder(2 * column.length() + 15);
        sb.append(column).append(" FROM ").append(table);
        sb.append(" WHERE ").append(column).append("=?");
        String sql = buildSelectFirstSql(1, sb.toString());

        PreparedStatement stmt = null;
        ResultSet rs = null;
        try {
            stmt = (conn != null) ? conn.prepareStatement(sql)
                    : getConnection().prepareStatement(sql);
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
            if (conn == null) {
                releaseResources(stmt, rs);
            } else {
                releaseStatementAndResultSet(stmt, rs);
            }
        }
    } // method columnExists

    public boolean tableHasColumn(Connection conn, String table, String column)
            throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);
        ParamUtil.requireNonBlank("column", column);

        Statement stmt;
        try {
            stmt = (conn != null) ? conn.createStatement() : getConnection().createStatement();
        } catch (SQLException ex) {
            throw translate(null, ex);
        }

        StringBuilder sqlBuilder = new StringBuilder(column.length() + table.length() + 20);
        sqlBuilder.append(column).append(" FROM ").append(table);
        final String sql = buildSelectFirstSql(1, sqlBuilder.toString());

        try {
            stmt.execute(sql);
            return true;
        } catch (SQLException ex) {
            return false;
        } finally {
            if (conn == null) {
                releaseResources(stmt, null);
            } else {
                releaseStatementAndResultSet(stmt, null);
            }
        }
    }

    public boolean tableExists(Connection conn, String table) throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);

        Statement stmt;
        try {
            stmt = (conn != null) ? conn.createStatement() : getConnection().createStatement();
        } catch (SQLException ex) {
            throw translate(null, ex);
        }

        StringBuilder sqlBuilder = new StringBuilder(table.length() + 10);
        sqlBuilder.append("1 FROM ").append(table);
        final String sql = buildSelectFirstSql(1, sqlBuilder.toString());

        try {
            stmt.execute(sql);
            return true;
        } catch (SQLException ex) {
            return false;
        } finally {
            if (conn == null) {
                releaseResources(stmt, null);
            } else {
                releaseStatementAndResultSet(stmt, null);
            }
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
        ParamUtil.requireNonBlank("sequenceName", sequenceName);
        final String sql = buildCreateSequenceSql(sequenceName, startValue);
        Connection conn = getConnection();
        Statement stmt = null;
        try {
            stmt = conn.createStatement();
            stmt.execute(sql);
            LOG.info("datasource {} CREATESEQ {} START {}", name, sequenceName, startValue);
        } catch (SQLException ex) {
            throw translate(sql, ex);
        } finally {
            releaseResources(stmt, null);
        }

    }

    public void dropSequence(String sequenceName) throws DataAccessException {
        ParamUtil.requireNonBlank("sequenceName", sequenceName);
        final String sql = buildDropSequenceSql(sequenceName);
        Connection conn = getConnection();
        Statement stmt = null;
        try {
            stmt = conn.createStatement();
            stmt.execute(sql);
            LOG.info("datasource {} DROPSEQ {}", name, sequenceName);
        } catch (SQLException ex) {
            throw translate(sql, ex);
        } finally {
            releaseResources(stmt, null);
        }
    }

    public void setLastUsedSeqValue(String sequenceName, long sequenceValue) {
        ParamUtil.requireNonBlank("sequenceName", sequenceName);
        lastUsedSeqValues.put(sequenceName, sequenceValue);
    }

    public long nextSeqValue(Connection conn, String sequenceName) throws DataAccessException {
        ParamUtil.requireNonBlank("sequenceName", sequenceName);
        final String sql = buildAndCacheNextSeqValueSql(sequenceName);
        boolean newConn = (conn == null);
        Connection tmpConn = (conn != null) ? conn : getConnection();
        Statement stmt = null;

        long next;
        try {
            stmt = tmpConn.createStatement();

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
                        throw new DataAccessException(
                                "could not increment the sequence " + sequenceName);
                    }
                } finally {
                    releaseStatementAndResultSet(null, rs);
                }
            }
        } catch (SQLException ex) {
            throw translate(sql, ex);
        } finally {
            if (newConn) {
                releaseResources(stmt, null);
            } else {
                releaseStatementAndResultSet(stmt, null);
            }
        }

        LOG.debug("datasource {} NEXVALUE({}): {}", name, sequenceName, next);
        return next;
    } // method nextSeqValue

    protected String getSqlToDropPrimaryKey(String primaryKeyName, String table) {
        ParamUtil.requireNonBlank("primaryKeyName", primaryKeyName);
        ParamUtil.requireNonBlank("table", table);
        StringBuilder sql = new StringBuilder(table.length() + 30);
        return sql.append("ALTER TABLE ").append(table).append(" DROP PRIMARY KEY ").toString();
    }

    public void dropPrimaryKey(Connection conn, String primaryKeyName, String table)
            throws DataAccessException {
        executeUpdate(conn, getSqlToDropPrimaryKey(primaryKeyName, table));
    }

    protected String getSqlToAddPrimaryKey(String primaryKeyName, String table, String... columns) {
        ParamUtil.requireNonBlank("primaryKeyName", primaryKeyName);
        ParamUtil.requireNonBlank("table", table);

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

    public void addPrimaryKey(Connection conn, String primaryKeyName,
            String table, String... columns) throws DataAccessException {
        executeUpdate(conn, getSqlToAddPrimaryKey(primaryKeyName, table, columns));
    }

    protected String getSqlToDropForeignKeyConstraint(String constraintName,
            String baseTable) throws DataAccessException {
        ParamUtil.requireNonBlank("constraintName", constraintName);
        ParamUtil.requireNonBlank("baseTable", baseTable);

        StringBuilder sb = new StringBuilder(baseTable.length() + constraintName.length() + 30);
        return sb.append("ALTER TABLE ").append(baseTable).append(" DROP CONSTRAINT ")
                .append(constraintName).toString();
    }

    public void dropForeignKeyConstraint(Connection conn, String constraintName,
            String baseTable) throws DataAccessException {
        executeUpdate(conn, getSqlToDropForeignKeyConstraint(constraintName, baseTable));
    }

    protected String getSqlToAddForeignKeyConstraint(String constraintName,
            String baseTable, String baseColumn, String referencedTable,
            String referencedColumn, String onDeleteAction, String onUpdateAction) {
        ParamUtil.requireNonBlank("constraintName", constraintName);
        ParamUtil.requireNonBlank("baseTable", baseTable);
        ParamUtil.requireNonBlank("baseColumn", baseColumn);
        ParamUtil.requireNonBlank("referencedTable", referencedTable);
        ParamUtil.requireNonBlank("referencedColumn", referencedColumn);
        ParamUtil.requireNonBlank("onDeleteAction", onDeleteAction);
        ParamUtil.requireNonBlank("onUpdateAction", onUpdateAction);

        final StringBuilder sb = new StringBuilder(100);
        sb.append("ALTER TABLE ").append(baseTable);
        sb.append(" ADD CONSTRAINT ").append(constraintName);
        sb.append(" FOREIGN KEY (").append(baseColumn).append(")");
        sb.append(" REFERENCES ").append(referencedTable);
        sb.append(" (").append(referencedColumn).append(")");
        sb.append(" ON DELETE ").append(onDeleteAction);
        sb.append(" ON UPDATE ").append(onUpdateAction);
        return sb.toString();
    }

    public void addForeignKeyConstraint(Connection conn, String constraintName,
            String baseTable, String baseColumn, String referencedTable,
            String referencedColumn, String onDeleteAction, String onUpdateAction)
            throws DataAccessException {
        final String sql = getSqlToAddForeignKeyConstraint(constraintName, baseTable, baseColumn,
                referencedTable, referencedColumn, onDeleteAction, onUpdateAction);
        executeUpdate(conn, sql);
    }

    protected String getSqlToDropIndex(String table, String indexName) {
        ParamUtil.requireNonBlank("indexName", indexName);
        return "DROP INDEX " + indexName;
    }

    public void dropIndex(Connection conn, String table, String indexName)
            throws DataAccessException {
        executeUpdate(conn, getSqlToDropIndex(table, indexName));
    }

    protected String getSqlToCreateIndex(String indexName, String table, String... columns) {
        ParamUtil.requireNonBlank("indexName", indexName);
        ParamUtil.requireNonBlank("table", table);
        if (columns == null || columns.length == 0) {
            throw new IllegalArgumentException("columns must not be null and empty");
        }

        final StringBuilder sb = new StringBuilder(200);
        sb.append("CREATE INDEX ").append(indexName);
        sb.append(" ON ").append(table).append("(");
        for (String column : columns) {
            ParamUtil.requireNonBlank("column", column);
            sb.append(column).append(',');
        }
        sb.deleteCharAt(sb.length() - 1); // delete the last ","
        sb.append(")");
        return sb.toString();
    }

    public void createIndex(Connection conn, String indexName, String table,
            String... columns) throws DataAccessException {
        executeUpdate(conn, getSqlToCreateIndex(indexName, table, columns));
    }

    protected String getSqlToDropUniqueConstraint(String constraintName, String table) {
        ParamUtil.requireNonBlank("table", table);
        ParamUtil.requireNonBlank("constraintName", constraintName);

        StringBuilder sb = new StringBuilder(table.length() + constraintName.length() + 30);
        return sb.append("ALTER TABLE ").append(table).append(" DROP CONSTRAINT ")
                .append(constraintName).toString();
    }

    public void dropUniqueConstrain(Connection conn, String constraintName, String table)
            throws DataAccessException {
        executeUpdate(conn, getSqlToDropUniqueConstraint(constraintName, table));
    }

    protected String getSqlToAddUniqueConstrain(String constraintName, String table,
            String... columns) {
        ParamUtil.requireNonBlank("constraintName", constraintName);
        ParamUtil.requireNonBlank("table", table);

        final StringBuilder sb = new StringBuilder(100);
        sb.append("ALTER TABLE ").append(table);
        sb.append(" ADD CONSTRAINT ").append(constraintName);
        sb.append(" UNIQUE (");
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

    public void addUniqueConstrain(Connection conn, String constraintName,
            String table, String... columns) throws DataAccessException {
        executeUpdate(conn, getSqlToAddUniqueConstrain(constraintName, table, columns));
    }

    public DataAccessException translate(String sql, SQLException ex) {
        ParamUtil.requireNonNull("ex", ex);

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
                return new DataAccessException(Reason.BadSqlGrammar,
                        buildMessage(sql, sqlEx), sqlEx);
            } else if (sqlErrorCodes.invalidResultSetAccessCodes.contains(errorCode)) {
                logTranslation(sql, sqlEx);
                return new DataAccessException(Reason.InvalidResultSetAccess,
                        buildMessage(sql, sqlEx), sqlEx);
            } else if (sqlErrorCodes.duplicateKeyCodes.contains(errorCode)) {
                logTranslation(sql, sqlEx);
                return new DataAccessException(Reason.DuplicateKey,
                        buildMessage(sql, sqlEx), sqlEx);
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
                return new DataAccessException(Reason.CannotAcquireLock,
                        buildMessage(sql, sqlEx), sqlEx);
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
                return new DataAccessException(Reason.BadSqlGrammar,
                        buildMessage(sql, sqlEx), ex);
            } else if (sqlStateCodes.dataIntegrityViolationCodes.contains(classCode)) {
                return new DataAccessException(Reason.DataIntegrityViolation,
                        buildMessage(sql, ex), ex);
            } else if (sqlStateCodes.dataAccessResourceFailureCodes.contains(classCode)) {
                return new DataAccessException(Reason.DataAccessResourceFailure,
                        buildMessage(sql, ex), ex);
            } else if (sqlStateCodes.transientDataAccessResourceCodes.contains(classCode)) {
                return new DataAccessException(Reason.TransientDataAccessResource,
                        buildMessage(sql, ex), ex);
            } else if (sqlStateCodes.concurrencyFailureCodes.contains(classCode)) {
                return new DataAccessException(Reason.ConcurrencyFailure,
                        buildMessage(sql, ex), ex);
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
                codes = new StringBuilder(60).append("SQL state '").append(sqlEx.getSQLState())
                        .append("', error code '").append(sqlEx.getErrorCode()).toString();
            } else {
                codes = "Error code '" + sqlEx.getErrorCode() + "'";
            }
            LOG.debug("Unable to translate SQLException with " + codes);
        }

        return new DataAccessException(Reason.UncategorizedSql, buildMessage(sql, sqlEx), sqlEx);
    } // method translate

    private void logTranslation(String sql, SQLException sqlEx) {
        if (!LOG.isDebugEnabled()) {
            return;
        }

        LOG.debug(
            "Translating SQLException: SQL state '{}', error code '{}', message [{}]; SQL was [{}]",
            sqlEx.getSQLState(), sqlEx.getErrorCode(), sqlEx.getMessage(), sql);
    }

    private String buildMessage(String sql, SQLException ex) {
        String msg = ex.getMessage();
        StringBuilder sb = new StringBuilder(msg.length() + sql.length() + 8);
        return sb.append("SQL [").append(sql).append("]; ").append(ex.getMessage()).toString();
    }

    private void executeUpdate(Connection conn, String sql) throws DataAccessException {
        Statement stmt = null;
        try {
            stmt = (conn != null) ? conn.createStatement() : getConnection().createStatement();
            stmt.executeUpdate(sql);
        } catch (SQLException ex) {
            throw translate(sql, ex);
        } finally {
            if (conn == null) {
                releaseResources(stmt, null);
            } else {
                releaseStatementAndResultSet(stmt, null);
            }
        }
    }

    static DataSourceWrapper createDataSource(String name, Properties props,
            DatabaseType databaseType) {
        ParamUtil.requireNonNull("props", props);
        ParamUtil.requireNonNull("databaseType", databaseType);

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
