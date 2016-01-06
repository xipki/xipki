/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.datasource.impl;

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
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.DatabaseType;
import org.xipki.datasource.api.exception.BadSqlGrammarException;
import org.xipki.datasource.api.exception.CannotAcquireLockException;
import org.xipki.datasource.api.exception.CannotSerializeTransactionException;
import org.xipki.datasource.api.exception.ConcurrencyFailureException;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.datasource.api.exception.DataAccessResourceFailureException;
import org.xipki.datasource.api.exception.DataIntegrityViolationException;
import org.xipki.datasource.api.exception.DeadlockLoserDataAccessException;
import org.xipki.datasource.api.exception.DuplicateKeyException;
import org.xipki.datasource.api.exception.InvalidResultSetAccessException;
import org.xipki.datasource.api.exception.PermissionDeniedDataAccessException;
import org.xipki.datasource.api.exception.QueryTimeoutException;
import org.xipki.datasource.api.exception.TransientDataAccessResourceException;
import org.xipki.datasource.api.exception.UncategorizedSQLException;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

/**
 * @author Lijun Liao
 */

public abstract class DataSourceWrapperImpl implements DataSourceWrapper {
    private static final Logger LOG = LoggerFactory.getLogger(DataSourceWrapperImpl.class);
    private final ConcurrentHashMap<String, Long> lastUsedSeqValues
            = new ConcurrentHashMap<String, Long>();

    private static class MySQL extends DataSourceWrapperImpl {
        MySQL(
                final String name,
                final HikariDataSource service) {
            super(name, service, DatabaseType.MYSQL);
        }

        @Override
        public final DatabaseType getDatabaseType() {
            return DatabaseType.MYSQL;
        }

        @Override
        public String createFetchFirstSelectSQL(
                final String coreSql,
                final int rows,
                final String orderBy) {
            StringBuilder sql = new StringBuilder(coreSql.length() + 50);
            sql.append("SELECT ").append(coreSql);

            if (StringUtil.isNotBlank(orderBy)) {
                sql.append(" ORDER BY ").append(orderBy);
            }

            sql.append(" LIMIT ").append(rows);
            return sql.toString();
        }

        @Override
        protected String buildCreateSequenceSql(
                final String sequenceName,
                final long startValue) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("INSERT INTO SEQ_TBL (SEQ_NAME, SEQ_VALUE) VALUES('");
            sql.append(sequenceName).append("', ").append(startValue).append(")");
            return sql.toString();
        }

        @Override
        protected String buildDropSequenceSql(
                final String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 40);
            sql.append("DELETE FROM SEQ_TBL WHERE SEQ_NAME='").append(sequenceName).append("'");
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(
                final String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 100);
            sql.append("UPDATE SEQ_TBL SET SEQ_VALUE=(@cur_value:=SEQ_VALUE)+1 WHERE SEQ_NAME = '");
            sql.append(sequenceName).append("'");
            return sql.toString();
        }

        @Override
        public long nextSeqValue(
                Connection conn,
                final String sequenceName)
        throws DataAccessException {
            final String sqlUpdate = buildNextSeqValueSql(sequenceName);
            final String SQL_SELECT = "SELECT @cur_value";
            String sql = null;

            boolean newConn = conn == null;
            if (newConn) {
                conn = getConnection();
            }
            Statement stmt = null;
            ResultSet rs = null;

            long ret;
            try {
                stmt = conn.createStatement();
                sql = sqlUpdate;
                stmt.executeUpdate(sql);

                sql = SQL_SELECT;
                rs = stmt.executeQuery(sql);
                if (rs.next()) {
                    ret = rs.getLong(1);
                } else {
                    throw new DataAccessException(
                            "could not increment the sequence " + sequenceName);
                }
            } catch (SQLException e) {
                throw translate(sqlUpdate, e);
            } finally {
                if (newConn) {
                    releaseResources(stmt, rs);
                } else {
                    super.releaseStatementAndResultSet(stmt, rs);
                }
            }

            LOG.debug("datasource {} NEXVALUE({}): {}", name, sequenceName, ret);
            return ret;
        }

        @Override
        protected String getSqlToDropForeignKeyConstraint(
                final String constraintName,
                final String baseTable)
        throws DataAccessException {
            return "ALTER TABLE " + baseTable + " DROP FOREIGN KEY " + constraintName;
        }

        @Override
        protected String getSqlToDropIndex(
                final String table,
                final String indexName) {
            return "DROP INDEX " + indexName + " ON " + table;
        }

        @Override
        protected String getSqlToDropUniqueConstraint(
                final String constraintName,
                final String table) {
            return "ALTER TABLE " + table + " DROP KEY " + constraintName;
        }

    }

    private static class DB2 extends DataSourceWrapperImpl {
        DB2(
                final String name,
                final HikariDataSource service) {
            super(name, service, DatabaseType.DB2);
        }

        @Override
        public final DatabaseType getDatabaseType() {
            return DatabaseType.DB2;
        }

        @Override
        public String createFetchFirstSelectSQL(
                final String coreSql,
                final int rows,
                final String orderBy) {
            StringBuilder sql = new StringBuilder(coreSql.length() + 50);
            sql.append("SELECT ").append(coreSql);

            if (StringUtil.isNotBlank(orderBy)) {
                sql.append(" ORDER BY ").append(orderBy);
            }

            sql.append(" FETCH FIRST ").append(rows).append(" ROWS ONLY");
            return sql.toString();
        }

        @Override
        protected String buildCreateSequenceSql(
                final String sequenceName,
                final long startValue) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("CREATE SEQUENCE ").append(sequenceName);
            sql.append(" AS BIGINT START WITH ").append(startValue);
            sql.append(" INCREMENT BY 1 NO CYCLE NO CACHE");
            return sql.toString();
        }

        @Override
        protected String buildDropSequenceSql(
                final String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("DROP SEQUENCE ").append(sequenceName);
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(
                final String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 50);
            sql.append("SELECT NEXT VALUE FOR ")
                .append(sequenceName)
                .append(" FROM sysibm.sysdummy1");
            return sql.toString();
        }

    }

    private static class PostgreSQL extends DataSourceWrapperImpl {
        PostgreSQL(
                final String name,
                final HikariDataSource service) {
            super(name, service, DatabaseType.POSTGRES);
        }

        @Override
        public final DatabaseType getDatabaseType() {
            return DatabaseType.POSTGRES;
        }

        @Override
        public String createFetchFirstSelectSQL(
                final String coreSql,
                final int rows,
                final String orderBy) {
            StringBuilder sql = new StringBuilder(coreSql.length() + 50);
            sql.append("SELECT ").append(coreSql);

            if (StringUtil.isNotBlank(orderBy)) {
                sql.append(" ORDER BY ").append(orderBy);
            }

            sql.append(" FETCH FIRST ").append(rows).append(" ROWS ONLY");
            return sql.toString();
        }

        @Override
        protected String buildCreateSequenceSql(
                final String sequenceName,
                final long startValue) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("CREATE SEQUENCE ").append(sequenceName);
            sql.append(" START WITH ").append(startValue);
            sql.append(" INCREMENT BY 1 NO CYCLE");
            return sql.toString();
        }

        @Override
        protected String buildDropSequenceSql(
                final String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("DROP SEQUENCE ").append(sequenceName);
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(
                final String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("SELECT NEXTVAL ('").append(sequenceName).append("')");
            return sql.toString();
        }

        @Override
        protected boolean isUseSqlStateAsCode() {
            return true;
        }

        @Override
        protected String getSqlToDropPrimaryKey(
                final String primaryKeyName,
                final String table) {
            StringBuilder sb = new StringBuilder(200);
            sb.append("DO $$ DECLARE constraint_name varchar;\n");
            sb.append("BEGIN\n");
            sb.append("  SELECT tc.CONSTRAINT_NAME into strict constraint_name\n");
            sb.append("    FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc\n");
            sb.append("    WHERE CONSTRAINT_TYPE = 'PRIMARY KEY'\n");
            sb.append("      AND TABLE_NAME = '").append(table.toLowerCase())
                .append("' AND TABLE_SCHEMA = 'public';\n");
            sb.append("    EXECUTE 'alter table public.").append(table.toLowerCase())
                .append(" drop constraint ' || constraint_name;\n");
            sb.append("END $$;");
            return sb.toString();
        }

    }

    private static class Oracle extends DataSourceWrapperImpl {
        Oracle(
                final String name,
                final HikariDataSource service) {
            super(name, service, DatabaseType.ORACLE);
        }

        @Override
        public final DatabaseType getDatabaseType() {
            return DatabaseType.ORACLE;
        }

        /*
         * Oracle: http://www.oracle.com/technetwork/issue-archive/2006/06-sep/o56asktom-086197.html
         *
         */
        @Override
        public String createFetchFirstSelectSQL(
                final String coreSql,
                final int rows,
                final String orderBy) {
            StringBuilder sql = new StringBuilder(coreSql.length() + 50);

            if (StringUtil.isBlank(orderBy)) {
                sql.append("SELECT ").append(coreSql);
                if (coreSql.contains(" WHERE")) {
                    sql.append(" AND");
                } else {
                    sql.append(" WHERE");
                }
            } else {
                sql.append("SELECT * FROM (SELECT ");
                sql.append(coreSql);
                sql.append(" ORDER BY ").append(orderBy).append(" ) WHERE");
            }

            sql.append(" ROWNUM < ").append(rows + 1);
            return sql.toString();
        }

        @Override
        protected String buildCreateSequenceSql(
                final String sequenceName,
                final long startValue) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("CREATE SEQUENCE ").append(sequenceName);
            sql.append(" START WITH ").append(startValue);
            sql.append(" INCREMENT BY 1 NOCYCLE NOCACHE");
            return sql.toString();
        }

        @Override
        protected String buildDropSequenceSql(
                final String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("DROP SEQUENCE ").append(sequenceName);
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(
                final String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 50);
            sql.append("SELECT ").append(sequenceName).append(".NEXTVAL FROM DUAL");
            return sql.toString();
        }

        @Override
        protected String getSqlToDropPrimaryKey(
                final String primaryKeyName,
                final String table) {
            return "ALTER TABLE " + table + " DROP CONSTRAINT " + primaryKeyName + " DROP INDEX";
        }

        @Override
        protected String getSqlToDropUniqueConstraint(
                final String contraintName,
                final String table) {
            return "ALTER TABLE " + table + " DROP CONSTRAINT " + contraintName + " DROP INDEX";
        }

        @Override
        protected String getSqlToAddForeignKeyConstraint(
                final String constraintName,
                final String baseTable,
                final String baseColumn,
                final String referencedTable,
                final String referencedColumn,
                final String onDeleteAction,
                final String onUpdateAction) {
            final StringBuilder sb = new StringBuilder(100);
            sb.append("ALTER TABLE ").append(baseTable);
            sb.append(" ADD CONSTRAINT ").append(constraintName);
            sb.append(" FOREIGN KEY (").append(baseColumn).append(")");
            sb.append(" REFERENCES ").append(referencedTable);
            sb.append(" (").append(referencedColumn).append(")");
            sb.append(" ON DELETE ").append(onDeleteAction);
            return sb.toString();
        }

        @Override
        protected String getSqlToAddPrimaryKey(
                final String primaryKeyName,
                final String table,
                final String... columns) {
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

    }

    private static class H2 extends DataSourceWrapperImpl {
        H2(
                final String name,
                final HikariDataSource service) {
            super(name, service, DatabaseType.H2);
        }

        @Override
        public final DatabaseType getDatabaseType() {
            return DatabaseType.H2;
        }

        @Override
        public String createFetchFirstSelectSQL(
                final String coreSql,
                final int rows,
                final String orderBy) {
            StringBuilder sql = new StringBuilder(coreSql.length() + 50);
            sql.append("SELECT ").append(coreSql);

            if (StringUtil.isNotBlank(orderBy)) {
                sql.append(" ORDER BY ").append(orderBy);
            }

            sql.append(" LIMIT ").append(rows);
            return sql.toString();
        }

        @Override
        protected String buildCreateSequenceSql(
                final String sequenceName,
                final long startValue) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("CREATE SEQUENCE ").append(sequenceName);
            sql.append(" START WITH ").append(startValue);
            sql.append(" INCREMENT BY 1 NO CYCLE NO CACHE");
            return sql.toString();
        }

        @Override
        protected String buildDropSequenceSql(
                final String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("DROP SEQUENCE ").append(sequenceName);
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(
                final String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("SELECT NEXTVAL ('").append(sequenceName).append("')");
            return sql.toString();
        }

    }

    private static class HSQL extends DataSourceWrapperImpl {
        HSQL(
                final String name,
                final HikariDataSource service) {
            super(name, service, DatabaseType.HSQL);
        }

        @Override
        public final DatabaseType getDatabaseType() {
            return DatabaseType.H2;
        }

        @Override
        public String createFetchFirstSelectSQL(
                final String coreSql,
                final int rows,
                final String orderBy) {
            StringBuilder sql = new StringBuilder(coreSql.length() + 80);
            sql.append("SELECT ").append(coreSql);

            if (StringUtil.isNotBlank(orderBy)) {
                sql.append(" ORDER BY ").append(orderBy);
            }

            sql.append(" LIMIT ").append(rows);
            return sql.toString();
        }

        @Override
        protected String buildCreateSequenceSql(
                final String sequenceName,
                final long startValue) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("CREATE SEQUENCE ").append(sequenceName);
            sql.append(" AS BIGINT START WITH ").append(startValue);
            sql.append(" INCREMENT BY 1");
            return sql.toString();
        }

        @Override
        protected String buildDropSequenceSql(
                final String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("DROP SEQUENCE ").append(sequenceName);
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(
                final String sequenceName) {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("SELECT NEXTVAL ('").append(sequenceName).append("')");
            return sql.toString();
        }

    }

    /**
     * References the real data source implementation this class acts as pure
     * proxy for. Derived classes must set this field at construction time.
     */
    protected final HikariDataSource service;

    protected final String name;

    private final SQLErrorCodes sqlErrorCodes;
    private final SQLStateCodes sqlStateCodes;

    private DataSourceWrapperImpl(
            final String name,
            final HikariDataSource service,
            final DatabaseType dbType) {
        ParamUtil.assertNotNull("service", service);
        this.name = name;
        this.service = service;
        this.sqlErrorCodes = SQLErrorCodes.newInstance(dbType);
        this.sqlStateCodes = SQLStateCodes.newInstance(dbType);
    }

    static DataSourceWrapper createDataSource(
            final String name,
            final Properties props,
            final DatabaseType databaseType) {
        ParamUtil.assertNotEmpty("props", props);
        ParamUtil.assertNotNull("databaseType", databaseType);

        // The DB2 schema name is case-sensitive, and must be specified in uppercase characters
        String dataSourceClassName = props.getProperty("dataSourceClassName");
        if (dataSourceClassName != null) {
            if (dataSourceClassName.contains(".db2.")) {
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
        }

        if (databaseType == DatabaseType.DB2
                || databaseType == DatabaseType.H2
                || databaseType == DatabaseType.HSQL
                || databaseType == DatabaseType.MYSQL
                || databaseType == DatabaseType.ORACLE
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
                case ORACLE:
                    return new Oracle(name, service);
                default: // POSTGRESQL:
                    return new PostgreSQL(name, service);
            }
        } else {
            throw new IllegalArgumentException("unknown datasource type " + databaseType);
        }
    }

    @Override
    public final String getDatasourceName() {
        return name;
    }

    @Override
    public final int getMaximumPoolSize() {
        return service.getMaximumPoolSize();
    }

    @Override
    public final Connection getConnection()
    throws DataAccessException {
        try {
            return service.getConnection();
        } catch (Exception e) {
            Throwable cause = e.getCause();
            if (cause instanceof SQLException) {
                e = (SQLException) cause;
            }
            LOG.error("could not create connection to database {}", e.getMessage());
            LOG.debug("could not create connection to database", e);
            if (e instanceof SQLException) {
                throw translate(null, (SQLException) e);
            } else {
                throw new DataAccessException("error occured while getting Connection: "
                        + e.getMessage(), e);
            }
        }
    }

    @Override
    public void returnConnection(
            final Connection conn) {
        if (conn == null) {
            return;
        }

        try {
            conn.close();
        } catch (Exception e) {
            Throwable cause = e.getCause();
            if (cause instanceof SQLException) {
                e = (SQLException) cause;
            }
            LOG.error("could not close connection to database {}", e.getMessage());
            LOG.debug("could not close connection to database", e);
        }
    }

    @Override
    public void shutdown() {
        try {
            service.close();
        } catch (Exception e) {
            LOG.warn("could not shutdown datasource: {}", e.getMessage());
            LOG.debug("could not close datasource", e);
        }
    }

    public final PrintWriter getLogWriter()
    throws SQLException {
        return service.getLogWriter();
    }

    @Override
    public Statement createStatement(
            final Connection conn)
    throws DataAccessException {
        try {
            return conn.createStatement();
        } catch (SQLException e) {
            throw translate(null, e);
        }
    }

    @Override
    public PreparedStatement prepareStatement(
            final Connection conn,
            final String sqlQuery)
    throws DataAccessException {
        try {
            return conn.prepareStatement(sqlQuery);
        } catch (SQLException e) {
            throw translate(sqlQuery, e);
        }
    }

    @Override
    public void releaseResources(
            final Statement ps,
            final ResultSet rs) {
        if (rs != null) {
            try {
                rs.close();
            } catch (Throwable t) {
                LOG.warn("could not close ResultSet", t);
            }
        }

        if (ps != null) {
            Connection conn = null;
            try {
                conn = ps.getConnection();
            } catch (SQLException e) {
            }

            try {
                ps.close();
            } catch (Throwable t) {
                LOG.warn("could not close statement", t);
            } finally {
                if (conn != null) {
                    returnConnection(conn);
                }
            }
        }
    }

    private void releaseStatementAndResultSet(
            final Statement ps,
            final ResultSet rs) {
        if (rs != null) {
            try {
                rs.close();
            } catch (Throwable t) {
                LOG.warn("could not close ResultSet", t);
            }
        }

        if (ps != null) {
            try {
                ps.close();
            } catch (Throwable t) {
                LOG.warn("could not close statement", t);
            }
        }
    }

    @Override
    public String createFetchFirstSelectSQL(
            final String coreSql,
            final int rows) {
        return createFetchFirstSelectSQL(coreSql, rows, null);
    }

    @Override
    public long getMin(
            final Connection conn,
            final String table,
            final String column)
    throws DataAccessException {
        return getMin(conn, table, column, null);
    }

    @Override
    public long getMin(
            final Connection conn,
            final String table,
            final String column,
            final String condition)
    throws DataAccessException {
        StringBuilder sqlBuilder = new StringBuilder(column.length() + table.length() + 20);
        sqlBuilder.append("SELECT MIN(").append(column).append(") FROM ").append(table);
        if (StringUtil.isNotBlank(condition)) {
            sqlBuilder.append(" WHERE ").append(condition);
        }

        final String sql = sqlBuilder.toString();

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = (conn != null)
                    ? conn.createStatement()
                    : getConnection().createStatement();
            rs = stmt.executeQuery(sql);
            rs.next();
            return rs.getLong(1);
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            if (conn == null) {
                releaseResources(stmt, rs);
            } else {
                releaseStatementAndResultSet(stmt, rs);
            }
        }
    }

    @Override
    public int getCount(
            final Connection conn,
            final String table)
    throws DataAccessException {
        StringBuilder sqlBuilder = new StringBuilder(table.length() + 25);
        sqlBuilder.append("SELECT COUNT(*) FROM ").append(table);
        final String sql = sqlBuilder.toString();

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = (conn != null)
                    ? conn.createStatement()
                    : getConnection().createStatement();
            rs = stmt.executeQuery(sql);
            rs.next();
            return rs.getInt(1);
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            if (conn == null) {
                releaseResources(stmt, rs);
            } else {
                releaseStatementAndResultSet(stmt, rs);
            }
        }
    }

    @Override
    public long getMax(
            final Connection conn,
            final String table,
            final String column)
    throws DataAccessException {
        return getMax(conn, table, column, null);
    }

    @Override
    public long getMax(
            final Connection conn,
            final String table,
            final String column,
            final String condition)
    throws DataAccessException {
        StringBuilder sqlBuilder = new StringBuilder(column.length() + table.length() + 20);
        sqlBuilder.append("SELECT MAX(").append(column).append(") FROM ").append(table);
        if (StringUtil.isNotBlank(condition)) {
            sqlBuilder.append(" WHERE ").append(condition);
        }
        final String sql = sqlBuilder.toString();

        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = (conn != null)
                    ? conn.createStatement()
                    : getConnection().createStatement();
            rs = stmt.executeQuery(sql);
            rs.next();
            return rs.getLong(1);
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            if (conn == null) {
                releaseResources(stmt, rs);
            } else {
                releaseStatementAndResultSet(stmt, rs);
            }
        }
    }

    @Override
    public boolean deleteFromTable(
            final Connection conn,
            final String table,
            final String idColumn,
            final int id) {
        final StringBuilder sb = new StringBuilder(50);
        sb.append("DELETE FROM ")
            .append(table)
            .append(" WHERE ")
            .append(idColumn)
            .append(" = ")
            .append(id);
        final String sql = sb.toString();

        Connection _conn = conn;
        if (_conn == null) {
            try {
                _conn = getConnection();
            } catch (Throwable t) {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("datasource {} could not get connection: {}", name, t.getMessage());
                }
                return false;
            }
        }

        Statement stmt = null;
        try {
            stmt = conn.createStatement();
            stmt.execute(sql);
        } catch (Throwable t) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("datasource {} could not deletefrom table {}: {}", name, table,
                        t.getMessage());
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

    @Override
    public boolean columnExists(
            final Connection conn,
            final String table,
            final String column,
            final Object value)
    throws DataAccessException {
        StringBuilder sb = new StringBuilder(50);
        sb.append(column)
            .append(" FROM ")
            .append(table)
            .append(" WHERE ")
            .append(column)
            .append("=?");
        String sql = createFetchFirstSelectSQL(sb.toString(), 1);

        PreparedStatement stmt = null;
        ResultSet rs = null;
        try {
            stmt = (conn != null)
                    ? conn.prepareStatement(sql)
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
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            if (conn == null) {
                releaseResources(stmt, rs);
            } else {
                releaseStatementAndResultSet(stmt, rs);
            }
        }
    }

    @Override
    public boolean tableHasColumn(
            final Connection conn,
            final String table,
            final String column)
    throws DataAccessException {
        Statement stmt;
        try {
            stmt = (conn != null)
                    ? conn.createStatement()
                    : getConnection().createStatement();
        } catch (SQLException e) {
            throw translate(null, e);
        }

        StringBuilder sqlBuilder = new StringBuilder(column.length() + table.length() + 20);
        sqlBuilder.append(column).append(" FROM ").append(table);
        final String sql = createFetchFirstSelectSQL(sqlBuilder.toString(), 1);

        try {
            stmt.execute(sql);
            return true;
        } catch (SQLException e) {
            return false;
        } finally {
            if (conn == null) {
                releaseResources(stmt, null);
            } else {
                releaseStatementAndResultSet(stmt, null);
            }
        }
    }

    @Override
    public boolean tableExists(
            final Connection conn,
            final String table)
    throws DataAccessException {
        Statement stmt;
        try {
            stmt = (conn != null)
                    ? conn.createStatement()
                    : getConnection().createStatement();
        } catch (SQLException e) {
            throw translate(null, e);
        }

        StringBuilder sqlBuilder = new StringBuilder(table.length() + 10);
        sqlBuilder.append("1 FROM ").append(table);
        final String sql = createFetchFirstSelectSQL(sqlBuilder.toString(), 1);

        try {
            stmt.execute(sql);
            return true;
        } catch (SQLException e) {
            return false;
        } finally {
            if (conn == null) {
                releaseResources(stmt, null);
            } else {
                releaseStatementAndResultSet(stmt, null);
            }
        }
    }

    protected abstract String buildCreateSequenceSql(
            String sequenceName,
            long startValue);

    protected abstract String buildDropSequenceSql(
            String sequenceName);

    protected abstract String buildNextSeqValueSql(
            String sequenceName);

    protected boolean isUseSqlStateAsCode() {
        return false;
    }

    @Override
    public void dropAndCreateSequence(
            final String sequenceName,
            final long startValue)
    throws DataAccessException {
        try {
            dropSequence(sequenceName);
        } catch (DataAccessException e) {
        }

        createSequence(sequenceName, startValue);
    }

    @Override
    public void createSequence(
            final String sequenceName,
            final long startValue)
    throws DataAccessException {
        final String sql = buildCreateSequenceSql(sequenceName, startValue);
        Connection conn = getConnection();
        Statement stmt = null;
        try {
            stmt = conn.createStatement();
            stmt.execute(sql);
            LOG.info("datasource {} CREATESEQ {} START {}", name, sequenceName, startValue);
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(stmt, null);
        }

    }

    @Override
    public void dropSequence(
            final String sequenceName)
    throws DataAccessException {
        final String sql = buildDropSequenceSql(sequenceName);

        Connection conn = getConnection();
        Statement stmt = null;
        try {
            stmt = conn.createStatement();
            stmt.execute(sql);
            LOG.info("datasource {} DROPSEQ {}", name, sequenceName);
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            releaseResources(stmt, null);
        }
    }

    @Override
    public void setLastUsedSeqValue(
            final String sequenceName,
            final long sequenceValue) {
        lastUsedSeqValues.put(sequenceName, sequenceValue);
    }

    @Override
    public long nextSeqValue(
            Connection conn,
            final String sequenceName)
    throws DataAccessException {
        final String sql = buildNextSeqValueSql(sequenceName);
        boolean newConn = conn == null;
        if (newConn) {
            conn = getConnection();
        }
        Statement stmt = null;

        long next;
        try {
            stmt = conn.createStatement();

            while (true) {
                ResultSet rs = stmt.executeQuery(sql);
                try {
                    if (rs.next()) {
                        next = rs.getLong(1);
                        synchronized (lastUsedSeqValues) {
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
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            if (newConn) {
                releaseResources(stmt, null);
            } else {
                releaseStatementAndResultSet(stmt, null);
            }
        }

        LOG.debug("datasource {} NEXVALUE({}): {}", name, sequenceName, next);
        return next;
    }

    protected String getSqlToDropPrimaryKey(
            final String primaryKeyName,
            final String table) {
        return "ALTER TABLE " + table + " DROP PRIMARY KEY ";
    }

    @Override
    public void dropPrimaryKey(
            final Connection conn,
            final String primaryKeyName,
            final String table)
    throws DataAccessException {
        executeUpdate(conn, getSqlToDropPrimaryKey(primaryKeyName, table));
    }

    protected String getSqlToAddPrimaryKey(
            final String primaryKeyName,
            final String table,
            final String... columns) {
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

    @Override
    public void addPrimaryKey(
            final Connection conn,
            final String primaryKeyName,
            final String table,
            final String... columns)
    throws DataAccessException {
        executeUpdate(conn, getSqlToAddPrimaryKey(primaryKeyName, table, columns));
    }

    protected String getSqlToDropForeignKeyConstraint(
            final String constraintName,
            final String baseTable)
    throws DataAccessException {
        return "ALTER TABLE " + baseTable + " DROP CONSTRAINT " + constraintName;
    }

    @Override
    public void dropForeignKeyConstraint(
            final Connection conn,
            final String constraintName,
            final String baseTable)
    throws DataAccessException {
        executeUpdate(conn, getSqlToDropForeignKeyConstraint(constraintName, baseTable));
    }

    protected String getSqlToAddForeignKeyConstraint(
            final String constraintName,
            final String baseTable,
            final String baseColumn,
            final String referencedTable,
            final String referencedColumn,
            final String onDeleteAction,
            final String onUpdateAction) {
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

    @Override
    public void addForeignKeyConstraint(
            final Connection conn,
            final String constraintName,
            final String baseTable,
            final String baseColumn,
            final String referencedTable,
            final String referencedColumn,
            final String onDeleteAction,
            final String onUpdateAction)
    throws DataAccessException {
        executeUpdate(conn,
                getSqlToAddForeignKeyConstraint(
                        constraintName,
                        baseTable, baseColumn,
                        referencedTable, referencedColumn,
                        onDeleteAction, onUpdateAction));
    }

    protected String getSqlToDropIndex(
            final String table,
            final String indexName) {
        return "DROP INDEX " + indexName;
    }

    @Override
    public void dropIndex(
            final Connection conn,
            final String table,
            final String indexName)
    throws DataAccessException {
        executeUpdate(conn, getSqlToDropIndex(table, indexName));
    }

    protected String getSqlToCreateIndex(
            final String indexName,
            final String table,
            final String column) {
        final StringBuilder sb = new StringBuilder(100);
        sb.append("CREATE INDEX ").append(indexName);
        sb.append(" ON ").append(table).append("(").append(column).append(")");
        return sb.toString();
    }

    @Override
    public void createIndex(
            final Connection conn,
            final String indexName,
            final String table,
            final String column)
    throws DataAccessException {
        executeUpdate(conn, getSqlToCreateIndex(indexName, table, column));
    }

    protected String getSqlToDropUniqueConstraint(
            final String constraintName,
            final String table) {
        return "ALTER TABLE " + table + " DROP CONSTRAINT " + constraintName;
    }

    @Override
    public void dropUniqueConstrain(
            final Connection conn,
            final String constraintName,
            final String table)
    throws DataAccessException {
        executeUpdate(conn, getSqlToDropUniqueConstraint(constraintName, table));
    }

    protected String getSqlToAddUniqueConstrain(
            final String constraintName,
            final String table,
            final String... columns) {
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

    @Override
    public void addUniqueConstrain(
            final Connection conn,
            final String constraintName,
            final String table,
            final String... columns)
    throws DataAccessException {
        executeUpdate(conn, getSqlToAddUniqueConstrain(constraintName, table, columns));
    }

    @Override
    public DataAccessException translate(
            String sql,
            final SQLException ex) {
        ParamUtil.assertNotNull("ex", ex);
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

        if (sqlErrorCodes.isUseSqlStateForTranslation()) {
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
            if (sqlErrorCodes.getBadSqlGrammarCodes().contains(errorCode)) {
                logTranslation(sql, sqlEx);
                return new BadSqlGrammarException(buildMessage(sql, sqlEx), sqlEx);
            } else if (sqlErrorCodes.getInvalidResultSetAccessCodes().contains(errorCode)) {
                logTranslation(sql, sqlEx);
                return new InvalidResultSetAccessException(buildMessage(sql, sqlEx), sqlEx);
            } else if (sqlErrorCodes.getDuplicateKeyCodes().contains(errorCode)) {
                logTranslation(sql, sqlEx);
                return new DuplicateKeyException(buildMessage(sql, sqlEx), sqlEx);
            } else if (sqlErrorCodes.getDataIntegrityViolationCodes().contains(errorCode)) {
                logTranslation(sql, sqlEx);
                return new DataIntegrityViolationException(buildMessage(sql, sqlEx), sqlEx);
            } else if (sqlErrorCodes.getPermissionDeniedCodes().contains(errorCode)) {
                logTranslation(sql, sqlEx);
                return new PermissionDeniedDataAccessException(buildMessage(sql, sqlEx), sqlEx);
            } else if (sqlErrorCodes.getDataAccessResourceFailureCodes().contains(errorCode)) {
                logTranslation(sql, sqlEx);
                return new DataAccessResourceFailureException(buildMessage(sql, sqlEx), sqlEx);
            } else if (sqlErrorCodes.getTransientDataAccessResourceCodes().contains(errorCode)) {
                logTranslation(sql, sqlEx);
                return new TransientDataAccessResourceException(buildMessage(sql, sqlEx), sqlEx);
            } else if (sqlErrorCodes.getCannotAcquireLockCodes().contains(errorCode)) {
                logTranslation(sql, sqlEx);
                return new CannotAcquireLockException(buildMessage(sql, sqlEx), sqlEx);
            } else if (sqlErrorCodes.getDeadlockLoserCodes().contains(errorCode)) {
                logTranslation(sql, sqlEx);
                return new DeadlockLoserDataAccessException(buildMessage(sql, sqlEx), sqlEx);
            } else if (sqlErrorCodes.getCannotSerializeTransactionCodes().contains(errorCode)) {
                logTranslation(sql, sqlEx);
                return new CannotSerializeTransactionException(buildMessage(sql, sqlEx), sqlEx);
            }
        }

        // try SQLState
        if (sqlState != null && sqlState.length() >= 2) {
            String classCode = sqlState.substring(0, 2);
            if (sqlStateCodes.getBadSQLGrammarCodes().contains(classCode)) {
                return new BadSqlGrammarException(buildMessage(sql, sqlEx), ex);
            } else if (sqlStateCodes.getDataIntegrityViolationCodes().contains(classCode)) {
                return new DataIntegrityViolationException(buildMessage(sql, ex), ex);
            } else if (sqlStateCodes.getDataAccessResourceFailureCodes().contains(classCode)) {
                return new DataAccessResourceFailureException(buildMessage(sql, ex), ex);
            } else if (sqlStateCodes.getTransientDataAccessResourceCodes().contains(classCode)) {
                return new TransientDataAccessResourceException(buildMessage(sql, ex), ex);
            } else if (sqlStateCodes.getConcurrencyFailureCodes().contains(classCode)) {
                return new ConcurrencyFailureException(buildMessage(sql, ex), ex);
            }
        }

        // For MySQL: exception class name indicating a timeout?
        // (since MySQL doesn't throw the JDBC 4 SQLTimeoutException)
        if (ex.getClass().getName().contains("Timeout")) {
            return new QueryTimeoutException(buildMessage(sql, ex), ex);
        }

        // We couldn't identify it more precisely
        if (LOG.isDebugEnabled()) {
            String codes;
            if (sqlErrorCodes != null && sqlErrorCodes.isUseSqlStateForTranslation()) {
                codes = "SQL state '" + sqlEx.getSQLState() + "', error code '"
                        + sqlEx.getErrorCode();
            } else {
                codes = "Error code '" + sqlEx.getErrorCode() + "'";
            }
            LOG.debug("Unable to translate SQLException with " + codes);
        }

        return new UncategorizedSQLException(buildMessage(sql, sqlEx), sqlEx);
    }

    private void logTranslation(
            final String sql,
            final SQLException sqlEx) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Translating SQLException with SQL state '{}', error code '{}',"
                    + " message [{}]; SQL was [{}]",
                    sqlEx.getSQLState(), sqlEx.getErrorCode(), sqlEx.getMessage(), sql);
        }
    }

    private String buildMessage(
            final String sql,
            final SQLException ex) {
        return "SQL [" + sql + "]; " + ex.getMessage();
    }

    private void executeUpdate(Connection conn, String sql)
    throws DataAccessException {
        Statement stmt = null;
        try {
            stmt = (conn != null)
                    ? conn.createStatement()
                            : getConnection().createStatement();
            stmt.executeUpdate(sql);
        } catch (SQLException e) {
            throw translate(sql, e);
        } finally {
            if (conn == null) {
                releaseResources(stmt, null);
            } else {
                releaseStatementAndResultSet(stmt, null);
            }
        }
    }

}
