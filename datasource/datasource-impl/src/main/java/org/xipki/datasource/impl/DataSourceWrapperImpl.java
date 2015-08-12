/*
 * Copyright (c) 2015 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
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

public abstract class DataSourceWrapperImpl implements DataSourceWrapper
{
    private static final Logger LOG = LoggerFactory.getLogger(DataSourceWrapperImpl.class);
    private final ConcurrentHashMap<String, Long> lastUsedSeqValues = new ConcurrentHashMap<String, Long>();

    private static class MySQL extends DataSourceWrapperImpl
    {
        MySQL(
                final String name,
                final HikariDataSource service)
        {
            super(name, service, DatabaseType.MYSQL);
        }

        @Override
        public final DatabaseType getDatabaseType()
        {
            return DatabaseType.MYSQL;
        }

        @Override
        public String createFetchFirstSelectSQL(
                final String coreSql,
                final int rows,
                final String orderBy)
        {
            StringBuilder sql = new StringBuilder(coreSql.length() + 50);
            sql.append("SELECT ").append(coreSql);

            if(StringUtil.isNotBlank(orderBy))
            {
                sql.append(" ORDER BY ").append(orderBy);
            }

            sql.append(" LIMIT ").append(rows);
            return sql.toString();
        }

        @Override
        protected String buildCreateSequenceSql(
                final String sequenceName,
                final long startValue)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("INSERT INTO SEQ_TBL (SEQ_NAME, SEQ_VALUE) VALUES('");
            sql.append(sequenceName).append("', ").append(startValue).append(")");
            return sql.toString();
        }

        @Override
        protected String buildDropSequenceSql(
                final String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 40);
            sql.append("DELETE FROM SEQ_TBL WHERE SEQ_NAME='").append(sequenceName).append("'");
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(
                final String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 100);
            sql.append("UPDATE SEQ_TBL SET SEQ_VALUE = (@cur_value := SEQ_VALUE) + 1 WHERE SEQ_NAME = '");
            sql.append(sequenceName).append("'");
            return sql.toString();
        }

        @Override
        public long nextSeqValue(
                Connection conn,
                final String sequenceName)
        throws DataAccessException
        {
            final String sqlUpdate = buildNextSeqValueSql(sequenceName);
            final String SQL_SELECT = "SELECT @cur_value";
            String sql = null;

            boolean newConn = conn == null;
            if(newConn)
            {
                conn = getConnection();
            }
            Statement stmt = null;
            ResultSet rs = null;

            long ret;
            try
            {
                stmt = conn.createStatement();
                sql = sqlUpdate;
                stmt.executeUpdate(sql);

                sql = SQL_SELECT;
                rs = stmt.executeQuery(sql);
                if(rs.next())
                {
                    ret = rs.getLong(1);
                } else
                {
                    throw new DataAccessException("could not increment the sequence " + sequenceName);
                }
            }catch(SQLException e)
            {
                throw translate(sqlUpdate, e);
            }finally
            {
                if(newConn)
                {
                    releaseResources(stmt, rs);
                }
                else
                {
                    super.releaseStatementAndResultSet(stmt, rs);
                }
            }

            LOG.debug("datasource {} NEXVALUE({}): {}", name, sequenceName, ret);
            return ret;
        }

    }

    private static class DB2 extends DataSourceWrapperImpl
    {
        DB2(
                final String name,
                final HikariDataSource service)
        {
            super(name, service, DatabaseType.DB2);
        }

        @Override
        public final DatabaseType getDatabaseType()
        {
            return DatabaseType.DB2;
        }

        @Override
        public String createFetchFirstSelectSQL(
                final String coreSql,
                final int rows,
                final String orderBy)
        {
            StringBuilder sql = new StringBuilder(coreSql.length() + 50);
            sql.append("SELECT ").append(coreSql);

            if(StringUtil.isNotBlank(orderBy))
            {
                sql.append(" ORDER BY ").append(orderBy);
            }

            sql.append(" FETCH FIRST ").append(rows).append(" ROWS ONLY");
            return sql.toString();
        }

        @Override
        protected String buildCreateSequenceSql(
                final String sequenceName,
                final long startValue)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("CREATE SEQUENCE ").append(sequenceName);
            sql.append("AS BIGINT START WITH ").append(startValue);
            sql.append(" INCREMENT BY 1 NO CYCLE NO CACHE");
            return sql.toString();
        }

        @Override
        protected String buildDropSequenceSql(
                final String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("DROP SEQUENCE ").append(sequenceName);
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(
                final String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 50);
            sql.append("SELECT NEXT VALUE FOR ").append(sequenceName).append(" FROM sysibm.sysdummy1");
            return sql.toString();
        }

    }

    private static class PostgreSQL extends DataSourceWrapperImpl
    {
        PostgreSQL(
                final String name,
                final HikariDataSource service)
        {
            super(name, service, DatabaseType.POSTGRES);
        }

        @Override
        public final DatabaseType getDatabaseType()
        {
            return DatabaseType.POSTGRES;
        }

        @Override
        public String createFetchFirstSelectSQL(
                final String coreSql,
                final int rows,
                final String orderBy)
        {
            StringBuilder sql = new StringBuilder(coreSql.length() + 50);
            sql.append("SELECT ").append(coreSql);

            if(StringUtil.isNotBlank(orderBy))
            {
                sql.append(" ORDER BY ").append(orderBy);
            }

            sql.append(" FETCH FIRST ").append(rows).append(" ROWS ONLY");
            return sql.toString();
        }

        @Override
        protected String buildCreateSequenceSql(
                final String sequenceName,
                final long startValue)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("CREATE SEQUENCE ").append(sequenceName);
            sql.append(" START WITH ").append(startValue);
            sql.append(" INCREMENT BY 1 NO CYCLE");
            return sql.toString();
        }

        @Override
        protected String buildDropSequenceSql(
                final String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("DROP SEQUENCE ").append(sequenceName);
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(
                final String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("SELECT NEXTVAL ('").append(sequenceName).append("')");
            return sql.toString();
        }

        @Override
        protected boolean isUseSqlStateAsCode()
        {
            return true;
        }

    }

    private static class Oracle extends DataSourceWrapperImpl
    {
        Oracle(
                final String name,
                final HikariDataSource service)
        {
            super(name, service, DatabaseType.ORACLE);
        }

        @Override
        public final DatabaseType getDatabaseType()
        {
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
                final String orderBy)
        {
            StringBuilder sql = new StringBuilder(coreSql.length() + 50);

            if(StringUtil.isBlank(orderBy))
            {
                sql.append("SELECT ").append(coreSql);
                if(coreSql.contains(" WHERE"))
                {
                    sql.append(" AND");
                } else
                {
                    sql.append(" WHERE");
                }
            } else
            {
                sql.append("SELECT * FROM ( SELECT ");
                sql.append(coreSql);
                sql.append(" ORDER BY ").append(orderBy).append(" ) WHERE");
            }

            sql.append(" ROWNUM < ").append(rows + 1);
            return sql.toString();
        }

        @Override
        protected String buildCreateSequenceSql(
                final String sequenceName,
                final long startValue)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("CREATE SEQUENCE ").append(sequenceName);
            sql.append(" START WITH ").append(startValue);
            sql.append(" INCREMENT BY 1 NOCYCLE NOCACHE");
            return sql.toString();
        }

        @Override
        protected String buildDropSequenceSql(
                final String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("DROP SEQUENCE ").append(sequenceName);
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(
                final String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 50);
            sql.append("SELECT ").append(sequenceName).append(".NEXTVAL FROM DUAL");
            return sql.toString();
        }

    }

    private static class H2 extends DataSourceWrapperImpl
    {
        H2(
                final String name,
                final HikariDataSource service)
        {
            super(name, service, DatabaseType.H2);
        }

        @Override
        public final DatabaseType getDatabaseType()
        {
            return DatabaseType.H2;
        }

        @Override
        public String createFetchFirstSelectSQL(
                final String coreSql,
                final int rows,
                final String orderBy)
        {
            StringBuilder sql = new StringBuilder(coreSql.length() + 50);
            sql.append("SELECT ").append(coreSql);

            if(StringUtil.isNotBlank(orderBy))
            {
                sql.append(" ORDER BY ").append(orderBy);
            }

            sql.append(" LIMIT ").append(rows);
            return sql.toString();
        }

        @Override
        protected String buildCreateSequenceSql(
                final String sequenceName,
                final long startValue)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("CREATE SEQUENCE ").append(sequenceName);
            sql.append(" START WITH ").append(startValue);
            sql.append(" INCREMENT BY 1 NO CYCLE NO CACHE");
            return sql.toString();
        }

        @Override
        protected String buildDropSequenceSql(
                final String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("DROP SEQUENCE ").append(sequenceName);
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(
                final String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("SELECT NEXTVAL ('").append(sequenceName).append("')");
            return sql.toString();
        }

    }

    private static class HSQL extends DataSourceWrapperImpl
    {
        HSQL(
                final String name,
                final HikariDataSource service)
        {
            super(name, service, DatabaseType.HSQL);
        }

        @Override
        public final DatabaseType getDatabaseType()
        {
            return DatabaseType.H2;
        }

        @Override
        public String createFetchFirstSelectSQL(
                final String coreSql,
                final int rows,
                final String orderBy)
        {
            StringBuilder sql = new StringBuilder(coreSql.length() + 80);
            sql.append("SELECT ").append(coreSql);

            if(StringUtil.isNotBlank(orderBy))
            {
                sql.append(" ORDER BY ").append(orderBy);
            }

            sql.append(" LIMIT ").append(rows);
            return sql.toString();
        }

        @Override
        protected String buildCreateSequenceSql(
                final String sequenceName,
                final long startValue)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("CREATE SEQUENCE ").append(sequenceName);
            sql.append(" AS BIGINT START WITH ").append(startValue);
            sql.append(" INCREMENT BY 1");
            return sql.toString();
        }

        @Override
        protected String buildDropSequenceSql(
                final String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("DROP SEQUENCE ").append(sequenceName);
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(
                final String sequenceName)
        {
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
            final DatabaseType dbType)
    {
        ParamUtil.assertNotNull("service", service);
        this.name = name;
        this.service = service;
        this.sqlErrorCodes = SQLErrorCodes.newInstance(dbType);
        this.sqlStateCodes = SQLStateCodes.newInstance(dbType);
    }

    static DataSourceWrapper createDataSource(
            final String name,
            final Properties props,
            final DatabaseType databaseType)
    {
        ParamUtil.assertNotEmpty("props", props);
        ParamUtil.assertNotNull("databaseType", databaseType);

        // The DB2 schema name is case-sensitive, and must be specified in uppercase characters
        String dataSourceClassName = props.getProperty("dataSourceClassName");
        if(dataSourceClassName != null)
        {
            if(dataSourceClassName.contains(".db2."))
            {
                String propName = "dataSource.currentSchema";
                String schema = props.getProperty(propName);
                if(schema != null)
                {
                    String upperCaseSchema = schema.toUpperCase();
                    if(schema.equals(upperCaseSchema) == false)
                    {
                        props.setProperty(propName, upperCaseSchema);
                    }
                }
            }
        }
        else
        {
            String propName = "jdbcUrl";
            final String url = props.getProperty(propName);
            if(StringUtil.startsWithIgnoreCase(url, "jdbc:db2:"))
            {
                String sep = ":currentSchema=";
                int idx = url.indexOf(sep);
                if(idx != 1)
                {
                    String schema = url.substring(idx + sep.length());
                    if(schema.endsWith(";"))
                    {
                        schema = schema.substring(0, schema.length() - 1);
                    }

                    String upperCaseSchema = schema.toUpperCase();
                    if(schema.equals(upperCaseSchema) == false)
                    {
                        String newUrl = url.replace(sep + schema, sep + upperCaseSchema);
                        props.setProperty(propName, newUrl);
                    }
                }
            }
        }

        if(databaseType == DatabaseType.DB2 || databaseType == DatabaseType.H2 ||
                databaseType == DatabaseType.HSQL ||databaseType == DatabaseType.MYSQL ||
                databaseType == DatabaseType.ORACLE ||databaseType == DatabaseType.POSTGRES)
        {
            HikariConfig conf = new HikariConfig(props);
            HikariDataSource service = new HikariDataSource(conf);
            switch (databaseType)
            {
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
        } else
        {
            throw new IllegalArgumentException("unknown datasource type " + databaseType);
        }
    }

    @Override
    public final String getDatasourceName()
    {
        return name;
    }

    @Override
    public final Connection getConnection()
    throws DataAccessException
    {
        try
        {
            return service.getConnection();
        } catch(SQLException e)
        {
            Throwable cause = e.getCause();
            if(cause instanceof SQLException)
            {
                e = (SQLException) cause;
            }
            LOG.error("could not create connection to database {}", e.getMessage());
            LOG.debug("could not create connection to database", e);
            throw translate(null, e);
        }
    }

    @Override
    public void returnConnection(
            final Connection conn)
    {
        if(conn == null)
        {
            return;
        }

        try
        {
            conn.close();
        } catch (SQLException e)
        {
            Throwable cause = e.getCause();
            if(cause instanceof SQLException)
            {
                e = (SQLException) cause;
            }
            LOG.error("could not create connection to database {}", e.getMessage());
            LOG.debug("could not create connection to database", e);
        }
    }

    @Override
    public void shutdown()
    {
        try
        {
            service.shutdown();
        } catch (Exception e)
        {
            LOG.warn("could not shutdown datasource: {}", e.getMessage());
            LOG.debug("could not close datasource", e);
        }
    }

    public final PrintWriter getLogWriter()
    throws SQLException
    {
        return service.getLogWriter();
    }

    @Override
    public Statement createStatement(
            final Connection conn)
    throws DataAccessException
    {
        try
        {
            return conn.createStatement();
        }catch(SQLException e)
        {
            throw translate(null, e);
        }
    }

    @Override
    public PreparedStatement prepareStatement(
            final Connection conn,
            final String sqlQuery)
    throws DataAccessException
    {
        try
        {
            return conn.prepareStatement(sqlQuery);
        }catch(SQLException e)
        {
            throw translate(sqlQuery, e);
        }
    }

    @Override
    public void releaseResources(
            final Statement ps,
            final ResultSet rs)
    {
        if(rs != null)
        {
            try
            {
                rs.close();
            }catch(Throwable t)
            {
                LOG.warn("could not close ResultSet", t);
            }
        }

        if(ps != null)
        {
            Connection conn = null;
            try
            {
                conn = ps.getConnection();
            }catch(SQLException e)
            {
            }

            try
            {
                ps.close();
            }catch(Throwable t)
            {
                LOG.warn("could not close statement", t);
            }finally
            {
                if(conn != null)
                {
                    returnConnection(conn);
                }
            }
        }
    }

    private void releaseStatementAndResultSet(
            final Statement ps,
            final ResultSet rs)
    {
        if(rs != null)
        {
            try
            {
                rs.close();
            }catch(Throwable t)
            {
                LOG.warn("could not close ResultSet", t);
            }
        }

        if(ps != null)
        {
            try
            {
                ps.close();
            }catch(Throwable t)
            {
                LOG.warn("could not close statement", t);
            }
        }
    }

    @Override
    public String createFetchFirstSelectSQL(
            final String coreSql,
            final int rows)
    {
        return createFetchFirstSelectSQL(coreSql, rows, null);
    }

    @Override
    public long getMin(
            final Connection conn,
            final String table,
            final String column)
    throws DataAccessException
    {
        StringBuilder sqlBuilder = new StringBuilder(column.length() + table.length() + 20);
        sqlBuilder.append("SELECT MIN(").append(column).append(") FROM ").append(table);
        final String sql = sqlBuilder.toString();

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = (conn != null) ? conn.createStatement() : getConnection().createStatement();
            rs = stmt.executeQuery(sql);
            rs.next();
            return rs.getLong(1);
        } catch(SQLException e)
        {
            throw translate(sql, e);
        } finally
        {
            if(conn == null)
            {
                releaseResources(stmt, rs);
            }
            else
            {
                releaseStatementAndResultSet(stmt, rs);
            }
        }
    }

    @Override
    public int getCount(
            final Connection conn,
            final String table)
    throws DataAccessException
    {
        StringBuilder sqlBuilder = new StringBuilder(table.length() + 25);
        sqlBuilder.append("SELECT COUNT(*) FROM ").append(table);
        final String sql = sqlBuilder.toString();

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = (conn != null) ? conn.createStatement() : getConnection().createStatement();
            rs = stmt.executeQuery(sql);
            rs.next();
            return rs.getInt(1);
        } catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            if(conn == null)
            {
                releaseResources(stmt, rs);
            }
            else
            {
                releaseStatementAndResultSet(stmt, rs);
            }
        }
    }

    @Override
    public long getMax(
            final Connection conn,
            final String table,
            final String column)
    throws DataAccessException
    {
        StringBuilder sqlBuilder = new StringBuilder(column.length() + table.length() + 20);
        sqlBuilder.append("SELECT MAX(").append(column).append(") FROM ").append(table);
        final String sql = sqlBuilder.toString();

        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = (conn != null) ? conn.createStatement() : getConnection().createStatement();
            rs = stmt.executeQuery(sql);
            rs.next();
            return rs.getLong(1);
        } catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            if(conn == null)
            {
                releaseResources(stmt, rs);
            }
            else
            {
                releaseStatementAndResultSet(stmt, rs);
            }
        }
    }

    @Override
    public boolean columnExists(
            final Connection conn,
            final String table,
            final String column,
            final Object value)
    throws DataAccessException
    {
        // TODO use fetch first
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT COUNT(*) FROM ").append(table).append(" WHERE ").append(column).append("=?");
        String sql = sb.toString();

        PreparedStatement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = (conn != null) ? conn.prepareStatement(sql) : getConnection().prepareStatement(sql);
            if(value instanceof Integer)
            {
                stmt.setInt(1, (Integer) value);
            } else if(value instanceof Long)
            {
                stmt.setLong(1, (Long) value);
            } else if(value instanceof String)
            {
                stmt.setString(1, (String) value);
            } else
            {
                stmt.setString(1, value.toString());
            }
            rs = stmt.executeQuery();
            rs.next();
            return rs.getInt(1) > 0;
        } catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            if(conn == null)
            {
                releaseResources(stmt, rs);
            }
            else
            {
                releaseStatementAndResultSet(stmt, rs);
            }
        }
    }

    @Override
    public boolean tableHasColumn(
            final Connection conn,
            final String table,
            final String column)
    throws DataAccessException
    {
        Statement stmt;
        try
        {
            stmt = (conn != null) ? conn.createStatement() : getConnection().createStatement();
        } catch (SQLException e)
        {
            throw translate(null, e);
        }

        StringBuilder sqlBuilder = new StringBuilder(column.length() + table.length() + 20);
        sqlBuilder.append(column).append(" FROM ").append(table);
        final String sql = createFetchFirstSelectSQL(sqlBuilder.toString(), 1);

        try
        {
            stmt.execute(sql);
            return true;
        }catch(SQLException e)
        {
            return false;
        } finally
        {
            if(conn == null)
            {
                releaseResources(stmt, null);
            }
            else
            {
                releaseStatementAndResultSet(stmt, null);
            }
        }
    }

    @Override
    public boolean tableExists(
            final Connection conn,
            final String table)
    throws DataAccessException
    {
        Statement stmt;
        try
        {
            stmt = (conn != null) ? conn.createStatement() : getConnection().createStatement();
        } catch (SQLException e)
        {
            throw translate(null, e);
        }

        StringBuilder sqlBuilder = new StringBuilder(table.length() + 10);
        sqlBuilder.append("1 FROM ").append(table);
        final String sql = createFetchFirstSelectSQL(sqlBuilder.toString(), 1);

        try
        {
            stmt.execute(sql);
            return true;
        }catch(SQLException e)
        {
            return false;
        } finally
        {
            if(conn == null)
            {
                releaseResources(stmt, null);
            }
            else
            {
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

    protected boolean isUseSqlStateAsCode()
    {
        return false;
    }

    @Override
    public void dropAndCreateSequence(
            final String sequenceName,
            final long startValue)
    throws DataAccessException
    {
        try
        {
            dropSequence(sequenceName);
        }catch(DataAccessException e)
        {
        }

        createSequence(sequenceName, startValue);
    }

    @Override
    public void createSequence(
            final String sequenceName,
            final long startValue)
    throws DataAccessException
    {
        final String sql = buildCreateSequenceSql(sequenceName, startValue);
        Connection conn = getConnection();
        Statement stmt = null;
        try
        {
            stmt = conn.createStatement();
            stmt.execute(sql);
            LOG.info("datasource {} CREATESEQ {} START {}", name, sequenceName, startValue);
        } catch(SQLException e)
        {
            throw translate(sql, e);
        }
        finally
        {
            releaseResources(stmt, null);
        }

    }

    @Override
    public void dropSequence(
            final String sequenceName)
    throws DataAccessException
    {
        final String sql = buildDropSequenceSql(sequenceName);

        Connection conn = getConnection();
        Statement stmt = null;
        try
        {
            stmt = conn.createStatement();
            stmt.execute(sql);
            LOG.info("datasource {} DROPSEQ {}", name, sequenceName);
        } catch(SQLException e)
        {
            throw translate(sql, e);
        }
        finally
        {
            releaseResources(stmt, null);
        }
    }

    @Override
    public void setLastUsedSeqValue(
            final String sequenceName,
            final long sequenceValue)
    {
        lastUsedSeqValues.put(sequenceName, sequenceValue);
    }

    @Override
    public long nextSeqValue(
            Connection conn,
            final String sequenceName)
    throws DataAccessException
    {
        final String sql = buildNextSeqValueSql(sequenceName);
        boolean newConn = conn == null;
        if(newConn)
        {
            conn = getConnection();
        }
        Statement stmt = null;

        long next;
        try
        {
            stmt = conn.createStatement();

            while(true)
            {
                ResultSet rs = stmt.executeQuery(sql);
                try
                {
                    if(rs.next())
                    {
                        next = rs.getLong(1);
                        synchronized (lastUsedSeqValues)
                        {
                            Long lastValue = lastUsedSeqValues.get(sequenceName);
                            if(lastValue == null || next > lastValue)
                            {
                                lastUsedSeqValues.put(sequenceName, next);
                                break;
                            }
                        }
                    } else
                    {
                        throw new DataAccessException("could not increment the sequence " + sequenceName);
                    }
                }finally
                {
                    releaseStatementAndResultSet(null, rs);
                }
            }
        } catch(SQLException e)
        {
            throw translate(sql, e);
        }finally
        {
            if(newConn)
            {
                releaseResources(stmt, null);
            }
            else
            {
                releaseStatementAndResultSet(stmt, null);
            }
        }

        LOG.debug("datasource {} NEXVALUE({}): {}", name, sequenceName, next);
        return next;
    }

    @Override
    public DataAccessException translate(
            String sql,
            final SQLException ex)
    {
        ParamUtil.assertNotNull("ex", ex);
        if(sql == null)
        {
            sql = "";
        }

        SQLException sqlEx = ex;
        if (sqlEx instanceof BatchUpdateException && sqlEx.getNextException() != null)
        {
            SQLException nestedSqlEx = sqlEx.getNextException();
            if (nestedSqlEx.getErrorCode() > 0 || nestedSqlEx.getSQLState() != null)
            {
                LOG.debug("Using nested SQLException from the BatchUpdateException");
                sqlEx = nestedSqlEx;
            }
        }

        // Check SQLErrorCodes with corresponding error code, if available.
        String errorCode;
        String sqlState;

        if (sqlErrorCodes.isUseSqlStateForTranslation())
        {
            errorCode = sqlEx.getSQLState();
            sqlState = null;
        }
        else
        {
            // Try to find SQLException with actual error code, looping through the causes.
            // E.g. applicable to java.sql.DataTruncation as of JDK 1.6.
            SQLException current = sqlEx;
            while (current.getErrorCode() == 0 && current.getCause() instanceof SQLException)
            {
                current = (SQLException) current.getCause();
            }
            errorCode = Integer.toString(current.getErrorCode());
            sqlState = current.getSQLState();
        }

        if (errorCode != null)
        {
            // look for grouped error codes.
            if (sqlErrorCodes.getBadSqlGrammarCodes().contains(errorCode))
            {
                logTranslation(sql, sqlEx);
                return new BadSqlGrammarException(sql, sqlEx);
            }
            else if (sqlErrorCodes.getInvalidResultSetAccessCodes().contains(errorCode))
            {
                logTranslation(sql, sqlEx);
                return new InvalidResultSetAccessException(sql, sqlEx);
            }
            else if (sqlErrorCodes.getDuplicateKeyCodes().contains(errorCode))
            {
                logTranslation(sql, sqlEx);
                return new DuplicateKeyException(buildMessage(sql, sqlEx), sqlEx);
            }
            else if (sqlErrorCodes.getDataIntegrityViolationCodes().contains(errorCode))
            {
                logTranslation(sql, sqlEx);
                return new DataIntegrityViolationException(buildMessage(sql, sqlEx), sqlEx);
            }
            else if (sqlErrorCodes.getPermissionDeniedCodes().contains(errorCode))
            {
                logTranslation(sql, sqlEx);
                return new PermissionDeniedDataAccessException(buildMessage(sql, sqlEx), sqlEx);
            }
            else if (sqlErrorCodes.getDataAccessResourceFailureCodes().contains(errorCode))
            {
                logTranslation(sql, sqlEx);
                return new DataAccessResourceFailureException(buildMessage(sql, sqlEx), sqlEx);
            }
            else if (sqlErrorCodes.getTransientDataAccessResourceCodes().contains(errorCode))
            {
                logTranslation(sql, sqlEx);
                return new TransientDataAccessResourceException(buildMessage(sql, sqlEx), sqlEx);
            }
            else if (sqlErrorCodes.getCannotAcquireLockCodes().contains(errorCode))
            {
                logTranslation(sql, sqlEx);
                return new CannotAcquireLockException(buildMessage(sql, sqlEx), sqlEx);
            }
            else if (sqlErrorCodes.getDeadlockLoserCodes().contains(errorCode))
            {
                logTranslation(sql, sqlEx);
                return new DeadlockLoserDataAccessException(buildMessage(sql, sqlEx), sqlEx);
            }
            else if (sqlErrorCodes.getCannotSerializeTransactionCodes().contains(errorCode))
            {
                logTranslation(sql, sqlEx);
                return new CannotSerializeTransactionException(buildMessage(sql, sqlEx), sqlEx);
            }
        }

        // try SQLState
        if (sqlState != null && sqlState.length() >= 2)
        {
            String classCode = sqlState.substring(0, 2);
            if (sqlStateCodes.getBadSQLGrammarCodes().contains(classCode))
            {
                return new BadSqlGrammarException(sql, ex);
            }
            else if (sqlStateCodes.getDataIntegrityViolationCodes().contains(classCode))
            {
                return new DataIntegrityViolationException(buildMessage(sql, ex), ex);
            }
            else if (sqlStateCodes.getDataAccessResourceFailureCodes().contains(classCode))
            {
                return new DataAccessResourceFailureException(buildMessage(sql, ex), ex);
            }
            else if (sqlStateCodes.getTransientDataAccessResourceCodes().contains(classCode))
            {
                return new TransientDataAccessResourceException(buildMessage(sql, ex), ex);
            }
            else if (sqlStateCodes.getConcurrencyFailureCodes().contains(classCode))
            {
                return new ConcurrencyFailureException(buildMessage(sql, ex), ex);
            }
        }

        // For MySQL: exception class name indicating a timeout?
        // (since MySQL doesn't throw the JDBC 4 SQLTimeoutException)
        if (ex.getClass().getName().contains("Timeout"))
        {
            return new QueryTimeoutException(buildMessage(sql, ex), ex);
        }

        // We couldn't identify it more precisely
        if (LOG.isDebugEnabled())
        {
            String codes;
            if (sqlErrorCodes != null && sqlErrorCodes.isUseSqlStateForTranslation())
            {
                codes = "SQL state '" + sqlEx.getSQLState() + "', error code '" + sqlEx.getErrorCode();
            }
            else
            {
                codes = "Error code '" + sqlEx.getErrorCode() + "'";
            }
            LOG.debug("Unable to translate SQLException with " + codes);
        }

        return new UncategorizedSQLException(sql, sqlEx);
    }

    private void logTranslation(
            final String sql,
            final SQLException sqlEx)
    {
        if (LOG.isDebugEnabled())
        {
            LOG.debug("Translating SQLException with SQL state '{}', error code '{}', message [{}]; SQL was [{}]",
                    sqlEx.getSQLState(), sqlEx.getErrorCode(), sqlEx.getMessage(), sql);
        }
    }

    private String buildMessage(
            final String sql,
            final SQLException ex)
    {
        return "SQL [" + sql + "]; " + ex.getMessage();
    }

}
