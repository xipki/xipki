/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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
import java.util.Arrays;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.ParamChecker;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.DatabaseType;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

/**
 * @author Lijun Liao
 */

public abstract class DataSourceWrapperImpl implements DataSourceWrapper
{
    private static final Logger LOG = LoggerFactory.getLogger(DataSourceWrapperImpl.class);

    private static class MySQL extends DataSourceWrapperImpl
    {
        private static final String[] duplicateKeyErrorCodes = new String[]{"1062"};
        private static final String[] dataIntegrityViolationCodes = new String[]
        {
            "630", "839", "840", "893", "1169", "1215", "1216", "1217", "1364", "1451", "1452", "1557"
        };

        MySQL(String name, HikariDataSource service)
        {
            super(name, service);
        }

        @Override
        public final DatabaseType getDatabaseType()
        {
            return DatabaseType.MYSQL;
        }

        @Override
        public String createFetchFirstSelectSQL(String coreSql, int rows, String orderBy)
        {
            StringBuilder sql = new StringBuilder(coreSql.length() + 50);
            sql.append("SELECT ").append(coreSql);

            if(orderBy != null && orderBy.isEmpty() == false)
            {
                sql.append(" ORDER BY ").append(orderBy);
            }

            sql.append(" LIMIT ").append(rows);
            return sql.toString();
        }

        @Override
        protected String buildCreateSequenceSql(String sequenceName, long startValue)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("INSERT INTO SEQ_TBL (SEQ_NAME, SEQ_VALUE) VALUES('");
            sql.append(sequenceName).append("', ").append(startValue).append(")");
            return sql.toString();
        }

        @Override
        protected String buildDropSequenceSql(String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 40);
            sql.append("DELETE FROM SEQ_TBL WHERE SEQ_NAME='").append(sequenceName).append("'");
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 100);
            sql.append("UPDATE SEQ_TBL SET SEQ_VALUE = (@cur_value := SEQ_VALUE) + 1 WHERE SEQ_NAME = '");
            sql.append(sequenceName).append("'");
            return sql.toString();
        }

        @Override
        public long nextSeqValue(String sequenceName)
        throws SQLException
        {
            final String sqlUpdate = buildNextSeqValueSql(sequenceName);
            final String SQL_SELECT = "SELECT @cur_value";

            Connection conn = getConnection();
            Statement stmt = conn.createStatement();
            ResultSet rs = null;

            long ret;
            try
            {
                stmt.executeUpdate(sqlUpdate);
                rs = stmt.executeQuery(SQL_SELECT);
                if(rs.next())
                {
                    ret = rs.getLong(1);
                } else
                {
                    throw new SQLException("Could not increment the sequence " + sequenceName);
                }
            }finally
            {
                releaseResources(stmt, rs);
            }

            LOG.debug("datasource {} NEXVALUE({}): {}", name, sequenceName, ret);
            return ret;
        }

        @Override
        protected String[] getDuplicateKeyErrorCodes()
        {
            return duplicateKeyErrorCodes;
        }

        @Override
        protected String[] getDataIntegrityViolationCodes()
        {
            return dataIntegrityViolationCodes;
        }

    }

    private static class DB2 extends DataSourceWrapperImpl
    {
        private static final String[] duplicateKeyErrorCodes = new String[]{"-803"};
        private static final String[] dataIntegrityViolationCodes = new String[]
        {
            "-407", "-530", "-531", "-532", "-543", "-544", "-545", "-603", "-667"
        };

        DB2(String name, HikariDataSource service)
        {
            super(name, service);
        }

        @Override
        public final DatabaseType getDatabaseType()
        {
            return DatabaseType.DB2;
        }

        @Override
        public String createFetchFirstSelectSQL(String coreSql, int rows, String orderBy)
        {
            StringBuilder sql = new StringBuilder(coreSql.length() + 50);
            sql.append("SELECT ").append(coreSql);

            if(orderBy != null && orderBy.isEmpty() == false)
            {
                sql.append(" ORDER BY ").append(orderBy);
            }

            sql.append(" FETCH FIRST ").append(rows).append(" ROWS ONLY");
            return sql.toString();
        }

        @Override
        protected String buildCreateSequenceSql(String sequenceName, long startValue)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("CREATE SEQUENCE ").append(sequenceName);
            sql.append("AS BIGINT START WITH ").append(startValue);
            sql.append(" INCREMENT BY 1 NO CYCLE NO CACHE");
            return sql.toString();
        }

        @Override
        protected String buildDropSequenceSql(String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("DROP SEQUENCE ").append(sequenceName);
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 50);
            sql.append("SELECT NEXT VALUE FOR ").append(sequenceName).append(" FROM sysibm.sysdummy1");
            return sql.toString();
        }

        @Override
        protected String[] getDuplicateKeyErrorCodes()
        {
            return duplicateKeyErrorCodes;
        }

        @Override
        protected String[] getDataIntegrityViolationCodes()
        {
            return dataIntegrityViolationCodes;
        }

    }

    private static class PostgreSQL extends DataSourceWrapperImpl
    {
        private static final String[] duplicateKeyErrorCodes = new String[]{"23505"};
        private static final String[] dataIntegrityViolationCodes = new String[]
        {
            "23000", "23502", "23503", "23514"
        };

        PostgreSQL(String name, HikariDataSource service)
        {
            super(name, service);
        }

        @Override
        public final DatabaseType getDatabaseType()
        {
            return DatabaseType.POSTGRES;
        }

        @Override
        public String createFetchFirstSelectSQL(String coreSql, int rows, String orderBy)
        {
            StringBuilder sql = new StringBuilder(coreSql.length() + 50);
            sql.append("SELECT ").append(coreSql);

            if(orderBy != null && orderBy.isEmpty() == false)
            {
                sql.append(" ORDER BY ").append(orderBy);
            }

            sql.append(" FETCH FIRST ").append(rows).append(" ROWS ONLY");
            return sql.toString();
        }

        @Override
        protected String buildCreateSequenceSql(String sequenceName, long startValue)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("CREATE SEQUENCE ").append(sequenceName);
            sql.append(" START WITH ").append(startValue);
            sql.append(" INCREMENT BY 1 NO CYCLE");
            return sql.toString();
        }

        @Override
        protected String buildDropSequenceSql(String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("DROP SEQUENCE ").append(sequenceName);
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("SELECT NEXTVAL ('").append(sequenceName).append("')");
            return sql.toString();
        }

        @Override
        protected String[] getDuplicateKeyErrorCodes()
        {
            return duplicateKeyErrorCodes;
        }

        @Override
        protected String[] getDataIntegrityViolationCodes()
        {
            return dataIntegrityViolationCodes;
        }

        @Override
        protected boolean isUseSqlStateAsCode()
        {
            return true;
        }

    }

    private static class Oracle extends DataSourceWrapperImpl
    {
        private static final String[] duplicateKeyErrorCodes = new String[]{"1"};
        private static final String[] dataIntegrityViolationCodes = new String[]
        {
            "1400", "1722", "2291", "2292"
        };

        Oracle(String name, HikariDataSource service)
        {
            super(name, service);
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
        public String createFetchFirstSelectSQL(String coreSql, int rows, String orderBy)
        {
            StringBuilder sql = new StringBuilder(coreSql.length() + 50);

            if(orderBy == null || orderBy.isEmpty())
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
        protected String buildCreateSequenceSql(String sequenceName, long startValue)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("CREATE SEQUENCE ").append(sequenceName);
            sql.append(" START WITH ").append(startValue);
            sql.append(" INCREMENT BY 1 NOCYCLE NOCACHE");
            return sql.toString();
        }

        @Override
        protected String buildDropSequenceSql(String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("DROP SEQUENCE ").append(sequenceName);
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 50);
            sql.append("SELECT ").append(sequenceName).append(".NEXTVAL FROM DUAL");
            return sql.toString();
        }

        @Override
        protected String[] getDuplicateKeyErrorCodes()
        {
            return duplicateKeyErrorCodes;
        }

        @Override
        protected String[] getDataIntegrityViolationCodes()
        {
            return dataIntegrityViolationCodes;
        }

    }

    private static class H2 extends DataSourceWrapperImpl
    {
        private static final String[] duplicateKeyErrorCodes = new String[]{"23001", "23505"};
        private static final String[] dataIntegrityViolationCodes = new String[]
        {
            "22001", "22003", "22012", "22018", "22025", "23000", "23002",
            "23003", "23502", "23503", "23506", "23507", "23513"
        };

        H2(String name, HikariDataSource service)
        {
            super(name, service);
        }

        @Override
        public final DatabaseType getDatabaseType()
        {
            return DatabaseType.H2;
        }

        @Override
        public String createFetchFirstSelectSQL(String coreSql, int rows, String orderBy)
        {
            StringBuilder sql = new StringBuilder(coreSql.length() + 50);
            sql.append("SELECT ").append(coreSql);

            if(orderBy != null && orderBy.isEmpty() == false)
            {
                sql.append(" ORDER BY ").append(orderBy);
            }

            sql.append(" LIMIT ").append(rows);
            return sql.toString();
        }

        @Override
        protected String buildCreateSequenceSql(String sequenceName, long startValue)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("CREATE SEQUENCE ").append(sequenceName);
            sql.append(" START WITH ").append(startValue);
            sql.append(" INCREMENT BY 1 NO CYCLE NO CACHE");
            return sql.toString();
        }

        @Override
        protected String buildDropSequenceSql(String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("DROP SEQUENCE ").append(sequenceName);
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("SELECT NEXTVAL ('").append(sequenceName).append("')");
            return sql.toString();
        }

        @Override
        protected String[] getDuplicateKeyErrorCodes()
        {
            return duplicateKeyErrorCodes;
        }

        @Override
        protected String[] getDataIntegrityViolationCodes()
        {
            return dataIntegrityViolationCodes;
        }

    }

    private static class HSQL extends DataSourceWrapperImpl
    {
        private static final String[] duplicateKeyErrorCodes = new String[]{"-104"};
        private static final String[] dataIntegrityViolationCodes = new String[]{"-9"};

        HSQL(String name, HikariDataSource service)
        {
            super(name, service);
        }

        @Override
        public final DatabaseType getDatabaseType()
        {
            return DatabaseType.H2;
        }

        @Override
        public String createFetchFirstSelectSQL(String coreSql, int rows, String orderBy)
        {
            StringBuilder sql = new StringBuilder(coreSql.length() + 80);
            sql.append("SELECT ").append(coreSql);

            if(orderBy != null && orderBy.isEmpty() == false)
            {
                sql.append(" ORDER BY ").append(orderBy);
            }

            sql.append(" LIMIT ").append(rows);
            return sql.toString();
        }

        @Override
        protected String buildCreateSequenceSql(String sequenceName, long startValue)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 80);
            sql.append("CREATE SEQUENCE ").append(sequenceName);
            sql.append(" AS BIGINT START WITH ").append(startValue);
            sql.append(" INCREMENT BY 1");
            return sql.toString();
        }

        @Override
        protected String buildDropSequenceSql(String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("DROP SEQUENCE ").append(sequenceName);
            return sql.toString();
        }

        @Override
        protected String buildNextSeqValueSql(String sequenceName)
        {
            StringBuilder sql = new StringBuilder(sequenceName.length() + 20);
            sql.append("SELECT NEXTVAL ('").append(sequenceName).append("')");
            return sql.toString();
        }

        @Override
        protected String[] getDuplicateKeyErrorCodes()
        {
            return duplicateKeyErrorCodes;
        }

        @Override
        protected String[] getDataIntegrityViolationCodes()
        {
            return dataIntegrityViolationCodes;
        }

    }

    /**
     * References the real data source implementation this class acts as pure
     * proxy for. Derived classes must set this field at construction time.
     */
    protected final HikariDataSource service;

    protected final String name;

    private DataSourceWrapperImpl(String name, HikariDataSource service)
    {
        ParamChecker.assertNotNull("service", service);
        this.name = name;
        this.service = service;
    }

    static DataSourceWrapper createDataSource(String name, Properties props, DatabaseType databaseType)
    {
        ParamChecker.assertNotEmpty("props", props);
        ParamChecker.assertNotNull("databaseType", databaseType);

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
            if(url.startsWith("jdbc:db2:"))
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
    throws SQLException
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
            LOG.error("Could not create connection to database {}", e.getMessage());
            LOG.debug("Could not create connection to database", e);
            throw e;
        }
    }

    @Override
    public void returnConnection(Connection conn)
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
            LOG.error("Could not create connection to database {}", e.getMessage());
            LOG.debug("Could not create connection to database", e);
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
            LOG.warn("Could not shutdown datasource: {}", e.getMessage());
            LOG.debug("Could not close datasource", e);
        }
    }

    public final PrintWriter getLogWriter()
    throws SQLException
    {
        return service.getLogWriter();
    }

    @Override
    public Statement createStatement(Connection conn)
    throws SQLException
    {
        return conn.createStatement();
    }

    @Override
    public PreparedStatement prepareStatement(Connection conn, String sqlQuery)
    throws SQLException
    {
        return conn.prepareStatement(sqlQuery);
    }

    @Override
    public void releaseResources(Statement ps, ResultSet rs)
    {
        if(rs != null)
        {
            try
            {
                rs.close();
            }catch(Throwable t)
            {
                LOG.warn("Cannot close ResultSet", t);
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
                LOG.warn("Cannot close statement", t);
            }finally
            {
                if(conn != null)
                {
                    returnConnection(conn);
                }
            }
        }
    }

    private void releaseStatementAndResultSet(Statement ps, ResultSet rs)
    {
        if(rs != null)
        {
            try
            {
                rs.close();
            }catch(Throwable t)
            {
                LOG.warn("Cannot close ResultSet", t);
            }
        }

        if(ps != null)
        {
            try
            {
                ps.close();
            }catch(Throwable t)
            {
                LOG.warn("Cannot close statement", t);
            }
        }
    }

    @Override
    public String createFetchFirstSelectSQL(String coreSql, int rows)
    {
        return createFetchFirstSelectSQL(coreSql, rows, null);
    }

    @Override
    public long getMin(Connection conn, String table, String column)
    throws SQLException
    {
        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = (conn != null) ? conn.createStatement() : getConnection().createStatement();
            StringBuilder sql = new StringBuilder(column.length() + table.length() + 20);
            sql.append("SELECT MIN(").append(column).append(") FROM ").append(table);
            rs = stmt.executeQuery(sql.toString());

            rs.next();
            return rs.getLong(1);
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
    public int getCount(Connection conn, String table)
    throws SQLException
    {
        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = (conn != null) ? conn.createStatement() : getConnection().createStatement();
            StringBuilder sql = new StringBuilder(table.length() + 25);
            sql.append("SELECT COUNT(*) FROM ").append(table);
            rs = stmt.executeQuery(sql.toString());
            rs.next();
            return rs.getInt(1);
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
    public long getMax(Connection conn, String table, String column)
    throws SQLException
    {
        Statement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = (conn != null) ? conn.createStatement() : getConnection().createStatement();
            StringBuilder sql = new StringBuilder(column.length() + table.length() + 20);
            sql.append("SELECT MAX(").append(column).append(") FROM ").append(table);
            rs = stmt.executeQuery(sql.toString());
            rs.next();
            return rs.getLong(1);
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
    public boolean columnExists(Connection conn, String table, String column, Object value)
    throws SQLException
    {
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
    public boolean tableHasColumn(Connection conn, String table, String column)
    throws SQLException
    {
        Statement stmt = (conn != null) ? conn.createStatement() : getConnection().createStatement();
        try
        {
            StringBuilder sql = new StringBuilder(column.length() + table.length() + 20);
            sql.append(column).append(" FROM ").append(table);
            stmt.execute(createFetchFirstSelectSQL(sql.toString(), 1));
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
    public boolean tableExists(Connection conn, String table)
    throws SQLException
    {
        Statement stmt = (conn != null) ? conn.createStatement() : getConnection().createStatement();
        try
        {
            StringBuilder sql = new StringBuilder(table.length() + 10);
            sql.append("1 FROM ").append(table);
            stmt.execute(createFetchFirstSelectSQL(sql.toString(), 1));
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

    protected abstract String buildCreateSequenceSql(String sequenceName, long startValue);

    protected abstract String buildDropSequenceSql(String sequenceName);

    protected abstract String buildNextSeqValueSql(String sequenceName);

    protected abstract String[] getDuplicateKeyErrorCodes();

    protected abstract String[] getDataIntegrityViolationCodes();

    protected boolean isUseSqlStateAsCode()
    {
        return false;
    }

    @Override
    public void dropAndCreateSequence(String sequenceName, long startValue)
    throws SQLException
    {
        try
        {
            dropSequence(sequenceName);
        }catch(SQLException e)
        {
        }

        createSequence(sequenceName, startValue);
    }

    @Override
    public void createSequence(String sequenceName, long startValue)
    throws SQLException
    {
        String sql = buildCreateSequenceSql(sequenceName, startValue);
        Connection conn = getConnection();
        Statement stmt = null;
        try
        {
            stmt = conn.createStatement();
            stmt.execute(sql);
            LOG.info("datasource {} CREATESEQ {} START {}", name, sequenceName, startValue);
        }
        finally
        {
            releaseResources(stmt, null);
        }

    }

    @Override
    public void dropSequence(String sequenceName)
    throws SQLException
    {
        String sql = buildDropSequenceSql(sequenceName);

        Connection conn = getConnection();
        Statement stmt = null;
        try
        {
            stmt = conn.createStatement();
            stmt.execute(sql);
            LOG.info("datasource {} DROPSEQ {}", name, sequenceName);
        }
        finally
        {
            releaseResources(stmt, null);
        }
    }

    @Override
    public long nextSeqValue(String sequenceName)
    throws SQLException
    {
        String sql = buildNextSeqValueSql(sequenceName);
        Connection conn = getConnection();
        Statement stmt = conn.createStatement();
        ResultSet rs = null;

        long ret;
        try
        {
            rs = stmt.executeQuery(sql);
            if(rs.next())
            {
                ret = rs.getLong(1);
            } else
            {
                throw new SQLException("Could not increment the sequence " + sequenceName);
            }
        }finally
        {
            releaseResources(stmt, rs);
        }

        LOG.debug("datasource {} NEXVALUE({}): {}", name, sequenceName, ret);
        return ret;
    }

    @Override
    public boolean isDuplicateKeyException(SQLException sqlException)
    {
        return isSqlExceptionContained(sqlException, getDuplicateKeyErrorCodes());
    }

    @Override
    public boolean isDataIntegrityViolation(SQLException sqlException)
    {
        return isSqlExceptionContained(sqlException, getDataIntegrityViolationCodes());
    }

    private boolean isSqlExceptionContained(SQLException ex, String[] errorCodes)
    {
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

        String errorCode;
        if (isUseSqlStateAsCode())
        {
            errorCode = sqlEx.getSQLState();
        } else
        {
            // Try to find SQLException with actual error code, looping through the causes.
            // E.g. applicable to java.sql.DataTruncation as of JDK 1.6.
            SQLException current = sqlEx;
            while (current.getErrorCode() == 0 && current.getCause() instanceof SQLException)
            {
                current = (SQLException) current.getCause();
            }
            errorCode = Integer.toString(current.getErrorCode());
        }

        LOG.debug("datasource {} SQLException errorCode: {}", name, errorCode);

        if (errorCode != null)
        {
            return Arrays.binarySearch(errorCodes, errorCode) >= 0;
        } else
        {
            return false;
        }
    }

}
