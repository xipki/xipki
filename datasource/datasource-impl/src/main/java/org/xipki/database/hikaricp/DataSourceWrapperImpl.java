/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.database.hikaricp;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.database.api.DataSourceWrapper;
import org.xipki.database.api.DatabaseType;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

/**
 * @author Lijun Liao
 */

public class DataSourceWrapperImpl implements DataSourceWrapper
{
    private static final Logger LOG = LoggerFactory.getLogger(DataSourceWrapperImpl.class);

    /**
     * References the real data source implementation this class acts as pure
     * proxy for. Derived classes must set this field at construction time.
     */
    final HikariDataSource service;

    private final DatabaseType databaseType;

    DataSourceWrapperImpl(Properties props, DatabaseType databaseType)
    {
        HikariConfig conf = new HikariConfig(props);
        this.service = new HikariDataSource(conf);
        this.databaseType = databaseType;
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
    public final DatabaseType getDatabaseType()
    {
        return databaseType;
    }

    @Override
    public Statement createStatement(Connection conn)
    throws SQLException
    {
        return conn.createStatement();
    }

    @Override
    public PreparedStatement prepareStatement(Connection conn,
            String sqlQuery)
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

    /*
     * Oracle: http://www.oracle.com/technetwork/issue-archive/2006/06-sep/o56asktom-086197.html
     *
     */
    @Override
    public String createFetchFirstSelectSQL(String coreSql, int rows, String orderBy)
    {
        String prefix;
        String suffix;

        if(databaseType == DatabaseType.ORACLE)
        {
            if(orderBy == null || orderBy.isEmpty())
            {
                prefix = "SELECT";
                if(coreSql.contains("WHERE"))
                {
                    suffix = " AND ROWNUM < " + (rows + 1);
                }
                else
                {
                    suffix = " WHERE ROWNUM < " + (rows + 1);
                }
            }
            else
            {
                prefix = "SELECT * FROM ( SELECT";
                suffix = "ORDER BY " + orderBy + " ) WHERE ROWNUM < " + (rows + 1);
            }
        }
        else
        {
            prefix = "SELECT";
            suffix = "";

            if(orderBy != null && orderBy.isEmpty() == false)
            {
                suffix += "ORDER BY " + orderBy + " ";
            }

            switch(databaseType)
            {
                case DB2:
                case POSTGRESQL:
                case SYBASE:
                    suffix += "FETCH FIRST " + rows + " ROWS ONLY";
                    break;
                case H2:
                case MYSQL:
                case HSQLDB:
                    suffix += "LIMIT " + rows;
                    break;
                case MSSQL2000:
                    prefix = "SELECT TOP " + rows;
                    break;
                default:
                    break;
            }
        }

        return prefix + " " + coreSql + " " + suffix;
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
            final String sql = "SELECT MIN(" + column + ") FROM " + table;
            rs = stmt.executeQuery(sql);

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
            final String sql = "SELECT COUNT(*) FROM " + table;
            rs = stmt.executeQuery(sql);

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
            final String sql = "SELECT MAX(" + column + ") FROM " + table;
            rs = stmt.executeQuery(sql);

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
    public boolean tableHasColumn(Connection conn, String table, String column)
    throws SQLException
    {
        Statement stmt = (conn != null) ? conn.createStatement() : getConnection().createStatement();
        try
        {
            stmt.execute(createFetchFirstSelectSQL(column + " FROM " + table, 1));
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
            stmt.execute(createFetchFirstSelectSQL("1 FROM " + table, 1));
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
    public void createSequence(String sequenceName, long startValue)
    throws SQLException
    {
        switch(databaseType)
        {
            case DB2:
            case ORACLE:
            case POSTGRESQL:
            case H2:
            case HSQLDB:
                StringBuilder sb = new StringBuilder();
                sb.append("CREATE SEQUENCE ").append(sequenceName).append(" ");

                if(DatabaseType.DB2 == databaseType)
                {
                    sb.append("AS BIGINT START WITH ");
                    sb.append(startValue);
                    sb.append(" INCREMENT BY 1 NO CYCLE NO CACHE");
                }
                else if(DatabaseType.ORACLE == databaseType)
                {
                    sb.append("START WITH ");
                    sb.append(startValue);
                    sb.append(" INCREMENT BY 1 NOCYCLE NOCACHE");
                }
                else if(DatabaseType.POSTGRESQL == databaseType)
                {
                    sb.append("START WITH ");
                    sb.append(startValue);
                    sb.append(" INCREMENT BY 1 NO CYCLE");
                }
                else if(DatabaseType.H2 == databaseType)
                {
                    sb.append("START WITH ");
                    sb.append(startValue);
                    sb.append(" INCREMENT BY 1 NO CYCLE NO CACHE");
                }
                else if(DatabaseType.HSQLDB == databaseType)
                {
                    sb.append("AS BIGINT START WITH ");
                    sb.append(startValue);
                    sb.append(" INCREMENT BY 1");
                }
                else
                {
                    throw new RuntimeException("should not reach here");
                }

                String sql = sb.toString();

                Connection conn = getConnection();
                Statement stmt = null;
                try
                {
                    stmt = conn.createStatement();
                    stmt.execute(sql);
                }
                finally
                {
                    releaseResources(stmt, null);
                }

                break;
            case MYSQL:
                break;
            default:
                throw new RuntimeException("unsupported database type " + databaseType);
        }
    }

    @Override
    public void dropSequence(String sequenceName)
    throws SQLException
    {
        switch(databaseType)
        {
            case DB2:
            case ORACLE:
            case POSTGRESQL:
            case H2:
            case HSQLDB:
                String  sql = "DROP SEQUENCE " + sequenceName;

                Connection conn = getConnection();
                Statement stmt = null;
                try
                {
                    stmt = conn.createStatement();
                    stmt.execute(sql);
                }
                finally
                {
                    releaseResources(stmt, null);
                }

                break;
            case MYSQL:
                break;
            default:
                throw new RuntimeException("unsupported database type " + databaseType);
        }
    }

}
