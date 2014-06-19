/*
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.database.hikaricp;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.database.api.DataSource;
import org.xipki.database.api.DatabaseType;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

/**
 * @author Lijun Liao
 */

public class DataSourceImpl implements DataSource
{
    private static final Logger LOG = LoggerFactory.getLogger(DataSourceImpl.class);
    private PasswordResolver passwordResolver;

    private Boolean autoCommit;
    private Boolean readOnly;
    private Integer transactionIsolation;
    private Integer connectionTimeout;
    private Integer idleTimeout;
    private Integer maxLifetime;
    private String driverClassName;
    private String url;
    private Integer minimumIdle;
    private Integer maxActive;
    private String username;
    private String password;

    /**
     * References the real data source implementation this class acts as pure
     * proxy for. Derived classes must set this field at construction time.
     */
    HikariDataSource service;

    private DatabaseType databaseType;

    public DataSourceImpl()
    {
    }

    public void init()
    throws SQLException, PasswordResolverException
    {
        if(driverClassName == null)
        {
            throw new IllegalStateException("driverClassName is not set");
        }

        if(url == null)
        {
            throw new IllegalStateException("url is not set");
        }

        if(username == null)
        {
            throw new IllegalStateException("url is not set");
        }

        String realPassword = null;
        if(password != null)
        {
            if(passwordResolver == null)
            {
                throw new IllegalStateException("password ist set but passwordResolver not");
            }
            else
            {
                char[] _realPassword = passwordResolver.resolvePassword(password);
                realPassword = new String(_realPassword);
            }
        }

        if(service != null)
        {
            service.close();
            service = null;
        }

        HikariConfig conf = new HikariConfig();
        conf.setDriverClassName(driverClassName);
        conf.setJdbcUrl(url);
        conf.setUsername(username);

        if(realPassword != null)
        {
            conf.setPassword(realPassword);
        }

        if(maxActive != null)
        {
            conf.setMaximumPoolSize(maxActive);
        }

        if(minimumIdle != null)
        {
            conf.setMinimumIdle(minimumIdle);
        }

        if(autoCommit != null)
        {
            conf.setAutoCommit(autoCommit);
        }

        if(readOnly != null)
        {
            conf.setReadOnly(readOnly);
        }

        if(transactionIsolation != null)
        {
            String isolationText;
            switch(transactionIsolation)
            {
                case Connection.TRANSACTION_READ_COMMITTED:
                    isolationText = "TRANSACTION_READ_COMMITTED";
                    break;
                case Connection.TRANSACTION_READ_UNCOMMITTED:
                    isolationText = "TRANSACTION_READ_UNCOMMITTED";
                    break;
                case Connection.TRANSACTION_REPEATABLE_READ:
                    isolationText = "TRANSACTION_REPEATABLE_READ";
                    break;
                case Connection.TRANSACTION_SERIALIZABLE:
                    isolationText = "TRANSACTION_SERIALIZABLE";
                    break;
                default:
                    isolationText = null;
            }
            if(isolationText != null)
            {
                conf.setTransactionIsolation(isolationText);
            }
        }

        if(connectionTimeout != null)
        {
            conf.setConnectionTimeout(connectionTimeout);
        }

        if(idleTimeout != null)
        {
            conf.setIdleTimeout(idleTimeout);
        }

        if(maxLifetime != null)
        {
            conf.setMaxLifetime(maxLifetime);
        }

        service = new HikariDataSource(conf);
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
            LOG.error("Could not create connection to database {} with the user {} and jdbc driver {}",
                    new String[]{url, username, driverClassName});
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
            LOG.warn("Could not close connection: {}", e.getMessage());
            LOG.debug("Could not close connection", e);
        }
    }

    public final PrintWriter getLogWriter()
    throws SQLException
    {
        return service.getLogWriter();
    }

    public final void setLogWriter(PrintWriter out)
    throws SQLException
    {
        service.setLogWriter(out);
    }

    public void setDriverClassName(String driverClassName)
    {
        this.driverClassName = driverClassName;
        this.databaseType = DatabaseType.getDataSourceForDriver(driverClassName);
    }

    public void setMaxActive(int maxActive)
    {
        this.maxActive = maxActive;
    }

    public void setMinimumIdle(int setMinimumIdle)
    {
        this.minimumIdle = setMinimumIdle;
    }

    public void setPassword(String password)
    {
        this.password = password;
    }

    public void setUrl(String url)
    {
        this.url = url;
    }

    public void setUsername(String username)
    {
        this.username = username;
    }

    public void setAutoCommit(boolean autoCommit)
    {
        this.autoCommit = autoCommit;
    }

    public void setReadOnly(boolean readOnly)
    {
        this.readOnly = readOnly;
    }

    public void setTransactionIsolation(int transactionIsolation)
    {
        this.transactionIsolation = transactionIsolation;
    }

    @Override
    public final DatabaseType getDatabaseType()
    {
        return databaseType;
    }

    public void setPasswordResolver(PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
    }

    public void setConnectionTimeout(Integer connectionTimeout)
    {
        this.connectionTimeout = connectionTimeout;
    }

    public void setIdleTimeout(Integer idleTimeout)
    {
        this.idleTimeout = idleTimeout;
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

}
