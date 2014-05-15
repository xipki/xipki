/*
 * Copyright (c) 2014 xipki.org
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

public class DataSourceImpl implements DataSource
{
    private static final Logger LOG = LoggerFactory.getLogger(DataSourceImpl.class);
    private PasswordResolver passwordResolver;

    private Integer loginTimeout;
    private String driverClassName;
    private Integer maxActive;
    private Integer minIdle;
    private String password;
    private String url;
    private String username;
    private String validationQuery;
    private Integer validationQueryTimeout;
    private Boolean defaultAutoCommit;
    private Boolean defaultReadOnly;
    private String defaultTransactionIsolation;
    @SuppressWarnings("unused")
    private String connectionProperties;

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

        if(minIdle != null)
        {
            conf.setMinimumIdle(minIdle);
        }

        if(validationQuery != null)
        {
            conf.setConnectionTestQuery(validationQuery);
        }

        if(validationQueryTimeout != null)
        {
        }

        if(defaultAutoCommit != null)
        {
            conf.setAutoCommit(defaultAutoCommit);
        }

        if(defaultReadOnly != null)
        {
            conf.setReadOnly(defaultReadOnly);
        }

        if(defaultTransactionIsolation != null)
        {
            service.setTransactionIsolation(defaultTransactionIsolation);
        }

        service = new HikariDataSource(conf);
        if(loginTimeout != null)
        {
            service.setLoginTimeout(loginTimeout);
        }

    }

    public final Connection getConnection(int timeout)
    throws SQLException
    {
    	try{
    		return service.getConnection();
        } catch(SQLException e)
        {
        	LOG.error("Could not create connection to database {} with the user {} and jdbc driver {}", 
        			new String[]{url, username, driverClassName});
            throw e;
        }
    }

    public void returnConnection(Connection conn)
    {
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

    public final void setLoginTimeout(int seconds)
    throws SQLException
    {
        this.loginTimeout = seconds;
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

    public void setMinIdle(int minIdle)
    {
        this.minIdle = minIdle;
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

    public void setValidationQuery(String validationQuery)
    {
        this.validationQuery = getString(validationQuery);
    }

    public void setValidationQueryTimeout(int timeout)
    {
        this.validationQueryTimeout = timeout;
    }

    public void setDefaultAutoCommit(boolean defaultAutoCommit)
    {
        this.defaultAutoCommit = defaultAutoCommit;
    }

    public void setDefaultReadOnly(boolean defaultReadOnly)
    {
        this.defaultReadOnly = defaultReadOnly;
    }

    public void setDefaultTransactionIsolation(String defaultTransactionIsolation)
    {
        this.defaultTransactionIsolation = defaultTransactionIsolation;
    }

    public final DatabaseType getDatabaseType()
    {
        return databaseType;
    }

    public void setConnectionProperties(String connectionProperties)
    {
        this.connectionProperties = getString(connectionProperties);
    }

    public void setPasswordResolver(PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
    }

    private static String getString(String str)
    {
        return (str == null || str.isEmpty()) ? null : str;
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

}