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

package org.xipki.database;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.dbcp.SQLNestedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.database.api.DataSource;
import org.xipki.database.api.DatabaseType;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;

@SuppressWarnings("deprecation")
public class DataSourceImpl implements DataSource
{
    private static final Logger LOG = LoggerFactory.getLogger(DataSourceImpl.class);
    private PasswordResolver passwordResolver;

    private Integer loginTimeout;
    private String driverClassName;
    private Integer maxActive;
    private Integer maxIdle;
    private Integer maxOpenPreparedStatements;
    private Long maxWait;
    private Long minEvictableIdleTimeMillis;
    private Integer minIdle;
    private Integer numTestsPerEvictionRun;
    private String password;
    private Boolean poolPreparedStatements;
    private Boolean removeAbandoned;
    private Integer removeAbandonedTimeout;
    private Boolean testOnBorrow;
    private Boolean testOnReturn;
    private Boolean testWhileIdle;
    private Long timeBetweenEvictionRunsMillis;
    private String url;
    private String username;
    private String validationQuery;
    private Integer validationQueryTimeout;
    private Boolean defaultAutoCommit;
    private Boolean defaultReadOnly;
    private Integer defaultTransactionIsolation;
    private String connectionProperties;

    /**
     * References the real data source implementation this class acts as pure
     * proxy for. Derived classes must set this field at construction time.
     */
    private BasicDataSource service;

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

        service = new BasicDataSource();

        service.setDriverClassName(driverClassName);
        service.setUrl(url);
        service.setUsername(username);
        if(realPassword != null)
        {
            service.setPassword(realPassword);
        }

        if(loginTimeout != null)
        {
            service.setLoginTimeout(loginTimeout);
        }

        if(maxActive != null)
        {
            service.setMaxActive(maxActive);
        }

        if(maxIdle != null)
        {
            service.setMaxIdle(maxIdle);
        }

        if(maxOpenPreparedStatements != null)
        {
            service.setMaxOpenPreparedStatements(maxOpenPreparedStatements);
        }

        if(maxWait != null)
        {
            service.setMaxWait(maxWait);
        }

        if(minEvictableIdleTimeMillis != null)
        {
            service.setMinEvictableIdleTimeMillis(minEvictableIdleTimeMillis);
        }

        if(minIdle != null)
        {
            service.setMinIdle(minIdle);
        }

        if(numTestsPerEvictionRun != null)
        {
            service.setNumTestsPerEvictionRun(numTestsPerEvictionRun);
        }

        if(poolPreparedStatements != null)
        {
            service.setPoolPreparedStatements(poolPreparedStatements);
        }

        if(removeAbandoned != null)
        {
            service.setRemoveAbandoned(removeAbandoned);
        }

        if(removeAbandonedTimeout != null)
        {
            service.setRemoveAbandonedTimeout(removeAbandonedTimeout);
        }

        if(testOnBorrow != null)
        {
            service.setTestOnBorrow(testOnBorrow);
        }

        if(testOnReturn != null)
        {
            service.setTestOnReturn(testOnReturn);
        }

        if(testWhileIdle != null)
        {
            service.setTestWhileIdle(testWhileIdle);
        }

        if(timeBetweenEvictionRunsMillis != null)
        {
            service.setTimeBetweenEvictionRunsMillis(timeBetweenEvictionRunsMillis);
        }

        if(validationQuery != null)
        {
            service.setValidationQuery(validationQuery);
        }

        if(validationQueryTimeout != null)
        {
            service.setValidationQueryTimeout(validationQueryTimeout);
        }

        if(defaultAutoCommit != null)
        {
            service.setDefaultAutoCommit(defaultAutoCommit);
        }

        if(defaultReadOnly != null)
        {
            service.setDefaultReadOnly(defaultReadOnly);
        }

        if(defaultTransactionIsolation != null)
        {
            service.setDefaultTransactionIsolation(defaultTransactionIsolation);
        }

        if(connectionProperties != null)
        {
            service.setConnectionProperties(connectionProperties);
        }

    }

    public final Connection getConnection(int timeout)
    throws SQLException
    {
        try
        {
            return service.getConnection();
        } catch (SQLException e)
        {
            LOG.error("Could not create connection to database {} with the user {} and jdbc driver {}",
                    new String[]{url, username, driverClassName});
            throw e;
        }
    }

    public void returnConnection(Connection conn)
    {
    	try {
			conn.close();
		} catch (SQLException e) {
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

    public void setMaxIdle(int maxIdle)
    {
        this.maxIdle = maxIdle;
    }

    public void setMaxOpenPreparedStatements(int maxOpenStatements)
    {
        this.maxOpenPreparedStatements = maxOpenStatements;
    }

    public void setMaxWait(long maxWait)
    {
        this.maxWait = maxWait;
    }

    public void setMinEvictableIdleTimeMillis(long minEvictableIdleTimeMillis)
    {
        this.minEvictableIdleTimeMillis = minEvictableIdleTimeMillis;
    }

    public void setMinIdle(int minIdle)
    {
        this.minIdle = minIdle;
    }

    public void setNumTestsPerEvictionRun(int numTestsPerEvictionRun)
    {
        this.numTestsPerEvictionRun = numTestsPerEvictionRun;
    }

    public void setPassword(String password)
    {
        this.password = password;
    }

    public void setPoolPreparedStatements(boolean poolingStatements)
    {
        this.poolPreparedStatements = poolingStatements;
    }

    public void setRemoveAbandoned(boolean removeAbandoned)
    {
        this.removeAbandoned = removeAbandoned;
    }

    public void setRemoveAbandonedTimeout(int removeAbandonedTimeout)
    {
        this.removeAbandonedTimeout = removeAbandonedTimeout;
    }

    public void setTestOnBorrow(boolean testOnBorrow)
    {
        this.testOnBorrow = testOnBorrow;
    }

    public void setTestOnReturn(boolean testOnReturn)
    {
        this.testOnReturn = testOnReturn;
    }

    public void setTestWhileIdle(boolean testWhileIdle)
    {
        this.testWhileIdle = testWhileIdle;
    }

    public void setTimeBetweenEvictionRunsMillis(long timeBetweenEvictionRunsMillis)
    {
        this.timeBetweenEvictionRunsMillis = timeBetweenEvictionRunsMillis;
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

    public void setDefaultTransactionIsolation(int defaultTransactionIsolation)
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
        try
        {
            return conn.createStatement();
        }catch (SQLNestedException e)
        {
            Throwable cause = e.getCause();
            if(cause instanceof SQLException)
            {
                throw (SQLException) e;
            }
            else
            {
                throw e;
            }
        }
    }

    @Override
    public PreparedStatement prepareStatement(Connection conn,
            String sqlQuery)
    throws SQLException
    {
        try
        {
            return conn.prepareStatement(sqlQuery);
        }catch (SQLNestedException e)
        {
            Throwable cause = e.getCause();
            if(cause instanceof SQLException)
            {
                throw (SQLException) cause;
            }
            else
            {
                throw e;
            }
        }
    }

}
