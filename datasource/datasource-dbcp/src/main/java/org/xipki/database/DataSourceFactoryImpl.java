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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.SQLException;
import java.util.Properties;

import org.xipki.database.api.DataSource;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;

public class DataSourceFactoryImpl implements DataSourceFactory
{
    @Override
    public DataSource createDataSourceForFile(String confFile, PasswordResolver passwordResolver)
    throws SQLException, PasswordResolverException, IOException
    {
        if(confFile == null)
        {
            throw new IllegalArgumentException("confFile could not be null");
        }
        if(passwordResolver == null)
        {
            throw new IllegalArgumentException("passwordResolver could not be null");
        }

        FileInputStream fIn = null;

        try
        {
            fIn = new FileInputStream(confFile);
            return createDataSource(fIn, passwordResolver);
        }finally
        {
            if(fIn != null)
            {
                try
                {
                    fIn.close();
                }catch(IOException e){};
            }
        }
    }

    @Override
    public DataSource createDataSource(InputStream conf, PasswordResolver passwordResolver)
    throws SQLException, PasswordResolverException, IOException
    {
        if(conf == null)
        {
            throw new IllegalArgumentException("conf could not be null");
        }
        if(passwordResolver == null)
        {
            throw new IllegalArgumentException("passwordResolver could not be null");
        }

        Properties config = new Properties();
        config.load(conf);

        DataSourceImpl ds = new DataSourceImpl();

        String s;
        Boolean b;
        Integer i;
        Long l;

        String driverClassName = config.getProperty(DRIVER_CLASSNAME);
        if(driverClassName != null)
        {
            ds.setDriverClassName(driverClassName.trim());
        }

        // username
        s = config.getProperty(USERNAME);
        if(s != null)
        {
            ds.setUsername(s.trim());
        }

        // password
        String password = config.getProperty(PASSWORD);
        if(password != null)
        {
            ds.setPassword(password.trim());
        }

        // url
        s = config.getProperty(URL);
        if(s != null)
        {
            ds.setUrl(s.trim());
        }

        // connectionProperties
        s = config.getProperty(CONNECTION_PROPERTIES);
        if(s != null)
        {
            ds.setConnectionProperties(s.trim());
        }

        // defaultAutoCommit
        b = getBooleanValue(config, DEFAULT_AUTOCOMMIT);
        if(b != null)
        {
            ds.setDefaultAutoCommit(b);
        }

        // defaultReadOnly
        b = getBooleanValue(config, DEFAULT_READONLY);
        if(b != null)
        {
            ds.setDefaultReadOnly(b);
        }

        // defaultTransactionIsolation
        i  = getIntValue(config,  DEFAULT_TRANSACTION_ISOLATION);
        if(i != null)
        {
            ds.setDefaultTransactionIsolation(i);
        }

        // maxActive
        i = getIntValue(config, MAX_ACTIVE);
        if(i != null)
        {
            ds.setMaxActive(i);
        }

        // maxIdle
        i = getIntValue(config, MAX_IDLE);
        if(i != null)
        {
            ds.setMaxIdle(i);
        }

        // minIdle
        i = getIntValue(config, MIN_IDLE);
        if(i != null)
        {
            ds.setMinIdle(i);
        }

        // maxWait
        l = getLongValue(config, MAX_WAIT);
        if(i != null)
        {
            ds.setMaxWait(l);
        }

        // validationQuery
        s = config.getProperty(VALIDATION_QUERY);
        if(s != null)
        {
            ds.setValidationQuery(s);
        }

        // testOnBorrow
        b = getBooleanValue(config, TEST_ON_BORROW);
        if(b != null)
        {
            ds.setTestOnBorrow(b);
        }

        // testOnReturn
        b = getBooleanValue(config, TEST_ON_RETURN);
        if(b != null)
        {
            ds.setTestOnReturn(b);
        }

        // testWhileIdle
        b = getBooleanValue(config, TEST_WHILE_IDLE);
        if(b != null)
        {
            ds.setTestWhileIdle(b);
        }

        // timeBetweenEvictionRunsMillis
        l = getLongValue(config, TIME_BETWEEN_EVICTION_RUNS_MILLIS);
        if(l != null)
        {
            ds.setTimeBetweenEvictionRunsMillis(l);
        }

        // numTestsPerEvictionRun
        i = getIntValue(config, NUM_TESTS_PER_EVICTION_RUN);
        if(i != null)
        {
            ds.setNumTestsPerEvictionRun(i);
        }

        // minEvictableIdleTimeMillis
        l = getLongValue(config, MIN_EVICTABLE_IDLE_TIME_MILLIS);
        if(l != null)
        {
            ds.setMinEvictableIdleTimeMillis(l);
        }

        // poolPreparedStatements
        b = getBooleanValue(config, POOL_PREPARED_STATMENTS);
        if(b != null)
        {
            ds.setPoolPreparedStatements(b);
        }

        // maxOpenPreparedStatements
        i = getIntValue(config, MAX_OPEN_PREPARED_STATEMENTS);
        if(i != null)
        {
            ds.setMaxOpenPreparedStatements(i);
        }

        ds.setPasswordResolver(passwordResolver);
        ds.init();
        return ds;
    }

    private static Boolean getBooleanValue(Properties props, String key)
    {
        String prop = props.getProperty(key);
        if(prop != null && !prop.isEmpty())
        {
            return Boolean.valueOf(prop.trim());
        }

        return null;
    }

    private static Integer getIntValue(Properties props, String key)
    {
        String prop = props.getProperty(key);
        if(prop != null && !prop.isEmpty())
        {
            try
            {
                return Integer.parseInt(prop.trim());
            }catch(NumberFormatException e)
            {
            }
        }

        return null;
    }

    private static Long getLongValue(Properties props, String key)
    {
        String prop = props.getProperty(key);
        if(prop != null && !prop.isEmpty())
        {
            try
            {
                return Long.parseLong(prop.trim());
            }catch(NumberFormatException e)
            {
            }
        }

        return null;
    }

    private final static String P = "db.";
    public final static String DRIVER_CLASSNAME = P + "driverClassName";
    public final static String URL = P + "url";
    public final static String USERNAME = P + "username";
    public final static String PASSWORD = P + "password";
    public final static String CONNECTION_PROPERTIES = P + "connectionProperties";

    public final static String DEFAULT_AUTOCOMMIT = "defaultAutoCommit";
    public final static String DEFAULT_READONLY = "defaultReadOnly";
    public final static String DEFAULT_TRANSACTION_ISOLATION = "defaultTransactionIsolation";

    public final static String MAX_ACTIVE = P + "maxActive";
    public final static String MIN_IDLE = P + "minIdle";
    public final static String MAX_IDLE = P + "maxIdle";
    public final static String MAX_WAIT = P + "maxWait";

    public final static String VALIDATION_QUERY = P + "validationQuery";
    public final static String TEST_ON_BORROW = P + "testOnBorrow";
    public final static String TEST_ON_RETURN = P + "testOnReturn";
    public final static String TEST_WHILE_IDLE = P + "testWhileIdle";

    public final static String NUM_TESTS_PER_EVICTION_RUN = P + "numTestsPerEvictionRun";
    public final static String TIME_BETWEEN_EVICTION_RUNS_MILLIS = P + "timeBetweenEvictionRunsMillis";
    public final static String MIN_EVICTABLE_IDLE_TIME_MILLIS = P + "minEvictableIdleTimeMillis";

    public final static String POOL_PREPARED_STATMENTS = P + "poolPreparedStatements";
    public final static String MAX_OPEN_PREPARED_STATEMENTS = P + "maxOpenPreparedStatements";

}
