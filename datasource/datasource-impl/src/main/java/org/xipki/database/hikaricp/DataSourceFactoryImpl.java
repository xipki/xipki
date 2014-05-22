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

        // defaultAutoCommit
        b = getBooleanValue(config, DEFAULT_AUTOCOMMIT);
        if(b != null)
        {
            ds.setAutoCommit(b);
        }

        // defaultReadOnly
        b = getBooleanValue(config, DEFAULT_READONLY);
        if(b != null)
        {
            ds.setReadOnly(b);
        }

        // defaultTransactionIsolation
        i  = getIntValue(config, DEFAULT_TRANSACTION_ISOLATION);
        if(i != null)
        {
            ds.setTransactionIsolation(i);
        }

        // maxActive
        i = getIntValue(config, MAX_ACTIVE);
        if(i != null)
        {
            ds.setMaxActive(i);
        }

        // minIdle
        i = getIntValue(config, MIN_IDLE);
        if(i != null)
        {
            ds.setMinimumIdle(i);
        }

        // connectionTimeout
        i = getIntValue(config, MAX_WAIT);
        if(i != null)
        {
            ds.setConnectionTimeout(i);
        }

        i = getIntValue(config,MAX_LIFETIME);
        if(i != null)
        {
            ds.setMaxActive(i);
        }

        i = getIntValue(config, IDLE_TIMEOUT);
        if(i != null)
        {
            ds.setIdleTimeout(i);
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

    private final static String P = "db.";
    private final static String DRIVER_CLASSNAME = P + "driverClassName";
    private final static String URL = P + "url";
    private final static String USERNAME = P + "username";
    private final static String PASSWORD = P + "password";

    private final static String DEFAULT_AUTOCOMMIT = "defaultAutoCommit";
    private final static String DEFAULT_READONLY = "defaultReadOnly";
    private final static String DEFAULT_TRANSACTION_ISOLATION = "defaultTransactionIsolation";

    private final static String MAX_ACTIVE = P + "maxActive";
    private final static String MIN_IDLE = P + "minIdle";
    private final static String MAX_WAIT = P + "maxWait";

    private final static String IDLE_TIMEOUT = P + "idleTimeout";
    private final static String MAX_LIFETIME = P + "maxLifetime";

}
