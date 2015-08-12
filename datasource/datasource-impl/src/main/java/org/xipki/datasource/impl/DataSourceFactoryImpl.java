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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.xipki.datasource.api.DataSourceFactory;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.DatabaseType;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.password.api.PasswordResolver;
import org.xipki.password.api.PasswordResolverException;

/**
 * @author Lijun Liao
 */

public class DataSourceFactoryImpl implements DataSourceFactory
{
    @Override
    public DataSourceWrapper createDataSourceForFile(
            final String name,
            final String confFile,
            final PasswordResolver passwordResolver)
    throws DataAccessException, PasswordResolverException, IOException
    {
        assertNotNull("confFile", confFile);

        FileInputStream fIn = new FileInputStream(expandFilepath(confFile));
        return createDataSource(name, fIn, passwordResolver);
    }

    @Override
    public DataSourceWrapper createDataSource(
            final String name,
            final InputStream conf,
            final PasswordResolver passwordResolver)
    throws DataAccessException, PasswordResolverException, IOException
    {
        assertNotNull("conf", conf);

        Properties config = new Properties();
        try
        {
            config.load(conf);
        }finally
        {
            try
            {
                conf.close();
            }catch(Exception e)
            {
            }
        }

        return createDataSource(name, config, passwordResolver);
    }

    @Override
    public DataSourceWrapper createDataSource(
            final String name,
            final Properties conf,
            final PasswordResolver passwordResolver)
    throws DataAccessException, PasswordResolverException
    {
        assertNotNull("conf", conf);

        DatabaseType databaseType;
        String className = conf.getProperty("dataSourceClassName");
        if(className != null)
        {
            databaseType = DatabaseType.getDataSourceForDataSource(className);

        }
        else
        {
            className = conf.getProperty("driverClassName");
            databaseType = DatabaseType.getDataSourceForDriver(className);
        }

        String password = conf.getProperty("password");
        if(password != null)
        {
            if(passwordResolver != null)
            {
                password = new String(passwordResolver.resolvePassword(password));
            }
            conf.setProperty("password", password);
        }

        password = conf.getProperty("dataSource.password");
        if(password != null)
        {
            if(passwordResolver != null)
            {
                password = new String(passwordResolver.resolvePassword(password));
            }
            conf.setProperty("dataSource.password", password);
        }

        return DataSourceWrapperImpl.createDataSource(name, conf, databaseType);
    }

    private static void assertNotNull(
            final String parameterName,
            final Object parameter)
    {
        if(parameter == null)
        {
            throw new IllegalArgumentException(parameterName + " could not be null");
        }
    }

    private static String expandFilepath(
            final String path)
    {
        if (path.startsWith("~" + File.separator))
        {
            return System.getProperty("user.home") + path.substring(1);
        }
        else
        {
            return path;
        }
    }

}
