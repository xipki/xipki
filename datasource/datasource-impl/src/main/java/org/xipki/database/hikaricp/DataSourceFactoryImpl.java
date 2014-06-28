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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.SQLException;
import java.util.Properties;

import org.xipki.database.api.DataSource;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.database.api.DatabaseType;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;

/**
 * @author Lijun Liao
 */

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

        DatabaseType databaseType;
        String legacyJdbcUrl = config.getProperty(LegacyConfConverter.DRIVER_CLASSNAME);
        if(legacyJdbcUrl != null)
        {
            config = LegacyConfConverter.convert(config);
        }

        String className = config.getProperty("dataSourceClassName");
        if(className != null)
        {
            databaseType = DatabaseType.getDataSourceForDataSource(className);

        }
        else
        {
            className = config.getProperty("driverClassName");
            databaseType = DatabaseType.getDataSourceForDriver(className);
        }

        String password = config.getProperty("password");
        if(password != null)
        {
            password = new String(passwordResolver.resolvePassword(password));
            config.setProperty("password", password);
        }

        password = config.getProperty("dataSource.password");
        if(password != null)
        {
            password = new String(passwordResolver.resolvePassword(password));
            config.setProperty("dataSource.password", password);
        }

        DataSourceImpl ds = new DataSourceImpl(config, databaseType);
        return ds;
    }

}
