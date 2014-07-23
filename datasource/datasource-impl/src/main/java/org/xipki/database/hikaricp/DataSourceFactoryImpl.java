/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.database.hikaricp;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.SQLException;
import java.util.Properties;

import org.xipki.database.api.DataSourceWrapper;
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
    public DataSourceWrapper createDataSourceForFile(String confFile, PasswordResolver passwordResolver)
    throws SQLException, PasswordResolverException, IOException
    {
        assertNotNull("confFile", confFile);
        assertNotNull("passwordResolver", passwordResolver);

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
    public DataSourceWrapper createDataSource(InputStream conf, PasswordResolver passwordResolver)
    throws SQLException, PasswordResolverException, IOException
    {
        assertNotNull("conf", conf);
        assertNotNull("passwordResolver", passwordResolver);

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

        DataSourceWrapperImpl ds = new DataSourceWrapperImpl(config, databaseType);
        return ds;
    }

    private static void assertNotNull(String parameterName, Object parameter)
    {
        if(parameter == null)
        {
            throw new IllegalArgumentException(parameterName + " could not be null");
        }
    }

}
