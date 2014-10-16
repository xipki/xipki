/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.database.hikaricp;

import java.io.File;
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

        FileInputStream fIn = new FileInputStream(expandFilepath(confFile));
        return createDataSource(fIn, passwordResolver);
    }

    @Override
    public DataSourceWrapper createDataSource(InputStream conf, PasswordResolver passwordResolver)
    throws SQLException, PasswordResolverException, IOException
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

        return createDataSource(config, passwordResolver);
    }

    @Override
    public DataSourceWrapper createDataSource(Properties conf, PasswordResolver passwordResolver)
    throws SQLException, PasswordResolverException
    {
        assertNotNull("conf", conf);

        DatabaseType databaseType;
        String legacyJdbcUrl = conf.getProperty(LegacyConfConverter.DRIVER_CLASSNAME);
        if(legacyJdbcUrl != null)
        {
            conf = LegacyConfConverter.convert(conf);
        }

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
            password = new String(passwordResolver.resolvePassword(password));
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

        DataSourceWrapperImpl ds = new DataSourceWrapperImpl(conf, databaseType);
        return ds;
    }

    private static void assertNotNull(String parameterName, Object parameter)
    {
        if(parameter == null)
        {
            throw new IllegalArgumentException(parameterName + " could not be null");
        }
    }

    private static String expandFilepath(String path)
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
