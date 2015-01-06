/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.datasource.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.SQLException;
import java.util.Properties;

import org.xipki.datasource.api.DataSourceFactory;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.DatabaseType;
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
