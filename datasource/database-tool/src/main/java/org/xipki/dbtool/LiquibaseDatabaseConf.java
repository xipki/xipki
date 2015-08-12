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

package org.xipki.dbtool;

import java.util.Properties;

import org.xipki.password.api.PasswordResolver;
import org.xipki.password.api.PasswordResolverException;

/**
 * @author Lijun Liao
 */

public class LiquibaseDatabaseConf
{
    private final String driver;
    private final String username;
    private final String password;
    private final String url;
    private final String schema;

    public static LiquibaseDatabaseConf getInstance(
            final Properties dbProps,
            final PasswordResolver passwordResolver)
    throws PasswordResolverException
    {
        String driverClassName;
        String url;
        String schema = null;
        String user;
        String password;

        String dataSourceClassName = dbProps.getProperty("dataSourceClassName");
        if(dataSourceClassName != null)
        {
            user = dbProps.getProperty("dataSource.user");
            password = dbProps.getProperty("dataSource.password");

            StringBuilder urlBuilder = new StringBuilder();

            dataSourceClassName = dataSourceClassName.toLowerCase();
            if(dataSourceClassName.contains("org.h2."))
            {
                driverClassName = "org.h2.Driver";
                urlBuilder.append(dbProps.getProperty("dataSource.url"));
            }
            else if(dataSourceClassName.contains("mysql."))
            {
                driverClassName = "com.mysql.jdbc.Driver";
                urlBuilder.append("jdbc:mysql://");
                urlBuilder.append(dbProps.getProperty("dataSource.serverName"));
                urlBuilder.append(":");
                urlBuilder.append(dbProps.getProperty("dataSource.port"));
                urlBuilder.append("/");
                urlBuilder.append(dbProps.getProperty("dataSource.databaseName"));
            }
            else if(dataSourceClassName.contains("oracle."))
            {
                driverClassName = "oracle.jdbc.driver.OracleDriver";
                String s = dbProps.getProperty("dataSource.URL");
                if(MyStringUtil.isNotBlank(s))
                {
                    urlBuilder.append(s);
                }
                else
                {
                    urlBuilder.append("jdbc:oracle:thin:@");
                    urlBuilder.append(dbProps.getProperty("dataSource.serverName"));
                    urlBuilder.append(":");
                    urlBuilder.append(dbProps.getProperty("dataSource.portNumber"));
                    urlBuilder.append(":");
                    urlBuilder.append(dbProps.getProperty("dataSource.databaseName"));
                }
            }
            else if(dataSourceClassName.contains("com.ibm.db2."))
            {
                driverClassName = "com.ibm.db2.jcc.DB2Driver";
                schema = dbProps.getProperty("dataSource.currentSchema");

                urlBuilder.append("jdbc:db2://");
                urlBuilder.append(dbProps.getProperty("dataSource.serverName"));
                urlBuilder.append(":");
                urlBuilder.append(dbProps.getProperty("dataSource.portNumber"));
                urlBuilder.append("/");
                urlBuilder.append(dbProps.getProperty("dataSource.databaseName"));
            }
            else if(dataSourceClassName.contains("postgresql.") || dataSourceClassName.contains("impossibl.postgres."))
            {
                String serverName;
                String portNumber;
                String databaseName;
                if(dataSourceClassName.contains("postgresql."))
                {
                    serverName = dbProps.getProperty("dataSource.serverName");
                    portNumber = dbProps.getProperty("dataSource.portNumber");
                    databaseName = dbProps.getProperty("dataSource.databaseName");
                }
                else
                {
                    serverName = dbProps.getProperty("dataSource.host");
                    portNumber = dbProps.getProperty("dataSource.port");
                    databaseName = dbProps.getProperty("dataSource.database");
                }
                driverClassName = "org.postgresql.Driver";
                urlBuilder.append("jdbc:postgresql://");
                urlBuilder.append(serverName).append(":").append(portNumber).append("/").append(databaseName);
            }
            else if(dataSourceClassName.contains("hsqldb."))
            {
                driverClassName = "org.hsqldb.jdbc.JDBCDriver";
                urlBuilder.append(dbProps.getProperty("dataSource.url"));
            }
            else
            {
                throw new IllegalArgumentException("unsupported datasbase type " + dataSourceClassName);
            }

            url = urlBuilder.toString();
        }
        else if(dbProps.containsKey("driverClassName") || dbProps.containsKey("db.driverClassName"))
        {
            if(dbProps.containsKey("driverClassName"))
            {
                driverClassName = dbProps.getProperty("driverClassName");
                user = dbProps.getProperty("username");
                password = dbProps.getProperty("password");
                url = dbProps.getProperty("jdbcUrl");
            }
            else
            {
                driverClassName = dbProps.getProperty("db.driverClassName");
                user = dbProps.getProperty("db.username");
                password = dbProps.getProperty("db.password");
                url= dbProps.getProperty("db.url");
            }

            if(MyStringUtil.startsWithIgnoreCase(url, "jdbc:db2:"))
            {
                String sep = ":currentSchema=";
                int idx = url.indexOf(sep);
                if(idx != 1)
                {
                    schema = url.substring(idx + sep.length());
                    if(schema.endsWith(";"))
                    {
                        schema = schema.substring(0, schema.length() - 1);
                    }
                    schema = schema.toUpperCase();
                    url = url.substring(0, idx);
                }
            }
        }
        else
        {
            throw new IllegalArgumentException("unsupported configuration");
        }

        if(passwordResolver != null && MyStringUtil.isNotBlank(password))
        {
            password = new String(passwordResolver.resolvePassword(password));
        }

        return new LiquibaseDatabaseConf(driverClassName, user, password, url, schema);
    }

    public LiquibaseDatabaseConf(
            final String driver,
            final String username,
            final String password,
            final String url,
            final String schema)
    {
        this.driver = driver;
        this.username = username;
        this.password = password;
        this.url = url;
        this.schema = schema;
    }

    public String getDriver()
    {
        return driver;
    }

    public String getUsername()
    {
        return username;
    }

    public String getPassword()
    {
        return password;
    }

    public String getUrl()
    {
        return url;
    }

    public String getSchema()
    {
        return schema;
    }

}
