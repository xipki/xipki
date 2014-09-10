/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.database.api;

import java.util.Properties;

import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;

/**
 * @author Lijun Liao
 */

public class SimpleDatabaseConf
{
    private final String driver;
    private final String username;
    private final String password;
    private final String url;
    private final String schema;

    public static SimpleDatabaseConf getInstance(Properties dbProps, PasswordResolver passwordResolver)
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
                if(s != null && s.isEmpty() == false)
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
            else
            {
                throw new IllegalArgumentException("Unsupported datasbase type " + dataSourceClassName);
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

            if(url.startsWith("jdbc:db2:"))
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
                    url = url.substring(0, idx);
                }
            }
        }
        else
        {
            throw new IllegalArgumentException("Unsupported configuration");
        }

        if(passwordResolver != null && password != null && password.isEmpty() == false)
        {
            password = new String(passwordResolver.resolvePassword(password));
        }

        return new SimpleDatabaseConf(driverClassName, user, password, url, schema);
    }

    public SimpleDatabaseConf(String driver, String username, String password, String url, String schema)
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
