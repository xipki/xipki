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

import java.sql.Connection;
import java.util.Properties;

/**
 * @author Lijun Liao
 */

class LegacyConfConverter
{

    private final static String P = "db.";
    final static String DRIVER_CLASSNAME = P + "driverClassName";
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

    static Properties convert(Properties config)
    {
        Properties newProps = new Properties();

        String s;

        s = config.getProperty(DRIVER_CLASSNAME);
        if(s != null)
        {
            newProps.setProperty("driverClassName", s);
        }

        // username
        s = config.getProperty(USERNAME);
        if(s != null)
        {
            newProps.setProperty("username", s);
        }

        // password
        String password = config.getProperty(PASSWORD);
        if(password != null)
        {
            newProps.setProperty("password", password);
        }

        // url
        s = config.getProperty(URL);
        if(s != null)
        {
            newProps.setProperty("jdbcUrl", s);
        }

        // defaultAutoCommit
        s = config.getProperty(DEFAULT_AUTOCOMMIT);
        if(s != null)
        {
            newProps.setProperty("autoCommit", s);
        }

        // defaultReadOnly
        s = config.getProperty(DEFAULT_READONLY);
        if(s != null)
        {
            newProps.setProperty("readOnly", s);
        }

        // defaultTransactionIsolation
        s  = config.getProperty(DEFAULT_TRANSACTION_ISOLATION);
        if(s != null)
        {
            int transactionIsolation = Integer.parseInt(s);
            String isolationText;
            switch(transactionIsolation)
            {
                case Connection.TRANSACTION_READ_COMMITTED:
                    isolationText = "TRANSACTION_READ_COMMITTED";
                    break;
                case Connection.TRANSACTION_READ_UNCOMMITTED:
                    isolationText = "TRANSACTION_READ_UNCOMMITTED";
                    break;
                case Connection.TRANSACTION_REPEATABLE_READ:
                    isolationText = "TRANSACTION_REPEATABLE_READ";
                    break;
                case Connection.TRANSACTION_SERIALIZABLE:
                    isolationText = "TRANSACTION_SERIALIZABLE";
                    break;
                default:
                    isolationText = null;
            }

            if(isolationText != null)
            {
                newProps.setProperty("transactionIsolation", isolationText);
            }
        }

        // maxActive
        s = config.getProperty(MAX_ACTIVE);
        if(s != null)
        {
            newProps.setProperty("maximumPoolSize", s);
        }

        // minIdle
        s = config.getProperty(MIN_IDLE);
        if(s != null)
        {
            newProps.setProperty("minimumIdle", s);
        }

        // connectionTimeout
        s = config.getProperty(MAX_WAIT);
        if(s != null)
        {
            newProps.setProperty("connectionTimeout",s);
        }

        s = config.getProperty(MAX_LIFETIME);
        if(s != null)
        {
            newProps.setProperty("maxLifttime", s);
        }

        s = config.getProperty(IDLE_TIMEOUT);
        if(s != null)
        {
            newProps.setProperty("idleTimeout", s);
        }

        return newProps;
    }

}
