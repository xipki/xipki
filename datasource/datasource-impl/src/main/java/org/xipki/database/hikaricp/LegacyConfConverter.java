/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License
 * (version 3 or later at your option)
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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
