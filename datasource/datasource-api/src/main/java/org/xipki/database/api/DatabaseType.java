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

package org.xipki.database.api;

public enum DatabaseType
{
    DB2,
    HSQLDB,
    INFORMIX,
    MSSQL2000,
    MYSQL,
    ORACLE,
    POSTGRESQL,
    SAPDB,
    SYBASE,
    UNKNOWN;

    public static DatabaseType getDataSourceForDriver(String driverClass)
    {
        DatabaseType type = null;
        if (driverClass.indexOf("OracleDriver") >= 0)
        {
            type = DatabaseType.ORACLE;
        }
        else if (driverClass.indexOf("hsqldb.jdbcDriver") >= 0)
        {
            type = DatabaseType.HSQLDB;
        }
        else if (driverClass.indexOf("postgresql.Driver") >= 0)
        {
            type = DatabaseType.POSTGRESQL;
        }
        else if (driverClass.indexOf("SQLServerDriver") >= 0)
        {
            type = DatabaseType.MSSQL2000;
        }
        else if (driverClass.indexOf("IfxDriver") >= 0)
        {
            type = DatabaseType.INFORMIX;
        }
        else if (driverClass.indexOf("DB2Driver") >= 0)
        {
            type = DatabaseType.DB2;
        }
        else if (driverClass.indexOf("mysql") >= 0)
        {
            type = DatabaseType.MYSQL;
        }
        else
        {
            type = DatabaseType.UNKNOWN;
        }

        return type;
    }
}
