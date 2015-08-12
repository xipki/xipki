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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.api.DatabaseType;

/**
 * JDBC error codes for a particular database.
 *
 * @author Lijun Liao
 */
public class SQLErrorCodes
{

    protected boolean useSqlStateForTranslation = false;

    protected Set<String> badSqlGrammarCodes;
    protected Set<String> invalidResultSetAccessCodes;
    protected Set<String> duplicateKeyCodes;
    protected Set<String> dataIntegrityViolationCodes;
    protected Set<String> permissionDeniedCodes;
    protected Set<String> dataAccessResourceFailureCodes;
    protected Set<String> transientDataAccessResourceCodes;
    protected Set<String> cannotAcquireLockCodes;
    protected Set<String> deadlockLoserCodes;
    protected Set<String> cannotSerializeTransactionCodes;

    public static SQLErrorCodes newInstance(
            final DatabaseType dbType)
    {
        ParamUtil.assertNotNull("dbType", dbType);
        switch(dbType)
        {
        case DB2:
            return new DB2();
        case H2:
            return new H2();
        case HSQL:
            return new HSQL();
        case MYSQL:
            return new MySQL();
        case ORACLE:
            return new Oracle();
        case POSTGRES:
            return new PostgreSQL();
        case UNKNOWN:
            return new SQLErrorCodes();
        default:
            throw new RuntimeException("should not reach here, unknown database type " + dbType);
        }
    }

    private SQLErrorCodes()
    {
        badSqlGrammarCodes = Collections.emptySet();
        invalidResultSetAccessCodes = Collections.emptySet();
        duplicateKeyCodes = Collections.emptySet();
        dataIntegrityViolationCodes = Collections.emptySet();
        permissionDeniedCodes = Collections.emptySet();
        dataAccessResourceFailureCodes = Collections.emptySet();
        transientDataAccessResourceCodes = Collections.emptySet();
        cannotAcquireLockCodes = Collections.emptySet();
        deadlockLoserCodes = Collections.emptySet();
        cannotSerializeTransactionCodes = Collections.emptySet();
    }

    public boolean isUseSqlStateForTranslation()
    {
        return useSqlStateForTranslation;
    }

    public Set<String> getBadSqlGrammarCodes()
    {
        return badSqlGrammarCodes;
    }

    public Set<String> getInvalidResultSetAccessCodes()
    {
        return invalidResultSetAccessCodes;
    }

    public Set<String> getDuplicateKeyCodes()
    {
        return duplicateKeyCodes;
    }

    public Set<String> getDataIntegrityViolationCodes()
    {
        return dataIntegrityViolationCodes;
    }

    public Set<String> getPermissionDeniedCodes()
    {
        return permissionDeniedCodes;
    }

    public Set<String> getDataAccessResourceFailureCodes()
    {
        return dataAccessResourceFailureCodes;
    }

    public Set<String> getTransientDataAccessResourceCodes()
    {
        return transientDataAccessResourceCodes;
    }

    public Set<String> getCannotAcquireLockCodes()
    {
        return cannotAcquireLockCodes;
    }

    public Set<String> getDeadlockLoserCodes()
    {
        return deadlockLoserCodes;
    }

    public Set<String> getCannotSerializeTransactionCodes()
    {
        return cannotSerializeTransactionCodes;
    }

    private static class DB2 extends SQLErrorCodes
    {
        DB2()
        {
            super();
            badSqlGrammarCodes = toSet(-7, -29, -97, -104, -109, -115, -128, -199, -204, -206, -301, -408, -441, -491);
            duplicateKeyCodes = toSet(-803);
            dataIntegrityViolationCodes = toSet(-407, -530, -531, -532, -543, -544, -545, -603, -667);
            dataAccessResourceFailureCodes = toSet(-904, -971);
            transientDataAccessResourceCodes = toSet(-1035, -1218, -30080, -30081);
            deadlockLoserCodes = toSet(-911, -913);
        }
    }

    private static class H2 extends SQLErrorCodes
    {
        H2()
        {
            super();
            badSqlGrammarCodes = toSet(42000, 42001, 42101, 42102, 42111, 42112, 42121, 42122, 42132);
            duplicateKeyCodes = toSet(23001, 23505);
            dataIntegrityViolationCodes = toSet(22001, 22003, 22012, 22018, 22025, 23000, 23002, 23003,
                    23502, 23503, 23506, 23507, 23513);
            dataAccessResourceFailureCodes = toSet(90046,90100,90117,90121,90126);
            cannotAcquireLockCodes = toSet(50200);
        }
    }

    private static class HSQL extends SQLErrorCodes
    {
        HSQL()
        {
            super();
            badSqlGrammarCodes = toSet(-22, -28);
            duplicateKeyCodes = toSet(-104);
            dataIntegrityViolationCodes = toSet(-9);
            dataAccessResourceFailureCodes = toSet(-80);
        }
    }

    private static class MySQL extends SQLErrorCodes
    {
        MySQL()
        {
            super();
            badSqlGrammarCodes = toSet(1054, 1064, 1146);
            duplicateKeyCodes = toSet(1062);
            dataIntegrityViolationCodes = toSet(630, 839, 840, 893, 1169, 1215, 1216, 1217, 1364, 1451, 1452, 1557);
            dataAccessResourceFailureCodes = toSet(1);
            cannotAcquireLockCodes = toSet(1205);
            deadlockLoserCodes = toSet(1213);
        }
    }

    private static class Oracle extends SQLErrorCodes
    {
        Oracle()
        {
            super();
            badSqlGrammarCodes = toSet(900, 903, 904, 917, 936, 942, 17006, 6550);
            invalidResultSetAccessCodes = toSet(17003);
            duplicateKeyCodes = toSet(1);
            dataIntegrityViolationCodes = toSet(1400, 1722, 2291, 2292);
            dataAccessResourceFailureCodes = toSet(17002, 17447);
            cannotAcquireLockCodes = toSet(54, 30006);
            cannotSerializeTransactionCodes = toSet(8177);
            deadlockLoserCodes = toSet(60);
        }
    }

    private static class PostgreSQL extends SQLErrorCodes
    {
        PostgreSQL()
        {
            super();
            useSqlStateForTranslation = true;
            badSqlGrammarCodes = toSet("03000", "42000", "42601", "42602", "42622", "42804", "42P01");
            duplicateKeyCodes = toSet(23505);
            dataIntegrityViolationCodes = toSet(23000, 23502, 23503, 23514);
            dataAccessResourceFailureCodes = toSet(53000, 53100, 53200, 53300);
            cannotAcquireLockCodes = toSet("55P03");
            cannotSerializeTransactionCodes = toSet(40001);
            deadlockLoserCodes = toSet("40P01");
        }
    }

    private static Set<String> toSet(
            final String... strs)
    {
        if(strs == null || strs.length == 0)
        {
            return Collections.emptySet();
        }

        Set<String> set = new HashSet<String>();
        for(String str : strs)
        {
            set.add(str);
        }
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> toSet(
            final int... ints)
    {
        if(ints == null || ints.length == 0)
        {
            return Collections.emptySet();
        }

        Set<String> set = new HashSet<String>();
        for(int i : ints)
        {
            set.add(Integer.toString(i));
        }
        return Collections.unmodifiableSet(set);
    }

}
