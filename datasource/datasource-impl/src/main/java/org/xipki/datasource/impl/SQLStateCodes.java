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
 * JDBC state codes for a particular database. It is the first two digits (the SQL state "class").
 *
 * @author Lijun Liao
 */
public class SQLStateCodes
{
    // bad grammar error
    private static final String bge_dynamic_SQL_error = "07";
    private static final String bge_cardinality_violation = "21";
    private static final String bge_syntax_error_directSQL = "2A";
    private static final String bge_syntax_error_dynamicSQL = "37";
    private static final String bge_general_SQL_syntax_error = "42";

    // data integrity violation
    private static final String div_data_truncation = "01";
    private static final String div_no_data_found = "02";
    private static final String div_value_outof_range = "22";
    private static final String div_integrity_constraint_violation = "23";
    private static final String div_triggered_data_change_violation = "27";
    private static final String div_with_check_violation = "44";

    // data access resource failure
    private static final String drf_connection_exception = "08";

    // transient data access resource
    private static final String tdr_communication_failure = "S1";

    // concurrency failure
    private static final String cf_transaction_rollback = "40";

    protected Set<String> badSQLGrammarCodes;
    protected Set<String> dataIntegrityViolationCodes;
    protected Set<String> dataAccessResourceFailureCodes;
    protected Set<String> transientDataAccessResourceCodes;
    protected Set<String> concurrencyFailureCodes;

    public static SQLStateCodes newInstance(DatabaseType dbType)
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
            return new SQLStateCodes();
        default:
            throw new RuntimeException("should not reach here, unknown database type " + dbType);
        }
    }

    private SQLStateCodes()
    {
        badSQLGrammarCodes = toSet(bge_dynamic_SQL_error, bge_cardinality_violation,
                bge_syntax_error_directSQL,    bge_syntax_error_dynamicSQL, bge_general_SQL_syntax_error);
        dataIntegrityViolationCodes = toSet(div_data_truncation, div_integrity_constraint_violation,
                div_no_data_found, div_triggered_data_change_violation,
                div_value_outof_range, div_with_check_violation);
        dataAccessResourceFailureCodes = toSet(drf_connection_exception);
        transientDataAccessResourceCodes = toSet(tdr_communication_failure);
        concurrencyFailureCodes = toSet(cf_transaction_rollback);
    }

    public Set<String> getBadSQLGrammarCodes()
    {
        return badSQLGrammarCodes;
    }

    public Set<String> getDataIntegrityViolationCodes()
    {
        return dataIntegrityViolationCodes;
    }

    public Set<String> getDataAccessResourceFailureCodes()
    {
        return dataAccessResourceFailureCodes;
    }

    public Set<String> getTransientDataAccessResourceCodes()
    {
        return transientDataAccessResourceCodes;
    }

    public Set<String> getConcurrencyFailureCodes()
    {
        return concurrencyFailureCodes;
    }

    private static class DB2 extends SQLStateCodes
    {
        DB2()
        {
            super();
            // 57: out-of-memory exception / database not started
            // 58: unexpected system error
            dataAccessResourceFailureCodes = addToSet(dataAccessResourceFailureCodes, "57", "58");

            // 51: communication failure
            transientDataAccessResourceCodes = addToSet(transientDataAccessResourceCodes, "51");
        }
    }

    private static class H2 extends SQLStateCodes
    {
        H2()
        {
            super();
        }
    }

    private static class HSQL extends SQLStateCodes
    {
        HSQL()
        {
            super();
        }
    }

    private static class MySQL extends SQLStateCodes
    {
        MySQL()
        {
            super();
        }
    }

    private static class Oracle extends SQLStateCodes
    {
        Oracle()
        {
            super();
            // 65: unknown identifier
            badSQLGrammarCodes = addToSet(badSQLGrammarCodes, "65");
            // 61: deadlock
            concurrencyFailureCodes = addToSet(concurrencyFailureCodes, "61");
        }
    }

    private static class PostgreSQL extends SQLStateCodes
    {
        PostgreSQL()
        {
            super();
            // 53: insufficient resources (e.g. disk full)
            // 54: program limit exceeded (e.g. statement too complex)
            dataAccessResourceFailureCodes = addToSet(dataAccessResourceFailureCodes, "53", "54");
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

    private static Set<String> addToSet(
            final Set<String> baseSet,
            final String... strs)
    {
        if(strs == null || strs.length == 0)
        {
            return baseSet;
        }
        Set<String> newSet = new HashSet<String>(baseSet.size() + strs.length);
        newSet.addAll(baseSet);
        for(String str : strs)
        {
            newSet.add(str);
        }
        return Collections.unmodifiableSet(newSet);
    }

}
