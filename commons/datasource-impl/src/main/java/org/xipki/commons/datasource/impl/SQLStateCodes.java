/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.commons.datasource.impl;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.datasource.api.DatabaseType;

/**
 * JDBC state codes for a particular database. It is the first two digits (the SQL state "class").
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
public class SQLStateCodes {

    private static class DB2 extends SQLStateCodes {

        DB2() {
            super();
            // 57: out-of-memory exception / database not started
            // 58: unexpected system error
            dataAccessResourceFailureCodes = addToSet(dataAccessResourceFailureCodes, "57", "58");

            // 51: communication failure
            transientDataAccessResourceCodes = addToSet(transientDataAccessResourceCodes, "51");
        }

    } // class DB2

    private static class H2 extends SQLStateCodes {

        H2() {
            super();
        }

    } // class H2

    private static class HSQL extends SQLStateCodes {

        HSQL() {
            super();
        }

    } // class HSQL

    private static class MySQL extends SQLStateCodes {
        MySQL() {
            super();
        }
    }

    private static class Oracle extends SQLStateCodes {

        Oracle() {
            super();
            // 65: unknown identifier
            badSQLGrammarCodes = addToSet(badSQLGrammarCodes, "65");
            // 61: deadlock
            concurrencyFailureCodes = addToSet(concurrencyFailureCodes, "61");
        }

    } // class Oracle

    private static class PostgreSQL extends SQLStateCodes {

        PostgreSQL() {
            super();
            // 53: insufficient resources (e.g. disk full)
            // 54: program limit exceeded (e.g. statement too complex)
            dataAccessResourceFailureCodes = addToSet(dataAccessResourceFailureCodes, "53", "54");
        }

    } // class PostgreSQL

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

    private SQLStateCodes() {
        badSQLGrammarCodes = toSet(bge_dynamic_SQL_error, bge_cardinality_violation,
                bge_syntax_error_directSQL, bge_syntax_error_dynamicSQL,
                bge_general_SQL_syntax_error);
        dataIntegrityViolationCodes = toSet(div_data_truncation, div_integrity_constraint_violation,
                div_no_data_found, div_triggered_data_change_violation,
                div_value_outof_range, div_with_check_violation);
        dataAccessResourceFailureCodes = toSet(drf_connection_exception);
        transientDataAccessResourceCodes = toSet(tdr_communication_failure);
        concurrencyFailureCodes = toSet(cf_transaction_rollback);
    }

    public Set<String> getBadSQLGrammarCodes() {
        return badSQLGrammarCodes;
    }

    public Set<String> getDataIntegrityViolationCodes() {
        return dataIntegrityViolationCodes;
    }

    public Set<String> getDataAccessResourceFailureCodes() {
        return dataAccessResourceFailureCodes;
    }

    public Set<String> getTransientDataAccessResourceCodes() {
        return transientDataAccessResourceCodes;
    }

    public Set<String> getConcurrencyFailureCodes() {
        return concurrencyFailureCodes;
    }

    public static SQLStateCodes newInstance(DatabaseType dbType) {
        ParamUtil.assertNotNull("dbType", dbType);
        switch (dbType) {
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

    private static Set<String> toSet(
            final String... strs) {
        if (strs == null || strs.length == 0) {
            return Collections.emptySet();
        }

        Set<String> set = new HashSet<String>();
        for (String str : strs) {
            set.add(str);
        }
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> addToSet(
            final Set<String> baseSet,
            final String... strs) {
        if (strs == null || strs.length == 0) {
            return baseSet;
        }
        Set<String> newSet = new HashSet<String>(baseSet.size() + strs.length);
        newSet.addAll(baseSet);
        for (String str : strs) {
            newSet.add(str);
        }
        return Collections.unmodifiableSet(newSet);
    }

}
