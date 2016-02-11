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
public class SqlStateCodes {

    private static class DB2 extends SqlStateCodes {

        DB2() {
            super();
            // 57: out-of-memory exception / database not started
            // 58: unexpected system error
            dataAccessResourceFailureCodes = addToSet(dataAccessResourceFailureCodes, "57", "58");

            // 51: communication failure
            transientDataAccessResourceCodes = addToSet(transientDataAccessResourceCodes, "51");
        }

    } // class DB2

    private static class H2 extends SqlStateCodes {

        H2() {
            super();
        }

    } // class H2

    private static class HSQL extends SqlStateCodes {

        HSQL() {
            super();
        }

    } // class HSQL

    private static class MySQL extends SqlStateCodes {
        MySQL() {
            super();
        }
    }

    private static class Oracle extends SqlStateCodes {

        Oracle() {
            super();
            // 65: unknown identifier
            badSqlGrammarCodes = addToSet(badSqlGrammarCodes, "65");
            // 61: deadlock
            concurrencyFailureCodes = addToSet(concurrencyFailureCodes, "61");
        }

    } // class Oracle

    private static class PostgreSQL extends SqlStateCodes {

        PostgreSQL() {
            super();
            // 53: insufficient resources (e.g. disk full)
            // 54: program limit exceeded (e.g. statement too complex)
            dataAccessResourceFailureCodes = addToSet(dataAccessResourceFailureCodes, "53", "54");
        }

    } // class PostgreSQL

    // bad grammar error
    private static final String BGE_DYNAMIC_SQL_ERROR = "07";

    private static final String BGE_CARDINALITY_VIOLATION = "21";

    private static final String BGE_SYNTAX_ERROR_DIRECT_SQL = "2A";

    private static final String BGE_SYNTAX_ERROR_DYNAMIC_SQL = "37";

    private static final String BGE_GENERAL_SQL_SYNTAX_ERROR = "42";

    // data integrity violation
    private static final String DIV_DATA_TRUNCATION = "01";

    private static final String DIV_NO_DATA_FOUND = "02";

    private static final String DIV_VALUE_OUTOF_RANGE = "22";

    private static final String DIV_INTEGRITY_CONSTRAINT_VIOLATION = "23";

    private static final String DIV_TRIGGERED_DATA_CHANGE_VIOLATION = "27";

    private static final String DIV_WITH_CHECK_VIOLATION = "44";

    // data access resource failure
    private static final String DRF_CONNECTION_EXCEPTION = "08";

    // transient data access resource
    private static final String TDR_COMMUNICATION_FAILURE = "S1";

    // concurrency failure
    private static final String CF_TRANSACTION_ROLLBACK = "40";

    protected Set<String> badSqlGrammarCodes;

    protected Set<String> dataIntegrityViolationCodes;

    protected Set<String> dataAccessResourceFailureCodes;

    protected Set<String> transientDataAccessResourceCodes;

    protected Set<String> concurrencyFailureCodes;

    private SqlStateCodes() {
        badSqlGrammarCodes = toSet(BGE_DYNAMIC_SQL_ERROR, BGE_CARDINALITY_VIOLATION,
                BGE_SYNTAX_ERROR_DIRECT_SQL, BGE_SYNTAX_ERROR_DYNAMIC_SQL,
                BGE_GENERAL_SQL_SYNTAX_ERROR);
        dataIntegrityViolationCodes = toSet(DIV_DATA_TRUNCATION, DIV_INTEGRITY_CONSTRAINT_VIOLATION,
                DIV_NO_DATA_FOUND, DIV_TRIGGERED_DATA_CHANGE_VIOLATION,
                DIV_VALUE_OUTOF_RANGE, DIV_WITH_CHECK_VIOLATION);
        dataAccessResourceFailureCodes = toSet(DRF_CONNECTION_EXCEPTION);
        transientDataAccessResourceCodes = toSet(TDR_COMMUNICATION_FAILURE);
        concurrencyFailureCodes = toSet(CF_TRANSACTION_ROLLBACK);
    }

    public Set<String> getBadSqlGrammarCodes() {
        return badSqlGrammarCodes;
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

    public static SqlStateCodes newInstance(DatabaseType dbType) {
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
            return new SqlStateCodes();
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
