// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.datasource;

import org.xipki.util.Args;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * JDBC state codes for a particular database. It is the first two digits (the SQL state "class").
 *
 * @author Lijun Liao (xipki)
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
    }

  } // class H2

  private static class HSQL extends SqlStateCodes {

    HSQL() {
    }

  } // class HSQL

  private static class MySQL extends SqlStateCodes {
    MySQL() {
    }
  }

  private static class MariaDB extends MySQL {
    MariaDB() {
    }
  }

  private static class Oracle extends SqlStateCodes {

    Oracle() {
      // 65: unknown identifier
      badSqlGrammarCodes = addToSet(badSqlGrammarCodes, "65");
      // 61: deadlock
      concurrencyFailureCodes = addToSet(concurrencyFailureCodes, "61");
    }

  } // class Oracle

  private static class PostgreSQL extends SqlStateCodes {

    PostgreSQL() {
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

  Set<String> badSqlGrammarCodes;

  Set<String> dataIntegrityViolationCodes;

  Set<String> dataAccessResourceFailureCodes;

  Set<String> transientDataAccessResourceCodes;

  Set<String> concurrencyFailureCodes;

  private SqlStateCodes() {
    badSqlGrammarCodes = toSet(BGE_DYNAMIC_SQL_ERROR, BGE_CARDINALITY_VIOLATION,
        BGE_SYNTAX_ERROR_DIRECT_SQL, BGE_SYNTAX_ERROR_DYNAMIC_SQL, BGE_GENERAL_SQL_SYNTAX_ERROR);
    dataIntegrityViolationCodes = toSet(DIV_DATA_TRUNCATION, DIV_INTEGRITY_CONSTRAINT_VIOLATION,
        DIV_NO_DATA_FOUND, DIV_TRIGGERED_DATA_CHANGE_VIOLATION, DIV_VALUE_OUTOF_RANGE, DIV_WITH_CHECK_VIOLATION);
    dataAccessResourceFailureCodes = toSet(DRF_CONNECTION_EXCEPTION);
    transientDataAccessResourceCodes = toSet(TDR_COMMUNICATION_FAILURE);
    concurrencyFailureCodes = toSet(CF_TRANSACTION_ROLLBACK);
  }

  public static SqlStateCodes newInstance(DatabaseType dbType) {
    Args.notNull(dbType, "dbType");
    switch (dbType) {
      case DB2:
        return new DB2();
      case H2:
        return new H2();
      case HSQL:
        return new HSQL();
      case MYSQL:
        return new MySQL();
      case MARIADB:
        return new MariaDB();
      case ORACLE:
        return new Oracle();
      case POSTGRES:
        return new PostgreSQL();
      case UNKNOWN:
        return new SqlStateCodes();
      default:
        throw new IllegalStateException("should not reach here, unknown database type " + dbType);
    }
  } // method newInstance

  private static Set<String> toSet(String... strs) {
    if (strs == null || strs.length == 0) {
      return Collections.emptySet();
    }

    Set<String> set = new HashSet<>();
    Collections.addAll(set, strs);
    return Collections.unmodifiableSet(set);
  }

  private static Set<String> addToSet(Set<String> baseSet, String... strs) {
    if (strs == null || strs.length == 0) {
      return baseSet;
    }
    Set<String> newSet = new HashSet<>(baseSet.size() + strs.length);
    newSet.addAll(baseSet);
    Collections.addAll(newSet, strs);
    return Collections.unmodifiableSet(newSet);
  }

}
