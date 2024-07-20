// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.datasource;

import org.xipki.util.Args;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * JDBC error codes for a particular database.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */
class SqlErrorCodes {

  private static class DB2 extends SqlErrorCodes {

    DB2() {
      badSqlGrammarCodes = toSet(-7, -29, -97, -104, -109, -115, -128, -199, -204, -206, -301, -408, -441, -491);
      duplicateKeyCodes = toSet(-803);
      dataIntegrityViolationCodes = toSet(-407, -530, -531, -532, -543, -544, -545, -603, -667);
      dataAccessResourceFailureCodes = toSet(-904, -971);
      transientDataAccessResourceCodes = toSet(-1035, -1218, -30080, -30081);
      deadlockLoserCodes = toSet(-911, -913);
    }

  } // class DB2

  private static class H2 extends SqlErrorCodes {

    H2() {
      badSqlGrammarCodes = toSet(42000, 42001, 42101, 42102, 42111, 42112, 42121, 42122, 42132);
      duplicateKeyCodes = toSet(23001, 23505);
      dataIntegrityViolationCodes = toSet(22001, 22003, 22012, 22018, 22025, 23000, 23002,
          23003, 23502, 23503, 23506, 23507, 23513);
      dataAccessResourceFailureCodes = toSet(90046, 90100, 90117, 90121, 90126);
      cannotAcquireLockCodes = toSet(50200);
    }

  } // class H2

  private static class HSQL extends SqlErrorCodes {

    HSQL() {
      badSqlGrammarCodes = toSet(-22, -28);
      duplicateKeyCodes = toSet(-104);
      dataIntegrityViolationCodes = toSet(-9);
      dataAccessResourceFailureCodes = toSet(-80);
    }

  } // class HSQL

  private static class MySQL extends SqlErrorCodes {

    MySQL() {
      badSqlGrammarCodes = toSet(1054, 1064, 1146);
      duplicateKeyCodes = toSet(1062);
      dataIntegrityViolationCodes = toSet(630, 839, 840, 893, 1169, 1215, 1216, 1217, 1364, 1451, 1452, 1557);
      dataAccessResourceFailureCodes = toSet(1);
      cannotAcquireLockCodes = toSet(1205);
      deadlockLoserCodes = toSet(1213);
    }

  } // class MySQL

  private static class MariaDB extends MySQL {

    MariaDB() {
    }

  } // class MariaDB

  private static class Oracle extends SqlErrorCodes {

    Oracle() {
      badSqlGrammarCodes = toSet(900, 903, 904, 917, 936, 942, 17006, 6550);
      invalidResultSetAccessCodes = toSet(17003);
      duplicateKeyCodes = toSet(1);
      dataIntegrityViolationCodes = toSet(1400, 1722, 2291, 2292);
      dataAccessResourceFailureCodes = toSet(17002, 17447);
      cannotAcquireLockCodes = toSet(54, 30006);
      cannotSerializeTransactionCodes = toSet(8177);
      deadlockLoserCodes = toSet(60);
    }

  } // class Oracle

  private static class PostgreSQL extends SqlErrorCodes {

    PostgreSQL() {
      useSqlStateForTranslation = true;
      badSqlGrammarCodes = toSet("03000", "42000", "42601", "42602", "42622", "42804", "42P01");
      duplicateKeyCodes = toSet(23505);
      dataIntegrityViolationCodes = toSet(23000, 23502, 23503, 23514);
      dataAccessResourceFailureCodes = toSet(53000, 53100, 53200, 53300);
      cannotAcquireLockCodes = toSet("55P03");
      cannotSerializeTransactionCodes = toSet(40001);
      deadlockLoserCodes = toSet("40P01");
    }

  } // class PostgreSQL

  boolean useSqlStateForTranslation;

  Set<String> badSqlGrammarCodes;

  Set<String> invalidResultSetAccessCodes;

  Set<String> duplicateKeyCodes;

  Set<String> dataIntegrityViolationCodes;

  Set<String> permissionDeniedCodes;

  Set<String> dataAccessResourceFailureCodes;

  Set<String> transientDataAccessResourceCodes;

  Set<String> cannotAcquireLockCodes;

  Set<String> deadlockLoserCodes;

  Set<String> cannotSerializeTransactionCodes;

  private SqlErrorCodes() {
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

  static SqlErrorCodes newInstance(DatabaseType dbType) {
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
        return new SqlErrorCodes();
      default:
        throw new IllegalStateException("should not reach here, unknown database type " + dbType);
    }
  } // method newInstance

  private static Set<String> toSet(String... strs) {
    if (strs == null || strs.length == 0) {
      return Collections.emptySet();
    }

    return Set.of(strs);
  }

  private static Set<String> toSet(int... ints) {
    if (ints == null || ints.length == 0) {
      return Collections.emptySet();
    }

    Set<String> set = new HashSet<>();
    for (int i : ints) {
      set.add(Integer.toString(i));
    }
    return Collections.unmodifiableSet(set);
  }

}
