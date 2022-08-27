// #THIRDPARTY# Spring Framework

/*
 * Copyright 2002-2006 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.datasource;

import org.xipki.util.Args;

/**
 * Root of the hierarchy of data access exceptions discussed in.
 *
 * @author Rod Johnson
 */
public class DataAccessException extends Exception {

  public enum Reason {
    /**
     * Root reason.
     */
    Root(null),

    /**
     * Root of the hierarchy of data access exceptions that are considered non-transient -
     * where a retry of the same operation would fail unless the cause of the Exception
     * is corrected.
     */
    NonTransientDataAccess(Root),

    /**
     *  Exception thrown when an attempt to insert or update data results in violation of an
     *  integrity constraint. Note that this is not purely a relational concept; unique primary
     *  keys are required by most database types.
     */
    DataIntegrityViolation(NonTransientDataAccess),

    /**
     * Exception thrown when an attempt to insert or update data results in violation of a
     * primary key or unique constraint.
     * Note that this is not necessarily a purely relational concept; unique primary keys are
     * required by most database types.
     */
    DuplicateKey(DataIntegrityViolation),

    /**
     * Root for exceptions thrown when we use a data access resource incorrectly.
     * Thrown for example on specifying bad SQL when using a RDBMS.
     * Resource-specific subclasses are supplied by concrete data access packages.
     */
    InvalidDataAccessResourceUsage(NonTransientDataAccess),

    /**
     * Exception thrown when SQL specified is invalid. Such exceptions always have
     * a {@code java.sql.SQLException} root cause.
     *
     * <p>It would be possible to have subclasses for no such table, no such column etc.
     * A custom SQLExceptionTranslator could create such more specific exceptions,
     * without affecting code using this class.
     */
    BadSqlGrammar(InvalidDataAccessResourceUsage),

    /**
     * Exception thrown when a ResultSet has been accessed in an invalid fashion. Such
     * exceptions always have a {@code java.sql.SQLException} root cause.
     *
     * <p>This typically happens when an invalid ResultSet column index or name has been
     * specified. Also thrown by disconnected SqlRowSets.
     */
    InvalidResultSetAccess(InvalidDataAccessResourceUsage),

    /**
     * Data access exception thrown when a resource fails completely and the failure is
     * permanent.
     */
    NonTransientDataAccessResource(NonTransientDataAccess),

    /**
     * Data access exception thrown when a resource fails completely: for example, if we can't
     * connect to a database using JDBC.
     */
    DataAccessResourceFailure(NonTransientDataAccessResource),

    /**
     * Exception thrown when the underlying resource denied a permission to access a specific
     * element, such as a specific database table.
     */
    PermissionDeniedDataAccess(NonTransientDataAccess),

    /**
     * Normal superclass when we can't distinguish anything more specific than "something went
     * wrong with the underlying resource": for example, a SQLException from JDBC we cannot
     * pinpoint more precisely.
     */
    UncategorizedDataAccess(NonTransientDataAccess),

    /**
     * Exception thrown when we can't classify a SQLException into one of our generic data
     * access exceptions.
     */
    UncategorizedSql(UncategorizedDataAccess),

    /**
     * Root of the hierarchy of data access exceptions that are considered transient - where a
     * previously failed operation might be able to succeed when the operation is retried
     * without any intervention by application-level functionality.
     */
    TransientDataAcces(Root),

    /**
     * Indicate the type of failure: optimistic locking, failure to acquire lock, etc.
     */
    ConcurrencyFailure(TransientDataAcces),

    /**
     * Exception thrown on a pessimistic locking violation.
     *
    */
    PessimisticLockingFailure(ConcurrencyFailure),

    /**
     * Failure to acquire a lock during an update, for example during a "select for update"
     * statement.
     */
    CannotAcquireLock(PessimisticLockingFailure),

    /**
     * Failure to complete a transaction in serialized mode due to update conflicts.
     */
    CannotSerializeTransaction(PessimisticLockingFailure),

    /**
     * Generic exception thrown when the current process was a deadlock loser, and its
     * transaction rolled back.
     */
    DeadlockLoserDataAccess(PessimisticLockingFailure),

    /**
     * Exception to be thrown on a query timeout. This could have different causes depending on
     * the database API in use but most likely thrown after the database interrupts or stops
     * the processing of a query before it has completed.
     *
     * <p>This exception can be thrown by user code trapping the native database exception or
     * by exception translation.
     */
    QueryTimeout(TransientDataAcces),

    /**
     * Exception thrown when the underlying resource denied a permission to access a specific
     * element, such as a specific database table.
     */
    TransientDataAccessResource(TransientDataAcces);

    private final Reason parent;

    Reason(Reason parent) {
      this.parent = parent;
    }

    public boolean isAncestorOf(Reason reason) {
      while (true) {
        Reason parent = reason.parent;
        if (parent == null) {
          return false;
        } else if (parent == this) {
          return true;
        } else {
          reason = parent;
        }
      }
    }

    public boolean isAncestorOrSelfOf(Reason reason) {
      return this == reason || isAncestorOf(reason);
    }

    public boolean isDescendantOf(Reason reason) {
      return reason.isAncestorOf(this);
    }

    public boolean isDescendantOrSelfOf(Reason reason) {
      return this == reason || isDescendantOf(reason);
    }

  }

  private final Reason reason;

  /**
   * Constructor for DataAccessException.
   * @param msg the detail message
   */
  public DataAccessException(String msg) {
    this (Reason.Root, msg);
  }

  /**
   * Constructor for DataAccessException.
   * @param reason the reason
   * @param msg the detail message
   */
  public DataAccessException(Reason reason, String msg) {
    super(reason + " - " + msg);
    this.reason = Args.notNull(reason, "reason");
  }

  /**
   * Constructor for DataAccessException.
   * @param msg the detail message
   * @param cause the root cause (usually from using an underlying data access API such as JDBC)
   */
  public DataAccessException(String msg, Throwable cause) {
    this(Reason.Root, msg, cause);
  }

  /**
   * Constructor for DataAccessException.
   * @param reason the reason
   * @param msg the detail message
   * @param cause the root cause (usually from using an underlying data access API such as JDBC)
   */
  public DataAccessException(Reason reason, String msg, Throwable cause) {
    super(reason + " - " + msg, cause);
    this.reason = Args.notNull(reason, "reason");
  }

  public Reason getReason() {
    return reason;
  }
}
