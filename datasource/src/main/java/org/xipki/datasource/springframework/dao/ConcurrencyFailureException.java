// #THIRDPARTY#

package org.xipki.datasource.springframework.dao;

/**
 *
 * Exception thrown on concurrency failure.
 *
 * <p>This exception should be subclassed to indicate the type of failure:
 * optimistic locking, failure to acquire lock, etc.
 *
 * @author Thomas Risberg
 * @since 1.1
 * @see OptimisticLockingFailureException
 * @see PessimisticLockingFailureException
 * @see could notAcquireLockException
 * @see DeadlockLoserDataAccessException
 */
@SuppressWarnings("serial")
public class ConcurrencyFailureException extends TransientDataAccessException {

    /**
     * Constructor for ConcurrencyFailureException.
     * @param msg the detail message
     */
    public ConcurrencyFailureException(final String msg) {
        super(msg);
    }

    /**
     * Constructor for ConcurrencyFailureException.
     * @param msg the detail message
     * @param cause the root cause from the data access API in use
     */
    public ConcurrencyFailureException(final String msg, final Throwable cause) {
        super(msg, cause);
    }

}
