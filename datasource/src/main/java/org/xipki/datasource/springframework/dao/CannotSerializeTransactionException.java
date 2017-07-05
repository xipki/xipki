// #THIRDPARTY#

package org.xipki.datasource.springframework.dao;

/**
 *
 * Exception thrown on failure to complete a transaction in serialized mode
 * due to update conflicts.
 *
 * @author Rod Johnson
 */
@SuppressWarnings("serial")
public class CannotSerializeTransactionException extends PessimisticLockingFailureException {

    /**
     * Constructor for could notSerializeTransactionException.
     * @param msg the detail message
     */
    public CannotSerializeTransactionException(final String msg) {
        super(msg);
    }

    /**
     * Constructor for could notSerializeTransactionException.
     * @param msg the detail message
     * @param cause the root cause from the data access API in use
     */
    public CannotSerializeTransactionException(final String msg, final Throwable cause) {
        super(msg, cause);
    }

}
