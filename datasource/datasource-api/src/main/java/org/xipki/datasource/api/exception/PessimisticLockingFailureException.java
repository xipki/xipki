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

package org.xipki.datasource.api.exception;

/**
 * Copied from Spring Framework licensed under Apache License, version 2.0.
 *
 * Exception thrown on a pessimistic locking violation.
 * Thrown by Spring's SQLException translation mechanism
 * if a corresponding database error is encountered.
 *
 * <p>Serves as superclass for more specific exceptions, like
 * could notAcquireLockException and DeadlockLoserDataAccessException.
 *
 * @author Thomas Risberg
 * @see could notAcquireLockException
 * @see DeadlockLoserDataAccessException
 * @see OptimisticLockingFailureException
 */
@SuppressWarnings("serial")
public class PessimisticLockingFailureException extends ConcurrencyFailureException
{

    /**
     * Constructor for PessimisticLockingFailureException.
     * @param msg the detail message
     */
    public PessimisticLockingFailureException(
            final String msg)
    {
        super(msg);
    }

    /**
     * Constructor for PessimisticLockingFailureException.
     * @param msg the detail message
     * @param cause the root cause from the data access API in use
     */
    public PessimisticLockingFailureException(
            final String msg,
            final Throwable cause)
    {
        super(msg, cause);
    }

}
