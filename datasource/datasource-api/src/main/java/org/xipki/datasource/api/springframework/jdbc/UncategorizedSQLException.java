/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.datasource.api.springframework.jdbc;

import java.sql.SQLException;

import org.xipki.datasource.api.springframework.dao.UncategorizedDataAccessException;

/**
 * Copied from Spring Framework licensed under Apache License, version 2.0.
 *
 * Exception thrown when we can't classify a SQLException into
 * one of our generic data access exceptions.
 *
 * @author Rod Johnson
 * @author Juergen Hoeller
 */
@SuppressWarnings("serial")
public class UncategorizedSQLException extends UncategorizedDataAccessException {

    /** SQL that led to the problem */
    private final String sql;

    /**
     * Constructor for UncategorizedSQLException.
     * @param task name of current task
     * @param sql the offending SQL statement
     * @param ex the root cause
     */
    public UncategorizedSQLException(
            final String sql,
            final SQLException ex) {
        super("uncategorized SQLException for SQL [" + sql + "]; SQL state ["
                + ex.getSQLState() + "]; error code [" + ex.getErrorCode() + "]; "
                + ex.getMessage(), ex);
        this.sql = sql;
    }

    /**
     * Return the underlying SQLException.
     */
    public SQLException getSQLException() {
        return (SQLException) getCause();
    }

    /**
     * Return the SQL that led to the problem.
     */
    public String getSql() {
        return this.sql;
    }

}
