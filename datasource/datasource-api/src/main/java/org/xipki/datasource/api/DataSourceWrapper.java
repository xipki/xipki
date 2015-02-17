/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

package org.xipki.datasource.api;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * @author Lijun Liao
 */

public interface DataSourceWrapper
{
    String getDatasourceName();

    Connection getConnection()
    throws SQLException;

    void returnConnection(Connection conn);

    void shutdown();

    DatabaseType getDatabaseType();

    Statement createStatement(Connection conn)
    throws SQLException;

    PreparedStatement prepareStatement(Connection conn, String sqlQuery)
    throws SQLException;

    void releaseResources(Statement ps, ResultSet rs);

    String createFetchFirstSelectSQL(String coreSql, int rows);

    String createFetchFirstSelectSQL(String coreSql, int rows, String orderBy);

    long getMin(Connection conn, String table, String column)
    throws SQLException;

    long getMax(Connection conn, String table, String column)
    throws SQLException;

    int getCount(Connection conn, String table)
    throws SQLException;

    boolean columnExists(Connection conn, String table, String column, Object value)
    throws SQLException;

    boolean tableHasColumn(Connection conn, String table, String column)
    throws SQLException;

    boolean tableExists(Connection conn, String table)
    throws SQLException;

    void dropAndCreateSequence(String sequenceName, long startValue)
    throws SQLException;

    void createSequence(String sequenceName, long startValue)
    throws SQLException;

    void dropSequence(String sequenceName)
    throws SQLException;

    long nextSeqValue(Connection conn, String sequenceName)
    throws SQLException;

    boolean isDuplicateKeyException(SQLException sqlException);

    boolean isDataIntegrityViolation(SQLException sqlException);

}
