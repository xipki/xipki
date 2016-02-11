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

package org.xipki.commons.datasource.api;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.xipki.commons.datasource.api.springframework.dao.DataAccessException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface DataSourceWrapper {

    String getDatasourceName();

    int getMaximumPoolSize();

    Connection getConnection()
    throws DataAccessException;

    void returnConnection(
            Connection conn);

    void shutdown();

    DatabaseType getDatabaseType();

    Statement createStatement(
            Connection conn)
    throws DataAccessException;

    PreparedStatement prepareStatement(
            Connection conn,
            String sqlQuery)
    throws DataAccessException;

    void releaseResources(
            Statement ps,
            ResultSet rs);

    String createFetchFirstSelectSQL(
            String coreSql,
            int rows);

    String createFetchFirstSelectSql(
            String coreSql,
            int rows,
            String orderBy);

    long getMin(
            Connection conn,
            String table,
            String column)
    throws DataAccessException;

    long getMax(
            Connection conn,
            String table,
            String column)
    throws DataAccessException;

    long getMin(
            Connection conn,
            String table,
            String column,
            String condition)
    throws DataAccessException;

    long getMax(
            Connection conn,
            String table,
            String column,
            String condition)
    throws DataAccessException;

    int getCount(
            Connection conn,
            String table)
    throws DataAccessException;

    boolean columnExists(
            Connection conn,
            String table,
            String column,
            Object value)
    throws DataAccessException;

    boolean tableHasColumn(
            Connection conn,
            String table,
            String column)
    throws DataAccessException;

    boolean tableExists(
            Connection conn,
            String table)
    throws DataAccessException;

    void dropAndCreateSequence(
            String sequenceName,
            long startValue)
    throws DataAccessException;

    void createSequence(
            String sequenceName,
            long startValue)
    throws DataAccessException;

    void dropSequence(
            String sequenceName)
    throws DataAccessException;

    void setLastUsedSeqValue(
            String sequenceName,
            long sequenceValue);

    long nextSeqValue(
            Connection conn,
            String sequenceName)
    throws DataAccessException;

    DataAccessException translate(
            String sql,
            SQLException ex);

    boolean deleteFromTable(
            Connection conn,
            String table,
            String idColumn,
            int id);

    void dropPrimaryKey(
            Connection conn,
            String primaryKeyName,
            String table)
    throws DataAccessException;

    void addPrimaryKey(
            Connection conn,
            String primaryKeyName,
            String table,
            String... columns)
    throws DataAccessException;

    void dropForeignKeyConstraint(
            Connection conn,
            String constraintName,
            String baseTable)
    throws DataAccessException;

    void addForeignKeyConstraint(
            Connection conn,
            String constraintName,
            String baseTable,
            String baseColumn,
            String referencedTable,
            String referencedColumn,
            String onDeleteAction,
            String onUpdateAction)
    throws DataAccessException;

    void dropIndex(
            Connection conn,
            String indexName,
            String table)
    throws DataAccessException;

    void createIndex(
            Connection conn,
            String indexName,
            String table,
            String column)
    throws DataAccessException;

    void dropUniqueConstrain(
            Connection conn,
            String constraintName,
            String table)
    throws DataAccessException;

    void addUniqueConstrain(
            Connection conn,
            String constraintName,
            String table,
            String... columns)
    throws DataAccessException;

}
