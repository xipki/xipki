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
 *
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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

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
            @Nonnull Connection conn);

    void shutdown();

    DatabaseType getDatabaseType();

    Statement createStatement(
            @Nonnull Connection conn)
    throws DataAccessException;

    PreparedStatement prepareStatement(
            @Nonnull Connection conn,
            @Nonnull String sqlQuery)
    throws DataAccessException;

    void releaseResources(
            @Nullable Statement ps,
            @Nullable ResultSet rs);

    String createFetchFirstSelectSql(
            @Nonnull String coreSql,
            int rows,
            @Nullable String orderBy);

    String createFetchFirstSelectSql(
            @Nonnull String coreSql,
            int rows);

    long getMin(
            @Nullable Connection conn,
            @Nonnull String table,
            @Nonnull String column,
            @Nullable String condition)
    throws DataAccessException;

    long getMin(
            @Nullable Connection conn,
            @Nonnull String table,
            @Nonnull String column)
    throws DataAccessException;

    long getMax(
            @Nullable Connection conn,
            @Nonnull String table,
            @Nonnull String column)
    throws DataAccessException;

    long getMax(
            @Nullable Connection conn,
            @Nonnull String table,
            @Nonnull String column,
            @Nullable String condition)
    throws DataAccessException;

    int getCount(
            @Nullable Connection conn,
            @Nonnull String table)
    throws DataAccessException;

    boolean columnExists(
            @Nullable Connection conn,
            @Nonnull String table,
            @Nonnull String column,
            @Nonnull Object value)
    throws DataAccessException;

    boolean tableHasColumn(
            @Nullable Connection conn,
            @Nonnull String table,
            @Nonnull String column)
    throws DataAccessException;

    boolean tableExists(
            @Nullable Connection conn,
            @Nonnull String table)
    throws DataAccessException;

    void dropAndCreateSequence(
            @Nonnull String sequenceName,
            long startValue)
    throws DataAccessException;

    void createSequence(
            @Nonnull String sequenceName,
            long startValue)
    throws DataAccessException;

    void dropSequence(
            @Nonnull String sequenceName)
    throws DataAccessException;

    void setLastUsedSeqValue(
            @Nonnull String sequenceName,
            long sequenceValue);

    long nextSeqValue(
            @Nullable Connection conn,
            @Nonnull String sequenceName)
    throws DataAccessException;

    DataAccessException translate(
            @Nullable String sql,
            @Nonnull SQLException ex);

    boolean deleteFromTable(
            @Nullable Connection conn,
            @Nonnull String table,
            @Nonnull String idColumn,
            int id);

    void dropPrimaryKey(
            @Nullable Connection conn,
            @Nonnull String primaryKeyName,
            @Nonnull String table)
    throws DataAccessException;

    void addPrimaryKey(
            @Nullable Connection conn,
            @Nonnull String primaryKeyName,
            @Nonnull String table,
            @Nonnull String... columns)
    throws DataAccessException;

    void dropForeignKeyConstraint(
            @Nullable Connection conn,
            @Nonnull String constraintName,
            @Nonnull String baseTable)
    throws DataAccessException;

    void addForeignKeyConstraint(
            @Nullable Connection conn,
            @Nonnull String constraintName,
            @Nonnull String baseTable,
            @Nonnull String baseColumn,
            @Nonnull String referencedTable,
            @Nonnull String referencedColumn,
            @Nonnull String onDeleteAction,
            @Nonnull String onUpdateAction)
    throws DataAccessException;

    void dropIndex(
            @Nullable Connection conn,
            @Nonnull String indexName,
            @Nonnull String table)
    throws DataAccessException;

    void createIndex(
            @Nullable Connection conn,
            @Nonnull String indexName,
            @Nonnull String table,
            @Nonnull String column)
    throws DataAccessException;

    void dropUniqueConstrain(
            @Nullable Connection conn,
            @Nonnull String constraintName,
            @Nonnull String table)
    throws DataAccessException;

    void addUniqueConstrain(
            @Nullable Connection conn,
            @Nonnull String constraintName,
            @Nonnull String table,
            @Nonnull String... columns)
    throws DataAccessException;

}
