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

package org.xipki.datasource.api;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.xipki.datasource.api.exception.DataAccessException;

/**
 * @author Lijun Liao
 */

public interface DataSourceWrapper
{
    String getDatasourceName();

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

    String createFetchFirstSelectSQL(
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

}
