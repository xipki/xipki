/*
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.database.api;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * @author Lijun Liao
 */

public interface DataSource
{
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

    int getMin(Connection conn, String table, String column)
    throws SQLException;

    int getMax(Connection conn, String table, String column)
    throws SQLException;

    boolean tableHasColumn(Connection conn, String table, String column)
    throws SQLException;

    boolean tableExists(Connection conn, String table)
    throws SQLException;
}
