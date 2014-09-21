/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
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

public interface DataSourceWrapper
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

    long getMin(Connection conn, String table, String column)
    throws SQLException;

    long getMax(Connection conn, String table, String column)
    throws SQLException;

    int getCount(Connection conn, String table)
    throws SQLException;

    boolean tableHasColumn(Connection conn, String table, String column)
    throws SQLException;

    boolean tableExists(Connection conn, String table)
    throws SQLException;

    void createSequence(String sequenceName, long startValue)
    throws SQLException;

    void dropSequence(String sequenceName)
    throws SQLException;

    long nextSeqValue(String sequenceName)
    throws SQLException;
}
