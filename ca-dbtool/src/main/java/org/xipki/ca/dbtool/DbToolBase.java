/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.dbtool;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.sql.Statement;
import java.sql.Types;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.Deflater;
import java.util.zip.ZipOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DbToolBase {

    private static final Logger LOG = LoggerFactory.getLogger(DbToolBase.class);

    private static final int STREAM_BUFFER_SIZE = 1048576; // 1M

    protected final AtomicBoolean stopMe;

    protected final DataSourceWrapper datasource;

    protected final String baseDir;

    protected Connection connection;

    private boolean connectionAutoCommit;

    public DbToolBase(DataSourceWrapper datasource, String baseDir, AtomicBoolean stopMe)
            throws DataAccessException {
        super();
        ParamUtil.requireNonBlank("baseDir", baseDir);
        this.stopMe = ParamUtil.requireNonNull("stopMe", stopMe);
        this.datasource = ParamUtil.requireNonNull("datasource", datasource);
        this.connection = datasource.getConnection();
        try {
            this.connectionAutoCommit = connection.getAutoCommit();
        } catch (SQLException ex) {
            throw datasource.translate(null, ex);
        }
        this.baseDir = IoUtil.expandFilepath(baseDir);
    }

    protected Statement createStatement() throws DataAccessException {
        try {
            return connection.createStatement();
        } catch (SQLException ex) {
            throw datasource.translate(null, ex);
        }
    }

    protected PreparedStatement prepareStatement(String sql) throws DataAccessException {
        ParamUtil.requireNonBlank("sql", sql);

        try {
            return connection.prepareStatement(sql);
        } catch (SQLException ex) {
            throw datasource.translate(sql, ex);
        }
    }

    public boolean deleteFromTableWithLargerId(String tableName, String idColumn,
            long id, Logger log) {
        ParamUtil.requireNonBlank("tableName", tableName);
        ParamUtil.requireNonBlank("idColumn", idColumn);

        StringBuilder sb = new StringBuilder(50);
        sb.append("DELETE FROM ").append(tableName).append(" WHERE ");
        sb.append(idColumn).append(">").append(id);

        Statement stmt;
        try {
            stmt = createStatement();
        } catch (DataAccessException ex) {
            log.error("could not create statement", ex);
            return false;
        }
        try {
            stmt.execute(sb.toString());
        } catch (Throwable th) {
            String msg = String.format("could not delete columns from table %s with %s > %s",
                    tableName, idColumn, id);
            LogUtil.error(log, th, msg);
            return false;
        } finally {
            releaseResources(stmt, null);
        }

        return true;
    } // method deleteFromTableWithLargerId

    public void shutdown() {
        datasource.returnConnection(connection);
        connection = null;
    }

    public long min(String table, String column) throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);
        ParamUtil.requireNonBlank("column", column);

        return datasource.getMin(connection, table, column);
    }

    public long min(String table, String column, String condition) throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);
        ParamUtil.requireNonBlank("column", column);

        return datasource.getMin(connection, table, column, condition);
    }

    public long max(String table, String column) throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);
        ParamUtil.requireNonBlank("column", column);

        return datasource.getMax(connection, table, column);
    }

    public long max(String table, String column, String condition) throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);
        ParamUtil.requireNonBlank("column", column);

        return datasource.getMax(connection, table, column, condition);
    }

    public int count(String table) throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);

        return datasource.getCount(connection, table);
    }

    public boolean tableHasColumn(String table, String column) throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);
        ParamUtil.requireNonBlank("column", column);

        return datasource.tableHasColumn(connection, table, column);
    }

    public boolean tableExists(String table) throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);

        return datasource.tableExists(connection, table);
    }

    protected Savepoint setSavepoint() throws DataAccessException {
        try {
            return connection.setSavepoint();
        } catch (SQLException ex) {
            throw datasource.translate(null, ex);
        }
    }

    protected void rollback() throws DataAccessException {
        try {
            connection.rollback();
        } catch (SQLException ex) {
            throw datasource.translate(null, ex);
        }
    }

    protected DataAccessException translate(String sql, SQLException ex) {
        ParamUtil.requireNonNull("ex", ex);
        return datasource.translate(sql, ex);
    }

    protected void disableAutoCommit() throws DataAccessException {
        try {
            connection.setAutoCommit(false);
        } catch (SQLException ex) {
            throw datasource.translate(null, ex);
        }
    }

    protected void recoverAutoCommit() {
        try {
            connection.setAutoCommit(connectionAutoCommit);
        } catch (SQLException ex) {
            DataAccessException dex = datasource.translate(null, ex);
            LogUtil.error(LOG, dex, "could not recover AutoCommit");
        }
    }

    protected void commit(String task) throws DataAccessException {
        ParamUtil.requireNonBlank("task", task);
        try {
            connection.commit();
        } catch (SQLException ex) {
            throw datasource.translate(task, ex);
        }
    }

    protected static void setLong(PreparedStatement ps, int index, Long value) throws SQLException {
        ParamUtil.requireNonNull("ps", ps);

        if (value != null) {
            ps.setLong(index, value.longValue());
        } else {
            ps.setNull(index, Types.BIGINT);
        }
    }

    protected static void setInt(PreparedStatement ps, int index, Integer value)
            throws SQLException {
        ParamUtil.requireNonNull("ps", ps);

        if (value != null) {
            ps.setInt(index, value.intValue());
        } else {
            ps.setNull(index, Types.INTEGER);
        }
    }

    protected static void setBoolean(PreparedStatement ps, int index, boolean value)
            throws SQLException {
        ParamUtil.requireNonNull("ps", ps);
        ps.setInt(index, value ? 1 : 0);
    }

    public static Properties getDbConfProperties(InputStream is) throws IOException {
        ParamUtil.requireNonNull("is", is);

        Properties props = new Properties();
        try {
            props.load(is);
        } finally {
            try {
                is.close();
            } catch (IOException ex) {
                LOG.warn("could not close stream: {}", ex.getMessage());
            }
        }

        // adapt the configuration
        if (props.getProperty("minimumIdle") != null) {
            props.setProperty("minimumIdle", "1");
        }

        return props;
    }

    public static void deleteTmpFiles(String dirName, String prefix) {
        ParamUtil.requireNonBlank("dirName", dirName);
        ParamUtil.requireNonBlank("prefix", prefix);

        // delete the temporary files
        File dir = new File(dirName);
        File[] children = dir.listFiles();
        if (children != null && children.length > 0) {
            for (File child : children) {
                if (child.getName().startsWith(prefix)) {
                    child.delete();
                }
            }
        }
    }

    protected static void writeLine(OutputStream os, String text) throws IOException {
        ParamUtil.requireNonNull("os", os);
        ParamUtil.requireNonNull("text", text);

        os.write(text.getBytes());
        os.write('\n');
    }

    public static String buildFilename(String prefix, String suffix,
            long minIdOfCurrentFile, long maxIdOfCurrentFile, long maxId) {
        ParamUtil.requireNonNull("prefix", prefix);
        ParamUtil.requireNonNull("suffix", suffix);

        StringBuilder sb = new StringBuilder();
        sb.append(prefix);

        int len = Long.toString(maxId).length();
        String minIdStr = Long.toString(minIdOfCurrentFile);
        for (int i = 0; i < len - minIdStr.length(); i++) {
            sb.append('0');
        }
        sb.append(minIdStr);
        sb.append("-");

        String maxIdStr = Long.toString(maxIdOfCurrentFile);
        for (int i = 0; i < len - maxIdStr.length(); i++) {
            sb.append('0');
        }
        sb.append(maxIdStr);

        sb.append(suffix);
        return sb.toString();
    } // method buildFilename

    public static ZipOutputStream getZipOutputStream(File zipFile) throws FileNotFoundException {
        ParamUtil.requireNonNull("zipFile", zipFile);

        BufferedOutputStream out = new BufferedOutputStream(
                new FileOutputStream(zipFile), STREAM_BUFFER_SIZE);
        ZipOutputStream zipOutStream = new ZipOutputStream(out);
        zipOutStream.setLevel(Deflater.BEST_SPEED);
        return zipOutStream;
    }

    public void releaseResources(Statement ps, ResultSet rs) {
        releaseResources(datasource, ps, rs);
    }

    public static void releaseResources(DataSourceWrapper datasource, Statement ps, ResultSet rs) {
        if (ps != null) {
            try {
                ps.close();
            } catch (SQLException ex) {
                DataAccessException dex = datasource.translate(null, ex);
                LogUtil.warn(LOG, dex, "could not close Statement");
            }
        }

        if (rs != null) {
            try {
                rs.close();
            } catch (SQLException ex) {
                DataAccessException dex = datasource.translate(null, ex);
                LogUtil.warn(LOG, dex, "could not close ResultSet");
            }
        }
    }

}
