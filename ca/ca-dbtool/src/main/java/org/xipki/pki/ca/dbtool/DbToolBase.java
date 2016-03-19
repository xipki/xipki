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

package org.xipki.pki.ca.dbtool;

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
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.datasource.api.DataSourceWrapper;
import org.xipki.commons.datasource.api.springframework.dao.DataAccessException;

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

    public DbToolBase(
            final DataSourceWrapper datasource,
            final String baseDir,
            final AtomicBoolean stopMe)
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

    protected Statement createStatement()
    throws DataAccessException {
        try {
            return connection.createStatement();
        } catch (SQLException ex) {
            throw datasource.translate(null, ex);
        }
    }

    protected PreparedStatement prepareStatement(
            final String sql)
    throws DataAccessException {
        ParamUtil.requireNonBlank("sql", sql);

        try {
            return connection.prepareStatement(sql);
        } catch (SQLException ex) {
            throw datasource.translate(sql, ex);
        }
    }

    public boolean deleteFromTableWithLargerId(
            final String tableName,
            final String idColumn,
            final int id,
            final Logger log) {
        ParamUtil.requireNonBlank("tableName", tableName);
        ParamUtil.requireNonBlank("idColumn", idColumn);

        StringBuilder sb = new StringBuilder(50);
        sb.append("DELETE FROM ").append(tableName).append(" WHERE ")
            .append(idColumn).append(" > ").append(id);

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
            String msg = String.format(
                    "could not delete columns from table %s with %s > %s", tableName, idColumn, id);
            log.error(msg, th);
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

    public long getMin(
            final String table,
            final String column)
    throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);
        ParamUtil.requireNonBlank("column", column);

        return datasource.getMin(connection, table, column);
    }

    public long getMin(
            final String table,
            final String column,
            final String condition)
    throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);
        ParamUtil.requireNonBlank("column", column);

        return datasource.getMin(connection, table, column, condition);
    }

    public long getMax(
            final String table,
            final String column)
    throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);
        ParamUtil.requireNonBlank("column", column);

        return datasource.getMax(connection, table, column);
    }

    public long getMax(
            final String table,
            final String column,
            final String condition)
    throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);
        ParamUtil.requireNonBlank("column", column);

        return datasource.getMax(connection, table, column, condition);
    }

    public int getCount(
            final String table)
    throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);

        return datasource.getCount(connection, table);
    }

    public boolean tableHasColumn(
            final String table,
            final String column)
    throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);
        ParamUtil.requireNonBlank("column", column);

        return datasource.tableHasColumn(connection, table, column);
    }

    public boolean tableExists(
            final String table)
    throws DataAccessException {
        ParamUtil.requireNonBlank("table", table);

        return datasource.tableExists(connection, table);
    }

    protected Savepoint setSavepoint()
    throws DataAccessException {
        try {
            return connection.setSavepoint();
        } catch (SQLException ex) {
            throw datasource.translate(null, ex);
        }
    }

    protected void rollback()
    throws DataAccessException {
        try {
            connection.rollback();
        } catch (SQLException ex) {
            throw datasource.translate(null, ex);
        }
    }

    protected DataAccessException translate(
            final String sql,
            final SQLException ex) {
        ParamUtil.requireNonNull("ex", ex);
        return datasource.translate(sql, ex);
    }

    protected void disableAutoCommit()
    throws DataAccessException {
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
            LOG.error("could not recover AutoCommit: {}", dex.getMessage());
            LOG.debug("could not recover AutoCommit", dex);
        }
    }

    protected void commit(
            final String task)
    throws DataAccessException {
        ParamUtil.requireNonBlank("task", task);
        try {
            connection.commit();
        } catch (SQLException ex) {
            throw datasource.translate(task, ex);
        }
    }

    protected static void setLong(
            final PreparedStatement ps,
            final int index,
            final Long value)
    throws SQLException {
        ParamUtil.requireNonNull("ps", ps);

        if (value != null) {
            ps.setLong(index, value.longValue());
        } else {
            ps.setNull(index, Types.BIGINT);
        }
    }

    protected static void setInt(
            final PreparedStatement ps,
            final int index,
            final Integer value)
    throws SQLException {
        ParamUtil.requireNonNull("ps", ps);

        if (value != null) {
            ps.setInt(index, value.intValue());
        } else {
            ps.setNull(index, Types.INTEGER);
        }
    }

    protected static void setBoolean(
            final PreparedStatement ps,
            final int index,
            final boolean value)
    throws SQLException {
        ParamUtil.requireNonNull("ps", ps);

        int intValue = value
                ? 1
                : 0;
        ps.setInt(index, intValue);
    }

    public static Properties getDbConfProperties(
            final InputStream is)
    throws IOException {
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

    public static void deleteTmpFiles(
            final String dirName,
            final String prefix) {
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

    protected static void writeLine(
            final OutputStream os,
            final String text)
    throws IOException {
        ParamUtil.requireNonNull("os", os);
        ParamUtil.requireNonNull("text", text);

        os.write(text.getBytes());
        os.write('\n');
    }

    public static String buildFilename(
            final String prefix,
            final String suffix,
            final int minIdOfCurrentFile,
            final int maxIdOfCurrentFile,
            final int maxId) {
        ParamUtil.requireNonNull("prefix", prefix);
        ParamUtil.requireNonNull("suffix", suffix);

        StringBuilder sb = new StringBuilder();
        sb.append(prefix);

        int len = Integer.toString(maxId).length();
        String minIdStr = Integer.toString(minIdOfCurrentFile);
        for (int i = 0; i < len - minIdStr.length(); i++) {
            sb.append('0');
        }
        sb.append(minIdStr);
        sb.append("-");

        String maxIdStr = Integer.toString(maxIdOfCurrentFile);
        for (int i = 0; i < len - maxIdStr.length(); i++) {
            sb.append('0');
        }
        sb.append(maxIdStr);

        sb.append(suffix);
        return sb.toString();
    } // method writeLine

    public static ZipOutputStream getZipOutputStream(
            final File zipFile)
    throws FileNotFoundException {
        ParamUtil.requireNonNull("zipFile", zipFile);

        BufferedOutputStream out = new BufferedOutputStream(
                new FileOutputStream(zipFile), STREAM_BUFFER_SIZE);
        ZipOutputStream zipOutStream = new ZipOutputStream(out);
        zipOutStream.setLevel(Deflater.BEST_SPEED);
        return zipOutStream;
    }

    public void releaseResources(
            final Statement ps,
            final ResultSet rs) {
        releaseResources(datasource, ps, rs);
    }

    public static void releaseResources(
            final DataSourceWrapper datasource,
            final Statement ps,
            final ResultSet rs) {
        if (ps != null) {
            try {
                ps.close();
            } catch (SQLException ex) {
                DataAccessException dex = datasource.translate(null, ex);
                LOG.warn("could not close Statement: {}", dex.getMessage());
                LOG.debug("could not close Statement", dex);
            }
        }

        if (rs != null) {
            try {
                rs.close();
            } catch (SQLException ex) {
                DataAccessException dex = datasource.translate(null, ex);
                LOG.warn("could not close ResultSet: {}", dex.getMessage());
                LOG.debug("could not close ResultSet", dex);
            }
        }
    }

}
