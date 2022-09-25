/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.mgmt.db;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.datasource.DataAccessException;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.util.Args;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;

import java.io.*;
import java.nio.file.Files;
import java.sql.*;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.Deflater;
import java.util.zip.ZipOutputStream;

/**
 * Database tool base.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DbToolBase implements Closeable {

  private static final Logger LOG = LoggerFactory.getLogger(DbToolBase.class);

  private static final int STREAM_BUFFER_SIZE = 1048576; // 1M

  protected final AtomicBoolean stopMe;

  protected final DataSourceWrapper datasource;

  protected final String baseDir;

  protected Connection connection;

  private final boolean connectionAutoCommit;

  public DbToolBase(DataSourceWrapper datasource, String baseDir, AtomicBoolean stopMe)
      throws DataAccessException {
    Args.notBlank(baseDir, "baseDir");
    this.stopMe = Args.notNull(stopMe, "stopMe");
    this.datasource = Args.notNull(datasource, "datasource");
    this.connection = datasource.getConnection();
    try {
      this.connectionAutoCommit = connection.getAutoCommit();
    } catch (SQLException ex) {
      throw datasource.translate(null, ex);
    }
    this.baseDir = IoUtil.expandFilepath(baseDir);
  } // constructor

  protected Statement createStatement() throws DataAccessException {
    try {
      return connection.createStatement();
    } catch (SQLException ex) {
      throw datasource.translate(null, ex);
    }
  }

  protected PreparedStatement prepareStatement(String sql) throws DataAccessException {
    try {
      return connection.prepareStatement(sql);
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    }
  }

  public boolean deleteFromTableWithLargerId(String table, String idColumn, long id, Logger log) {
    String sql = StringUtil.concatObjects("DELETE FROM ", table, " WHERE ", idColumn, ">", id);

    Statement stmt;
    try {
      stmt = createStatement();
    } catch (DataAccessException ex) {
      log.error("could not create statement", ex);
      return false;
    }

    try {
      stmt.execute(sql);
    } catch (Throwable th) {
      LogUtil.error(log, th, String.format("could not delete columns from table %s with %s > %s", table, idColumn, id));
      return false;
    } finally {
      releaseResources(stmt, null);
    }

    return true;
  } // method deleteFromTableWithLargerId

  @Override
  public void close() {
    datasource.returnConnection(connection);
    connection = null;
  }

  public long min(String table, String column) throws DataAccessException {
    return datasource.getMin(connection, table, column);
  }

  public long min(String table, String column, String condition) throws DataAccessException {
    return datasource.getMin(connection, table, column, condition);
  }

  public long max(String table, String column) throws DataAccessException {
    return datasource.getMax(connection, table, column);
  }

  public long max(String table, String column, String condition) throws DataAccessException {
    return datasource.getMax(connection, table, column, condition);
  }

  public int count(String table) throws DataAccessException {
    return datasource.getCount(connection, table);
  }

  public boolean tableHasColumn(String table, String column) throws DataAccessException {
    return datasource.tableHasColumn(connection, table, column);
  }

  public boolean tableExists(String table) throws DataAccessException {
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
    return datasource.translate(sql, Args.notNull(ex, "ex"));
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
    Args.notBlank(task, "task");
    try {
      connection.commit();
    } catch (SQLException ex) {
      throw datasource.translate(task, ex);
    }
  }

  protected static void setLong(PreparedStatement ps, int index, Long value) throws SQLException {
    if (value != null) {
      ps.setLong(index, value);
    } else {
      ps.setNull(index, Types.BIGINT);
    }
  }

  protected static void setInt(PreparedStatement ps, int index, Integer value) throws SQLException {
    if (value != null) {
      ps.setInt(index, value);
    } else {
      ps.setNull(index, Types.INTEGER);
    }
  }

  protected static void setBoolean(PreparedStatement ps, int index, boolean value) throws SQLException {
    ps.setInt(index, value ? 1 : 0);
  }

  public static Properties getDbConfProperties(InputStream is) throws IOException {
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
  } // method getDbConfProperties

  public static void deleteTmpFiles(String dirName, String prefix) {
    Args.notBlank(dirName, "dirName");
    Args.notBlank(prefix, "prefix");

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
  } // method deleteTmpFiles

  protected static void writeLine(OutputStream os, String text) throws IOException {
    os.write(StringUtil.toUtf8Bytes(text));
    os.write('\n');
  }

  public static String buildFilename(
      String prefix, String suffix, long minIdOfCurrentFile, long maxIdOfCurrentFile, long maxId) {
    Args.notNull(prefix, "prefix");
    Args.notNull(suffix, "suffix");

    StringBuilder sb = new StringBuilder().append(prefix);

    int len = Long.toString(maxId).length();
    String minIdStr = Long.toString(minIdOfCurrentFile);
    for (int i = 0; i < len - minIdStr.length(); i++) {
      sb.append('0');
    }
    sb.append(minIdStr).append("-");

    String maxIdStr = Long.toString(maxIdOfCurrentFile);
    for (int i = 0; i < len - maxIdStr.length(); i++) {
      sb.append('0');
    }
    sb.append(maxIdStr).append(suffix);
    return sb.toString();
  } // method buildFilename

  public static ZipOutputStream getZipOutputStream(File zipFile) throws IOException {
    BufferedOutputStream out = new BufferedOutputStream(Files.newOutputStream(zipFile.toPath()), STREAM_BUFFER_SIZE);
    ZipOutputStream zipOutStream = new ZipOutputStream(out);
    zipOutStream.setLevel(Deflater.BEST_SPEED);
    return zipOutStream;
  } // method getZipOutputStream

  public void releaseResources(Statement ps, ResultSet rs) {
    datasource.releaseResources(ps, rs, false);
  }

}
