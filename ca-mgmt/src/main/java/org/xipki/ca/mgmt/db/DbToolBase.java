// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.codec.Args;
import org.xipki.util.conf.ConfigurableProperties;
import org.xipki.util.datasource.DataAccessException;
import org.xipki.util.datasource.DataSourceWrapper;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;

import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.Deflater;
import java.util.zip.ZipOutputStream;

/**
 * Database tool base.
 *
 * @author Lijun Liao (xipki)
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

  public DbToolBase(DataSourceWrapper datasource, String baseDir,
                    AtomicBoolean stopMe)
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

  protected PreparedStatement prepareStatement(String sql)
      throws DataAccessException {
    try {
      return connection.prepareStatement(sql);
    } catch (SQLException ex) {
      throw datasource.translate(sql, ex);
    }
  }

  public boolean deleteFromTableWithLargerId(
      String table, String idColumn, long id, Logger log) {
    String sql = StringUtil.concatObjects("DELETE FROM ", table,
        " WHERE ", idColumn, ">", id);

    PreparedStatement stmt;
    try {
      stmt = prepareStatement(sql);
    } catch (DataAccessException ex) {
      log.error("could not create statement", ex);
      return false;
    }

    try {
      stmt.execute();
    } catch (Throwable th) {
      LogUtil.error(log, th, String.format(
          "could not delete columns from table %s with %s > %s",
          table, idColumn, id));
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

  public long max(String table, String column) throws DataAccessException {
    return datasource.getMax(connection, table, column);
  }

  public int count(String table) throws DataAccessException {
    return datasource.getCount(connection, table);
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

  protected static void setLong(PreparedStatement ps, int index, Long value)
      throws SQLException {
    if (value != null) {
      ps.setLong(index, value);
    } else {
      ps.setNull(index, Types.BIGINT);
    }
  }

  protected static void setInt(PreparedStatement ps, int index, Integer value)
      throws SQLException {
    if (value != null) {
      ps.setInt(index, value);
    } else {
      ps.setNull(index, Types.INTEGER);
    }
  }

  protected static void setBoolean(
      PreparedStatement ps, int index, boolean value)
      throws SQLException {
    ps.setInt(index, value ? 1 : 0);
  }

  public static ConfigurableProperties getDbConfProperties(Path path)
      throws IOException {
    ConfigurableProperties props = new ConfigurableProperties();
    try (InputStream is = Files.newInputStream(path)) {
      props.load(is);
    }

    // adapt the configuration
    props.setProperty("minimumIdle", "1");

    return props;
  } // method getDbConfProperties

  public static void deleteTmpFiles(String dirName, String prefix) {
    Args.notBlank(dirName, "dirName");
    Args.notBlank(prefix, "prefix");

    // delete the temporary files
    File dir = new File(dirName);
    File[] children = dir.listFiles();
    if (children != null) {
      for (File child : children) {
        if (child.getName().startsWith(prefix)) {
          try {
            IoUtil.deleteFile0(child);
          } catch (IOException ex) {
            LOG.warn("error deleting temporary file {}", child.getPath(), ex);
          }
        }
      }
    }
  } // method deleteTmpFiles

  protected static void writeLine(OutputStream os, String text)
      throws IOException {
    os.write(StringUtil.toUtf8Bytes(text));
    os.write('\n');
  }

  public static String buildFilename(
      String prefix, String suffix, long minIdOfCurrentFile,
      long maxIdOfCurrentFile, long maxId) {
    Args.notNull(prefix, "prefix");
    Args.notNull(suffix, "suffix");

    StringBuilder sb = new StringBuilder().append(prefix);

    int len = Long.toString(maxId).length();
    String minIdStr = Long.toString(minIdOfCurrentFile);
    sb.append("0".repeat(Math.max(0, len - minIdStr.length())));
    sb.append(minIdStr).append("-");

    String maxIdStr = Long.toString(maxIdOfCurrentFile);
    sb.append("0".repeat(Math.max(0, len - maxIdStr.length())));
    sb.append(maxIdStr).append(suffix);
    return sb.toString();
  } // method buildFilename

  public static ZipOutputStream getZipOutputStream(File zipFile)
      throws IOException {
    BufferedOutputStream out = new BufferedOutputStream(
        Files.newOutputStream(zipFile.toPath()), STREAM_BUFFER_SIZE);
    ZipOutputStream zipOutStream = new ZipOutputStream(out);
    zipOutStream.setLevel(Deflater.BEST_SPEED);
    return zipOutStream;
  } // method getZipOutputStream

  public void releaseResources(PreparedStatement ps, ResultSet rs) {
    datasource.releaseResources(ps, rs, false);
  }

}
