// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.datasource;

/*
 * XiPKI's Change:
 * - Remove the use of user.dir
 * - Add flag '-- IGNORE-ERROR'
 *
 * Original Text in https://github.com/BenoitDuffez/ScriptRunner/blob/master/ScriptRunner.java
 * Slightly modified version of the com.ibatis.common.jdbc.ScriptRunner class
 * from the iBATIS Apache project. Only removed dependency on Resource class
 * and a constructor
 * GPSHansl, 06.08.2015: regex for delimiter, rearrange comment/delimiter detection, remove
 * some ide warnings.
 */

import org.xipki.util.ConfigurableProperties;
import org.xipki.util.IoUtil;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.LineNumberReader;
import java.io.PrintWriter;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.ZonedDateTime;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Tool to run database scripts.
 * @author Apach project iBATIS
 * @author Benoit Duffez
 * @author Lijun Liao (xipki)
 */
public class ScriptRunner {
  private static final String DEFAULT_DELIMITER = ";";
  private static final Pattern SOURCE_COMMAND = Pattern.compile("^\\s*SOURCE\\s+(.*?)\\s*$", Pattern.CASE_INSENSITIVE);

  /**
   * regex to detect delimiter.
   * ignores spaces, allows delimiter in comment, allows an equals-sign
   */
  public static final Pattern delimP = Pattern.compile(
      "^\\s*(--)?\\s*delimiter\\s*=?\\s*([^\\s]+)+\\s*.*$", Pattern.CASE_INSENSITIVE);

  private final Connection connection;

  private final boolean stopOnError;
  //private final boolean autoCommit = true;

  @SuppressWarnings("UseOfSystemOutOrSystemErr")
  private PrintWriter logWriter = null;
  @SuppressWarnings("UseOfSystemOutOrSystemErr")
  private PrintWriter errorLogWriter = null;

  private String delimiter = DEFAULT_DELIMITER;
  private boolean fullLineDelimiter = false;

  public static void runScript(String dbConfFile, String scriptFile) throws Exception {
    ConfigurableProperties props = new ConfigurableProperties();
    try (InputStream inStream = Files.newInputStream(Paths.get(IoUtil.expandFilepath(dbConfFile)))) {
      props.load(inStream);
    }
    // only one connection is needed.
    props.setProperty("minimumIdle", "1");
    try (DataSourceWrapper dataSource = new DataSourceFactory().createDataSource("default", props)) {
      runScript(dataSource, scriptFile);
    }
  }

  public static void runScript(DataSourceWrapper dataSource, String scriptFile)
      throws Exception {
    Connection conn = dataSource.getConnection();
    try {
      runScript(conn, scriptFile);
    } finally {
      dataSource.returnConnection(conn);
    }
  }

  public static void runScript(Connection conn, String scriptFile)
      throws Exception {
    ScriptRunner runner = new ScriptRunner(conn, true);
    runner.runScript(IoUtil.expandFilepath(scriptFile));
  }

  /**
   * Default constructor
   * @param connection the SQL connection
   * @param stopOnError whether the process stops when error occurs.
   */
  public ScriptRunner(Connection connection, boolean stopOnError) {
    this.connection = connection;
    this.stopOnError = stopOnError;
    File logFile = new File("create_db.log");
    try {
      logWriter = new PrintWriter(new FileWriter(logFile, logFile.exists()));
    } catch(IOException e){
      System.err.println("Unable to access or create the db_create log");
    }

    File errorLogFile = new File("create_db_error.log");
    try {
      errorLogWriter = new PrintWriter(new FileWriter(errorLogFile, errorLogFile.exists()));
    } catch(IOException e){
      System.err.println("Unable to access or create the db_create error log");
    }
    String timeStamp = ZonedDateTime.now().toString();
    println("\n-------\n" + timeStamp + "\n-------\n");
    printlnError("\n-------\n" + timeStamp + "\n-------\n");
  }

  public void setDelimiter(String delimiter, boolean fullLineDelimiter) {
    this.delimiter = delimiter;
    this.fullLineDelimiter = fullLineDelimiter;
  }

  /**
   * Setter for logWriter property
   *
   * @param logWriter - the new value of the logWriter property
   */
  public void setLogWriter(PrintWriter logWriter) {
    this.logWriter = logWriter;
  }

  /**
   * Setter for errorLogWriter property
   *
   * @param errorLogWriter - the new value of the errorLogWriter property
   */
  public void setErrorLogWriter(PrintWriter errorLogWriter) {
    this.errorLogWriter = errorLogWriter;
  }

  /**
   * Runs an SQL script (read in using the Reader parameter)
   *
   * @param filepath - the filepath of the script to run. May be relative to the userDirectory.
   * @throws SQLException if any SQL errors occur
   * @throws IOException if there is an error reading from the Reader
   */
  public void runScript(String filepath) throws IOException, SQLException {
    this.runScript(new BufferedReader(new FileReader(filepath)));
  }

  /**
   * Runs an SQL script (read in using the Reader parameter)
   *
   * @param reader - the source of the script
   * @throws SQLException if any SQL errors occur
   * @throws IOException if there is an error reading from the Reader
   */
  public void runScript(Reader reader) throws IOException, SQLException {
    try {
      boolean originalAutoCommit = connection.getAutoCommit();
      try {
        if (!originalAutoCommit) {
          connection.setAutoCommit(true);
        }
        runScript(connection, reader);
      } finally {
        connection.setAutoCommit(originalAutoCommit);
      }
    } catch (IOException | SQLException e) {
      throw e;
    } catch (Exception e) {
      throw new RuntimeException("Error running script.  Cause: " + e, e);
    }
  }

  /**
   * Runs an SQL script (read in using the Reader parameter) using the
   * connection passed in.
   *
   * @param conn - the connection to use for the script
   * @param reader - the source of the script
   * @throws SQLException if any SQL errors occur
   * @throws IOException if there is an error reading from the Reader
   */
  private void runScript(Connection conn, Reader reader) throws IOException, SQLException {
    StringBuilder command = null;

    try {
      LineNumberReader lineReader = new LineNumberReader(reader);
      String line;
      boolean ignoreSqlError = false;

      while ((line = lineReader.readLine()) != null) {
        if (command == null) {
          command = new StringBuilder();
        }

        String trimmedLine = line.trim();

        final Matcher delimMatch = delimP.matcher(trimmedLine);
        if (trimmedLine.isEmpty() || trimmedLine.startsWith("//")) {
          // Do nothing
        } else if (delimMatch.matches()) {
          setDelimiter(delimMatch.group(2), false);
        } else if (trimmedLine.startsWith("--")) {
          if (trimmedLine.startsWith("-- IGNORE-ERROR")) {
            ignoreSqlError = true;
          }
          println(trimmedLine);
        } else if (!fullLineDelimiter && trimmedLine.endsWith(getDelimiter())
            ||  fullLineDelimiter && trimmedLine.equals(getDelimiter())) {
          command.append(line, 0, line.lastIndexOf(getDelimiter())).append(" ");
          this.execCommand(conn, command, lineReader, ignoreSqlError);
          ignoreSqlError = false;
          command = null;
        } else {
          command.append(line);
          command.append("\n");
        }
      }

      if (command != null) {
        this.execCommand(conn, command, lineReader, ignoreSqlError);
      }
    }
    catch (IOException e) {
      throw new IOException(String.format("Error executing '%s': %s", command, e.getMessage()), e);
    } finally {
      // conn.rollback();
      flush();
    }
  }

  private void execCommand(Connection conn, StringBuilder command, LineNumberReader lineReader,
                           boolean ignoreSqlError)
      throws IOException, SQLException {
    if (command.length() == 0) {
      return;
    }

    Matcher sourceCommandMatcher = SOURCE_COMMAND.matcher(command);
    if (sourceCommandMatcher.matches()) {
      this.runScriptFile(conn, sourceCommandMatcher.group(1));
      return;
    }

    if (ignoreSqlError) {
      try {
        this.execSqlCommand(conn, command, lineReader, false);
      } catch (SQLException e) {
        System.out.println("Ignore " + e.getMessage());
      }
    } else {
      this.execSqlCommand(conn, command, lineReader, true);
    }
  }

  private void runScriptFile(Connection conn, String filepath) throws IOException, SQLException {
    File file = new File(filepath);
    this.runScript(conn, new BufferedReader(new FileReader(file)));
  }

  private void execSqlCommand(Connection conn, StringBuilder command, LineNumberReader lineReader, boolean outputErr)
      throws SQLException {
    Statement statement = conn.createStatement();

    println(command);

    boolean hasResults = false;
    try {
      hasResults = statement.execute(command.toString());
    } catch (SQLException e) {
      if (outputErr) {
        final String errText = String.format("Error executing '%s' (line %d): %s",
            command, lineReader.getLineNumber(), e.getMessage());

        printlnError(errText);
        System.err.println(errText);
        if (stopOnError) {
          throw new SQLException(errText, e);
        }
      }
    }

    if (!conn.getAutoCommit()) {
      conn.commit();
    }

    ResultSet rs = statement.getResultSet();
    if (hasResults && rs != null) {
      ResultSetMetaData md = rs.getMetaData();
      int cols = md.getColumnCount();
      for (int i = 1; i <= cols; i++) {
        String name = md.getColumnLabel(i);
        print(name + "\t");
      }
      println("");
      while (rs.next()) {
        for (int i = 1; i <= cols; i++) {
          String value = rs.getString(i);
          print(value + "\t");
        }
        println("");
      }
    }

    try {
      statement.close();
    } catch (Exception e) {
      // Ignore to work around a bug in Jakarta DBCP
    }
  }

  private String getDelimiter() {
    return delimiter;
  }

  private void print(Object o) {
    if (logWriter != null) {
      logWriter.print(o);
    }
  }

  private void println(Object o) {
    if (logWriter != null) {
      logWriter.println(o);
    }
  }

  private void printlnError(Object o) {
    if (errorLogWriter != null) {
      errorLogWriter.println(o);
    }
  }

  private void flush() {
    if (logWriter != null) {
      logWriter.flush();
    }
    if (errorLogWriter != null) {
      errorLogWriter.flush();
    }
  }
}
