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

package org.xipki.dbtool;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Properties;

/**
 * Class with main method to run scripts on the database.
 *
 * @author Lijun Liao
 */

public class RunScriptMain {

  private static final Logger LOG = LoggerFactory.getLogger(RunScriptMain.class);

  public static void main(String[] args) {

    if (args == null || args.length < 4 || "--help".equals(args[0])) {
      printUsage(null);
      return;
    }

    boolean force = false;
    String dbConfFile = null;
    String scriptFile = null;

    final int argSize = args.length;

    for (int i = 0; i < argSize; i++) {
      String name = args[i];
      switch (name) {
        case "--db-conf":
          if (i < argSize - 1) {
            dbConfFile = args[++i];
          }
          break;
        case "--script":
          if (i < argSize - 1) {
            scriptFile = args[++i];
          }
          break;
        case "--force":
        case "-f":
          force = true;
          break;
        default:
          break;
      }
    }

    if (dbConfFile == null) {
      printUsage("dbConfFile is not specified");
      return;
    }

    if (scriptFile == null) {
      printUsage("scriptFile is not specified");
      return;
    }

    try {
      exec(dbConfFile, scriptFile, force);
    } catch (Exception ex) {
      System.err.println("Error while running script on the database: " + ex.getMessage());
      LOG.error("Error while running script on the database", ex);
    }
  } // method main

  private static void exec(String dbConfFile, String scriptFile, boolean force)
      throws Exception {
    Properties props = new Properties();
    try (InputStream is = Files.newInputStream(
                            Paths.get(IoUtil.expandFilepath(dbConfFile)))) {
      props.load(is);
    }

    LiquibaseMain.DatabaseConf dbConf = LiquibaseMain.DatabaseConf.getInstance(props, null);
    printDatabaseInfo(dbConf, scriptFile);
    if (!force) {
      if (!confirm("run the script on the database")) {
        System.out.println("cancelled");
        return;
      }
    }

    runScript(dbConf, scriptFile);
  } // method exec

  public static void runScript(LiquibaseMain.DatabaseConf dbConf, String scriptFile)
      throws Exception {
    Connection conn = null;
    try {
      conn = DriverManager.getConnection(dbConf.getUrl(),
          dbConf.getUsername(), dbConf.getPassword());
      if (dbConf.getSchema() != null) {
        conn.setSchema(dbConf.getSchema());
      }

      ScriptRunner runner = new ScriptRunner(conn, false, true);
      runner.runScript(IoUtil.expandFilepath(scriptFile));
      conn.commit();
    } finally {
      if (conn != null) {
        conn.close();
      }
    }

  } // method initDb

  private static void printDatabaseInfo(LiquibaseMain.DatabaseConf dbParams, String schemaFile) {
    String msg = StringUtil.concat("\n--------------------------------------------",
        "\n     driver: ", dbParams.getDriver(),  "\n       user: ", dbParams.getUsername(),
        "\n        URL: ", dbParams.getUrl(),
        (dbParams.getSchema() != null ? "     schema: " + dbParams.getSchema() : ""),
        "\nscript file: ", schemaFile, "\n");

    System.out.println(msg);
  } // method printDatabaseInfo

  private static boolean confirm(String command) {
    String prompt = "Do you wish to " + command + " the database (Yes/No)? ";
    String answer = IoUtil.readLineFromConsole(prompt);
    return "yes".equalsIgnoreCase(answer) || "y".equalsIgnoreCase(answer);
  }

  private static void printUsage(String prefix) {
    StringBuilder sb = new StringBuilder();
    if (prefix != null) {
      sb.append(prefix).append("\n");
    }

    sb.append("DESCRIPTION\n");
    sb.append("\trunscript [options]\n");
    sb.append("\tRun script on the database\n");
    sb.append("OPTIONS\n");
    sb.append("\t--script\n");
    sb.append("\t\tSQL script file\n");
    sb.append("\t\t(required)\n");
    sb.append("\t--db-conf\n");
    sb.append("\t\tDB configuration file\n");
    sb.append("\t\t(required)\n");
    sb.append("\t--help\n");
    sb.append("\t\tDisplay this help message\n");
    sb.append("\t--force, -f\n");
    sb.append("\t\tNever prompt for confirmation");

    System.out.println(sb.toString());
  } // method printUsage

}
