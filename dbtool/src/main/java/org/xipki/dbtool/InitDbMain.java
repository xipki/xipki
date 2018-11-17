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

package org.xipki.dbtool;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.OBFSinglePasswordResolver;
import org.xipki.password.PBEPasswordService;
import org.xipki.util.CollectionUtil;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 */

public class InitDbMain {

  private static final Logger LOG = LoggerFactory.getLogger(InitDbMain.class);

  public static void main(String[] args) {

    if (args == null || args.length < 4 || "--help".equals(args[0])) {
      printUsage(null);
      return;
    }

    boolean force = false;
    String dbConfFile = null;
    String dbSchemaFile = null;

    final int argSize = args.length;

    for (int i = 0; i < argSize; i++) {
      String name = args[i];
      switch (name) {
        case "--db-conf":
          if (i < argSize - 1) {
            dbConfFile = args[++i];
          }
          break;
        case "--db-schema":
          if (i < argSize - 1) {
            dbSchemaFile = args[++i];
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

    if (dbSchemaFile == null) {
      printUsage("dbSchemaFile is not specified");
      return;
    }

    try {
      exec(dbConfFile, dbSchemaFile, force);
    } catch (Exception ex) {
      System.err.println("Error while initializing database: " + ex.getMessage());
      LOG.error("Error while initializing database", ex);
    }
  }

  private static void exec(String dbConfFile, String dbSchemaFile, boolean force) throws Exception {
    Properties props = new Properties();
    props.load(Files.newInputStream(Paths.get(IoUtil.expandFilepath(dbConfFile))));
    LiquibaseDatabaseConf dbConf = LiquibaseDatabaseConf.getInstance(props, null);
    String password = dbConf.getPassword();
    if (password != null) {
      char[] newPassword = null;
      if (StringUtil.startsWithIgnoreCase(password, "OBF:")) {
        OBFSinglePasswordResolver resolver = new OBFSinglePasswordResolver();
        newPassword = resolver.resolvePassword(password);
      } else if (StringUtil.startsWithIgnoreCase(password, "PBE:")) {
        char[] masterPassword = IoUtil.readPasswordFromConsole("Enter the master password");
        newPassword = PBEPasswordService.decryptPassword(masterPassword, password);
      }

      if (newPassword != null) {
        dbConf = new LiquibaseDatabaseConf(dbConf.getDriver(), dbConf.getUsername(),
            new String(newPassword), dbConf.getUrl(), dbConf.getSchema());
      }
    }

    printDatabaseInfo(dbConf, dbSchemaFile);
    if (!force) {
      if (!confirm("reset and initialize")) {
        System.out.println("cancelled");
        return;
      }
    }

    initDb(dbConf, dbSchemaFile);
  }

  public static void initDb(LiquibaseDatabaseConf dbConf, String dbSchemaFile) throws Exception {
    LiquibaseMain liquibase = new LiquibaseMain(dbConf, dbSchemaFile);
    try {
      liquibase.init();
      liquibase.releaseLocks();
      liquibase.dropAll();
      liquibase.update();
    } finally {
      liquibase.close();
    }

    dropLiquibaseTables(dbConf);
  }

  private static void printDatabaseInfo(LiquibaseDatabaseConf dbParams, String schemaFile) {
    String msg = StringUtil.concat("\n--------------------------------------------",
        "\n     driver: ", dbParams.getDriver(),  "\n       user: ", dbParams.getUsername(),
        "\n        URL: ", dbParams.getUrl(),
        (dbParams.getSchema() != null ? "     schema: " + dbParams.getSchema() : ""),
        "\nschema file: ", schemaFile, "\n");

    System.out.println(msg);
  }

  private static boolean confirm(String command) throws IOException {
    String text = read("\nDo you wish to " + command + " the database", Arrays.asList("yes", "no"));
    return "yes".equalsIgnoreCase(text);
  }

  private static String read(String prompt, List<String> validValues) throws IOException {
    List<String> tmpValidValues = validValues;
    if (tmpValidValues == null) {
      tmpValidValues = Collections.emptyList();
    }

    if (prompt == null) {
      prompt = "Please enter";
    }

    if (CollectionUtil.isNonEmpty(tmpValidValues)) {
      StringBuilder promptBuilder = new StringBuilder(prompt);
      promptBuilder.append(" [");

      for (String validValue : tmpValidValues) {
        promptBuilder.append(validValue).append("/");
      }
      promptBuilder.deleteCharAt(promptBuilder.length() - 1);
      promptBuilder.append("] ?");

      prompt = promptBuilder.toString();
    }

    while (true) {
      String answer = IoUtil.readLineFromConsole(prompt);
      if (CollectionUtil.isEmpty(tmpValidValues) || tmpValidValues.contains(answer)) {
        return answer;
      } else {
        StringBuilder retryPromptBuilder = new StringBuilder("Please answer with ");
        for (String validValue : tmpValidValues) {
          retryPromptBuilder.append(validValue).append("/");
        }
        retryPromptBuilder.deleteCharAt(retryPromptBuilder.length() - 1);
        prompt = retryPromptBuilder.toString();
      }
    }
  } // method read

  private static void printUsage(String prefix) {
    StringBuilder sb = new StringBuilder();
    if (prefix != null) {
      sb.append(prefix).append("\n");
    }

    sb.append("DESCRIPTION\n");
    sb.append("\tinitdb [options]\n");
    sb.append("\tReset and initialize the database\n");
    sb.append("OPTIONS\n");
    sb.append("\t--db-schema\n");
    sb.append("\t\tDB schema file\n");
    sb.append("\t\t(required)\n");
    sb.append("\t--db-conf\n");
    sb.append("\t\tDB configuration file\n");
    sb.append("\t\t(required)\n");
    sb.append("\t--help\n");
    sb.append("\t\tDisplay this help message\n");
    sb.append("\t--force, -f\n");
    sb.append("\t\tNever prompt for confirmation");

    System.out.println(sb.toString());
  }

  /**
   * Drop the tables DATABASECHANGELOG and DATABASECHANGELOGLOCK generated by Liquibase.
   *
   */
  private static void dropLiquibaseTables(LiquibaseDatabaseConf dbConf) {
    List<String> tables = Arrays.asList("DATABASECHANGELOG", "DATABASECHANGELOGLOCK");

    Connection conn = null;
    Statement stmt;

    try {
      try {
        conn = DriverManager.getConnection(dbConf.getUrl(),
            dbConf.getUsername(), dbConf.getPassword());
        if (dbConf.getSchema() != null) {
          conn.setSchema(dbConf.getSchema());
        }

        stmt = conn.createStatement();
      } catch (SQLException ex) {
        LOG.info("Could not create statement, message: {}, this is OK", ex.getMessage());
        LOG.info("Could not create statement, this is OK", ex);
        return;
      }

      for (String table : tables) {
        try {
          stmt.execute("DROP TABLE " + table);
        } catch (SQLException ex) {
          LOG.info("Could not drop table {}, this is OK", table);
          LOG.debug("Could not drop table" + table, ex);
        }
      }
    } finally {
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException ex) {
          LOG.info("Could not close database connection, this is OK");
          LOG.debug("Could not close database connection", ex);
        }
      }
    }
  }

}
