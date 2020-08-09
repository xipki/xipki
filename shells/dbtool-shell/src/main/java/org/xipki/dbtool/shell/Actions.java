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

package org.xipki.dbtool.shell;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.dbtool.InitDbMain;
import org.xipki.dbtool.LiquibaseMain;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.shell.XiAction;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

/**
 * Actions of database tool.
 *
 * @author Lijun Liao
 */
public class Actions {

  @Command(scope = "xi", name = "initdb", description = "reset and initialize single database")
  @Service
  public static class Initdb extends LiquibaseAction {

    @Override
    protected Object execute0()
        throws Exception {
      LiquibaseMain.DatabaseConf dbConf = getDatabaseConf();

      printDatabaseInfo(dbConf, dbSchemaFile);
      if (!force) {
        if (!confirm("reset and initialize", 3)) {
          println("cancelled");
          return null;
        }
      }

      InitDbMain.initDb(dbConf, dbSchemaFile);

      return null;
    }

  } // class Initdb

  public abstract static class LiquibaseAction extends XiAction {

    @Reference
    private PasswordResolver passwordResolver;

    @Option(name = "--force", aliases = "-f", description = "never prompt for confirmation")
    protected Boolean force = Boolean.FALSE;

    @Option(name = "--db-schema", required = true, description = "DB schema file")
    @Completion(FileCompleter.class)
    protected String dbSchemaFile;

    @Option(name = "--db-conf", required = true, description = "DB configuration file")
    @Completion(FileCompleter.class)
    private String dbConfFile;

    static void printDatabaseInfo(LiquibaseMain.DatabaseConf dbParams, String schemaFile) {
      String msg = StringUtil.concat("\n--------------------------------------------",
          "\n     driver: ", dbParams.getDriver(),  "\n       user: ", dbParams.getUsername(),
          "\n        URL: ", dbParams.getUrl(),
          (dbParams.getSchema() != null ? "     schema: " + dbParams.getSchema() : ""),
          "\nschema file: ", schemaFile, "\n");

      System.out.println(msg);
    }

    protected LiquibaseMain.DatabaseConf getDatabaseConf()
        throws IOException, PasswordResolverException {
      Properties props = new Properties();
      props.load(Files.newInputStream(Paths.get(IoUtil.expandFilepath(dbConfFile))));
      return LiquibaseMain.DatabaseConf.getInstance(props, passwordResolver);
    }

    protected static Properties getPropertiesFromFile(String propFile)
        throws IOException {
      Properties props = new Properties();
      props.load(Files.newInputStream(Paths.get(IoUtil.expandFilepath(propFile))));
      return props;
    }

  } // class LiquibaseAction

}
