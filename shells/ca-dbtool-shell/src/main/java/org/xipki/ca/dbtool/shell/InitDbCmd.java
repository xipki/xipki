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

package org.xipki.ca.dbtool.shell;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.dbtool.shell.completer.LogLevelCompleter;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.console.karaf.XiAction;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.dbtool.LiquibaseDatabaseConf;
import org.xipki.dbtool.LiquibaseMain;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "initdb",
        description = "reset and initialize single database")
@Service
public class InitDbCmd extends XiAction {

    private static final List<String> YES_NO = Arrays.asList("yes", "no");

    @Reference
    private PasswordResolver passwordResolver;

    @Option(name = "--force", aliases = "-f",
            description = "never prompt for confirmation")
    private Boolean force = Boolean.FALSE;

    @Option(name = "--log-level",
            description = "log level, valid values are debug, info, warning, severe, off")
    @Completion(LogLevelCompleter.class)
    private String logLevel = "warning";

    @Option(name = "--log-file",
            description = "log file")
    @Completion(FilePathCompleter.class)
    private String logFile;

    @Option(name = "--db-conf", required = true,
            description = "DB configuration file")
    @Completion(FilePathCompleter.class)
    private String dbConfFile;

    @Option(name = "--db-schema", required = true,
            description = "DB schema file")
    @Completion(FilePathCompleter.class)
    private String dbSchemaFile;

    @Override
    protected Object execute0() throws Exception {
        LiquibaseDatabaseConf dbConf = getDatabaseConf();
        resetAndInit(dbConf, dbSchemaFile);
        return null;
    }

    private void resetAndInit(final LiquibaseDatabaseConf dbConf, final String schemaFile)
            throws Exception {
        ParamUtil.requireNonNull("dbConf", dbConf);
        ParamUtil.requireNonNull("schemaFile", schemaFile);

        printDatabaseInfo(dbConf, schemaFile);
        if (!force) {
            if (!confirm("reset and initialize")) {
                println("cancelled");
                return;
            }
        }

        LiquibaseMain liquibase = new LiquibaseMain(dbConf, schemaFile);
        try {
            liquibase.init(logLevel, logFile);
            liquibase.releaseLocks();
            liquibase.dropAll();
            liquibase.update();
        } finally {
            liquibase.shutdown();
        }

    }

    private LiquibaseDatabaseConf getDatabaseConf()
            throws FileNotFoundException, IOException, PasswordResolverException {
        Properties props = new Properties();
        props.load(new FileInputStream(IoUtil.expandFilepath(dbConfFile)));
        return LiquibaseDatabaseConf.getInstance(props, passwordResolver);
    }

    private void printDatabaseInfo(final LiquibaseDatabaseConf dbParams, final String schemaFile) {
        StringBuilder msg = new StringBuilder();
        msg.append("\n--------------------------------------------\n");
        msg.append("     driver: ").append(dbParams.driver()).append("\n");
        msg.append("       user: ").append(dbParams.username()).append("\n");
        msg.append("        URL: ").append(dbParams.url()).append("\n");
        if (dbParams.schema() != null) {
            msg.append("     schema: ").append(dbParams.schema()).append("\n");
        }
        msg.append("schema file: ").append(schemaFile).append("\n");

        System.out.println(msg);
    }

    private boolean confirm(final String command) throws IOException {
        String text = read("\nDo you wish to " + command + " the database", YES_NO);
        return "yes".equalsIgnoreCase(text);
    }

    private String read(final String prompt, final List<String> validValues) throws IOException {
        String tmpPrompt = prompt;
        List<String> tmpValidValues = validValues;
        if (tmpValidValues == null) {
            tmpValidValues = Collections.emptyList();
        }

        if (tmpPrompt == null) {
            tmpPrompt = "Please enter";
        }

        if (isNotEmpty(tmpValidValues)) {
            StringBuilder promptBuilder = new StringBuilder(tmpPrompt);
            promptBuilder.append(" [");

            for (String validValue : tmpValidValues) {
                promptBuilder.append(validValue).append("/");
            }
            promptBuilder.deleteCharAt(promptBuilder.length() - 1);
            promptBuilder.append("] ?");

            tmpPrompt = promptBuilder.toString();
        }

        while (true) {
            String answer = readPrompt(tmpPrompt);
            if (isEmpty(tmpValidValues) || tmpValidValues.contains(answer)) {
                return answer;
            } else {
                StringBuilder retryPromptBuilder = new StringBuilder("Please answer with ");
                for (String validValue : tmpValidValues) {
                    retryPromptBuilder.append(validValue).append("/");
                }
                retryPromptBuilder.deleteCharAt(retryPromptBuilder.length() - 1);
                tmpPrompt = retryPromptBuilder.toString();
            }
        }
    } // method read

}
