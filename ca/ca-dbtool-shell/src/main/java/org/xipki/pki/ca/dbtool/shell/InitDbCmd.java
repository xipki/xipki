/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.pki.ca.dbtool.shell;

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
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.console.karaf.XipkiCommandSupport;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.dbtool.LiquibaseDatabaseConf;
import org.xipki.dbtool.LiquibaseMain;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.pki.ca.dbtool.shell.completer.LogLevelCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xipki-db", name = "initdb",
        description = "reset and initialize single database")
@Service
public class InitDbCmd extends XipkiCommandSupport {

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
