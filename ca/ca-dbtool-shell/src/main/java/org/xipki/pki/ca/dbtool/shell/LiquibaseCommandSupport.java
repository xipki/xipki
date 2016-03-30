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

package org.xipki.pki.ca.dbtool.shell;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.console.karaf.XipkiCommandSupport;
import org.xipki.commons.console.karaf.completer.FilePathCompleter;
import org.xipki.commons.dbtool.LiquibaseDatabaseConf;
import org.xipki.commons.dbtool.LiquibaseMain;
import org.xipki.commons.password.api.PasswordResolver;
import org.xipki.commons.password.api.PasswordResolverException;
import org.xipki.pki.ca.dbtool.shell.completer.LogLevelCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class LiquibaseCommandSupport extends XipkiCommandSupport {

    private static final String DFLT_CACONF_FILE = "xipki/ca-config/ca.properties";

    private static final List<String> YES_NO = Arrays.asList("yes", "no");

    @Reference
    private PasswordResolver passwordResolver;

    @Option(name = "--quiet", aliases = "-q",
            description = "quiet mode")
    private Boolean quiet = Boolean.FALSE;

    @Option(name = "--log-level",
            description = "log level, valid values are debug, info, warning, severe, off")
    @Completion(LogLevelCompleter.class)
    private String logLevel = "warning";

    @Option(name = "--log-file",
            description = "log file")
    @Completion(FilePathCompleter.class)
    private String logFile;

    @Option(name = "--ca-conf",
            description = "CA configuration file")
    @Completion(FilePathCompleter.class)
    private String caconfFile = DFLT_CACONF_FILE;

    protected void resetAndInit(
            final LiquibaseDatabaseConf dbConf,
            final String schemaFile)
    throws Exception {
        ParamUtil.requireNonNull("dbConf", dbConf);
        ParamUtil.requireNonNull("schemaFile", schemaFile);

        printDatabaseInfo(dbConf, schemaFile);
        if (!quiet) {
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

    protected void update(
            final LiquibaseDatabaseConf dbConf,
            final String schemaFile)
    throws Exception {
        ParamUtil.requireNonNull("dbConf", dbConf);
        ParamUtil.requireNonNull("schemaFile", schemaFile);

        printDatabaseInfo(dbConf, schemaFile);
        if (!quiet) {
            if (!confirm("update")) {
                println("cancelled");
                return;
            }
        }

        LiquibaseMain liquibase = new LiquibaseMain(dbConf, schemaFile);
        try {
            liquibase.init(logLevel, logFile);
            liquibase.update();
        } finally {
            liquibase.shutdown();
        }

    }

    private static Properties getDbConfPoperties(
            final String dbconfFile)
    throws FileNotFoundException, IOException {
        Properties props = new Properties();
        props.load(new FileInputStream(IoUtil.expandFilepath(dbconfFile)));
        return props;
    }

    protected Map<String, LiquibaseDatabaseConf> getDatabaseConfs()
    throws FileNotFoundException, IOException, PasswordResolverException {
        Map<String, LiquibaseDatabaseConf> ret = new HashMap<>();
        Properties props = getPropertiesFromFile(caconfFile);
        for (Object objKey : props.keySet()) {
            String key = (String) objKey;
            if (key.startsWith("datasource.")) {
                String datasourceFile = props.getProperty(key);
                String datasourceName = key.substring("datasource.".length());
                Properties dbConf = getDbConfPoperties(datasourceFile);
                LiquibaseDatabaseConf dbParams = LiquibaseDatabaseConf.getInstance(
                        dbConf, passwordResolver);
                ret.put(datasourceName, dbParams);
            }
        }

        return ret;
    }

    private static Properties getPropertiesFromFile(
            final String propFile)
    throws FileNotFoundException, IOException {
        Properties props = new Properties();
        props.load(new FileInputStream(IoUtil.expandFilepath(propFile)));
        return props;
    }

    private void printDatabaseInfo(
            final LiquibaseDatabaseConf dbParams,
            final String schemaFile) {
        StringBuilder msg = new StringBuilder();
        msg.append("\n--------------------------------------------\n");
        msg.append("     driver: ").append(dbParams.getDriver()).append("\n");
        msg.append("       user: ").append(dbParams.getUsername()).append("\n");
        msg.append("        url: ").append(dbParams.getUrl()).append("\n");
        if (dbParams.getSchema() != null) {
            msg.append("     schema: ").append(dbParams.getSchema()).append("\n");
        }
        msg.append("schema file: ").append(schemaFile).append("\n");

        System.out.println(msg);
    }

    private boolean confirm(
            final String command)
    throws IOException {
        String text = read("\nDo you wish to " + command + " the database", YES_NO);
        return "yes".equalsIgnoreCase(text);
    }

    private String read(
            final String prompt,
            final List<String> validValues)
    throws IOException {
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
