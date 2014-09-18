/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.dbi.shell;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import jline.console.ConsoleReader;

import org.apache.felix.gogo.commands.Option;
import org.xipki.console.karaf.XipkiOsgiCommandSupport;
import org.xipki.liquibase.LiquibaseDatabaseConf;
import org.xipki.liquibase.LiquibaseMain;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

public abstract class LiquibaseCommand extends XipkiOsgiCommandSupport
{
    private static final Set<String> yesNo = new HashSet<>();

    private PasswordResolver passwordResolver;

    static
    {
        yesNo.add("yes");
        yesNo.add("no");
    }

    @Option(name = "-q", aliases="--quiet",
            required = false, description = "Quiet mode")
    protected Boolean quiet = Boolean.FALSE;

    @Option(name = "-logLevel",
            description = "Log level, valid values are debug, info, warning, severe, off")
    protected String logLevel = "warning";

    protected void resetAndInit(LiquibaseDatabaseConf dbConf, String schemaFile)
    throws Exception
    {
        printDatabaseInfo(dbConf, schemaFile);
        if(quiet == false)
        {
            if(confirm("reset and initialize") == false)
            {
                out("Cancelled");
                return;
            }
        }

        LiquibaseMain liquibase = new LiquibaseMain(dbConf, schemaFile);
        try
        {
            liquibase.init(logLevel);
            liquibase.releaseLocks();

            if(LiquibaseMain.loglevelIsSevereOrOff(logLevel) == false)
            {
                liquibase.init("severe");
            }
            liquibase.dropAll();

            if(LiquibaseMain.loglevelIsSevereOrOff(logLevel) == false)
            {
                liquibase.init(logLevel);
            }
            liquibase.update();
        }finally
        {
            liquibase.shutdown();
        }

    }

    protected static Properties getDbConfPoperties(String dbconfFile)
    throws FileNotFoundException, IOException
    {
        Properties props = new Properties();
        props.load(new FileInputStream(IoCertUtil.expandFilepath(dbconfFile)));
        return props;
    }

    protected Map<String, LiquibaseDatabaseConf> getDatabaseConfs()
    throws FileNotFoundException, IOException, PasswordResolverException
    {
        Map<String, LiquibaseDatabaseConf> ret = new HashMap<>();
        Properties props = getPropertiesFromFile("ca-config/ca.properties");
        for(Object objKey : props.keySet())
        {
            String key = (String) objKey;
            if(key.startsWith("datasource."))
            {
                String datasourceFile = props.getProperty(key);
                String datasourceName = key.substring("datasource.".length());
                Properties dbConf = getDbConfPoperties(datasourceFile);
                LiquibaseDatabaseConf dbParams = LiquibaseDatabaseConf.getInstance(dbConf, passwordResolver);
                ret.put(datasourceName, dbParams);
            }
        }

        return ret;
    }

    private static Properties getPropertiesFromFile(String propFile)
    throws FileNotFoundException, IOException
    {
        Properties props = new Properties();
        props.load(new FileInputStream(IoCertUtil.expandFilepath(propFile)));
        return props;
    }

    private void printDatabaseInfo(LiquibaseDatabaseConf dbParams, String schemaFile)
    {
        StringBuilder msg = new StringBuilder();
        msg.append("\n--------------------------------------------\n");
        msg.append("DRIVER      = ").append(dbParams.getDriver()).append("\n");
        msg.append("USER        = ").append(dbParams.getUsername()).append("\n");
        msg.append("URL         = ").append(dbParams.getUrl()).append("\n");
        if(dbParams.getSchema() != null)
        {
            msg.append("SCHEMA      = ").append(dbParams.getSchema()).append("\n");
        }
        msg.append("SCHEMA_FILE = ").append(schemaFile).append("\n");

        System.out.println(msg);
    }

    private boolean confirm(String command)
    throws IOException
    {
        String text = read("\nDo you wish to " + command + " the database", yesNo);
        return "yes".equalsIgnoreCase(text);
    }

    private String read(String prompt, Set<String> validValues)
    throws IOException
    {
        if(validValues == null)
        {
            validValues = Collections.emptySet();
        }

        if(prompt == null)
        {
            prompt = "Please enter";
        }

        if(validValues.isEmpty() == false)
        {
            StringBuilder promptBuilder = new StringBuilder(prompt);
            promptBuilder.append(" [");

            for(String validValue : validValues)
            {
                promptBuilder.append(validValue).append("/");
            }
            promptBuilder.deleteCharAt(promptBuilder.length() - 1);
            promptBuilder.append("] ?");

            prompt = promptBuilder.toString();
        }

        ConsoleReader reader = (ConsoleReader) session.get(".jline.reader");

        out(prompt);
        while(true)
        {
            String answer = reader.readLine();
            if(answer == null)
            {
                throw new IOException("interrupted");
            }

            if(validValues.isEmpty() || validValues.contains(answer))
            {
                return answer;
            }
            else
            {
                StringBuilder retryPromptBuilder = new StringBuilder("Please answer with ");
                for(String validValue : validValues)
                {
                    retryPromptBuilder.append(validValue).append("/");
                }
                retryPromptBuilder.deleteCharAt(retryPromptBuilder.length() - 1);
                out(retryPromptBuilder.toString());
            }
        }
    }

    public void setPasswordResolver(PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
    }
}
