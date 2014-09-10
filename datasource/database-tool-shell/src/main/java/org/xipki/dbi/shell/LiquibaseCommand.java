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
import org.xipki.database.api.SimpleDatabaseConf;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

public abstract class LiquibaseCommand extends XipkiOsgiCommandSupport
{
    private static final Set<String> yesNo = new HashSet<>();

    static
    {
        yesNo.add("yes");
        yesNo.add("no");
    }

    @Option(name = "-logLevel",
            description = "Log level, valid values are debug, info, warning, severe, off")
    protected String logLevel = "warning";

    protected static Properties getDbConfPoperties(String dbconfFile)
    throws FileNotFoundException, IOException
    {
        Properties props = new Properties();
        props.load(new FileInputStream(IoCertUtil.expandFilepath(dbconfFile)));
        return props;
    }

    protected Map<String, SimpleDatabaseConf> getDatabaseConfs()
    throws FileNotFoundException, IOException
    {
        Map<String, SimpleDatabaseConf> ret = new HashMap<>();
        Properties props = getPropertiesFromFile("ca-config/ca.properties");
        for(Object objKey : props.keySet())
        {
            String key = (String) objKey;
            if(key.startsWith("datasource."))
            {
                String datasourceFile = props.getProperty(key);
                String datasourceName = key.substring("datasource.".length());
                Properties dbConf = getDbConfPoperties(datasourceFile);
                SimpleDatabaseConf dbParams = SimpleDatabaseConf.getInstance(dbConf);
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

    protected boolean confirm(String command, SimpleDatabaseConf dbParams)
    throws IOException
    {
        return confirm(command, dbParams, null);
    }

    protected boolean confirm(String command, SimpleDatabaseConf dbParams, String schemaFile)
    throws IOException
    {
        StringBuilder promptBuilder = new StringBuilder();
        promptBuilder.append("\n--------------------------------------------\n");
        promptBuilder.append("DRIVER      = ").append(dbParams.getDriver()).append("\n");
        promptBuilder.append("USER        = ").append(dbParams.getUsername()).append("\n");
        promptBuilder.append("URL         = ").append(dbParams.getUrl()).append("\n");
        if(dbParams.getSchema() != null)
        {
            promptBuilder.append("SCHEMA      = ").append(dbParams.getSchema()).append("\n");
        }
        promptBuilder.append("SCHEMA_FILE = ").append(schemaFile).append("\n");

        promptBuilder.append("\nDo you wish to ").append(command).append(" the database");
        String text = read(promptBuilder.toString(), yesNo);
        return "yes".equalsIgnoreCase(text);
    }

    protected String read(String prompt, Set<String> validValues)
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

}
