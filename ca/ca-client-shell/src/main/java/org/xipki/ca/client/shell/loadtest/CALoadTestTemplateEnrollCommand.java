/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell.loadtest;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ca.client.shell.ClientCommand;
import org.xipki.common.AbstractLoadTest;

/**
 * @author Lijun Liao
 */

@Command(scope = "caclient", name = "loadtest-template-enroll", description="CA Client Template Enroll Load test")
public class CALoadTestTemplateEnrollCommand extends ClientCommand
{

    @Option(name = "-template",
            required = true,
            description = "Required. Template file")
    protected String templateFile;

    @Option(name = "-duration",
            required = false,
            description = "Required. Duration in seconds")
    protected Integer durationInSecond = 30;

    @Option(name = "-thread",
            required = false,
            description = "Number of threads")
    protected Integer numThreads = 5;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(numThreads < 1)
        {
            err("Invalid number of threads " + numThreads);
            return null;
        }

        if(durationInSecond < 1)
        {
            err("Invalid duration " + durationInSecond);
            return null;
        }

        StringBuilder startMsg = new StringBuilder();
        CALoadTestTemplateEnroll loadTest = new CALoadTestTemplateEnroll(raWorker, templateFile);
        int n = loadTest.getNumberOfCertsInOneRequest();

        startMsg.append("Threads:         ").append(numThreads).append("\n");
        startMsg.append("Duration:        ").append(AbstractLoadTest.formatTime(durationInSecond).trim()).append("\n");
        startMsg.append("Template:        ").append(templateFile).append("\n");
        startMsg.append("#Certs/Request:  ").append(n).append("\n");
        startMsg.append("Unit:            ").append(n).append(" certificate");
        if(n > 1)
        {
            startMsg.append("s");
        }
        startMsg.append("\n");
        out(startMsg.toString());

        loadTest.setDuration(durationInSecond);
        loadTest.setThreads(numThreads);
        loadTest.test();

        return null;
    }
}
