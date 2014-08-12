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
import org.xipki.security.common.AbstractLoadTest;

/**
 * @author Lijun Liao
 */

@Command(scope = "caclient", name = "loadtest-enroll", description="CA Client Enroll Load test")
public class CALoadTestCommand extends ClientCommand
{

    @Option(name = "-profile",
            required = true,
            description = "Required. Certificate profile")
    protected String certProfile;

    @Option(name = "-subject",
            required = true,
            description = "Required. Subject template")
    protected String subjectTemplate;

    @Option(name = "-duration",
            required = false,
            description = "Required. Duration in seconds, the default is 10")
    protected Integer durationInSecond;

    @Option(name = "-thread",
            required = false,
            description = "Number of threads, the default is 5")
    protected Integer numThreads;

    @Option(name="-ec",
            required = false,
            description = "Generate certificate for ECC key")
    private Boolean ecc;

    @Option(name="-keysize",
            required = false,
            description = "Key size of RSA key, the default is 2048.")
    private Integer keysize;

    @Option(name = "-curve",
            description = "EC curve name or OID, the default is brainpoolp256r1",
            required = false)
    protected String curveName;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(numThreads == null)
        {
            numThreads = 5;
        }

        if(numThreads < 1)
        {
            System.err.println("Invalid number of threads " + numThreads);
            return null;
        }

        if(durationInSecond == null)
        {
            durationInSecond = 10;
        }

        if(durationInSecond < 1)
        {
            System.err.println("Invalid duration " + durationInSecond);
            return null;
        }

        StringBuilder startMsg = new StringBuilder();

        startMsg.append("Threads:         ").append(numThreads).append("\n");
        startMsg.append("Duration:        ").append(AbstractLoadTest.formatTime(durationInSecond).trim()).append("\n");
        startMsg.append("SubjectTemplate: ").append(subjectTemplate).append("\n");
        startMsg.append("Profile:         ").append(certProfile).append("\n");
        System.out.print(startMsg.toString());

        CALoadTest loadTest;
        if(ecc != null && ecc.booleanValue())
        {
            if(curveName == null)
            {
                curveName = "brainpoolp256r1";
            }
            loadTest = new CALoadTest.ECCALoadTest(raWorker, certProfile, subjectTemplate, curveName);
        }
        else
        {
            if(keysize == null)
            {
                keysize = 2048;
            }
            loadTest = new CALoadTest.RSACALoadTest(raWorker, certProfile, subjectTemplate, keysize.intValue());
        }

        loadTest.setDuration(durationInSecond);
        loadTest.setThreads(numThreads);
        loadTest.test();

        return null;
    }
}
