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
import org.xipki.ca.client.shell.loadtest.KeyEntry.DSAKeyEntry;
import org.xipki.ca.client.shell.loadtest.KeyEntry.ECKeyEntry;
import org.xipki.ca.client.shell.loadtest.KeyEntry.RSAKeyEntry;
import org.xipki.ca.client.shell.loadtest.LoadTestEntry.RandomDN;
import org.xipki.security.common.AbstractLoadTest;

/**
 * @author Lijun Liao
 */

@Command(scope = "caclient", name = "loadtest-enroll", description="CA Client Enroll Load test")
public class CALoadTestEnrollCommand extends ClientCommand
{

    @Option(name = "-profile",
            required = true,
            description = "Required. Certificate profile")
    protected String certProfile;

    @Option(name = "-subject",
            required = true,
            description = "Required. Subject template")
    protected String subjectTemplate;

    @Option(name = "-randomDN",
            required = false,
            description = "DN name to be incremented, valid values are\n"
                    + "GIVENNAME, SURNAME, STREET, POSTALCODE, O, OU and CN")
    protected String randomDNStr = "O";

    @Option(name = "-duration",
            required = false,
            description = "Required. Duration in seconds")
    protected Integer durationInSecond = 30;

    @Option(name = "-thread",
            required = false,
            description = "Number of threads")
    protected Integer numThreads = 5;

    @Option(name="-keyType",
            required = false,
            description = "Key type to be requested. Valid values are RSA, EC and DSA")
    private String keyType = "RSA";

    @Option(name = "-user",
            required = false, description = "Username")
    protected String user;

    @Option(name="-keysize",
            required = false,
            description = "Modulus length of RSA key or p length of DSA key")
    private Integer keysize = 2048;

    @Option(name = "-curve",
            description = "EC curve name or OID of EC key",
            required = false)
    protected String curveName = "brainpoolp256r1";

    @Option(name = "-n",
            description = "Number of certificates to be requested in one request",
            required = false)
    protected Integer n = 1;

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

        startMsg.append("Threads:         ").append(numThreads).append("\n");
        startMsg.append("Duration:        ").append(AbstractLoadTest.formatTime(durationInSecond).trim()).append("\n");
        startMsg.append("SubjectTemplate: ").append(subjectTemplate).append("\n");
        startMsg.append("Profile:         ").append(certProfile).append("\n");
        startMsg.append("KeyType:         ").append(keyType).append("\n");
        startMsg.append("#Certs/Request:  ").append(n).append("\n");
        out(startMsg.toString());

        RandomDN randomDN = null;
        if(randomDNStr != null)
        {
            randomDN = RandomDN.getInstance(randomDNStr);
            if(randomDN == null)
            {
                err("Invalid randomDN " + randomDNStr);
                return null;
            }
        }

        KeyEntry keyEntry;
        if("EC".equalsIgnoreCase(keyType))
        {
            keyEntry = new ECKeyEntry(curveName);
        }
        else if("RSA".equalsIgnoreCase(keyType))
        {
            keyEntry = new RSAKeyEntry(keysize.intValue());
        }
        else if("DSA".equalsIgnoreCase(keyType))
        {
            keyEntry = new DSAKeyEntry(keysize.intValue());
        }
        else
        {
            err("Invalid keyType " + keyType);
            return null;
        }

        LoadTestEntry loadtestEntry = new LoadTestEntry(certProfile, keyEntry, subjectTemplate, randomDN);
        CALoadTestEnroll loadTest = new CALoadTestEnroll(raWorker, loadtestEntry, user, n);

        loadTest.setDuration(durationInSecond);
        loadTest.setThreads(numThreads);
        loadTest.test();

        return null;
    }
}
