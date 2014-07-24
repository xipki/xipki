/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp.client.shell.loadtest;

import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.ocsp.client.shell.AbstractOCSPStatusCommand;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "ocsp", name = "loadtest-status", description="OCSP Load test")
public class OCSPStatusLoadTestCommand extends AbstractOCSPStatusCommand
{
    @Option(name = "-serial",
            required = true,
            description = "Required. Serial numbers.\n"
                    + "Comma-seperated serial numbers or ranges")
    protected String           serialNumbers;

    @Option(name = "-duration",
            required = true,
            description = "Required. Duration in seconds")
    protected int              durationInSecond;

    @Option(name = "-thread",
            required = false,
            description = "Number of threads, the default is 5")
    protected Integer          numThreads;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(numThreads == null)
        {
            numThreads = 5;
        }

        List<Long> serialNumbers = new LinkedList<>();

        try
        {
            StringTokenizer tokens = new StringTokenizer(this.serialNumbers, ",");
            while(tokens.hasMoreTokens())
            {
                String token = tokens.nextToken().trim();
                StringTokenizer subtokens = new StringTokenizer(token, "- ");
                int countTokens = subtokens.countTokens();
                if(countTokens == 1)
                {
                    serialNumbers.add(Long.parseLong(subtokens.nextToken().trim()));
                }
                else if(countTokens == 2)
                {
                    int startSerial = Integer.parseInt(subtokens.nextToken().trim());
                    int endSerial = Integer.parseInt(subtokens.nextToken().trim());
                    if(startSerial < 1 || endSerial < 1 || startSerial > endSerial)
                    {
                        System.err.println("invalid serial number " + this.serialNumbers);
                        return null;
                    }
                    for(long i = startSerial; i <= endSerial; i++)
                    {
                        serialNumbers.add(i);
                    }
                }
                else
                {
                    System.err.println("invalid serial number " + this.serialNumbers);
                    return null;
                }
            }
        }catch(Exception e)
        {
            System.err.println("invalid serial numbers " + this.serialNumbers);
            return null;
        }

        if(numThreads < 1)
        {
            System.err.println("Invalid number of threads " + numThreads);
            return null;
        }

        URL serverUrl = getServiceURL();

        StringBuilder startMsg = new StringBuilder();

        startMsg.append("Threads:        " + numThreads).append("\n");
        startMsg.append("Duration:       " + durationInSecond + " s").append("\n");
        startMsg.append("Serial numbers: " + this.serialNumbers).append("\n");
        startMsg.append("CA cert:        " + caCertFile).append("\n");
        startMsg.append("Server URL:     " + serverUrl.toString()).append("\n");
        startMsg.append("Hash:           " + hashAlgo).append("\n");
        System.out.print(startMsg.toString());

        X509Certificate caCert = IoCertUtil.parseCert(caCertFile);

        RequestOptions options = getRequestOptions();

        OcspLoadTest loadTest = new OcspLoadTest(requestor, serialNumbers,
                caCert, serverUrl, options);
        loadTest.setDuration(durationInSecond);
        loadTest.setThreads(numThreads);
        loadTest.test();

        return null;
    }
}
