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

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.xipki.common.AbstractLoadTest;
import org.xipki.common.IoCertUtil;
import org.xipki.common.StringUtil;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.ocsp.client.shell.AbstractOCSPStatusCommand;

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
    protected String serialNumbers;

    @Option(name = "-duration",
            required = false,
            description = "Duration in seconds")
    protected int durationInSecond = 30;

    @Option(name = "-thread",
            required = false,
            description = "Number of threads")
    protected Integer numThreads = 5;

    @Override
    protected Object doExecute()
    throws Exception
    {
        List<Long> serialNumbers = new LinkedList<>();

        try
        {
            List<String> tokens = StringUtil.split(this.serialNumbers, ",");
            for(String token : tokens)
            {
                List<String> subtokens = StringUtil.split(token.trim(), "- ");
                int countTokens = subtokens.size();
                if(countTokens == 1)
                {
                    serialNumbers.add(Long.parseLong(subtokens.get(0)));
                }
                else if(countTokens == 2)
                {
                    int startSerial = Integer.parseInt(subtokens.get(0).trim());
                    int endSerial = Integer.parseInt(subtokens.get(1).trim());
                    if(startSerial < 1 || endSerial < 1 || startSerial > endSerial)
                    {
                        err("invalid serial number " + this.serialNumbers);
                        return null;
                    }
                    for(long i = startSerial; i <= endSerial; i++)
                    {
                        serialNumbers.add(i);
                    }
                }
                else
                {
                    err("invalid serial number " + this.serialNumbers);
                    return null;
                }
            }
        }catch(Exception e)
        {
            err("invalid serial numbers " + this.serialNumbers);
            return null;
        }

        if(numThreads < 1)
        {
            err("Invalid number of threads " + numThreads);
            return null;
        }

        URL serverUrl = getServiceURL();

        StringBuilder startMsg = new StringBuilder();

        startMsg.append("Threads:        ").append(numThreads).append("\n");
        startMsg.append("Duration:       ").append(AbstractLoadTest.formatTime(durationInSecond).trim()).append("\n");
        startMsg.append("Serial numbers: ").append(this.serialNumbers).append("\n");
        startMsg.append("CA cert:        ").append(caCertFile).append("\n");
        startMsg.append("Server URL:     ").append(serverUrl.toString()).append("\n");
        startMsg.append("Hash:           ").append(hashAlgo).append("\n");
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
