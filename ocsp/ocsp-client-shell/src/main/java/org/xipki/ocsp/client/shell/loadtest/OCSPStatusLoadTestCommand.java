/*
 * Copyright (c) 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
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
import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.xipki.ocsp.client.api.OCSPRequestor;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.security.common.IoCertUtil;

@Command(scope = "ocsp", name = "status-loadtest", description="OCSP Load test")
public class OCSPStatusLoadTestCommand extends OsgiCommandSupport
{
    private static final String DFLT_URL = "http://localhost:8080/ocsp";
    @Option(name = "-url",
            description = "Server URL, the default is " + DFLT_URL)
    protected String            serverURL;

    @Option(name = "-ca",
            required = true, description = "Required. CA certificate file")
    protected String            cacertFile;

    @Option(name = "-serial",
            required = true,
            description = "Required. Serial numbers. Comma-seperated serial numbers or ranges")
    protected String           serialNumbers;

    @Option(name = "-duration",
            required = true,
            description = "Required. Duration in seconds")
    protected int              durationInSecond;
    @Option(name = "-thread",
            required = false,
            description = "Number of threads, the default is 5")
    protected Integer          numThreads;

    private OCSPRequestor      requestor;

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(numThreads == null)
        {
            numThreads = 5;
        }

        List<Long> serialNumbers = new LinkedList<Long>();

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
                if(countTokens == 2)
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

        URL serverUrl = new URL(serverURL == null ? DFLT_URL : serverURL);

        StringBuilder startMsg = new StringBuilder();

        startMsg.append("Threads:        " + numThreads).append("\n");
        startMsg.append("Duration:       " + durationInSecond + " s").append("\n");
        startMsg.append("Serial numbers: " + this.serialNumbers).append("\n");
        startMsg.append("CA cert:        " + cacertFile).append("\n");
        startMsg.append("Server URL:     " + serverUrl.toString()).append("\n");
        System.out.print(startMsg.toString());

        X509Certificate caCert = IoCertUtil.parseCert(cacertFile);

        RequestOptions options = new RequestOptions();
        options.setUseNonce(true);
        options.setHashAlgorithmId(NISTObjectIdentifiers.id_sha256);

        OcspLoadTest loadTest = new OcspLoadTest(requestor, serialNumbers,
                caCert, serverUrl, options);
        loadTest.setDuration(durationInSecond);
        loadTest.setThreads(numThreads);
        loadTest.test();

        return null;
    }

    public OCSPRequestor getRequestor()
    {
        return requestor;
    }

    public void setRequestor(OCSPRequestor requestor)
    {
        this.requestor = requestor;
    }
}
